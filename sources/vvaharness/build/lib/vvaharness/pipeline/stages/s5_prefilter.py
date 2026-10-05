# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Step 5 — Deterministic pre-filter.

Runs between s4 deep-dive and s6 verify. Pure Python, no model calls.
Cuts obvious false-positives and trivial duplicates so the expensive
adversarial verifier isn't burned on findings that can be rejected
mechanically:

  - test/mock/example/fixture paths (model ignores the prompt rule ~10%)
  - hallucinated file paths not present in the repo inventory
    - s4 confidence below step5_prefilter.min_pre_confidence
    - missing source_ref/sink_ref when step5_prefilter.require_evidence is on
    — this gate judges each finding's OWN refs; AST/seed backfill runs only on
    survivors afterwards, so it decorates kept findings but never satisfies the
    gate for a finding that arrived without evidence
  - trivial dups: same file + vuln_class within step7_dedup.line_tolerance
  - SEMANTIC dups (one LLM call) when ≥ step7_dedup.pre_verify_threshold
    findings survive the gates above — collapsing root-cause duplicates here
    avoids paying for N independent verifiers on the same bug in s6

Not checkpointed — the deterministic gates are ~0ms and the optional semantic
call is one cheap dedup-model invocation, both re-run against the loaded s4
checkpoint on --resume.
"""
from __future__ import annotations

import logging
import re
import sys

log = logging.getLogger(__name__)

from vvaharness.models import ContextPackage, DroppedFinding, Finding, VulnClass
from vvaharness.pipeline.callgraph_consumer import (
    best_source_from_seed,
    entry_anchor_lines,
    seed_paths_by_file,
)

from . import s7_dedup

_EXCLUDE_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|mocks?|examples?|fixtures?|samples?|testdata)(/|$)"
    r"|_test\.|\.test\.|\.spec\.|Test\.java$|Tests\.cs$",
    re.IGNORECASE,
)

# CWEs that represent point-of-occurrence hardcoded-credential findings.
# These have no source→sink taint flow to prove — the committed value IS
# the evidence. Checked by CWE id (f.cwe) so the gate bypass is
# unconditional regardless of how S4 phrases the finding title.
_HARDCODED_CWES: frozenset[str] = frozenset({
    "CWE-798",  # Use of Hard-coded Credentials (umbrella)
    "CWE-259",  # Use of Hard-coded Password
    "CWE-321",  # Use of Hard-coded Cryptographic Key
    "CWE-256",  # Plaintext Storage of a Password
})

# "Missing control" / configuration-absence findings: the PRESENCE (or
# absence) of a code element IS the evidence — there is no source→sink
# taint path to prove.  Requiring source_ref/sink_ref for these classes
# would silently drop every legitimate finding at the require_evidence gate.
#
# Examples:
#   CWE-352  @csrf_exempt on a POST handler — the decorator IS the evidence
#   CWE-1004 Missing HttpOnly/Secure flag on a Set-Cookie line
#   CWE-614  Missing Secure attribute on a cookie
#   CWE-307  No rate-limit on a login endpoint
#   CWE-778  No logging on an auth-failure path
#   CWE-311  Sensitive data stored without encryption (storage class)
#   CWE-312  Cleartext storage (passwords in logs — point of occurrence)
#   CWE-532  Insertion of sensitive info into log file
#   CWE-209  Exposure of error message containing sensitive info
_CONTROL_ABSENCE_CWES: frozenset[str] = frozenset({
    "CWE-352",   # CSRF — missing token check
    "CWE-1004",  # Sensitive Cookie Without HttpOnly Flag
    "CWE-614",   # Sensitive Cookie Without Secure Attribute
    "CWE-307",   # Improper Restriction of Excessive Authentication Attempts
    "CWE-778",   # Insufficient Logging
    "CWE-311",   # Missing Encryption of Sensitive Data
    "CWE-312",   # Cleartext Storage of Sensitive Information
    "CWE-532",   # Insertion of Sensitive Information into Log File
    "CWE-209",   # Generation of Error Message Containing Sensitive Information
})

# Credential-class evidence in the finding text. A committed AWS key, JWT,
# or BEGIN PRIVATE KEY block in tests/fixtures/*.pem is a real production
# risk regardless of where it lives — the file is in source control and
# was likely real once. Findings matching this stay even when the path
# matches _EXCLUDE_PATH_RE.
_SECRET_TEXT_RX = re.compile(
    r"(?i)\b(?:"
    r"hard[\s-]?coded|"
    r"password|passwd|"
    r"api[_-]?key|access[_-]?key|secret[_-]?key|"
    r"auth[_-]?token|bearer\s+token|jwt|"
    r"private[_-]?key|client[_-]?secret|credential"
    r")\b"
    r"|-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[0-9A-Za-z]{36,}\b"
    r"|\bxox[baprs]-[0-9A-Za-z-]{10,}\b"
)


def _is_secret_class(f: Finding) -> bool:
    """True for findings that are point-of-occurrence — no source→sink taint
    flow exists to prove, so the require_evidence gate must not apply.

    Covers two families:
      A. Hardcoded credentials / committed secrets (_HARDCODED_CWES):
         the literal value in source IS the evidence.
      B. Missing controls / configuration absence (_CONTROL_ABSENCE_CWES):
         the presence or absence of a decorator / attribute / log call IS
         the evidence (e.g. @csrf_exempt, missing HttpOnly flag, no rate limit).

    Three independent signals, any one is sufficient:
      1. vuln_class == INFO_LEAK  (sensitive_data_exposure / information_disclosure)
      2. f.cwe in _HARDCODED_CWES or _CONTROL_ABSENCE_CWES — unconditional,
         regardless of how S4 phrased the title.
      3. _SECRET_TEXT_RX matches the finding title/description/snippet.
    """
    if f.vuln_class == VulnClass.INFO_LEAK:
        return True
    if f.cwe and (f.cwe in _HARDCODED_CWES or f.cwe in _CONTROL_ABSENCE_CWES):
        return True
    haystack = " ".join(s for s in (f.title, f.description, f.code_snippet) if s)
    return bool(_SECRET_TEXT_RX.search(haystack))


def _gate(cfg, key: str, default):
    """Read a prefilter gate. Prefers the new `step5_prefilter` section;
    falls back to legacy `step6_verify` for older configs that haven't been
    migrated yet."""
    s5p = getattr(cfg, "step5_prefilter", None)
    if s5p is not None:
        v = getattr(s5p, key, None)
        if v is not None:
            return v
    s6v = getattr(cfg, "step6_verify", None)
    if s6v is not None:
        v = getattr(s6v, key, None)
        if v is not None:
            return v
    return default


def _ast_backfill_evidence(f: Finding,
                           entry_anchors: dict[str, list[int]],
                           seed_idx: dict[str, list[list[str]]]) -> tuple[Finding, bool]:
    """Backfill missing source_ref/sink_ref using AST/callgraph/seed paths.

    This improves evidence completeness for true findings when one side of the
    flow was omitted by s4 output formatting, without introducing model calls.
    """
    src = (f.source_ref or "").strip()
    sink = (f.sink_ref or "").strip()
    changed = False
    backfilled: list[str] = []

    if not sink:
        sink = f"{f.file}:{max(1, int(f.line_start))}"
        changed = True
        backfilled.append("sink_ref")

    if not src:
        if f.vuln_class == VulnClass.INFO_LEAK:
            src = sink
            changed = True
            backfilled.append("source_ref")
        else:
            anchors = entry_anchors.get(f.file, ())
            if anchors:
                best = min(anchors, key=lambda ln: abs(ln - int(f.line_start)))
                src = f"{f.file}:{best}"
                changed = True
                backfilled.append("source_ref")
            else:
                seed_src = best_source_from_seed(seed_idx.get(f.file, ()))
                if seed_src:
                    src = seed_src
                    changed = True
                    backfilled.append("source_ref")

    if not changed:
        return f, False

    return f.model_copy(update={
        "source_ref": src or None,
        "sink_ref": sink or None,
        "backfilled_refs": sorted(set(f.backfilled_refs) | set(backfilled)),
    }), True


def run(findings: list[Finding], ctx: ContextPackage, cfg
        ) -> tuple[list[Finding], list[DroppedFinding]]:
    log.info("s5/prefilter: starting pre-filter - findings=%d", len(findings))
    min_conf = _gate(cfg, "min_pre_confidence", 0.0) or 0.0
    require_evidence = _gate(cfg, "require_evidence", False)
    ast_backfill = bool(_gate(cfg, "ast_backfill_evidence", True))

    valid_files = set(ctx.all_files) if ctx.all_files else None
    keep: list[Finding] = []
    dropped: list[DroppedFinding] = []
    backfilled = 0
    entry_anchors = entry_anchor_lines(ctx) if ast_backfill else {}
    seed_idx = seed_paths_by_file(ctx.seed_taint_paths) if ast_backfill else {}

    def _drop(f: Finding, reason: str, detail: str) -> None:
        dropped.append(DroppedFinding(
            file=f.file, line=f.line_start, vuln_class=f.vuln_class,
            title=f.title, chunk_id=f.chunk_id, reason=reason, detail=detail))

    kept_in_test: list[Finding] = []
    for f in findings:
        in_test_path = bool(_EXCLUDE_PATH_RE.search(f.file))
        # Evaluated unconditionally: used both for the test-path exception and
        # for the require_evidence gate bypass below.  Hardcoded-credential /
        # secret-class findings are point-of-occurrence — the credential being
        # present in the file IS the evidence; there is no source→sink taint
        # flow to require.
        secret_class = _is_secret_class(f)
        if in_test_path and not secret_class:
            _drop(f, "EXCLUDED", "test/mock/example path")
        elif valid_files is not None and f.file not in valid_files:
            _drop(f, "EXCLUDED", "file not in repo inventory")
        elif f.confidence < min_conf:
            _drop(f, "UNCONFIRMED",
                  f"s4 confidence {f.confidence:.2f} < gate {min_conf:.2f}")
        elif (require_evidence
              and not secret_class
              and not ((f.source_ref or "").strip()
                       and (f.sink_ref or "").strip())):
            # Precision-first: the require_evidence gate judges the finding's
            # OWN source/sink refs. Backfill runs only on the keep-path below,
            # so it can never manufacture the evidence this gate demands.
            # Exception: secret-class findings (hardcoded passwords, API keys,
            # committed credentials) are point-of-occurrence — no taint flow
            # exists to prove, so they must not be filtered here.
            _drop(f, "UNCONFIRMED",
                  "missing source_ref/sink_ref — data flow unproven")
        else:
            if ast_backfill:
                f, changed = _ast_backfill_evidence(f, entry_anchors, seed_idx)
                if changed:
                    backfilled += 1
            keep.append(f)
            if in_test_path and secret_class:
                kept_in_test.append(f)

    if kept_in_test:
        shown = ", ".join(f"{f.file}:{f.line_start}" for f in kept_in_test[:5])
        more = (f" (+{len(kept_in_test) - 5} more)"
                if len(kept_in_test) > 5 else "")
        print(f"  [s5-prefilter] kept {len(kept_in_test)} secret-class "
              f"finding(s) in test paths: {shown}{more}", file=sys.stderr)
    if backfilled:
        print(f"  [s5-prefilter] AST backfill: filled source/sink refs on "
              f"{backfilled} finding(s)", file=sys.stderr)

    s7d = getattr(cfg, "step7_dedup", None)
    s5p = getattr(cfg, "step5_prefilter", None)
    # S5 and S7 each have their own line_tolerance so you can tune pre-verify
    # (tight, catches raw duplicates) independently of post-verify (looser,
    # absorbs verifier-introduced line jitter). Falls back to step7_dedup for
    # backward compatibility with configs that only set the shared key.
    line_tol = (getattr(s5p, "line_tolerance", None)
                or getattr(s7d, "line_tolerance", 10))
    keep, dup_dropped = s7_dedup.prefilter(keep, line_tol)
    dropped.extend(dup_dropped)

    # One cheap dedup-model call here can save dozens of expensive s6 verifier
    # calls on chatty repos where parallel s4 chunks report the same root cause
    # under different titles/categories. Only fires above the threshold.
    # Keys are read from step5_prefilter first; fall back to step7_dedup for
    # backward compatibility with configs that haven't been migrated.
    # 0 is a MEANINGFUL value here — default.yaml documents it as "always run" —
    # so resolve on None, not on truthiness. An `or` chain read 0 as "unset" and
    # silently substituted the step7 fallback of 25, which is why every run
    # logged "≥ pre_verify_threshold 25" while the profile asked for 0.
    pre_thresh = getattr(s5p, "pre_verify_threshold", None)
    if pre_thresh is None:
        pre_thresh = getattr(s7d, "pre_verify_threshold", None)
    if pre_thresh is None:
        pre_thresh = 25
    pre_semantic = (getattr(s5p, "pre_verify_semantic", None)
                    if s5p is not None and
                       hasattr(s5p, "pre_verify_semantic")
                    else getattr(s7d, "pre_verify_semantic",
                                 getattr(s7d, "semantic", True)))
    # No `pre_thresh and ...` guard: that treated 0 as "never run", the exact
    # inverse of the documented meaning. `len(keep) >= 0` is always true, so 0
    # always runs; `pre_verify_semantic: false` is the documented off switch.
    if (len(keep) >= pre_thresh and pre_semantic):
        print(f"  [s5-prefilter] {len(keep)} survivors ≥ pre_verify_threshold "
              f"{pre_thresh} → running semantic dedup ahead of s6",
              file=sys.stderr)
        keep, sem_dropped = s7_dedup.run(keep, cfg, label="s5-prefilter",
                         ctx=ctx)
        for d in sem_dropped:
            # canonical_idx points into the *pre-verify* list and would be
            # stale once s6 drops FPs and re-dedups; report reasoning only.
            d.canonical_idx = None
            d.detail = f"pre-verify semantic: {d.detail}"
        dropped.extend(sem_dropped)

    if dropped:
        by: dict[str, int] = {}
        for d in dropped:
            by[d.reason] = by.get(d.reason, 0) + 1
        breakdown = ", ".join(f"{n} {k.lower()}" for k, n in sorted(by.items()))
        print(f"  [s5-prefilter] {len(findings)} → {len(keep)} ({breakdown})",
              file=sys.stderr)
        log.info("s5/prefilter: complete - input=%d output=%d dropped=%d reason_breakdown=%s",
                 len(findings), len(keep), len(dropped), breakdown)
    else:
        print(f"  [s5-prefilter] {len(findings)} → {len(keep)} (nothing dropped)",
              file=sys.stderr)
        log.info("s5/prefilter: complete - input=%d output=%d dropped=0",
                 len(findings), len(keep))
    return keep, dropped
