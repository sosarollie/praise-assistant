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
Step 6 — Adversarial verification.

For every finding that survived the s4 vote, spawn a fresh agentic Claude
session inside the target repo with Read/Grep tools. The verifier's job is to
PROVE THE FINDING WRONG: re-read the source, trace callers, hunt for upstream
protections, and emit a TRUE_POSITIVE / FALSE_POSITIVE verdict + CVSS 3.1
vector.

Only TRUE_POSITIVE findings continue to s7. FALSE_POSITIVEs are recorded as
DroppedFinding entries for the audit trail.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from vvaharness.backends.llm import cli
from vvaharness.backends.llm import deepagents as _deepagents
from vvaharness.backends.llm.cli import GuardrailBlocked
from vvaharness.backends.llm.models import validate_detection_tools
from vvaharness.backends.llm.registry import resolve
from vvaharness.models import ContextPackage, DroppedFinding, Finding
from vvaharness.orchestrator.store import ensure_state_dir
from vvaharness.pipeline.callgraph_consumer import graph_view, qnodes_at
from vvaharness.pipeline.stages.s1_preprocess import q_file
from vvaharness.report.cvss import rating as cvss_rating
from vvaharness.report.cvss import score as cvss_score
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.util.prompts import EXCLUSION_RULES
from vvaharness.util.response_quality import stage_floors

log = logging.getLogger(__name__)

_REPAIR_MIN_CHARS = 60
_REPAIR_MIN_TOKENS = 10

# VVAH-E003 floors for the PRIMARY verify dispatch. Derived, not guessed:
#
# The shortest reply this stage ACTS ON is a bare verdict line —
#   VERDICT: TRUE_POSITIVE (confidence: N/10)
# = 41 chars, ~13-15 visible-text tokens. The parser salvages that (CVSS simply
# degrades to None), so it is a success, not a degenerate reply. A fully
# contract-conforming answer is the 41-char VERDICT plus the ~50-char CVSS line
# (~92 chars), and ~120-140 with the mandated one-line reason — all three sit
# UNDER the 150-char global default, which is why a correct verdict was being
# logged as a degenerate response.
#
# 40 / 10 sits just below the 41-char / ~13-token floor of the smallest reply
# the parser accepts, and above every degenerate archetype: empty body (0),
# one-word acknowledgement (~1-2 tokens), empty fenced block (~4 tokens), and —
# on the token axis — the one-sentence refusal (~8-9 tokens) that
# s1_autoexclude.py's derivation also deliberately clears.
#
# The char axis CANNOT separate the two here: a refusal is ~30-60 chars, longer
# than the 41-char valid verdict, so no char floor distinguishes them. That
# detection is carried structurally instead — _parse_verdict's failure sentinel
# is reclassified to a visible VERIFY_ERROR drop rather than the FALSE_POSITIVE
# bucket, so a verdict-free reply can never become a silent confirmed drop.
#
# Deliberately NOT reusing _REPAIR_MIN_* (60/10) even though the numbers look
# close: the repair path's smallest conforming reply is the two-line footer
# (~92-100 chars, safely above 60), while the primary's smallest acted-on reply
# is the 41-char VERDICT line, which a 60-char floor would flag on the SUCCESS
# path — the exact spurious warning the repair floors were added to end. One
# pair of numbers cannot serve both shapes.
#
# Latent rather than firing today: check_response_quality runs on the agentic
# path only for via:deepagents (sdk/openai/cli agentic() skip it entirely), so
# this misfires only when `verify` resolves to that route.
_PRIMARY_MIN_CHARS = 40
_PRIMARY_MIN_TOKENS = 10

_CVSS_RE = re.compile(
    # Accept both CVSS:3.0 and CVSS:3.1 vectors — the downstream scorer
    # (report/cvss.py _VECTOR_RE) accepts CVSS:3.[01], so requiring exactly
    # 3.1 here silently dropped well-formed 3.0 vectors.
    r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
    r"C:[NLH]/I:[NLH]/A:[NLH]"
)
_VERDICT_RE = re.compile(
    r"VERDICT:\s*(TRUE_POSITIVE|FALSE_POSITIVE)\s*"
    r"\(confidence:\s*(\d{1,2})\s*/\s*10\)\s*[—\-–]?\s*(.*)",
    re.IGNORECASE,
)

SYSTEM = f"""You are the second-opinion reviewer in a SAST pipeline. A scanner
has produced the finding below; assume it is WRONG until you have personally
confirmed it in the source. Your only output that matters is a
TRUE_POSITIVE / FALSE_POSITIVE verdict plus a CVSS vector.

Tools available: Read, Glob, Grep. Use them — do not reason from the snippet
alone.

WORKFLOW
  A. Start from the CALL GRAPH CONTEXT section in the user prompt (it is
      SQLite-backed graph metadata from prior stages). Validate those edges
      in code with Grep/Read; do not assume they are perfect.
  B. Open the cited file at the cited line. Establish what the code really
      does (the scanner's description is a claim, not evidence).
  C. Walk the call chain outward: follow callers/callees from graph context,
      then verify each hop in source. Continue backward until you reach an
      external entry point or run out of callers. No external entry point →
      not exploitable.
  D. Try to kill the finding. Look specifically for: input validation or
     allow-lists earlier in the flow; framework-level encoding /
     parameterisation; type or length constraints; auth/authz gates in front
     of the route; feature flags or config that disable the path in prod;
     the code being test-only or simply never invoked.
  E. If you found a defence in (D), probe it: does it cover every route into
     the sink, or only the one you happened to read? Can edge-case input
     (encoding tricks, nulls, oversized values) slip past it?

If the call graph is sparse/ambiguous for this finding, say that clearly and
fall back to broader code-led verification (imports, router wiring, dispatch,
and upstream callers discovered via Grep). Missing graph edges are NOT enough
to refute a finding by themselves.

{EXCLUSION_RULES}

DECISION RULE
  TRUE_POSITIVE  — only when (B) reached an external/lower-privileged entry
                   point AND (C)/(D) found no defence that fully closes the
                   path AND the impact is real, not hypothetical.
  FALSE_POSITIVE — any one of: no external caller; an upstream control fully
                   neutralises the input; the scanner mis-read the code
                   (wrong sink, wrong class, wrong file).

Confidence 8–10 means you actively searched for the opposite verdict and
could not support it. Confidence ≤5 means you are guessing — say so.

═══════════════════════════════════════════════════════════════════════════
CVSS 3.1 BASE VECTOR — required on the line directly after VERDICT
═══════════════════════════════════════════════════════════════════════════
  AV  N network · A adjacent · L local · P physical
  AC  L trivial · H needs race/MITM/unusual state
  PR  N none · L any authenticated user · H admin/operator
  UI  N none · R victim must act
  S   U same component · C crosses a security boundary
  C/I/A  H full · L limited · N none

Score the vector against the claimed impact even when returning
FALSE_POSITIVE (it feeds severity calibration downstream).

Last two lines of your reply MUST match exactly:
VERDICT: TRUE_POSITIVE|FALSE_POSITIVE (confidence: N/10) — brief reason
CVSS: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_"""


def run(findings: list[Finding], ctx: ContextPackage, cfg, *, run_id: str = ""
        ) -> tuple[list[Finding], list[DroppedFinding]]:
    """Verify every finding. Returns (verified, dropped)."""
    log.info("s6/verify: starting verification - findings=%d", len(findings))
    progress = _S6Progress(len(findings), cfg, run_id)
    if not findings:
        progress.finish()
        log.info("s6/verify: no findings to verify")
        return [], []

    parallel = getattr(cfg.step6_verify, "parallel", 4)
    min_conf = getattr(cfg.step6_verify, "min_confidence", 7)
    # Validate the allowlist HERE, before the pool spawns: s6 is a detection
    # stage, and on `via: sdk` a mutating tool would silently delegate the
    # whole agentic call to the Agent SDK backend (repo mutation). Raising
    # inside _verify_one would be swallowed into per-finding VERIFY_ERROR
    # drops below, so a bad profile must fail closed before any model call.
    # The guard is via-aware: `via: cli` honours the allowlist verbatim
    # (Bash there is a shipped capability), every other via stays read-only.
    tools = validate_detection_tools(
        getattr(cfg.step6_verify, "allowed_tools", None),
        config_key="step6_verify.allowed_tools",
        via=resolve(cfg.models.verify).via)
    print(f"  [s6-verify] verifying {len(findings)} findings "
          f"({parallel} parallel, gate≥{min_conf}/10)...", file=sys.stderr)

    verified: list[Finding] = []
    dropped: list[DroppedFinding] = []
    guardrail_hits = 0
    guardrail_gate = max(3, parallel)

    ex = ThreadPoolExecutor(max_workers=parallel)
    futs = {ex.submit(_verify_one, i, f, ctx, cfg, tools): (i, f)
            for i, f in enumerate(findings)}
    try:
        for fut in as_completed(futs):
            i, f = futs[fut]
            try:
                f2 = fut.result()
            except GuardrailBlocked as e:
                guardrail_hits += 1
                print(f"    [s6-verify] #{i} GUARDRAIL-BLOCKED "
                      f"({guardrail_hits}/{guardrail_gate})", file=sys.stderr)
                _errlog.log("s6-verify", f"guardrail#{i}", e,
                            file=getattr(f, "file", None),
                            line=getattr(f, "line_start", None))
                # redact() before the [:200] cut: the detail ships in the
                # report's Dropped Findings table, whose write-boundary
                # redaction cannot re-match a secret this slice bisected.
                dropped.append(_drop(f, "GUARDRAIL_BLOCKED",
                                     redact(str(e))[:200]))
                progress.record("GUARDRAIL_BLOCKED")
                if guardrail_hits >= guardrail_gate and not verified:
                    cli.abort()
                    ex.shutdown(wait=False, cancel_futures=True)
                    raise RuntimeError(
                        f"s6-verify: {guardrail_hits} cumulative guardrail "
                        "blocks with zero successes — aborting run.") from e
                continue
            except Exception as e:
                print(f"    [s6-verify] #{i} verify ERROR: {redact(str(e))}", file=sys.stderr)
                _errlog.log("s6-verify", f"#{i}", e,
                            file=getattr(f, "file", None),
                            line=getattr(f, "line_start", None),
                            vuln_class=str(getattr(f, "vuln_class", "")))
                # redact() before the [:200] cut — same report-bound trap as
                # the GUARDRAIL_BLOCKED detail above.
                dropped.append(_drop(f, "VERIFY_ERROR", redact(str(e))[:200]))
                progress.record("VERIFY_ERROR")
                continue
            if f2.verdict == "TRUE_POSITIVE" and (f2.verdict_confidence or 0) >= min_conf:
                verified.append(f2)
                progress.record("TRUE_POSITIVE")
            elif f2.verdict == "TRUE_POSITIVE":
                dropped.append(_drop(f2, "UNCONFIRMED",
                                     f"verifier confidence {f2.verdict_confidence}/10 "
                                     f"below gate {min_conf}"))
                progress.record("UNCONFIRMED")
            elif (f2.verdict_reason == "verifier output unparseable"
                  and (f2.verdict_confidence or 0) == 0):
                # An unparseable verifier reply (no VERDICT line) is an
                # *undetermined* result, not a confirmed FALSE_POSITIVE.
                # Laundering it into the FP bucket understated true risk and
                # skewed the precision metric — record it as VERIFY_ERROR so a
                # flaky/truncated verification is visible, not silently "clean".
                dropped.append(_drop(f2, "VERIFY_ERROR", f2.verdict_reason))
                progress.record("VERIFY_ERROR")
            else:
                dropped.append(_drop(f2, "FALSE_POSITIVE", f2.verdict_reason))
                progress.record("FALSE_POSITIVE")
    except KeyboardInterrupt:
        n = cli.abort()
        print(f"  [s6-verify] interrupted — killed {n} running verifier "
              f"process(es), cancelling {sum(1 for f in futs if not f.done())} "
              f"pending", file=sys.stderr)
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        ex.shutdown(wait=True)

    tp = len(verified)
    fp = sum(1 for d in dropped if d.reason == "FALSE_POSITIVE")
    unc = sum(1 for d in dropped if d.reason == "UNCONFIRMED")
    gb = sum(1 for d in dropped if d.reason == "GUARDRAIL_BLOCKED")
    errs = len(dropped) - fp - unc - gb
    print(f"  [s6-verify] done: {tp} TRUE_POSITIVE, {fp} FALSE_POSITIVE, "
          f"{unc} UNCONFIRMED, {gb} GUARDRAIL_BLOCKED, {errs} errors",
          file=sys.stderr)
    log.info("s6/verify: verification complete - tp=%d fp=%d unconfirmed=%d guardrail=%d errors=%d",
             tp, fp, unc, gb, errs)
    return verified, dropped


class _S6Progress:
    """Optional atomic on-disk progress reporter for concurrent S6 work."""

    def __init__(self, total: int, cfg, run_id: str):
        self.total = total
        self.enabled = bool(getattr(cfg.step6_verify, "progress_file", False))
        self.path: Path | None = None
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._completed = 0
        if self.enabled:
            safe_run_id = re.sub(r"[^A-Za-z0-9_.-]", "_", run_id or "current")
            self.path = ensure_state_dir("s6_progress", safe_run_id) / "s6_progress.json"
            self._write("running")

    def record(self, outcome: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._completed += 1
            self._counts[outcome] = self._counts.get(outcome, 0) + 1
            self._write("completed" if self._completed == self.total else "running")

    def finish(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._write("completed")

    def _write(self, status: str) -> None:
        assert self.path is not None
        payload = {
            "status": status,
            "total": self.total,
            "completed": self._completed,
            "remaining": self.total - self._completed,
            "outcomes": dict(sorted(self._counts.items())),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        fd, tmp_name = tempfile.mkstemp(
            prefix=".s6_progress.", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                json.dump(payload, tmp, separators=(",", ":"))
                tmp.write("\n")
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, self.path)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass


def _verify_one(idx: int, f: Finding, ctx: ContextPackage, cfg,
                tools: list[str]) -> Finding:
    """Verify one finding; *tools* is the allowlist run() already validated."""
    if cli.aborted():
        raise RuntimeError("aborted by user (Ctrl-C)")
    user = _build_user_prompt(f, ctx)

    # Hoist the dispatch kwargs the primary and repair calls share VERBATIM into
    # one dict. This is not just shorter: it structurally prevents the repair
    # call drifting from the primary (same model, caps, tools, cwd, graph) — the
    # two must go through an identical seam or the repair could silently run with
    # different budget/tools than the answer it is restating. Only the prompt and
    # the `tag` differ, so those stay explicit per call.
    agentic_kwargs = dict(
        model=cfg.models.verify,
        cfg=cfg,
        system_prompt=SYSTEM,
        allowed_tools=list(tools),
        cwd=ctx.repo_root,
        max_budget_usd=getattr(cfg.step6_verify, "max_budget_usd", 1.0),
        max_turns=getattr(cfg.step6_verify, "max_turns", None),
        graph_name="s6-verify",
    )


    primary_tag = f"s6 verify#{idx}"
    with stage_floors(primary_tag, min_chars=_PRIMARY_MIN_CHARS,
                      min_tokens=_PRIMARY_MIN_TOKENS):
        raw = _deepagents.dispatch_agentic(user, tag=primary_tag, **agentic_kwargs)

    verdict, conf, reason, cvss, reasoning = _parse_verdict(raw)
    if reason == "verifier output unparseable":
        # ONE bounded parse-repair re-ask, following the house pattern S2 and S4
        # already use (`_repair_json_prompt` in both `s2_threatmodel` and
        # `s4_deepdive`) and that S6 was the only agentic detection stage missing.
        # The old behaviour dropped the finding outright the moment
        # `_parse_verdict` failed — and the campaign proved that discards
        # *committed* true positives (e.g. a `TRUE_POSITIVE (confidence: 9/10) —
        # Confirmed:` reply missing only the literal `VERDICT:` prefix, and
        # replies that ran long past the footer). A model that reached a
        # conclusion but mis-shaped the reply gets exactly one chance to restate
        # it in the contract's form; we do NOT loosen `_VERDICT_RE` (see
        # `_repair_verdict_prompt` for why a permissive parser would be worse on a
        # security verdict). Bound: strictly one re-ask — S6 verify is the run's
        # dominant cost, so an unbounded retry here would be a cost incident;
        # S2/S4 also cap at one.
        #
        # GATE (fixes the verdict-fabrication defect): only re-ask when the
        # PRIMARY reply actually mentions a verdict token. The repair prompt
        # ASSERTS "your previous reply reached a conclusion … restate it" to a
        # FRESH session that shares no context beyond the pasted `raw`. If `raw`
        # is empty / hard-truncated / verdict-free, there is nothing to restate,
        # so the model would INVENT a verdict — a fabricated FALSE_POSITIVE re-
        # launders the finding into the confirmed-FP bucket this stage's own
        # comment (see run() below) exists to prevent, and a fabricated
        # TRUE_POSITIVE ships an unverified finding. A verdict-free reply must go
        # straight to VERIFY_ERROR with NO repair call — both correct and cheaper.
        raw_up = (raw or "").upper()
        primary_tp = "TRUE_POSITIVE" in raw_up
        primary_fp = "FALSE_POSITIVE" in raw_up
        raw2: str | None = None
        if primary_tp or primary_fp:
            # F4: mirror the entry-point abort guard (see top of _verify_one)
            # before spending on the repair. run() cancels only PENDING futures on
            # Ctrl-C; without this an in-flight worker would still start a fresh
            # billed repair dispatch after the user quit. Same shape as the entry
            # check so the abort trail is uniform.
            if cli.aborted():
                raise RuntimeError("aborted by user (Ctrl-C)")
            repair_tag = f"s6 verify#{idx} verdict-repair"
            try:
                # F2: scope the VVAH-E003 floors around the repair via stage_floors
                # (keyed by the SAME tag the backends hand check_response_quality),
                # so a conforming-but-short two-line repair is not flagged as
                # degenerate on the healthy path. Reuse of S1's mechanism.
                with stage_floors(repair_tag, min_chars=_REPAIR_MIN_CHARS,
                                  min_tokens=_REPAIR_MIN_TOKENS):
                    raw2 = _deepagents.dispatch_agentic(
                        _repair_verdict_prompt(raw), tag=repair_tag,
                        **agentic_kwargs)
            except Exception as repair_err:  # noqa: BLE001
                # F5: the previous author claimed a "byte-identical VERIFY_ERROR
                # trail". That only held on the parses-but-fails path. If the
                # REPAIR call itself raises, letting it propagate would (a) turn a
                # GuardrailBlocked on the repair into a second guardrail hit for
                # ONE finding, double-counting toward run()'s abort gate, and (b)
                # reclassify the drop as GUARDRAIL_BLOCKED / an exception-text
                # VERIFY_ERROR with no unparseable errlog record. Pre-fix there was
                # NO repair call, so no such exception could occur — the faithful
                # behaviour is to swallow ANY repair failure and fall through to
                # the exact VERIFY_ERROR trail below. GuardrailBlocked is a
                # RuntimeError, so `except Exception` covers it; KeyboardInterrupt
                # (BaseException) still propagates to abort the run.
                print(f"    [s6-verify] #{idx} verdict-repair failed, keeping "
                      f"VERIFY_ERROR — {redact(str(repair_err))[:120]}",
                      file=sys.stderr)
                raw2 = None
        v2, c2, r2, cv2, rs2 = _parse_verdict(raw2 or "")
        # ADOPTION RULE. Adopt the repaired verdict only when it parsed AND is
        # consistent with what the primary reply committed to:
        #   * primary committed to exactly ONE token (only TRUE_POSITIVE or only
        #     FALSE_POSITIVE present) → the repair MUST match it. This recovers
        #     the missing-`VERDICT:`-prefix committed TP, but forbids a repair
        #     flipping a clear commitment to its opposite.
        #   * primary mentioned BOTH tokens (prose weighing TP vs FP without
        #     ending in the contract's shape — 3 of 4 real campaign cases) → the
        #     model analysed but did not commit to a shape, so the repair IS the
        #     legitimate disambiguation; adopt whichever it commits to.
        # A verdict-free primary never reaches here (no re-ask fired, raw2 is
        # None → r2 is unparseable), so it can never be adopted.
        consistent = ((primary_tp and primary_fp)
                      or (primary_tp and v2 == "TRUE_POSITIVE")
                      or (primary_fp and v2 == "FALSE_POSITIVE"))
        if r2 != "verifier output unparseable" and consistent:
            # The re-ask restated a parseable verdict consistent with the primary
            # commitment: adopt it and skip the drop. Downstream this simply moves
            # the finding from `dropped` to `verified` (run() re-classifies on the
            # recovered verdict); no other field or code path changes. This is the
            # recovery for the committed TP the campaign lost to a formatting
            # technicality.
            verdict, conf, reason, cvss, reasoning = v2, c2, r2, cv2, rs2
        else:
            # No re-ask fired (verdict-free primary), the re-ask stayed
            # unparseable, or it was rejected as inconsistent with the primary
            # commitment — a genuinely undetermined result. Keep today's
            # VERIFY_ERROR trail byte-for-byte so the loss still reaches the
            # operator's report (models/_scan.py:1733-1737 counts it, :1893
            # renders it as VERIFY-ERR) — we ADD a gated recovery attempt before
            # the drop, not replace it.
            #
            # Log the last text we actually saw: the repair reply when we made one
            # (raw2), else the primary (raw) — mirrors s2's "head of whichever
            # text the final attempt tried to parse", and stays useful when no
            # repair fired or it raised. redact() the FULL reply BEFORE cutting it:
            # slicing first can bisect a credential the verifier quoted from the
            # repo, and the surviving prefix matches no redaction pattern. errlog
            # redacts its string fields internally, but only AFTER receiving them —
            # a pre-truncated fragment would land in errors.jsonl unmasked, and the
            # stderr print has no other redaction at all. Kept inline as
            # redact(...)[:n] — the exact shape the contract tripwire blesses.
            logged = raw2 if raw2 is not None else raw
            _errlog.log("s6-verify", f"unparseable#{idx}",
                        "no VERDICT line in verifier output after one repair re-ask",
                        file=f.file, line=f.line_start,
                        raw_len=len(logged or ""), raw=redact(logged or "")[:600])
            print(f"    [s6-verify] #{idx} UNPARSEABLE raw[:200]="
                  f"{redact(logged or '')[:200]!r}", file=sys.stderr)
    s = cvss_score(cvss)
    print(f"    [s6-verify] #{idx} {f.file}:{f.line_start} → {verdict} "
          f"({conf}/10) cvss={s if s is not None else '-'}", file=sys.stderr)

    return f.model_copy(update={
        "verdict": verdict,
        "verdict_confidence": conf,
        "verdict_reason": reason,
        "cvss_vector": cvss,
        "cvss_score": s,
        "cvss_rating": cvss_rating(s) if s is not None else None,
        "verifier_reasoning": reasoning,
    })


def _controls_for(file: str, ctx: ContextPackage) -> list[str]:
    out = []
    for c in ctx.design_controls:
        hit = not c.protects or any(fnmatch.fnmatch(file, g) for g in c.protects)
        if hit:
            note = f" — {c.notes}" if c.notes else ""
            out.append(f"  - [{c.kind}] {c.name} protects this path{note}")
    return out


def _callers_of(file: str, ctx: ContextPackage, limit: int = 15) -> list[str]:
    out = []
    for caller, callees in ctx.call_graph.items():
        if any(q_file(cal) == file or q_file(cal).endswith("/" + file)
               for cal in callees):
            out.append(f"  - {caller}")
            if len(out) >= limit:
                break
    return out


def _candidate_qnodes_for_finding(f: Finding, ctx: ContextPackage,
                                  limit: int = 6) -> list[str]:
    """Best-effort qnodes for the finding location.

    Uses the shared, call-graph-first resolver: spans corroborate the precise
    function, the call graph's file membership is the fallback.
    """
    return qnodes_at(graph_view(ctx), f.file or "",
                     int(f.line_start or 1), int(f.line_end or f.line_start or 1),
                     limit=limit)


def _callgraph_context_for_finding(f: Finding, ctx: ContextPackage) -> str:
    graph = ctx.call_graph or {}
    if not graph:
        return "CALL GRAPH CONTEXT (sqlite-hydrated): (none available)"

    cands = _candidate_qnodes_for_finding(f, ctx)
    rev = graph_view(ctx).rev

    lines = [
        "CALL GRAPH CONTEXT (sqlite-hydrated; validate each edge with Grep/Read):",
        f"  - graph nodes: {len(graph)}",
        f"  - graph edges: {sum(len(v or ()) for v in graph.values())}",
    ]
    if f.source_ref:
        marker = " (inferred from AST, unverified)" if "source_ref" in f.backfilled_refs else ""
        lines.append(f"  - finding.source_ref: {f.source_ref}{marker}")
    if f.sink_ref:
        marker = " (inferred from AST, unverified)" if "sink_ref" in f.backfilled_refs else ""
        lines.append(f"  - finding.sink_ref: {f.sink_ref}{marker}")

    if not cands:
        lines.append("  - candidate functions at finding location: (none)")
        lines.append("  - action: use Grep on file/class symbols to recover callers/callees from code")
        return "\n".join(lines)

    lines.append("  - candidate functions at/near finding line:")
    for qn in cands:
        lines.append(f"    - {qn}")

    for qn in cands:
        callers = rev.get(qn, [])[:8]
        callees = (graph.get(qn) or [])[:8]
        lines.append(f"  - around {qn}:")
        if callers:
            for c in callers:
                lines.append(f"    - caller -> {c} -> {qn}")
        else:
            lines.append("    - caller -> (none in graph)")
        if callees:
            for c in callees:
                lines.append(f"    - callee -> {qn} -> {c}")
        else:
            lines.append("    - callee -> (none in graph)")

    return "\n".join(lines)


def _build_user_prompt(f: Finding, ctx: ContextPackage) -> str:
    pre = "\n".join(f"  - {p}" for p in f.preconditions) or "  (none listed)"

    eps = [f"  - {e.kind}: {e.function} @ {e.file}"
           f"{' [UNAUTH-REACHABLE]' if e.reachable_from_unauth else ''}"
           for e in ctx.entry_points]
    ep_block = ("KNOWN EXTERNAL ENTRY POINTS (from architecture scan):\n"
                + "\n".join(eps[:25])
                + ("\n  ...(+%d more)" % (len(eps) - 25) if len(eps) > 25 else "")
                ) if eps else ""

    callers = _callers_of(f.file, ctx)
    cg_block = ("KNOWN CALLERS OF THIS FILE (from call graph — verify with Grep):\n"
                + "\n".join(callers)) if callers else ""
    cg_focus = _callgraph_context_for_finding(f, ctx)

    controls = _controls_for(f.file, ctx)
    ctl_block = ("DESIGN CONTROLS IN EFFECT ON THIS PATH:\n"
                 + "\n".join(controls)
                 + "\nYou MUST demonstrate a bypass of these controls to return "
                   "TRUE_POSITIVE. If the control fully mitigates the finding, "
                   "return FALSE_POSITIVE.") if controls else ""

    notes_block = (f"ARCHITECTURE NOTES:\n{ctx.notes}") if ctx.notes else ""

    arch = "\n\n".join(b for b in (cg_focus, ep_block, cg_block, ctl_block, notes_block) if b)

    return f"""FINDING TO VERIFY:
File: {f.file}
Line: {f.line_start}-{f.line_end}
Category: {f.vuln_class.value}
Title: {f.title}

Description:
{f.description}

Exploit scenario:
{f.exploit_scenario or "(not provided)"}

Preconditions:
{pre}

Code snippet (as reported by scanner — verify against actual file):
{f.code_snippet}

═══════════════════════════════════════════════════════════════════════════
ARCHITECTURE CONTEXT (from prior repo analysis and sqlite callgraph — use as starting points,
but VERIFY against actual code; this may be incomplete or stale):
═══════════════════════════════════════════════════════════════════════════
{arch or "(none captured)"}

Investigate using Read/Grep. Start with CALL GRAPH CONTEXT, and if it is
ambiguous/incomplete for this finding, expand to broader code-led tracing.
Then end with the two required VERDICT and CVSS lines."""


def _repair_verdict_prompt(raw: str) -> str:
    """One-shot format-repair re-ask — the S6 analogue of s2/s4's
    `_repair_json_prompt`.

    S6's contract is not JSON (it is the two-line VERDICT/CVSS footer at
    SYSTEM:122-124), so it cannot reuse `_repair_json_prompt` verbatim; it needs
    its own one-line-contract prompt. Everything else follows the house pattern.

    Deliberately asks ONLY for the two required lines to be RESTATED — it does
    NOT re-open the analysis. The model has already reached a conclusion; the
    failure was one of *shape*, not of *judgement* (a reply that ran long, lost
    the footer, or omitted the literal `VERDICT:` token). Re-litigating the
    verdict here could flip a correct answer, and on a security verdict a flipped
    answer is worse than the drop we are trying to avoid — the same reasoning
    that argues against loosening `_VERDICT_RE` (a permissive parser would read a
    verdict out of prose the model was still weighing). Restating the committed
    conclusion in the strict shape preserves the deliberate contract while
    recovering the paid-for verification work.
    """
    return f"""REPAIR TASK:
Your previous reply reached a conclusion but did not end with the two required
lines, so the pipeline could not read your verdict. Do NOT reconsider or change
your conclusion — restate it now in the exact required format and output NOTHING
ELSE:

VERDICT: TRUE_POSITIVE|FALSE_POSITIVE (confidence: N/10) — brief reason
CVSS: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_

YOUR PREVIOUS REPLY:
{raw}
"""


def _parse_verdict(raw: str) -> tuple[str, int, str, str | None, str]:
    """Return (verdict, confidence, reason, cvss_vector|None, reasoning_body)."""
    lines = raw.strip().splitlines()

    verdict, conf, reason = "FALSE_POSITIVE", 0, "verifier output unparseable"
    verdict_line_idx = len(lines)
    for i in range(len(lines) - 1, -1, -1):
        m = _VERDICT_RE.search(lines[i])
        if m:
            verdict = m.group(1).upper()
            conf = max(0, min(10, int(m.group(2))))
            reason = m.group(3).strip() or "(no reason given)"
            verdict_line_idx = i
            break

    cvss = None
    tail = "\n".join(lines[verdict_line_idx:])
    m = _CVSS_RE.search(tail)
    if not m:
        matches = list(_CVSS_RE.finditer(raw))
        m = matches[-1] if matches else None
    if m:
        cvss = m.group(0)

    reasoning = "\n".join(lines[:verdict_line_idx]).strip()
    return verdict, conf, reason, cvss, reasoning


def _drop(f: Finding, reason: str, detail: str) -> DroppedFinding:
    return DroppedFinding(
        file=f.file,
        line=f.line_start,
        vuln_class=f.vuln_class,
        title=f.title,
        chunk_id=f.chunk_id,
        reason=reason,
        detail=detail,
    )
