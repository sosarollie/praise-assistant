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

"""Step 8 — the chain-analysis LLM sees ALL findings together, identifies exploit chains, re-ranks by true exploitability, and checks for combinations with known unpatched CVEs."""
from __future__ import annotations

import sys

from vvaharness.backends.llm import deepagents as _deepagents
from vvaharness.models import (
    Chain,
    ContextPackage,
    DroppedFinding,
    FinalReport,
    Finding,
    RankedFinding,
    ScanMetrics,
    Severity,
)
from vvaharness.pipeline.callgraph_consumer import graph_view, qnodes_at
from vvaharness.pipeline.stages.s1_preprocess import q_file
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.util.json_extract import extract_json
from vvaharness.util.prompts import SEVERITY_GUIDANCE
from vvaharness.util.response_quality import stage_floors

SYSTEM = f"""You are an exploit development strategist reviewing verified findings
that have ALREADY PASSED adversarial verification by a security expert. Each finding
carries a TRUE_POSITIVE verdict, confidence level, and CVSS vector — use this as
authoritative ground truth. Your job is NOT to re-verify bugs or judge exploitability
directly — it's to assess what an attacker can actually DO with these bugs TOGETHER,
and to rank them by chaining opportunity.

For each finding, reassess only the CHAIN potential given:
- Is it pre-auth or post-auth? (check design controls)
- Can a prior finding (or external source) supply input to this sink?
- Does a prior finding's output become this finding's input?
- What primitive does it give? (read, write, control flow, leak, DoS only)

Then look for CHAINS — combinations more dangerous than any single bug:
- Info leak + ASLR bypass + memory corruption = full chain
- UAF + type confusion = arbitrary write
- Logic flaw bypassing auth + post-auth bug = pre-auth exploit
- New finding + known unpatched CVE = combined attack
- Reachability: Finding #A flows to Finding #B via call-graph if they share
  function neighborhoods or data flow (check the "reachability" block per finding).

If a design control genuinely blocks a chain, say so and downrank it.

Rank each finding primarily by its CVSS base score (verifier already validated it):
- CRITICAL (9.0-10.0): likely a standalone problem needing immediate patching
- HIGH (7.0-8.9): serious but may be blocked by pre-auth, sandboxing, or require a chain
- MEDIUM (4.0-6.9): chaining or multi-stage is common; look for it
- LOW (0.1-3.9): useful only in chain or as a stepping stone
- INFO: no standalone or chained exploit path visible

Respond with ONLY a JSON object:
{{
  "summary": "Executive summary, 2-4 sentences.",
  "ranked_findings": [
    {{
      "index": 0,
      "severity": "critical|high|medium|low|info",
      "exploitability_notes": "Why this severity, what controls apply."
    }}
  ],
  "chains": [
    {{
      "title": "UAF -> arb write -> RCE",
      "steps": [2, 0, 5],
      "severity": "high",
      "blocked_by_controls": ["seccomp-sandbox"],
      "narrative": "Step-by-step explanation."
    }}
  ]
}}
The 'index' and 'steps' values are 0-based indices into the findings list."""

# VVAH-E003 floors for the chain dispatch. Derived, not guessed:
#
# SYSTEM demands "ONLY a JSON object", run() dispatches only with >= 1 finding,
# and the schema wants one ranked_findings entry per finding, so the shortest
# schema-conforming reply is:
#   {"summary":"","ranked_findings":[{"index":0,"severity":"low",
#    "exploitability_notes":""}],"chains":[]}
# = 101 chars, ~26 tokens. Both are under the 150/30 global defaults, so a
# terse-but-valid single-finding "no chains to report" answer was logged as a
# degenerate response. A large scan's reply runs to kilobytes and never comes
# near the floor — the misfire is the small-finding-count tail.
#
# 90 sits just below the 101-char schema minimum and above the near-empty
# archetypes (empty body 0, one-word acknowledgement ~2, empty fenced block ~7
# chars). 15 tokens sits below the ~26 of the minimum valid reply and above the
# one-sentence-refusal archetype (~8-9 tokens).
#
# The parser is deliberately more permissive than the schema (missing keys
# coerce), so a content-bearing off-schema reply can be ~50 chars and draws one
# cosmetic warning. It cannot escalate: s8 dispatches once per scan and the
# raise needs three consecutive failures of the same tag. The coverage check
# after hydration — not this floor — is what catches a parseable reply whose
# ranked entries are all discarded.
_MIN_RESPONSE_CHARS = 90
_MIN_RESPONSE_TOKENS = 15
_TAG = "s8 chain"


def _redacted_err(e: BaseException, cap: int = 400) -> str:
    """Exception text destined for the DELIVERED report ``summary``.

    Hazard: a provider error body can quote request fragments — repository
    source or credential-shaped material — and the summary lands in the
    artifact handed to the customer, not merely a log. So the FULL text is
    redacted first and only then truncated; truncating first could bisect a
    secret so its pattern no longer matches.
    """
    return redact(str(e))[:cap]


def _reachability_for_finding(f: Finding, ctx: ContextPackage) -> str:
    """Compact reachability signature for chaining, showing source/sink refs and candidate call-graph neighborhoods."""
    graph = ctx.call_graph or {}
    if not graph:
        parts = []
        if f.source_ref:
            marker = " (inferred from AST, unverified)" if "source_ref" in f.backfilled_refs else ""
            parts.append(f"source={f.source_ref}{marker}")
        if f.sink_ref:
            marker = " (inferred from AST, unverified)" if "sink_ref" in f.backfilled_refs else ""
            parts.append(f"sink={f.sink_ref}{marker}")
        return " ".join(parts) if parts else "(no graph context)"

    # Shared, call-graph-first resolution + per-run reverse index, so the chain builder, verifier and deduper agree on reachability for the same finding.
    view = graph_view(ctx)
    cands = qnodes_at(view, f.file or "",
                      int(f.line_start or 1), int(f.line_end or f.line_start or 1),
                      limit=6)

    parts = []
    if f.source_ref:
        marker = " (inferred from AST, unverified)" if "source_ref" in f.backfilled_refs else ""
        parts.append(f"source={f.source_ref}{marker}")
    if f.sink_ref:
        marker = " (inferred from AST, unverified)" if "sink_ref" in f.backfilled_refs else ""
        parts.append(f"sink={f.sink_ref}{marker}")

    if cands:
        qn = cands[0]
        callers = (view.rev.get(qn) or [])[:3]
        callees = (graph.get(qn) or [])[:3]
        reachable = []
        if callers:
            reachable.append(f"called-by: {', '.join(callers[:2])}")
        if callees:
            reachable.append(f"calls: {', '.join(callees[:2])}")
        if reachable:
            parts.append("neighbors=" + "; ".join(reachable))

    return " ".join(parts) if parts else "(no reachability data)"


def run(findings: list[Finding], ctx: ContextPackage, cfg, *,
        dropped: list[DroppedFinding] | None = None,
        raw_findings_count: int = 0,
        metrics: ScanMetrics | None = None) -> FinalReport:
    dropped = dropped or []
    if not findings:
        # "read nothing" and "found nothing" are opposite states and must not share a summary.
        empty = metrics is not None and not metrics.total_files_in_scope
        return FinalReport(
            repo_root=ctx.repo_root,
            findings=[],
            chains=[],
            dropped=dropped,
            raw_findings_count=raw_findings_count,
            metrics=metrics,
            summary=("0 files analysed — no conclusion can be drawn about "
                     "this repository; check the S1 file inventory and "
                     "exclusions." if empty else
                     "No findings survived adversarial verification."),
            degraded=empty,
            degraded_reason=("scope was empty: 0 files reached analysis"
                             if empty else ""),
        )

    user = _build_prompt(findings, ctx)

    # The LLM call itself can fail (provider/network/timeout); mirror s7_dedup's degrade-on-Exception so the FINAL pipeline step never crashes the run.
    try:
        # cwd roots the deepagents route at the scanned repo (ctx.repo_root is
        # required here); legacy vias ignore it and keep today's kwargs.

        with stage_floors(_TAG, min_chars=_MIN_RESPONSE_CHARS,
                          min_tokens=_MIN_RESPONSE_TOKENS):
            raw = _deepagents.dispatch_prompt(
                user,
                model=cfg.models.chain,
                cfg=cfg,
                cwd=ctx.repo_root,
                system_prompt=SYSTEM,
                max_tokens=getattr(cfg.step8, "max_tokens", None),
                timeout=getattr(cfg.step8, "timeout", 1800),
                tag=_TAG,
            )
    except Exception as e:  # provider errors are heterogeneous
        print(f"  [s8] WARN: chain LLM call failed ({redact(str(e))}); "
              f"emitting unranked report.", file=sys.stderr)
        _errlog.log("s8", "chain", e)
        return _unranked_report(
            ctx, findings, dropped, raw_findings_count, metrics,
            # _redacted_err: the summary ships in the customer report — never
            # interpolate raw provider-error text (may quote source/secrets).
            summary=f"Chain analysis call failed ({_redacted_err(e)}). "
                    f"{len(findings)} verified findings reported unranked.",
        )

    # Persist the FULL raw chain response next to the errors log BEFORE parsing, so a parse/hydration failure is salvageable offline without re-spending the s8 call.
    try:
        errp = _errlog.current_path()
        stem = (errp.name[:-len("_errors.jsonl")]
                if errp.name.endswith("_errors.jsonl") else errp.stem)
        raw_path = errp.parent / f"{stem}_s8_raw.txt"
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(redact(raw or ""), encoding="utf-8")
    except OSError as e:
        print(f"  [s8] WARN: could not persist raw chain response "
              f"({redact(str(e))})", file=sys.stderr)

    # Bound before the branch that sets it: the coverage check after hydration
    # reads it on every path, and only the top-level-array recovery can set it.
    chains_only_salvage = False
    try:
        data = extract_json(raw)
        if isinstance(data, list):
            # extract_json may return a top-level array; recover it only when the elements are actually chain- or ranked-finding-shaped, else raise so we degrade cleanly.
            data = _coerce_list_payload(data)
            # A salvaged top-level chains array legitimately has no
            # ranked_findings key; the coverage check below must not
            # report that working path as a degradation.
            chains_only_salvage = "ranked_findings" not in data
        if not isinstance(data, dict):
            raise ValueError(f"expected JSON object, got {type(data).__name__}")
    # ValueError covers "no JSON found"/off-schema shapes (extract_json and
    # _coerce_list_payload raise it; json.JSONDecodeError subclasses it).
    # TypeError is the other realistic malformed-output shape: a backend that
    # yields None/bytes makes extract_json's len()/.strip() raise it — which
    # used to escape this handler and kill the run at the FINAL stage, after
    # all detection spend. Kept deliberately narrower than a bare Exception so
    # a genuine programming error in the parser still surfaces instead of
    # being silently downgraded.
    except (ValueError, TypeError) as e:
        # Redact the FULL response before truncating — slicing first could
        # bisect a secret so its pattern no longer matches (non-str raw, e.g.
        # the None that raised TypeError above, degrades to "").
        safe_raw = redact(raw) if isinstance(raw, str) else ""
        head = safe_raw[:500].replace("\n", "\\n")
        tail = safe_raw[-200:].replace("\n", "\\n")
        print(f"  [s8] WARN: chain response not parseable ({redact(str(e))}); "
              f"emitting unranked report.", file=sys.stderr)
        _errlog.log("s8", "chain", e, raw_head=head, raw_tail=tail)
        print(f"  [s8] raw[:500]  = {head!r}", file=sys.stderr)
        print(f"  [s8] raw[-200:] = {tail!r}", file=sys.stderr)
        return _unranked_report(
            ctx, findings, dropped, raw_findings_count, metrics,
            # _redacted_err: this summary ships in the customer report.
            summary=f"Chain analysis failed to parse ({_redacted_err(e)}). "
                    f"{len(findings)} verified findings reported unranked.",
        )

    # extract_json() only guarantees a dict — its *values* are still model-controlled and may be off-schema, and this hand-rolled hydration accesses them directly, so degrade to an unranked report rather than crashing.
    try:
        report, covered = _hydrate_report(
            data, ctx, findings, dropped, raw_findings_count, metrics)
    except Exception as e:  # hydration touches model JSON
        print(f"  [s8] WARN: chain hydration failed ({redact(str(e))}); "
              f"emitting unranked report.", file=sys.stderr)
        _errlog.log("s8", "chain-hydrate", e)
        return _unranked_report(
            ctx, findings, dropped, raw_findings_count, metrics,
            # _redacted_err: this summary ships in the customer report.
            summary=f"Chain analysis hydration failed ({_redacted_err(e)}). "
                    f"{len(findings)} verified findings reported unranked.",
        )

    # Coverage, not emptiness. A reply can carry ranked_findings entries that
    # every index filter in _hydrate_report discards — a string "0", an index
    # past the end, a repeat — and still leave every finding backfilled as
    # "(not ranked by chaining pass)" at INFO with report.degraded False. That
    # silent case is the one worth an error record; a legitimately salvaged
    # top-level chains array has no ranked_findings by design and must stay
    # quiet, or the record fires on working replies and desensitises the
    # artifact against the broken ones.
    if not chains_only_salvage and len(covered) < len(findings):
        head = redact(raw)[:500].replace("\n", "\\n") if isinstance(raw, str) else ""
        missing = len(findings) - len(covered)
        print(f"  [s8] WARN: chain pass ranked {len(covered)}/{len(findings)} "
              f"findings; {missing} ship unranked (severity from CVSS only). "
              f"raw[:500]={head!r}", file=sys.stderr)
        _errlog.log("s8", "chain",
                    f"chain reply ranked {len(covered)}/{len(findings)} "
                    f"findings; {missing} ship unranked",
                    raw_head=head)

    print(f"  [s8] done: {len(report.findings)} ranked findings, "
          f"{len(report.chains)} chains", file=sys.stderr)
    return report


def _coerce_list_payload(items: list) -> dict:
    """Map a top-level JSON array onto the chain-object schema when its elements are recognisably chains or ranked findings; raise ValueError otherwise."""
    dicts = [x for x in items if isinstance(x, dict)]
    if dicts and all(("steps" in x or "title" in x) for x in dicts):
        return {"chains": dicts}
    if dicts and all("index" in x for x in dicts):
        return {"ranked_findings": dicts}
    raise ValueError("top-level array is not chain- or ranked-finding-shaped")


def _unranked_report(ctx, findings, dropped, raw_findings_count, metrics,
                     *, summary: str) -> FinalReport:
    """Degraded fallback used ONLY when the exploit-chain pass could not be COMPUTED; findings keep their CVSS-anchored severity band, only the chain-pass ranking is lost."""
    ranked = [_ranked(f, _final_severity(f, Severity.INFO),
                      "(chain analysis unavailable — severity from CVSS only)")
              for f in findings]
    # Order the fallback the same way the hydrated report would, so CRITICAL/HIGH surface at the top instead of in arbitrary input order.
    order = _severity_sort_order(ranked)
    ranked = [ranked[k] for k in order]
    # orig finding index -> post-sort position, to keep "DUP of #N" correct.
    orig_to_sorted = {orig: new_i for new_i, orig in enumerate(order)}
    # Remap on FRESH copies so the caller's shared `dropped` is never mutated.
    dropped_out = [
        d.model_copy(update={"canonical_idx": orig_to_sorted[d.canonical_idx]})
        if (d.reason == "DUPLICATE" and d.canonical_idx in orig_to_sorted)
        else d
        for d in dropped
    ]
    return FinalReport(
        repo_root=ctx.repo_root,
        findings=ranked,
        chains=[],
        dropped=dropped_out,
        raw_findings_count=raw_findings_count,
        metrics=metrics,
        summary=summary,
        degraded=True,
        degraded_reason=summary,
    )


def _hydrate_report(data: dict, ctx, findings, dropped,
                    raw_findings_count, metrics) -> tuple[FinalReport, set[int]]:
    """Build the report and report WHICH finding indices the chain pass ranked.

    ``covered`` is returned because emptiness of ``ranked_findings`` is not the
    question an operator cares about: a reply can carry entries that every
    index filter below discards (string index, out of range, duplicate) and
    still leave every finding backfilled as "(not ranked by chaining pass)"
    at INFO. Only the caller comparing this set against ``findings`` can tell
    a working reply from a silently unranked one."""
    # Track the ORIGINAL finding index alongside each ranked entry: Finding has value-based __eq__, so list.index() would silently mis-map a repeated or equal-comparing entry.
    ranked: list[RankedFinding] = []
    ranked_orig_idx: list[int] = []
    covered: set[int] = set()
    # Guard against present-but-null lists (data.get returns the explicit None, which is not iterable).
    for item in data.get("ranked_findings") or []:
        if not isinstance(item, dict):
            continue
        idx = item.get("index")
        # Type-guard idx BEFORE the `< 0` comparison — a string index or other non-int raises TypeError under py3 ordered compare.
        if isinstance(idx, bool) or not isinstance(idx, int):
            continue
        if idx < 0 or idx >= len(findings) or idx in covered:
            continue
        covered.add(idx)
        # Anchor the label to the CVSS framework (environmental band first, then base); the LLM's qualitative severity is only a fallback when the finding has no CVSS vector at all.
        ranked.append(_ranked(
            findings[idx],
            _final_severity(findings[idx], _coerce_sev(item.get("severity"))),
            item.get("exploitability_notes", ""),
        ))
        ranked_orig_idx.append(idx)

    for i, f in enumerate(findings):
        if i not in covered:
            ranked.append(_ranked(f, _final_severity(f, Severity.INFO),
                                  "(not ranked by chaining pass)"))
            ranked_orig_idx.append(i)

    # Sort (ranked, orig_idx) pairs together so the orig-index mapping survives the reorder without any value-based identity lookup.
    order = _severity_sort_order(ranked)
    ranked = [ranked[k] for k in order]
    ranked_orig_idx = [ranked_orig_idx[k] for k in order]

    orig_to_sorted = {orig: new_i
                      for new_i, orig in enumerate(ranked_orig_idx)}

    chains: list[Chain] = []
    for item in data.get("chains") or []:
        if not isinstance(item, dict):
            continue
        raw_steps = item.get("steps") or []
        if not isinstance(raw_steps, list):
            raw_steps = []

        def _valid_step(s) -> bool:
            # An int (not bool) that maps to a finding in the verified set.
            return isinstance(s, int) and not isinstance(s, bool) and s in orig_to_sorted

        remapped = [orig_to_sorted[s] for s in raw_steps if _valid_step(s)]
        if len(remapped) < 2:
            continue
        narrative = item.get("narrative", "") or ""
        # Only integer indices pointing outside the verified set are meaningful "dropped" references; non-int junk is omitted and the list is capped, so a malformed/oversized steps[] can't balloon the narrative.
        dropped_steps = [s for s in raw_steps
                         if isinstance(s, int) and not isinstance(s, bool)
                         and s not in orig_to_sorted]
        if dropped_steps:
            shown = dropped_steps[:20]
            extra = "" if len(dropped_steps) <= 20 else f" (+{len(dropped_steps) - 20} more)"
            narrative = (f"{narrative}\n\n_Note: this chain referenced finding "
                         f"indices {shown}{extra} that were not in the verified "
                         "set; they have been omitted from the path above._"
                         ).strip()
        blocked = item.get("blocked_by_controls") or []
        if not isinstance(blocked, list):
            blocked = []
        chains.append(Chain(
            title=item.get("title", "Unnamed chain") or "Unnamed chain",
            steps=remapped,
            severity=_coerce_sev(item.get("severity")),
            blocked_by_controls=blocked,
            narrative=narrative,
        ))

    # Remap duplicate canonical_idx so "DUP of #N" matches post-sort order, on FRESH copies: if a later step raises, the caller's exception fallback must still see the ORIGINAL canonical_idx values.
    dropped_out = [
        d.model_copy(update={"canonical_idx": orig_to_sorted[d.canonical_idx]})
        if (d.reason == "DUPLICATE" and d.canonical_idx in orig_to_sorted)
        else d
        for d in dropped
    ]

    return (FinalReport(
        repo_root=ctx.repo_root,
        findings=ranked,
        chains=chains,
        dropped=dropped_out,
        raw_findings_count=raw_findings_count,
        metrics=metrics,
        # Coerce an off-schema (non-string) summary to "" — never its repr — so a stray value from the model can't raise ValidationError here, after findings are already reordered.
        summary=(data.get("summary") if isinstance(data.get("summary"), str) else ""),
    )), covered


def _build_prompt(findings: list[Finding], ctx: ContextPackage) -> str:
    blocks = []
    for i, f in enumerate(findings):
        cvss = f.cvss_vector or "n/a"
        verified = (f"{f.verdict} {f.verdict_confidence}/10"
                    if f.verdict else "unverified")
        reachability = _reachability_for_finding(f, ctx)
        blocks.append(
            f"[{i}] {f.vuln_class.value} @ {f.file}:{f.line_start}-{f.line_end}\n"
            f"    Title: {f.title}\n"
            f"    CVSS: {cvss}  |  Verified: {verified}\n"
            f"    Confidence: {f.confidence:.2f} ({f.votes} runs agreed)\n"
            f"    {f.description}\n"
            f"    Reachability: {reachability}\n"
        )
    findings_block = "\n".join(blocks)

    controls_block = "\n".join(
        f"  - [{c.kind}] {c.name} -> protects: {', '.join(c.protects) or 'global'}"
        for c in ctx.design_controls
    ) or "  (none)"

    cve_block = "\n".join(
        f"  - {c.id} (CVSS {c.cvss}, {'patched' if c.patched else 'UNPATCHED'}): {c.summary}"
        for c in ctx.known_cves
    ) or "  (none)"

    tm_block = ""
    if ctx.app_profile:
        tm_block += ctx.app_profile.to_prompt_block() + "\n"
    if ctx.threat_model:
        tm_block += ctx.threat_model.to_prompt_block() + "\n"

    return f"""REPO: {ctx.repo_root}

{tm_block}DESIGN CONTROLS:
{controls_block}

KNOWN CVEs (check for combinations with new findings):
{cve_block}

FINDINGS (indices are 0-based):
{findings_block}

Analyze and respond with ONLY the JSON object."""


_CVSS_BAND_TO_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _sev_from_band(rating: str | None) -> Severity | None:
    """Map a CVSS qualitative band string to a Severity, or None for a missing band so the caller can fall through to the next, less-contextual source."""
    return _CVSS_BAND_TO_SEV.get((rating or "").strip().lower())


def _final_severity(finding, llm_label: Severity) -> Severity:
    """Reconcile a finding's severity to the CVSS framework: VulContextSeverity (environmental) first, else base CVSS, else the LLM's qualitative label — OffensivePriority is a separate axis, never folded in."""
    return (_sev_from_band(getattr(finding, "vsvs_rating", None))
            or _sev_from_band(getattr(finding, "cvss_rating", None))
            or llm_label)


def _ranked(finding, severity: Severity, notes: str) -> RankedFinding:
    """Wrap *finding* for the report and stamp the resolved severity and notes onto the finding itself, so anything holding a bare ``Finding`` still sees them."""
    finding.severity = severity
    finding.exploitability_notes = notes
    return RankedFinding(finding=finding, severity=severity,
                         exploitability_notes=notes)


def _offensive_rank(finding) -> int:
    """OffensivePriority as a secondary sort key (P1 first, unset last), orthogonal to severity."""
    op = (getattr(finding, "offensive_priority", None) or "").strip().upper()
    return int(op[1]) if len(op) == 2 and op[0] == "P" and op[1].isdigit() else 9


_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
              Severity.LOW: 3, Severity.INFO: 4}


def _severity_sort_order(ranked: list[RankedFinding]) -> list[int]:
    """Index permutation ordering `ranked` by severity band, then OffensivePriority (P1 first) as the tie-break; shared by the hydrated report and the degraded fallback."""
    return sorted(range(len(ranked)),
                  key=lambda k: (_SEV_ORDER[ranked[k].severity],
                                 _offensive_rank(ranked[k].finding)))


def _coerce_sev(s) -> Severity:
    if not s:
        return Severity.INFO
    key = str(s).strip().lower()
    try:
        return Severity(key)
    except ValueError:
        return Severity.INFO
