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
Build ScanMetrics from pipeline state. Kept out of the orchestrator so the main
flow stays readable.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from vvaharness.lang.hints import EXT_TO_LANG
from vvaharness.models import Chunk, ContextPackage, ScanMetrics, ScopeEntry, TaskManifest
from vvaharness.util import errlog
from vvaharness.util.counters import COUNTERS
from vvaharness.util.tokens import TOKENS


# Ordered most-specific-prefix-first. A chunk id that matches none of these
# falls into "other" -- counted rather than silently absorbed into "risk", so
# a future chunk-naming convention shows up as a visible sixth bucket instead
# of corrupting the risk-chunk count the way taint/threat-fallback ids used to.
_KIND_PREFIXES = (
    ("taint-", "taint"),
    ("catchall-", "catchall"),
    ("spec-", "specialist"),
    ("threat-", "threat_fallback"),
    ("chunk-", "risk"),
)


def _classify_chunk_kind(c: Chunk) -> str:
    """Classify a chunk's analysis kind from its id prefix, not from the
    ``specialist`` attribute.

    The two signals agree at every real construction site (a specialist shard
    is built with id ``spec-<name>-<NN>`` AND ``specialist=<name>`` set
    together), so this only matters for a chunk where they disagree -- and in
    that case the id prefix wins. The prefix is the stable, inspectable
    contract the rest of the pipeline already keys off (chunk ordering,
    fallback detection, catch-all handling); the attribute is incidental state
    that a future code path could set without also renaming the chunk. Keying
    off the attribute is also what caused taint-derived and threat-model
    fallback chunks -- which never set ``specialist`` -- to be miscounted as
    "risk" chunks, hiding whether the risk-ranking model call had run at all.
    """
    cid = c.id
    for prefix, kind in _KIND_PREFIXES:
        if cid.startswith(prefix):
            return kind
    return "other"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _elapsed_sec(start_ts: str, end_ts: str) -> float:
    try:
        s = datetime.fromisoformat(start_ts.replace("Z", "+00:00"))
        e = datetime.fromisoformat(end_ts.replace("Z", "+00:00"))
        return (e - s).total_seconds()
    except Exception:
        return 0.0


def refresh_tokens(metrics: ScanMetrics | None, *,
                   end_ts: str | None = None) -> None:
    """Re-snapshot TOKENS into an already-built ScanMetrics, in place.

    build() has to run BEFORE s8 so the chain stage can render the metrics block
    into the report, which leaves those metrics blind to s8's own spend (and to
    anything after it). Calling this once s8 has returned makes the persisted
    metrics cover every stage that has run so far.

    Leaves the token fields alone when no call reported usage — build() sets them
    to None in that case, and "unavailable" must not silently become 0. A None
    *metrics* (a --resume that loaded a report without them) is a no-op.
    """
    if metrics is None:
        return
    if end_ts:
        metrics.end_ts = end_ts
        metrics.duration_sec = _elapsed_sec(metrics.start_ts, end_ts)
    tok = TOKENS.snapshot()
    if tok["calls_with_usage"] <= 0:
        return
    metrics.prompt_tokens = tok["prompt"]
    metrics.completion_tokens = tok["completion"]
    metrics.total_tokens = tok["total"]
    metrics.tokens_by_phase = tok.get("by_phase")


def build(ctx: ContextPackage, manifest: TaskManifest, *,
          repo_name: str, start_ts: str, end_ts: str,
          raw_findings: int, true_pos: int, false_pos: int,
          duplicates: int,
          chunk_outcomes: dict[str, str] | None = None) -> ScanMetrics:
    repo_root = Path(ctx.repo_root)

    # File coverage: every file that appears in at least one chunk whose
    # deep-dive actually completed. A file whose every hosting chunk failed
    # produced NO findings, so counting it as analyzed would overstate the
    # assurance the coverage number exists to convey — chunk-level failures
    # are disclosed (Scan Health, SARIF), and this keeps the file-level
    # number consistent with them. A chunk with no recorded outcome (a legacy
    # --resume predating outcome tracking, or a scan stopped before s4) is
    # counted, matching the treat-as-clean convention chunks_failed uses
    # below. A "skipped" chunk was deliberately never sent, so it vouches for
    # no file either — in practice it has no resolvable files to contribute.
    outcomes = chunk_outcomes or {}
    analyzed: set[str] = set()
    scope: list[ScopeEntry] = []
    kind_counts: dict[str, int] = defaultdict(int)
    for c in manifest.chunks:
        if outcomes.get(c.id, "completed") == "completed":
            analyzed.update(c.files)
        kind = _classify_chunk_kind(c)
        kind_counts[kind] += 1
        scope.append(ScopeEntry(name=c.id, kind=kind, files=sorted(c.files)))
    # Back-compat tallies for reports rendered before the wider kind set
    # existed. They now count ONLY their own bucket (kind_counts["risk"] is
    # exactly the "chunk-" chunks) rather than lumping taint/threat-fallback
    # chunks into "risk" the way the old id-prefix-then-catchall logic did.
    n_spec = kind_counts.get("specialist", 0)
    n_catch = kind_counts.get("catchall", 0)
    n_risk = kind_counts.get("risk", 0)

    folders = sorted({str(Path(f).parent).replace("\\", "/")
                      for f in analyzed if "/" in f or "\\" in f} | {"."})

    # LOC by language (in-scope vs scanned).
    loc_scope: dict[str, int] = defaultdict(int)
    loc_scan: dict[str, int] = defaultdict(int)
    for f in ctx.all_files:
        lang = EXT_TO_LANG.get(Path(f).suffix.lower(), "other")
        loc = _loc(repo_root / f)
        loc_scope[lang] += loc
        if f in analyzed:
            loc_scan[lang] += loc

    dur = _elapsed_sec(start_ts, end_ts)

    tok = TOKENS.snapshot()
    tok_avail = tok["calls_with_usage"] > 0

    # Deep-dive chunk outcomes (authoritative failure count comes from here, not
    # from the coarse per-stage error log). Absent on a legacy --resume that
    # predates outcome-tracking → treat as clean (0 failed), no false alarm.
    chunks_attempted = len(manifest.chunks)
    # "skipped" is a DESIGNED outcome, not a failure: a chunk left with no
    # resolvable files is deliberately not sent to the model. Counting it here
    # made the report announce "N chunks failed or timed out — their findings
    # are absent", which is both wrong and alarming. It shows up in practice on
    # a resumed run whose checkpoint was written before emptied chunks were
    # dropped, so those are exactly the chunks that survive into it.
    chunks_failed = sum(1 for v in outcomes.values()
                        if v not in ("completed", "skipped"))

    # Process-wide event counters that stages bump/note while they run (see
    # vvaharness.util.counters) -- read once, here, exactly like TOKENS and
    # errlog.counts_by_stage() above, because no ScanMetrics instance exists
    # yet while s2/s3 are running and the underlying facts (a dropped file
    # reference, a truncated threat list) are not recoverable from the
    # finished manifest. A stage that never ran leaves its name out of the
    # snapshot entirely, and only the keys actually present are passed to the
    # constructor below.
    #
    # Be clear about what that does and does not buy: the declared defaults are
    # 0/""/[], so a consumer reading a finished ScanMetrics still CANNOT tell
    # "never ran" from "ran and reported zero" — the two are byte-identical.
    # Distinguishing them would mean making every counter field optional and
    # teaching the renderer a third state, which is not worth it while the
    # renderer already shows only non-empty values. What this does buy is that
    # `build()` never invents a measurement for a stage that produced none.
    counters = COUNTERS.snapshot()
    counter_fields: dict[str, object] = {}

    _int_counter_names = (
        "s2_threats_raw", "s2_threats_truncated", "s2_threats_promoted",
        "s3_unknown_file_ids", "s3_dropped_paths", "s3_relocated_paths",
        "s3_dropped_empty_chunks", "s3_forced_coverage_files",
        "s3_fallback_chunks_dropped", "s3_cohesion_groups", "s3_buckets",
        "s4_findings_truncated",
        "deepagents_oversize_prompts",
        "llm_truncated_replies",
    )
    for name in _int_counter_names:
        if name in counters:
            counter_fields[name] = counters[name]

    # s2_degraded is declared as bool on ScanMetrics, not int: the stage bumps
    # a count of degradation events, and any nonzero count means the run
    # degraded at least once.
    if "s2_degraded" in counters:
        counter_fields["s2_degraded"] = bool(counters["s2_degraded"])

    # Recorded as comma-joined strings via COUNTERS.note (these are ids/kinds,
    # not counts) -- split back into the list[str] shape the field declares.
    # An empty note ("" -- nothing to join) means "ran and found none," which
    # must stay [] rather than [""].
    for name in ("s2_baseline_undisposed", "s2_repo_kinds"):
        if name in counters:
            raw = counters[name]
            counter_fields[name] = raw.split(",") if raw else []

    if "s3_output_shape" in counters:
        counter_fields["s3_output_shape"] = counters["s3_output_shape"]

    return ScanMetrics(
        scan_id=f"{start_ts}__{repo_name}",
        module_name=repo_name,
        start_ts=start_ts,
        end_ts=end_ts,
        duration_sec=dur,
        total_files_in_scope=len(ctx.all_files),
        analyzed_files_unique=len(analyzed & set(ctx.all_files)),
        chunks_total=len(manifest.chunks),
        chunks_risk=n_risk,
        chunks_catchall=n_catch,
        chunks_specialist=n_spec,
        chunks_attempted=chunks_attempted,
        chunks_failed=chunks_failed,
        errors_by_stage=errlog.counts_by_stage(),
        errors_log_path=str(errlog.current_path()),
        loc_in_scope_by_language=dict(loc_scope),
        loc_scanned_by_language=dict(loc_scan),
        raw_findings_count=raw_findings,
        true_positive_count=true_pos,
        false_positive_count=false_pos,
        duplicate_count=duplicates,
        prompt_tokens=tok["prompt"] if tok_avail else None,
        completion_tokens=tok["completion"] if tok_avail else None,
        total_tokens=tok["total"] if tok_avail else None,
        tokens_by_phase=tok.get("by_phase") if tok_avail else None,
        folders_scanned=folders,
        scope=scope,
        excluded=ctx.excluded or {},
        # Per-kind tally across the widened kind set, computed here (not read
        # from the counter sink) because it is a property of the manifest's
        # own chunks, not an event a stage reports mid-run.
        chunks_by_kind=dict(kind_counts),
        **counter_fields,
    )


def _loc(p: Path) -> int:
    try:
        return sum(1 for ln in p.open("r", encoding="utf-8", errors="replace")
                   if ln.strip())
    except OSError:
        return 0
