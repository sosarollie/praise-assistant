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

"""Unit tests for vvaharness.util.metrics — pure aggregation helpers.

Offline & deterministic: no network, no LLM, no subprocess. The only global
state touched is util.tokens.TOKENS; an autouse fixture resets it so the full
suite is order-independent.
"""
from __future__ import annotations

import re

from vvaharness.models import (
    Chunk,
    ContextPackage,
    FinalReport,
    ScanMetrics,
    ScopeEntry,
    TaskManifest,
)
from vvaharness.util import metrics
from vvaharness.util.counters import COUNTERS
from vvaharness.util.tokens import TOKENS

# Global-state isolation: TOKENS and COUNTERS are process-wide singletons.
# Both are reset before AND after every test by the autouse fixtures in
# tests/conftest.py (_reset_token_counter / _reset_stage_counters), so neither
# prior accounting nor our own writes leak into sibling test files.


# now_iso
def test_now_iso_matches_utc_zulu_format():
    ts = metrics.now_iso()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", ts), ts


def test_now_iso_roundtrips_via_fromisoformat():
    from datetime import datetime, timezone

    ts = metrics.now_iso()
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo == timezone.utc


# _loc — counts non-blank lines, swallows OSError
def test_loc_counts_only_nonblank_lines(tmp_path):
    p = tmp_path / "code.py"
    # 3 non-blank lines, 2 blank/whitespace-only lines
    p.write_text("alpha\n\nbeta\n   \ngamma\n", encoding="utf-8")
    assert metrics._loc(p) == 3


def test_loc_empty_file_is_zero(tmp_path):
    p = tmp_path / "empty.py"
    p.write_text("", encoding="utf-8")
    assert metrics._loc(p) == 0


def test_loc_missing_file_returns_zero(tmp_path):
    # OSError path: file does not exist.
    assert metrics._loc(tmp_path / "does-not-exist.py") == 0


def test_loc_directory_returns_zero(tmp_path):
    # Opening a directory raises OSError (IsADirectoryError) -> 0.
    assert metrics._loc(tmp_path) == 0


# Helpers to build inputs for build()
def _write(repo, rel, text):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return rel


def _ctx(repo_root, all_files, excluded=None):
    return ContextPackage(
        repo_root=str(repo_root),
        language="python",
        all_files=list(all_files),
        excluded=excluded if excluded is not None else {},
    )


# build — chunk classification (risk / catchall / specialist / taint /
# threat_fallback / other), keyed on the chunk id's prefix.
def test_build_classifies_chunk_kinds(tmp_path):
    repo = tmp_path / "repo"
    f_risk = _write(repo, "src/a.py", "x = 1\n")
    f_catch = _write(repo, "src/b.py", "y = 2\n")
    f_spec = _write(repo, "src/c.py", "z = 3\n")

    manifest = TaskManifest(
        chunks=[
            Chunk(id="chunk-01", files=[f_risk]),
            Chunk(id="catchall-1", files=[f_catch]),
            # A real specialist shard's id and `specialist` attribute are
            # always set together (see s3_decompose.py's shard construction).
            Chunk(id="spec-crypto-01", files=[f_spec], specialist="crypto"),
        ],
        rationale="r",
    )
    ctx = _ctx(repo, [f_risk, f_catch, f_spec])

    m = metrics.build(
        ctx, manifest,
        repo_name="repo", start_ts="2026-01-01T00:00:00Z",
        end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )

    assert m.chunks_total == 3
    assert m.chunks_specialist == 1
    assert m.chunks_catchall == 1
    assert m.chunks_risk == 1
    # scope entries carry sorted files + classified kind
    kinds = {e.name: e.kind for e in m.scope}
    assert kinds == {
        "chunk-01": "risk",
        "catchall-1": "catchall",
        "spec-crypto-01": "specialist",
    }
    assert all(isinstance(e, ScopeEntry) for e in m.scope)


def test_build_id_prefix_wins_over_specialist_attribute_on_disagreement(tmp_path):
    # A chunk whose id starts with "catchall-" but ALSO carries a `specialist`
    # attribute is classified by the ID PREFIX (catchall), not the attribute.
    # Every real specialist shard sets id and attribute together, so this
    # only matters for a chunk where the two disagree; the id prefix wins
    # because it is the stable, inspectable per-chunk contract the rest of
    # the pipeline already keys off, while `specialist` is incidental state a
    # future code path could set without renaming the chunk.
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x = 1\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="catchall-x", files=[f], specialist="logic-bug")],
        rationale="r",
    )
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.chunks_specialist == 0
    assert m.chunks_catchall == 1
    assert m.chunks_risk == 0
    assert m.scope[0].kind == "catchall"


def test_build_taint_and_threat_fallback_chunks_are_not_counted_as_risk(tmp_path):
    # This is the defect the reclassification fixes: taint-derived and
    # threat-model-fallback chunks never set `specialist` and do not start
    # with "catchall-", so the old logic counted them as "risk" -- meaning a
    # report could not tell an operator whether the risk-ranking model call
    # (the actual "chunk-*" chunks) had run at all.
    repo = tmp_path / "repo"
    f_taint = _write(repo, "app/handlers.py", "x = 1\n")
    f_fallback = _write(repo, "app/routes.py", "y = 2\n")
    f_risk = _write(repo, "app/util.py", "z = 3\n")

    manifest = TaskManifest(
        chunks=[
            Chunk(id="taint-01", files=[f_taint]),
            Chunk(id="threat-t1-fallback", files=[f_fallback]),
            Chunk(id="chunk-01", files=[f_risk]),
        ],
        rationale="r",
    )
    ctx = _ctx(repo, [f_taint, f_fallback, f_risk])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    # Only the "chunk-01" chunk is "risk" now.
    assert m.chunks_risk == 1
    kinds = {e.name: e.kind for e in m.scope}
    assert kinds == {
        "taint-01": "taint",
        "threat-t1-fallback": "threat_fallback",
        "chunk-01": "risk",
    }
    assert m.chunks_by_kind == {"taint": 1, "threat_fallback": 1, "risk": 1}


def test_build_classifies_one_chunk_of_each_five_kinds_into_five_buckets(tmp_path):
    repo = tmp_path / "repo"
    files = {
        name: _write(repo, f"{name}.py", "x = 1\n")
        for name in ("taint", "catchall", "spec", "threat", "chunk")
    }
    manifest = TaskManifest(
        chunks=[
            Chunk(id="taint-01", files=[files["taint"]]),
            Chunk(id="catchall-1", files=[files["catchall"]]),
            Chunk(id="spec-crypto-01", files=[files["spec"]], specialist="crypto"),
            Chunk(id="threat-t9-fallback", files=[files["threat"]]),
            Chunk(id="chunk-01", files=[files["chunk"]]),
        ],
        rationale="r",
    )
    ctx = _ctx(repo, list(files.values()))
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.chunks_by_kind == {
        "taint": 1, "catchall": 1, "specialist": 1, "threat_fallback": 1, "risk": 1,
    }
    assert m.chunks_risk == 1  # counts exactly the "chunk-" chunk
    assert len({e.kind for e in m.scope}) == 5


def test_build_classifies_unrecognised_id_prefix_as_other_and_counts_it(tmp_path):
    # A chunk id that matches none of the five known prefixes must be visible
    # as its own bucket rather than silently folded into "risk".
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x = 1\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="weird-shape-01", files=[f])],
        rationale="r",
    )
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.scope[0].kind == "other"
    assert m.chunks_by_kind == {"other": 1}
    assert m.chunks_risk == 0
    assert m.chunks_catchall == 0
    assert m.chunks_specialist == 0


# build — analyzed-file coverage (only files that are also in ctx.all_files)
def test_build_analyzed_unique_intersects_scope(tmp_path):
    repo = tmp_path / "repo"
    a = _write(repo, "a.py", "x=1\n")
    b = _write(repo, "b.py", "y=2\n")
    # "ghost.py" is referenced by a chunk but NOT in all_files -> excluded.
    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=[a, b, "ghost.py"])],
        rationale="r",
    )
    ctx = _ctx(repo, [a, b])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.total_files_in_scope == 2
    # ghost.py is analyzed but not in scope -> not counted
    assert m.analyzed_files_unique == 2


def test_build_folders_scanned_includes_dot_and_dirs(tmp_path):
    repo = tmp_path / "repo"
    top = _write(repo, "top.py", "a=1\n")          # no slash -> not a folder
    nested = _write(repo, "pkg/sub/mod.py", "b=2\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=[top, nested])],
        rationale="r",
    )
    ctx = _ctx(repo, [top, nested])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert "." in m.folders_scanned
    assert "pkg/sub" in m.folders_scanned
    # sorted output
    assert m.folders_scanned == sorted(m.folders_scanned)


# build — LOC by language (in-scope vs scanned)
def test_build_loc_by_language_scope_vs_scanned(tmp_path):
    repo = tmp_path / "repo"
    # 2 python files, only one analyzed; 1 unknown-ext file -> "other"
    py_scanned = _write(repo, "scanned.py", "a\nb\nc\n")     # 3 loc
    py_unscanned = _write(repo, "skipped.py", "x\ny\n")      # 2 loc
    other = _write(repo, "data.unknownext", "k\n")           # 1 loc -> other

    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=[py_scanned])],
        rationale="r",
    )
    ctx = _ctx(repo, [py_scanned, py_unscanned, other])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.loc_in_scope_by_language["python"] == 5   # 3 + 2
    assert m.loc_scanned_by_language["python"] == 3     # only scanned.py
    assert m.loc_in_scope_by_language["other"] == 1
    # "other" not analyzed -> absent or zero in scanned map
    assert m.loc_scanned_by_language.get("other", 0) == 0


# build — duration parsing (happy + malformed timestamps)
def test_build_duration_from_valid_timestamps(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:01:30Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.duration_sec == 90.0


def test_build_duration_zero_on_malformed_timestamp(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="not-a-timestamp", end_ts="also-bad",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.duration_sec == 0.0


# build — token accounting (available vs unavailable)
def test_build_tokens_unavailable_when_no_usage(tmp_path):
    # No TOKENS.add(dict) call -> calls_with_usage == 0 -> token fields None.
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.prompt_tokens is None
    assert m.completion_tokens is None
    assert m.total_tokens is None
    assert m.tokens_by_phase is None


def test_build_tokens_populated_from_usage(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])

    # Record real usage on the global counter under a labelled phase.
    with TOKENS.phase("s4"):
        TOKENS.add({
            "input_tokens": 100,
            "cache_creation_input_tokens": 20,
            "cache_read_input_tokens": 5,
            "output_tokens": 40,
        })

    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    # prompt = fresh + cache-write = 100 + 20
    assert m.prompt_tokens == 120
    assert m.completion_tokens == 40
    assert m.total_tokens == 160
    assert m.tokens_by_phase is not None
    assert m.tokens_by_phase["s4"]["prompt"] == 120
    assert m.tokens_by_phase["s4"]["completion"] == 40
    assert m.tokens_by_phase["s4"]["cache_read"] == 5


# refresh_tokens — the post-s8 re-snapshot
def test_refresh_tokens_picks_up_spend_after_build(tmp_path):
    """build() runs before s8, so s8's own phase must land via refresh."""
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])

    with TOKENS.phase("s4-deepdive"):
        TOKENS.add({"input_tokens": 100, "output_tokens": 40})
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:10Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.tokens_by_phase is not None
    assert "s8-chain" not in m.tokens_by_phase

    with TOKENS.phase("s8-chain"):
        TOKENS.add({"input_tokens": 10, "output_tokens": 5})
    metrics.refresh_tokens(m, end_ts="2026-01-01T00:00:30Z")

    assert m.prompt_tokens == 110
    assert m.completion_tokens == 45
    assert m.total_tokens == 155
    assert m.tokens_by_phase["s8-chain"]["prompt"] == 10
    assert m.end_ts == "2026-01-01T00:00:30Z"
    assert m.duration_sec == 30.0


def test_refresh_tokens_keeps_end_ts_when_not_supplied(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    m = metrics.build(
        _ctx(repo, [f]), manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:10Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    metrics.refresh_tokens(m)
    assert m.end_ts == "2026-01-01T00:00:10Z"
    assert m.duration_sec == 10.0


def test_refresh_tokens_leaves_unavailable_tokens_as_none(tmp_path):
    """No call reported usage: "unavailable" must not become 0."""
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    m = metrics.build(
        _ctx(repo, [f]), manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:10Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    metrics.refresh_tokens(m, end_ts="2026-01-01T00:00:20Z")
    assert m.prompt_tokens is None
    assert m.total_tokens is None
    assert m.tokens_by_phase is None
    assert m.end_ts == "2026-01-01T00:00:20Z"


def test_refresh_tokens_on_none_metrics_is_a_noop():
    """A --resume can load a report whose metrics were never built."""
    metrics.refresh_tokens(None, end_ts="2026-01-01T00:00:00Z")


# build — identity / passthrough fields
def test_build_scan_id_and_counts_and_excluded(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    excluded = {"dirs": {"vendor": 12}, "oversize": 3}
    ctx = _ctx(repo, [f], excluded=excluded)
    m = metrics.build(
        ctx, manifest, repo_name="acme-svc",
        start_ts="2026-03-04T05:06:07Z", end_ts="2026-03-04T05:06:08Z",
        raw_findings=10, true_pos=6, false_pos=3, duplicates=1,
    )
    assert m.scan_id == "2026-03-04T05:06:07Z__acme-svc"
    assert m.module_name == "acme-svc"
    assert m.raw_findings_count == 10
    assert m.true_positive_count == 6
    assert m.false_positive_count == 3
    assert m.duplicate_count == 1
    assert m.excluded == excluded


def test_build_excluded_none_coerced_to_empty_dict(tmp_path):
    # ctx.excluded falsy -> `ctx.excluded or {}` yields {}.
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f], excluded={})
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.excluded == {}


def test_build_empty_manifest_no_chunks(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[], rationale="r")
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.chunks_total == 0
    assert m.chunks_risk == 0
    assert m.analyzed_files_unique == 0
    # No analyzed files -> folders is just "."
    assert m.folders_scanned == ["."]
    assert m.scope == []


# build — chunk-outcome health tally (a failed/timed-out chunk must surface)
def test_build_chunk_outcomes_tally_and_health_render(tmp_path):
    repo = tmp_path / "repo"
    fa = _write(repo, "a.py", "x=1\n")
    fb = _write(repo, "b.py", "y=2\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=[fa]),
                Chunk(id="chunk-02", files=[fb])],
        rationale="r")
    ctx = _ctx(repo, [fa, fb])
    m = metrics.build(
        ctx, manifest, repo_name="repo",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
        chunk_outcomes={"chunk-01": "completed", "chunk-02": "error"},
    )
    assert m.chunks_attempted == 2
    assert m.chunks_failed == 1
    # The degraded-coverage warning is surfaced in the rendered report.
    rep = FinalReport(repo_root=str(repo), findings=[], chains=[],
                      raw_findings_count=0, metrics=m, summary="s")
    md = rep.to_markdown()
    assert "## Scan Health" in md
    assert "1/2" in md and "failed or timed out" in md


def test_scan_metrics_markdown_labels_unscoped_token_phase(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    m = ScanMetrics(
        scan_id="s",
        module_name="repo",
        start_ts="2026-01-01T00:00:00Z",
        end_ts="2026-01-01T00:00:01Z",
        duration_sec=1.0,
        total_files_in_scope=0,
        analyzed_files_unique=0,
        chunks_total=0,
        chunks_risk=0,
        chunks_catchall=0,
        chunks_specialist=0,
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        tokens_by_phase={
            "unlabeled": {
                "calls": 1,
                "prompt": 10,
                "completion": 5,
                "cache_read": 0,
                "cache_write": 0,
            }
        },
    )
    rep = FinalReport(repo_root=str(repo), findings=[], chains=[],
                      raw_findings_count=0, metrics=m, summary="s")
    md = rep.to_markdown()
    assert "unscoped (outside stage wrapper)" in md
    assert "| unlabeled |" not in md


def test_build_no_outcomes_reports_zero_failures(tmp_path):
    # A legacy --resume with no outcome data must not raise a false alarm.
    repo = tmp_path / "repo"
    fa = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="chunk-01", files=[fa])], rationale="r")
    ctx = _ctx(repo, [fa])
    m = metrics.build(
        ctx, manifest, repo_name="repo",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.chunks_failed == 0


# build — file-level coverage must not vouch for files whose every hosting
# chunk failed: a failed chunk produced NO findings for its files, so counting
# them as analyzed overstates assurance while chunks_failed discloses the loss.
def test_build_failed_chunk_files_are_not_counted_as_analyzed(tmp_path):
    repo = tmp_path / "repo"
    fa = _write(repo, "a.py", "x=1\n")
    fb = _write(repo, "b.py", "y=2\n")
    shared = _write(repo, "shared.py", "z=3\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=[fa, shared]),
                Chunk(id="chunk-02", files=[fb, shared])],
        rationale="r")
    ctx = _ctx(repo, [fa, fb, shared])
    m = metrics.build(
        ctx, manifest, repo_name="repo",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
        chunk_outcomes={"chunk-01": "completed", "chunk-02": "error"},
    )
    # b.py lived ONLY in the failed chunk -> not analyzed; shared.py is still
    # covered because a completed chunk also carried it.
    assert m.analyzed_files_unique == 2
    assert m.chunks_failed == 1
    # Derived views follow the honest set: only a.py + shared.py were scanned.
    assert m.loc_scanned_by_language["python"] == 2
    assert m.loc_in_scope_by_language["python"] == 3


def test_build_skipped_chunk_files_not_analyzed_but_not_failed(tmp_path):
    # "skipped" is a designed outcome (chunk deliberately never sent): it must
    # not count as a failure, but it vouches for no file either.
    repo = tmp_path / "repo"
    fa = _write(repo, "a.py", "x=1\n")
    fb = _write(repo, "b.py", "y=2\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=[fa]),
                Chunk(id="chunk-02", files=[fb])],
        rationale="r")
    ctx = _ctx(repo, [fa, fb])
    m = metrics.build(
        ctx, manifest, repo_name="repo",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
        chunk_outcomes={"chunk-01": "completed", "chunk-02": "skipped"},
    )
    assert m.chunks_failed == 0
    assert m.analyzed_files_unique == 1


def test_build_chunk_without_recorded_outcome_still_counts_its_files(tmp_path):
    # Treat-as-clean parity with chunks_failed: an outcome dict that simply
    # lacks a chunk id (legacy checkpoint) must not shrink coverage.
    repo = tmp_path / "repo"
    fa = _write(repo, "a.py", "x=1\n")
    fb = _write(repo, "b.py", "y=2\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=[fa]),
                Chunk(id="chunk-02", files=[fb])],
        rationale="r")
    ctx = _ctx(repo, [fa, fb])
    m = metrics.build(
        ctx, manifest, repo_name="repo",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
        chunk_outcomes={"chunk-01": "error"},   # chunk-02 unrecorded
    )
    assert m.analyzed_files_unique == 1          # b.py counted, a.py not
    assert m.chunks_failed == 1


# build — process-wide counter fields (vvaharness.util.counters.COUNTERS),
# read once here exactly like TOKENS and errlog.counts_by_stage() above.
def _min_build(tmp_path, **kw):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="chunk-01", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])
    return metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
        **kw,
    )


def test_build_populates_plain_int_counters_when_stages_reported_them(tmp_path):
    COUNTERS.bump("s2_threats_raw", 12)
    COUNTERS.bump("s3_dropped_paths", 3)
    COUNTERS.bump("s3_dropped_paths", 2)  # additive
    m = _min_build(tmp_path)
    assert m.s2_threats_raw == 12
    assert m.s3_dropped_paths == 5


def test_build_leaves_int_counters_at_their_default_when_stage_never_ran(tmp_path):
    # Nothing bumped "s3_cohesion_groups" -> the field keeps its declared
    # default (0), which must not be confused with "ran and found none".
    m = _min_build(tmp_path)
    assert m.s3_cohesion_groups == 0
    assert m.s3_buckets == 0
    assert m.s3_unknown_file_ids == 0


def test_build_populates_s4_findings_truncated_from_counter(tmp_path):
    COUNTERS.bump("s4_findings_truncated", 2)
    COUNTERS.bump("s4_findings_truncated", 3)  # additive across s4 calls
    m = _min_build(tmp_path)
    assert m.s4_findings_truncated == 5


def test_build_s4_findings_truncated_defaults_zero_when_never_bumped(tmp_path):
    m = _min_build(tmp_path)
    assert m.s4_findings_truncated == 0


def test_build_populates_deepagents_oversize_prompts_from_counter(tmp_path):
    COUNTERS.bump("deepagents_oversize_prompts", 2)
    COUNTERS.bump("deepagents_oversize_prompts")  # additive across refusals
    m = _min_build(tmp_path)
    assert m.deepagents_oversize_prompts == 3


def test_build_deepagents_oversize_prompts_defaults_zero_when_never_bumped(tmp_path):
    m = _min_build(tmp_path)
    assert m.deepagents_oversize_prompts == 0


def test_build_populates_llm_truncated_replies_from_counter(tmp_path):
    COUNTERS.bump("llm_truncated_replies", 2)
    COUNTERS.bump("llm_truncated_replies")  # additive across truncations
    m = _min_build(tmp_path)
    assert m.llm_truncated_replies == 3


def test_build_llm_truncated_replies_defaults_zero_when_never_bumped(tmp_path):
    m = _min_build(tmp_path)
    assert m.llm_truncated_replies == 0


def test_build_s2_degraded_is_bool_from_a_nonzero_bump_count(tmp_path):
    COUNTERS.bump("s2_degraded")
    m = _min_build(tmp_path)
    assert m.s2_degraded is True


def test_build_s2_degraded_defaults_false_when_never_bumped(tmp_path):
    m = _min_build(tmp_path)
    assert m.s2_degraded is False


def test_build_splits_comma_joined_note_into_list_str(tmp_path):
    COUNTERS.note("s2_baseline_undisposed", "B002,B001,B010")
    COUNTERS.note("s2_repo_kinds", "library,service")
    m = _min_build(tmp_path)
    assert m.s2_baseline_undisposed == ["B002", "B001", "B010"]
    assert m.s2_repo_kinds == ["library", "service"]


def test_build_empty_note_yields_empty_list_not_list_with_blank_string(tmp_path):
    # "ran and found none" (note called with "") must stay [], not [""].
    COUNTERS.note("s2_baseline_undisposed", "")
    m = _min_build(tmp_path)
    assert m.s2_baseline_undisposed == []


def test_build_list_str_counters_default_empty_when_stage_never_ran(tmp_path):
    m = _min_build(tmp_path)
    assert m.s2_baseline_undisposed == []
    assert m.s2_repo_kinds == []


def test_build_populates_s3_output_shape_string_note(tmp_path):
    COUNTERS.note("s3_output_shape", "ids")
    m = _min_build(tmp_path)
    assert m.s3_output_shape == "ids"


def test_build_s3_output_shape_defaults_empty_string_when_stage_never_ran(tmp_path):
    m = _min_build(tmp_path)
    assert m.s3_output_shape == ""


def test_build_chunks_by_kind_is_computed_from_chunks_not_from_counters(tmp_path):
    # chunks_by_kind is a property of the manifest's own chunks, not an event
    # a stage reports through COUNTERS -- bumping an unrelated counter must
    # not affect it.
    COUNTERS.bump("s3_dropped_paths", 7)
    m = _min_build(tmp_path)  # single "chunk-01" chunk
    assert m.chunks_by_kind == {"risk": 1}


# ScanMetrics derived properties (pure aggregations)
def test_coverage_pct_normal():
    m = ScanMetrics(total_files_in_scope=4, analyzed_files_unique=1)
    assert m.coverage_pct == 25.0


def test_coverage_pct_zero_scope_guard():
    m = ScanMetrics(total_files_in_scope=0, analyzed_files_unique=0)
    assert m.coverage_pct == 0.0


def test_verification_precision_pct_normal():
    m = ScanMetrics(raw_findings_count=10, true_positive_count=7)
    assert m.verification_precision_pct == 70.0


def test_verification_precision_pct_zero_raw_guard():
    m = ScanMetrics(raw_findings_count=0, true_positive_count=0)
    assert m.verification_precision_pct == 0.0
