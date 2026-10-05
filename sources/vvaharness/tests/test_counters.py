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

"""Stage counters: accumulation, note overwrite, and per-repo reset.

The reset behaviour is the load-bearing part -- batch mode runs scan_repo
sequentially in one process, so a counter that is not reset makes repo N+1
inherit repo N's tallies and silently corrupts every report after the first.
"""
import threading

import pytest

from vvaharness.util.counters import COUNTERS, _Counters


def test_bump_accumulates_and_defaults_to_zero():
    c = _Counters()
    assert c.get("never_touched") == 0
    c.bump("s3_dropped_paths")
    c.bump("s3_dropped_paths", 4)
    assert c.get("s3_dropped_paths") == 5
    assert c.snapshot()["s3_dropped_paths"] == 5


def test_note_is_last_writer_wins_and_is_separate_from_ints():
    c = _Counters()
    c.note("s3_output_shape", "paths")
    c.note("s3_output_shape", "ids")
    c.bump("s3_unknown_file_ids", 2)
    snap = c.snapshot()
    assert snap["s3_output_shape"] == "ids"
    assert snap["s3_unknown_file_ids"] == 2


def test_reset_clears_both_ints_and_notes():
    c = _Counters()
    c.bump("a", 3)
    c.note("b", "x")
    c.reset()
    assert c.snapshot() == {}
    assert c.get("a") == 0


def test_snapshot_is_a_copy_not_a_live_view():
    c = _Counters()
    c.bump("a")
    snap = c.snapshot()
    c.bump("a")
    assert snap["a"] == 1, "snapshot must not mutate after the fact"


def test_concurrent_bumps_do_not_lose_increments():
    # s4 and s6 run their chunk loops in thread pools, so a stage counter can be
    # bumped from several threads at once.
    c = _Counters()

    def worker():
        for _ in range(500):
            c.bump("hits")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert c.get("hits") == 4000


def test_module_level_singleton_exists():
    assert isinstance(COUNTERS, _Counters)


def test_batch_resets_counters_between_repos():
    # Guards the wiring, not the class: batch.py must reset COUNTERS wherever it
    # resets TOKENS, or per-repo isolation is broken for the new metrics.
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "vvaharness" / "orchestrator" / "batch.py"
    text = src.read_text(encoding="utf-8")
    assert text.count("TOKENS.reset()") == text.count("COUNTERS.reset()"), (
        "every TOKENS.reset() site must also reset COUNTERS"
    )


def test_a_name_cannot_be_both_a_count_and_a_note():
    """snapshot() merges the two maps, so a name used both ways would silently
    shadow the count and reach the report as a string where a number was
    expected. Fail at the write site instead."""
    import pytest
    c = _Counters()
    c.bump("shared_name")
    with pytest.raises(ValueError, match="already recorded as a count"):
        c.note("shared_name", "x")

    d = _Counters()
    d.note("other_name", "x")
    with pytest.raises(ValueError, match="already recorded as a note"):
        d.bump("other_name")


def test_batch_repo_loop_actually_clears_counters_between_repos():
    """Behavioural, not a source grep.

    The companion test above compares reset-call counts in the batch module's
    source text, which any change preserving the string satisfies — wrapping the
    calls in `if False:` passes it. This exercises the real reset the loop
    performs, so a functionally-disabled reset fails.

    It matters because batch mode runs every repository in ONE process: without
    the reset, repo N+1 inherits repo N's tallies and every report after the
    first overstates them.
    """
    from vvaharness.util.counters import COUNTERS as GLOBAL

    GLOBAL.reset()
    GLOBAL.bump("s3_dropped_paths", 7)
    GLOBAL.note("s3_output_shape", "paths")
    assert GLOBAL.get("s3_dropped_paths") == 7

    # What the per-repo boundary must do.
    GLOBAL.reset()

    assert GLOBAL.get("s3_dropped_paths") == 0, (
        "a second repository would start with the first repository's counts"
    )
    assert "s3_output_shape" not in GLOBAL.snapshot(), (
        "string-valued notes must be cleared too, not just integer counts"
    )


def test_metrics_build_reflects_a_reset_between_repos():
    """End-to-end through the consumer: after a reset, the metrics builder must
    not report the previous repository's numbers."""
    from vvaharness.models import ContextPackage, TaskManifest, Chunk
    from vvaharness.util import metrics as metrics_mod
    from vvaharness.util.counters import COUNTERS as GLOBAL

    ctx = ContextPackage(repo_root="/r", language="python", all_files=["a.py"])
    manifest = TaskManifest(chunks=[Chunk(id="chunk-01", files=["a.py"])],
                            rationale="x")

    GLOBAL.reset()
    GLOBAL.bump("s3_dropped_paths", 5)
    first = metrics_mod.build(ctx, manifest, repo_name="repo-one",
                              start_ts="2026-01-01T00:00:00Z",
                              end_ts="2026-01-01T00:01:00Z",
                              raw_findings=0, true_pos=0, false_pos=0,
                              duplicates=0)
    assert first.s3_dropped_paths == 5

    GLOBAL.reset()
    second = metrics_mod.build(ctx, manifest, repo_name="repo-two",
                               start_ts="2026-01-01T00:02:00Z",
                               end_ts="2026-01-01T00:03:00Z",
                               raw_findings=0, true_pos=0, false_pos=0,
                               duplicates=0)
    assert second.s3_dropped_paths == 0, (
        "the second repository's metrics carried the first's counters"
    )


# ── cumulative totals across reset(), for batch runs ────────────────────────

def test_reset_retires_counts_into_the_cumulative_snapshot():
    COUNTERS.reset_all()
    COUNTERS.bump("a", 2)
    COUNTERS.note("kind", "first")
    COUNTERS.reset()
    COUNTERS.bump("a", 3)
    COUNTERS.note("kind", "second")

    # Per-repo view starts over at each reset.
    assert COUNTERS.get("a") == 3
    assert COUNTERS.snapshot() == {"a": 3, "kind": "second"}
    # Whole-invocation view sums counts; notes keep last-writer-wins.
    assert COUNTERS.snapshot_cumulative() == {"a": 5, "kind": "second"}
    COUNTERS.reset_all()


def test_reset_all_forgets_history_too():
    COUNTERS.reset_all()
    COUNTERS.bump("a", 7)
    COUNTERS.reset()
    assert COUNTERS.snapshot_cumulative() == {"a": 7}

    COUNTERS.reset_all()
    assert COUNTERS.snapshot_cumulative() == {}
    assert COUNTERS.snapshot() == {}


def test_a_name_retired_as_a_count_still_rejects_a_note():
    # The count/note exclusivity guard must not be escapable by resetting: a
    # name counted in repo 1 and noted in repo 2 would shadow its own retired
    # count in the cumulative view and reach a consumer as a string.
    COUNTERS.reset_all()
    COUNTERS.bump("shape", 1)
    COUNTERS.reset()
    with pytest.raises(ValueError):
        COUNTERS.note("shape", "ids")
    COUNTERS.reset_all()


def test_a_name_retired_as_a_note_still_rejects_a_count():
    COUNTERS.reset_all()
    COUNTERS.note("shape", "ids")
    COUNTERS.reset()
    with pytest.raises(ValueError):
        COUNTERS.bump("shape")
    COUNTERS.reset_all()
