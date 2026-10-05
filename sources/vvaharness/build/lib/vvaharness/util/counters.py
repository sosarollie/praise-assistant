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
Process-wide stage counters, read once by util.metrics.build().

Why this exists: ScanMetrics is built after the fact, from ctx + manifest
(util/metrics.py). A stage that wants to report "I dropped 3 unresolvable file
references" has no metrics object to write to while it runs, and the fact is not
recoverable from the finished manifest -- the dropped paths are gone.

This mirrors the pattern the package already uses twice: TOKENS
(util/tokens.py) and errlog.counts_by_stage() are both process-wide sinks that
stages write to and metrics.build() reads. Same shape, same reset discipline, so
there is one convention rather than three.

    from vvaharness.util.counters import COUNTERS
    COUNTERS.bump("s3_dropped_paths")
    COUNTERS.note("s3_output_shape", "ids")

Batch mode must reset between repos, exactly like TOKENS.reset()
(orchestrator/batch.py) -- otherwise repo N+1 inherits repo N's tallies.
"""
from __future__ import annotations
import threading


class _Counters:
    """Ints you add to, strings you overwrite. Nothing else."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ints: dict[str, int] = {}
        self._notes: dict[str, str] = {}
        # Totals carried over from before each reset(), so a batch run can still
        # report the whole invocation. Never cleared.
        self._retired_ints: dict[str, int] = {}
        self._retired_notes: dict[str, str] = {}

    # snapshot() merges the two maps into one dict, so a name used for both a
    # count and a note would silently shadow the count and reach the report as a
    # string where a number was expected. No name is used both ways today; these
    # two guards make that a loud error at the write site rather than a quiet
    # wrong value in a finished report. They consult the RETIRED maps as well,
    # so a batch reset cannot be used to sneak a name across kinds — otherwise a
    # name counted in repo 1 and noted in repo 2 would shadow its own retired
    # count in the cumulative view and surface as a string.
    def bump(self, name: str, n: int = 1) -> None:
        with self._lock:
            if name in self._notes or name in self._retired_notes:
                raise ValueError(
                    f"counter {name!r} is already recorded as a note; a name "
                    f"must be either a count or a note, never both"
                )
            self._ints[name] = self._ints.get(name, 0) + n

    def note(self, name: str, value: str) -> None:
        """Last writer wins -- for one-of-N facts like s3_output_shape."""
        with self._lock:
            if name in self._ints or name in self._retired_ints:
                raise ValueError(
                    f"counter {name!r} is already recorded as a count; a name "
                    f"must be either a count or a note, never both"
                )
            self._notes[name] = value

    def get(self, name: str, default: int = 0) -> int:
        with self._lock:
            return self._ints.get(name, default)

    def snapshot(self) -> dict:
        with self._lock:
            return {**self._ints, **self._notes}

    def snapshot_cumulative(self) -> dict:
        """Every count since process start, across reset() calls.

        `reset()` is called per repo in a batch run, while the run manifest wraps
        the whole CLI invocation — so a manifest built from `snapshot()` reports
        only the LAST repo's tallies while presenting itself as the run's totals.
        An engineer reading `s0_files_dropped_scan_error: 0` would conclude no
        file was dropped when earlier repos dropped dozens. Counts are summed;
        notes keep last-writer-wins, matching `note()`'s own contract.
        """
        with self._lock:
            merged = dict(self._retired_ints)
            for k, v in self._ints.items():
                merged[k] = merged.get(k, 0) + v
            return {**merged, **self._retired_notes, **self._notes}

    def reset(self) -> None:
        """Clear the current tallies, retiring them into the cumulative totals.

        This is the per-repo boundary in a batch run: `get()`/`snapshot()` start
        from zero again for the next repo, while `snapshot_cumulative()` still
        sees what the finished repos measured.
        """
        with self._lock:
            for k, v in self._ints.items():
                self._retired_ints[k] = self._retired_ints.get(k, 0) + v
            self._retired_notes.update(self._notes)
            self._ints.clear()
            self._notes.clear()

    def reset_all(self) -> None:
        """Forget everything, cumulative history included.

        For tests that need a genuinely clean slate: plain `reset()` deliberately
        keeps history, so using it between tests would let one test's counts show
        up in another's cumulative assertions.
        """
        with self._lock:
            self._ints.clear()
            self._notes.clear()
            self._retired_ints.clear()
            self._retired_notes.clear()


COUNTERS = _Counters()
