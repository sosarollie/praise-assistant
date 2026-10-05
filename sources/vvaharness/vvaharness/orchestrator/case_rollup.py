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

"""The remediation/validation rollup the run manifest carries: counts of case states and
validator decisions, tallied from the case records s10/s11 left under
``<repo>/security-remediation/``.

The tally keys on :class:`CaseState` because that is the engine's own verdict:
``models/vocab.py`` documents ``MergeReadiness`` as belonging to whoever runs the scan
rather than to the engine — under ``MergeReadiness`` a ``PARTIALLY_FIXED`` case can be
conditionally mergeable, while ``CaseState`` calls it ``FAILED``. The raw
:class:`Decision` counts ride along precisely so an operator can apply their own
readiness policy without the engine pre-judging it.

Counts only, by design: the case files live inside the *scanned target*, which is
untrusted input, so no title, path, case id or snippet from them may reach
``run_manifest.json`` through this rollup.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

from vvaharness.models.case import FindingCase
from vvaharness.models.derive import state_of, verdict_state
from vvaharness.models.vocab import CaseState
from vvaharness.orchestrator.artifacts import CASE_DIR_NAME, CASE_FILE_NAME

if TYPE_CHECKING:
    from collections.abc import Iterable

    from vvaharness.models.verdict import Verdict

__all__ = [
    "EXIT_NOT_REMEDIATED",
    "rc_for_verdicts",
    "record",
    "reset",
    "rollup_for",
    "totals",
]

#: The run completed and nothing it remediated validated as fixed. Distinct from ``1``,
#: which means the harness itself broke, and from ``2``, which refuses work before
#: spending on it. Defined here so the validation run and the batch summary cannot drift
#: apart on what the number means; the published contract is in ``docs/outputs.md``.
EXIT_NOT_REMEDIATED: Final = 3

#: A pre-seeded ``security-remediation/`` directory in a hostile checkout must not be a
#: way to make the scanner read a gigabyte into memory; anything larger is skipped.
_MAX_CASE_BYTES: Final = 4 * 1024 * 1024

# The invocation-wide accumulator, cumulative across repos for the same reason
# util.counters carries snapshot_cumulative(): a batch run writes one manifest for the
# whole invocation, so a per-repo view alone would report only the last repo as if it
# were the run's totals.
_TOTALS: Final[dict] = {}


def rc_for_verdicts(verdicts: Iterable[Verdict | None]) -> int:
    """``EXIT_NOT_REMEDIATED`` when *verdicts* validated nothing and failed something.

    The condition is deliberately narrow: nothing validated **and** at least one case
    failed. Any single validated case clears it, and a run of only inconclusive cases
    does not trip it either, because ``INCONCLUSIVE`` derives to ``OPEN`` rather than
    ``FAILED`` -- such a run neither validated nor failed, and re-validating it is the
    answer, not a red exit code. An any-failure gate would go non-zero on most mixed
    runs, and a signal that is almost always red gets wrapped in ``|| true`` and stops
    being a signal.

    Keys on ``CaseState`` through the shared ``verdict_state``, so this cannot disagree
    with what the case files say once they are written. ``MergeReadiness`` is not
    consulted: a partially-fixed case can be conditionally mergeable under it, and that
    judgement belongs to whoever runs the scan rather than to the engine.

    Takes the verdicts the caller already holds in memory. It does not read disk -- a
    tally of case FILES would answer for cases the run never selected, including ones an
    earlier run left behind.
    """
    states = [verdict_state(v) for v in verdicts if v is not None]
    if CaseState.VALIDATED in states or CaseState.FAILED not in states:
        return 0
    return EXIT_NOT_REMEDIATED


def _inside(path: Path, root: Path) -> bool:
    """Whether *path* really resolves inside *root*.

    ``Path.glob`` follows symlinks in every position, so a hostile checkout can plant
    ``security-remediation/x -> /etc`` or point the case file itself at a file outside
    the target and have the reader open it. Only counts leave this module, but a
    validation error echoes a fragment of what it parsed, so the read is refused rather
    than merely being harmless.
    """
    try:
        return path.resolve().is_relative_to(root.resolve())
    except OSError:
        return False


def _shaped(cases: int, states: dict[str, int], decisions: dict[str, int]) -> dict:
    """The one shape both :func:`rollup_for` and :func:`totals` return, so the per-repo
    and invocation-wide views cannot drift apart. Keys are sorted for stable diffing
    between runs, exactly as the manifest's counters dump does; only observed names
    appear, so consumers read with ``.get(name, 0)``."""
    return {
        "cases": cases,
        "states": dict(sorted(states.items())),
        "decisions": dict(sorted(decisions.items())),
    }


def rollup_for(repo: Path | str) -> dict:
    """Tally the case records under ``<repo>/security-remediation/``, touching no module state.

    Returns ``{}`` — not zeros — when the directory is absent or no case file parsed, so
    the manifest omits the key entirely and "no validation ran" stays distinguishable
    from "validation ran and everything is zero".

    This stays separate from :func:`totals` on purpose: the two answer different
    questions, and in a batch where repo 1 validated something and repo 2 validated
    nothing, ``totals()`` reports ``validated > 0`` and can never express "*this* repo
    validated nothing".

    Note what it is deliberately NOT for: driving an exit code. It counts every case
    ON DISK, while s11 validates only the subset ``select_cases`` picked, so a gate
    built on this would answer for cases the run never looked at — including ones an
    earlier run left behind. The exit code is decided where the verdicts are.
    """
    cases = 0
    states: dict[str, int] = {}
    decisions: dict[str, int] = {}
    case_root = Path(repo) / CASE_DIR_NAME
    # The same two-segment pattern s11's own case_loader.discover_cases globs, so the
    # manifest describes the population validation DISCOVERED rather than some other
    # set. It is not the population s11 necessarily VALIDATED: select_cases may cap or
    # narrow it, which is exactly why this tally reports and does not decide. That is
    # also why it deliberately does NOT filter by age: security-remediation/ is
    # preserved across runs by design, so what is on disk is what s11 looked at.
    for path in Path(repo).glob(f"{CASE_DIR_NAME}/*/{CASE_FILE_NAME}"):
        try:
            # is_file() stats without opening, so a device node or a FIFO planted under
            # the case directory is skipped rather than blocking the read forever.
            if not path.is_file():
                continue
            if not _inside(path, case_root):
                print(
                    f"  [rollup] WARN: {path} resolves outside {case_root}; "
                    "ignoring it",
                    file=sys.stderr,
                )
                continue
            size = path.stat().st_size
            if size > _MAX_CASE_BYTES:
                msg = f"{size} bytes exceeds the {_MAX_CASE_BYTES}-byte case limit"
                raise ValueError(msg)
            case = FindingCase.read(path)
            state = state_of(case.attempts).value
            # An unvalidated attempt contributes to `states` but to no decision.
            verdict = case.attempts[-1].verdict if case.attempts else None
            decision = verdict.decision.value if verdict is not None else None
        except Exception as exc:  # noqa: BLE001  # see the comment below
            # findings_json._validated names the three exception types it expects; this
            # catches everything on purpose. The tally runs at the tail of a scan that
            # has already done its work, so nothing a single case file can raise --
            # including a KeyError from a decision vocabulary that outgrew derive.py --
            # may be the thing that fails a finished run. The file is named in the
            # warning, so a skipped case is never silent.
            print(
                f"  [rollup] WARN: {path} is not a readable case record ({exc}); "
                "ignoring it",
                file=sys.stderr,
            )
            continue
        cases += 1
        states[state] = states.get(state, 0) + 1
        if decision is not None:
            decisions[decision] = decisions.get(decision, 0) + 1
    if not cases:
        return {}
    return _shaped(cases, states, decisions)


def record(repo: Path | str) -> dict:
    """Compute the rollup for *repo*, fold it into the invocation-wide accumulator, and
    return what was computed — so a caller needing both the per-repo answer and the
    running totals reads disk once."""
    rollup = rollup_for(repo)
    if rollup:
        _TOTALS["cases"] = _TOTALS.get("cases", 0) + rollup["cases"]
        for key in ("states", "decisions"):
            bucket = _TOTALS.setdefault(key, {})
            for name, n in rollup[key].items():
                bucket[name] = bucket.get(name, 0) + n
    return rollup


def totals() -> dict:
    """The accumulated invocation-wide rollup, same shape as :func:`rollup_for`;
    ``{}`` when nothing was recorded."""
    if not _TOTALS:
        return {}
    return _shaped(_TOTALS["cases"], _TOTALS["states"], _TOTALS["decisions"])


def reset() -> None:
    """Forget the accumulated totals — for test isolation, like COUNTERS.reset_all():
    the accumulator is a process-global that outlives any one test."""
    _TOTALS.clear()
