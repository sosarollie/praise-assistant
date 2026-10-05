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

"""Discover and load finding cases from a target repo, selecting by FindingCase.state (derived)."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from vvaharness.models import CaseState, Disposition, FindingCase
from vvaharness.validation.constants.artifacts import FINDING_CASE_GLOB, VALIDATABLE_STATES
from vvaharness.validation.ingest.errors import IngestError

__all__ = ["LoadedCase", "all_case_ids", "discover_cases", "load_case",
           "select_cases"]

# The states named in the refusal message; DECLINED is conditional, see _is_validatable.
_VALIDATABLE = ", ".join(sorted(
    [*(state.value for state in VALIDATABLE_STATES),
     f"{CaseState.DECLINED.value} (only when not-applicable)"]))


@dataclass(frozen=True)
class LoadedCase:
    """A parsed case and the path it came from, so its verdict lands back in the same file."""

    case: FindingCase
    path: Path

    @property
    def case_id(self) -> str:
        """The case's stable identity."""
        return self.case.case_id


def discover_cases(repo: Path) -> list[Path]:
    """Return sorted case-file paths under the repo's remediation dir."""
    return sorted(repo.glob(FINDING_CASE_GLOB))


def load_case(path: Path) -> LoadedCase:
    """Parse a single finding case from disk."""
    return LoadedCase(case=FindingCase.read(path), path=path)


def _load_case_safe(path: Path) -> LoadedCase | None:
    """Load a case, or None with a printed warning, so one bad case can't abort --all."""
    try:
        return load_case(path)
    except (OSError, ValueError, ValidationError) as exc:
        print(
            f"validate: skipping finding '{path.parent.name}' — "
            f"unreadable finding case ({path}): {exc}",
            file=sys.stderr,
        )
        return None


def all_case_ids(repo: Path) -> list[str] | None:
    """Every case id on disk, or None if the set can't be fully enumerated."""
    try:
        return [load_case(path).case_id for path in discover_cases(repo)]
    except (OSError, ValueError, ValidationError):
        return None


def _all_cases(repo: Path) -> list[LoadedCase]:
    """Load every readable case under *repo* (any state)."""
    return [c for path in discover_cases(repo) if (c := _load_case_safe(path)) is not None]


def _is_validatable(loaded: LoadedCase) -> bool:
    """True: validator can act; DECLINED/NOT_APPLICABLE too, not FALSE_POSITIVE/POLICY_DENIED."""
    case = loaded.case
    if case.state in VALIDATABLE_STATES:
        return True
    return case.state is CaseState.DECLINED and _declined_for_review(case)


def _declined_for_review(case: FindingCase) -> bool:
    """True when the latest attempt declined for a reason a re-check could overturn."""
    latest = case.attempts[-1] if case.attempts else None
    return (latest is not None
            and latest.remediation.disposition is Disposition.NOT_APPLICABLE)


def _cvss_score(loaded: LoadedCase) -> float:
    """Return the finding's CVSS base score; 0.0 when absent, so it sorts last."""
    return loaded.case.finding.cvss_score or 0.0


def _top_by_cvss(cases: list[LoadedCase], limit: int) -> list[LoadedCase]:
    """Return the *limit* highest-CVSS cases; stable discovery order on ties."""
    return sorted(cases, key=_cvss_score, reverse=True)[:limit]


def _log_selection(cases: list[LoadedCase]) -> None:
    """Emit one stderr line per selected case so the ``--all`` route is never silent."""
    for loaded in cases:
        print(
            f"validate: selected {loaded.case_id} (state={loaded.case.state.value})",
            file=sys.stderr,
        )


def _capped(cases: list[LoadedCase], max_findings: int | None) -> list[LoadedCase]:
    """Trim *cases* to the top ``max_findings`` by CVSS, announcing the cap on stderr."""
    if max_findings is None or max_findings <= 0 or len(cases) <= max_findings:
        return cases
    total = len(cases)
    print(
        f"validate: capping to top {max_findings} of {total} validatable findings by CVSS "
        f"(use --all to validate every finding)",
        file=sys.stderr,
    )
    return _top_by_cvss(cases, max_findings)


def select_cases(
    repo: Path,
    case_ids: list[str] | None,
    max_findings: int | None = None,
) -> list[LoadedCase]:
    """Load validatable cases: case_ids selects exactly those, else top max_findings by CVSS."""
    all_cases = _all_cases(repo)
    if case_ids is not None:
        selected = _select_by_id(all_cases, case_ids)
    else:
        selected = _capped([c for c in all_cases if _is_validatable(c)], max_findings)
    _log_selection(selected)
    return selected


def _select_by_id(all_cases: list[LoadedCase], case_ids: list[str]) -> list[LoadedCase]:
    """Resolve explicit case ids, raising IngestError on a missing or non-validatable state."""
    by_id = {loaded.case_id: loaded for loaded in all_cases}
    missing = [cid for cid in case_ids if cid not in by_id]
    if missing:
        raise IngestError(f"requested finding ids not found: {', '.join(missing)}")
    not_validatable = [
        f"{cid} (state '{by_id[cid].case.state.value}')"
        for cid in case_ids
        if not _is_validatable(by_id[cid])
    ]
    if not_validatable:
        raise IngestError(
            "validation cannot run — these findings are not in a validatable state "
            f"(need {_VALIDATABLE}): {', '.join(not_validatable)}"
        )
    return [by_id[cid] for cid in case_ids]
