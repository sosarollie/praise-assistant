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

"""Tests for validation finding selection: the max_findings (top-N by CVSS) cap.

Covers _resolve_selection precedence (--finding / --all / --max-findings / config
default), the CVSS sort helpers, and select_cases capping against on-disk finding cases.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from vvaharness.models import Finding, FindingCase, Remediation, RemediationKind
from vvaharness.validation.cli import _resolve_selection
from vvaharness.validation.cli._run import Selection
from vvaharness.validation.cli.args import ValidateArgs
from vvaharness.validation.ingest.case_loader import (
    LoadedCase,
    _cvss_score,
    _top_by_cvss,
    select_cases,
)
from vvaharness.validation.ingest.errors import IngestError

# _resolve_selection precedence


def _args(*, every: bool = False, findings=None, max_findings=None) -> ValidateArgs:
    return ValidateArgs(
        repo=Path("/repo"),
        findings=tuple(findings or ()),
        every_validatable=every,
        max_findings=max_findings,
    )


_CFG = SimpleNamespace(max_findings=20)


def test_default_uses_config_cap() -> None:
    """No flags -> cap from config.max_findings, no explicit ids."""
    assert _resolve_selection(_args(), _CFG) == Selection(case_ids=None, max_findings=20)


def test_all_bypasses_cap() -> None:
    """--all -> no ids, no cap (validate everything)."""
    assert _resolve_selection(_args(every=True), _CFG) == Selection(None, None)


def test_finding_ids_bypass_cap() -> None:
    """--finding ids -> exactly those, cap ignored."""
    sel = _resolve_selection(_args(findings=["F-1", "F-2"]), _CFG)
    assert sel == Selection(case_ids=["F-1", "F-2"], max_findings=None)


def test_flag_overrides_config_cap() -> None:
    """--max-findings N overrides the config default."""
    assert _resolve_selection(_args(max_findings=5), _CFG) == Selection(None, 5)


def test_all_wins_over_max_flag() -> None:
    """--all beats --max-findings ('all means all')."""
    assert _resolve_selection(_args(every=True, max_findings=5), _CFG) == Selection(None, None)


# CVSS helpers


def _finding(case_id: str = "F-1", cvss: object = 9.1) -> Finding:
    return Finding(
        title="t", file="app/x.py", line_start=3, vuln_class="injection",
        severity="high", case_id=case_id, cvss_score=cvss,
    )


def _case(case_id: str = "F-1", cvss: object = 9.1) -> FindingCase:
    """A remediated case: one applied-edits attempt, no verdict -> state REMEDIATED."""
    return FindingCase(case_id=case_id, finding=_finding(case_id, cvss)).with_attempt(
        Remediation(
            kind=RemediationKind.EDITS_APPLIED, summary="s",
            files_touched=("app/x.py",), diff="--- a\n+++ b\n",
        )
    )


def _loaded(case_id: str, cvss: object) -> LoadedCase:
    return LoadedCase(case=_case(case_id, cvss), path=Path(f"/repo/{case_id}/finding_case.json"))


def test_cvss_score_reads_the_findings_base_score() -> None:
    """The sort key is the finding's own CVSS base score."""
    assert _cvss_score(_loaded("a", 9.8)) == 9.8


def test_cvss_score_numeric_string_is_coerced() -> None:
    """A JSON string that is a number still parses to float, so it sorts by value."""
    assert _cvss_score(_loaded("b", "7.5")) == 7.5


def test_cvss_score_absent_sorts_last() -> None:
    """cvss_score is float | None: an absent score falls back to 0.0 rather than crashing."""
    assert _cvss_score(_loaded("c", None)) == 0.0


@pytest.mark.parametrize("garbage", ["", "n/a"])
def test_non_numeric_cvss_is_rejected_at_parse(garbage: str) -> None:
    """Garbage is now a parse error, not a silent 0.0.

    The retired DTO stored CVSS as a free string and the sort helper coerced ``""``/``"n/a"``
    to 0.0; ``Finding.cvss_score`` is typed ``float | None``, so an unparseable value is
    refused at the boundary instead of being scored as the lowest severity.
    """
    with pytest.raises(ValidationError):
        _finding(cvss=garbage)


def test_top_by_cvss_orders_and_trims() -> None:
    """Highest CVSS first; trimmed to the limit."""
    cases = [
        _loaded("low", 2.1), _loaded("crit", 9.8), _loaded("none", None), _loaded("med", 5.5),
    ]
    top = _top_by_cvss(cases, 2)
    assert [c.case_id for c in top] == ["crit", "med"]


# select_cases capping against on-disk finding cases


def _write_case(repo: Path, case_id: str, cvss: float) -> None:
    d = repo / "security-remediation" / case_id
    d.mkdir(parents=True)
    _case(case_id, cvss).write(d / "finding_case.json")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _write_case(tmp_path, "f-crit", 9.8)
    _write_case(tmp_path, "f-high", 7.2)
    _write_case(tmp_path, "f-low", 3.1)
    return tmp_path


def test_select_caps_to_top_n_by_cvss(repo: Path) -> None:
    """max_findings keeps only the top-N validatable cases by CVSS."""
    got = select_cases(repo, None, max_findings=2)
    assert {c.case_id for c in got} == {"f-crit", "f-high"}


def test_select_no_cap_returns_all(repo: Path) -> None:
    """max_findings=None (the --all path) returns every validatable case."""
    got = select_cases(repo, None, max_findings=None)
    assert len(got) == 3


def test_select_cap_above_count_returns_all(repo: Path) -> None:
    """A cap larger than the validatable count returns everything (no trim)."""
    assert len(select_cases(repo, None, max_findings=99)) == 3


def test_select_case_ids_ignore_cap(repo: Path) -> None:
    """Explicit case ids are returned verbatim, cap ignored."""
    got = select_cases(repo, ["f-low"], max_findings=1)
    assert [c.case_id for c in got] == ["f-low"]


def test_select_missing_case_id_raises(repo: Path) -> None:
    """An unknown explicit id raises IngestError."""
    with pytest.raises(IngestError, match="requested finding ids not found: nope"):
        select_cases(repo, ["nope"], max_findings=None)


def test_selected_cases_are_announced_with_their_state(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each selected case is logged with its DERIVED state, never a stored status string."""
    select_cases(repo, ["f-crit"], max_findings=None)
    assert "validate: selected f-crit (state=remediated)" in capsys.readouterr().err
