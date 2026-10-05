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

"""A malformed finding_case.json must be skipped (named), not abort the run.

Regression for the validator crashing with a bare json.JSONDecodeError that did
not identify which security-remediation/*/finding_case.json was corrupt.
"""
from pathlib import Path

import pytest

from vvaharness.models import (
    Decision,
    Disposition,
    Finding,
    FindingCase,
    Remediation,
    RemediationKind,
    Verdict,
)
from vvaharness.validation.ingest.case_loader import select_cases
from vvaharness.validation.ingest.errors import IngestError


def _finding(case_id: str, cvss: float = 5.0) -> Finding:
    return Finding(
        title="t", file="app/x.py", line_start=3, vuln_class="injection",
        severity="high", case_id=case_id, cvss_score=cvss,
    )


def _remediated(case_id: str, cvss: float = 5.0) -> FindingCase:
    """One applied-edits attempt, unjudged -> derived state REMEDIATED."""
    return FindingCase(case_id=case_id, finding=_finding(case_id, cvss)).with_attempt(
        Remediation(
            kind=RemediationKind.EDITS_APPLIED, summary="s",
            files_touched=("app/x.py",), diff="--- a\n+++ b\n",
        )
    )


def _judged(case_id: str, decision: Decision) -> FindingCase:
    """A remediated case whose latest attempt carries *decision*."""
    return _remediated(case_id).with_verdict(Verdict(decision=decision, rationale="r"))


def _declined(case_id: str) -> FindingCase:
    """A case the engine declined outright -> derived state DECLINED, not validatable."""
    return FindingCase(case_id=case_id, finding=_finding(case_id)).with_attempt(
        Remediation(
            kind=RemediationKind.NO_ACTION, summary="s",
            disposition=Disposition.FALSE_POSITIVE,
        )
    )


def _write(dir_: Path, name: str, case: FindingCase) -> Path:
    sub = dir_ / "security-remediation" / name
    sub.mkdir(parents=True)
    path = sub / "finding_case.json"
    case.write(path)
    return path


def _write_text(dir_: Path, name: str, text: str) -> Path:
    sub = dir_ / "security-remediation" / name
    sub.mkdir(parents=True)
    path = sub / "finding_case.json"
    path.write_text(text, encoding="utf-8")
    return path


# "Expecting ',' delimiter" — the exact field-level failure mode reported.
_MALFORMED = '{\n  "case_id": "bad-1"\n  "finding": {}\n}'


def test_malformed_case_is_skipped_not_fatal(tmp_path: Path, capsys) -> None:
    _write(tmp_path, "01_good", _remediated("good-1", cvss=7.5))
    _write_text(tmp_path, "02_bad", _MALFORMED)

    cases = select_cases(tmp_path, None, None)

    assert [c.case_id for c in cases] == ["good-1"]          # good one survives
    warning = capsys.readouterr().err
    assert "skipping finding '02_bad'" in warning            # names the finding
    assert "unreadable finding case" in warning


def test_schema_invalid_case_is_skipped_not_fatal(tmp_path: Path, capsys) -> None:
    """Valid JSON that is not a FindingCase is skipped the same way, not raised."""
    _write(tmp_path, "01_good", _remediated("good-1"))
    _write_text(tmp_path, "02_bad", '{"case_id": "bad-1"}')  # no `finding` -> ValidationError

    assert [c.case_id for c in select_cases(tmp_path, None, None)] == ["good-1"]
    assert "skipping finding '02_bad'" in capsys.readouterr().err


def test_read_error_names_the_path(tmp_path: Path) -> None:
    path = _write_text(tmp_path, "02_bad", _MALFORMED)
    with pytest.raises(ValueError, match="malformed JSON in finding case"):
        FindingCase.read(path)


def test_null_cvss_fields_survive_as_none() -> None:
    # Remediation may emit cvss_* as JSON null; that must parse (staying None, which means
    # "not computed"), not raise a pydantic ValidationError that aborts the whole load.
    finding = Finding.model_validate({
        "title": "t", "file": "app/x.py", "line_start": 3, "vuln_class": "injection",
        "cvss_vector": None, "cvss_score": None, "cvss_rating": None,
    })
    assert finding.cvss_vector is None
    assert finding.cvss_score is None
    assert finding.cvss_rating is None


# Derived state, not a stored status: REMEDIATED and FAILED both re-drive validation


@pytest.mark.parametrize("decision", [Decision.NOT_FIXED, Decision.PARTIALLY_FIXED])
def test_remediated_and_failed_both_selected(tmp_path: Path, decision: Decision) -> None:
    _write(tmp_path, "01_remediated", _remediated("RM-1"))
    _write(tmp_path, "02_failed", _judged("FL-1", decision))
    _write(tmp_path, "03_declined", _declined("DC-1"))          # not validatable

    ids = {c.case_id for c in select_cases(tmp_path, None, None)}

    assert ids == {"RM-1", "FL-1"}   # failed re-drives; declined is closed


def test_finding_in_non_validatable_state_reports_clearly(tmp_path: Path) -> None:
    _write(tmp_path, "01_validated", _judged("V-1", Decision.FIXED))
    with pytest.raises(IngestError, match=r"not in a validatable state.*V-1 \(state 'validated'\)"):
        select_cases(tmp_path, ["V-1"], None)


def test_failed_finding_selectable_by_id(tmp_path: Path) -> None:
    _write(tmp_path, "01_failed", _judged("FL-1", Decision.NOT_FIXED))
    sel = select_cases(tmp_path, ["FL-1"], None)
    assert [c.case_id for c in sel] == ["FL-1"]
