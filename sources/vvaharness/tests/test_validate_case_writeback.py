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

"""Tests for the finding-case verdict write-back (distinct re-validatable failed state).

The case file carries no status string: ``FindingCase.state`` is derived from the attempt
sequence by ``derive.state_of``, so these tests assert the DERIVED state that a written
verdict produces -- FIXED -> validated, NOT_FIXED/PARTIALLY_FIXED -> failed (re-validatable),
INCONCLUSIVE -> open -- plus the end-to-end ``build_verdict`` fold of the host verdict into
``finding_case.json``.
"""
import json
from pathlib import Path

import pytest

from vvaharness.models import (
    CaseState,
    Decision,
    Finding,
    FindingCase,
    Provenance,
    Remediation,
    RemediationKind,
    Verdict,
)
from vvaharness.validation.constants.artifacts import FINDING_CASE_FILENAME
from vvaharness.validation.ingest.case_loader import _is_validatable, load_case, select_cases
from vvaharness.validation.io.case_writeback import build_verdict, write_back_verdict

from fixtures.validation_ws import (
    ALL_FAIL as _ALL_FAIL,
    ALL_PASS as _ALL_PASS,
    write_gates as _write_gates,
    write_report as _write_report,
)

_PROV = Provenance(engine="vvaharness.validation", engine_version="1.4.0")


def _output_finding(**overrides: object) -> dict:
    """One agent-emitted finding block, with every required field filled."""
    return {
        "tracking_id": "F-1", "finding_title": "t", "finding_description": "d",
        "affected_files": "app/x.py", **overrides,
    }


def _finding(case_id: str) -> Finding:
    return Finding(
        title="t", file="app/x.py", line_start=3, vuln_class="injection",
        severity="high", case_id=case_id, cvss_score=7.5,
    )


def _case(case_id: str) -> FindingCase:
    """One applied-edits attempt, unjudged -> derived state REMEDIATED."""
    return FindingCase(case_id=case_id, finding=_finding(case_id)).with_attempt(
        Remediation(
            kind=RemediationKind.EDITS_APPLIED, summary="s",
            files_touched=("app/x.py",), diff="x",
        )
    )


def _write_case(repo: Path, name: str, case: FindingCase) -> Path:
    sub = repo / "security-remediation" / name
    sub.mkdir(parents=True)
    path = sub / FINDING_CASE_FILENAME
    case.write(path)
    return path


def _state_on_disk(path: Path) -> CaseState:
    """Re-read the case from disk, so the assertion is on the persisted attempt sequence."""
    return load_case(path).case.state


# verdict -> derived state, over every decision the engine can reach


@pytest.mark.parametrize(
    ("decision", "expected"),
    [
        (Decision.FIXED, CaseState.VALIDATED),
        (Decision.NOT_FIXED, CaseState.FAILED),
        (Decision.PARTIALLY_FIXED, CaseState.FAILED),
        (Decision.INCONCLUSIVE, CaseState.OPEN),
    ],
)
def test_written_verdict_derives_the_case_state(
    tmp_path: Path, decision: Decision, expected: CaseState
) -> None:
    """The verdict lands on the last attempt and the state follows from it, unwritten."""
    path = _write_case(tmp_path, "01_finding", _case("F-1"))
    verdict = Verdict(decision=decision, rationale="r")

    judged = write_back_verdict(load_case(path).case, verdict, path)

    assert judged is not None
    assert judged.state is expected
    assert _state_on_disk(path) is expected
    # No status string is ever persisted; `state` is emitted for readers, derived on load.
    assert "status" not in json.loads(path.read_text(encoding="utf-8"))


def test_verdict_lands_on_the_latest_attempt(tmp_path: Path) -> None:
    """A second attempt is what gets judged; the first attempt's record is left alone."""
    first = _case("F-1")
    second = first.with_attempt(
        Remediation(kind=RemediationKind.DIFF_PROPOSED, summary="retry", diff="y")
    )
    path = _write_case(tmp_path, "01_finding", second)

    judged = write_back_verdict(second, Verdict(decision=Decision.FIXED, rationale="r"), path)

    assert judged is not None
    assert judged.attempts[0].verdict is None
    assert judged.attempts[1].verdict is not None
    assert judged.attempts[1].verdict.decision is Decision.FIXED


# build_verdict — end-to-end fold of the workspace artifacts into the case


def test_write_back_failing_verdict_sets_failed(tmp_path: Path) -> None:
    ws = tmp_path / "workspace"
    ws.mkdir()
    path = _write_case(tmp_path, "01_finding", _case("F-1"))
    _write_report(ws, [_output_finding(
        fix_status="Not Fixed", raw_score=0.0, justification="agent narrative",
        conditions_for_full_fix=["sanitize the query"],
    )])
    _write_gates(ws, "F-1", _ALL_FAIL)

    case = load_case(path).case
    verdict = build_verdict(case, ws, provenance=_PROV)
    write_back_verdict(case, verdict, path)

    assert verdict.decision is Decision.NOT_FIXED
    assert _state_on_disk(path) is CaseState.FAILED
    # The host verdict — decision, score and the agent's surviving narrative — is on the attempt.
    written = load_case(path).case.attempts[-1].verdict
    assert written is not None
    assert written.decision is Decision.NOT_FIXED
    assert written.conditions == ("sanitize the query",)
    assert written.produced_by.engine == "vvaharness.validation"


def test_write_back_redacts_secret_in_narrative(tmp_path: Path) -> None:
    """A secret the agent echoed into free text is masked before it can reach the case file.

    The verdict no longer carries the agent's own ``justification``: its rationale is built from
    the gate summaries, so this drives the real host write of the whole agent payload
    (``_write_workspace_json`` -> ``redact_tree``) and asserts on ``finding_case.json`` on disk,
    covering both the gate text and the narrative fields that do survive onto the verdict.
    """
    from vvaharness.validation.session.launcher import _write_validation_outputs

    ws = tmp_path / "workspace"
    ws.mkdir()
    path = _write_case(tmp_path, "01_finding", _case("F-1"))
    _write_validation_outputs(ws, {
        "target_jira_status": "In Review",
        "findings": [_output_finding(
            fix_status="Not Fixed", raw_score=0.0,
            justification="still hardcodes AKIAIOSFODNN7EXAMPLE",
            conditions_for_full_fix=["rotate AKIAIOSFODNN7EXAMPLE"],
        )],
        "synthesized_gates": [{
            "tracking_id": "F-1",
            "gates": [
                {**gate, "summary": "AKIAIOSFODNN7EXAMPLE still present"}
                for gate in _ALL_FAIL
            ],
        }],
    })

    case = load_case(path).case
    write_back_verdict(case, build_verdict(case, ws, provenance=_PROV), path)

    on_disk = path.read_text(encoding="utf-8")
    assert "[REDACTED-AWS-KEY]" in on_disk
    assert "AKIAIOSFODNN7EXAMPLE" not in on_disk


def test_write_back_absent_gates_fails_closed(tmp_path: Path) -> None:
    # Agent self-reports Fixed but writes no synthesized_gates.json → the host cannot
    # recompute, so the verdict fails closed to INCONCLUSIVE and the case derives back to the
    # re-validatable `open` state, never `validated`.
    ws = tmp_path / "workspace"
    ws.mkdir()
    path = _write_case(tmp_path, "01_finding", _case("F-1"))
    _write_report(ws, [_output_finding(
        fix_status="Fixed", raw_score=0.99, justification="agent narrative",
        recommendations=["add a regression test"],
    )])
    # Deliberately no _write_gates(...) call.

    case = load_case(path).case
    verdict = build_verdict(case, ws, provenance=_PROV)
    write_back_verdict(case, verdict, path)

    assert verdict.decision is Decision.INCONCLUSIVE
    # None, not 0.0: "no number" is a different claim from "zero confidence".
    assert verdict.score is None
    assert _state_on_disk(path) is CaseState.OPEN
    # Agent narrative is still preserved alongside the fail-closed decision.
    assert verdict.recommendations == ("add a regression test",)


def test_write_back_session_failed_fails_closed_despite_passing_gates(tmp_path: Path) -> None:
    # Gates are present and all passing -- without the guard this derives a terminal
    # `validated` state for a session that actually failed, and validated is excluded from
    # re-validation. session_failed discards the gates so the verdict fails closed to
    # INCONCLUSIVE -> open.
    ws = tmp_path / "workspace"
    ws.mkdir()
    path = _write_case(tmp_path, "01_finding", _case("F-1"))
    _write_report(ws, [_output_finding(fix_status="Fixed", raw_score=0.99)])
    _write_gates(ws, "F-1", _ALL_PASS)

    case = load_case(path).case
    # Same inputs without the flag are a clean pass -- the flag alone changes the outcome.
    clean = build_verdict(case, ws, provenance=_PROV)
    assert clean.decision is Decision.FIXED
    write_back_verdict(case, clean, path)
    assert _state_on_disk(path) is CaseState.VALIDATED

    failed = build_verdict(case, ws, provenance=_PROV, session_failed=True)
    write_back_verdict(case, failed, path)

    assert failed.decision is Decision.INCONCLUSIVE
    assert failed.score is None
    assert _state_on_disk(path) is CaseState.OPEN


def test_write_back_without_an_attempt_returns_none(tmp_path: Path) -> None:
    # A case with no remediation attempt has nothing to attach a verdict to; the writer
    # reports that instead of raising, and leaves the file untouched.
    path = _write_case(
        tmp_path, "01_finding", FindingCase(case_id="F-1", finding=_finding("F-1"))
    )
    before = path.read_text(encoding="utf-8")

    result = write_back_verdict(
        load_case(path).case, Verdict(decision=Decision.FIXED, rationale="r"), path
    )

    assert result is None
    assert path.read_text(encoding="utf-8") == before


def test_write_back_unwritable_path_returns_none(tmp_path: Path) -> None:
    # An IO failure is reported as None so the caller can flag the finding as unrecorded.
    missing = tmp_path / "no_such_dir" / FINDING_CASE_FILENAME
    result = write_back_verdict(
        _case("F-1"), Verdict(decision=Decision.FIXED, rationale="r"), missing
    )
    assert result is None


# Re-validation — a `failed` case is re-selectable on the next run


def test_failed_state_is_validatable(tmp_path: Path) -> None:
    path = _write_case(
        tmp_path, "01_finding",
        _case("F-1").with_verdict(Verdict(decision=Decision.NOT_FIXED, rationale="r")),
    )
    assert _is_validatable(load_case(path)) is True


def test_failed_case_selected_for_revalidation(tmp_path: Path) -> None:
    _write_case(
        tmp_path, "01_failed",
        _case("VF-1").with_verdict(Verdict(decision=Decision.NOT_FIXED, rationale="r")),
    )
    _write_case(  # terminal pass; excluded
        tmp_path, "02_validated",
        _case("V-1").with_verdict(Verdict(decision=Decision.FIXED, rationale="r")),
    )

    ids = {c.case_id for c in select_cases(tmp_path, None, None)}

    assert ids == {"VF-1"}  # failed re-drives; validated does not
