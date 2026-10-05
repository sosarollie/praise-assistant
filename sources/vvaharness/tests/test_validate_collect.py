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

"""Result collection: validation_report.json -> (Verdict, ValidationResult) per finding.

The host recomputes every verdict from ``synthesized_gates.json`` via the deterministic scoring
engine. The agent's own ``fix_status`` / ``raw_score`` / ``merge_readiness`` are narrative only
and must never become the recorded judgement.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from pathlib import Path

import pytest

from vvaharness.models import Decision, MergeReadiness, Provenance
from vvaharness.validation.constants.artifacts import (
    MANIFEST_FILENAME,
    SYNTHESIZED_GATES_FILENAME,
    VALIDATION_REPORT_FILENAME,
)
from vvaharness.validation.enums import EffortLevel
from vvaharness.validation.io._host_score import verdict_for
from vvaharness.validation.io.result_collector import collect_and_enrich
from vvaharness.validation.models import output as output_models
from vvaharness.validation.models.output import OutputFinding, ValidationReport
from vvaharness.validation.scoring import score_fix

from fixtures.validation_ws import (
    ALL_FAIL as _ALL_FAIL,
    ALL_PASS as _ALL_PASS,
    write_gates as _write_gates,
    write_report as _write_report,
)


def _finding(**overrides: object) -> dict:
    """A report entry with the frozen schema's required fields filled in."""
    base: dict = {
        "tracking_id": "F-1",
        "finding_title": "t",
        "finding_description": "d",
        "affected_files": "app/db.py",
    }
    return base | overrides


_ROOT_FAIL: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "fail"},
    {"gate_name": "instance_coverage", "status": "pass"},
    {"gate_name": "no_new_vulnerabilities", "status": "pass"},
    {"gate_name": "security_best_practices", "status": "pass"},
]
# root_cause + instance_coverage pass (0.43 + 0.2467) -> score in [0.50, 0.80) -> PARTIALLY_FIXED.
_PARTIAL: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "pass"},
    {"gate_name": "instance_coverage", "status": "pass"},
    {"gate_name": "no_new_vulnerabilities", "status": "fail"},
    {"gate_name": "security_best_practices", "status": "fail"},
]
# _ALL_PASS / _ALL_FAIL (full coverage, score 0.0 -> NOT_FIXED, not INCONCLUSIVE) are the shared
# fixtures.validation_ws constants imported above.


# Decision -> tri-state render columns


def test_collect_maps_fixed(tmp_path: Path) -> None:
    """All gates pass -> host decision FIXED -> fixed=Yes (host number, not the agent's)."""
    _write_report(tmp_path, [_finding(fix_status="Fixed", raw_score=0.91)])
    _write_gates(tmp_path, "F-1", _ALL_PASS)
    (item,) = collect_and_enrich(tmp_path)
    assert item.verdict.decision is Decision.FIXED
    assert item.row.fixed == "Yes"
    assert item.row.not_fixed == "No"
    assert item.row.fix_confidence == score_fix(_ALL_PASS).raw_score
    assert Decision.FIXED.value in item.row.reason_for_decision


def test_collect_maps_partial_and_not_fixed(tmp_path: Path) -> None:
    """Host decisions drive the tri-state columns, not the agent's claims."""
    _write_report(tmp_path, [
        _finding(tracking_id="F-1", fix_status="Partially Fixed", raw_score=0.6),
        _finding(tracking_id="F-2", fix_status="Not Fixed", raw_score=0.2),
    ])
    (tmp_path / SYNTHESIZED_GATES_FILENAME).write_text(json.dumps([
        {"tracking_id": "F-1", "gates": _PARTIAL},
        {"tracking_id": "F-2", "gates": _ALL_FAIL},
    ]))
    first, second = collect_and_enrich(tmp_path)
    assert first.verdict.decision is Decision.PARTIALLY_FIXED
    assert first.row.partially_fixed == "Yes" and first.row.fixed == "No"
    assert second.verdict.decision is Decision.NOT_FIXED
    assert second.row.not_fixed == "Yes" and second.row.fixed == "No"


def test_collect_numbers_findings_from_start(tmp_path: Path) -> None:
    _write_report(tmp_path, [_finding(fix_status="Fixed")])
    (item,) = collect_and_enrich(tmp_path, finding_number_start=5)
    assert item.row.finding_number == 5


def test_collect_missing_report_returns_empty(tmp_path: Path) -> None:
    assert collect_and_enrich(tmp_path) == []


def test_collect_invalid_json_returns_empty(tmp_path: Path) -> None:
    (tmp_path / VALIDATION_REPORT_FILENAME).write_text("{ not json")
    assert collect_and_enrich(tmp_path) == []


# collect_and_enrich — blank row fields backfilled from manifest.json


def test_enrich_fills_blank_fields_from_manifest(tmp_path: Path) -> None:
    """A blank title/tracking_id/affected_files is backfilled from the manifest's Finding."""
    _write_report(
        tmp_path, [_finding(tracking_id="", finding_title="", affected_files="", fix_status="Fixed")]
    )
    (tmp_path / MANIFEST_FILENAME).write_text(json.dumps({
        "case_id": "JIRA-9",
        "affected_files": ["app/db.py"],
        "finding": {
            "case_id": "JIRA-9", "title": "SQLi", "file": "app/db.py", "line_start": 4,
            "vuln_class": "injection", "severity": "high", "cwe": "CWE-89",
        },
    }))
    (item,) = collect_and_enrich(tmp_path)
    assert item.row.finding_title == "SQLi"        # backfilled
    assert item.row.tracking_id == "JIRA-9"        # backfilled from blank
    assert "app/db.py" in item.row.affected_files
    # The agent left severity at the schema default, so the finding's severity wins.
    assert item.row.severity == "high"


def test_enrich_without_manifest_returns_results(tmp_path: Path) -> None:
    _write_report(tmp_path, [_finding(fix_status="Fixed", finding_title="T")])
    (item,) = collect_and_enrich(tmp_path)
    assert item.row.finding_title == "T"


# Host-side scoring overrides whatever the agent reported


def test_host_score_overrides_inflated_agent_number(tmp_path: Path) -> None:
    """Agent claims Fixed/0.99, but root_cause FAILED -> the host caps it below FIXED."""
    _write_report(tmp_path, [_finding(fix_status="Fixed", raw_score=0.99)])
    _write_gates(tmp_path, "F-1", _ROOT_FAIL)
    (item,) = collect_and_enrich(tmp_path)
    expected = score_fix(_ROOT_FAIL)
    assert item.row.fix_confidence == expected.raw_score      # host number, not 0.99
    assert item.row.fix_confidence != 0.99
    assert item.verdict.decision is not Decision.FIXED        # root_cause fail caps it
    assert item.verdict.decision is expected.decision


def test_host_score_matches_engine_exactly(tmp_path: Path) -> None:
    """A pessimistic agent claim is also overridden -- the host number is the only one."""
    _write_report(tmp_path, [_finding(fix_status="Not Fixed", raw_score=0.0)])
    _write_gates(tmp_path, "F-1", _ALL_PASS)
    (item,) = collect_and_enrich(tmp_path)
    assert item.row.fix_confidence == score_fix(_ALL_PASS).raw_score  # exact, deterministic
    assert item.verdict.decision is Decision.FIXED


def test_agent_merge_readiness_is_never_trusted(tmp_path: Path) -> None:
    """The agent may claim it is mergeable; readiness is a host policy call regardless."""
    _write_report(
        tmp_path, [_finding(fix_status="Fixed", raw_score=1.0, merge_readiness="Ready")]
    )
    _write_gates(tmp_path, "F-1", _ALL_FAIL)
    (item,) = collect_and_enrich(tmp_path)
    assert item.verdict.decision is Decision.NOT_FIXED
    assert item.row.pr_merge_readiness == MergeReadiness.NOT_READY.value


# Fail-closed paths: no usable gates means no number, never a zero-confidence claim


def test_no_synthesized_gates_fails_closed(tmp_path: Path) -> None:
    """No gates file -> the host cannot recompute -> INCONCLUSIVE with score=None."""
    _write_report(tmp_path, [_finding(fix_status="Fixed", raw_score=0.88)])
    (item,) = collect_and_enrich(tmp_path)
    assert item.verdict.decision is Decision.INCONCLUSIVE
    assert item.verdict.score is None                 # NOT 0.0 -- zero is a different claim
    # All three columns are "?": reaching no conclusion is not evidence the fix is absent.
    assert (item.row.fixed, item.row.partially_fixed, item.row.not_fixed) == ("?", "?", "?")
    assert Decision.INCONCLUSIVE.value in item.row.reason_for_decision


def test_malformed_gates_non_list_fails_closed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A present-but-non-array gates file fails closed and warns."""
    _write_report(tmp_path, [_finding(fix_status="Fixed", raw_score=0.95)])
    (tmp_path / SYNTHESIZED_GATES_FILENAME).write_text(json.dumps({"not": "a list"}))
    with caplog.at_level(logging.WARNING):
        (item,) = collect_and_enrich(tmp_path)
    assert item.verdict.decision is Decision.INCONCLUSIVE
    assert item.verdict.score is None
    assert any("not a JSON array" in m for m in caplog.messages)


def test_malformed_gates_bad_entry_dropped_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An entry whose "gates" is not a list is dropped, and the drop is logged."""
    _write_report(tmp_path, [_finding(fix_status="Fixed", raw_score=0.95)])
    (tmp_path / SYNTHESIZED_GATES_FILENAME).write_text(
        json.dumps([{"tracking_id": "F-1", "gates": "not-a-list"}])
    )
    with caplog.at_level(logging.WARNING):
        (item,) = collect_and_enrich(tmp_path)
    assert item.verdict.decision is Decision.INCONCLUSIVE
    assert item.verdict.score is None
    assert any("dropped" in m for m in caplog.messages)


def test_verdict_for_foreign_id_fails_closed() -> None:
    """Scoring must never borrow another finding's gates."""
    verdict = verdict_for(None, None, provenance=Provenance())
    assert verdict.decision is Decision.INCONCLUSIVE
    assert verdict.score is None


def test_foreign_only_gates_fail_closed(tmp_path: Path) -> None:
    """Gates for a DIFFERENT finding must not become this finding's verdict."""
    _write_report(tmp_path, [_finding(fix_status="Fixed", raw_score=0.97)])
    _write_gates(tmp_path, "F-OTHER", _ALL_PASS)
    (item,) = collect_and_enrich(tmp_path)
    assert item.verdict.decision is Decision.INCONCLUSIVE
    assert item.verdict.score is None
    assert item.verdict.gates == ()                 # never inherits F-OTHER's evidence


# Parse-boundary defences on the agent-reported numbers and prose


def test_report_clamps_raw_score_above_one_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An out-of-range score is clamped, not rejected -- a raise would drop every finding."""
    with caplog.at_level(logging.WARNING, logger=output_models.__name__):
        score = OutputFinding.model_validate(_finding(raw_score=500)).raw_score

    assert score == 1.0
    assert (
        "validation output raw_score=500.0 is outside [0.0, 1.0]; clamped to 1.0"
        in caplog.text
    )


def test_report_clamps_raw_score_below_zero_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=output_models.__name__):
        score = OutputFinding.model_validate(_finding(raw_score=-100)).raw_score

    assert score == 0.0
    assert (
        "validation output raw_score=-100.0 is outside [0.0, 1.0]; clamped to 0.0"
        in caplog.text
    )


@pytest.mark.parametrize(
    ("raw_score", "expected"),
    [(float("inf"), 1.0), (float("-inf"), 0.0), (float("nan"), 0.0)],
)
def test_report_clamps_non_finite_raw_score_and_warns(
    raw_score: float,
    expected: float,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=output_models.__name__):
        score = OutputFinding.model_validate(_finding(raw_score=raw_score)).raw_score

    assert score == expected
    assert "validation output raw_score=" in caplog.text
    assert "is outside [0.0, 1.0]; clamped to" in caplog.text


@pytest.mark.parametrize("raw_score", [0, 0.5, 1])
def test_report_does_not_warn_for_in_range_raw_score(
    raw_score: float,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=output_models.__name__):
        score = OutputFinding.model_validate(_finding(raw_score=raw_score)).raw_score

    assert score == raw_score
    assert "raw_score" not in caplog.text


@pytest.mark.parametrize("value", [["app/a.py", "app/b.py"], ("app/a.py", "app/b.py")])
def test_report_coerces_csv_sequences(value: object) -> None:
    finding = OutputFinding.model_validate(_finding(affected_files=value))
    assert finding.affected_files == "app/a.py,app/b.py"


@pytest.mark.parametrize("field", ["affected_files", "files_needing_fixes"])
def test_report_caps_csv_fields_and_logs_truncation(
    field: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    oversized = ["a" * 3000, "b" * 3000]

    with caplog.at_level(logging.WARNING, logger=output_models.__name__):
        finding = OutputFinding.model_validate(_finding(**{field: oversized}))

    value = getattr(finding, field)
    assert len(value) == output_models._CSV_MAX_CHARS
    assert value.endswith(output_models._TRUNCATION_MARKER)
    assert (
        f"validation output field {field} exceeded "
        f"{output_models._CSV_MAX_CHARS} characters; truncating"
    ) in caplog.text


def test_report_caps_an_oversized_csv_string() -> None:
    finding = OutputFinding.model_validate(
        _finding(affected_files="x" * (output_models._CSV_MAX_CHARS + 1))
    )
    assert len(finding.affected_files) == output_models._CSV_MAX_CHARS
    assert finding.affected_files.endswith(output_models._TRUNCATION_MARKER)


def test_report_preserves_csv_string_at_exact_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    value = "x" * output_models._CSV_MAX_CHARS

    with caplog.at_level(logging.WARNING, logger=output_models.__name__):
        finding = OutputFinding.model_validate(_finding(affected_files=value))

    assert finding.affected_files == value
    assert "truncating" not in caplog.text


def test_csv_value_is_redacted_before_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = "x" * (output_models._CSV_MAX_CHARS + 100)
    seen: list[str] = []

    def fake_redact(value: str) -> str:
        seen.append(value)
        return value

    monkeypatch.setattr(output_models, "redact", fake_redact)
    OutputFinding.model_validate(_finding(affected_files=[raw]))

    assert seen == [raw]


def test_out_of_range_score_does_not_drop_the_report() -> None:
    """The whole report must survive one finding with a bogus score."""
    report = ValidationReport.model_validate(
        {"findings": [_finding(tracking_id="F-1", raw_score=42.0), _finding(tracking_id="F-2")]}
    )
    assert [f.tracking_id for f in report.findings] == ["F-1", "F-2"]
    assert report.findings[0].raw_score == 1.0


def test_report_redacts_secret_in_narrative() -> None:
    """Agent free-text is masked at parse; identifiers stay intact for heading matching."""
    report = ValidationReport.model_validate({"findings": [_finding(
        finding_title="Hardcoded AKIAIOSFODNN7EXAMPLE",
        justification="the fix still exposes AKIAIOSFODNN7EXAMPLE",
        recommendations=["rotate AKIAIOSFODNN7EXAMPLE"],
    )]})
    finding = report.findings[0]
    assert "[REDACTED-AWS-KEY]" in finding.justification
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.justification
    assert finding.recommendations == ["rotate [REDACTED-AWS-KEY]"]
    assert finding.finding_title == "Hardcoded AKIAIOSFODNN7EXAMPLE"  # identifier untouched


def test_collect_redacts_secret_in_justification(tmp_path: Path) -> None:
    """End-to-end: a secret in the justification is masked in both the verdict and the row."""
    _write_report(tmp_path, [_finding(
        fix_status="Fixed", raw_score=1.0, justification="still leaks AKIAIOSFODNN7EXAMPLE"
    )])
    _write_gates(tmp_path, "F-1", _ALL_PASS)
    (item,) = collect_and_enrich(tmp_path)
    assert "AKIAIOSFODNN7EXAMPLE" not in item.row.justification
    assert "AKIAIOSFODNN7EXAMPLE" not in item.row.reason_for_decision
    assert "AKIAIOSFODNN7EXAMPLE" not in item.verdict.rationale


# enum parsers


def test_effortlevel_parse() -> None:
    assert EffortLevel.parse("high") is EffortLevel.HIGH
    assert EffortLevel.parse("XHIGH".lower()) is EffortLevel.XHIGH
    assert EffortLevel.parse(None) is None
    assert EffortLevel.parse("bogus") is None
