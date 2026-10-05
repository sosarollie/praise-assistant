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

# START GENAI
"""Tests for ``report.rows`` — presentation derived from the contract, not stored on it.

Two claims the old stored shape made that it was not entitled to, and that these tests hold
the new one to:

  * ``No`` across the tri-state for a case nothing had judged, which reads as "we checked and
    it is not fixed";
  * ``0.0`` for an unscored verdict, which reads as "no confidence in this fix" — a
    measurement, where the validator made none.
"""
from __future__ import annotations

import json

import pytest

from vvaharness.models import (
    Decision,
    DupLocation,
    Finding,
    FindingCase,
    GateAssessment,
    GateStatus,
    MergeReadiness,
    Provenance,
    Remediation,
    RemediationKind,
    ScoringPolicy,
    Severity,
    Verdict,
)
from vvaharness.report.rows import (
    NO,
    UNKNOWN,
    YES,
    md_section_for,
    row_for,
    sarif_result_for,
)


def _finding(**over) -> Finding:
    fields = {
        "title": "SQLi in login", "file": "app/db.py", "line_start": 42,
        "line_end": 44, "vuln_class": "injection", "severity": Severity.CRITICAL,
        "cwe": "CWE-89",
    }
    return Finding(**{**fields, **over})


def _case(*, verdict: Verdict | None = None, attempted: bool = True,
          finding: Finding | None = None) -> FindingCase:
    case = FindingCase(case_id="vvaf1_abc", finding=finding or _finding())
    if not attempted:
        return case
    case = case.with_attempt(
        Remediation(kind=RemediationKind.EDITS_APPLIED, summary="parameterised the query",
                    produced_by=Provenance(engine="vvaharness.agentic")))
    return case if verdict is None else case.with_verdict(verdict)


def _verdict(**over) -> Verdict:
    return Verdict(**{"decision": Decision.FIXED, "rationale": "query is bound now", **over})


# tri-state


def test_unjudged_case_answers_unknown_not_no():
    """Nothing has been validated, so no cell may say ``No``."""
    row = row_for(_case())
    assert (row["fixed"], row["partially_fixed"], row["not_fixed"]) == (
        UNKNOWN, UNKNOWN, UNKNOWN)


def test_case_with_no_attempt_answers_unknown():
    row = row_for(_case(attempted=False))
    assert row["fixed"] == UNKNOWN and row["state"] == "open"


def test_inconclusive_verdict_answers_unknown_across_the_board():
    """A validator that reached no conclusion cannot assert "not partially fixed" either."""
    row = row_for(_case(verdict=_verdict(decision=Decision.INCONCLUSIVE)))
    assert (row["fixed"], row["partially_fixed"], row["not_fixed"]) == (
        UNKNOWN, UNKNOWN, UNKNOWN)


@pytest.mark.parametrize("decision,expected", [
    (Decision.FIXED, (YES, NO, NO)),
    (Decision.PARTIALLY_FIXED, (NO, YES, NO)),
    (Decision.NOT_FIXED, (NO, NO, YES)),
])
def test_concluded_verdict_answers_all_three_cells(decision, expected):
    row = row_for(_case(verdict=_verdict(decision=decision)))
    assert (row["fixed"], row["partially_fixed"], row["not_fixed"]) == expected


# confidence


def test_unscored_verdict_renders_absent_never_zero():
    """Zero is a claim about the fix; absence is a fact about the validator."""
    row = row_for(_case(verdict=_verdict(score=None)))
    assert row["fix_confidence"] is None


def test_scored_verdict_carries_the_number():
    row = row_for(_case(verdict=_verdict(score=0.82)))
    assert row["fix_confidence"] == pytest.approx(0.82)


def test_unscored_verdict_is_still_banded_on_its_decision():
    """A pass/fail validator yields a readiness rather than being read as zero confidence."""
    row = row_for(_case(verdict=_verdict(decision=Decision.FIXED, score=None)))
    assert row["merge_readiness"] == MergeReadiness.READY.value


def test_readiness_follows_the_scan_owners_policy():
    """The thresholds belong to whoever runs the scan; the report does not second-guess them."""
    case = _case(verdict=_verdict(score=0.7))
    strict = ScoringPolicy(ready_at=0.95, conditional_at=0.9)
    assert row_for(case)["merge_readiness"] != row_for(case, policy=strict)["merge_readiness"]
    assert row_for(case, policy=strict)["merge_readiness"] == MergeReadiness.NOT_READY.value


def test_unjudged_case_has_no_readiness():
    assert row_for(_case())["merge_readiness"] == ""


# reason and gates


def test_reason_is_prefixed_with_the_decision():
    """A truncated cell still carries the verdict, which is the part read first."""
    row = row_for(_case(verdict=_verdict(score=0.82)))
    assert row["reason"] == "fixed (score: 0.82). query is bound now"


def test_reason_omits_a_score_nobody_reported():
    row = row_for(_case(verdict=_verdict(score=None)))
    assert row["reason"] == "fixed. query is bound now"


def test_gate_results_json_carries_only_recorded_outcomes():
    """No invented ``weight``: the contract records an outcome and its evidence, not maths."""
    verdict = _verdict(gates=(
        GateAssessment(name="regression", status=GateStatus.PASS, summary="suite green"),
    ))
    parsed = json.loads(row_for(_case(verdict=verdict))["gate_results_json"])
    assert parsed == {"regression": {"status": "pass", "summary": "suite green"}}


def test_gate_results_json_is_empty_without_gates():
    assert row_for(_case(verdict=_verdict()))["gate_results_json"] == ""


def test_row_lists_the_other_sites_a_fix_must_cover():
    finding = _finding(duplicates=[DupLocation(file="app/admin.py", line_start=77,
                                               vuln_class="injection")])
    assert row_for(_case(finding=finding))["also_at"] == ["app/admin.py:77"]


# SARIF


def test_sarif_result_carries_the_case_id_as_a_fingerprint():
    result = sarif_result_for(_case(verdict=_verdict(score=0.82)))
    assert result["partialFingerprints"] == {"vvaFindingId/v1": "vvaf1_abc"}
    assert result["level"] == "error"
    assert result["ruleId"] == "CWE-89"
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 42, "endLine": 44}


def test_sarif_omits_weighted_score_for_an_unscored_verdict():
    """A consumer reading a zero would conclude the fix was measured and found worthless."""
    block = sarif_result_for(_case(verdict=_verdict(score=None)))["properties"]["validation"]
    assert "weightedScore" not in block
    assert block["validationStatus"] == "fixed"


def test_sarif_has_no_validation_block_before_a_verdict():
    assert "validation" not in sarif_result_for(_case())["properties"]


def test_sarif_surfaces_duplicate_sites_as_related_locations():
    """Duplicates are the other sites a fix must reach, not noise dedup threw away."""
    finding = _finding(duplicates=[DupLocation(file="app/admin.py", line_start=77,
                                               line_end=79, vuln_class="injection")])
    related = sarif_result_for(_case(finding=finding))["relatedLocations"]
    assert related[0]["physicalLocation"]["region"] == {"startLine": 77, "endLine": 79}


# markdown


def test_md_section_says_not_yet_validated_rather_than_guessing():
    text = md_section_for(_case())
    assert "Not yet validated" in text
    assert "Confidence" not in text


def test_md_section_says_not_scored_for_an_unscored_verdict():
    text = md_section_for(_case(verdict=_verdict(score=None)))
    assert "**Confidence:** not scored" in text
    assert "0.00" not in text


def test_md_section_defangs_agent_authored_text():
    """The rationale is model output; it must not be able to inject Markdown or HTML."""
    text = md_section_for(_case(verdict=_verdict(
        rationale="see <script>x</script> | ### heading")))
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "\\|" in text and "\\#" in text


def test_md_section_renders_gate_rows():
    verdict = _verdict(gates=(
        GateAssessment(name="regression", status=GateStatus.FAIL, summary="2 tests red"),
    ))
    text = md_section_for(_case(verdict=verdict))
    assert "| gate | status | summary |" in text
    assert "| regression | fail | 2 tests red |" in text
