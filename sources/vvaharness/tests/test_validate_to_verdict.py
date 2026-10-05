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

"""The adapter from this engine's retired verdict vocabulary onto the shared Decision.

``vvaharness.models.Decision`` deliberately carries no aliases for ``"UNVERIFIABLE"`` or
``"Partially Fixed"`` -- those are this engine's prompt values, so translating them is this
adapter's job. These tests pin that the translation is TOTAL: every label the prompt asks the
model for resolves to a decision, and nothing silently reads as FIXED.
"""

from __future__ import annotations

import pytest

from vvaharness.models import Decision, GateStatus, Provenance
from vvaharness.validation.models.output import (
    FIX_STATUS_LABELS,
    GateEntry,
    OutputFinding,
    SynthesizedGatesEntry,
    decision_for,
    to_verdict,
)

# The exact strings vvaharness/validation/prompts/system.md asks the model to emit.
_PROMPT_VOCABULARY = ("Fixed", "Partially Fixed", "Not Fixed", "UNVERIFIABLE")

_EXPECTED = {
    "Fixed": Decision.FIXED,
    "Partially Fixed": Decision.PARTIALLY_FIXED,
    "Not Fixed": Decision.NOT_FIXED,
    "UNVERIFIABLE": Decision.INCONCLUSIVE,
}


def _finding(**overrides: object) -> OutputFinding:
    """An OutputFinding with only the frozen schema's required fields supplied."""
    base: dict[str, object] = {
        "tracking_id": "F-1",
        "finding_title": "t",
        "finding_description": "d",
        "affected_files": "app/x.py",
    }
    return OutputFinding.model_validate(base | overrides)


class TestMappingIsTotal:
    def test_every_prompt_label_is_mapped(self) -> None:
        """No label the prompt asks for may be missing from the table."""
        assert set(FIX_STATUS_LABELS) == set(_PROMPT_VOCABULARY)

    def test_no_extra_labels(self) -> None:
        """The table must not claim to translate a label the prompt never asks for."""
        assert set(FIX_STATUS_LABELS) <= set(_PROMPT_VOCABULARY)

    def test_every_decision_is_reachable(self) -> None:
        """All four decisions must be producible, or a verdict is unexpressible."""
        assert set(FIX_STATUS_LABELS.values()) == set(Decision)

    @pytest.mark.parametrize(("label", "decision"), sorted(_EXPECTED.items()))
    def test_each_label_maps_to_its_decision(self, label: str, decision: Decision) -> None:
        """The retired vocabulary translates exactly, UNVERIFIABLE included."""
        assert FIX_STATUS_LABELS[label] is decision
        assert decision_for(label) is decision


class TestDecisionForFailsClosed:
    @pytest.mark.parametrize("label", ["", "  ", "Sort of fixed", "FIXED?", "resolved", "true"])
    def test_unknown_label_is_inconclusive(self, label: str) -> None:
        """An invented label must never read as a fix."""
        assert decision_for(label) is Decision.INCONCLUSIVE

    @pytest.mark.parametrize(
        ("label", "decision"),
        [
            ("fixed", Decision.FIXED),
            ("FIXED", Decision.FIXED),
            (" Fixed ", Decision.FIXED),
            ("\tFixed\n", Decision.FIXED),
            ("partially fixed", Decision.PARTIALLY_FIXED),
            ("PARTIALLY FIXED", Decision.PARTIALLY_FIXED),
            ("not fixed", Decision.NOT_FIXED),
            ("unverifiable", Decision.INCONCLUSIVE),
        ],
    )
    def test_casing_and_whitespace_are_folded(self, label: str, decision: Decision) -> None:
        """A model that varies casing or pads whitespace is understood, not failed closed on."""
        assert decision_for(label) is decision


class TestToVerdict:
    def test_score_is_none_when_inconclusive(self) -> None:
        """An unscored verdict records None, never 0.0 -- zero is a different claim.

        The frozen schema defaults ``raw_score`` to 0.0, so an UNVERIFIABLE finding always
        arrives carrying a zero it never meant as a confidence value.
        """
        verdict = to_verdict(
            _finding(fix_status="UNVERIFIABLE", raw_score=0.0),
            None,
            provenance=Provenance(),
        )
        assert verdict.decision is Decision.INCONCLUSIVE
        assert verdict.score is None

    def test_score_is_carried_when_conclusive(self) -> None:
        """A real decision keeps the agent's number."""
        verdict = to_verdict(
            _finding(fix_status="Fixed", raw_score=0.91), None, provenance=Provenance()
        )
        assert verdict.decision is Decision.FIXED
        assert verdict.score == pytest.approx(0.91)

    def test_zero_score_survives_a_real_decision(self) -> None:
        """A genuine 0.0 on a NOT_FIXED verdict is a claim, so it is not turned into None."""
        verdict = to_verdict(
            _finding(fix_status="Not Fixed", raw_score=0.0), None, provenance=Provenance()
        )
        assert verdict.decision is Decision.NOT_FIXED
        assert verdict.score == 0.0

    def test_narrative_and_provenance_are_carried(self) -> None:
        """Conditions, recommendations and rationale reach the verdict intact."""
        stamp = Provenance(engine="vvaharness.validation", model="m")
        verdict = to_verdict(
            _finding(
                fix_status="Partially Fixed",
                raw_score=0.6,
                justification="half done",
                conditions_for_full_fix=["escape the other sink"],
                recommendations=["add a regression test"],
            ),
            None,
            provenance=stamp,
        )
        assert verdict.decision is Decision.PARTIALLY_FIXED
        assert verdict.rationale == "half done"
        assert verdict.conditions == ("escape the other sink",)
        assert verdict.recommendations == ("add a regression test",)
        assert verdict.produced_by == stamp

    def test_gates_are_adapted_onto_the_shared_contract(self) -> None:
        """Synthesized gates become GateAssessments, with structured evidence preserved."""
        gates = SynthesizedGatesEntry(
            tracking_id="F-1",
            gates=[
                GateEntry(
                    gate_name="root_cause",
                    status="pass",
                    summary="fixed at source",
                    details="d",
                    evidence=[{"file": "app/x.py", "line": 12, "snippet": "parameterised"}],
                ),
                GateEntry(gate_name="instance_coverage", status="skip", summary="not assessed"),
            ],
        )
        verdict = to_verdict(
            _finding(fix_status="Fixed", raw_score=1.0), gates, provenance=Provenance()
        )
        assert [g.name for g in verdict.gates] == ["root_cause", "instance_coverage"]
        assert verdict.gates[0].status is GateStatus.PASS
        assert verdict.gates[0].summary == "fixed at source"
        assert verdict.gates[0].evidence[0].file == "app/x.py"
        assert verdict.gates[0].evidence[0].line == 12
        assert verdict.gates[0].evidence[0].snippet == "parameterised"
        # skip is a real outcome the model may report; it must survive as SKIP, not fold to FAIL.
        assert verdict.gates[1].status is GateStatus.SKIP

    def test_absent_gates_yield_no_gates(self) -> None:
        """A finding with no synthesized gates carries none, rather than inventing them."""
        verdict = to_verdict(_finding(fix_status="Fixed"), None, provenance=Provenance())
        assert verdict.gates == ()


def test_conformance_downgrades_a_verdict_missing_a_required_gate() -> None:
    """A replacement validator cannot score itself over a partial gate set.

    The engine owns HOW gates become a decision; the harness owns WHICH must be answered."""
    from vvaharness.models import Decision, GateAssessment, GateStatus, ScoringPolicy, Verdict
    from vvaharness.validation.io._host_score import conformant

    policy = ScoringPolicy(required_gates=("root_cause", "no_new_vulnerabilities"),
                           weights={"root_cause": 0.5, "no_new_vulnerabilities": 0.5})
    claimed = Verdict(
        decision=Decision.FIXED, score=1.0, rationale="all good",
        gates=(GateAssessment(name="root_cause", status=GateStatus.PASS),),
    )
    checked = conformant(claimed, policy)
    assert checked.decision is Decision.INCONCLUSIVE
    assert checked.score is None
    assert "no_new_vulnerabilities" in checked.rationale


def test_conformance_allows_extra_gates() -> None:
    """The gate vocabulary is open; only silence on a required gate is a failure."""
    from vvaharness.models import Decision, GateAssessment, GateStatus, ScoringPolicy, Verdict
    from vvaharness.validation.io._host_score import conformant

    policy = ScoringPolicy(required_gates=("root_cause",), weights={"root_cause": 1.0})
    v = Verdict(
        decision=Decision.FIXED, score=0.9, rationale="ok",
        gates=(GateAssessment(name="root_cause", status=GateStatus.PASS),
               GateAssessment(name="acme_custom_check", status=GateStatus.PASS)),
    )
    assert conformant(v, policy) is v


def test_scoring_policy_refuses_disagreeing_gate_sets() -> None:
    """The contract and the scorer cannot name different gates; it used to prefer weights."""
    import pytest

    from vvaharness.models import ScoringPolicy

    with pytest.raises(ValueError, match="gate sets disagree"):
        ScoringPolicy(required_gates=("a", "b"), weights={"a": 0.5, "c": 0.5})
