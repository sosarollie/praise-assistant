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

"""Characterization tests for the pure validation scoring logic.

Locks down exact outputs for the scoring engine, justifier, and the host-side publisher
so later refactors can prove behavioral equivalence.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from vvaharness.models import (
    Decision,
    EvidenceAnchor,
    GateStatus,
    MergeReadiness,
    Provenance,
    Verdict,
    merge_readiness_for,
)
from vvaharness.validation.constants.scoring import FIX_POLICY
from vvaharness.validation.io._host_score import verdict_for
from vvaharness.validation.models.scoring import (
    RawCriterion,
    ScoreResult,
    ScoringConfig,
    VerdictRule,
)
from vvaharness.validation.scoring import score_fix
from vvaharness.validation.scoring._configs import FIX_CONFIG
from vvaharness.validation.scoring._engine import (
    INCONCLUSIVE_PREFIX,
    _apply_verdicts,
    parse_raw_criterion,
    score,
)
from vvaharness.validation.scoring._justify import build_fix_justification

# Fixtures / shared config

_WEIGHTS = {
    "root_cause": 0.43,
    "instance_coverage": 0.2467,
    "no_new_vulnerabilities": 0.1867,
    "security_best_practices": 0.1366,
}
_MULTIPLIER = {"pass": 1.0, "partial": 0.5, "fail": 0.0, "skip": 0.0}
_VERDICTS = (
    VerdictRule(min_score=0.80, decision=Decision.FIXED),
    VerdictRule(min_score=0.50, decision=Decision.PARTIALLY_FIXED),
    VerdictRule(min_score=0.0, decision=Decision.NOT_FIXED),
)

# expected_criteria is the published contract, stated explicitly -- it is no longer inferred
# from the weights, so a config cannot quietly enforce a different gate set than it asked for.
_CFG = ScoringConfig(
    name="fix",
    criterion_name_field="gate_name",
    weights=_WEIGHTS,
    expected_criteria=frozenset(_WEIGHTS),
    status_multiplier=_MULTIPLIER,
    verdicts=_VERDICTS,
    justify=build_fix_justification,
)

# Same as _CFG, but with no_new_vulnerabilities pinned as a non-skippable critical gate
# (mirrors the shipped FIX_CONFIG) so the fail-closed critical-gate paths are exercised.
_CRIT_CFG = ScoringConfig(
    name="fix",
    criterion_name_field="gate_name",
    weights=_WEIGHTS,
    expected_criteria=frozenset(_WEIGHTS),
    status_multiplier=_MULTIPLIER,
    verdicts=_VERDICTS,
    justify=build_fix_justification,
    critical_criteria=frozenset({"no_new_vulnerabilities"}),
)

_ALL_PASS = [
    RawCriterion(name="root_cause", status="pass", summary="Root cause addressed"),
    RawCriterion(name="instance_coverage", status="pass", summary="All instances covered"),
    RawCriterion(name="no_new_vulnerabilities", status="pass", summary="No new vulns"),
    RawCriterion(name="security_best_practices", status="pass", summary="Best practices met"),
]

_ALL_FAIL = [
    RawCriterion(name="root_cause", status="fail", summary="Root cause not fixed"),
    RawCriterion(name="instance_coverage", status="fail", summary="Instances missed"),
    RawCriterion(name="no_new_vulnerabilities", status="fail", summary="New vulns introduced"),
    RawCriterion(name="security_best_practices", status="fail", summary="Best practices ignored"),
]

_PARTIAL = [
    RawCriterion(name="root_cause", status="pass", summary="Root cause addressed"),
    RawCriterion(name="instance_coverage", status="partial", summary="Some instances covered"),
    RawCriterion(name="no_new_vulnerabilities", status="pass", summary="No new vulns"),
    RawCriterion(name="security_best_practices", status="fail", summary="Practices missing"),
]


# ScoringConfig / ScoringPolicy round trip

class TestConfigDerivesFromPolicy:
    def test_expected_criteria_is_the_weight_key_set(self) -> None:
        """The gate set is derived, so a weight and its expectation cannot disagree."""
        assert _CFG.expected_criteria == frozenset(_WEIGHTS)   # they agree, and now by contract

    def test_shipped_config_bands_at_the_policy_thresholds(self) -> None:
        """FIX_POLICY owns the thresholds; the engine config must not restate them."""
        assert FIX_CONFIG.verdicts[0].min_score == FIX_POLICY.ready_at
        assert FIX_CONFIG.verdicts[1].min_score == FIX_POLICY.conditional_at
        assert FIX_CONFIG.expected_criteria == frozenset(FIX_POLICY.weights)
        assert FIX_CONFIG.critical_criteria == FIX_POLICY.critical

    def test_to_policy_round_trips_the_shipped_config(self) -> None:
        """A host reading the config back out gets the policy it was built from.

        ``required_gates`` round-trips as a set, not a sequence: to_policy sorts it, while
        FIX_POLICY declares the panel's own order. Nothing branches on that order.
        """
        derived = FIX_CONFIG.to_policy()
        assert set(derived.required_gates) == set(FIX_POLICY.required_gates)
        assert derived.weights == FIX_POLICY.weights
        assert derived.critical == FIX_POLICY.critical
        assert derived.ready_at == FIX_POLICY.ready_at
        assert derived.conditional_at == FIX_POLICY.conditional_at


# parse_raw_criterion

class TestParseRawCriterion:
    def test_full_entry(self) -> None:
        entry = {
            "gate_name": "root_cause",
            "status": "pass",
            "summary": "Fixed",
            "details": "detail text",
            "evidence": [{"file": "a.py", "line": 10, "snippet": "code"}],
        }
        rc = parse_raw_criterion(entry, "gate_name")
        assert rc.name == "root_cause"
        assert rc.status == "pass"
        assert rc.summary == "Fixed"
        assert rc.details == "detail text"
        assert len(rc.evidence) == 1
        assert rc.evidence[0] == EvidenceAnchor(file="a.py", line=10, snippet="code")

    def test_missing_fields_default_to_empty(self) -> None:
        rc = parse_raw_criterion({"gate_name": "x"}, "gate_name")
        # An absent status is out-of-vocabulary, so it canonicalizes to "invalid"
        # (scored 0.0, kept in the denominator) rather than a droppable "skip";
        # summary/evidence still default to empty.
        assert rc.status == "invalid"
        assert rc.summary == ""
        assert rc.evidence == ()

    def test_evidence_ignores_non_mappings(self) -> None:
        entry = {"gate_name": "x", "status": "pass", "evidence": ["not a dict", 42]}
        rc = parse_raw_criterion(entry, "gate_name")
        assert rc.evidence == ()

    def test_bool_line_value_becomes_none(self) -> None:
        entry = {"gate_name": "x", "evidence": [{"file": "f.py", "line": True}]}
        rc = parse_raw_criterion(entry, "gate_name")
        assert rc.evidence[0].line is None


# _apply_verdicts

class TestApplyVerdicts:
    def test_above_fixed_threshold(self) -> None:
        assert _apply_verdicts(_CFG, 1.0) is Decision.FIXED
        assert _apply_verdicts(_CFG, 0.80) is Decision.FIXED

    def test_partial_range(self) -> None:
        assert _apply_verdicts(_CFG, 0.79) is Decision.PARTIALLY_FIXED
        assert _apply_verdicts(_CFG, 0.50) is Decision.PARTIALLY_FIXED

    def test_below_partial_threshold(self) -> None:
        assert _apply_verdicts(_CFG, 0.49) is Decision.NOT_FIXED
        assert _apply_verdicts(_CFG, 0.0) is Decision.NOT_FIXED


# score

class TestScore:
    def test_all_pass_is_fixed(self) -> None:
        result = score(_CFG, _ALL_PASS)
        assert result.decision is Decision.FIXED
        assert result.raw_score == pytest.approx(1.0, abs=1e-4)

    def test_all_fail_is_not_fixed(self) -> None:
        result = score(_CFG, _ALL_FAIL)
        assert result.decision is Decision.NOT_FIXED
        assert result.raw_score == 0.0

    def test_partial_gates_produce_fractional_score(self) -> None:
        result = score(_CFG, _PARTIAL)
        expected = round(
            0.43 * 1.0 + 0.2467 * 0.5 + 0.1867 * 1.0 + 0.1366 * 0.0, 4
        )
        assert result.raw_score == pytest.approx(expected, abs=1e-4)


# SKIP earns no credit; raw_score clamped to <= 1.0

class TestSkipAndClamp:
    def test_skip_gate_is_weight_neutral(self) -> None:
        # A skipped gate is unevaluated — dropped from the denominator, never a
        # failure. Two passes + two skips renormalize to a perfect, Fixed score.
        skipped = [
            RawCriterion(name="root_cause", status="pass", summary="ok"),
            RawCriterion(name="instance_coverage", status="skip", summary="not evaluated"),
            RawCriterion(name="no_new_vulnerabilities", status="skip", summary="not evaluated"),
            RawCriterion(name="security_best_practices", status="pass", summary="ok"),
        ]
        result = score(_CFG, skipped)
        # active weight 0.43 + 0.1366 = 0.5666 >= floor; both pass → 1.0 / FIXED.
        assert result.raw_score == pytest.approx(1.0, abs=1e-4)
        assert result.decision is Decision.FIXED

    def test_production_config_refuses_a_skipped_critical_gate(self) -> None:
        gates: list[Mapping[str, object]] = [
            {"gate_name": "root_cause", "status": "fail"},
            {"gate_name": "instance_coverage", "status": "skip"},
            {"gate_name": "no_new_vulnerabilities", "status": "skip"},
            {"gate_name": "security_best_practices", "status": "skip"},
        ]
        # The one gate anybody evaluated failed, and both critical gates went unevaluated:
        # the shipped policy pins root_cause AND no_new_vulnerabilities, so this fails closed
        # with no number rather than renormalizing the lone fail into a scoreable verdict.
        result = score_fix(gates)
        assert result.decision is Decision.INCONCLUSIVE
        assert result.raw_score == pytest.approx(0.0, abs=1e-4)

    def test_raw_score_clamped_to_one(self) -> None:
        # A weights-misconfig that sums > 1.0 must not produce a score above 1.0.
        inflated = ScoringConfig(
            name="fix",
            criterion_name_field="gate_name",
            weights={"a": 0.8, "b": 0.8},
            expected_criteria=frozenset({"a", "b"}),
            status_multiplier={"pass": 1.0, "partial": 0.5, "fail": 0.0, "skip": 0.0},
            verdicts=_VERDICTS,
            justify=build_fix_justification,
        )
        result = score(inflated, [
            RawCriterion(name="a", status="pass", summary="x"),
            RawCriterion(name="b", status="pass", summary="y"),
        ])
        assert result.raw_score == 1.0

    def test_missing_criteria_returns_inconclusive(self) -> None:
        incomplete = [RawCriterion(name="root_cause", status="pass")]
        result = score(_CFG, incomplete)
        assert result.decision is Decision.INCONCLUSIVE
        assert result.raw_score == 0.0
        assert result.justification.startswith(f"{INCONCLUSIVE_PREFIX}: ")
        assert "Missing criterion" in result.justification

    def test_duplicate_criterion_returns_inconclusive(self) -> None:
        dup = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="fail"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CFG, dup)
        assert result.decision is Decision.INCONCLUSIVE
        assert result.raw_score == 0.0
        assert result.justification.startswith(f"{INCONCLUSIVE_PREFIX}: ")
        assert "Duplicate criterion" in result.justification
        assert "root_cause" in result.justification

    def test_justification_is_populated(self) -> None:
        result = score(_CFG, _ALL_PASS)
        assert result.justification != ""

    def test_extra_none_is_treated_as_empty(self) -> None:
        result = score(_CFG, _ALL_PASS, extra=None)
        assert result.decision is Decision.FIXED


# renormalization: skip is weight-neutral; thin coverage is guarded by the critical
# gates, not by an aggregate weight threshold

class TestRenormalization:
    def test_cross_repo_two_skips_still_fixed(self) -> None:
        # Cross-repo persona by design skips no_new_vulnerabilities +
        # security_best_practices; the two passing gates renormalize to a clean FIXED
        # instead of being deflated by the skips.
        gates = [
            RawCriterion(name="root_cause", status="pass", summary="ok"),
            RawCriterion(name="instance_coverage", status="pass", summary="ok"),
            RawCriterion(name="no_new_vulnerabilities", status="skip", summary="n/a"),
            RawCriterion(name="security_best_practices", status="skip", summary="n/a"),
        ]
        result = score(_CFG, gates)
        assert result.raw_score == pytest.approx(1.0, abs=1e-4)
        assert result.decision is Decision.FIXED

    def test_single_gate_is_inconclusive_via_critical_gate(self) -> None:
        # Only root_cause evaluated. The retired coverage floor used to catch this by
        # aggregate weight; the critical-gate check catches it outright and unwaivably,
        # because skipping no_new_vulnerabilities is itself INCONCLUSIVE.
        gates = [
            RawCriterion(name="root_cause", status="pass", summary="ok"),
            RawCriterion(name="instance_coverage", status="skip"),
            RawCriterion(name="no_new_vulnerabilities", status="skip"),
            RawCriterion(name="security_best_practices", status="skip"),
        ]
        result = score(_CRIT_CFG, gates)
        assert result.decision is Decision.INCONCLUSIVE
        assert result.raw_score == 0.0
        assert "no_new_vulnerabilities" in result.justification

    def test_thin_coverage_scores_without_critical_gates(self) -> None:
        # Documents the consequence of retiring the floor: a config that pins no critical
        # gates now scores a single evaluated gate rather than refusing it. Every shipped
        # config pins critical gates, so this shape is unreachable in production.
        gates = [
            RawCriterion(name="root_cause", status="pass", summary="ok"),
            RawCriterion(name="instance_coverage", status="skip"),
            RawCriterion(name="no_new_vulnerabilities", status="skip"),
            RawCriterion(name="security_best_practices", status="skip"),
        ]
        result = score(_CFG, gates)
        assert result.raw_score == pytest.approx(1.0, abs=1e-4)

    def test_all_skip_is_inconclusive_no_zero_division(self) -> None:
        # Active weight 0.0 must short-circuit to INCONCLUSIVE, never ZeroDivisionError.
        # This is the sole remaining purpose of the zero guard in _renormalized_score.
        gates = [
            RawCriterion(name="root_cause", status="skip"),
            RawCriterion(name="instance_coverage", status="skip"),
            RawCriterion(name="no_new_vulnerabilities", status="skip"),
            RawCriterion(name="security_best_practices", status="skip"),
        ]
        result = score(_CFG, gates)
        assert result.decision is Decision.INCONCLUSIVE
        assert result.raw_score == 0.0
        assert "no gates were evaluated" in result.justification

    def test_no_skip_cases_unchanged(self) -> None:
        # Regression: with no skips active_weight == 1.0, so renormalization is a no-op.
        assert score(_CFG, _ALL_PASS).raw_score == pytest.approx(1.0, abs=1e-4)
        expected = round(0.43 * 1.0 + 0.2467 * 0.5 + 0.1867 * 1.0 + 0.1366 * 0.0, 4)
        assert score(_CFG, _PARTIAL).raw_score == pytest.approx(expected, abs=1e-4)


# critical gate: no_new_vulnerabilities cannot be skipped, garbled, or waived

class TestCriticalGate:
    def test_critical_skip_is_inconclusive(self) -> None:
        # A skipped critical gate cannot be dropped to inflate the score — fail closed.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="skip"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CRIT_CFG, gates)
        assert result.decision is Decision.INCONCLUSIVE
        assert result.raw_score == 0.0

    def test_critical_invalid_is_inconclusive(self) -> None:
        # A garbled critical status canonicalizes to INVALID, which also fails closed.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="invalid"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CRIT_CFG, gates)
        assert result.decision is Decision.INCONCLUSIVE

    def test_critical_fail_caps_below_fixed(self) -> None:
        # nnv fails but the other gates pass: raw_score 0.8133 would clear the FIXED
        # threshold, yet a failed critical gate caps the decision at PARTIALLY_FIXED.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="fail"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CRIT_CFG, gates)
        assert result.raw_score == pytest.approx(0.8133, abs=1e-4)
        assert result.decision is Decision.PARTIALLY_FIXED

    def test_critical_partial_caps_below_fixed(self) -> None:
        # nnv=partial earns half credit, so the other three passes leave raw_score 0.9066
        # (above the FIXED threshold) — yet a not-clean critical gate still caps to
        # PARTIALLY_FIXED. partial scores higher than fail (0.8133) but must not out-weight
        # the gate.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="partial"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CRIT_CFG, gates)
        assert result.raw_score == pytest.approx(0.9066, abs=1e-4)
        assert result.decision is Decision.PARTIALLY_FIXED

    def test_non_critical_invalid_stays_in_denominator(self) -> None:
        # A garbled NON-critical gate is INVALID (scored 0.0, kept in the denominator),
        # so it drags the score down rather than vanishing.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="pass"),
            RawCriterion(name="security_best_practices", status="invalid"),
        ]
        result = score(_CRIT_CFG, gates)
        # 1.0 - 0.1366 weight earns 0.0 → 0.8634, still FIXED but not a perfect 1.0.
        assert result.raw_score == pytest.approx(0.8634, abs=1e-4)

    @pytest.mark.parametrize("nnv,expected", [("fail", True), ("partial", True), ("pass", False)])
    def test_score_fix_sets_has_critical_failure(self, nnv: str, expected: bool) -> None:
        # has_critical_failure tracks a not-clean critical gate (fail OR partial), not just fail.
        gates: list[Mapping[str, object]] = [
            {"gate_name": "root_cause", "status": "pass"},
            {"gate_name": "instance_coverage", "status": "pass"},
            {"gate_name": "no_new_vulnerabilities", "status": nnv},
            {"gate_name": "security_best_practices", "status": "pass"},
        ]
        assert score_fix(gates).has_critical_failure is expected


# GateStatus: tolerant status coercion via _missing_ (replaces the retired GateStatus.parse)

class TestGateStatusCoercion:
    def test_canonical_values(self) -> None:
        assert GateStatus("pass") is GateStatus.PASS
        assert GateStatus("skip") is GateStatus.SKIP

    def test_case_and_whitespace_variants(self) -> None:
        assert GateStatus("PASS") is GateStatus.PASS
        assert GateStatus(" Pass ") is GateStatus.PASS

    def test_unknown_token_is_invalid(self) -> None:
        # Out-of-vocabulary tokens fail closed to INVALID (scored 0.0), never SKIP,
        # so a garbled status can't be silently dropped from the denominator.
        assert GateStatus("verified") is GateStatus.INVALID

    def test_non_string_is_invalid(self) -> None:
        # _missing_ absorbs these rather than raising ValueError, so one garbled field
        # from a model never aborts the run.
        assert GateStatus(None) is GateStatus.INVALID
        assert GateStatus(42) is GateStatus.INVALID

    def test_score_fix_tolerates_unknown_status(self) -> None:
        # An out-of-vocabulary status must not raise; it coerces to INVALID
        # (scored 0.0, kept in the denominator) and a full gate set is still built.
        gates: list[Mapping[str, object]] = [
            {"gate_name": "root_cause", "status": "totally-bogus"},
            {"gate_name": "instance_coverage", "status": "pass"},
            {"gate_name": "no_new_vulnerabilities", "status": "pass"},
            {"gate_name": "security_best_practices", "status": "pass"},
        ]
        result = score_fix(gates)
        assert len(result.gates) == len(gates)
        root = next(g for g in result.gates if g.name == "root_cause")
        assert root.status is GateStatus.INVALID


# build_fix_justification

class TestBuildFixJustification:
    def _partial_result(self, decision: Decision, score_val: float = 0.65) -> ScoreResult:
        return ScoreResult(raw_score=score_val, decision=decision, justification="")

    def test_inconclusive_returns_existing_justification(self) -> None:
        r = ScoreResult(
            raw_score=0.0, decision=Decision.INCONCLUSIVE, justification="pre-set"
        )
        assert build_fix_justification(r, [], {}) == "pre-set"

    def test_inconclusive_empty_justification_returns_empty(self) -> None:
        r = ScoreResult(raw_score=0.0, decision=Decision.INCONCLUSIVE, justification="")
        assert build_fix_justification(r, [], {}) == ""

    def test_fixed_contains_confidence_and_pass_gates(self) -> None:
        r = self._partial_result(Decision.FIXED, 0.86)
        text = build_fix_justification(r, _ALL_PASS, {})
        assert "Fix verified:" in text
        assert "86%" in text
        assert "Evidence:" in text

    def test_partially_fixed_contains_gaps(self) -> None:
        r = self._partial_result(Decision.PARTIALLY_FIXED, 0.65)
        text = build_fix_justification(r, _PARTIAL, {})
        assert "Partial fix:" in text
        assert "Gaps:" in text
        assert "65%" in text

    def test_not_fixed_contains_failed_gates(self) -> None:
        r = self._partial_result(Decision.NOT_FIXED, 0.0)
        text = build_fix_justification(r, _ALL_FAIL, {})
        assert "Fix insufficient:" in text
        assert "Recommended action:" in text

    def test_evidence_anchors_appear_in_fixed_text(self) -> None:
        gates = [
            RawCriterion(
                name="root_cause",
                status="pass",
                summary="ok",
                evidence=(EvidenceAnchor(file="a.py", line=5, snippet=""),),
            ),
            *_ALL_PASS[1:],
        ]
        r = ScoreResult(raw_score=1.0, decision=Decision.FIXED, justification="")
        text = build_fix_justification(r, gates, {})
        assert "a.py:5" in text


# The published gate list must never contradict the verdict
#
# A second, diverging gate-table builder used to live in scoring/__main__.py and skipped
# status canonicalisation, so a case variant like "PASS" scored 0.0 in the published table
# while the engine scored the same input Fixed/1.0. There is now one builder: verdict_for
# publishes exactly the gates score_fix scored. These lock that class of divergence out of it.

_GATE_NAMES = ("root_cause", "instance_coverage", "no_new_vulnerabilities",
               "security_best_practices")


def _gates(status: str, names: tuple[str, ...] = _GATE_NAMES) -> list[Mapping[str, object]]:
    return [{"gate_name": name, "status": status} for name in names]


def _published(status: str, names: tuple[str, ...] = _GATE_NAMES) -> Verdict:
    """The host-facing verdict for gates carrying *status*, as a scan would publish it."""
    return verdict_for(
        None, _gates(status, names), provenance=Provenance(), policy=FIX_POLICY
    )


class TestPublishedGatesAgreeWithVerdict:
    def test_uppercase_pass_scores_full_credit_not_zero(self) -> None:
        """The exact regression: "PASS" must earn its weight, not 0.0."""
        published = _published("PASS")
        assert published.decision is Decision.FIXED
        assert published.score == pytest.approx(1.0, abs=1e-4)

    @pytest.mark.parametrize("gate_name", _GATE_NAMES)
    def test_uppercase_pass_earns_exactly_that_gates_weight(self, gate_name: str) -> None:
        """Canonicalisation credits the weight of the gate that passed, not some other gate's."""
        gates: list[Mapping[str, object]] = [
            {"gate_name": name, "status": "PASS" if name == gate_name else "FAIL"}
            for name in _GATE_NAMES
        ]
        # Weights sum to 1.0 and no gate is skipped, so the renormalized score is the weight.
        assert score_fix(gates).raw_score == pytest.approx(
            FIX_CONFIG.weights[gate_name], abs=1e-4
        )

    def test_published_score_is_the_engine_raw_score(self) -> None:
        """The published number is derived from the scored gates, not computed independently."""
        gates = _gates("PASS")
        published = verdict_for(None, gates, provenance=Provenance(), policy=FIX_POLICY)
        assert published.score == pytest.approx(score_fix(gates).raw_score, abs=1e-4)

    def test_case_variants_produce_identical_published_gates(self) -> None:
        baseline = _published("pass")
        for variant in ("PASS", "Pass", "pAsS", " pass "):
            candidate = _published(variant)
            assert candidate.gates == baseline.gates
            assert candidate.score == baseline.score
            assert candidate.decision is baseline.decision

    def test_uppercase_partial_scores_half_credit(self) -> None:
        published = _published("PARTIAL")
        assert published.score == pytest.approx(0.5, abs=1e-4)
        assert published.decision is Decision.PARTIALLY_FIXED

    def test_uppercase_fail_scores_zero(self) -> None:
        published = _published("FAIL")
        assert published.score == 0.0
        assert published.decision is Decision.NOT_FIXED

    def test_uppercase_skip_earns_no_credit_and_no_number(self) -> None:
        # Every gate unevaluated, including both critical ones: refused outright, so there
        # is no score at all rather than a zero that could read as a scored outcome.
        published = _published("SKIP")
        assert published.decision is Decision.INCONCLUSIVE
        assert published.score is None
        assert published.rationale.startswith(f"{INCONCLUSIVE_PREFIX}: ")

    def test_status_is_published_canonicalised(self) -> None:
        """The published gates report the canonical status actually scored, not the raw input."""
        published = _published("PASS")
        assert {gate.status for gate in published.gates} == {GateStatus.PASS}

    def test_out_of_vocab_status_is_published_invalid_and_earns_zero(self) -> None:
        # security_best_practices is the one non-critical gate; a garbled status on a
        # critical gate refuses the panel outright instead of being scored (see
        # TestCriticalGate.test_critical_invalid_is_inconclusive).
        garbled = "security_best_practices"
        gates: list[Mapping[str, object]] = [
            {"gate_name": name, "status": "definitely-not-a-status" if name == garbled else "pass"}
            for name in _GATE_NAMES
        ]
        result = score_fix(gates)
        assert next(gate for gate in result.gates if gate.name == garbled).status is (
            GateStatus.INVALID
        )
        # INVALID stays in the denominator, so that gate's 0.1366 is forfeited, not dropped.
        assert result.raw_score == pytest.approx(1.0 - FIX_CONFIG.weights[garbled], abs=1e-4)

    def test_unknown_gate_name_earns_no_credit(self) -> None:
        # An unrecognised name is published (the evidence for the refusal) but cannot be
        # weighted, so the panel is refused rather than scored on a gate nobody defined.
        published = _published("PASS", ("not_a_real_gate",))
        assert [gate.name for gate in published.gates] == ["not_a_real_gate"]
        assert published.decision is Decision.INCONCLUSIVE
        assert published.score is None


def test_merge_readiness_is_derivable_for_a_passing_score() -> None:
    """Guards the readiness derivation with the shape a production caller publishes."""
    assert merge_readiness_for(_published("PASS"), FIX_POLICY) is MergeReadiness.READY


def test_merge_readiness_is_not_ready_for_a_refused_panel() -> None:
    """An unscored, refused verdict must not fall through to READY."""
    assert merge_readiness_for(_published("SKIP"), FIX_POLICY) is MergeReadiness.NOT_READY
