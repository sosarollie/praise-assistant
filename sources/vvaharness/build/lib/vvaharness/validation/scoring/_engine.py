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

"""Config-driven scoring engine; speaks Decision, fails closed to INCONCLUSIVE on any gap."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from vvaharness.models import Decision, EvidenceAnchor, GateStatus
from vvaharness.validation.constants.scoring import SCORE_FLOOR, SCORE_PRECISION
from vvaharness.validation.enums.synthesis import SynthesisConfidence
from vvaharness.validation.models.scoring import (
    RawCriterion,
    RawExtra,
    ScoreResult,
    ScoringConfig,
)

__all__ = ["parse_raw_criterion", "score"]

#: Prefix on a fail-closed rationale. Host-facing diagnostic text, not prompt vocabulary.
INCONCLUSIVE_PREFIX: Final = "INCONCLUSIVE"


def _str_from(entry: Mapping[str, object], field_key: str, default: str = "") -> str:
    """Return a string field from an agent-emitted dict, or *default* when absent/mistyped."""
    value = entry.get(field_key, default)
    return value if isinstance(value, str) else default


def _int_or_none(value: object) -> int | None:
    """Narrow a line number to int, rejecting bool (a JSON ``true`` is not line 1)."""
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _parse_evidence(entry: Mapping[str, object]) -> EvidenceAnchor:
    """Narrow one agent-emitted evidence dict onto the shared anchor contract."""
    return EvidenceAnchor(
        file=_str_from(entry, "file"),
        line=_int_or_none(entry.get("line")),
        snippet=_str_from(entry, "snippet"),
    )


def parse_raw_criterion(entry: Mapping[str, object], name_field: str) -> RawCriterion:
    """Narrow one agent-emitted dict into a typed RawCriterion."""
    evidence_raw = entry.get("evidence", [])
    evidence: tuple[EvidenceAnchor, ...] = ()
    if isinstance(evidence_raw, list):
        evidence = tuple(
            _parse_evidence(evidence_entry)
            for evidence_entry in evidence_raw
            if isinstance(evidence_entry, Mapping)
        )
    return RawCriterion(
        name=_str_from(entry, name_field),
        # Canonicalise status here so a bad/case-variant value never reaches the multiplier.
        status=GateStatus(_str_from(entry, "status")).value,
        confidence=_str_from(entry, "confidence"),
        summary=_str_from(entry, "summary"),
        details=_str_from(entry, "details"),
        evidence=evidence,
    )


def _inconclusive(reason: str) -> ScoreResult:
    """Build the fail-closed result, so every refusal path reads identically."""
    return ScoreResult(
        raw_score=0.0,
        decision=Decision.INCONCLUSIVE,
        justification=f"{INCONCLUSIVE_PREFIX}: {reason}",
    )


def _shape_error(config: ScoringConfig, criteria: list[RawCriterion]) -> ScoreResult | None:
    """Return an INCONCLUSIVE result when the criteria set is malformed, else None."""
    names: list[str] = [criterion.name for criterion in criteria]
    provided: set[str] = set(names)
    if provided != config.expected_criteria:
        missing = sorted(config.expected_criteria - provided)
        return _inconclusive(f"Missing criterion evaluations: {', '.join(missing)}.")
    if len(names) != len(provided):
        duplicates: list[str] = sorted({name for name in names if names.count(name) > 1})
        return _inconclusive(f"Duplicate criterion evaluations: {', '.join(duplicates)}.")
    return None


def _renormalized_score(
    config: ScoringConfig, criteria: list[RawCriterion]
) -> ScoreResult | float:
    """Weighted score over evaluated (non-skip) gates, or INCONCLUSIVE when none was evaluated."""
    earned = 0.0
    active_weight = 0.0
    for criterion in criteria:
        if criterion.status == GateStatus.SKIP.value:
            continue
        active_weight += config.weights[criterion.name]
        earned += config.weights[criterion.name] * config.status_multiplier.get(
            criterion.status, SCORE_FLOOR
        )
    if active_weight <= 0.0:
        return _inconclusive("no gates were evaluated.")
    # clamp: a weights misconfig must never push the score above 1.0.
    return round(min(earned / active_weight, 1.0), SCORE_PRECISION)


_UNEVALUATED: Final = frozenset({GateStatus.SKIP.value, GateStatus.INVALID.value})
# evaluated but not clean: a critical gate in either state caps the decision below the top one
_CRITICAL_NOT_CLEAN: Final = frozenset({GateStatus.PARTIAL.value, GateStatus.FAIL.value})


def _critical_gate_error(
    config: ScoringConfig, criteria: list[RawCriterion]
) -> ScoreResult | None:
    """INCONCLUSIVE when a critical gate is unevaluated (skip) or invalid -- never waivable."""
    for criterion in criteria:
        if criterion.name in config.critical_criteria and criterion.status in _UNEVALUATED:
            return _inconclusive(
                f"critical gate '{criterion.name}' was not evaluated "
                f"(status '{criterion.status}')."
            )
    return None


def _consensus_error(criteria: list[RawCriterion]) -> ScoreResult | None:
    """Fail closed when the host panel could not reach consensus on any gate."""
    flagged = sorted(
        criterion.name
        for criterion in criteria
        if criterion.confidence == SynthesisConfidence.FLAGGED.value
    )
    if not flagged:
        return None
    return _inconclusive(
        f"Insufficient persona consensus for gate(s): {', '.join(flagged)}."
    )


def _cap_critical_fail(
    config: ScoringConfig, criteria: list[RawCriterion], decision: Decision
) -> Decision:
    """Cap below the top decision when a critical gate isn't clean, so it can't be out-weighted."""
    if not config.verdicts or decision is not config.verdicts[0].decision:
        return decision
    not_clean = any(
        criterion.name in config.critical_criteria and criterion.status in _CRITICAL_NOT_CLEAN
        for criterion in criteria
    )
    return config.verdicts[1].decision if (not_clean and len(config.verdicts) > 1) else decision


def _precheck(config: ScoringConfig, criteria: list[RawCriterion]) -> ScoreResult | None:
    """Fail-closed gates before scoring: malformed criteria set, or an unevaluated critical gate."""
    return (
        _shape_error(config, criteria)
        or _consensus_error(criteria)
        or _critical_gate_error(config, criteria)
    )


def _apply_verdicts(config: ScoringConfig, raw_score: float) -> Decision:
    """Band a score onto a decision; a score under every threshold is INCONCLUSIVE."""
    for rule in config.verdicts:
        if raw_score >= rule.min_score:
            return rule.decision
    return Decision.INCONCLUSIVE


def score(
    config: ScoringConfig,
    criteria: list[RawCriterion],
    extra: RawExtra | None = None,
) -> ScoreResult:
    """Score a list of parsed criteria against a scoring config."""
    precheck_error: ScoreResult | None = _precheck(config, criteria)
    if precheck_error is not None:
        return precheck_error
    scored: ScoreResult | float = _renormalized_score(config, criteria)
    if isinstance(scored, ScoreResult):
        return scored
    decision = _cap_critical_fail(config, criteria, _apply_verdicts(config, scored))
    partial = ScoreResult(raw_score=scored, decision=decision, justification="")
    return ScoreResult(
        raw_score=scored,
        decision=decision,
        justification=config.justify(partial, criteria, extra or {}),
    )
