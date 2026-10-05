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

"""Public scoring API: parse raw gate dicts and return a typed ValidationScore."""

from __future__ import annotations

from collections.abc import Mapping

from vvaharness.models import GateAssessment, GateStatus, ScoringPolicy
from vvaharness.validation.constants.scoring import (
    CRITERION_NAME_FIELD,
    FIX_POLICY,
    STATUS_MULTIPLIER,
)
from vvaharness.validation.models.scoring import (
    RawCriterion,
    ScoringConfig,
    ValidationScore,
)

from ._configs import FIX_CONFIG
from ._engine import _CRITICAL_NOT_CLEAN, parse_raw_criterion
from ._engine import score as _score
from ._justify import build_fix_justification

__all__ = ["FIX_CONFIG", "FIX_POLICY", "ValidationScore", "score_fix"]


def _config_for(policy: ScoringPolicy | None) -> ScoringConfig:
    """Return the engine config for *policy*, or the bundled panel's when none is supplied."""
    if policy is None or policy == FIX_POLICY:
        return FIX_CONFIG
    return ScoringConfig.from_policy(
        policy,
        name="fix",
        criterion_name_field=CRITERION_NAME_FIELD,
        status_multiplier=STATUS_MULTIPLIER,
        justify=build_fix_justification,
    )


def _has_critical_failure(config: ScoringConfig, parsed: list[RawCriterion]) -> bool:
    """True when a critical gate is not clean (fail or partial) -- the decision is capped."""
    return any(
        criterion.name in config.critical_criteria and criterion.status in _CRITICAL_NOT_CLEAN
        for criterion in parsed
    )


def _to_gate(criterion: RawCriterion) -> GateAssessment:
    """Carry one scored criterion onto the shared gate contract."""
    return GateAssessment(
        name=criterion.name,
        status=GateStatus(criterion.status),
        summary=criterion.summary,
        details=criterion.details,
        evidence=criterion.evidence,
    )


def score_fix(
    gates: list[Mapping[str, object]], *, policy: ScoringPolicy | None = None
) -> ValidationScore:
    """Score raw agent-emitted gate dicts against *policy*, carrying every gate onto the result."""
    config = _config_for(policy)
    parsed = [parse_raw_criterion(gate, config.criterion_name_field) for gate in gates]
    result = _score(config, parsed)
    return ValidationScore(
        raw_score=result.raw_score,
        decision=result.decision,
        justification=result.justification,
        gates=tuple(_to_gate(criterion) for criterion in parsed),
        has_critical_failure=_has_critical_failure(config, parsed),
    )
