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

"""Value types shared by scoring engine and package; gate outcomes live on GateAssessment."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vvaharness.models import Decision, GateAssessment, ScoringPolicy

if TYPE_CHECKING:
    from vvaharness.models import EvidenceAnchor

__all__ = [
    "RawCriterion",
    "RawExtra",
    "ScoreResult",
    "ScoringConfig",
    "ValidationScore",
    "VerdictRule",
]

#: Auxiliary input passed through to justifiers.
RawExtra = Mapping[str, object]


@dataclass(frozen=True)
class RawCriterion:
    """Typed view of a single gate/criterion emitted by the agent (name-folded across paths)."""

    name: str
    status: str
    summary: str = ""
    details: str = ""
    evidence: tuple[EvidenceAnchor, ...] = field(default_factory=tuple)
    confidence: str = ""


@dataclass(frozen=True)
class VerdictRule:
    """Threshold-to-decision mapping entry in a ScoringConfig."""

    min_score: float
    decision: Decision


@dataclass(frozen=True)
class ScoreResult:
    """Raw output of the scoring engine; ``decision`` is shared vocabulary, not a prompt label."""

    raw_score: float
    decision: Decision
    justification: str


@dataclass(frozen=True)
class ScoringConfig:
    """Full spec of one scoring path, interconvertible with ScoringPolicy via to/from_policy."""

    name: str
    criterion_name_field: str
    weights: Mapping[str, float]
    status_multiplier: Mapping[str, float]
    verdicts: tuple[VerdictRule, ...]
    justify: Callable[[ScoreResult, list[RawCriterion], RawExtra], str]
    # Gate set the agent must emit, from required_gates; required so config can't accept nothing.
    expected_criteria: frozenset[str]
    # Gates that cannot be skipped/garbled (-> INCONCLUSIVE); cap the decision on FAIL regardless.
    critical_criteria: frozenset[str] = frozenset()

    @classmethod
    def from_policy(
        cls,
        policy: ScoringPolicy,
        *,
        name: str,
        criterion_name_field: str,
        status_multiplier: Mapping[str, float],
        justify: Callable[[ScoreResult, list[RawCriterion], RawExtra], str],
    ) -> ScoringConfig:
        """Build the engine config from a host policy; its thresholds become the decision bands."""
        return cls(
            name=name,
            criterion_name_field=criterion_name_field,
            weights=dict(policy.weights),
            expected_criteria=frozenset(policy.required_gates),
            status_multiplier=dict(status_multiplier),
            verdicts=(
                VerdictRule(min_score=policy.ready_at, decision=Decision.FIXED),
                VerdictRule(min_score=policy.conditional_at, decision=Decision.PARTIALLY_FIXED),
                VerdictRule(min_score=0.0, decision=Decision.NOT_FIXED),
            ),
            justify=justify,
            critical_criteria=frozenset(policy.critical),
        )

    def to_policy(self) -> ScoringPolicy:
        """Express this config as a policy, so a host can read the gates it must fill."""
        return ScoringPolicy(
            required_gates=tuple(sorted(self.expected_criteria)),
            weights=dict(self.weights),
            critical=self.critical_criteria,
            ready_at=self.verdicts[0].min_score if self.verdicts else 0.0,
            conditional_at=self.verdicts[1].min_score if len(self.verdicts) > 1 else 0.0,
        )


@dataclass(frozen=True)
class ValidationScore:
    """Aggregate scoring output for one fix-validation run."""

    raw_score: float
    decision: Decision
    justification: str
    gates: tuple[GateAssessment, ...]
    has_critical_failure: bool
