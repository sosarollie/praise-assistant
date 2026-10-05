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

"""Per-run counters and the flat render row the report builds from; a RENDER ROW, not a contract."""

# These validation render helpers remain here because validation owns their
# result and scoring contracts.

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from vvaharness.models import Decision, MergeReadiness, Severity, merge_readiness_for
from vvaharness.validation.constants.scoring import SCORE_PRECISION

if TYPE_CHECKING:
    from vvaharness.models import ScoringPolicy, Verdict
    from vvaharness.validation.models.output import OutputFinding
    from vvaharness.validation.models.scoring import ScoringConfig

__all__ = [
    "RunMetadata",
    "SarifLocation",
    "ValidationResult",
    "gate_score_rows",
    "render_row",
    "unverifiable_row",
]

# Tri-state answer flags the report row renders; the row is prose, so these stay strings.
_YES = "Yes"
_NO = "No"
_UNKNOWN = "?"


class RunMetadata(BaseModel):
    """Per-run counters surfaced to the caller."""

    model_config = ConfigDict(extra="forbid")

    total_findings: int = 0
    findings_processed: int = 0
    findings_failed: int = 0
    errors: list[str] = Field(default_factory=list)


class ValidationResult(BaseModel):
    """The host-facing, rendered result for a single validated finding."""

    model_config = ConfigDict(extra="forbid")

    finding_number: int
    tracking_id: str
    finding_title: str
    finding_description: str
    affected_files: str
    fixed: str
    partially_fixed: str
    not_fixed: str
    files_needing_fixes: str
    reason_for_decision: str
    severity: str
    pr_merge_readiness: str
    recommendations: str
    fix_confidence: float = 0.0
    gate_results_json: str = ""
    justification: str = ""


@dataclass(frozen=True)
class SarifLocation:
    """Location of a SARIF result, keyed by (uri, start_line)."""

    uri: str
    start_line: int


def gate_score_rows(verdict: Verdict, config: ScoringConfig) -> dict[str, dict[str, object]]:
    """Render per-gate ``{status, weight, weighted_score}`` cells; weight joined here, not stale."""
    rows: dict[str, dict[str, object]] = {}
    for gate in verdict.gates:
        weight = config.weights.get(gate.name, 0.0)
        multiplier = config.status_multiplier.get(gate.status.value, 0.0)
        rows[gate.name] = {
            "status": gate.status.value,
            "weight": weight,
            "weighted_score": round(weight * multiplier, SCORE_PRECISION),
        }
    return rows


# How a decision fills the row's tri-state columns; INCONCLUSIVE renders "?" everywhere, not "No".
_ANSWER_COLUMNS: dict[Decision, tuple[str, str, str]] = {
    Decision.FIXED: (_YES, _NO, _NO),
    Decision.PARTIALLY_FIXED: (_NO, _YES, _NO),
    Decision.NOT_FIXED: (_NO, _NO, _YES),
    Decision.INCONCLUSIVE: (_UNKNOWN, _UNKNOWN, _UNKNOWN),
}


def render_row(
    verdict: Verdict,
    output_finding: OutputFinding,
    *,
    finding_number: int,
    gate_scores_json: str = "",
    policy: ScoringPolicy | None = None,
) -> ValidationResult:
    """Flatten one verdict plus the agent's narrative into a report row."""
    fixed, partially, not_fixed = _ANSWER_COLUMNS[verdict.decision]
    score = verdict.score if verdict.score is not None else 0.0
    return ValidationResult(
        finding_number=finding_number,
        tracking_id=output_finding.tracking_id,
        finding_title=output_finding.finding_title,
        finding_description=output_finding.finding_description,
        affected_files=output_finding.affected_files,
        fixed=fixed,
        partially_fixed=partially,
        not_fixed=not_fixed,
        files_needing_fixes=_files_needing_fixes(output_finding),
        reason_for_decision=f"{verdict.decision.value} (score: {score}). {verdict.rationale}",
        severity=output_finding.severity,
        pr_merge_readiness=merge_readiness_for(verdict, policy).value,
        recommendations="; ".join(verdict.recommendations),
        fix_confidence=score,
        gate_results_json=gate_scores_json,
        justification=verdict.rationale,
    )


def _files_needing_fixes(output_finding: OutputFinding) -> str:
    """Prefer the agent's full-fix conditions, falling back to the explicit field."""
    if output_finding.conditions_for_full_fix:
        return "; ".join(output_finding.conditions_for_full_fix)
    return output_finding.files_needing_fixes


def unverifiable_row(
    tracking_id: str, title: str, reason: str, finding_number: int = 0
) -> ValidationResult:
    """Build a row for an unvalidatable finding; confidence 0.0, column can't hold "no number"."""
    return ValidationResult(
        finding_number=finding_number,
        tracking_id=tracking_id,
        finding_title=title,
        finding_description="",
        affected_files="",
        fixed=_UNKNOWN,
        partially_fixed=_UNKNOWN,
        not_fixed=_UNKNOWN,
        files_needing_fixes="",
        reason_for_decision=f"{Decision.INCONCLUSIVE.value}: {reason}",
        severity=Severity.MEDIUM.value,
        # Explicitly NOT_READY, not blank, so matching on "not_ready" can't read this as unset.
        pr_merge_readiness=MergeReadiness.NOT_READY.value,
        recommendations=f"Manual review required: {reason}",
    )
