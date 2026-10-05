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

"""remediation_agent.models.verdict — the per-finding ``RemediationVerdict`` contract; frozen prompt schema, translated by :func:`to_evidence`."""
from __future__ import annotations

import json
from typing import Final, Literal

from pydantic import BaseModel, Field

from vvaharness.models import (
    FileChange,
    GateAssessment,
    GateStatus,
    Provenance,
    RemediationEvidence,
    RemediationOutcome,
)
from vvaharness.remediation_agent.models.change import Change
from vvaharness.remediation_agent.models.gates import Gates

__all__ = ["RemediationVerdict", "Verdict", "to_evidence"]

Verdict = Literal["Fixed", "Partially Fixed", "Not Fixed",
                  "False Positive", "Needs Review", "Denied"]


class RemediationVerdict(BaseModel):
    """Structured result the remediation agent must return for one finding.

    Only ``verdict`` is strictly required; every other field has a safe default
    so a near-complete agent response (e.g. one that omits ``summary``) is
    preserved rather than thrown away. ``verdict`` itself is salvaged in
    :meth:`coerce` when missing/invalid."""

    finding_index: int = 0
    verdict: Verdict = "Needs Review"
    gates: Gates = Field(default_factory=Gates)
    root_cause: str = Field(default="", description="one paragraph, cites file:line")
    changes: list[Change] = Field(
        default_factory=list,
        description="edits applied (fix mode) or proposed (report-only)")
    remaining_risks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(
        default_factory=list,
        description="code-level follow-ups only — no operational controls")
    summary: str = Field(default="", description="2-4 sentence human-readable summary")

    @classmethod
    def schema_json_compact(cls) -> str:
        """Compact JSON schema string for embedding in the SYSTEM prompt."""
        return json.dumps(cls.model_json_schema(), separators=(",", ":"))

    @classmethod
    def coerce(cls, data, *, finding_index: int) -> "RemediationVerdict":
        """Build a verdict from a possibly-imperfect agent payload, salvaging recognised fields rather than raising."""
        if not isinstance(data, dict):
            return cls(finding_index=finding_index, verdict="Needs Review",
                       summary="agent response was not a JSON object")
        try:
            v = cls.model_validate(data)
            v.finding_index = finding_index
            return v
        except Exception:  # noqa: BLE001 — fall through to salvage
            pass

        clean = {k: data[k] for k in cls.model_fields if k in data}
        valid_verdicts = set(Verdict.__args__)  # type: ignore[attr-defined]
        if clean.get("verdict") not in valid_verdicts:
            clean["verdict"] = "Needs Review"
        try:
            v = cls.model_validate(clean)
        except Exception:  # noqa: BLE001 — last resort: construct from defaults
            v = cls(verdict="Needs Review",
                    summary="agent verdict could not be fully validated; "
                            "salvaged available fields")
            for k, val in clean.items():
                try:
                    setattr(v, k, val)
                except Exception:  # noqa: BLE001
                    pass
        v.finding_index = finding_index
        return v


# Prompt phrase -> outcome vocabulary; total over the Verdict Literal, so an unmapped phrase raises rather than guessing.
_OUTCOMES: Final[dict[str, RemediationOutcome]] = {
    "Fixed": RemediationOutcome.FIXED,
    "Partially Fixed": RemediationOutcome.PARTIALLY_FIXED,
    "Not Fixed": RemediationOutcome.NOT_FIXED,
    "False Positive": RemediationOutcome.FALSE_POSITIVE,
    "Needs Review": RemediationOutcome.NEEDS_REVIEW,
    "Denied": RemediationOutcome.DENIED,
}

# The prompt asks for exactly these three evidence gates, in this order.
_GATE_FIELDS: Final[tuple[str, ...]] = ("source", "sink", "missing_control")


def _gate_assessments(gates: Gates) -> tuple[GateAssessment, ...]:
    """Widen the three named gate fields into the open-vocabulary gate list."""
    return tuple(
        GateAssessment(name=name, status=GateStatus(getattr(gates, name)))
        for name in _GATE_FIELDS
    )


def to_evidence(verdict: RemediationVerdict, *,
                provenance: Provenance) -> RemediationEvidence:
    """Translate this engine's prompt verdict into the shared evidence contract; this is what makes the bundled engine substitutable."""
    return RemediationEvidence(
        outcome=_OUTCOMES[verdict.verdict],
        summary=verdict.summary,
        root_cause=verdict.root_cause,
        changes=tuple(FileChange(file=c.file, summary=c.summary)
                      for c in verdict.changes if c.file),
        gates=_gate_assessments(verdict.gates),
        remaining_risks=tuple(verdict.remaining_risks),
        recommendations=tuple(verdict.recommendations),
        produced_by=provenance,
    )
