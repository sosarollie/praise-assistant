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

"""Strict output schema for DeepAgents session; FROZEN, checked by test_contract_tripwires.py."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from vvaharness.models import (
    Decision,
    EvidenceAnchor,
    GateAssessment,
    GateStatus,
    Provenance,
    Verdict,
)
from vvaharness.report.redact import redact

log = logging.getLogger(__name__)

__all__ = [
    "FIX_STATUS_LABELS",
    "GateEntry",
    "OutputFinding",
    "SynthesizedGatesEntry",
    "ValidationOutput",
    "ValidationReport",
    "decision_for",
    "to_verdict",
]

# The retired verdict vocabulary; values (not keys) are load-bearing as schema defaults below.
_FIX_STATUS_FIXED: Final = "Fixed"
_FIX_STATUS_PARTIALLY_FIXED: Final = "Partially Fixed"
_FIX_STATUS_NOT_FIXED: Final = "Not Fixed"
_FIX_STATUS_UNVERIFIABLE: Final = "UNVERIFIABLE"

# Retired readiness label the model emits; readiness itself is a host policy call, never read back.
_MERGE_READINESS_NOT_READY: Final = "Not Ready"

# These two fields hold comma-separated paths, not narrative. Four KiB leaves room for
# hundreds of normal paths while preventing a malformed structured response from
# ballooning every downstream JSON, Markdown, and SARIF artifact.
_CSV_MAX_CHARS: Final = 4096
_TRUNCATION_MARKER: Final = "...[truncated]"

#: Map from prompt verdict vocabulary to shared decision vocabulary; else closes to INCONCLUSIVE.
FIX_STATUS_LABELS: Final[dict[str, Decision]] = {
    _FIX_STATUS_FIXED: Decision.FIXED,
    _FIX_STATUS_PARTIALLY_FIXED: Decision.PARTIALLY_FIXED,
    _FIX_STATUS_NOT_FIXED: Decision.NOT_FIXED,
    _FIX_STATUS_UNVERIFIABLE: Decision.INCONCLUSIVE,
}


class GateEntry(BaseModel):
    """One gate verdict for a single finding."""

    model_config = ConfigDict(extra="ignore")

    gate_name: str
    # skip is legal: narrowing forces the model to invent pass/fail for gates nobody assessed.
    status: Literal["pass", "partial", "fail", "skip"]
    summary: str = ""
    # Structured (file/line/snippet), matching PersonaGateEntry.evidence -- both feed the
    # same synthesized_gates.json shape the scoring engine parses.
    evidence: list[EvidenceAnchor] = Field(default_factory=list)
    details: str = ""


class SynthesizedGatesEntry(BaseModel):
    """Synthesized gates for one finding, keyed by tracking_id."""

    model_config = ConfigDict(extra="ignore")

    tracking_id: str
    gates: list[GateEntry]


class OutputFinding(BaseModel):
    """Single finding block emitted by the validation agent."""

    model_config = ConfigDict(extra="ignore")

    tracking_id: str
    finding_title: str
    finding_description: str
    affected_files: str
    severity: str = "Medium"
    fix_status: str = _FIX_STATUS_UNVERIFIABLE
    raw_score: float = Field(ge=0.0, le=1.0, default=0.0)
    justification: str = ""
    merge_readiness: str = _MERGE_READINESS_NOT_READY
    gate_scores: dict[str, object] = Field(default_factory=dict)
    conditions_for_full_fix: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    files_needing_fixes: str = ""

    @field_validator("affected_files", "files_needing_fixes", mode="before")
    @classmethod
    def _coerce_csv(cls, v: object, info: ValidationInfo) -> object:
        # Schema hint says CSV, but gpt-5.5 (and peers) often emit a JSON list; join it here.
        if isinstance(v, (list, tuple)):
            v = ",".join(str(x) for x in v)
        if not isinstance(v, str):
            return v

        # Redact the complete value before truncating.  Reversing this order can
        # bisect a credential at the boundary and make the surviving fragment
        # unrecognisable to the redactor.
        safe = redact(v)
        if len(safe) <= _CSV_MAX_CHARS:
            return safe
        log.warning(
            "validation output field %s exceeded %d characters; truncating",
            info.field_name,
            _CSV_MAX_CHARS,
        )
        return safe[: _CSV_MAX_CHARS - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER

    @field_validator("raw_score", mode="before")
    @classmethod
    def _clamp_raw_score(cls, v: object) -> object:
        """Clamp an out-of-range score instead of rejecting; raising drops it from the report."""
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return v
        score = float(v)
        clamped = min(1.0, max(0.0, score))
        if clamped != score:
            # Log only the normalized numeric value: agent-controlled prose never
            # reaches the log, while persistent scoring malfunctions become visible.
            log.warning(
                "validation output raw_score=%r is outside [0.0, 1.0]; "
                "clamped to %.1f",
                score,
                clamped,
            )
        return clamped


class ValidationOutput(BaseModel):
    """Top-level structured response from any validation Harness backend.

    The host (not the agent) writes ``validation_report.json`` and
    ``synthesized_gates.json`` from this payload.
    """

    model_config = ConfigDict(extra="ignore")

    target_jira_status: str
    findings: list[OutputFinding]
    synthesized_gates: list[SynthesizedGatesEntry]


# Narrative fields the agent writes into; tracking_id/finding_title excluded to protect headings.
_NARRATIVE_TEXT: Final = (
    "finding_description",
    "affected_files",
    "files_needing_fixes",
    "justification",
)
_NARRATIVE_LISTS: Final = ("conditions_for_full_fix", "recommendations")


class ValidationReport(BaseModel):
    """``validation_report.json`` as the host persisted it -- same findings, minus gates."""

    model_config = ConfigDict(extra="ignore")

    findings: list[OutputFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def _redact_narrative(self) -> ValidationReport:
        """Mask secret the agent echoed into free text, at parse boundary, as defense-in-depth."""
        for finding in self.findings:
            for name in _NARRATIVE_TEXT:
                setattr(finding, name, redact(getattr(finding, name)))
            for name in _NARRATIVE_LISTS:
                setattr(finding, name, [redact(item) for item in getattr(finding, name)])
        return self

    @classmethod
    def from_file(cls, path: Path) -> ValidationReport:
        """Parse the persisted report, naming the file on malformed JSON."""
        return cls.model_validate(_read_json(path))


def _read_json(path: Path) -> object:
    """Read and parse *path*, raising a path-qualified error on malformed JSON."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"malformed JSON in validation report {path}: {exc}"
        raise ValueError(msg) from exc


def decision_for(fix_status: str) -> Decision:
    """Translate one retired verdict label into shared vocabulary; closes to INCONCLUSIVE."""
    folded = fix_status.strip().casefold()
    return next(
        (d for label, d in FIX_STATUS_LABELS.items() if label.casefold() == folded),
        Decision.INCONCLUSIVE,
    )


def _to_gate(entry: GateEntry) -> GateAssessment:
    """Narrow one agent-emitted gate onto the shared gate contract."""
    return GateAssessment(
        name=entry.gate_name,
        status=GateStatus(entry.status),
        summary=entry.summary,
        details=entry.details,
        evidence=tuple(entry.evidence),
    )


def to_verdict(
    output_finding: OutputFinding,
    synthesized_gates: SynthesizedGatesEntry | None,
    *,
    provenance: Provenance,
) -> Verdict:
    """Adapt one agent finding onto :class:`Verdict`; score is None, not 0.0, when INCONCLUSIVE."""
    decision = decision_for(output_finding.fix_status)
    gates = synthesized_gates.gates if synthesized_gates is not None else []
    return Verdict(
        decision=decision,
        rationale=output_finding.justification,
        score=None if decision is Decision.INCONCLUSIVE else output_finding.raw_score,
        gates=tuple(_to_gate(entry) for entry in gates),
        conditions=tuple(output_finding.conditions_for_full_fix),
        recommendations=tuple(output_finding.recommendations),
        produced_by=provenance,
    )
