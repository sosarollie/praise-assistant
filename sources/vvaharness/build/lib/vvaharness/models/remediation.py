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

"""What a remediation produced; only ``kind`` and ``summary`` are required, no diff needed."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vvaharness.models.gates import GateAssessment
from vvaharness.models.provenance import Provenance
from vvaharness.models.vocab import Disposition, RemediationKind, RemediationOutcome

__all__ = ["FileChange", "Remediation", "RemediationEvidence", "finalize"]

#: Both spellings, because "report-only" and "report_only" both circulate as the mode.
_REPORT_ONLY = frozenset({"report-only", "report_only"})


class FileChange(BaseModel):
    """One edited file and why it changed."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    file: str = Field(description="repo-relative path that was edited")
    summary: str = Field(default="", description="what changed and why")


class Remediation(BaseModel):
    """The outcome of one remediation attempt on one finding."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    kind: RemediationKind = Field(description="what the engine did")
    summary: str = Field(description="human-readable account of the attempt")
    disposition: Disposition | None = Field(
        default=None, description="why nothing was applied; required when kind is no_action"
    )
    # Advisory only: the harness's own pre/post snapshot is authoritative for what changed.
    diff: str = Field(default="", description="unified diff, when the engine produced one")
    files_touched: tuple[str, ...] = Field(default=(), description="advisory list of edits")
    changes: tuple[FileChange, ...] = Field(default=(), description="per-file rationale")
    gates: tuple[GateAssessment, ...] = Field(default=(), description="evidence gates asserted")
    root_cause: str = Field(default="", description="why the vulnerability existed")
    remaining_risks: tuple[str, ...] = Field(default=(), description="what the fix does not cover")
    recommendations: tuple[str, ...] = Field(default=(), description="code-level follow-ups")
    external_ref: str = Field(default="", description="pull-request URL, for engines that open one")
    produced_by: Provenance = Field(default=Provenance(), description="attributable origin")

    @model_validator(mode="after")
    def _require_disposition_for_no_action(self) -> Remediation:
        """Demand a reason when nothing was applied, so 'no fix' is never unexplained."""
        if self.kind is RemediationKind.NO_ACTION and self.disposition is None:
            msg = "kind=no_action requires a disposition explaining why nothing was applied"
            raise ValueError(msg)
        return self


class RemediationEvidence(BaseModel):
    """What an engine reports, sans ``diff``/``files_touched``/``kind``, set by :func:`finalize`."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    outcome: RemediationOutcome = Field(description="what the engine claims it achieved")
    summary: str = Field(description="human-readable account of the attempt")
    root_cause: str = Field(default="", description="why the vulnerability existed")
    changes: tuple[FileChange, ...] = Field(default=(), description="per-file rationale")
    gates: tuple[GateAssessment, ...] = Field(default=(), description="evidence gates asserted")
    remaining_risks: tuple[str, ...] = Field(default=(), description="what the fix does not cover")
    recommendations: tuple[str, ...] = Field(default=(), description="code-level follow-ups")
    produced_by: Provenance = Field(default=Provenance(), description="attributable origin")


#: Outcome x mode -> ``kind``; total, so a new outcome member breaks :func:`finalize`.
_KIND: dict[RemediationOutcome, tuple[RemediationKind, RemediationKind, Disposition | None]] = {
    RemediationOutcome.FIXED:
        (RemediationKind.EDITS_APPLIED, RemediationKind.DIFF_PROPOSED, None),
    RemediationOutcome.PARTIALLY_FIXED:
        (RemediationKind.EDITS_APPLIED, RemediationKind.DIFF_PROPOSED, None),
    RemediationOutcome.NOT_FIXED:
        (RemediationKind.NO_ACTION, RemediationKind.NO_ACTION, Disposition.NOT_APPLICABLE),
    RemediationOutcome.FALSE_POSITIVE:
        (RemediationKind.NO_ACTION, RemediationKind.NO_ACTION, Disposition.FALSE_POSITIVE),
    RemediationOutcome.NEEDS_REVIEW:
        (RemediationKind.NO_ACTION, RemediationKind.NO_ACTION, Disposition.NOT_APPLICABLE),
    RemediationOutcome.DENIED:
        (RemediationKind.NO_ACTION, RemediationKind.NO_ACTION, Disposition.POLICY_DENIED),
}


def finalize(evidence: RemediationEvidence, *, mode: str, diff: str = "",
             files_touched: tuple[str, ...] = ()) -> Remediation:
    """Turn engine evidence into harness's contract, adding *diff*, *files_touched*, ``kind``."""
    fix_kind, report_kind, disposition = _KIND[evidence.outcome]
    kind = report_kind if mode in _REPORT_ONLY else fix_kind
    # edits_applied with no files touched and no diff is treated as already_resolved instead.
    if kind is RemediationKind.EDITS_APPLIED and not files_touched and not diff:
        kind = RemediationKind.ALREADY_RESOLVED
    return Remediation(
        kind=kind,
        summary=evidence.summary,
        disposition=disposition,
        diff=diff,
        files_touched=files_touched,
        changes=evidence.changes,
        gates=evidence.gates,
        root_cause=evidence.root_cause,
        remaining_risks=evidence.remaining_risks,
        recommendations=evidence.recommendations,
        produced_by=evidence.produced_by,
    )
