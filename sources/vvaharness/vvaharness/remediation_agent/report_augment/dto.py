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

"""remediation_agent.report_augment.dto — load the per-finding cases and bucket them by derived state."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vvaharness.models import (
    CaseState,
    Disposition,
    Finding,
    FindingCase,
    Remediation,
)

__all__ = ["DENY", "REMEDIATED", "SKIPPED", "CaseRecord"]

log = logging.getLogger(__name__)

FINDING_CASE_FILENAME = "finding_case.json"
TRIAGE_RELPATH = ("evidence", "triage.json")

#: The three report-facing buckets — narrower than ``CaseState`` on purpose.
REMEDIATED = "remediated"
DENY = "deny"
SKIPPED = "skipped"

# Reason for a finding never handed to the remediation agent — it still gets a block so no finding is left ambiguous.
_NOT_PROCESSED_REASON = "finding not processed for remediation"

# Bucket per derived case state; DECLINED lands as skipped, re-routed to DENY only when policy refused it.
_STATE_BUCKET: Final[dict[CaseState, str]] = {
    CaseState.REMEDIATED: REMEDIATED,
    CaseState.VALIDATED: REMEDIATED,
    CaseState.FAILED: SKIPPED,
    CaseState.DECLINED: SKIPPED,
    CaseState.OPEN: SKIPPED,
    CaseState.PENDING: SKIPPED,
}


@dataclass(frozen=True)
class CaseRecord:
    """One loaded case plus the report bucket and reason derived from it."""

    bucket: str
    reason: str
    case: FindingCase | None = None
    false_positive: bool = False


def _load_cases(rem_dir: Path) -> list[CaseRecord]:
    """Load every ``finding_case.json`` under the remediation dir, bucketed for the report."""
    records: list[CaseRecord] = []
    for path in sorted(rem_dir.glob(f"*/{FINDING_CASE_FILENAME}")):
        case = _read_case(path)
        if case is None:
            continue
        bucket, reason = _bucket_and_reason(case, _load_triage(path.parent))
        records.append(CaseRecord(
            bucket=bucket, reason=reason, case=case,
            false_positive=_disposition_of(case) is Disposition.FALSE_POSITIVE,
        ))
    return records


def _read_case(path: Path) -> FindingCase | None:
    """Load one case file, naming it in the log and skipping it when unreadable."""
    try:
        return FindingCase.read(path)
    except (OSError, ValueError) as e:
        log.warning("remediate: skipping unreadable case '%s' (%s): %s",
                    path.parent.name, path, e)
        return None


def _load_triage(finding_dir: Path) -> dict:
    """Load the ``evidence/triage.json`` sidecar for one finding (``{}`` on absence)."""
    triage_path = finding_dir.joinpath(*TRIAGE_RELPATH)
    try:
        data = json.loads(triage_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _bucket_and_reason(case: FindingCase, triage: dict) -> tuple[str, str]:
    """Map one case to its (bucket, human reason) for the report; a policy denial is called out separately since a human must act."""
    remediation = _remediation_of(case)
    summary = remediation.summary.strip() if remediation is not None else ""
    if remediation is not None and remediation.disposition is Disposition.POLICY_DENIED:
        reason = (triage.get("policy_reason") or summary
                  or "policy gate denied automated remediation")
        return DENY, str(reason)
    bucket = _STATE_BUCKET[case.state]
    if bucket == REMEDIATED:
        return REMEDIATED, summary or "remediation applied"
    return SKIPPED, summary or _skipped_reason(case)


def _skipped_reason(case: FindingCase) -> str:
    """Explain a non-success bucket. A failed validation is not the same as an untried fix."""
    if _disposition_of(case) is Disposition.FALSE_POSITIVE:
        return "finding rejected as a false positive"
    if case.state is CaseState.FAILED:
        return "fix applied but failed validation; needs rework"
    return "remediation not applied; needs review"


def _remediation_of(case: FindingCase | None) -> Remediation | None:
    """The newest attempt's remediation; the last attempt is what the report reflects."""
    if case is None or not case.attempts:
        return None
    return case.attempts[-1].remediation


def _disposition_of(case: FindingCase | None) -> Disposition | None:
    """Why nothing landed on the newest attempt, when the engine said."""
    remediation = _remediation_of(case)
    return remediation.disposition if remediation is not None else None


def _skipped_record() -> CaseRecord:
    """A synthetic record for a finding that was never processed → skipped."""
    return CaseRecord(bucket=SKIPPED, reason=_NOT_PROCESSED_REASON)


def _finding_of(record: CaseRecord) -> Finding | None:
    """The scan finding a record was built from, or None for a synthetic skipped record."""
    return record.case.finding if record.case is not None else None


def _summary_of(record: CaseRecord) -> str:
    """The engine's own account of the newest attempt, as rendered prose."""
    remediation = _remediation_of(record.case)
    return remediation.summary.strip() if remediation is not None else ""


def _files_touched(record: CaseRecord) -> list[str]:
    """Files the newest attempt reports editing, de-duplicated in first-seen order."""
    remediation = _remediation_of(record.case)
    if remediation is None:
        return []
    seen: set[str] = set()
    unique: list[str] = []
    for f in remediation.files_touched:
        if f and f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def _remediation_block(record: CaseRecord) -> dict:
    """Build the SARIF per-result ``remediation`` object."""
    return {
        "remediationStatus": record.bucket,
        "remediationReason": record.reason[:2000],
    }
