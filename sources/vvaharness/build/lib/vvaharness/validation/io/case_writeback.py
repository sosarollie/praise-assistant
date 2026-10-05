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

"""Attach the validation verdict to a case and persist it; state_of derives lifecycle."""

from __future__ import annotations

import logging
from pathlib import Path

from vvaharness.models import FindingCase, Provenance, ScoringPolicy, Verdict
from vvaharness.validation.constants.artifacts import VALIDATION_REPORT_FILENAME
from vvaharness.validation.io._host_score import (
    conformant,
    load_synthesized_gates,
    verdict_for,
)
from vvaharness.validation.models.output import OutputFinding, ValidationReport

log = logging.getLogger(__name__)

__all__ = ["write_back_verdict"]


def _load_output_finding(workspace: Path, case_id: str) -> OutputFinding | None:
    """Return the agent's report entry for *case_id*, or None when unreadable/absent."""
    report_path: Path = workspace / VALIDATION_REPORT_FILENAME
    try:
        report: ValidationReport = ValidationReport.from_file(report_path)
    except (OSError, ValueError):
        log.warning("no readable validation report at %s; recording INCONCLUSIVE", report_path)
        return None
    for finding in report.findings:
        if finding.tracking_id == case_id:
            return finding
    return report.findings[0] if report.findings else None


def build_verdict(
    case: FindingCase,
    workspace: Path,
    *,
    provenance: Provenance,
    policy: ScoringPolicy | None = None,
    session_failed: bool = False,
) -> Verdict:
    """Compute *case*'s verdict from workspace artifacts; a session failure discards gates."""
    output_finding = _load_output_finding(workspace, case.case_id)
    gates = None if session_failed else load_synthesized_gates(workspace).get(case.case_id)
    scored = verdict_for(output_finding, gates, provenance=provenance, policy=policy)
    return conformant(scored, policy)


def write_back_verdict(case: FindingCase, verdict: Verdict, path: Path) -> FindingCase | None:
    """Attach *verdict* to *case*'s latest attempt; None on missing attempt/IO failure."""
    try:
        judged = case.with_verdict(verdict)
        judged.write(path)
    except (OSError, ValueError):
        log.warning("could not write verdict back to %s", path)
        return None
    return judged
