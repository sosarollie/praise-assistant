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

"""Assembles the canonical ``finding_case.json`` by joining the scan finding with the attempt this pass produced."""
from __future__ import annotations

from vvaharness.models import FindingCase, Remediation
from vvaharness.remediation_agent.target import RemediationTarget

__all__ = ["build_report"]


def build_report(target: RemediationTarget, remediation: Remediation, *,
                 reverted_paths: tuple[str, ...] = ()) -> FindingCase:
    """Assemble the per-finding case: the scan finding plus this attempt."""
    case_id = target.case_id
    # Stamp the id onto the finding too, so a case file read on its own is self-describing.
    finding = (target.finding if target.finding.case_id
               else target.finding.model_copy(update={"case_id": case_id}))
    case = FindingCase(case_id=case_id, finding=finding)
    return case.with_attempt(remediation, reverted_paths=reverted_paths)
