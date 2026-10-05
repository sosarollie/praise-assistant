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

"""remediation_agent.report_augment.summary — the report-level ``## Remediation Summary``."""
from __future__ import annotations

from vvaharness.remediation_agent.report_augment.dto import REMEDIATED, CaseRecord


def _summary_counts(records: list[CaseRecord]) -> dict[str, int]:
    """Tally report-level remediation metrics (true_positive, in_scope, remediated) from the loaded cases."""
    total = len(records)
    false_positive = sum(1 for r in records if r.false_positive)
    remediated = sum(1 for r in records if r.bucket == REMEDIATED)
    return {
        "true_positive": total - false_positive,
        "in_scope": total,
        "remediated": remediated,
    }


def _md_summary_section(records: list[CaseRecord]) -> str:
    """Render the report-level ``## Remediation Summary`` section."""
    c = _summary_counts(records)
    in_scope = c["in_scope"]
    remediated = c["remediated"]
    rate = f"{(remediated / in_scope * 100):.0f}%" if in_scope > 0 else "n/a"
    return (
        "## Remediation Summary\n"
        f"- Total findings (true positive): {c['true_positive']}\n"
        f"- Findings in scope for remediation: {in_scope}\n"
        f"- Remediated: {remediated}\n"
        f"- Success Rate(remediated/true positive): {rate}\n"
    )
