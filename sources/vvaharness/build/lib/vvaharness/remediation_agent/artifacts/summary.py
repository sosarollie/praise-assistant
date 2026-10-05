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

"""remediation_agent.artifacts.summary — the human-readable ``summary.md`` renderer."""
from __future__ import annotations

from vvaharness.remediation_agent.models import RemediationVerdict


def render_summary(verdict: RemediationVerdict, *, meta: dict) -> str:
    """Human-readable per-finding report. *meta* carries display-only context
    (severity, title, file, mode, generated timestamp)."""
    changes = "\n".join(
        f"- `{c.file}` — {c.summary}" for c in verdict.changes
    ) or "- (none reported)"
    recs = "\n".join(f"- {r}" for r in verdict.recommendations) or "- (none)"
    risks = "\n".join(f"- {r}" for r in verdict.remaining_risks) or "- (none)"
    g = verdict.gates
    return (
        f"# Remediation — finding {verdict.finding_index}\n\n"
        f"- **Severity:** {meta.get('severity')}\n"
        f"- **Title:** {meta.get('title')}\n"
        f"- **File:** {meta.get('file') or 'n/a'}\n"
        f"- **Mode:** {meta.get('mode')}\n"
        f"- **Verdict:** {verdict.verdict}\n"
        f"- **Gates:** source={g.source}, sink={g.sink}, "
        f"missing_control={g.missing_control}\n"
        f"- **Generated:** {meta.get('generated')}\n\n"
        f"## Root cause\n{verdict.root_cause}\n\n"
        f"## Changes\n{changes}\n\n"
        f"## Remaining risks\n{risks}\n\n"
        f"## Recommendations\n{recs}\n\n"
        f"## Summary\n{verdict.summary}\n"
    )
