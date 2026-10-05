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

"""Build the fix-validation launch prompt; bullet LABELS are prompt text, apart from field names."""

from __future__ import annotations

from typing import TYPE_CHECKING

from vvaharness.validation.constants.artifacts import DIFF_FILENAME, MISSING_FIELD_PLACEHOLDER
from vvaharness.validation.hints import hints_for
from vvaharness.validation.models import Manifest

if TYPE_CHECKING:
    from vvaharness.models import Finding

__all__ = ["build_launch_prompt"]

# (prompt label, Finding attribute) for the optional narrative bullets, in render order.
_NARRATIVE_FIELDS: tuple[tuple[str, str], ...] = (
    ("Description Detail", "description"),
    ("Impact", "impact"),
    ("Exploit Scenario", "exploit_scenario"),
    ("Preconditions", "preconditions"),
    ("Recommendation", "recommendation"),
)


def _score_line(label: str, score: object, vector: object) -> str:
    """Render a ``- **LABEL**: score (vector)`` markdown bullet line."""
    line = f"- **{label}**: {score}"
    if vector:
        line += f" ({vector})"
    return line


def _render(value: object) -> str:
    """Render a narrative value; a list becomes one bullet per item, never a joined blob."""
    if isinstance(value, (list, tuple)):
        return "; ".join(str(item) for item in value)
    return str(value)


def _narrative_lines(finding: Finding) -> list[str]:
    """Return markdown bullets for optional narrative fields that are non-empty."""
    return [
        f"- **{label}**: {_render(value)}"
        for label, attr in _NARRATIVE_FIELDS
        if (value := getattr(finding, attr, ""))
    ]


def _category(finding: Finding) -> str:
    """The finding's weakness class as the prompt names it: CWE when known, else vuln class."""
    return finding.cwe or finding.vuln_class.value


def _bypass_hint_lines(finding: Finding) -> list[str]:
    """Return markdown bullets for known bypass patterns, empty list if none."""
    category = _category(finding)
    hints = hints_for(category)
    if not hints:
        return []
    return [
        f"- **Known bypass patterns for {category}**:",
        *[f"  - {hint}" for hint in hints],
    ]


def _append_finding_details(lines: list[str], finding: Finding, affected: list[str]) -> None:
    """Append a markdown finding-details section to lines in place."""
    lines += ["", "## Finding Details", ""]
    lines.append(f"- **Title**: {finding.title or MISSING_FIELD_PLACEHOLDER}")
    lines.append(f"- **Category**: {_category(finding) or MISSING_FIELD_PLACEHOLDER}")
    lines.append(
        f"- **Severity**: {finding.cvss_rating or finding.severity.value}"
    )
    if finding.cvss_score is not None:
        lines.append(_score_line("CVSS", finding.cvss_score, finding.cvss_vector))
    if finding.file:
        lines.append(f"- **Source**: {finding.file}:{finding.line_start}")
    if affected:
        lines.append(f"- **Affected files**: {', '.join(affected)}")
    lines += _narrative_lines(finding)
    lines += _bypass_hint_lines(finding)


def build_launch_prompt(manifest: Manifest) -> str:
    """Compose the fix-validation launch prompt for a pre-staged workspace."""
    lines = [
        f"Finding: {manifest.case_id}",
        f"Session: {manifest.session_id}",
        "",
        "## Patch under validation",
        "",
        f"The remediation patch is **already applied** to this workspace tree; the "
        f"applied unified diff is at `{DIFF_FILENAME}` in the workspace root. Read it first "
        "-- it is your primary focus -- then read the rest of the tree freely for "
        "cross-file context. Follow the grounding and independence rules in the system "
        "prompt: navigate by hunk content and symbol names, never by line number; treat "
        "the remediator's `triage.json` verdict as an unverified claim to confirm or "
        "refute, not as evidence.",
    ]
    if manifest.finding:
        _append_finding_details(lines, manifest.finding, manifest.affected_files)
    lines.append("")
    lines.append("## Session Config")
    lines.append(f"- post_results: {'true' if manifest.post_results else 'false'}")
    if manifest.post_results:
        lines.append("")
        lines.append("### Post Markers")
        lines.append(
            f"- Finding {manifest.case_id}: "
            f"<!-- validation-session:{manifest.session_id} -->"
        )
    return "\n".join(lines)
