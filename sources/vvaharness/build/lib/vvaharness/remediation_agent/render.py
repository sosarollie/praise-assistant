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

"""Renders one typed :class:`vvaharness.models.Finding` as the prose markdown block the remediation prompt embeds."""
from __future__ import annotations

from vvaharness.models import Finding, _demote_md_headings, _md_cell
from vvaharness.report.cwe import cwe_for, cwe_name

__all__ = ["render_finding_md"]


def render_finding_md(finding: Finding, index: int) -> str:
    """Render *finding* as the ``### N. [SEV] title`` markdown block the prompt embeds."""
    lines = [
        f"### {index}. [{finding.severity.value.upper()}] {_md_cell(finding.title)}",
        *_metadata_lines(finding),
        "",
    ]
    lines.extend(_narrative_lines(finding))
    return "\n".join(lines).rstrip() + "\n"


def _cwe_label(finding: Finding) -> tuple[str, str]:
    """Return (resolved CWE id, human label) for *finding*, both "" when unclassified."""
    cwe = cwe_for(finding.cwe, finding.vuln_class)
    if not cwe:
        return "", ""
    name = cwe_name(cwe)
    return cwe, f"{cwe}: {name}" if name else cwe


def _cvss_text(finding: Finding) -> str:
    """The CVSS cell, matching the report's three renderings (scored / vector-only / none)."""
    if finding.cvss_score is not None:
        return f"**{finding.cvss_score:.1f}** ({finding.cvss_rating}) — `{finding.cvss_vector}`"
    if finding.cvss_vector:
        return f"`{finding.cvss_vector}`"
    return "_not computed_"


def _metadata_lines(finding: Finding) -> list[str]:
    """The inline ``**Field:**`` lines under the heading."""
    cwe, label = _cwe_label(finding)
    lines = [f"**Class:** {label or finding.vuln_class.value}"]
    if cwe:
        number = cwe.split("-")[-1]
        lines.append(f"**CWE:** {label} - "
                     f"https://cwe.mitre.org/data/definitions/{number}.html")
    lines.append(f"**File:** `{finding.file}:{finding.line_start}-{finding.line_end}`")
    lines.append(f"**CVSS 3.1:** {_cvss_text(finding)}")
    vote_word = "run" if finding.votes == 1 else "runs"
    lines.append(f"**Confidence:** {finding.confidence:.2f} "
                 f"({finding.votes} {vote_word} agreed)")
    # Taint refs are the s4 evidence gate; kept with metadata so the gate assessment can cite them.
    if finding.source_ref:
        lines.append(f"**Source:** `{finding.source_ref}`")
    if finding.sink_ref:
        lines.append(f"**Sink:** `{finding.sink_ref}`")
    lines.extend(_duplicate_lines(finding))
    return lines


def _duplicate_lines(finding: Finding) -> list[str]:
    """The other call sites dedup collapsed into this finding -- each needs the same fix."""
    if not finding.duplicates:
        return []
    refs = ", ".join(
        f"`{d.file}:{d.line_start}"
        + (f"-{d.line_end}`" if d.line_end and d.line_end != d.line_start else "`")
        for d in finding.duplicates
    )
    return [f"**Also at:** {refs}"]


def _narrative_lines(finding: Finding) -> list[str]:
    """The ``#### Heading`` prose sections, each omitted when the field is empty and demoted so model prose cannot forge a heading."""
    lines = ["#### Description", _demote_md_headings(finding.description), ""]
    for heading, text in (("Impact", finding.impact),
                          ("Exploit scenario", finding.exploit_scenario)):
        if text:
            lines.extend([f"#### {heading}", _demote_md_headings(text), ""])
    if finding.preconditions:
        lines.append("#### Preconditions")
        lines.extend(f"- {_md_cell(p)}" for p in finding.preconditions)
        lines.append("")
    if finding.code_snippet:
        lines.extend(["```", finding.code_snippet, "```", ""])
    if finding.recommendation:
        lines.extend(["#### How to fix",
                      _demote_md_headings(finding.recommendation), ""])
    lines.extend(_verification_lines(finding))
    lines.extend(_exploitability_lines(finding))
    return lines


def _exploitability_lines(finding: Finding) -> list[str]:
    """The s8 chain-pass commentary, incl. mitigations that may make the fix unnecessary."""
    if not finding.exploitability_notes:
        return []
    return [
        f"**Exploitability:** {_demote_md_headings(finding.exploitability_notes)}",
        "",
    ]


def _verification_lines(finding: Finding) -> list[str]:
    """The adversarial-verification block, so the agent sees why this survived triage."""
    if not finding.verdict:
        return []
    return [
        "#### Adversarial verification",
        f"**Verdict:** {finding.verdict} (confidence: "
        f"{finding.verdict_confidence}/10) — "
        f"{_demote_md_headings(finding.verdict_reason)}",
        "",
    ]
