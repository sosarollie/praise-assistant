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

"""remediation_agent.report_parser.parse — finding-header parsing and the done-marker."""
from __future__ import annotations

import re
from pathlib import Path

from vvaharness.remediation_agent.report_parser.fields import to_scan_finding
from vvaharness.remediation_agent.report_parser.finding import Finding
from vvaharness.remediation_agent.target import RemediationTarget

# Invisible marker appended to a finding header once remediated, so "done" survives across runs in the report itself.
DONE_MARKER = "<!-- remediation-agent:done -->"

# Finding header, e.g. ``### 1. [CRITICAL] Stored JQL injection via …``.
# The trailing group optionally captures the done marker so parsing strips it from the title and records ``done``.
_HEADER_RE = re.compile(
    r"^###\s+(\d+)\.\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?)\s*"
    r"(<!--\s*remediation-agent:done\s*-->)?\s*$",
    re.IGNORECASE,
)
# The ``**File:** `routers/jira.py:174-174``` line emitted under each header.
_FILE_RE = re.compile(r"^\*\*File:\*\*\s*`([^`]+)`")


def parse_findings(md_text: str) -> list[RemediationTarget]:
    """Extract findings from a scan report's Markdown as typed remediation targets."""
    return [
        RemediationTarget(finding=to_scan_finding(parsed), index=parsed.index,
                          done=parsed.done)
        for parsed in _parse_blocks(md_text)
    ]


def _parse_blocks(md_text: str) -> list[Finding]:
    """Split *md_text* into the per-finding markdown blocks, as parse intermediates."""
    findings: list[Finding] = []
    current: Finding | None = None
    buf: list[str] = []

    def _flush() -> None:
        if current is not None:
            current.body = "\n".join(buf).strip()

    for line in md_text.splitlines():
        m = _HEADER_RE.match(line)
        if m:
            _flush()
            current = Finding(
                index=int(m.group(1)),
                severity=m.group(2).upper(),
                title=m.group(3).strip(),
                done=bool(m.group(4)),  # DONE_MARKER captured by the header regex
            )
            findings.append(current)
            buf = [line]
            continue
        if current is not None:
            buf.append(line)
            if current.file is None:
                fm = _FILE_RE.match(line.strip())
                if fm:
                    current.file = fm.group(1).strip()
    _flush()
    return findings


def mark_done(report_path: Path, target: RemediationTarget) -> bool:
    """Append :data:`DONE_MARKER` to *target*'s header line in *report_path*, in place; idempotent, matched by index + severity."""
    report_path = Path(report_path)
    text = report_path.read_text(encoding="utf-8")
    out: list[str] = []
    changed = False
    for line in text.splitlines():
        m = _HEADER_RE.match(line)
        if (m and int(m.group(1)) == target.index
                and m.group(2).upper() == target.severity
                and not m.group(4)):
            line = f"{line.rstrip()}  {DONE_MARKER}"
            changed = True
        out.append(line)
    if changed:
        trailing = "\n" if text.endswith("\n") else ""
        report_path.write_text("\n".join(out) + trailing, encoding="utf-8")
    return changed
