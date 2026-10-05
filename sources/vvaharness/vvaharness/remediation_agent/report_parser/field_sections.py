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

"""remediation_agent.report_parser.field_sections — regexes + section splitting."""
from __future__ import annotations

import re

# Inline metadata lines emitted under each finding header by FinalReport.to_markdown.
_CLASS_RE = re.compile(r"^\*\*Class:\*\*\s*(.+?)\s*$")
_CWE_RE = re.compile(r"^\*\*CWE:\*\*\s*(CWE-\d+)")
_CONF_RE = re.compile(r"^\*\*Confidence:\*\*\s*([0-9.]+)\s*\((\d+)\s+runs?\s+agreed\)")
_CVSS_SCORE_RE = re.compile(
    r"^\*\*CVSS 3\.1:\*\*\s*\*\*([0-9.]+)\*\*\s*\(([^)]+)\)\s*—\s*`([^`]+)`")
_CVSS_VECONLY_RE = re.compile(r"^\*\*CVSS 3\.1:\*\*\s*`([^`]+)`")
# Taint evidence refs — the bundled renderer doesn't emit these, but a report that does carry them must not drop them (the s4 evidence gate).
_SOURCE_RE = re.compile(r"^\*\*Source:\*\*\s*`?([^`]+?)`?\s*$")
_SINK_RE = re.compile(r"^\*\*Sink:\*\*\s*`?([^`]+?)`?\s*$")
# `**Verdict:** TRUE_POSITIVE (confidence: 9/10) — reason`
_VERDICT_RE = re.compile(
    r"^\*\*Verdict:\*\*\s*(\w+)\s*\(confidence:\s*(\d+)/10\)\s*—?\s*(.*)$")
# `path:174-147` → file, line_start, line_end
_FILELOC_RE = re.compile(r"^(.*?):(\d+)(?:-(\d+))?$")


def _file_loc(ref: str) -> tuple[str, int, int]:
    """Split a ``path:start-end`` reference into (file, line_start, line_end); falls back to (ref, 0, 0) when malformed."""
    m = _FILELOC_RE.match(ref.strip())
    if not m:
        return ref.strip(), 0, 0
    start = int(m.group(2))
    end = int(m.group(3)) if m.group(3) else start
    return m.group(1).strip(), start, end


def _sections(body: str) -> dict[str, str]:
    """Split a finding's markdown block into its ``#### Heading`` sections, keyed by lower-cased heading text."""
    out: dict[str, str] = {}
    key = ""
    buf: list[str] = []
    for line in body.splitlines():
        m = re.match(r"^####\s+(.+?)\s*$", line)
        if m:
            out[key] = "\n".join(buf).strip()
            key = m.group(1).strip().lower()
            buf = []
            continue
        buf.append(line)
    out[key] = "\n".join(buf).strip()
    return out


def _first_code_block(text: str) -> str:
    """Return the contents of the first ```` ``` ```` fenced block in *text*."""
    m = re.search(r"```[^\n]*\n(.*?)\n```", text, re.DOTALL)
    return m.group(1) if m else ""
