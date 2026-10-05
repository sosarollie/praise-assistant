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

"""remediation_agent.report_augment.markdown — add remediation sections to the MD copy."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from vvaharness.remediation_agent.report_augment.dto import (
    CaseRecord,
    _files_touched,
    _finding_of,
    _skipped_record,
    _summary_of,
)
from vvaharness.remediation_agent.report_augment.mdsafe import _md_code_span, _md_escape
from vvaharness.remediation_agent.report_augment.summary import _md_summary_section

log = logging.getLogger(__name__)

# Finding heading in the markdown report, e.g. ``### 1. [HIGH] Some title``.
_FINDING_RE = re.compile(r"(?m)^### \d+\. \[[^\]]*\]\s*(.+?)\s*$")
# A previously-appended ``### Remediation`` block, anchored to the end of a finding segment.
_EXISTING_REMEDIATION_RE = re.compile(r"(?s)\n+### Remediation\n.*\Z")
# A previously-appended ``## Remediation Summary`` block, stripped before re-inserting for idempotent re-runs.
_SUMMARY_RE = re.compile(r"(?s)## Remediation Summary\n.*?(?=\n#{1,6} |\Z)")


def _md_remediation_section(record: CaseRecord) -> str:
    """Render the ``### Remediation`` markdown section for one finding."""
    status = record.bucket
    summary = _summary_of(record) or record.reason.strip() or "n/a"
    files = _files_touched(record)

    if status == "remediated":
        approach = ("Automated fix applied by the Remediation Agent and written as a "
                    "unified diff; awaiting validation.")
    elif status == "deny":
        approach = ("Policy gate denied automated patching; guidance-only — a human "
                    "must remediate.")
    else:
        approach = "No automated patch applied."

    # summary/file names are model-controlled and MUST be escaped at this render boundary (CWE-79).
    lines = [
        "### Remediation",
        f"- **Status:** {_md_escape(status)}",
        f"- **Summary:** {_md_escape(summary)}",
        f"- **Approach:** {approach}",
        "- **Details of what was remediated:**",
    ]
    if files:
        lines += [f"  - {_md_code_span(f)}" for f in files]
    else:
        lines.append("  - (no files changed)")
    return "\n".join(lines) + "\n"


def _case_title(record: CaseRecord) -> str:
    """The record's finding title, normalised for matching ("" when synthetic)."""
    finding = _finding_of(record)
    return finding.title.strip().lower() if finding is not None else ""


def _best_md_match(title: str, records: list[CaseRecord]) -> CaseRecord | None:
    """Find the case for the MD heading *title*, refusing ambiguous matches (fails closed to avoid mis-attribution, CWE-345)."""
    norm = title.strip().lower()
    if not norm:
        return None

    exact = [r for r in records if _case_title(r) == norm]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        log.warning("remediate: %d cases share the exact title %r — refusing to "
                    "guess; finding rendered as skipped", len(exact), title)
        return None

    # No exact match → unambiguous substring fallback only.
    fuzzy = [r for r in records
             if _case_title(r) and (_case_title(r) in norm or norm in _case_title(r))]
    if len(fuzzy) == 1:
        return fuzzy[0]
    if len(fuzzy) > 1:
        log.warning("remediate: ambiguous title match for %r (%d candidates) — "
                    "refusing to guess; finding rendered as skipped",
                    title, len(fuzzy))
    return None


def _augment_md(path: Path, records: list[CaseRecord]) -> None:
    """Insert/replace per-finding ``### Remediation`` sections plus a report-level ``## Remediation Summary``."""
    text = path.read_text(encoding="utf-8")
    # Drop any prior report-level summary so re-runs stay idempotent; it's re-appended from the freshly tallied DTOs.
    text = _SUMMARY_RE.sub("", text).rstrip() + "\n"
    matches = list(_FINDING_RE.finditer(text))
    if not matches:
        return
    bounds = [m.start() for m in matches] + [len(text)]
    rebuilt = [text[: bounds[0]]]
    for i, m in enumerate(matches):
        segment = text[bounds[i]: bounds[i + 1]]
        # A finding with no matching case was never processed → skipped section.
        record = _best_md_match(m.group(1), records) or _skipped_record()
        rebuilt.append(_augment_segment(segment, record))
    rebuilt.append("\n" + _md_summary_section(records))
    path.write_text("".join(rebuilt), encoding="utf-8")


def _augment_segment(segment: str, record: CaseRecord) -> str:
    """Replace any prior ``### Remediation`` block in *segment* and append the current one."""
    stripped = _EXISTING_REMEDIATION_RE.sub("", segment)
    return stripped.rstrip() + "\n\n" + _md_remediation_section(record) + "\n"
