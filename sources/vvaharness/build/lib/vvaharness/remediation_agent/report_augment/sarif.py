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

"""remediation_agent.report_augment.sarif — add remediation blocks to the SARIF copy."""
from __future__ import annotations

import json
from pathlib import Path

from vvaharness.remediation_agent.report_augment.dto import (
    CaseRecord,
    _finding_of,
    _remediation_block,
    _skipped_record,
)


def _result_loc(sarif_result: dict) -> tuple[str, int]:
    """Return (uri, startLine) for a SARIF result, or ("", -1) when unavailable."""
    try:
        pl = sarif_result["locations"][0]["physicalLocation"]
        return pl["artifactLocation"]["uri"], int(pl["region"]["startLine"])
    except (KeyError, IndexError, TypeError, ValueError):
        return "", -1


def _match_by_loc(results: list[dict], file: str, line: int) -> dict | None:
    """Return the result whose physical location is exactly (file, line)."""
    for r in results:
        if _result_loc(r) == (file, line):
            return r
    return None


def _match_by_title(results: list[dict], title: str) -> dict | None:
    """Return the first result whose message text starts with *title*."""
    for r in results:
        if str(r.get("message", {}).get("text", "")).startswith(title):
            return r
    return None


def _match_sarif(results: list[dict], record: CaseRecord) -> dict | None:
    """Match a SARIF result to a case by (file, line_start), else by title prefix."""
    finding = _finding_of(record)
    if finding is None:
        return None
    by_loc = (_match_by_loc(results, finding.file, finding.line_start)
              if finding.file else None)
    if by_loc is not None:
        return by_loc
    title = finding.title.strip()
    return _match_by_title(results, title) if title else None


def _augment_sarif(path: Path, records: list[CaseRecord]) -> None:
    """Add a ``remediation`` block to every SARIF result — matched cases get their status, everything else gets an explicit ``skipped`` block."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    runs = doc.get("runs") or [{}]
    results = runs[0].get("results", []) if runs else []
    matched_ids: set[int] = set()
    for record in records:
        match = _match_sarif(results, record)
        if match is not None:
            match["remediation"] = _remediation_block(record)
            matched_ids.add(id(match))
    # Unprocessed findings → explicit skipped block.
    skipped = _remediation_block(_skipped_record())
    for r in results:
        if id(r) not in matched_ids:
            r["remediation"] = dict(skipped)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
