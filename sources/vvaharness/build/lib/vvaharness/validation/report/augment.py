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

"""Augment the combined SARIF + MD report with validation results; best-effort, never fails."""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

# One definition of the invisible-character defence for every report escaper; no cycle,
# vvaharness.models imports nothing from vvaharness.validation.
from vvaharness.models import _MD_INVISIBLE_RX, _MD_LINEBREAK_RX
from vvaharness.validation.constants.artifacts import (
    REMEDIATION_DIRNAME,
    SCAN_REPORT_GLOB,
)
from vvaharness.validation.models.results import SarifLocation
from vvaharness.validation.report.models import (
    CombinedReportPaths,
    SarifResult,
    SarifValidationBlock,
    ValidatedFinding,
)

if TYPE_CHECKING:
    from vvaharness.models import Finding
    from vvaharness.validation.models import ValidationResult

log = logging.getLogger(__name__)

# Finding heading in the markdown report, e.g. ``### 1. [HIGH] Some title``.
_FINDING_RE = re.compile(r"(?m)^### \d+\. \[[^\]]*\]\s*(.+?)\s*$")
# A previously-appended ``### Validation`` block, anchored to the end of a finding segment.
_EXISTING_VALIDATION_RE = re.compile(r"(?s)\n+### Validation\n.*\Z")
# Per-finding ``### Validation`` blocks must stay above any ``## `` section that s10 appended.
_TRAILING_SECTION_RE = re.compile(r"(?m)^## ")


def augment_reports(
    repo: Path, pairs: list[ValidatedFinding], report_md: Path | None = None
) -> None:
    """Add validation results to the report under ``security-remediation/``, logging failures."""
    try:
        _augment(repo, pairs, report_md)
    except Exception as exc:  # report augmentation must never fail the validation run
        log.warning(
            "report augmentation skipped (results not written to combined report): %s: %s",
            type(exc).__name__, exc,
        )


def _augment(repo: Path, pairs: list[ValidatedFinding], report_md: Path | None) -> None:
    """Resolve the combined report in ``security-remediation/`` and augment SARIF + MD in place."""
    located = _locate_combined_report(repo, report_md)
    if located is None:
        log.warning("no combined report under %s/%s — skipping report augmentation",
                    repo, REMEDIATION_DIRNAME)
        return
    sarif_dst, md_dst = located
    _augment_sarif(sarif_dst, pairs)
    _augment_md(md_dst, pairs)
    log.info("validation results written to combined report under %s", sarif_dst.parent)


def _locate_combined_report(
    repo: Path, report_md: Path | None = None,
) -> CombinedReportPaths | None:
    """Pick the ``(*_report.sarif, *_report.md)`` pair to enrich; explicit wins, else newest."""
    if report_md is not None:
        md = repo / REMEDIATION_DIRNAME / Path(report_md).with_suffix(".md").name
        sarif = md.with_suffix(".sarif")
        return CombinedReportPaths(sarif, md) if (md.exists() and sarif.exists()) else None
    sarifs = sorted((repo / REMEDIATION_DIRNAME).glob(SCAN_REPORT_GLOB))
    if not sarifs:
        return None
    sarif = sarifs[-1]
    md = sarif.with_suffix(".md")
    return CombinedReportPaths(sarif, md) if md.exists() else None


# value helpers


def _status_label(result: ValidationResult) -> str:
    """Map the tri-state result to the report's ``validationStatus`` enum."""
    if result.fixed == "Yes":
        return "fixed"
    if result.partially_fixed == "Yes":
        return "partially_fixed"
    return "not_fixed"


def _status_word(result: ValidationResult) -> str:
    """Human-readable status for the markdown section."""
    return {"fixed": "Fixed", "partially_fixed": "Partially Fixed",
            "not_fixed": "Not Fixed"}[_status_label(result)]


def _parse_gates(raw_json: str) -> dict[str, object]:
    """Parse the gate-scores JSON blob, returning {} on absence/error."""
    if not raw_json:
        return {}
    try:
        parsed = json.loads(raw_json)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _validation_block(result: ValidationResult) -> SarifValidationBlock:
    """Build the SARIF per-result ``validation`` object."""
    reason = (result.reason_for_decision or result.justification or "").strip()
    return {
        "validationStatus": _status_label(result),
        "validationReason": reason[:2000],
        "weightedScore": result.fix_confidence,
        "mergeReadiness": result.pr_merge_readiness,
        "gateScores": _parse_gates(result.gate_results_json),
    }


# SARIF augmentation


def _norm_path(path_text: str) -> str:
    """Fold Windows separators to POSIX so a separator mismatch can't defeat location matching."""
    return path_text.replace("\\", "/")


def _result_loc(sarif_result: SarifResult) -> SarifLocation | None:
    """Return the SARIF result's physical location, or None when unavailable."""
    try:
        locations = cast(list[object], sarif_result["locations"])
        first_location = cast(SarifResult, locations[0])
        physical = cast(SarifResult, first_location["physicalLocation"])
        artifact = cast(SarifResult, physical["artifactLocation"])
        region = cast(SarifResult, physical["region"])
        uri = _norm_path(str(artifact["uri"]))
        start_line = int(cast(int, region["startLine"]))
        return SarifLocation(uri, start_line)
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def _match_by_loc(results: list[SarifResult], file: str, line: int) -> SarifResult | None:
    """Return the result whose physical location is exactly (file, line)."""
    target = SarifLocation(_norm_path(file), line)
    for result in results:
        if _result_loc(result) == target:
            return result
    return None


def _message_text(result: SarifResult) -> str:
    """Return a SARIF result's ``message.text``, or empty string when absent."""
    message = cast(SarifResult, result.get("message") or {})
    return str(message.get("text", ""))


def _match_by_title(results: list[SarifResult], title: str) -> SarifResult | None:
    """Return the result whose message text starts with *title* — only when exactly one does."""
    hits = [result for result in results if _message_text(result).startswith(title)]
    return hits[0] if len(hits) == 1 else None


def _match_sarif(results: list[SarifResult], finding: Finding) -> SarifResult | None:
    """Match a SARIF result to a finding by (file, startLine), else by title prefix."""
    by_loc = _match_by_loc(results, finding.file, finding.line_start) if finding.file else None
    if by_loc is not None:
        return by_loc
    title = (finding.title or "").strip()
    return _match_by_title(results, title) if title else None


def _augment_sarif(path: Path, pairs: list[ValidatedFinding]) -> None:
    """Add a ``validation`` block to each SARIF result matching a validated finding."""
    document = json.loads(path.read_text(encoding="utf-8"))
    runs = document.get("runs") or [{}]
    results = runs[0].get("results", []) if runs else []
    for finding, row in pairs:
        match = _match_sarif(results, finding)
        if match is not None:
            match["validation"] = _validation_block(row)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


# Markdown augmentation


# Escapes Markdown/HTML metacharacters per-character; mirrors remediation_agent mdsafe.py.
_MD_ESCAPE: dict[str, str] = {
    "\\": "\\\\", "`": "\\`", "*": "\\*", "_": "\\_",
    "[": "\\[", "]": "\\]", "|": "\\|", "#": "\\#",
    "<": "&lt;", ">": "&gt;", "&": "&amp;",
}


def _trim_dangling_escape(text: str) -> str:
    """Drop a trailing lone backslash left by truncation; an odd run cut an escaped pair."""
    if (len(text) - len(text.rstrip("\\"))) % 2:
        return text[:-1]
    return text


def _md_escape(text: object, limit: int = 2000) -> str:
    """Neutralize agent text for inline Markdown, bounding length to a real caller-usable bound."""
    if text is None:
        return ""
    cleaned = _MD_LINEBREAK_RX.sub(" ", str(text))
    cleaned = _MD_INVISIBLE_RX.sub("", cleaned)
    cleaned = "".join(_MD_ESCAPE.get(char, char) for char in cleaned)
    return _trim_dangling_escape(cleaned[:limit])


#: The only weighted-score key any producer emits; a `weighted` fallback here was dead.
_WEIGHTED_SCORE_KEY = "weighted_score"


def _md_cell(text: object) -> str:
    """Escape a value for a Markdown table cell (``|`` is part of the escape map)."""
    return _md_escape(text, limit=200)


def _gate_rows(gates: Mapping[str, object]) -> list[str]:
    """Render gate-score rows as markdown table lines, handling any persisted blob shape."""
    rows: list[str] = []
    for name, entry in gates.items():
        if isinstance(entry, dict):
            status = entry.get("status", "")
            weight = entry.get("weight", "")
            weighted = entry.get(_WEIGHTED_SCORE_KEY, "")
            cells = " | ".join(_md_cell(field) for field in (name, status, weight, weighted))
            rows.append(f"  | {cells} |")
        else:
            rows.append(f"  | {_md_cell(name)} | {_md_cell(entry)} | | |")
    return rows


def _md_validation_section(result: ValidationResult) -> str:
    """Render the ``### Validation`` markdown section for one finding."""
    lines = [
        "### Validation",
        f"- **Status:** {_status_word(result)}",
        f"- **Weighted score:** {result.fix_confidence}"
        f"  (merge readiness: {result.pr_merge_readiness or 'n/a'})",
    ]
    summary = (result.justification or result.reason_for_decision or "").strip()
    if summary:
        lines.append(f"- **Summary:** {_md_escape(summary)}")
    gates = _parse_gates(result.gate_results_json)
    rows = _gate_rows(gates)
    if rows:
        lines += ["- **Gate scores:**", "", "  | gate | status | weight | weighted |",
                  "  |---|---|---|---|", *rows]
    return "\n".join(lines) + "\n"


def _ftitle(pair: ValidatedFinding) -> str:
    """Return the pair's finding title, folded for matching."""
    return (pair.finding.title or pair.row.finding_title or "").strip().lower()


def _only(pairs: list[ValidatedFinding]) -> ValidationResult | None:
    """The single result when *pairs* is unambiguous, else None (fail closed on 0 or >1)."""
    return pairs[0].row if len(pairs) == 1 else None


def _best_md_match(title: str, pairs: list[ValidatedFinding]) -> ValidationResult | None:
    """Match an MD heading title to a result, failing closed to None on ambiguity (CWE-345)."""
    norm = title.strip().lower()
    if not norm:
        return None
    exact = [pair for pair in pairs if _ftitle(pair) == norm]
    if exact:
        return _only(exact)
    return _only([
        pair for pair in pairs
        if (pair_title := _ftitle(pair)) and (pair_title in norm or norm in pair_title)
    ])


def _augment_md(path: Path, pairs: list[ValidatedFinding]) -> None:
    """Insert/replace a ``### Validation`` section at finding's end, before any ``## `` heading."""
    text = path.read_text(encoding="utf-8")
    matches = list(_FINDING_RE.finditer(text))
    if not matches:
        return
    tail = _TRAILING_SECTION_RE.search(text, matches[-1].start())
    findings_end = tail.start() if tail else len(text)
    bounds = [heading_match.start() for heading_match in matches] + [findings_end]
    rebuilt = [text[: bounds[0]]]
    for index, heading_match in enumerate(matches):
        segment = text[bounds[index]: bounds[index + 1]]
        result = _best_md_match(heading_match.group(1), pairs)
        rebuilt.append(_augment_segment(segment, result))
    rebuilt.append(text[findings_end:])  # report-level ``## `` sections stay below every finding
    path.write_text("".join(rebuilt), encoding="utf-8")


def _augment_segment(segment: str, result: ValidationResult | None) -> str:
    """Replace any prior ``### Validation`` block in *segment* and append the current one."""
    if result is None:
        return segment
    stripped = _EXISTING_VALIDATION_RE.sub("", segment)
    return stripped.rstrip() + "\n\n" + _md_validation_section(result) + "\n"
