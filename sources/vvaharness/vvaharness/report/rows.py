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

"""Rendering one :class:`~vvaharness.models.FindingCase` for a human or a tool: derived at render time, never stored, so `No` is only ever a concluded claim (else `?`) and an unscored fix renders absent rather than `0.0`."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, Final

from vvaharness.models import (
    Decision,
    GateAssessment,
    Severity,
    Verdict,
    merge_readiness_for,
)

if TYPE_CHECKING:  # typing only -- the render layer is importable without the pipeline
    from vvaharness.models import FindingCase, ScoringPolicy

__all__ = [
    "NO",
    "UNKNOWN",
    "YES",
    "md_section_for",
    "row_for",
    "sarif_result_for",
]

#: The tri-state. ``UNKNOWN`` is a first-class answer, not a formatting fallback.
YES: Final = "Yes"
NO: Final = "No"
UNKNOWN: Final = "?"

# A decision that concluded answers all three cells; INCONCLUSIVE answers none of them.
_TRISTATE: Final[dict[Decision, tuple[str, str, str]]] = {
    Decision.FIXED: (YES, NO, NO),
    Decision.PARTIALLY_FIXED: (NO, YES, NO),
    Decision.NOT_FIXED: (NO, NO, YES),
    Decision.INCONCLUSIVE: (UNKNOWN, UNKNOWN, UNKNOWN),
}

# Human wording for the single-status cell, keyed on the same decision.
_STATUS_WORD: Final[dict[Decision, str]] = {
    Decision.FIXED: "Fixed",
    Decision.PARTIALLY_FIXED: "Partially Fixed",
    Decision.NOT_FIXED: "Not Fixed",
    Decision.INCONCLUSIVE: "Inconclusive",
}

# SARIF's four levels; the scan's five severities fold onto them.
_SARIF_LEVEL: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Per-character defanging of Markdown and HTML metacharacters in agent-authored text.
_MD_ESCAPE: Final[dict[str, str]] = {
    "\\": "\\\\", "`": "\\`", "*": "\\*", "_": "\\_",
    "[": "\\[", "]": "\\]", "|": "\\|", "#": "\\#",
    "<": "&lt;", ">": "&gt;", "&": "&amp;",
}


def _trim_dangling_escape(text: str) -> str:
    """Drop a trailing lone backslash left behind by truncation, which would otherwise escape the next cell's ``|``."""
    if (len(text) - len(text.rstrip("\\"))) % 2:
        return text[:-1]
    return text


def _md(text: object, limit: int = 2000) -> str:
    """Neutralise agent-authored text for inline Markdown, bounded after escaping so the cut can't split an escape pair."""
    cleaned = _CTRL_RE.sub("", str(text)).replace("\r", " ").replace("\n", " ")
    return _trim_dangling_escape("".join(_MD_ESCAPE.get(c, c) for c in cleaned)[:limit])


def _verdict_of(case: FindingCase) -> Verdict | None:
    """The verdict that speaks for the case: the last attempt's, once judged — an earlier pass never overrides a later one."""
    return case.attempts[-1].verdict if case.attempts else None


def _tristate(verdict: Verdict | None) -> tuple[str, str, str]:
    """``(fixed, partially_fixed, not_fixed)`` for *verdict*, or all-``?`` without one."""
    if verdict is None:
        return (UNKNOWN, UNKNOWN, UNKNOWN)
    return _TRISTATE[verdict.decision]


def _readiness(verdict: Verdict | None, policy: ScoringPolicy | None) -> str:
    """Merge readiness banded by policy, or empty when nothing has been judged yet; the report gets no second opinion on thresholds."""
    return "" if verdict is None else merge_readiness_for(verdict, policy).value


def _reason(verdict: Verdict | None) -> str:
    """The rationale, prefixed with the decision so a cell truncated downstream still carries the verdict first."""
    if verdict is None:
        return ""
    head = verdict.decision.value
    if verdict.score is not None:
        head = f"{head} (score: {verdict.score})"
    return f"{head}. {verdict.rationale}".strip()


def _gate_entry(gate: GateAssessment) -> dict[str, str]:
    """One gate as a JSON object, carrying only what the assessment holds — no weight/weighted_score, an arithmetic nobody computed."""
    entry = {"status": gate.status.value}
    if gate.summary:
        entry["summary"] = gate.summary
    if gate.details:
        entry["details"] = gate.details
    return entry


def _gate_results_json(verdict: Verdict | None) -> str:
    """Gate outcomes as a JSON string (not a mapping) keyed by gate name, since this lands in flat single-column destinations."""
    if verdict is None or not verdict.gates:
        return ""
    return json.dumps({gate.name: _gate_entry(gate) for gate in verdict.gates},
                      sort_keys=True)


def row_for(case: FindingCase, *, policy: ScoringPolicy | None = None) -> dict[str, Any]:
    """One flat record for *case*, for a table, a CSV, or a JSON summary; `fix_confidence` is None, not 0.0, when unscored."""
    finding = case.finding
    verdict = _verdict_of(case)
    fixed, partially_fixed, not_fixed = _tristate(verdict)
    return {
        "case_id": case.case_id,
        "state": case.state.value,
        "title": finding.title,
        "file": finding.file,
        "line_start": finding.line_start,
        "severity": finding.severity.value,
        "vuln_class": finding.vuln_class_label or finding.vuln_class.value,
        "cwe": finding.cwe or "",
        "fixed": fixed,
        "partially_fixed": partially_fixed,
        "not_fixed": not_fixed,
        "fix_confidence": None if verdict is None else verdict.score,
        "merge_readiness": _readiness(verdict, policy),
        "reason": _reason(verdict),
        "gate_results_json": _gate_results_json(verdict),
        "conditions": "; ".join(verdict.conditions) if verdict else "",
        "recommendations": "; ".join(verdict.recommendations) if verdict else "",
        "also_at": [f"{dup.file}:{dup.line_start}" for dup in finding.duplicates],
    }


def _validation_properties(verdict: Verdict, policy: ScoringPolicy | None) -> dict[str, Any]:
    """The SARIF ``validation`` property bag for a judged case; `weightedScore` is omitted entirely on an unscored verdict."""
    block: dict[str, Any] = {
        "validationStatus": verdict.decision.value,
        "validationReason": _reason(verdict)[:2000],
        "mergeReadiness": _readiness(verdict, policy),
    }
    if verdict.score is not None:
        block["weightedScore"] = verdict.score
    if verdict.gates:
        block["gateScores"] = {gate.name: _gate_entry(gate) for gate in verdict.gates}
    if verdict.disposition is not None:
        block["disposition"] = verdict.disposition.value
    return block


def _related_locations(case: FindingCase) -> list[dict[str, Any]]:
    """The other call sites this case covers, as SARIF related locations — duplicates are fix sites, not collapsed noise."""
    related: list[dict[str, Any]] = []
    for dup in case.finding.duplicates:
        region: dict[str, Any] = {"startLine": dup.line_start}
        if dup.line_end and dup.line_end != dup.line_start:
            region["endLine"] = dup.line_end
        related.append({
            "physicalLocation": {
                "artifactLocation": {"uri": dup.file},
                "region": region,
            },
            "message": {"text": "Additional call site collapsed during dedup — same root "
                                "cause, and it needs the same fix."},
        })
    return related


def sarif_result_for(case: FindingCase, *,
                     policy: ScoringPolicy | None = None) -> dict[str, Any]:
    """A SARIF ``result`` object for *case*; the case id goes in ``partialFingerprints`` so scans correlate across line drift."""
    finding = case.finding
    verdict = _verdict_of(case)
    region: dict[str, Any] = {"startLine": finding.line_start}
    if finding.line_end and finding.line_end != finding.line_start:
        region["endLine"] = finding.line_end
    properties: dict[str, Any] = {
        "severity": finding.severity.value,
        "caseState": case.state.value,
    }
    if verdict is not None:
        properties["validation"] = _validation_properties(verdict, policy)
    result: dict[str, Any] = {
        "ruleId": finding.cwe or finding.vuln_class.value,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.title},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file},
                "region": region,
            },
        }],
        "partialFingerprints": {"vvaFindingId/v1": case.case_id},
        "properties": properties,
    }
    related = _related_locations(case)
    if related:
        result["relatedLocations"] = related
    return result


def _gate_rows(verdict: Verdict) -> list[str]:
    """Gate outcomes as Markdown table lines."""
    return [f"| {_md(g.name, limit=200)} | {g.status.value} | {_md(g.summary, limit=200)} |"
            for g in verdict.gates]


def _status_line(verdict: Verdict | None) -> str:
    """The status bullet, saying *unknown* rather than guessing when nothing was judged."""
    if verdict is None:
        return "- **Status:** Not yet validated"
    return f"- **Status:** {_STATUS_WORD[verdict.decision]}"


def _confidence_line(verdict: Verdict, policy: ScoringPolicy | None) -> str:
    """The confidence bullet, reading *not scored* when the validator reported no number."""
    score = "not scored" if verdict.score is None else f"{verdict.score:.2f}"
    return f"- **Confidence:** {score}  (merge readiness: {_readiness(verdict, policy) or 'n/a'})"


def md_section_for(case: FindingCase, *, policy: ScoringPolicy | None = None) -> str:
    """The Markdown section for *case*, appended under its finding in the report."""
    verdict = _verdict_of(case)
    lines = [
        f"### Case `{_md(case.case_id, limit=64)}` — {case.state.value}",
        _status_line(verdict),
    ]
    if verdict is None:
        return "\n".join(lines) + "\n"
    lines.append(_confidence_line(verdict, policy))
    lines.append(f"- **Reason:** {_md(_reason(verdict))}")
    if verdict.conditions:
        lines.append(f"- **Conditions for a full fix:** {_md('; '.join(verdict.conditions))}")
    if verdict.recommendations:
        lines.append(f"- **Recommendations:** {_md('; '.join(verdict.recommendations))}")
    rows = _gate_rows(verdict)
    if rows:
        lines += ["- **Gates:**", "", "| gate | status | summary |", "|---|---|---|", *rows]
    return "\n".join(lines) + "\n"
