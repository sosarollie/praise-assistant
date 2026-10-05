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

"""Fix-path justification builder; tracker templates embed these phrasings -- edit deliberately."""

from __future__ import annotations

from typing import Final

from vvaharness.models import Decision, GateStatus
from vvaharness.validation.constants.scoring import (
    CONFIDENCE_PERCENT_SCALE,
    MAX_EVIDENCE_ANCHORS,
)
from vvaharness.validation.models.scoring import RawCriterion, RawExtra, ScoreResult

__all__ = ["build_fix_justification"]

_FAIL_STATUSES: Final = frozenset({GateStatus.FAIL.value, GateStatus.PARTIAL.value})
_PASS_STATUSES: Final = frozenset({GateStatus.PASS.value})


def _confidence(result: ScoreResult) -> int:
    """Return raw_score scaled to a 0-100 integer percentage."""
    return round(result.raw_score * CONFIDENCE_PERCENT_SCALE)


def _summaries(gates: list[RawCriterion], statuses: frozenset[str]) -> str:
    """Join the summaries of every gate whose status is in *statuses*."""
    return "; ".join(criterion.summary for criterion in gates if criterion.status in statuses)


def _anchors_str(gates: list[RawCriterion]) -> str:
    """Return up to MAX_EVIDENCE_ANCHORS evidence anchors joined by '; '."""
    return "; ".join(_collect_evidence_anchors(gates)[:MAX_EVIDENCE_ANCHORS])


def _fixed_text(result: ScoreResult, gates: list[RawCriterion]) -> str:
    """Render the justification for a fully verified fix."""
    return (
        f"Fix verified: {_summaries(gates, _PASS_STATUSES)}. "
        f"Fix confidence: {_confidence(result)}%. "
        f"Evidence: {_anchors_str(gates)}."
    )


def _partial_text(result: ScoreResult, gates: list[RawCriterion]) -> str:
    """Render the justification for a partial fix, naming the gaps."""
    files = _files_needing_fixes(gates)
    return (
        f"Partial fix: {_summaries(gates, _PASS_STATUSES)}. "
        f"Gaps: {_summaries(gates, _FAIL_STATUSES)}. "
        f"Fix confidence: {_confidence(result)}%. "
        f"Files needing fixes: {', '.join(files) if files else 'N/A'}."
    )


def _not_fixed_text(result: ScoreResult, gates: list[RawCriterion]) -> str:
    """Render the justification for an insufficient fix, naming the required actions."""
    files = _files_needing_fixes(gates)
    actions = _recommended_actions(gates)
    return (
        f"Fix insufficient: {_summaries(gates, frozenset({GateStatus.FAIL.value}))}. "
        f"Vulnerable pattern remains in {', '.join(files) if files else 'affected files'}. "
        f"Fix confidence: {_confidence(result)}%. "
        f"Recommended action: {'; '.join(actions)}."
    )


_DECISION_FORMATTERS: Final = {
    Decision.FIXED: _fixed_text,
    Decision.PARTIALLY_FIXED: _partial_text,
    Decision.NOT_FIXED: _not_fixed_text,
}


def build_fix_justification(
    result: ScoreResult,
    gates: list[RawCriterion],
    _extra: RawExtra,
) -> str:
    """Build a tracker-comment justification for the fix decision, not re-narrating INCONCLUSIVE."""
    if result.decision is Decision.INCONCLUSIVE:
        return result.justification or ""
    return _DECISION_FORMATTERS.get(result.decision, _not_fixed_text)(result, gates)


def _collect_evidence_anchors(criteria: list[RawCriterion]) -> list[str]:
    """Render every evidence anchor as ``file:line`` (or bare ``file`` when unanchored)."""
    return [
        f"{item.file}:{item.line}" if item.line is not None else item.file
        for criterion in criteria
        for item in criterion.evidence
    ]


def _files_needing_fixes(criteria: list[RawCriterion]) -> list[str]:
    """Return the sorted set of files cited by gates that did not pass cleanly."""
    files: set[str] = set()
    for criterion in criteria:
        if criterion.status in _FAIL_STATUSES:
            files.update(item.file for item in criterion.evidence)
    return sorted(filename for filename in files if filename)


def _recommended_actions(gates: list[RawCriterion]) -> list[str]:
    """Name one action per failing gate, or a generic fallback when none is identifiable."""
    actions = [
        f"Address {criterion.name}: {criterion.summary}"
        for criterion in gates
        if criterion.status == GateStatus.FAIL.value
    ]
    return actions or ["Review all failing gates and apply fixes"]
