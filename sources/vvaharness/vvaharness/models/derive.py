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

"""Decisions computed from a case, not stored; pure so callers reach one without the pipeline."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Final

from vvaharness.models.context import ScoringPolicy
from vvaharness.models.vocab import (
    CaseState,
    Decision,
    Disposition,
    MergeReadiness,
    RemediationKind,
)

if TYPE_CHECKING:  # typing only, so case.py may import this module at runtime
    from vvaharness.models.case import Attempt
    from vvaharness.models.verdict import Verdict

__all__ = ["merge_readiness_for", "state_of", "verdict_state"]

# An unvalidated attempt's state follows what the engine did.
_KIND_STATE: Final[dict[RemediationKind, CaseState]] = {
    RemediationKind.EDITS_APPLIED: CaseState.REMEDIATED,
    RemediationKind.DIFF_PROPOSED: CaseState.REMEDIATED,
    RemediationKind.PULL_REQUEST: CaseState.REMEDIATED,
    RemediationKind.ALREADY_RESOLVED: CaseState.REMEDIATED,
    RemediationKind.NO_ACTION: CaseState.DECLINED,
}

# A validated attempt's state follows the decision; INCONCLUSIVE stays re-validatable.
_DECISION_STATE: Final[dict[Decision, CaseState]] = {
    Decision.FIXED: CaseState.VALIDATED,
    Decision.PARTIALLY_FIXED: CaseState.FAILED,
    Decision.NOT_FIXED: CaseState.FAILED,
    Decision.INCONCLUSIVE: CaseState.OPEN,
}

# Dispositions that close a case without a fix having been proven.
_CLOSING: Final[frozenset[Disposition]] = frozenset(
    {Disposition.FALSE_POSITIVE, Disposition.ACCEPTED_RISK, Disposition.NOT_APPLICABLE}
)


def verdict_state(verdict: Verdict) -> CaseState:
    """Map one verdict to a case state.

    Public because a caller holding verdicts in memory -- the validation run, which has
    them before any case file is rewritten -- must reach the same answer ``state_of``
    reaches from disk. Two implementations of "did this verdict validate the fix?" is
    exactly the contradiction this module exists to prevent.
    """
    if verdict.ticket is not None:
        return CaseState.PENDING
    if verdict.disposition in _CLOSING:
        return CaseState.DECLINED
    return _DECISION_STATE[verdict.decision]


def _attempt_state(attempt: Attempt) -> CaseState:
    """Map one attempt to a case state, validated or not."""
    if attempt.verdict is None:
        return _KIND_STATE[attempt.remediation.kind]
    return verdict_state(attempt.verdict)


def state_of(attempts: Sequence[Attempt]) -> CaseState:
    """Case state implied by *attempts*; the LAST attempt rules, not the best one ever seen."""
    if not attempts:
        return CaseState.OPEN
    return _attempt_state(attempts[-1])


def _readiness_for_score(score: float, policy: ScoringPolicy) -> MergeReadiness:
    """Band a numeric score against the policy's thresholds."""
    if score >= policy.ready_at:
        return MergeReadiness.READY
    if score >= policy.conditional_at:
        return MergeReadiness.READY_WITH_CONDITIONS
    return MergeReadiness.NOT_READY


# The ceiling each decision imposes; a failed critical gate caps it regardless of the arithmetic.
_DECISION_READINESS: Final[dict[Decision, MergeReadiness]] = {
    Decision.FIXED: MergeReadiness.READY,
    Decision.PARTIALLY_FIXED: MergeReadiness.READY_WITH_CONDITIONS,
    Decision.NOT_FIXED: MergeReadiness.NOT_READY,
    Decision.INCONCLUSIVE: MergeReadiness.NOT_READY,
}

# Explicit order, because MergeReadiness is a StrEnum and its members do not compare.
_RANK: Final[dict[MergeReadiness, int]] = {
    MergeReadiness.NOT_READY: 0,
    MergeReadiness.READY_WITH_CONDITIONS: 1,
    MergeReadiness.READY: 2,
}


def _lowest(*readiness: MergeReadiness) -> MergeReadiness:
    """The least-ready of *readiness*, so every rule can only ever lower the bar."""
    return min(readiness, key=_RANK.__getitem__)


def merge_readiness_for(
    verdict: Verdict, policy: ScoringPolicy | None = None
) -> MergeReadiness:
    """Whether *verdict* clears the merge bar; every input can only lower it, never raise it."""
    ceiling = _DECISION_READINESS[verdict.decision]
    if verdict.conditions:
        ceiling = _lowest(ceiling, MergeReadiness.READY_WITH_CONDITIONS)
    if verdict.score is None:
        return ceiling
    return _lowest(ceiling, _readiness_for_score(verdict.score, policy or ScoringPolicy()))
