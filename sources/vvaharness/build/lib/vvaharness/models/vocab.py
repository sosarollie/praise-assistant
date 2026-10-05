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

"""The vocabulary this package draws on: closed enums vs open labels the pipeline branches on."""

from __future__ import annotations

from enum import Enum, StrEnum
from typing import Final

__all__ = [
    "CANONICAL_GATE_NAMES",
    "EVIDENCE_GATES",
    "FIX_VALIDATION_GATES",
    "OFFENSIVE_LABELS",
    "CaseState",
    "Decision",
    "Disposition",
    "GateStatus",
    "MergeReadiness",
    "RemediationKind",
    "RemediationOutcome",
    "Severity",
    "VulnClass",
    "normalise_gate_name",
]


def _fold(value: object) -> str | None:
    """Return *value* casefolded with separators unified, or None if it is not a string."""
    if not isinstance(value, str):
        return None
    return value.strip().casefold().replace("-", "_").replace(" ", "_")


class Severity(str, Enum):  # noqa: UP042  # StrEnum would change report render output
    """How bad a finding is; kept ``(str, Enum)`` because report code interpolates members."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def _missing_(cls, value: object) -> Severity | None:
        """Accept any casing, so validation's title-case ``"Medium"`` resolves here too."""
        folded = _fold(value)
        return next((m for m in cls if m.value == folded), None)


#: Offensive-priority bands, kept beside the severity vocabulary they qualify.
OFFENSIVE_LABELS: Final[dict[str, str]] = {
    "P1": "Externally Exploitable, No Auth",
    "P2": "Externally Exploitable, Obtainable Auth",
    "P3": "Internal Network / Privileged Position",
    "P4": "Code-Knowledge / Insider Dependent",
}


class VulnClass(str, Enum):  # noqa: UP042  # kept consistent with Severity
    """Weakness class; an unknown label folds to OTHER, kept in ``vuln_class_label``."""

    UAF = "use-after-free"
    HEAP_OVERFLOW = "heap-overflow"
    STACK_OVERFLOW = "stack-overflow"
    FMT_STRING = "format-string"
    INT_OVERFLOW = "integer-overflow"
    TYPE_CONFUSION = "type-confusion"
    RACE = "race-condition"
    INJECTION = "injection"
    DESERIALIZATION = "unsafe-deserialization"
    LOGIC = "logic-flaw"
    INFO_LEAK = "info-leak"
    OTHER = "other"

    @classmethod
    def _missing_(cls, value: object) -> VulnClass:
        """Resolve a near-miss label, falling back to OTHER rather than raising."""
        folded = _fold(value)
        if folded is None:
            return cls.OTHER
        for member in cls:
            if member.value.replace("-", "_") == folded:
                return member
        return cls.OTHER


class RemediationKind(StrEnum):
    """What an engine did; lets a codemod, a PR bot or a decline fit without faking a diff."""

    EDITS_APPLIED = "edits_applied"
    DIFF_PROPOSED = "diff_proposed"
    PULL_REQUEST = "pull_request"
    NO_ACTION = "no_action"
    ALREADY_RESOLVED = "already_resolved"


class RemediationOutcome(StrEnum):
    """What an engine claims; unlike :class:`RemediationKind`, independent of the run's mode."""

    FIXED = "fixed"
    PARTIALLY_FIXED = "partially_fixed"
    NOT_FIXED = "not_fixed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    DENIED = "denied"


class Disposition(StrEnum):
    """Why no fix was produced or wanted; split out of verdicts so accepted risk is expressible."""

    FALSE_POSITIVE = "false_positive"
    POLICY_DENIED = "policy_denied"
    ACCEPTED_RISK = "accepted_risk"
    NOT_APPLICABLE = "not_applicable"


class Decision(StrEnum):
    """A validator's conclusion about whether a remediation worked."""

    FIXED = "fixed"
    PARTIALLY_FIXED = "partially_fixed"
    NOT_FIXED = "not_fixed"
    INCONCLUSIVE = "inconclusive"

    @classmethod
    def _missing_(cls, value: object) -> Decision:
        """Fold casing/spacing only, failing closed; no alias for retired values."""
        folded = _fold(value)
        if folded is None:
            return cls.INCONCLUSIVE
        return next((m for m in cls if m.value == folded), cls.INCONCLUSIVE)


class GateStatus(StrEnum):
    """One check's outcome; INVALID is harness-only and scores as failure, never dropped."""

    PASS = "pass"  # noqa: S105  # a gate outcome, not a credential
    PARTIAL = "partial"
    FAIL = "fail"
    SKIP = "skip"
    INVALID = "invalid"

    @classmethod
    def _missing_(cls, value: object) -> GateStatus:
        """Resolve a near-miss status, failing closed to INVALID."""
        folded = _fold(value)
        if folded is None:
            return cls.INVALID
        return next((m for m in cls if m.value == folded), cls.INVALID)


class CaseState(StrEnum):
    """Lifecycle position; never engine-set and never stored -- ``derive.state_of`` computes it."""

    OPEN = "open"
    REMEDIATED = "remediated"
    VALIDATED = "validated"
    FAILED = "failed"
    DECLINED = "declined"
    PENDING = "pending"


class MergeReadiness(StrEnum):
    """Whether a fix may merge; owned by whoever runs the scan, not by the engine."""

    READY = "ready"
    READY_WITH_CONDITIONS = "ready_with_conditions"
    NOT_READY = "not_ready"


#: Evidence gates a remediator asserts before patching.
EVIDENCE_GATES: Final[tuple[str, ...]] = ("source", "sink", "missing_control")

#: Gates the bundled fix-validation panel scores.
FIX_VALIDATION_GATES: Final[tuple[str, ...]] = (
    "root_cause",
    "instance_coverage",
    "no_new_vulnerabilities",
    "security_best_practices",
)

#: Every gate name this project ships. Documented, not enforced -- gate names are open.
CANONICAL_GATE_NAMES: Final[tuple[str, ...]] = EVIDENCE_GATES + FIX_VALIDATION_GATES


def normalise_gate_name(value: str) -> str:
    """Canonicalise a gate name's spelling; an unknown name passes through, never rejected."""
    return _fold(value) or ""
