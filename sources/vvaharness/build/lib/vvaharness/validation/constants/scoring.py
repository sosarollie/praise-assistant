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

"""Canonical scoring weights/thresholds for the bundled fix-validation panel, as a ScoringPolicy."""

from __future__ import annotations

from typing import Final

from vvaharness.models import FIX_VALIDATION_GATES, GateStatus, ScoringPolicy

__all__ = [
    "CONFIDENCE_PERCENT_SCALE",
    "CRITERION_NAME_FIELD",
    "FIX_POLICY",
    "GATE_WEIGHTS",
    "MAX_EVIDENCE_ANCHORS",
    "SCORE_FLOOR",
    "SCORE_PRECISION",
    "STATUS_MULTIPLIER",
]

# Four renormalized gates (branch_targeting dropped; the agent must emit exactly these keys).
GATE_WEIGHTS: Final[dict[str, float]] = {
    "root_cause": 0.43,
    "instance_coverage": 0.2467,
    "no_new_vulnerabilities": 0.1867,
    "security_best_practices": 0.1366,
}

# Load-bearing gates: neither can be skipped or out-weighted by the other three.
_CRITICAL_GATES: Final[frozenset[str]] = frozenset({"no_new_vulnerabilities", "root_cause"})

#: This engine's scoring policy; ready_at/conditional_at mirror the prompt's scoring matrix.
FIX_POLICY: Final[ScoringPolicy] = ScoringPolicy(
    required_gates=FIX_VALIDATION_GATES,
    weights=GATE_WEIGHTS,
    critical=_CRITICAL_GATES,
    ready_at=0.80,
    conditional_at=0.50,
)

# SKIP is weight-neutral: dropped from the denominator so it neither earns nor drags credit.
STATUS_MULTIPLIER: Final[dict[str, float]] = {
    GateStatus.PASS.value: 1.0,
    GateStatus.PARTIAL.value: 0.5,
    GateStatus.FAIL.value: 0.0,
    GateStatus.SKIP.value: 0.0,
}

# Score floor constant (minimum possible score, floor of VerdictRule and fallback default).
SCORE_FLOOR: Final[float] = 0.0

# JSON field name used by the scoring agent to identify a gate criterion.
CRITERION_NAME_FIELD: Final[str] = "gate_name"

# Decimal precision for rounded scores (engine output and wire shape).
SCORE_PRECISION: Final[int] = 4

# Scale factor to convert a 0.0-1.0 score to a 0-100 confidence percentage.
CONFIDENCE_PERCENT_SCALE: Final[int] = 100

# Maximum evidence anchors included in the justification string.
MAX_EVIDENCE_ANCHORS: Final[int] = 5
