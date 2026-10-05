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

"""Engine-local data shapes for the validation agent; see vvaharness.models for its contracts."""

from __future__ import annotations

from vvaharness.validation.models.manifest import Manifest
from vvaharness.validation.models.output import (
    GateEntry,
    OutputFinding,
    SynthesizedGatesEntry,
    ValidationOutput,
    ValidationReport,
    to_verdict,
)
from vvaharness.validation.models.persona_report import (
    HarnessTerminalState,
    PersonaGateEntry,
    PersonaReport,
)
from vvaharness.validation.models.plans import FixValidationPlan
from vvaharness.validation.models.results import (
    RunMetadata,
    SarifLocation,
    ValidationResult,
    gate_score_rows,
    render_row,
    unverifiable_row,
)
from vvaharness.validation.models.scoring import (
    RawCriterion,
    RawExtra,
    ScoreResult,
    ScoringConfig,
    ValidationScore,
    VerdictRule,
)

__all__ = [
    "FixValidationPlan",
    "GateEntry",
    "HarnessTerminalState",
    "Manifest",
    "OutputFinding",
    "PersonaGateEntry",
    "PersonaReport",
    "RawCriterion",
    "RawExtra",
    "RunMetadata",
    "SarifLocation",
    "ScoreResult",
    "ScoringConfig",
    "SynthesizedGatesEntry",
    "ValidationOutput",
    "ValidationReport",
    "ValidationResult",
    "ValidationScore",
    "VerdictRule",
    "gate_score_rows",
    "render_row",
    "to_verdict",
    "unverifiable_row",
]
