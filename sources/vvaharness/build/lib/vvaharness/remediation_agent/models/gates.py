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

"""remediation_agent.models.gates — the 3-gate evidence status block.

The remediation agent assesses three evidence gates before fixing (source,
sink, missing-control). This module owns ONLY that sub-model so it can be reused
and tested in isolation from the full verdict."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# Domain-qualified name (F23): this remediation-side status is intentionally a
# DISTINCT type from the s11 ``validation.enums.gates.GateStatus`` enum — they
# live in never-co-imported packages. The qualified name disambiguates for a
# human reader / avoids a copy-paste mixup of the two same-named symbols.
EvidenceGateStatus = Literal["pass", "partial", "fail"]
# Back-compat alias (kept because it is re-exported in models.__all__). Prefer
# ``EvidenceGateStatus`` in new code.
GateStatus = EvidenceGateStatus


class Gates(BaseModel):
    # Default to "fail" (conservative) so a verdict that omits a gate still
    # validates rather than being discarded wholesale.
    source: EvidenceGateStatus = Field(default="fail", description="Gate A — attacker-controlled source identified")
    sink: EvidenceGateStatus = Field(default="fail", description="Gate B — security-relevant sink reachable from source")
    missing_control: EvidenceGateStatus = Field(default="fail", description="Gate C — missing/insufficient validation")
