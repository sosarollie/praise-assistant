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

"""Wire shapes for DeepAgents persona reports; FROZEN -- names match the schema personas fill."""

from __future__ import annotations

from typing import NotRequired, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from vvaharness.models import EvidenceAnchor, GateStatus

__all__ = ["HarnessTerminalState", "PersonaGateEntry", "PersonaReport"]


class HarnessTerminalState(TypedDict, total=False):
    """Backend-specific shape of the harness's terminal graph/session state."""

    sdk_persona_reports: NotRequired[list[dict[str, object]]]
    messages: NotRequired[list[object]]


class PersonaGateEntry(BaseModel):
    """One gate verdict emitted by a single persona."""

    # Tolerate stray fields: gpt-5.5 and peers add unknown keys; dropping beats aborting the run.
    model_config = ConfigDict(extra="ignore")

    gate_name: str
    # Folds casing/spacing and fails closed to INVALID, which scores 0.0 and stays in the
    # denominator -- strictly safer than rejecting the whole report over one garbled status.
    status: GateStatus
    summary: str
    details: str = ""
    evidence: list[EvidenceAnchor] = Field(default_factory=list)


class PersonaReport(BaseModel):
    """Structured response from one validation subagent / persona."""

    # A persona must NOT emit synthesis-level fields; ignore so an appended one is not fatal.
    model_config = ConfigDict(extra="ignore")

    persona: str
    tracking_id: str
    gates: list[PersonaGateEntry]
