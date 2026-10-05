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

"""One check and its source evidence, shared because both remediators and validators carry gates."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vvaharness.models.vocab import GateStatus, normalise_gate_name

__all__ = ["EvidenceAnchor", "GateAssessment"]


class EvidenceAnchor(BaseModel):
    """A file/line/snippet reference pinning a gate outcome to real source."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    file: str = Field(default="", description="repo-relative path")
    line: int | None = Field(default=None, description="1-indexed line, when anchored")
    snippet: str = Field(default="", description="the cited source text")

    @field_validator("file", "snippet", mode="before")
    @classmethod
    def _none_to_empty(cls, value: object) -> object:
        """Coerce a null to empty; models emit one for evidence with no file anchor."""
        return "" if value is None else value


class GateAssessment(BaseModel):
    """One named check, its outcome, and the evidence cited for it."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    name: str = Field(description="gate identifier; an OPEN vocabulary, so any name is legal")
    status: GateStatus = Field(default=GateStatus.INVALID, description="the outcome")
    summary: str = Field(default="", description="one-line result")
    details: str = Field(default="", description="longer reasoning, when supplied")
    evidence: tuple[EvidenceAnchor, ...] = Field(default=(), description="cited source")

    @field_validator("name", mode="before")
    @classmethod
    def _canonical_name(cls, value: object) -> object:
        """Normalise spelling without rejecting an unknown name."""
        return normalise_gate_name(value) if isinstance(value, str) else value
