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

"""Whether a fix worked; ``score`` is ``None``, not ``0.0``, when unscored."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from vvaharness.models.gates import GateAssessment
from vvaharness.models.provenance import Provenance
from vvaharness.models.vocab import Decision, Disposition

__all__ = ["Ticket", "Verdict"]


class Ticket(BaseModel):
    """A handle for a verdict that will arrive later, e.g. from a human reviewer."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    ref: str = Field(description="the validator's own identifier for the pending review")
    opaque: str = Field(default="", description="validator-private state to resume with")


class Verdict(BaseModel):
    """One validator's conclusion about one remediation."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    decision: Decision = Field(description="did the fix work")
    # ``rationale`` is the host's account; ``engine_rationale`` is the validator's own prose.
    rationale: str = Field(description="why, as the host scored it")
    engine_rationale: str = Field(
        default="", description="the validator's own account, verbatim; empty when it gave none"
    )
    score: float | None = Field(
        default=None, ge=0.0, le=1.0, description="0-1 confidence; None when unscored"
    )
    gates: tuple[GateAssessment, ...] = Field(default=(), description="per-check outcomes")
    conditions: tuple[str, ...] = Field(default=(), description="what would make this a full fix")
    recommendations: tuple[str, ...] = Field(default=(), description="code-level follow-ups")
    disposition: Disposition | None = Field(
        default=None, description="accepted risk or false positive, when a reviewer says so"
    )
    ticket: Ticket | None = Field(default=None, description="set when the verdict is deferred")
    produced_by: Provenance = Field(default=Provenance(), description="attributable origin")
