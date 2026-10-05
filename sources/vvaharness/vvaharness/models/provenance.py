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

"""Who produced a result, with what, and at what cost; never holds credential values."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["HARNESS_REGISTRY", "LLM_REGISTRY", "Provenance"]

#: ``Provenance.backend`` prefixes; a bare via like "cli" or "deepagents" names different
#: transports depending on the registry, so the prefix is what disambiguates them.
LLM_REGISTRY = "llm"
HARNESS_REGISTRY = "harness"


class Provenance(BaseModel):
    """The attributable origin of one remediation or one verdict."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    engine: str = Field(default="", description="engine identity, e.g. 'vvaharness.agentic'")
    engine_version: str = Field(default="", description="version of that engine")
    model: str = Field(default="", description="model id, when the engine used one")
    # Only two paths stamp this: S10 remediation via `engine_model`
    # (plugin_runner/run.py) emits `llm:<via>`, and S11 validation
    # (validation/cli/_run.py) emits `harness:<via>`. No detection role writes a
    # Provenance at all, so an `llm:` prefix here always means S10.
    backend: str = Field(
        default="",
        description=(
            "registry-qualified transport, e.g. 'llm:cli'. NOTE 'llm:deepagents' is S10 "
            "remediation on the deepagents route — a historical label, not an accurate "
            "one: that call executes on the HARNESS, not through the llm registry (which "
            "has no deepagents backend and raises on one). It is kept as-is because the "
            "(model, backend) pair is hashed into S10 resume checkpoint keys, so "
            "relabelling it would invalidate in-flight resume state. "
            "'harness:deepagents' is S11 validation."
        ),
    )
    # None, not 0: a zero could not be told from a policy-denied attempt's genuine zero.
    turns: int | None = Field(default=None, description="agent turns; None when unreported")
    usd: float | None = Field(default=None, description="spend in USD; None when unreported")
    started: datetime | None = Field(default=None, description="UTC start")
    ended: datetime | None = Field(default=None, description="UTC finish")
