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

"""remediation_agent.policy_gate.action — the gate decision value types.

The binary :class:`Action` (PATCH vs GUIDANCE_ONLY) and the immutable
:class:`Decision` the gate returns. There is no "auto" vs "suggest" autonomy
mode: a finding is either patched or routed to guidance-only output."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Action(str, Enum):
    PATCH = "patch"                  # generate patch and apply (no human gate)
    GUIDANCE_ONLY = "guidance_only"  # NEVER call patch LLM; emit prose advice


@dataclass(frozen=True)
class Decision:
    action: Action
    reason: str
    matched_rule: str | None = None

    @property
    def may_generate_patch(self) -> bool:
        return self.action is Action.PATCH


_FAIL_CLOSED = Decision(Action.GUIDANCE_ONLY, "policy_unavailable_fail_closed")
