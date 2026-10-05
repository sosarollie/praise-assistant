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

"""What a validator must produce; lets any replacement validator discover the gate set it owes."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = ["ScoringPolicy"]


class ScoringPolicy(BaseModel):
    """What a validator must produce, and how this host scores it; ``required_gates`` is owed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    required_gates: tuple[str, ...] = Field(default=(), description="gates a validator must answer")
    weights: dict[str, float] = Field(default_factory=dict, description="per-gate weight")
    critical: frozenset[str] = Field(
        default=frozenset(), description="gates whose failure caps the verdict"
    )
    ready_at: float = Field(default=0.85, description="score at or above which a fix is ready")
    conditional_at: float = Field(
        default=0.60, description="score at or above which a fix is ready with conditions"
    )

    @model_validator(mode="after")
    def _gates_and_weights_agree(self) -> ScoringPolicy:
        """Refuse a policy whose gates/weights disagree, since the scorer prefers ``weights``."""
        if set(self.required_gates) != set(self.weights):
            only_required = sorted(set(self.required_gates) - set(self.weights))
            only_weighted = sorted(set(self.weights) - set(self.required_gates))
            msg = (f"ScoringPolicy gate sets disagree: required-only={only_required}, "
                   f"weighted-only={only_weighted}. A gate this host scores must be one it "
                   f"asked for, and vice versa.")
            raise ValueError(msg)
        return self

    def missing_from(self, gate_names: Iterable[str]) -> tuple[str, ...]:
        """Gates *gate_names* omits, after normalising both sides against folded names."""
        from vvaharness.models.vocab import normalise_gate_name

        answered = {normalise_gate_name(n) for n in gate_names}
        return tuple(g for g in self.required_gates
                     if normalise_gate_name(g) not in answered)
