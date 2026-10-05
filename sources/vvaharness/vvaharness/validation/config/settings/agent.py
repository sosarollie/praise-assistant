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

"""Agent runtime knobs: model selection, backend, execution limits."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from vvaharness.validation.constants.artifacts import (
    DEFAULT_CLAUDE_BINARY,
    DEFAULT_EFFORT,
    DEFAULT_MAX_BUDGET_USD,
    DEFAULT_MAX_RETRIES,
    DEFAULT_MAX_TURNS,
    DEFAULT_MODEL,
    DEFAULT_VALIDATION_VIA,
)
from vvaharness.validation.enums import EffortLevel


class AgentConfig(BaseModel):
    """Agent runtime knobs: model selection, backend, execution limits."""

    model_config = ConfigDict(extra="forbid")

    binary: str = DEFAULT_CLAUDE_BINARY
    model: str = DEFAULT_MODEL
    max_turns: int = DEFAULT_MAX_TURNS
    max_budget_usd: float | None = DEFAULT_MAX_BUDGET_USD
    effort: EffortLevel = DEFAULT_EFFORT
    max_retries: int = DEFAULT_MAX_RETRIES
    via: str = DEFAULT_VALIDATION_VIA
    provider: str | None = None  # deepagents backend: openai|anthropic; None → infer
    # OpenAI-branch transport override for deepagents; None resolves (learned, then Responses).
    use_responses_api: bool | None = None
    # Optional per-persona model overrides for the s11 validator; None → inherit ``model``.
    security_architect_model: str | None = None
    penetration_tester_model: str | None = None
    cross_repo_analyzer_model: str | None = None
    # Tool allow-list for the reviewer personas (step_validate.allowed_tools); None → .md default.
    validate_tools: tuple[str, ...] | None = None
    # Whether BlockMarkerPromptCaching places cache markers; from the sdk block's cache_markers key.
    cache_markers: bool = True
