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

"""Extract subagent persona reports from the parent graph state (DeepAgents or SDK/CLI)."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import ToolMessage
from pydantic import ValidationError

from vvaharness.validation.models.persona_report import HarnessTerminalState, PersonaReport


def _validate_candidates(
    candidates: list[Any],
) -> list[PersonaReport]:
    """Validate and dedupe a list of candidate PersonaReport dicts."""
    reports: list[PersonaReport] = []
    seen: set[tuple[str | None, str | None]] = set()
    for data in candidates:
        if not isinstance(data, dict):
            continue
        if "persona" not in data or "gates" not in data:
            continue
        key = (data.get("persona"), data.get("tracking_id"))
        if key in seen:
            continue
        seen.add(key)
        try:
            reports.append(PersonaReport.model_validate(data))
        except ValidationError:
            continue
    return reports


def extract_subagent_reports(
    final_state: HarnessTerminalState,
) -> list[PersonaReport]:
    """Pull persona reports from either a DeepAgents or SDK/CLI terminal state.

    DeepAgents: LangChain ``ToolMessage`` content in ``state["messages"]``; SDK/CLI:
    ``state["sdk_persona_reports"]``. Callers must fail closed to UNVERIFIABLE on empty.
    """
    # SDK/CLI: ClaudeHarness pre-parsed the persona reports from transcript files.
    if "sdk_persona_reports" in final_state:
        return _validate_candidates(final_state["sdk_persona_reports"])

    # DeepAgents: extract from LangChain ToolMessage objects in graph state.
    candidates: list[Any] = []
    for msg in final_state.get("messages", []):
        if not isinstance(msg, ToolMessage):
            continue
        content = msg.content
        if isinstance(content, (list, tuple)):
            content = content[0] if content else ""
        if not isinstance(content, str) or not content.strip():
            continue
        try:
            data = json.loads(content.strip())
        except json.JSONDecodeError:
            continue
        candidates.append(data)

    return _validate_candidates(candidates)
