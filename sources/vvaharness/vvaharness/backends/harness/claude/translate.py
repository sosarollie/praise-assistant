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

"""SDK message translation: Claude Agent SDK types → HarnessMessage variants."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import cast

from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolUseBlock,
    UserMessage,
)

from vvaharness.backends.harness.models import (
    HarnessAssistantText,
    HarnessMessage,
    HarnessResult,
    HarnessSessionInit,
    HarnessToolResult,
    HarnessToolUse,
)
from vvaharness.util.tokens import TOKENS, TokenUsage


def translate_init(message: SystemMessage) -> list[HarnessMessage]:
    """Translate a SystemMessage init into a session-init harness message."""
    data: Mapping[str, object] = message.data if isinstance(message.data, Mapping) else {}
    sid_raw = data.get("session_id")
    return [HarnessSessionInit(
        session_id=sid_raw if isinstance(sid_raw, str) else "",
        raw=dict(data),
    )]


def translate_assistant(message: AssistantMessage) -> list[HarnessMessage]:
    """Translate assistant tool-use and text blocks into harness messages."""
    out: list[HarnessMessage] = []
    for block in message.content:
        if isinstance(block, ToolUseBlock):
            inp: Mapping[str, object] = block.input if isinstance(block.input, Mapping) else {}
            out.append(HarnessToolUse(tool_id=block.id or "", name=block.name, input=dict(inp)))
        elif isinstance(block, TextBlock):
            out.append(HarnessAssistantText(text=block.text))
    return out


def translate_tool_result(message: UserMessage) -> list[HarnessMessage]:
    """Translate user tool-use results into harness tool-result messages."""
    tru = message.tool_use_result
    items: list[object] = list(tru) if isinstance(tru, list) else [tru]
    out: list[HarnessMessage] = []
    for item in items:
        if isinstance(item, Mapping):
            out.append(HarnessToolResult(is_error=bool(item.get("is_error", False)),
                                         content=dict(item)))
        else:
            out.append(HarnessToolResult(is_error=False, content=item))
    return out


def translate_result(message: ResultMessage) -> list[HarnessMessage]:
    """Translate a terminal ResultMessage and feed the process-wide token counter."""
    # Cumulative per session; added once here, using the SDK's own measured cost.
    TOKENS.add(cast("TokenUsage | None", message.usage), usd=message.total_cost_usd)
    return [HarnessResult(
        subtype=message.subtype,
        is_error=bool(message.is_error),
        session_id=message.session_id,
        result_text=message.result,
        structured=message.structured_output,
        errors=message.errors,
        usage=cast("TokenUsage | None", message.usage),
        total_cost_usd=message.total_cost_usd,
    )]


def _translate_system(message: object) -> list[HarnessMessage]:
    m = cast(SystemMessage, message)
    return translate_init(m) if m.subtype == "init" else []


def _translate_user(message: object) -> list[HarnessMessage]:
    m = cast(UserMessage, message)
    return translate_tool_result(m) if m.tool_use_result is not None else []


_TRANSLATORS: dict[type, Callable[[object], list[HarnessMessage]]] = {
    SystemMessage: _translate_system,
    AssistantMessage: lambda m: translate_assistant(cast(AssistantMessage, m)),
    UserMessage: _translate_user,
    ResultMessage: lambda m: translate_result(cast(ResultMessage, m)),
}


def translate(message: object) -> list[HarnessMessage]:
    """Dispatch a raw SDK message to the appropriate HarnessMessage translation."""
    handler = _TRANSLATORS.get(type(message))
    return handler(message) if handler is not None else []
