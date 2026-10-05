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

"""Translate DeepAgents / LangGraph state and messages into HarnessMessage types."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    ToolMessage,
)
from langchain_core.messages.tool import ToolCall
from pydantic import BaseModel

from vvaharness.backends.harness.deepagents.models import DeepAgentsGraphState, StreamEvent
from vvaharness.backends.harness.deepagents.usage import (
    SessionUsage,
    aggregate_usage_metadata,
)
from vvaharness.backends.harness.models import (
    HarnessAssistantText,
    HarnessMessage,
    HarnessResult,
    HarnessToolResult,
    HarnessToolUse,
    OneShotResult,
)
from vvaharness.util.tokens import TOKENS


def _extract_text(message: AIMessage) -> str:
    if isinstance(message.content, str):
        return message.content
    parts = [
        str(block.get("text", ""))
        for block in message.content
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    return "".join(parts)


def _tool_calls(message: AIMessage) -> list[ToolCall]:
    return list(message.tool_calls)


def _last_ai_text(messages: Sequence[BaseMessage]) -> str | None:
    """Return the last non-empty assistant text found scanning messages in reverse."""
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            text = _extract_text(message).strip()
            if text:
                return text
    return None


def translate_final_state(state: DeepAgentsGraphState, *, oneshot: bool = False) -> OneShotResult:
    """Convert a terminal LangGraph state into a OneShotResult."""
    messages = state.get("messages", [])
    # state["usage"] is never populated on this route; recover per-call usage
    # from the messages so one-shot invocations count toward stage telemetry.
    usage = aggregate_usage_metadata(messages)
    if usage is not None:
        TOKENS.add(usage)
    structured = state.get("structured_response")
    if structured is not None:
        dump_as_json = getattr(structured, "model_dump_json", None)
        dump_as_dict = getattr(structured, "model_dump", None)
        if callable(dump_as_json):
            result_text = dump_as_json()
        elif callable(dump_as_dict):
            result_text = dump_as_dict()
        else:
            result_text = str(structured)
        return OneShotResult(
            result_text=None,
            structured=result_text,
            usage=usage,
        )
    return OneShotResult(result_text=_last_ai_text(messages), usage=usage)


def _messages_from_event(payload: Mapping[str, DeepAgentsGraphState]) -> list[BaseMessage]:
    """Collect new messages from a LangGraph ``stream_mode='updates'`` payload."""
    messages: list[BaseMessage] = []
    for update in payload.values():
        if not isinstance(update, dict):
            continue
        node_messages = update.get("messages")
        if isinstance(node_messages, Sequence):
            messages.extend(node_messages)
    return messages


async def translate_stream_events(
    event: StreamEvent | Mapping[str, DeepAgentsGraphState],
    seen_tool_call_ids: set[str],
    ns_to_agent: dict[tuple[str, ...], str] | None = None,
) -> AsyncIterator[HarnessMessage]:
    """Yield HarnessMessage variants for one LangGraph stream event.

    Messages are tagged by persona from AIMessage.name; tool results inherit it via ns_to_agent.
    """
    if ns_to_agent is None:
        ns_to_agent = {}
    namespace, payload = event if isinstance(event, tuple) else ((), event)
    namespace_tag = tuple(namespace) if namespace else None
    for message in _messages_from_event(payload):
        if isinstance(message, AIMessage):
            name = getattr(message, "name", None)
            if name:
                ns_to_agent[namespace] = name
            agent = name or ns_to_agent.get(namespace)
            text = _extract_text(message)
            if text.strip():
                yield HarnessAssistantText(text=text, agent=agent, namespace=namespace_tag)
            for call in _tool_calls(message):
                tool_call_id = call.get("id", "")
                if not tool_call_id:
                    continue
                if tool_call_id in seen_tool_call_ids:
                    continue
                seen_tool_call_ids.add(tool_call_id)
                yield HarnessToolUse(
                    tool_id=tool_call_id,
                    name=call.get("name", ""),
                    input=call.get("args", {}),
                    agent=agent,
                    namespace=namespace_tag,
                )
        elif isinstance(message, ToolMessage):
            yield HarnessToolResult(
                content=message.content,
                is_error=getattr(message, "status", "success") == "error",
                agent=ns_to_agent.get(namespace),
                namespace=namespace_tag,
            )


def make_terminal_result(
    state: DeepAgentsGraphState,
    session_id: str | None = None,
    stream_usage: SessionUsage | None = None,
) -> HarnessResult:
    """Synthesize a terminal HarnessResult from the final LangGraph state.

    ``stream_usage`` is a UsageAccumulator snapshot collected while streaming;
    it is preferred over final-state aggregation because it includes persona
    subagent turns, which never reach the parent graph state.
    """
    messages = state.get("messages", [])
    final_text = _last_ai_text(messages)
    structured = state.get("structured_response")
    if isinstance(structured, BaseModel):
        structured = structured.model_dump()
    # Mirror the Claude backend token counter hook. state["usage"] is never
    # populated on this route, so fall back to stream accumulation, then to
    # aggregating the final state's messages.
    raw_usage = state.get("usage")
    usage = raw_usage if isinstance(raw_usage, dict) else None
    if usage is None:
        usage = stream_usage if stream_usage is not None else aggregate_usage_metadata(messages)
    if usage is not None:
        TOKENS.add(usage)

    return HarnessResult(
        subtype="success",
        session_id=session_id,
        result_text=final_text,
        structured=structured,
        usage=usage,
        total_cost_usd=None,
        state=state,
    )


__all__ = ["make_terminal_result", "translate_final_state", "translate_stream_events"]
