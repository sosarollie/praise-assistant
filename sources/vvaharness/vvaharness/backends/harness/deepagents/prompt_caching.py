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

"""Anthropic prompt caching via block-level markers only.

The stock middleware requests conversation-tail caching through the top-level
``cache_control`` request param, which the gateway drops. This subclass keeps
the parent's system/tools block markers and marks the tail with a block-level
marker instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from langchain_anthropic.middleware.prompt_caching import (
    AnthropicPromptCachingMiddleware,
    _tag_system_message,
    _tag_tools,
)

if TYPE_CHECKING:
    from langchain.agents.middleware.types import ModelRequest
    from langchain_core.messages import AnyMessage

#: Uniform TTL for every marker this middleware places.
_TTL: Final = "5m"

#: Non-Anthropic models pass through untouched, matching the auto-attached instance.
_UNSUPPORTED_MODEL_BEHAVIOR: Final = "ignore"

#: Block types Anthropic rejects cache_control on; the tail walk skips them.
_INELIGIBLE_TAIL_BLOCK_TYPES: Final[frozenset[str]] = frozenset(
    {"thinking", "redacted_thinking"}
)


def _tagged_block(
    block: str | dict[str, object], cache_control: dict[str, str]
) -> dict[str, object] | None:
    """The block with a marker attached, or None when it is ineligible."""
    if isinstance(block, str):
        promoted: dict[str, object] = {
            "type": "text",
            "text": block,
            "cache_control": cache_control,
        }
        return promoted if block else None
    if isinstance(block, dict) and block.get("type") not in _INELIGIBLE_TAIL_BLOCK_TYPES:
        return {**block, "cache_control": cache_control}
    return None


def _tag_blocks(
    content: list[str | dict[str, object]], cache_control: dict[str, str]
) -> list[str | dict[str, object]] | None:
    """Copy of *content* with the last eligible block marked, or None if none is."""
    for index in range(len(content) - 1, -1, -1):
        tagged = _tagged_block(content[index], cache_control)
        if tagged is not None:
            return [*content[:index], tagged, *content[index + 1 :]]
    return None


def _tag_content(
    content: str | list[str | dict[str, object]], cache_control: dict[str, str]
) -> list[str | dict[str, object]] | None:
    """Content copy with the last eligible block marked, or None when nothing is."""
    if isinstance(content, str):
        block = _tagged_block(content, cache_control)
        return None if block is None else [block]
    return _tag_blocks(content, cache_control)


def _tag_tail(
    messages: list[AnyMessage], cache_control: dict[str, str]
) -> list[AnyMessage] | None:
    """New message list with a marker on the tail's last eligible block, or None."""
    if not messages:
        return None
    last = messages[-1]
    new_content = _tag_content(last.content, cache_control)
    if new_content is None:
        return None
    return [*messages[:-1], last.model_copy(update={"content": new_content})]


class BlockMarkerPromptCaching(AnthropicPromptCachingMiddleware):
    """Conversation caching with block markers; never the top-level request param."""

    def __init__(self, *, enabled: bool = True, mark_tail: bool = True) -> None:
        """Cache via block markers when *enabled*; pass requests through untouched otherwise.

        *mark_tail* False skips the conversation-tail marker: a single-call
        one-shot request pays the write premium on content nothing reads back.
        """
        super().__init__(ttl=_TTL, unsupported_model_behavior=_UNSUPPORTED_MODEL_BEHAVIOR)
        self._enabled = enabled
        self._mark_tail = mark_tail

    @property
    def name(self) -> str:
        """Parent class name, so deepagents replaces its auto-attached instance in-place."""
        return AnthropicPromptCachingMiddleware.__name__

    def _should_apply_caching(self, request: ModelRequest) -> bool:
        """False when disabled, else the parent's Anthropic-model check."""
        return self._enabled and super()._should_apply_caching(request)

    def _apply_caching(self, request: ModelRequest) -> ModelRequest:
        """Mark system, tools and (on agentic sessions) the conversation tail."""
        cache_control = self._cache_control
        # No model_settings["cache_control"]: the gateway drops the top-level param.
        system_message = _tag_system_message(request.system_message, cache_control)
        tools = _tag_tools(request.tools, cache_control)
        tail = _tag_tail(request.messages, cache_control) if self._mark_tail else None
        return request.override(
            system_message=system_message,
            tools=request.tools if tools is None else tools,
            messages=request.messages if tail is None else tail,
        )


__all__ = ["BlockMarkerPromptCaching"]
