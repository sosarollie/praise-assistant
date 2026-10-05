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

"""Read-only session middleware: redact file content, remove the write tools.

DeepAgents' native ``read_file``/``grep`` have no redaction hook, so results are masked here
before they re-enter model context; write tools are withheld too since the filesystem deny
rules fail open on unmatched paths and cannot be relied on alone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import ToolMessage

from vvaharness.backends.harness.deepagents.exclude_tools import ExcludeTools
from vvaharness.backends.harness.deepagents.models import DELETE_TOOL_NAME
from vvaharness.backends.harness.models import NATIVE_CONTENT_TOOLS, NATIVE_WRITE_TOOLS
from vvaharness.report.redact import redact_counts

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from langchain.agents.middleware.types import ToolCallRequest
    from langgraph.types import Command


def _redact_message(message: ToolMessage | Command[Any]) -> ToolMessage | Command[Any]:
    """Mask credential material in a ToolMessage's string content, in place."""
    if isinstance(message, ToolMessage) and isinstance(message.content, str) and message.content:
        message.content = redact_counts(message.content)[0]
    return message


def _redact_if_content_tool(
    request: ToolCallRequest, result: ToolMessage | Command[Any]
) -> ToolMessage | Command[Any]:
    """Mask *result* when *request* called a content-returning native tool."""
    if request.tool_call.get("name") in NATIVE_CONTENT_TOOLS:
        return _redact_message(result)
    return result


class RedactToolResults(AgentMiddleware):
    """Mask PII/credentials in content-returning native filesystem tool results."""

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        """Run the tool call, masking the result when it carries file content."""
        return _redact_if_content_tool(request, handler(request))

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        """Async counterpart of :meth:`wrap_tool_call`."""
        return _redact_if_content_tool(request, await handler(request))


def read_only_middleware(
    extra_excluded: frozenset[str] = frozenset(),
) -> list[AgentMiddleware]:
    """Middleware every read-only agent needs, parent and subagents alike.

    DeepAgents applies ``create_deep_agent(middleware=...)`` to the parent stack
    only, so subagents must be given their own copy or they read unredacted and
    keep the write tools.

    ``delete`` is not in ``NATIVE_WRITE_TOOLS`` (write sessions keep edit tools
    but still withhold it), so a read-only agent must exclude it explicitly.

    ``extra_excluded`` is merged into the single ExcludeTools entry — the
    middleware stack rejects duplicate instances of one class, so callers must
    never append a second ExcludeTools.
    """
    excluded = NATIVE_WRITE_TOOLS | frozenset({DELETE_TOOL_NAME}) | extra_excluded
    return [RedactToolResults(), ExcludeTools(excluded)]


__all__ = [
    "RedactToolResults",
    "read_only_middleware",
]
