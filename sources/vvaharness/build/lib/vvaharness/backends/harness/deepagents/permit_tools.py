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

"""Middleware that refuses execution of any tool call outside a permitted set.

The executor-seam counterpart of :mod:`exclude_tools`. ``ExcludeTools`` acts at
``wrap_model_call`` and only UN-ADVERTISES tools: the LangGraph tool node keeps
every tool object deepagents registered (natives from ``FilesystemMiddleware``,
``task`` from ``SubAgentMiddleware``), so a forged/hallucinated tool_call the
model was never offered still executes. ``PermitTools`` acts at
``wrap_tool_call`` and FAILS CLOSED: a call whose name is not in the permitted
set is answered with a synthetic ``status="error"`` ToolMessage and is never
handed to the tool node. Only the tool NAME is logged — never arguments or
file content.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import ToolMessage

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from langchain.agents.middleware.types import ToolCallRequest
    from langgraph.types import Command


class PermitTools(AgentMiddleware):
    """Refuse any tool call whose name is not in a fixed permitted set."""

    def __init__(self, permitted: frozenset[str]) -> None:
        """Allow only the tool names in *permitted* to execute; refuse the rest."""
        super().__init__()
        self._permitted = permitted

    def _refusal(self, request: ToolCallRequest) -> ToolMessage | None:
        """A synthetic error ToolMessage when the call is not permitted, else None."""
        tool_call = request.tool_call
        name = tool_call.get("name") or ""
        if name in self._permitted:
            return None
        print(
            f"WARN [deepagents]: refused tool call {name!r} — not in this "
            f"session's permitted tool set; returned an error ToolMessage "
            f"instead of executing",
            file=sys.stderr,
        )
        return ToolMessage(
            content=(
                f"Error: tool {name!r} is not permitted in this session "
                f"and was not executed."
            ),
            name=name,
            tool_call_id=tool_call.get("id") or "",
            status="error",
        )

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        """Execute the call only when permitted; otherwise return the refusal."""
        return self._refusal(request) or handler(request)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        """Async counterpart of :meth:`wrap_tool_call`."""
        return self._refusal(request) or await handler(request)


__all__ = ["PermitTools"]
