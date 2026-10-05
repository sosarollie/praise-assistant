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

"""Middleware that withholds a fixed set of tools from every model request."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langchain.agents.middleware.types import AgentMiddleware

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from langchain.agents.middleware.types import ModelCallResult, ModelRequest
    from langchain_core.tools import BaseTool


def _tool_name(tool: BaseTool | dict[str, Any]) -> str | None:
    """Name of a BaseTool or dict-shaped tool spec."""
    name = tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)
    return name if isinstance(name, str) else None


class ExcludeTools(AgentMiddleware):
    """Withhold named tools from the model's request."""

    def __init__(self, excluded: frozenset[str]) -> None:
        """Withhold the tools named in *excluded* from every model request."""
        super().__init__()
        self._excluded = excluded

    def _filter(self, request: ModelRequest) -> ModelRequest:
        kept = [tool for tool in request.tools if _tool_name(tool) not in self._excluded]
        return request.override(tools=kept) if len(kept) != len(request.tools) else request

    def wrap_model_call(
        self, request: ModelRequest, handler: Callable[[ModelRequest], ModelCallResult]
    ) -> ModelCallResult:
        """Call the model with the excluded tools removed from the request."""
        return handler(self._filter(request))

    async def awrap_model_call(
        self,
        request: ModelRequest,
        handler: Callable[[ModelRequest], Awaitable[ModelCallResult]],
    ) -> ModelCallResult:
        """Async counterpart of :meth:`wrap_model_call`."""
        return await handler(self._filter(request))


__all__ = ["ExcludeTools"]
