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

"""Streaming (multi-turn) graph compilation and its public entry point."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from langgraph.graph.state import CompiledStateGraph

from vvaharness.backends.harness.deepagents.limits import RECURSION_HEADROOM
from vvaharness.backends.harness.deepagents.models import (
    ALL_NATIVE_TOOLS,
    SUBAGENT_DISPATCH_TOOL,
    CompiledGraph,
    SubagentSpec,
)
from vvaharness.backends.harness.deepagents.options.filesystem import (
    _filesystem_permissions,
    _session_backend,
    _skill_sources,
)
from vvaharness.backends.harness.deepagents.options.graph_builder import _create_agent
from vvaharness.backends.harness.deepagents.options.graph_config import _recursion_counter
from vvaharness.backends.harness.deepagents.options.response_format import _response_format
from vvaharness.backends.harness.deepagents.options.subagents import (
    _build_session_tools,
    _tool_policy,
    get_subagent_specs,
)
from vvaharness.backends.harness.deepagents.tools import session_tool_names
from vvaharness.backends.harness.models import READ_TOOLS, StreamingOptions

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool


def build_subagents(options: StreamingOptions) -> list[SubagentSpec]:
    """Return native DeepAgents subagent specs for the streaming parent."""
    return get_subagent_specs(options)


def _permitted_tool_calls(
    options: StreamingOptions, session_tools: list[BaseTool]
) -> frozenset[str] | None:
    """Executor-permitted tool names: the caller's set plus its session tools.

    The streaming counterpart of ``_oneshot_permitted_tools`` — fed to the
    ``PermitTools`` gate via ``_create_agent``, so a tool_call outside the set
    is refused with a synthetic error ToolMessage instead of executing (fail
    closed). The caller-built session tools are unioned in here because only
    this builder sees the constructed tool objects; the caller declares just
    the granted natives. ``None`` — every caller that does not opt in, which
    includes the frozen S10 remediation and S11 validation option builders —
    installs NO gate, keeping those paths byte-identical by construction.
    """
    if options.permitted_tool_calls is None:
        return None
    return options.permitted_tool_calls | session_tool_names(session_tools)


def _extra_excluded_tools(options: StreamingOptions) -> frozenset[str] | None:
    """Advertisement counterpart of the executor gate: un-offer what it refuses.

    The streaming analog of ``_oneshot_excluded_tools``, derived from the SAME
    ``permitted_tool_calls`` field that feeds ``PermitTools`` — never computed
    independently — so the model is offered exactly the natives the executor
    would allow and the two seams cannot drift. ``task`` is not in
    ``ALL_NATIVE_TOOLS`` (SubAgentMiddleware injects it whenever the graph has
    any sub-agent), so ``SUBAGENT_DISPATCH_TOOL`` is folded in by name; the
    gate never permits it on this path. SCOPE — advertisement only: this feeds
    ``ExcludeTools`` (wrap_model_call), a denylist that removes tools from what
    the model is TOLD about; ``PermitTools`` (wrap_tool_call) stays the
    enforcing layer for forged calls. ``None`` — every caller that does not opt
    in, which includes the frozen S10 remediation and S11 validation option
    builders — adds NO exclusion, keeping those advertised sets byte-identical
    by construction (``_create_agent`` treats None as the empty set).
    """
    if options.permitted_tool_calls is None:
        return None
    return (ALL_NATIVE_TOOLS - options.permitted_tool_calls) | frozenset(
        {SUBAGENT_DISPATCH_TOOL}
    )


def _build_streaming_graph(options: StreamingOptions) -> CompiledStateGraph:
    """Compile the parent agent graph and its declarative subagents."""
    subagent_specs = build_subagents(options)
    # The orchestrator only gets read tools; it dispatches subagents via the auto-added task() tool.
    parent_tools = tuple(t for t in _tool_policy(options).allowed_tools if t in READ_TOOLS)
    tools = _build_session_tools(options, parent_tools)
    return _create_agent(
        model_id=options.model,
        env=options.env,
        system_prompt=options.system_prompt,
        tools=tools,
        name=options.graph_name,
        skills=_skill_sources(options.skill_root, options.cwd),
        permissions=_filesystem_permissions(options),
        model_provider=options.model_provider,
        redact_reads=bool(subagent_specs) or not options.allow_writes,
        backend=_session_backend(options),
        response_model=options.response_model,
        response_format=_response_format(
            options.response_model, options.model, options.model_provider
        ),
        subagents=subagent_specs,
        # Advertisement aligned with the executor gate below, derived from the
        # same opt-in field; None (S10/S11 and every other caller that does not
        # opt in) adds no exclusion — see _extra_excluded_tools.
        extra_excluded_tools=_extra_excluded_tools(options),
        # Executor-seam least-privilege gate; None (S10/S11 and every other
        # caller that does not opt in) installs nothing — see _permitted_tool_calls.
        permitted_tool_calls=_permitted_tool_calls(options, tools),
        # Per-turn output cap; None (the frozen S10/S11 defaults) keeps the
        # model's own ceiling — see SessionOptions.max_output_tokens.
        max_output_tokens=options.max_output_tokens,
        cache_markers=options.cache_markers,
        # Agentic sessions re-read the marked tail every turn; keep it on.
        cache_tail=True,
        parent_middleware=options.parent_middleware,
        effort=options.effort,
        use_responses_api=options.use_responses_api,
    )


def build_streaming_agent(options: StreamingOptions) -> CompiledGraph:
    """Return a compiled parent graph and its LangGraph invoke config."""
    graph = _build_streaming_graph(options)
    # Generous headroom: LangGraph ticks the recursion limit per node, not per parallel batch.
    base_limit = (options.max_turns or 50) + RECURSION_HEADROOM
    return CompiledGraph(
        graph=graph,
        config={
            "configurable": {"thread_id": os.urandom(8).hex()},
            "recursion_limit": _recursion_counter.next(base_limit),
        },
    )
