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

"""Subagent tool resolution and native DeepAgents subagent spec construction."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from deepagents.middleware.subagents import (
    DEFAULT_GENERAL_PURPOSE_DESCRIPTION,
    DEFAULT_SUBAGENT_PROMPT,
)
from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.tools import BaseTool

from vvaharness.backends.harness.deepagents.exclude_tools import ExcludeTools
from vvaharness.backends.harness.deepagents.models import DELETE_TOOL_NAME, SubagentSpec
from vvaharness.backends.harness.deepagents.options.model_building import build_model_cached
from vvaharness.backends.harness.deepagents.options.response_format import _strategy_for
from vvaharness.backends.harness.deepagents.permit_tools import PermitTools
from vvaharness.backends.harness.deepagents.prompt_caching import BlockMarkerPromptCaching
from vvaharness.backends.harness.deepagents.redaction import read_only_middleware
from vvaharness.backends.harness.deepagents.tools import build_tools
from vvaharness.backends.harness.models import (
    LEGACY_AGENT_TOOL,
    MUTATING_TOOLS,
    READ_TOOLS,
    OneShotOptions,
    StreamingOptions,
    SubagentDefinition,
    ToolPolicy,
)

# DeepAgents auto-adds a builtin subagent under this name with the parent's
# full toolset and none of this package's gate middleware; supplying our own
# spec under the same name suppresses it (deepagents graph.py).
GENERAL_PURPOSE_NAME = "general-purpose"


def _tool_policy(options: OneShotOptions | StreamingOptions) -> ToolPolicy:
    """Return the effective tool policy, falling back to an empty policy."""
    return options.tool_policy if options.tool_policy is not None else ToolPolicy()


def _build_session_tools(
    options: StreamingOptions, allowed_tools: tuple[str, ...]
) -> list[BaseTool]:
    """Build tools via the caller's injected ``tool_builder`` or the generic readers."""
    builder = options.tool_builder or build_tools
    return builder(options, allowed_tools=allowed_tools)


def _subagent_tools(subagent: SubagentDefinition, options: StreamingOptions) -> tuple[str, ...]:
    """Return the tool allow-list for a subagent, filtered by denied tools."""
    policy = _tool_policy(options)
    allowed = subagent.tools if subagent.tools is not None else policy.allowed_tools
    denied = set(subagent.disallowed_tools or policy.disallowed_tools)
    if not options.allow_writes:
        denied |= MUTATING_TOOLS
    return tuple(t for t in allowed if t not in denied)


def _subagent_tool_names(
    subagent: SubagentDefinition, options: StreamingOptions
) -> tuple[str, ...]:
    """Resolve a subagent's tool names: allow-list plus fact tools, minus denied tools."""
    granted = tuple(dict.fromkeys([*_subagent_tools(subagent, options), *options.fact_tools]))
    excluded = {LEGACY_AGENT_TOOL}
    if not options.allow_writes:
        excluded |= MUTATING_TOOLS
    return tuple(t for t in granted if t not in excluded)


def _general_purpose_agent(options: StreamingOptions) -> SubagentDefinition:
    """Shadow the builtin general-purpose subagent with a gated equivalent.

    The builtin dispatches with the parent's full toolset, no read redaction,
    and the delete tool. The shadow keeps the builtin's advertised role but is
    read-only even in write sessions; only an explicitly configured writer
    subagent holds write tools.
    """
    read_tools = tuple(t for t in _tool_policy(options).allowed_tools if t in READ_TOOLS)
    return SubagentDefinition(
        name=GENERAL_PURPOSE_NAME,
        description=DEFAULT_GENERAL_PURPOSE_DESCRIPTION,
        prompt=DEFAULT_SUBAGENT_PROMPT,
        tools=read_tools,
    )


def _spec_middleware(tool_names: Sequence[str], options: object) -> list[AgentMiddleware]:
    """Middleware for one sub-agent spec: redaction/exclusion plus the executor gate.

    Redaction is narrowed to sub-agents that actually hold write tools. The gate
    used to be the session-level allow_writes flag, which silently lifted
    redaction from EVERY sub-agent in fix mode; analyzer/planner sub-agents that
    only read do not need byte-exact content for edit_file and must have their
    reads masked regardless of session mode.

    `PermitTools` extends the executor-seam gate to the sub-agent tier.
    `ExcludeTools` only un-advertises, which fails open against a forged or
    hallucinated tool call, so without this the fail-closed guarantee stopped at
    the parent graph and a call inside a dispatched sub-agent met no executor
    check. Unreachable today — `task` is never permitted on either gated
    detection path, so no sub-agent can be dispatched — but the layer must not
    depend on that staying true.

    Gated by the SAME per-construction-site opt-in as the parent graph: `None`
    installs nothing, which is what keeps S10 fix mode and S11 validation inert.
    The permitted set is this sub-agent's OWN tools, so the gate can never widen
    what the spec already grants. `getattr` because the one-shot path passes a
    SessionOptions shape that need not carry the field at all.
    """
    middleware: list[AgentMiddleware]
    if set(tool_names) & MUTATING_TOOLS:
        middleware = [ExcludeTools(frozenset({DELETE_TOOL_NAME}))]
    else:
        middleware = read_only_middleware()
    if getattr(options, "permitted_tool_calls", None) is not None:
        middleware.append(PermitTools(frozenset(tool_names)))
    # Per-spec middleware is merged into each sub-agent's own stack, so every
    # persona (and the general-purpose shadow) gets the block-marker replacement.
    middleware.append(
        BlockMarkerPromptCaching(enabled=bool(getattr(options, "cache_markers", True)))
    )
    return middleware


def get_subagent_specs(
    options: StreamingOptions,
    *,
    agents: Mapping[str, SubagentDefinition] | None = None,
) -> list[SubagentSpec]:
    """Build native DeepAgents subagent specs, one per configured persona.

    Always includes a ``general-purpose`` spec so the builtin never dispatches
    ungated (a caller-supplied definition of that name wins). *agents* overrides
    ``options.agents`` as the configured-persona source; the one-shot path — a
    ``SessionOptions`` shape with no ``agents`` field — passes ``{}`` to get
    exactly the gated ``general-purpose`` shadow and nothing else.
    """
    configured: dict[str, SubagentDefinition] = dict(
        options.agents if agents is None else agents
    )
    configured.setdefault(GENERAL_PURPOSE_NAME, _general_purpose_agent(options))
    specs: list[SubagentSpec] = []
    for name, subagent in configured.items():
        tool_names = _subagent_tool_names(subagent, options)
        tools = _build_session_tools(options, tool_names)
        # Resolve to configured Chat* instances; bare strings would bypass transport resolution.
        subagent_model_id = subagent.model or options.model
        subagent_model = build_model_cached(
            subagent_model_id,
            options.env,
            options.model_provider,
            use_responses_api=options.use_responses_api,
        )
        spec: SubagentSpec = {
            "name": name,
            "description": subagent.description,
            "system_prompt": subagent.prompt,
            "model": subagent_model,
            "tools": tools,
        }
        spec["middleware"] = _spec_middleware(tool_names, options)
        if subagent.response_model is not None:
            spec["response_format"] = _strategy_for(
                subagent.response_model, subagent_model_id, options.model_provider
            )
        specs.append(spec)
    return specs
