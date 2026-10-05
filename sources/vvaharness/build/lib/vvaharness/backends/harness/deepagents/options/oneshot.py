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

"""One-shot (single-turn) graph compilation and its public entry point."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from langgraph.graph.state import CompiledStateGraph

from vvaharness.backends.harness.deepagents.models import (
    ALL_NATIVE_TOOLS,
    SUBAGENT_DISPATCH_TOOL,
    CompiledGraph,
)
from vvaharness.backends.harness.deepagents.options.filesystem import (
    _filesystem_permissions,
    _session_backend,
    _skill_sources,
)
from vvaharness.backends.harness.deepagents.options.graph_builder import _create_agent
from vvaharness.backends.harness.deepagents.options.graph_config import _make_config
from vvaharness.backends.harness.deepagents.options.response_format import (
    _oneshot_response_format,
)
from vvaharness.backends.harness.deepagents.options.subagents import (
    _build_session_tools,
    _tool_policy,
    get_subagent_specs,
)
from vvaharness.backends.harness.deepagents.tools import session_tool_names
from vvaharness.backends.harness.models import (
    LOGICAL_TO_NATIVE,
    OneShotOptions,
    StreamingOptions,
)

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool


def _granted_natives(options: OneShotOptions) -> frozenset[str]:
    """Native tool names the one-shot policy's allowed logicals map to."""
    if options.tool_policy is None:
        return frozenset()
    return frozenset(
        LOGICAL_TO_NATIVE[logical]
        for logical in options.tool_policy.allowed_tools
        if logical in LOGICAL_TO_NATIVE
    )


def _oneshot_excluded_tools(options: OneShotOptions) -> frozenset[str]:
    """Tools withheld from the model's REQUEST on the one-shot (single-turn) path.

    THE TRAP — never reintroduce it: an empty/explicit ``ToolPolicy`` means
    "grant no tools", and sub-agent dispatch (``task``) is a tool, so it must be
    withheld too. ``task`` is NOT in ``ALL_NATIVE_TOOLS``, so withholding every
    native filesystem tool would still leave ``task`` on offer.
    ``SUBAGENT_DISPATCH_TOOL`` is therefore excluded unconditionally, folded into
    the same ExcludeTools entry the redaction stack already applies.

    Native tools come from FilesystemMiddleware, not the policy, so without this
    an empty policy still offered read_file/grep/glob/ls. A ``None`` policy keeps
    that legacy native behavior (only ``task`` is withheld); an explicit policy
    advertises only the natives its allowed logicals map to.

    SCOPE — advertisement only. This set feeds ``ExcludeTools``, which acts at
    ``wrap_model_call``: it removes tools from what the model is TOLD about, but
    the LangGraph tool node keeps every registered tool object, so a forged or
    hallucinated tool_call would still reach the executor. The security
    properties of the one-shot path are enforced by complementary layers, each
    at its own seam:

    * Execution: ``PermitTools`` (``wrap_tool_call``, installed via
      ``permitted_tool_calls`` below) refuses any tool_call outside
      ``_oneshot_permitted_tools`` with a synthetic error ToolMessage — fail
      closed; ``task`` is never permitted here.
    * Write/delete ops: ``READ_ONLY_PERMISSIONS`` deny rules
      (``_filesystem_permissions``) refuse ``write_file``/``edit_file``/
      ``delete`` graph-wide, sub-agents included.
    * Command execution: the session backend is a ``FilesystemBackend``, not a
      sandbox, so ``execute`` has no implementation to dispatch to.
    * Read redaction: the parent carries the read-redaction stack
      (``redact_reads``), and ``_build_oneshot_graph`` supplies its own gated
      ``general-purpose`` sub-agent spec (``get_subagent_specs``) so deepagents
      never auto-adds its UNREDACTED builtin — a dispatched sub-agent's reads
      are masked too.
    """
    task = frozenset({SUBAGENT_DISPATCH_TOOL})
    if options.tool_policy is None:
        return task
    return (ALL_NATIVE_TOOLS - _granted_natives(options)) | task


def _oneshot_permitted_tools(
    options: OneShotOptions, session_tools: list[BaseTool]
) -> frozenset[str]:
    """Tool names the one-shot EXECUTOR may run; everything else is refused.

    The least-privilege counterpart of ``_oneshot_excluded_tools``: fed to
    ``PermitTools`` at the ``wrap_tool_call`` seam, so a tool_call the policy
    never granted is refused instead of executed, whether it names a native, a
    custom tool, ``task``, or something unrecognised (fail closed). The
    detection parser path (``ToolPolicy()``) therefore permits NOTHING beyond
    any caller-built session tools; ``task`` is never permitted on this path.
    A ``None`` policy keeps the legacy contract — every native stays callable —
    but ``task`` execution is still refused, matching its unconditional
    exclusion above.
    """
    custom = session_tool_names(session_tools)
    if options.tool_policy is None:
        return ALL_NATIVE_TOOLS | custom
    return _granted_natives(options) | custom


def _build_oneshot_graph(options: OneShotOptions) -> CompiledStateGraph:
    """Compile a single-turn parser graph."""
    streaming_view = cast(StreamingOptions, options)
    policy = _tool_policy(options)
    tools = _build_session_tools(streaming_view, tuple(policy.allowed_tools))
    # Supply our own gated `general-purpose` spec (redaction-wrapped, read-only)
    # so deepagents does NOT auto-add its ungated, UNREDACTED builtin: an
    # explicit spec of that name displaces the auto-added one. `agents={}`
    # because OneShotOptions is a SessionOptions shape with no personas.
    subagents = get_subagent_specs(streaming_view, agents={})
    return _create_agent(
        model_id=options.model,
        env=options.env,
        system_prompt=options.system_prompt,
        tools=tools,
        name=f"{options.graph_name}-oneshot",
        # `or None`: an empty skill list must become an OMITTED create_deep_agent
        # kwarg, or SkillsMiddleware ships its ~1.9k-char "## Skills System"
        # block (~430 est. tokens, "No skills available yet") on EVERY one-shot
        # detection call. DELIBERATE ASYMMETRY: options/streaming.py keeps
        # passing the list unchanged so S10/S11 prompts stay byte-identical —
        # S10/S11 are frozen; do not "tidy" this into an unconditional fix.
        skills=_skill_sources(options.skill_root, options.cwd) or None,
        permissions=_filesystem_permissions(options),
        model_provider=options.model_provider,
        redact_reads=not options.allow_writes,
        backend=_session_backend(options),
        response_model=options.response_model,
        response_format=_oneshot_response_format(options),
        subagents=subagents,
        extra_excluded_tools=_oneshot_excluded_tools(options),
        # None inherits today's ceiling (64k Anthropic / uncapped OpenAI).
        max_output_tokens=options.max_output_tokens,
        # Executor-seam gate: refuse (fail closed) any tool_call outside this
        # set — un-advertising alone does not stop a forged call.
        permitted_tool_calls=_oneshot_permitted_tools(options, tools),
        cache_markers=options.cache_markers,
        # Single-call requests: a tail write is never read back (+5.0M dead S4 writes).
        cache_tail=False,
        # The model-keyed agentic suffix is dead weight on a tool-less
        # single turn: measured +23.5% output on sonnet-class models (prose
        # preamble breaking the JSON-only contract) and ~530 uncached input
        # tokens per call on every model. Streaming (S10/S11) keeps it.
        strip_harness_suffix=True,
        effort=options.effort,
        use_responses_api=options.use_responses_api,
    )


def build_oneshot_options(options: OneShotOptions) -> CompiledGraph:
    """Return a compiled parser graph and invoke config for a single-turn run."""
    graph = _build_oneshot_graph(options)
    return CompiledGraph(graph=graph, config=_make_config(options, buffer=5))
