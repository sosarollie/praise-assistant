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

"""Graph-compilation helper shared by the streaming and one-shot graphs."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from deepagents.middleware.filesystem import FilesystemPermission
from deepagents.profiles.harness.harness_profiles import (
    _HARNESS_PROFILES,
    _ensure_harness_profiles_loaded,
)
from langchain.agents.middleware.types import AgentMiddleware
from langchain.agents.structured_output import ToolStrategy
from langchain_core.tools import BaseTool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph.state import CompiledStateGraph

from vvaharness.backends.harness.deepagents.exclude_tools import ExcludeTools
from vvaharness.backends.harness.deepagents.models import DELETE_TOOL_NAME, SubagentSpec
from vvaharness.backends.harness.deepagents.options.model_building import build_model_cached
from vvaharness.backends.harness.deepagents.permit_tools import PermitTools
from vvaharness.backends.harness.deepagents.prompt_caching import BlockMarkerPromptCaching
from vvaharness.backends.harness.deepagents.redaction import read_only_middleware

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator

    from langchain.agents.middleware.types import ModelCallResult, ModelRequest

# Serializes every create_deep_agent call so a suffix-stripped build window
# can never leak into a concurrent streaming (S10/S11) build.
_BUILD_LOCK = threading.Lock()


@contextmanager
def _suffixless_harness_profiles() -> Generator[None]:
    """Blank every harness-profile suffix for the enclosed build; caller holds _BUILD_LOCK."""
    # create_deep_agent has no public opt-out for its model-keyed suffix (0.7.x);
    # only the suffix is blanked, every other profile field is preserved.
    _ensure_harness_profiles_loaded()
    saved = dict(_HARNESS_PROFILES)
    for key, profile in saved.items():
        _HARNESS_PROFILES[key] = replace(profile, system_prompt_suffix="")
    try:
        yield
    finally:
        _HARNESS_PROFILES.clear()
        _HARNESS_PROFILES.update(saved)


class CapOutputTokens(AgentMiddleware):
    """Per-request output-token cap, applied as a ``model_settings`` override.

    ``request.model_settings`` is bound into every model call by langchain's
    agent factory (``request.model.bind(**model_settings)``), and an
    invocation-level ``max_tokens`` overrides the constructor ceiling on both
    vendor branches: ChatAnthropic's ``max_tokens_to_sample`` (64k) and
    ChatOpenAI's provider default (uncapped). The model instance is never
    rebuilt or re-keyed, so ``build_model_cached`` — shared with S10/S11 —
    gains no entries and leaks no clients. Existing ``model_settings`` keys
    are preserved, not replaced wholesale.
    """

    def __init__(self, max_tokens: int) -> None:
        """Cap every model request in this graph at *max_tokens* output tokens."""
        super().__init__()
        self._max_tokens = max_tokens

    def _cap(self, request: ModelRequest) -> ModelRequest:
        return request.override(
            model_settings={**request.model_settings, "max_tokens": self._max_tokens}
        )

    def wrap_model_call(
        self, request: ModelRequest, handler: Callable[[ModelRequest], ModelCallResult]
    ) -> ModelCallResult:
        """Call the model with the output-token cap bound onto the request."""
        return handler(self._cap(request))

    async def awrap_model_call(
        self,
        request: ModelRequest,
        handler: Callable[[ModelRequest], Awaitable[ModelCallResult]],
    ) -> ModelCallResult:
        """Async counterpart of :meth:`wrap_model_call`."""
        return await handler(self._cap(request))


def _create_agent(
    model_id: str,
    env: dict[str, str],
    system_prompt: str | None,
    tools: list[BaseTool],
    *,
    name: str,
    skills: list[str] | None,
    permissions: list[FilesystemPermission],
    model_provider: str | None = None,
    redact_reads: bool = False,
    backend: FilesystemBackend | None = None,
    response_model: type | None = None,
    response_format: ToolStrategy | type | None = None,
    subagents: list[SubagentSpec] | None = None,
    extra_excluded_tools: frozenset[str] | None = None,
    max_output_tokens: int | None = None,
    permitted_tool_calls: frozenset[str] | None = None,
    strip_harness_suffix: bool = False,
    cache_markers: bool = True,
    cache_tail: bool = True,
    parent_middleware: tuple[AgentMiddleware, ...] = (),
    effort: str | None = None,
    use_responses_api: bool | None = None,
) -> CompiledStateGraph:
    """Graph builder shared by the streaming and one-shot graphs."""
    checkpointer: MemorySaver
    if response_model is None:
        checkpointer = MemorySaver()
    else:
        allowed_models = [(response_model.__module__, response_model.__name__)]
        checkpointer = MemorySaver(
            serde=JsonPlusSerializer(allowed_msgpack_modules=allowed_models)
        )
    kwargs: dict[str, Any] = {
        "model": build_model_cached(
            model_id, env, model_provider, effort, use_responses_api
        ),
        "system_prompt": system_prompt,
        "tools": tools,
        "name": name,
        "permissions": permissions,
        "checkpointer": checkpointer,
    }
    # `skills` is omitted (not passed as None/[]) when the caller has none:
    # create_deep_agent attaches SkillsMiddleware whenever `skills is not None`,
    # and that middleware injects its ~1.9k-char "## Skills System" how-to block
    # into the system prompt even with ZERO skills ("No skills available yet").
    # DELIBERATE ASYMMETRY — do not "tidy": only the one-shot path passes None
    # here (options/oneshot.py, `... or None`); options/streaming.py still
    # passes the list unchanged, so S10 (which gets [] and today's dead block)
    # and S11 (which gets a real skill_root) keep exactly today's prompts.
    # S10/S11 are frozen.
    if skills is not None:
        kwargs["skills"] = skills
    # Restore the localtools read-redaction guarantee for agents that don't write.
    # A flat fix agent (no subagents) cannot redact: edit_file needs byte-exact
    # old_string from that same read. An orchestrator with subagents only dispatches
    # and never calls edit_file directly, so masking its reads is safe.
    # Merged into the one ExcludeTools entry: the stack rejects duplicate
    # middleware instances of the same class.
    extra: frozenset[str] = extra_excluded_tools or frozenset()
    middleware: list[AgentMiddleware]
    if redact_reads:
        middleware = [*read_only_middleware(extra), *parent_middleware]
    else:
        middleware = [
            ExcludeTools(frozenset({DELETE_TOOL_NAME}) | extra),
            *parent_middleware,
        ]
    # Per-call output cap; None (the frozen S10/S11 defaults) keeps the
    # model's own ceiling: 64k on Anthropic, uncapped on OpenAI.
    if max_output_tokens is not None:
        middleware.append(CapOutputTokens(max_output_tokens))
    # Executor-seam least-privilege gate: a tool_call whose name is not in
    # *permitted_tool_calls* is refused with a synthetic error ToolMessage
    # instead of executing (ExcludeTools above only un-advertises; the tool
    # node keeps the objects — deepagents 0.7.13 offers no per-call way to
    # remove a middleware-injected tool, so "unreachable" is the guarantee,
    # not "absent").
    #
    # None installs NO gate, and that default is what keeps S10/S11
    # byte-identical: opt-in is per CONSTRUCTION SITE, not per graph shape.
    # The two detection sites pass a set — the one-shot parser (empty: it
    # needs no tools) and `llm.deepagents.agentic` (the granted read natives)
    # — while S10 fix mode (plugin_runner) and S11 validation (session
    # launcher) never set the field. Pinned per-site in
    # tests/test_oneshot_least_privilege.py and
    # tests/test_agentic_detection_permit_gate.py, so a future caller cannot
    # start gating remediation unnoticed.
    if permitted_tool_calls is not None:
        middleware.append(PermitTools(permitted_tool_calls))
    # Shares the auto-attached prompt-caching middleware's name, so deepagents
    # replaces that instance in-place; disabled = requests pass through unmarked.
    middleware.append(
        BlockMarkerPromptCaching(enabled=cache_markers, mark_tail=cache_tail)
    )
    kwargs["middleware"] = middleware
    if response_format is not None:
        kwargs["response_format"] = response_format
    if subagents is not None:
        kwargs["subagents"] = subagents
    if backend is not None:
        kwargs["backend"] = backend
    # Every build takes the lock so the strip window cannot bleed into a
    # concurrent unstripped (streaming, S10/S11) build.
    with _BUILD_LOCK:
        if strip_harness_suffix:
            with _suffixless_harness_profiles():
                return create_deep_agent(**kwargs)
        return create_deep_agent(**kwargs)
