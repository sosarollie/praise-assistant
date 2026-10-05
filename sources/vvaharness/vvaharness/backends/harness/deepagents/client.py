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

"""DeepAgents implementation of the validation Harness contract."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Final, cast
from uuid import uuid4

from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph

from vvaharness.backends.harness.deepagents.models import DeepAgentsGraphState
from vvaharness.backends.harness.deepagents.options import (
    build_oneshot_options,
    build_streaming_agent,
)
from vvaharness.backends.harness.deepagents.options.model_building import (
    _CHAT_COMPLETIONS_ONLY_MODELS,
    _NO_REASONING_EFFORT,
    _to_openai_reasoning_effort,
    resolve_use_responses_api,
)
from vvaharness.backends.harness.deepagents.translate import (
    make_terminal_result,
    translate_final_state,
    translate_stream_events,
)
from vvaharness.backends.harness.deepagents.usage import UsageAccumulator
from vvaharness.backends.harness.harness import Harness
from vvaharness.backends.harness.models import (
    HarnessError,
    HarnessMessage,
    HarnessProcessError,
    HarnessSessionInit,
    OneShotOptions,
    OneShotResult,
    SessionOptions,
    StreamingOptions,
)
from vvaharness.util.counters import COUNTERS
from vvaharness.util.warn_once import warn_once

#: 5m-TTL marker shape, matching every other marker this codebase places.
_EPHEMERAL_CACHE_CONTROL: dict[str, str] = {"type": "ephemeral"}

_HTTP_BAD_REQUEST = 400
_HTTP_NOT_FOUND = 404

#: Substrings (lowercased) an endpoint uses to reject a request-shape parameter.
_UNSUPPORTED_PARAM_MARKERS: Final[tuple[str, ...]] = (
    "unsupported parameter",
    "unknown parameter",
)

#: Models that completed at least one call on the Responses API this process.
_RESPONSES_PROVEN_MODELS: set[str] = set()

_EFFORT_UNSUPPORTED_WARNED: set[str] = set()
_TRANSPORT_FALLBACK_WARNED: set[str] = set()

#: Counter surfaced in the manifest's unfiltered counters dump.
_RESPONSES_FALLBACK_COUNTER = "deepagents_responses_fallback"


def _is_reasoning_effort_rejection(exc: Exception) -> bool:
    """Whether *exc* is the gateway rejecting `reasoning_effort` with a 400."""
    status = getattr(exc, "status_code", None)
    return status == _HTTP_BAD_REQUEST and "reasoning_effort" in str(exc).lower()


def _drop_reasoning_effort(model_id: str, effort: str | None) -> None:
    """Remember *model_id* as rejecting this reasoning_effort value, and warn once."""
    mapped = _to_openai_reasoning_effort(effort)
    if mapped is None:
        return
    _NO_REASONING_EFFORT.add((model_id, mapped))
    warn_once(
        _EFFORT_UNSUPPORTED_WARNED,
        f"{model_id}:{mapped}",
        f"WARN [deepagents]: model '{model_id}' rejected reasoning_effort={mapped!r} "
        f"— retrying without it",
    )


def _responses_active(options: SessionOptions) -> bool:
    """Whether this call resolved to the Responses API by DEFAULT, not by config pin."""
    resolved = resolve_use_responses_api(
        options.model, options.model_provider, options.use_responses_api
    )
    return resolved is True and options.use_responses_api is None


def _is_responses_shape_rejection(exc: Exception) -> bool:
    """Whether *exc* is an endpoint rejecting the Responses request shape itself."""
    status = getattr(exc, "status_code", None)
    if status == _HTTP_NOT_FOUND:
        return True
    body = str(exc).lower()
    return status == _HTTP_BAD_REQUEST and any(
        marker in body for marker in _UNSUPPORTED_PARAM_MARKERS
    )


def _should_fall_back(exc: Exception, options: SessionOptions) -> bool:
    """Whether a failed call warrants one retry on Chat Completions.

    Differential: a model with no proven Responses call yet falls back on ANY
    error (its very first call is the capability probe); a proven model falls
    back only on a shape rejection, so a transient 5xx never flips a working
    transport mid-scan.
    """
    if not _responses_active(options):
        return False
    if options.model not in _RESPONSES_PROVEN_MODELS:
        return True
    return _is_responses_shape_rejection(exc)


def _learn_chat_completions_only(model_id: str) -> None:
    """Record *model_id* as Chat-Completions-only, count it, and warn once."""
    _CHAT_COMPLETIONS_ONLY_MODELS.add(model_id)
    COUNTERS.bump(_RESPONSES_FALLBACK_COUNTER)
    warn_once(
        _TRANSPORT_FALLBACK_WARNED,
        model_id,
        f"WARN [deepagents]: model '{model_id}' failed its first Responses API "
        f"call — retrying on Chat Completions",
    )


def _oneshot_content(
    prompt: str, cache_prefix: str | None
) -> str | list[str | dict[str, object]]:
    """User-turn content; a vetted cache_prefix becomes a cache_control-marked leading block."""
    if not cache_prefix:
        return prompt
    # 4th of 4 breakpoints (middleware spends 3: system, tools, tail — all
    # block-level); nothing here may add a 5th.
    blocks: list[str | dict[str, object]] = [
        {"type": "text", "text": cache_prefix,
         "cache_control": dict(_EPHEMERAL_CACHE_CONTROL)},
        {"type": "text", "text": prompt},
    ]
    return blocks


async def _final_state(
    graph: CompiledStateGraph, config: RunnableConfig
) -> DeepAgentsGraphState:
    """Return the graph's terminal state values, or {} if it has no initialised state."""
    try:
        snapshot = await graph.aget_state(config)
    except ValueError:
        return {}
    return cast("DeepAgentsGraphState", getattr(snapshot, "values", None) or {})


class DeepAgentHarness(Harness):
    """Validation harness backed by the DeepAgents / LangGraph runtime."""

    async def run_oneshot(
        self, prompt: str, options: OneShotOptions
    ) -> OneShotResult:
        """Run a single-turn parser-only invocation and return the result."""
        graph, config = build_oneshot_options(options)
        content = _oneshot_content(prompt, options.cache_prefix)
        responses_active = _responses_active(options)
        try:
            state = await graph.ainvoke(
                {"messages": [HumanMessage(content=content)]},
                config=cast(RunnableConfig, config),
            )
        except Exception as exc:
            if _is_reasoning_effort_rejection(exc):
                _drop_reasoning_effort(options.model, options.effort)
                return await self.run_oneshot(prompt, options)
            if not _should_fall_back(exc, options):
                raise
            # Bounded: learning flips the resolved transport, so the re-entry
            # is not responses-active and can never take this branch again.
            _learn_chat_completions_only(options.model)
            try:
                return await self.run_oneshot(prompt, options)
            except Exception:  # noqa: BLE001 — nothing masked: the original re-raises
                # Both transports failed: unlearn (a transient outage must not
                # permanently mislabel the model) and surface the ORIGINAL failure.
                _CHAT_COMPLETIONS_ONLY_MODELS.discard(options.model)
                raise exc from None
        if responses_active:
            _RESPONSES_PROVEN_MODELS.add(options.model)
        return translate_final_state(cast("DeepAgentsGraphState", state), oneshot=True)

    def run_streaming(
        self, prompt: str, options: StreamingOptions
    ) -> AsyncIterator[HarnessMessage]:
        """Return an async iterator of typed messages for a streaming session.

        A transport or reasoning-effort retry re-delegates to a fresh session,
        so consumers may see a second ``HarnessSessionInit`` mid-stream.
        """
        graph, config = build_streaming_agent(options)
        runnable_config = cast(RunnableConfig, config)

        async def _gen() -> AsyncIterator[HarnessMessage]:
            session_id = uuid4().hex
            seen_tool_ids: set[str] = set()
            # Subgraph namespace -> persona name, so subagent steps are tagged.
            ns_to_agent: dict[tuple[str, ...], str] = {}
            # Usage lives on streamed AIMessages, not in graph state; subagent
            # turns are only visible here, so accumulate while streaming.
            usage_acc = UsageAccumulator()
            responses_active = _responses_active(options)
            try:
                yield HarnessSessionInit(session_id=session_id)
                # subgraphs=True surfaces each persona's steps as (namespace, payload) tuples.
                async for event in graph.astream(
                    {"messages": [HumanMessage(content=prompt)]},
                    config=runnable_config,
                    stream_mode="updates",
                    subgraphs=True,
                ):
                    usage_acc.add_event(event)
                    async for message in translate_stream_events(
                        event, seen_tool_ids, ns_to_agent
                    ):
                        yield message
                if responses_active:
                    _RESPONSES_PROVEN_MODELS.add(options.model)
                state = await _final_state(graph, runnable_config)
                yield make_terminal_result(
                    state, session_id=session_id, stream_usage=usage_acc.snapshot()
                )
            except HarnessError:
                raise
            except Exception as error:
                if _is_reasoning_effort_rejection(error):
                    _drop_reasoning_effort(options.model, options.effort)
                    async for message in self.run_streaming(prompt, options):
                        yield message
                    return
                if _should_fall_back(error, options):
                    # Bounded like the one-shot seam: learning flips the resolved
                    # transport, so the re-delegated session cannot re-enter here.
                    _learn_chat_completions_only(options.model)
                    try:
                        async for message in self.run_streaming(prompt, options):
                            yield message
                    except Exception:  # noqa: BLE001 — nothing masked: the original re-raises
                        # Both transports failed: unlearn and surface the ORIGINAL failure.
                        _CHAT_COMPLETIONS_ONLY_MODELS.discard(options.model)
                        raise HarnessProcessError(
                            f"DeepAgents stream failed: {type(error).__name__}",
                            exit_code=1,
                            stderr=str(error),
                        ) from error
                    return
                # On recursion-limit errors, snapshot state so consumers can retry extraction.
                if "GraphRecursionError" in type(error).__name__:
                    state = await _final_state(graph, runnable_config)
                    yield make_terminal_result(
                        state, session_id=session_id, stream_usage=usage_acc.snapshot()
                    )
                raise HarnessProcessError(
                    f"DeepAgents stream failed: {type(error).__name__}",
                    exit_code=1,
                    stderr=str(error),
                ) from error

        return _gen()
