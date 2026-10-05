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

"""OpenAI-branch transport selection on the deepagents route.

Covers the single resolution rule (config override, then the learned
``_CHAT_COMPLETIONS_ONLY_MODELS`` set, then the Responses default; N/A on the
Anthropic route), the Responses constructor trio
(``use_responses_api``/``store``/``include``) on a real ``ChatOpenAI``, and
the cache rule: the transport is resolved BEFORE the
cache key is built, so a learned flip is a cache miss that rebuilds the model
rather than an unbounded retry on the stale instance. The parent graph and
its subagent specs must resolve the same transport — a split would pass a
single-shot probe and fail only on dispatch.

The differential first-call fallback (client.py) is covered at both harness
seams: an unproven model falls back on ANY first-call error, a proven model
only on a Responses shape rejection (404, or 400 naming an unsupported
parameter), a config-pinned model never falls back, and a fallback whose
retry ALSO fails un-learns the model and surfaces the original error. No test
opens a socket — the autouse ``_deny_network`` fixture in conftest.py
enforces that.
"""

from __future__ import annotations

import asyncio
from collections.abc import Generator
from pathlib import Path
from typing import ClassVar, cast

import pytest
from fixtures.deepagents_scaffolding import fake_model
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_openai import ChatOpenAI
from langgraph.graph.state import CompiledStateGraph

from vvaharness.backends.harness.deepagents import client as da_client
from vvaharness.backends.harness.deepagents.models import CompiledGraph
from vvaharness.backends.harness.deepagents.options import (
    graph_builder as _da_graph_builder,
)
from vvaharness.backends.harness.deepagents.options import model_building
from vvaharness.backends.harness.deepagents.options import (
    subagents as _da_subagents,
)
from vvaharness.backends.harness.deepagents.options.model_building import (
    build_model,
    build_model_cached,
    resolve_use_responses_api,
)
from vvaharness.backends.harness.deepagents.options.streaming import (
    build_streaming_agent,
)
from vvaharness.backends.harness.models import (
    HarnessProcessError,
    HarnessSessionInit,
    OneShotOptions,
    StreamingOptions,
    SubagentDefinition,
    ToolPolicy,
)
from vvaharness.util.counters import COUNTERS

_ENV = {"OPENAI_API_KEY": "sk-test"}
_ANTHROPIC_ENV = {"ANTHROPIC_API_KEY": "sk-ant"}

_FALLBACK_COUNTER = da_client._RESPONSES_FALLBACK_COUNTER


@pytest.fixture(autouse=True)
def _clear_learned_transport_state() -> Generator[None]:
    """Reset the learned/proven transport sets and the model cache around each test."""
    for registry in (
        model_building._CHAT_COMPLETIONS_ONLY_MODELS,
        da_client._RESPONSES_PROVEN_MODELS,
        da_client._TRANSPORT_FALLBACK_WARNED,
    ):
        registry.clear()
    model_building._model_cache.clear()
    yield
    for registry in (
        model_building._CHAT_COMPLETIONS_ONLY_MODELS,
        da_client._RESPONSES_PROVEN_MODELS,
        da_client._TRANSPORT_FALLBACK_WARNED,
    ):
        registry.clear()
    model_building._model_cache.clear()


def _as_openai(chat: BaseChatModel) -> ChatOpenAI:
    """Narrow a built model to ChatOpenAI so field assertions typecheck."""
    assert isinstance(chat, ChatOpenAI)
    return chat


# Resolution rule


def test_resolve_defaults_to_responses_on_the_openai_route() -> None:
    """No override, nothing learned: an OpenAI-routed model resolves to Responses."""
    assert resolve_use_responses_api("gpt-5.5", "openai", None) is True


def test_resolve_override_false_pins_chat_completions() -> None:
    """A config ``use_responses_api: false`` wins over the default."""
    assert resolve_use_responses_api("gpt-5.5", "openai", False) is False


def test_resolve_override_true_beats_a_learned_rejection() -> None:
    """A config ``use_responses_api: true`` wins over the learned set, disabling learning."""
    model_building._CHAT_COMPLETIONS_ONLY_MODELS.add("gpt-5.5")
    assert resolve_use_responses_api("gpt-5.5", "openai", True) is True


def test_resolve_learned_model_falls_back_to_chat_completions() -> None:
    """A model in the learned set resolves to Chat Completions without an override."""
    model_building._CHAT_COMPLETIONS_ONLY_MODELS.add("gpt-5.5")
    assert resolve_use_responses_api("gpt-5.5", "openai", None) is False


def test_resolve_is_not_applicable_on_the_anthropic_route() -> None:
    """The Anthropic route has no OpenAI transport: None, whatever the override says."""
    assert resolve_use_responses_api("claude-sonnet-4-6", "anthropic", None) is None
    assert resolve_use_responses_api("claude-sonnet-4-6", None, False) is None


# Constructor fields, on real ChatOpenAI instances


def test_build_model_defaults_to_responses_with_store_off() -> None:
    """The default OpenAI-branch build carries the full Responses trio."""
    chat = _as_openai(build_model("gpt-5.5", _ENV, "openai"))
    assert chat.use_responses_api is True
    assert chat.store is False
    assert chat.include == ["reasoning.encrypted_content"]


def test_build_model_override_false_builds_chat_completions() -> None:
    """A pinned-off model is built on Chat Completions with no Responses extras."""
    chat = _as_openai(build_model("gpt-5.5", _ENV, "openai", use_responses_api=False))
    assert chat.use_responses_api is False
    assert chat.store is None
    assert chat.include is None


def test_build_model_learned_model_builds_chat_completions() -> None:
    """A learned rejection flips the built transport without any config change."""
    model_building._CHAT_COMPLETIONS_ONLY_MODELS.add("gpt-5.5")
    chat = _as_openai(build_model("gpt-5.5", _ENV, "openai"))
    assert chat.use_responses_api is False


def test_build_model_anthropic_route_is_untouched() -> None:
    """The Anthropic branch never sees the transport kwargs."""
    chat = build_model("claude-sonnet-4-6", _ANTHROPIC_ENV, "anthropic",
                       use_responses_api=True)
    assert not hasattr(chat, "use_responses_api")


# Cache rule — resolve BEFORE keying


def test_build_model_cached_misses_after_a_learned_flip() -> None:
    """Learning a rejection must invalidate the cache: same args, new instance."""
    first = _as_openai(build_model_cached("gpt-5.5", _ENV, "openai"))
    assert first.use_responses_api is True
    model_building._CHAT_COMPLETIONS_ONLY_MODELS.add("gpt-5.5")
    second = _as_openai(build_model_cached("gpt-5.5", _ENV, "openai"))
    assert second is not first
    assert second.use_responses_api is False


def test_build_model_cached_keys_on_the_override() -> None:
    """Two override values must not share a cached model instance."""
    on = _as_openai(build_model_cached("gpt-5.5", _ENV, "openai", None, True))
    off = _as_openai(build_model_cached("gpt-5.5", _ENV, "openai", None, False))
    assert on is not off
    assert on.use_responses_api is True
    assert off.use_responses_api is False


def test_build_model_cached_hits_when_the_resolution_is_stable() -> None:
    """Unchanged inputs keep sharing one instance — the cache still caches."""
    first = build_model_cached("gpt-5.5", _ENV, "openai")
    second = build_model_cached("gpt-5.5", _ENV, "openai")
    assert first is second


# Parent/subagent agreement


def test_parent_and_subagent_graphs_resolve_the_same_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Every model resolution in one streaming build sees the same override.

    The parent graph, the persona subagents and the general-purpose shadow all
    resolve through ``build_model_cached``; a site that dropped the override
    would silently run a different transport than the rest of the session.
    """
    seen: list[bool | None] = []
    stub = fake_model([])

    def recording(
        _model_id: str,
        _env: dict[str, str],
        _provider: str | None = None,
        _effort: str | None = None,
        use_responses_api: bool | None = None,
    ) -> BaseChatModel:
        seen.append(use_responses_api)
        return stub

    monkeypatch.setattr(_da_graph_builder, "build_model_cached", recording)
    monkeypatch.setattr(_da_subagents, "build_model_cached", recording)
    options = StreamingOptions(
        model="gpt-5.5",
        model_provider="openai",
        use_responses_api=False,
        cwd=tmp_path,
        env=dict(_ENV),
        tool_policy=ToolPolicy(),
        agents={
            "reviewer": SubagentDefinition(
                name="reviewer", description="reviews", prompt="review"
            ),
        },
    )
    build_streaming_agent(options)
    assert len(seen) >= 3  # parent + persona + general-purpose shadow
    assert set(seen) == {False}


# Differential first-call fallback — stubbed harness seams


class _GenericFailureError(Exception):
    """A first-call failure with no status_code: any error fells an unproven model."""


class _StatusFailureError(Exception):
    """A provider-shaped failure carrying an HTTP status code."""

    def __init__(self, message: str, status_code: int) -> None:
        """Carry the message and an OpenAI-SDK-shaped status_code."""
        super().__init__(message)
        self.status_code = status_code


class _ScriptedOneshotGraph:
    """Fake CompiledStateGraph raising scripted errors, then succeeding."""

    def __init__(self, errors: list[Exception]) -> None:
        """Raise each of *errors* in order; succeed afterwards."""
        self.errors = list(errors)
        self.calls = 0

    async def ainvoke(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        """Replay the scripted failure, or an empty terminal state."""
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return {"messages": []}


def _openai_oneshot_options(
    tmp_path: Path, use_responses_api: bool | None = None
) -> OneShotOptions:
    return OneShotOptions(
        model="gpt-5.5",
        model_provider="openai",
        use_responses_api=use_responses_api,
        cwd=tmp_path,
        env=dict(_ENV),
    )


def _patch_oneshot(
    monkeypatch: pytest.MonkeyPatch, graph: _ScriptedOneshotGraph
) -> None:
    compiled = CompiledGraph(
        graph=cast("CompiledStateGraph", graph),
        config={"configurable": {"thread_id": "t"}},
    )
    monkeypatch.setattr(da_client, "build_oneshot_options", lambda _options: compiled)


def test_oneshot_unproven_model_falls_back_on_any_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unproven model's first-call failure learns, warns once, and retries."""
    graph = _ScriptedOneshotGraph([_GenericFailureError("boom")])
    _patch_oneshot(monkeypatch, graph)
    harness = da_client.DeepAgentHarness()

    result = asyncio.run(harness.run_oneshot("hi", _openai_oneshot_options(tmp_path)))
    assert graph.calls == 2
    assert not result.is_error
    assert "gpt-5.5" in model_building._CHAT_COMPLETIONS_ONLY_MODELS
    assert COUNTERS.get(_FALLBACK_COUNTER) == 1
    assert capsys.readouterr().err.count("Responses API") == 1


def test_oneshot_both_transports_failing_raises_the_original_and_unlearns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When the Chat Completions retry also fails, the ORIGINAL error surfaces."""
    original = _GenericFailureError("responses outage")
    graph = _ScriptedOneshotGraph([original, _GenericFailureError("retry outage")])
    _patch_oneshot(monkeypatch, graph)
    harness = da_client.DeepAgentHarness()

    with pytest.raises(_GenericFailureError) as excinfo:
        asyncio.run(harness.run_oneshot("hi", _openai_oneshot_options(tmp_path)))
    assert excinfo.value is original
    assert graph.calls == 2
    assert "gpt-5.5" not in model_building._CHAT_COMPLETIONS_ONLY_MODELS


def test_oneshot_proven_model_does_not_retry_a_transient_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A proven Responses model keeps its transport through a 500."""
    da_client._RESPONSES_PROVEN_MODELS.add("gpt-5.5")
    graph = _ScriptedOneshotGraph([_StatusFailureError("upstream error", 500)])
    _patch_oneshot(monkeypatch, graph)
    harness = da_client.DeepAgentHarness()

    with pytest.raises(_StatusFailureError):
        asyncio.run(harness.run_oneshot("hi", _openai_oneshot_options(tmp_path)))
    assert graph.calls == 1
    assert "gpt-5.5" not in model_building._CHAT_COMPLETIONS_ONLY_MODELS


@pytest.mark.parametrize(
    "error",
    [
        _StatusFailureError("not found", 404),
        _StatusFailureError("Unsupported parameter: 'store'", 400),
        _StatusFailureError("Unknown parameter: 'include'", 400),
    ],
)
def test_oneshot_proven_model_falls_back_on_a_shape_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: Exception
) -> None:
    """Even a proven model falls back when the endpoint rejects the request shape."""
    da_client._RESPONSES_PROVEN_MODELS.add("gpt-5.5")
    graph = _ScriptedOneshotGraph([error])
    _patch_oneshot(monkeypatch, graph)
    harness = da_client.DeepAgentHarness()

    result = asyncio.run(harness.run_oneshot("hi", _openai_oneshot_options(tmp_path)))
    assert graph.calls == 2
    assert not result.is_error
    assert "gpt-5.5" in model_building._CHAT_COMPLETIONS_ONLY_MODELS


@pytest.mark.parametrize("pin", [True, False])
def test_oneshot_config_pinned_transport_never_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pin: bool
) -> None:
    """A config-pinned model propagates its failure; the operator chose the transport."""
    graph = _ScriptedOneshotGraph([_GenericFailureError("boom")])
    _patch_oneshot(monkeypatch, graph)
    harness = da_client.DeepAgentHarness()

    with pytest.raises(_GenericFailureError):
        asyncio.run(
            harness.run_oneshot("hi", _openai_oneshot_options(tmp_path, pin))
        )
    assert graph.calls == 1
    assert "gpt-5.5" not in model_building._CHAT_COMPLETIONS_ONLY_MODELS
    assert COUNTERS.get(_FALLBACK_COUNTER) == 0


def test_oneshot_success_marks_the_model_proven(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A completed Responses call promotes the model out of any-error fallback."""
    graph = _ScriptedOneshotGraph([])
    _patch_oneshot(monkeypatch, graph)
    harness = da_client.DeepAgentHarness()

    asyncio.run(harness.run_oneshot("hi", _openai_oneshot_options(tmp_path)))
    assert "gpt-5.5" in da_client._RESPONSES_PROVEN_MODELS


class _ScriptedStreamingGraph:
    """Fake CompiledStateGraph whose astream raises scripted errors, then completes."""

    def __init__(self, errors: list[Exception]) -> None:
        """Raise each of *errors* in order; complete with no events afterwards."""
        self.errors = list(errors)
        self.calls = 0

    async def astream(self, *_args: object, **_kwargs: object):
        """Replay the scripted failure before yielding, or complete empty."""
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
            yield  # pragma: no cover — makes this an async generator
        return
        yield  # pragma: no cover

    async def aget_state(self, *_args: object, **_kwargs: object) -> object:
        """Report no initialised state, matching a fresh checkpoint."""
        raise ValueError("no state")


def _openai_streaming_options(
    tmp_path: Path, use_responses_api: bool | None = None
) -> StreamingOptions:
    return StreamingOptions(
        model="gpt-5.5",
        model_provider="openai",
        use_responses_api=use_responses_api,
        cwd=tmp_path,
        env=dict(_ENV),
    )


def _drain_streaming(
    monkeypatch: pytest.MonkeyPatch,
    graph: _ScriptedStreamingGraph,
    options: StreamingOptions,
) -> list[object]:
    compiled = CompiledGraph(
        graph=cast("CompiledStateGraph", graph),
        config={"configurable": {"thread_id": "t"}},
    )
    monkeypatch.setattr(da_client, "build_streaming_agent", lambda _opts: compiled)
    harness = da_client.DeepAgentHarness()

    async def _drain() -> list[object]:
        return [msg async for msg in harness.run_streaming("hi", options)]

    return asyncio.run(_drain())


def test_streaming_unproven_model_falls_back_on_any_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The streaming seam learns and re-delegates; consumers see a second init."""
    graph = _ScriptedStreamingGraph([_GenericFailureError("boom")])
    messages = _drain_streaming(
        monkeypatch, graph, _openai_streaming_options(tmp_path)
    )
    assert graph.calls == 2
    assert "gpt-5.5" in model_building._CHAT_COMPLETIONS_ONLY_MODELS
    assert COUNTERS.get(_FALLBACK_COUNTER) == 1
    inits = [m for m in messages if isinstance(m, HarnessSessionInit)]
    assert len(inits) == 2


def test_streaming_both_transports_failing_raises_the_original_and_unlearns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failed retry surfaces the original failure in the wrapped process error."""
    graph = _ScriptedStreamingGraph(
        [_GenericFailureError("responses outage"), _GenericFailureError("retry outage")]
    )
    with pytest.raises(HarnessProcessError) as excinfo:
        _drain_streaming(monkeypatch, graph, _openai_streaming_options(tmp_path))
    assert graph.calls == 2
    assert "responses outage" in (excinfo.value.stderr or "")
    assert "gpt-5.5" not in model_building._CHAT_COMPLETIONS_ONLY_MODELS


def test_streaming_config_pinned_transport_never_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A pinned streaming session propagates its failure without learning."""
    graph = _ScriptedStreamingGraph([_GenericFailureError("boom")])
    with pytest.raises(HarnessProcessError):
        _drain_streaming(
            monkeypatch, graph, _openai_streaming_options(tmp_path, False)
        )
    assert graph.calls == 1
    assert "gpt-5.5" not in model_building._CHAT_COMPLETIONS_ONLY_MODELS


def test_streaming_success_marks_the_model_proven(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A completed streaming session promotes the model out of any-error fallback."""
    graph = _ScriptedStreamingGraph([])
    _drain_streaming(monkeypatch, graph, _openai_streaming_options(tmp_path))
    assert "gpt-5.5" in da_client._RESPONSES_PROVEN_MODELS


# Non-stubbed regression — the retry must reach the real cache, not a graph stub


class _TransportProbeChatOpenAI(ChatOpenAI):
    """Real ChatOpenAI whose generation fails only on the Responses transport."""

    constructions: ClassVar[list[bool | None]] = []

    def __init__(self, **kwargs: object) -> None:
        """Construct normally and record the transport this instance carries."""
        super().__init__(**kwargs)  # type: ignore[arg-type]
        type(self).constructions.append(self.use_responses_api)

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: object = None,
        **kwargs: object,
    ) -> ChatResult:
        """Fail on the Responses transport; answer plainly on Chat Completions."""
        del messages, stop, run_manager, kwargs
        if self.use_responses_api:
            raise _StatusFailureError("Unsupported parameter: 'store'", 400)
        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content="ok"))]
        )


def test_first_call_fallback_rebuilds_through_the_real_model_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The retry must construct a SECOND model on the flipped transport.

    Runs the real option builders and ``build_model_cached`` — no graph stubs —
    so a cache that keys on the raw override instead of the resolved transport
    would serve the stale Responses instance
    back to the retry and fail this test by looping on the same error.
    """
    _TransportProbeChatOpenAI.constructions.clear()
    monkeypatch.setattr(model_building, "ChatOpenAI", _TransportProbeChatOpenAI)
    harness = da_client.DeepAgentHarness()

    options = OneShotOptions(
        model="gpt-5.5",
        model_provider="openai",
        cwd=tmp_path,
        env=dict(_ENV),
        tool_policy=ToolPolicy(),
    )
    result = asyncio.run(harness.run_oneshot("hi", options))
    assert not result.is_error
    assert _TransportProbeChatOpenAI.constructions == [True, False]
    assert "gpt-5.5" in model_building._CHAT_COMPLETIONS_ONLY_MODELS
