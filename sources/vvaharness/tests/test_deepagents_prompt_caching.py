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

"""Tests for the harness block-marker prompt-caching middleware.

``BlockMarkerPromptCaching`` must (1) place a block-level marker on the
conversation tail, (2) never emit the top-level ``cache_control`` param the
gateway drops, and (3) leave persistent message history unmutated so markers
cannot accumulate across turns.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Coroutine
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from deepagents.graph import _apply_custom_middleware
from langchain.agents.middleware.types import ModelRequest, ModelResponse
from langchain_anthropic import ChatAnthropic
from langchain_anthropic.middleware.prompt_caching import (
    AnthropicPromptCachingMiddleware,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    AnyMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.tools import BaseTool, tool

import vvaharness.backends.harness.deepagents.options.graph_builder as _da_graph_builder
import vvaharness.backends.llm.deepagents as deep
from fixtures.deepagents_scaffolding import (
    HEALTHY_TEXT,
    fake_model,
    oneshot_options,
    patch_models,
)
from vvaharness.backends.harness.deepagents.options import build_oneshot_options
from vvaharness.backends.harness.deepagents.options.streaming import _build_streaming_graph
from vvaharness.backends.harness.deepagents.options.subagents import get_subagent_specs
from vvaharness.backends.harness.deepagents.prompt_caching import (
    BlockMarkerPromptCaching,
)
from vvaharness.backends.harness.models import (
    HarnessResult,
    OneShotOptions,
    OneShotResult,
    StreamingOptions,
    SubagentDefinition,
)
from vvaharness.remediation_agent import plugin_runner
from vvaharness.validation.cli._model import _apply_model_env
from vvaharness.validation.config import load_config
from vvaharness.validation.models import Manifest
from vvaharness.validation.session.launcher import build_validation_options

MODEL_ID = "claude-sonnet-4-6"

EXPECTED_CACHE_CONTROL = {"type": "ephemeral", "ttl": "5m"}


@tool
def _probe_tool(path: str) -> str:
    """Read a file for the caching tests."""
    return path


def _chat_model() -> ChatAnthropic:
    """Offline ChatAnthropic; construction and payload building hit no network."""
    return ChatAnthropic(
        model_name=MODEL_ID,
        api_key="test",  # type: ignore[arg-type]
        timeout=5,
        stop=None,
    )


def _request(
    messages: list[AnyMessage],
    *,
    system: str | None = "You are a scanner.",
    with_tools: bool = True,
    model: BaseChatModel | None = None,
) -> ModelRequest:
    """A ModelRequest shaped like the agent factory hands to middleware."""
    return ModelRequest(
        model=model if model is not None else _chat_model(),
        messages=messages,
        system_message=SystemMessage(content=system) if system is not None else None,
        tools=[_probe_tool] if with_tools else [],
    )


def _apply(
    request: ModelRequest, *, enabled: bool = True, mark_tail: bool = True
) -> ModelRequest:
    """Run the middleware's wrap_model_call and capture the request it forwards."""
    middleware = BlockMarkerPromptCaching(enabled=enabled, mark_tail=mark_tail)
    captured: list[ModelRequest] = []

    def _handler(inner: ModelRequest) -> ModelResponse:
        captured.append(inner)
        return ModelResponse(result=[AIMessage(content="ok")])

    middleware.wrap_model_call(request, _handler)
    assert len(captured) == 1
    return captured[0]


def _payload(request: ModelRequest) -> dict[str, object]:
    """Serialize a middleware-shaped request through the real ChatAnthropic."""
    messages: list[BaseMessage] = []
    if request.system_message is not None:
        messages.append(request.system_message)
    messages.extend(request.messages)
    chat = request.model
    assert isinstance(chat, ChatAnthropic)
    return chat._get_request_payload(messages, **request.model_settings)


def _marker_count(payload: object) -> int:
    return json.dumps(payload).count('"cache_control"')


def _wire_messages(payload: dict[str, object]) -> list[dict[str, object]]:
    messages = payload["messages"]
    assert isinstance(messages, list)
    return messages


# ── (b) tail marker ──────────────────────────────────────────────────────────


class TestTailMarker:
    def test_str_tail_promoted_to_marked_text_block(self) -> None:
        request = _request([HumanMessage(content="scan this repo")])
        out = _apply(request)
        tail = out.messages[-1]
        assert tail.content == [
            {
                "type": "text",
                "text": "scan this repo",
                "cache_control": EXPECTED_CACHE_CONTROL,
            }
        ]

    def test_block_list_tail_tags_last_block_only(self) -> None:
        original_blocks: list[str | dict[str, object]] = [
            {"type": "text", "text": "first"},
            {"type": "text", "text": "second"},
        ]
        request = _request([HumanMessage(content=original_blocks)])
        out = _apply(request)
        tail_content = out.messages[-1].content
        assert isinstance(tail_content, list)
        assert tail_content[0] == {"type": "text", "text": "first"}
        assert tail_content[1] == {
            "type": "text",
            "text": "second",
            "cache_control": EXPECTED_CACHE_CONTROL,
        }

    def test_original_messages_never_mutated(self) -> None:
        blocks: list[str | dict[str, object]] = [{"type": "text", "text": "keep me clean"}]
        message = HumanMessage(content=blocks)
        request = _request([message])
        _apply(request)
        assert message.content == [{"type": "text", "text": "keep me clean"}]
        assert blocks == [{"type": "text", "text": "keep me clean"}]

    def test_earlier_messages_untouched_and_shared(self) -> None:
        first = HumanMessage(content="turn one")
        second = AIMessage(content="reply one")
        third = HumanMessage(content="turn two")
        request = _request([first, second, third])
        out = _apply(request)
        assert out.messages[0] is first
        assert out.messages[1] is second
        assert out.messages[2] is not third

    def test_tool_message_str_tail_hoisted_onto_tool_result_block(self) -> None:
        messages: list[AnyMessage] = [
            HumanMessage(content="scan"),
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "_probe_tool", "args": {"path": "a"}, "id": "t1", "type": "tool_call"}
                ],
            ),
            ToolMessage(content="file contents here", tool_call_id="t1"),
        ]
        out = _apply(_request(messages))
        wire_tail = _wire_messages(_payload(out))[-1]
        assert wire_tail["role"] == "user"
        content = wire_tail["content"]
        assert isinstance(content, list)
        result_block = content[-1]
        assert result_block["type"] == "tool_result"
        assert result_block["cache_control"] == EXPECTED_CACHE_CONTROL

    def test_tool_message_block_list_tail_hoisted_onto_tool_result_block(self) -> None:
        messages: list[AnyMessage] = [
            HumanMessage(content="scan"),
            AIMessage(
                content="",
                tool_calls=[
                    {"name": "_probe_tool", "args": {"path": "a"}, "id": "t1", "type": "tool_call"}
                ],
            ),
            ToolMessage(
                content=[
                    {"type": "text", "text": "chunk one"},
                    {"type": "text", "text": "chunk two"},
                ],
                tool_call_id="t1",
            ),
        ]
        out = _apply(_request(messages))
        wire_tail = _wire_messages(_payload(out))[-1]
        content = wire_tail["content"]
        assert isinstance(content, list)
        result_block = content[-1]
        assert result_block["type"] == "tool_result"
        assert result_block["cache_control"] == EXPECTED_CACHE_CONTROL

    def test_no_marker_accumulation_across_turns(self) -> None:
        # Turn-2 requests are rebuilt from state, which holds unmarked originals.
        turn_one: list[AnyMessage] = [HumanMessage(content="turn one")]
        out_one = _apply(_request(turn_one, with_tools=False))
        assert _marker_count(_payload(out_one)) == 2  # system + tail

        turn_two: list[AnyMessage] = [
            *turn_one,
            AIMessage(content="reply"),
            HumanMessage(content="turn two"),
        ]
        out_two = _apply(_request(turn_two, with_tools=False))
        payload_two = _payload(out_two)
        assert _marker_count(payload_two) == 2  # system + tail, none inherited
        assert _marker_count(_wire_messages(payload_two)[:-1]) == 0

    def test_ineligible_thinking_tail_left_unmarked(self) -> None:
        thinking_only: list[str | dict[str, object]] = [
            {"type": "thinking", "thinking": "hidden", "signature": "sig"}
        ]
        request = _request([HumanMessage(content="q"), AIMessage(content=thinking_only)])
        out = _apply(request)
        assert out.messages is request.messages

    def test_empty_messages_handled(self) -> None:
        request = _request([])
        out = _apply(request)
        assert out.messages is request.messages

    def test_mixed_tail_skips_ineligible_then_tags_prior_block(self) -> None:
        blocks: list[str | dict[str, object]] = [
            {"type": "text", "text": "visible"},
            {"type": "redacted_thinking", "data": "opaque"},
        ]
        request = _request([AIMessage(content=blocks)])
        out = _apply(request)
        tail_content = out.messages[-1].content
        assert isinstance(tail_content, list)
        assert tail_content[0] == {
            "type": "text",
            "text": "visible",
            "cache_control": EXPECTED_CACHE_CONTROL,
        }
        assert tail_content[1] == {"type": "redacted_thinking", "data": "opaque"}


# ── (c) passthrough absent ───────────────────────────────────────────────────


class TestPassthroughAbsent:
    def test_no_model_settings_cache_control(self) -> None:
        out = _apply(_request([HumanMessage(content="scan")]))
        assert "cache_control" not in out.model_settings

    def test_no_top_level_cache_control_in_payload(self) -> None:
        out = _apply(_request([HumanMessage(content="scan")]))
        payload = _payload(out)
        assert "cache_control" not in payload

    def test_stock_middleware_emits_the_shape_we_removed(self) -> None:
        # If an upgrade stops the parent shipping the top-level param, revisit the subclass.
        request = _request([HumanMessage(content="scan")])
        stock = AnthropicPromptCachingMiddleware(
            ttl="5m", unsupported_model_behavior="ignore"
        )
        captured: list[ModelRequest] = []

        def _handler(inner: ModelRequest) -> ModelResponse:
            captured.append(inner)
            return ModelResponse(result=[AIMessage(content="ok")])

        stock.wrap_model_call(request, _handler)
        assert captured[0].model_settings.get("cache_control") == EXPECTED_CACHE_CONTROL
        assert "cache_control" in _payload(captured[0])

    def test_system_and_tools_markers_still_placed(self) -> None:
        out = _apply(_request([HumanMessage(content="scan")]))
        system = out.system_message
        assert system is not None
        assert isinstance(system.content, list)
        last_block = system.content[-1]
        assert isinstance(last_block, dict)
        assert last_block["cache_control"] == EXPECTED_CACHE_CONTROL
        last_tool = out.tools[-1]
        assert isinstance(last_tool, BaseTool)
        assert (last_tool.extras or {}).get("cache_control") == EXPECTED_CACHE_CONTROL

    def test_disabled_is_identity(self) -> None:
        request = _request([HumanMessage(content="scan")])
        out = _apply(request, enabled=False)
        assert out is request

    def test_non_anthropic_model_passes_through(self) -> None:
        request = _request(
            [HumanMessage(content="scan")],
            model=fake_model([AIMessage(content="ok")]),
        )
        out = _apply(request)
        assert out is request


# ── (a) replacement of the auto-attached instance ────────────────────────────


def _streaming_options(cwd: Path, **overrides: object) -> StreamingOptions:
    options = StreamingOptions(model="claude-test", cwd=cwd, env={})
    for key, value in overrides.items():
        setattr(options, key, value)
    return options


def _capture_create_agent_kwargs(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    captured: dict[str, object] = {}
    real = cast("Callable[..., object]", _da_graph_builder.create_deep_agent)

    def _capture(**kwargs: object) -> object:
        captured.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(_da_graph_builder, "create_deep_agent", _capture)
    return captured


def _our_instances(middleware: object) -> list[BlockMarkerPromptCaching]:
    assert isinstance(middleware, list)
    return [m for m in middleware if isinstance(m, BlockMarkerPromptCaching)]


class TestReplacement:
    def test_name_matches_auto_attached_instance(self) -> None:
        ours = BlockMarkerPromptCaching()
        assert ours.name == AnthropicPromptCachingMiddleware.__name__
        assert ours.name == AnthropicPromptCachingMiddleware(
            unsupported_model_behavior="ignore"
        ).name

    def test_apply_custom_middleware_replaces_in_place(self) -> None:
        # Upgrade tripwire: deepagents must keep replacing same-name middleware in-place.
        stock = AnthropicPromptCachingMiddleware(unsupported_model_behavior="ignore")
        ours = BlockMarkerPromptCaching()
        result = _apply_custom_middleware([stock], [ours])
        assert result == [ours]
        assert result[0] is ours

    def test_oneshot_build_carries_exactly_one_instance(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        captured = _capture_create_agent_kwargs(monkeypatch)
        patch_models(monkeypatch, fake_model([AIMessage(content="ok")]))
        build_oneshot_options(oneshot_options(tmp_path))
        ours = _our_instances(captured["middleware"])
        assert len(ours) == 1
        assert ours[0]._enabled is True
        assert ours[0]._mark_tail is False  # single-call: dead-write premium

    def test_streaming_build_threads_disabled_flag(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        captured = _capture_create_agent_kwargs(monkeypatch)
        patch_models(monkeypatch, fake_model([AIMessage(content="ok")]))
        _build_streaming_graph(_streaming_options(tmp_path, cache_markers=False))
        ours = _our_instances(captured["middleware"])
        assert len(ours) == 1
        assert ours[0]._enabled is False
        assert ours[0]._mark_tail is True  # agentic sessions keep the tail

    def test_real_build_passes_factory_uniqueness_assertion(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The langchain factory asserts middleware names are unique per stack;
        # in-place replacement must leave exactly one instance under this name.
        patch_models(monkeypatch, fake_model([AIMessage(content="ok")]))
        graph, _config = build_oneshot_options(oneshot_options(tmp_path))
        assert graph is not None

    def test_subagent_specs_carry_ours(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        patch_models(monkeypatch, fake_model([AIMessage(content="ok")]))
        persona = SubagentDefinition(
            name="reviewer", description="review findings", prompt="review"
        )
        options = _streaming_options(tmp_path)
        options.agents = {"reviewer": persona}
        specs = get_subagent_specs(options)
        assert {spec["name"] for spec in specs} == {"reviewer", "general-purpose"}
        for spec in specs:
            ours = _our_instances(spec.get("middleware"))
            assert len(ours) == 1
            assert ours[0]._enabled is True

    def test_subagent_specs_thread_disabled_flag(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        patch_models(monkeypatch, fake_model([AIMessage(content="ok")]))
        options = _streaming_options(tmp_path, cache_markers=False)
        specs = get_subagent_specs(options)
        for spec in specs:
            ours = _our_instances(spec.get("middleware"))
            assert len(ours) == 1
            assert ours[0]._enabled is False


# ── (d) kill switch: config → construction sites ─────────────────────────────


class _OneShotHarness:
    def __init__(self) -> None:
        self.options: list[OneShotOptions] = []

    async def run_oneshot(self, prompt: str, options: OneShotOptions) -> OneShotResult:
        del prompt
        self.options.append(options)
        return OneShotResult(result_text=HEALTHY_TEXT)


class _StreamHarness:
    def __init__(self) -> None:
        self.options: list[StreamingOptions] = []

    def run_streaming(
        self, prompt: str, options: StreamingOptions
    ) -> AsyncIterator[HarnessResult]:
        del prompt
        self.options.append(options)

        async def _gen() -> AsyncIterator[HarnessResult]:
            yield HarnessResult(subtype="success", result_text=HEALTHY_TEXT)

        return _gen()


def _sdk_cfg(**extra: object) -> SimpleNamespace:
    return SimpleNamespace(api_key="sk-ant", base_url="https://gw.example/", **extra)


def _model_node() -> SimpleNamespace:
    return SimpleNamespace(id="claude-test", via="deepagents")


class TestKillSwitchThreading:
    def test_prompt_defaults_to_markers_on(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        fake = _OneShotHarness()
        monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
        deep.prompt("body", model=_model_node(), sdk_cfg=_sdk_cfg(), cwd=str(tmp_path))
        assert fake.options[0].cache_markers is True

    def test_prompt_threads_kill_switch_off(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        fake = _OneShotHarness()
        monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
        deep.prompt(
            "body",
            model=_model_node(),
            sdk_cfg=_sdk_cfg(cache_markers="off"),
            cwd=str(tmp_path),
        )
        assert fake.options[0].cache_markers is False

    def test_agentic_threads_kill_switch_off(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        fake = _StreamHarness()
        monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
        deep.agentic(
            "walk the repo",
            model=_model_node(),
            sdk_cfg=_sdk_cfg(cache_markers="off"),
            cwd=str(tmp_path),
        )
        assert fake.options[0].cache_markers is False

    def test_agentic_defaults_to_markers_on(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        fake = _StreamHarness()
        monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
        deep.agentic(
            "walk the repo", model=_model_node(), sdk_cfg=_sdk_cfg(), cwd=str(tmp_path)
        )
        assert fake.options[0].cache_markers is True

    def test_plugin_runner_threads_kill_switch_off(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        captured: list[StreamingOptions] = []

        def _fake_consume(
            prompt: str, options: StreamingOptions, *, verbose: bool
        ) -> Coroutine[object, object, None]:
            del prompt, verbose
            captured.append(options)

            async def _noop() -> None:
                return None

            return _noop()

        monkeypatch.setattr(plugin_runner, "_consume_deepagents", _fake_consume)
        cfg = SimpleNamespace(sdk=_sdk_cfg(cache_markers="off"), step_remediate=None)
        plugin_runner._invoke_deepagents(
            "fix it",
            model_id="claude-test",
            repo=tmp_path,
            mode="report-only",
            sr=SimpleNamespace(),
            cfg=cfg,
            verbose=False,
        )
        assert captured[0].cache_markers is False

    def test_validate_profile_kill_switch_reaches_overrides(self, tmp_path: Path) -> None:
        cfg_path = tmp_path / "p.yaml"
        cfg_path.write_text(
            "models:\n  validate:\n    orchestrator: {id: claude-test, via: deepagents}\n"
            "sdk:\n  cache_markers: off\n",
            encoding="utf-8",
        )
        rc, overrides = _apply_model_env(str(cfg_path))
        assert rc == 0
        assert overrides.get("cache_markers") is False

    def test_validate_profile_defaults_markers_on(self, tmp_path: Path) -> None:
        cfg_path = tmp_path / "p.yaml"
        cfg_path.write_text(
            "models:\n  validate:\n    orchestrator: {id: claude-test, via: deepagents}\n",
            encoding="utf-8",
        )
        rc, overrides = _apply_model_env(str(cfg_path))
        assert rc == 0
        assert overrides.get("cache_markers") is True

    def test_load_config_and_launcher_thread_the_flag(self, tmp_path: Path) -> None:
        config = load_config(overrides={"cache_markers": False})
        assert config.agent.cache_markers is False
        assert load_config().agent.cache_markers is True
        options = build_validation_options(
            config=config,
            manifest=Manifest(case_id="TEST-1", session_id="s1"),
            workspace=tmp_path,
            output_dir=tmp_path / "out",
            system_prompt=None,
        )
        assert options.cache_markers is False


# ── (e) breakpoint budget ────────────────────────────────────────────────────


class TestBreakpointBudget:
    def test_s4_oneshot_spends_exactly_two_of_four(self) -> None:
        # S4 one-shot (mark_tail off): system + cache_prefix block; tools are
        # excluded and the tail write premium is skipped — nothing reads it back.
        prefix_block: dict[str, object] = {
            "type": "text",
            "text": "SHARD PREFIX",
            "cache_control": {"type": "ephemeral"},
        }
        request = _request(
            [HumanMessage(content=[prefix_block, {"type": "text", "text": "the body"}])],
            with_tools=False,
        )
        payload = _payload(_apply(request, mark_tail=False))
        assert _marker_count(payload) == 2

    def test_mark_tail_off_keeps_system_and_tools_markers(self) -> None:
        out = _apply(_request([HumanMessage(content="scan")]), mark_tail=False)
        assert _marker_count(_payload(out)) == 1  # system only on the wire
        last_tool = out.tools[-1]
        assert isinstance(last_tool, BaseTool)
        assert (last_tool.extras or {}).get("cache_control")
        assert out.messages == [HumanMessage(content="scan")]  # tail untouched

    def test_agentic_request_spends_exactly_three_of_four(self) -> None:
        # Agentic: system + tools + tail.
        out = _apply(_request([HumanMessage(content="scan")]))
        wire_markers = _marker_count(_payload(out))
        last_tool = out.tools[-1]
        assert isinstance(last_tool, BaseTool)
        tool_markers = 1 if (last_tool.extras or {}).get("cache_control") else 0
        assert wire_markers + tool_markers == 3
