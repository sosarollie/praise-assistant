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

"""Unit tests for the legacy-shaped DeepAgents wrappers (backends/llm/deepagents.py).

The harness itself is faked at the module's get_harness seam; these tests pin
the option-building, tool-mapping, terminal-draining and telemetry contracts
the S1 stages rely on.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from vvaharness.backends.harness import (
    HarnessAssistantText,
    HarnessProcessError,
    HarnessResult,
    OneShotResult,
    ToolPolicy,
)
from vvaharness.backends.harness.models import AuthenticationError, ProxyError
from vvaharness.backends.llm import deepagents as deep
from vvaharness.util.scan_progress import set_active_tracker
from vvaharness.util.tokens import TOKENS

# Long enough (and token-rich enough) to clear the VVAH-E003 quality floor, so
# tests asserting a clean stderr aren't polluted by degenerate-output warnings.
_HEALTHY_TEXT = "finding: " + "x" * 160
_HEALTHY_USAGE = {"input_tokens": 100, "output_tokens": 120}


class _StreamHarness:
    """Fake harness whose run_streaming yields a fixed message sequence."""

    def __init__(self, messages, error=None):
        self.messages = messages
        self.error = error
        self.calls = []

    def run_streaming(self, prompt, options):
        self.calls.append((prompt, options))

        async def gen():
            for message in self.messages:
                yield message
            if self.error is not None:
                raise self.error

        return gen()


class _OneShotHarness:
    """Fake harness recording run_oneshot invocations."""

    def __init__(self, result, log=None):
        self.result = result
        self.calls = []
        self.log = log if log is not None else []

    async def run_oneshot(self, prompt, options):
        self.calls.append((prompt, options))
        self.log.append("harness")
        return self.result


def _model_node(**extra):
    return SimpleNamespace(id="claude-test", via="deepagents", **extra)


# ── agentic: option building and tool mapping ────────────────────────────────

def test_agentic_builds_streaming_options(monkeypatch, tmp_path):
    fake = _StreamHarness([HarnessResult(subtype="success", result_text="done")])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
    sdk_cfg = SimpleNamespace(api_key="sk-test", base_url="https://gw.example/")

    out = deep.agentic(
        "explore the repo",
        model=_model_node(),
        system_prompt="SYSTEM TEXT",
        allowed_tools=["Read", "Glob", "Grep"],
        cwd=str(tmp_path),
        max_budget_usd=25.0,
        max_turns=40,
        graph_name="s1-preprocess",
        sdk_cfg=sdk_cfg,
        openai_cfg=None,
    )

    assert out == "done"
    prompt_sent, options = fake.calls[0]
    assert prompt_sent == "explore the repo"
    assert options.model == "claude-test"
    assert options.model_provider is None
    assert options.cwd == Path(str(tmp_path))
    assert options.env["ANTHROPIC_API_KEY"] == "sk-test"
    assert options.env["ANTHROPIC_BASE_URL"] == "https://gw.example/"
    assert options.max_turns == 40
    assert options.max_budget_usd == 25.0
    assert options.system_prompt == "SYSTEM TEXT"
    assert options.tool_policy == ToolPolicy(allowed_tools=("Read", "Glob", "Grep"))
    assert options.response_model is None
    assert options.allow_writes is False
    assert options.graph_name == "s1-preprocess"


def test_agentic_forwards_declared_provider(monkeypatch, tmp_path):
    fake = _StreamHarness([HarnessResult(subtype="success", result_text="ok")])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.agentic("p", model=_model_node(provider="openai"), cwd=str(tmp_path))

    assert fake.calls[0][1].model_provider == "openai"


def test_agentic_pins_the_per_turn_output_cap(monkeypatch, tmp_path):
    """Route parity: sdk/openai agentic cap every turn at AGENTIC_MAX_TOKENS."""
    from vvaharness.backends.llm.models import AGENTIC_MAX_TOKENS

    fake = _StreamHarness([HarnessResult(subtype="success", result_text="ok")])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.agentic("p", model=_model_node(), cwd=str(tmp_path))

    assert fake.calls[0][1].max_output_tokens == AGENTIC_MAX_TOKENS


def test_agentic_strips_bash_and_warns(monkeypatch, tmp_path, capsys):
    fake = _StreamHarness([HarnessResult(subtype="success", result_text="ok")])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.agentic(
        "p",
        model=_model_node(),
        allowed_tools=["Read", "Glob", "Grep", "Bash"],
        cwd=str(tmp_path),
    )

    options = fake.calls[0][1]
    assert options.tool_policy.allowed_tools == ("Read", "Glob", "Grep")
    assert options.tool_policy.disallowed_tools == ("Bash",)
    err = capsys.readouterr().err
    assert "WARN" in err and "Bash" in err


def test_agentic_clean_tool_list_no_warning(monkeypatch, tmp_path, capsys):
    # A healthy result: a degenerate/zero-usage one would legitimately WARN.
    fake = _StreamHarness([HarnessResult(
        subtype="success", result_text=_HEALTHY_TEXT, usage=dict(_HEALTHY_USAGE)
    )])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.agentic(
        "p", model=_model_node(), allowed_tools=["Read", "Grep"], cwd=str(tmp_path)
    )

    assert fake.calls[0][1].tool_policy.disallowed_tools == ()
    assert "WARN" not in capsys.readouterr().err


def test_map_allowed_tools_none_grants_default_read_set():
    assert deep.map_allowed_tools(None) == (("Read", "Glob", "Grep"), ())


def test_map_allowed_tools_dedupes_preserving_order():
    granted, stripped = deep.map_allowed_tools(
        ["Grep", "Read", "Grep", "Bash", "Edit", "Bash"]
    )
    assert granted == ("Grep", "Read")
    assert stripped == ("Bash", "Edit")


# ── drain_streaming: terminal handling ───────────────────────────────────────

def test_drain_streaming_no_terminal_raises(monkeypatch, tmp_path):
    fake = _StreamHarness([HarnessAssistantText(text="thinking...")])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(RuntimeError, match="without a terminal result"):
        deep.agentic("p", model=_model_node(), cwd=str(tmp_path))


def test_drain_streaming_error_terminal_raises(monkeypatch, tmp_path):
    fake = _StreamHarness([HarnessResult(is_error=True, subtype="boom")])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(RuntimeError, match="boom"):
        deep.agentic("p", model=_model_node(), cwd=str(tmp_path))


def test_drain_streaming_recursion_after_terminal_returns_partial(monkeypatch, tmp_path):
    error = HarnessProcessError(
        "DeepAgents stream failed: GraphRecursionError", exit_code=1, stderr="limit"
    )
    fake = _StreamHarness(
        [HarnessResult(subtype="success", result_text="partial map")], error=error
    )
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    assert deep.agentic("p", model=_model_node(), cwd=str(tmp_path)) == "partial map"


def test_drain_streaming_recursion_without_terminal_propagates(monkeypatch, tmp_path):
    error = HarnessProcessError(
        "DeepAgents stream failed: GraphRecursionError", exit_code=1, stderr="limit"
    )
    fake = _StreamHarness([], error=error)
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(HarnessProcessError):
        deep.agentic("p", model=_model_node(), cwd=str(tmp_path))


def test_drain_streaming_other_process_error_propagates(monkeypatch, tmp_path):
    error = HarnessProcessError(
        "DeepAgents stream failed: ValueError", exit_code=1, stderr="bad"
    )
    fake = _StreamHarness(
        [HarnessResult(subtype="success", result_text="ignored")], error=error
    )
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(HarnessProcessError):
        deep.agentic("p", model=_model_node(), cwd=str(tmp_path))


# ── prompt: one-shot contract and telemetry ──────────────────────────────────

def test_prompt_uses_explicit_empty_tool_policy(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text="```yaml\n{}\n```"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    out = deep.prompt(
        "survey text",
        model=_model_node(),
        system_prompt="SYS",
        max_tokens=8000,
        cwd=str(tmp_path),
        tag="s1 autoexclude",
        graph_name="s1-autoexclude",
    )

    assert out == "```yaml\n{}\n```"
    prompt_sent, options = fake.calls[0]
    assert prompt_sent == "survey text"
    assert options.tool_policy == ToolPolicy()
    assert options.system_prompt == "SYS"
    assert options.graph_name == "s1-autoexclude"
    # max_tokens is honoured (not accepted-and-ignored): it becomes the
    # one-shot per-call output cap, matching via: cli / via: sdk.
    assert options.max_output_tokens == 8000


def test_prompt_without_max_tokens_leaves_cap_unset(monkeypatch, tmp_path):
    """No max_tokens => None => inherit the model ceiling (64k Anthropic / uncapped OpenAI)."""
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.prompt("p", model=_model_node(), cwd=str(tmp_path))

    assert fake.calls[0][1].max_output_tokens is None


def test_prompt_none_result_text_returns_empty_string(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text=None))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    assert deep.prompt("p", model=_model_node(), cwd=str(tmp_path)) == ""


def test_prompt_flattens_content_block_lists(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.prompt(
        [
            {"type": "text", "text": "part one"},
            {"type": "image", "source": "ignored"},
            {"type": "text", "text": "part two"},
        ],
        model=_model_node(),
        cwd=str(tmp_path),
    )

    assert fake.calls[0][0] == "part one\n\npart two"


def test_prompt_emits_llm_payload_before_harness_call(monkeypatch, tmp_path):
    log = []
    fake = _OneShotHarness(OneShotResult(result_text="ok"), log=log)
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    payloads = []

    class _Tracker:
        def llm_payload(self, **kw):
            payloads.append(kw)
            log.append("payload")

    set_active_tracker(_Tracker())
    try:
        deep.prompt(
            "survey", model=_model_node(), system_prompt="SYS",
            cwd=str(tmp_path), tag="s1 autoexclude",
        )
    finally:
        set_active_tracker(None)

    assert log == ["payload", "harness"]
    assert len(payloads) == 1
    assert payloads[0]["backend"] == "deepagents"
    assert payloads[0]["model_id"] == "claude-test"
    assert payloads[0]["tag"] == "s1 autoexclude"
    assert payloads[0]["user_prompt"] == "survey"
    assert payloads[0]["system_prompt"] == "SYS"


def test_prompt_adds_no_token_usage_itself(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    before = TOKENS.snapshot()["total"]
    deep.prompt("p", model=_model_node(), cwd=str(tmp_path))
    assert TOKENS.snapshot()["total"] == before


# ── build_harness_env ────────────────────────────────────────────────────────

def test_build_harness_env_openai_route(monkeypatch):
    monkeypatch.setenv("PATH_MARKER_FOR_TEST", "kept")
    openai_cfg = SimpleNamespace(api_key="sk-oai", base_url="https://oai.example/")

    env = deep.build_harness_env(
        "gpt-5.5", None, sdk_cfg=None, openai_cfg=openai_cfg
    )

    assert env["OPENAI_API_KEY"] == "sk-oai"
    assert env["OPENAI_BASE_URL"] == "https://oai.example/"
    assert env["PATH_MARKER_FOR_TEST"] == "kept"


def test_build_harness_env_emits_profile_tls_carriers(tmp_path):
    """sdk.ca_cert / client_cert / verify_ssl reach the env, anchored at cfg_dir."""
    from vvaharness.backends.harness.deepagents.models import (
        SSL_CERT_FILE_VAR,
        TLS_CLIENT_CERT_VAR,
        TLS_CLIENT_KEY_VAR,
        TLS_VERIFY_VAR,
    )

    sdk_cfg = SimpleNamespace(
        api_key="sk-ant",
        ca_cert="certs/ca.pem",
        client_cert=("certs/client.pem", "certs/client.key"),
        verify_ssl=True,
    )
    env = deep.build_harness_env(
        "claude-x", "anthropic", sdk_cfg=sdk_cfg, openai_cfg=None,
        cfg_dir=str(tmp_path),
    )

    assert env["ANTHROPIC_API_KEY"] == "sk-ant"
    assert env[SSL_CERT_FILE_VAR] == str(tmp_path / "certs/ca.pem")
    assert env[TLS_CLIENT_CERT_VAR] == str(tmp_path / "certs/client.pem")
    assert env[TLS_CLIENT_KEY_VAR] == str(tmp_path / "certs/client.key")
    assert TLS_VERIFY_VAR not in env  # verify_ssl: true is the default — no carrier


def test_build_harness_env_picks_openai_tls_block_for_openai_route():
    """An OpenAI-routed model reads TLS material off the openai: block, not sdk:."""
    from vvaharness.backends.harness.deepagents.models import SSL_CERT_FILE_VAR

    sdk_cfg = SimpleNamespace(ca_cert="/sdk/ca.pem")
    openai_cfg = SimpleNamespace(api_key="sk-oai", ca_cert="/oai/ca.pem")
    env = deep.build_harness_env(
        "gpt-4o", "openai", sdk_cfg=sdk_cfg, openai_cfg=openai_cfg
    )

    assert env[SSL_CERT_FILE_VAR] == "/oai/ca.pem"


def test_build_harness_env_without_tls_is_byte_identical_to_legacy():
    """S10/S11 regression guard: no TLS config ⇒ exactly the pre-TLS env."""
    import os

    from vvaharness.backends.harness.provider_routing import credential_env_overrides

    sdk_cfg = SimpleNamespace(api_key="sk-ant", base_url="https://gw.example/")
    env = deep.build_harness_env(
        "claude-x", "anthropic", sdk_cfg=sdk_cfg, openai_cfg=None
    )

    assert env == {
        **os.environ,
        **credential_env_overrides(
            "claude-x", "anthropic", sdk_cfg=sdk_cfg, openai_cfg=None
        ),
    }


# ── dispatch_prompt / dispatch_agentic: the single dispatch seam ─────────────

_LEGACY_VIAS = ["cli", "sdk", "openai"]


@pytest.fixture(autouse=True)
def _fresh_kwarg_warnings():
    """Each test observes the one-time per-process warnings from a clean slate."""
    deep._WARNED_LEGACY_KW.clear()
    deep._NO_USAGE_WARNED_TAGS.clear()
    yield
    deep._WARNED_LEGACY_KW.clear()
    deep._NO_USAGE_WARNED_TAGS.clear()


class _FakeRegistry:
    """Stand-in for backends.llm.registry recording prompt()/agentic() calls."""

    def __init__(self, result="legacy-result"):
        self.result = result
        self.prompt_calls = []
        self.agentic_calls = []

    def prompt(self, user_prompt, **kw):
        self.prompt_calls.append((user_prompt, kw))
        return self.result

    def agentic(self, user_prompt, **kw):
        self.agentic_calls.append((user_prompt, kw))
        return self.result


class _ExplodingRegistry:
    """Registry stand-in that fails the test if the legacy path is taken."""

    def prompt(self, *a, **kw):
        raise AssertionError("legacy registry.prompt must not be called")

    def agentic(self, *a, **kw):
        raise AssertionError("legacy registry.agentic must not be called")


def _cfg_node(tmp_path, **extra):
    return SimpleNamespace(
        sdk=SimpleNamespace(api_key="sk-ant", base_url="https://gw.example/"),
        openai=None,
        _data={"_config_dir": str(tmp_path)},
        **extra,
    )


@pytest.mark.parametrize("via", _LEGACY_VIAS)
def test_dispatch_prompt_legacy_via_forwards_kwargs_unchanged(
    monkeypatch, tmp_path, via
):
    fake_registry = _FakeRegistry()
    monkeypatch.setattr(deep, "registry", fake_registry)
    monkeypatch.setattr(
        deep, "get_harness",
        lambda _via: pytest.fail("harness must not be touched on a legacy via"),
    )
    model = SimpleNamespace(id="m-legacy", via=via)

    out = deep.dispatch_prompt(
        "ask",
        model=model,
        cfg=_cfg_node(tmp_path),
        cwd=str(tmp_path),
        system_prompt="SYS",
        max_tokens=9000,
        tag="s2 threatmodel",
        timeout=1800,
        cache_prefix="PREFIX ",
        output_format="text",
    )

    assert out == "legacy-result"
    user_prompt, kw = fake_registry.prompt_calls[0]
    assert user_prompt == "ask"
    # The legacy route gets its kwargs byte-for-byte; cwd/graph_name are
    # deepagents-route concepts no registry.prompt caller passes today.
    assert kw == {
        "model": model,
        "system_prompt": "SYS",
        "max_tokens": 9000,
        "tag": "s2 threatmodel",
        "timeout": 1800,
        "cache_prefix": "PREFIX ",
        "output_format": "text",
    }


@pytest.mark.parametrize("via", _LEGACY_VIAS)
def test_dispatch_agentic_legacy_via_forwards_kwargs_unchanged(
    monkeypatch, tmp_path, via
):
    fake_registry = _FakeRegistry()
    monkeypatch.setattr(deep, "registry", fake_registry)
    monkeypatch.setattr(
        deep, "get_harness",
        lambda _via: pytest.fail("harness must not be touched on a legacy via"),
    )
    model = SimpleNamespace(id="m-legacy", via=via)

    out = deep.dispatch_agentic(
        "explore",
        model=model,
        cfg=_cfg_node(tmp_path),
        cwd=str(tmp_path),
        system_prompt="SYS",
        allowed_tools=["Read", "Grep"],
        max_turns=12,
        max_budget_usd=25.0,
        tag="s1 preprocess",
        permission_mode="auto",
        stream_cb=None,
    )

    assert out == "legacy-result"
    user_prompt, kw = fake_registry.agentic_calls[0]
    assert user_prompt == "explore"
    assert kw == {
        "model": model,
        "system_prompt": "SYS",
        "allowed_tools": ["Read", "Grep"],
        "cwd": str(tmp_path),
        "max_budget_usd": 25.0,
        "max_turns": 12,
        "tag": "s1 preprocess",
        "permission_mode": "auto",
        "stream_cb": None,
    }


def test_dispatch_prompt_deepagents_via_builds_harness_options(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text="harness answer"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
    monkeypatch.setattr(deep, "registry", _ExplodingRegistry())

    out = deep.dispatch_prompt(
        "survey",
        model=_model_node(),
        cfg=_cfg_node(tmp_path),
        cwd=str(tmp_path),
        system_prompt="SYS",
        max_tokens=8000,
        tag="s1 autoexclude",
        graph_name="s1-autoexclude",
    )

    assert out == "harness answer"
    prompt_sent, options = fake.calls[0]
    assert prompt_sent == "survey"
    assert options.model == "claude-test"
    assert options.cwd == Path(str(tmp_path))
    assert options.env["ANTHROPIC_API_KEY"] == "sk-ant"
    assert options.env["ANTHROPIC_BASE_URL"] == "https://gw.example/"
    assert options.system_prompt == "SYS"
    assert options.graph_name == "s1-autoexclude"
    assert options.tool_policy == ToolPolicy()


def test_dispatch_agentic_deepagents_via_builds_harness_options(monkeypatch, tmp_path):
    fake = _StreamHarness([HarnessResult(subtype="success", result_text="mapped")])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
    monkeypatch.setattr(deep, "registry", _ExplodingRegistry())

    out = deep.dispatch_agentic(
        "explore",
        model=_model_node(provider="openai"),
        cfg=SimpleNamespace(
            sdk=None,
            openai=SimpleNamespace(api_key="sk-oai"),
            _data={"_config_dir": str(tmp_path)},
        ),
        cwd=str(tmp_path),
        system_prompt="SYS",
        allowed_tools=["Read", "Glob", "Grep"],
        max_turns=40,
        max_budget_usd=25.0,
        tag="s1 preprocess",
        graph_name="s1-preprocess",
    )

    assert out == "mapped"
    prompt_sent, options = fake.calls[0]
    assert prompt_sent == "explore"
    assert options.model_provider == "openai"
    assert options.env["OPENAI_API_KEY"] == "sk-oai"
    assert options.max_turns == 40
    assert options.max_budget_usd == 25.0
    assert options.graph_name == "s1-preprocess"
    assert options.tool_policy == ToolPolicy(allowed_tools=("Read", "Glob", "Grep"))


def test_dispatch_deepagents_threads_cfg_dir_to_tls_carriers(monkeypatch, tmp_path):
    """A relative profile ca_cert resolves against cfg._data['_config_dir']."""
    from vvaharness.backends.harness.deepagents.models import SSL_CERT_FILE_VAR

    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
    cfg = SimpleNamespace(
        sdk=SimpleNamespace(api_key="sk-ant", ca_cert="certs/ca.pem"),
        openai=None,
        _data={"_config_dir": str(tmp_path)},
    )

    deep.dispatch_prompt("p", model=_model_node(), cfg=cfg, cwd=str(tmp_path))

    options = fake.calls[0][1]
    assert options.env[SSL_CERT_FILE_VAR] == str(tmp_path / "certs/ca.pem")


# ── dispatch: legacy-kwarg policy on the deepagents branch ───────────────────

def test_dispatch_prompt_marks_cache_prefix_on_anthropic_route(
    monkeypatch, tmp_path, capsys
):
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.dispatch_prompt(
        "the body", model=_model_node(), cfg=_cfg_node(tmp_path),
        cwd=str(tmp_path), cache_prefix="THE SHARD PREFIX\n",
    )

    # Content split, not folded: the harness marks the prefix block.
    prompt_arg, options = fake.calls[0]
    assert prompt_arg == "the body"
    assert options.cache_prefix == "THE SHARD PREFIX\n"
    assert "WARN [deepagents]: legacy kwarg `cache_prefix`" not in capsys.readouterr().err


def test_dispatch_prompt_folds_cache_prefix_on_openai_route(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.dispatch_prompt(
        "the body", model=_model_node(provider="openai"),
        cfg=_cfg_node(tmp_path), cwd=str(tmp_path),
        cache_prefix="THE SHARD PREFIX\n",
    )

    prompt_arg, options = fake.calls[0]
    assert prompt_arg == "THE SHARD PREFIX\nthe body"
    assert options.cache_prefix is None


def test_dispatch_prompt_kill_switch_folds_cache_prefix(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
    cfg = _cfg_node(tmp_path)
    cfg.sdk.cache_markers = "off"

    deep.dispatch_prompt(
        "the body", model=_model_node(), cfg=cfg, cwd=str(tmp_path),
        cache_prefix="THE SHARD PREFIX\n",
    )

    prompt_arg, options = fake.calls[0]
    assert prompt_arg == "THE SHARD PREFIX\nthe body"
    assert options.cache_prefix is None


def test_dispatch_agentic_folds_cache_prefix_into_flat_prompt(monkeypatch, tmp_path):
    fake = _StreamHarness([HarnessResult(subtype="success", result_text="ok")])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.dispatch_agentic(
        "walk the repo", model=_model_node(), cfg=_cfg_node(tmp_path),
        cwd=str(tmp_path), cache_prefix="CTX ",
    )

    assert fake.calls[0][0] == "CTX walk the repo"


def test_dispatch_prompt_marks_cache_prefix_for_block_lists(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.dispatch_prompt(
        [{"type": "text", "text": "body"}],
        model=_model_node(), cfg=_cfg_node(tmp_path), cwd=str(tmp_path),
        cache_prefix="PREFIX",
    )

    prompt_arg, options = fake.calls[0]
    assert prompt_arg == "body"
    assert options.cache_prefix == "PREFIX"


def test_oneshot_content_marks_prefix_block():
    from vvaharness.backends.harness.deepagents.client import _oneshot_content

    blocks = _oneshot_content("the body", "PREFIX")

    assert blocks == [
        {"type": "text", "text": "PREFIX",
         "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "the body"},
    ]


def test_oneshot_content_without_prefix_is_plain_string():
    from vvaharness.backends.harness.deepagents.client import _oneshot_content

    assert _oneshot_content("the body", None) == "the body"
    assert _oneshot_content("the body", "") == "the body"


def test_dispatch_accepted_unused_kwargs_stay_silent(monkeypatch, tmp_path, capsys):
    """timeout/output_format/… have accepted-and-unused precedent: no warning."""
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.dispatch_prompt(
        "p", model=_model_node(), cfg=_cfg_node(tmp_path), cwd=str(tmp_path),
        timeout=1800, output_format="text", json_schema={"type": "object"},
        temperature=0.2, thinking_budget=1024, betas=["b1"],
    )

    assert "WARN [deepagents]: legacy kwarg" not in capsys.readouterr().err


def test_dispatch_unknown_kwarg_warns_once_and_is_ignored(
    monkeypatch, tmp_path, capsys
):
    """A kwarg with no precedent never vanishes silently — it warns by name."""
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
    cfg = _cfg_node(tmp_path)

    deep.dispatch_prompt(
        "p", model=_model_node(), cfg=cfg, cwd=str(tmp_path), mystery_knob=1
    )
    deep.dispatch_prompt(
        "p", model=_model_node(), cfg=cfg, cwd=str(tmp_path), mystery_knob=1
    )

    err = capsys.readouterr().err
    assert err.count("WARN [deepagents]: legacy kwarg `mystery_knob`") == 1


# ── error taxonomy: provider failures → VVAH-E001 / VVAH-E002 ────────────────

_SECRET_KEY = "sk-ant-api03-" + "A" * 40


class _FakeStatusError(Exception):
    """Provider APIStatusError stand-in: carries .status_code and .message."""

    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class APIConnectionError(Exception):
    """Stand-in matching the provider class NAME the seam recognises.

    Both anthropic and openai raise an ``APIConnectionError`` that carries no
    ``status_code``; the seam matches it by name, so this local double does.
    """


class _FailingOneShotHarness:
    """Fake harness whose run_oneshot raises a canned error."""

    def __init__(self, error):
        self.error = error

    async def run_oneshot(self, prompt, options):
        raise self.error


def test_oneshot_auth_failure_raises_vvah_e001_with_redacted_body(
    monkeypatch, tmp_path
):
    # The key STRADDLES the 400-char truncation point: redact-then-truncate
    # removes it entirely, while the buggy truncate-then-redact order would
    # bisect it so the pattern no longer matches and a fragment survives.
    body = "x" * 389 + " " + _SECRET_KEY + " unauthorized"
    fake = _FailingOneShotHarness(_FakeStatusError(401, body))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(AuthenticationError) as excinfo:
        deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s3 decompose")

    text = str(excinfo.value)
    assert "VVAH-E001" in text
    assert _SECRET_KEY not in text
    assert "sk-ant-" not in text  # proves redact() ran BEFORE truncation
    assert "claude-test" in text  # model id is named
    assert "s3 decompose" in text  # stage tag is named
    assert excinfo.value.status_code == 401
    assert excinfo.value.backend == "deepagents"


def test_streaming_auth_failure_unwraps_harness_process_error(monkeypatch, tmp_path):
    # client.py wraps stream failures: HarnessProcessError(...) from <provider error>.
    provider = _FakeStatusError(401, f"authentication_failed for {_SECRET_KEY}")
    wrapper = HarnessProcessError(
        "DeepAgents stream failed: APIStatusError", exit_code=1, stderr="401"
    )
    wrapper.__cause__ = provider
    fake = _StreamHarness([], error=wrapper)
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(AuthenticationError) as excinfo:
        deep.agentic("p", model=_model_node(), cwd=str(tmp_path), tag="s1 preprocess")

    assert "VVAH-E001" in str(excinfo.value)
    assert _SECRET_KEY not in str(excinfo.value)


def test_oneshot_tls_connection_failure_raises_vvah_e002(monkeypatch, tmp_path):
    conn = APIConnectionError("Connection error.")
    conn.__cause__ = Exception(
        "CERTIFICATE_VERIFY_FAILED: self-signed certificate in chain"
    )
    fake = _FailingOneShotHarness(conn)
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(ProxyError) as excinfo:
        deep.prompt("p", model=_model_node(), cwd=str(tmp_path))

    assert "VVAH-E002" in str(excinfo.value)
    assert excinfo.value.backend == "deepagents"


def test_streaming_proxy_407_maps_status_code(monkeypatch, tmp_path):
    conn = APIConnectionError("tunnel failed")
    conn.__cause__ = Exception("proxy_auth required: 407")
    wrapper = HarnessProcessError(
        "DeepAgents stream failed: APIConnectionError", exit_code=1, stderr="407"
    )
    wrapper.__cause__ = conn
    fake = _StreamHarness([], error=wrapper)
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(ProxyError) as excinfo:
        deep.agentic("p", model=_model_node(), cwd=str(tmp_path))

    assert excinfo.value.status_code == 407


def test_unclassifiable_failure_passes_through_unchanged(monkeypatch, tmp_path):
    fake = _FailingOneShotHarness(ValueError("plain programming error"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(ValueError, match="plain programming error"):
        deep.prompt("p", model=_model_node(), cwd=str(tmp_path))


def test_connection_error_without_proxy_signature_passes_through(
    monkeypatch, tmp_path
):
    conn = APIConnectionError("Connection error.")
    conn.__cause__ = Exception("temporary DNS resolution failure")
    fake = _FailingOneShotHarness(conn)
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(APIConnectionError):
        deep.prompt("p", model=_model_node(), cwd=str(tmp_path))


# ── quality gate (VVAH-E003) and zero-usage visibility ───────────────────────

def test_prompt_routes_text_through_quality_gate(monkeypatch, tmp_path):
    fake = _OneShotHarness(
        OneShotResult(result_text="short", usage={"output_tokens": 5})
    )
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
    calls = []
    monkeypatch.setattr(
        deep, "check_response_quality",
        lambda text, stage="", *, output_tokens=None: calls.append(
            (text, stage, output_tokens)
        ),
    )

    deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s7 dedup")

    assert calls == [("short", "s7 dedup", 5)]


def test_agentic_routes_text_through_quality_gate(monkeypatch, tmp_path):
    fake = _StreamHarness([HarnessResult(
        subtype="success", result_text="brief", usage={"output_tokens": 3}
    )])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)
    calls = []
    monkeypatch.setattr(
        deep, "check_response_quality",
        lambda text, stage="", *, output_tokens=None: calls.append(
            (text, stage, output_tokens)
        ),
    )

    deep.agentic("p", model=_model_node(), cwd=str(tmp_path), tag="s1 preprocess")

    assert calls == [("brief", "s1 preprocess", 3)]


def test_prompt_short_response_warns_vvah_e003_but_still_returns(
    monkeypatch, tmp_path, capsys
):
    fake = _OneShotHarness(OneShotResult(result_text="ok"))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    out = deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s3 decompose")

    assert out == "ok"  # safety net, not a per-call gate: first miss only warns
    assert "VVAH-E003" in capsys.readouterr().err


def test_no_usage_warning_fires_once_per_tag(monkeypatch, tmp_path, capsys):
    fake = _OneShotHarness(OneShotResult(result_text=_HEALTHY_TEXT))  # usage=None
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s8 chain")
    deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s8 chain")
    err = capsys.readouterr().err
    assert err.count("no token usage recorded for stage 's8 chain'") == 1
    assert "claude-test" in err

    deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s7 dedup")
    assert "no token usage recorded for stage 's7 dedup'" in capsys.readouterr().err


def test_agentic_no_usage_warning_covers_streaming_path(monkeypatch, tmp_path, capsys):
    fake = _StreamHarness([HarnessResult(subtype="success", result_text=_HEALTHY_TEXT)])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.agentic("p", model=_model_node(), cwd=str(tmp_path), tag="s1 preprocess")

    err = capsys.readouterr().err
    assert "no token usage recorded for stage 's1 preprocess'" in err


def test_usage_present_suppresses_no_usage_warning(monkeypatch, tmp_path, capsys):
    fake = _OneShotHarness(
        OneShotResult(result_text=_HEALTHY_TEXT, usage=dict(_HEALTHY_USAGE))
    )
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s8 chain")

    assert "no token usage recorded" not in capsys.readouterr().err


def test_no_usage_warning_keyed_on_stage_prefix(monkeypatch, tmp_path, capsys):
    """Tags sharing a stage prefix warn once (no per-chunk storm under S4);
    the message keeps the first offender's full tag."""
    fake = _OneShotHarness(OneShotResult(result_text=_HEALTHY_TEXT))  # usage=None
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s4 chunk-01")
    deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s4 chunk-02")
    err = capsys.readouterr().err
    assert err.count("no token usage recorded") == 1
    assert "stage 's4 chunk-01'" in err

    deep.prompt("p", model=_model_node(), cwd=str(tmp_path), tag="s7 dedup")
    assert "stage 's7 dedup'" in capsys.readouterr().err


# ── _run_sync: the persistent harness loop ───────────────────────────────────

def test_run_sync_runs_without_a_caller_loop():
    async def coro():
        return "value"

    assert deep._run_sync(coro()) == "value"


def test_run_sync_propagates_exceptions():
    async def boom():
        raise ValueError("harness failure")

    with pytest.raises(ValueError, match="harness failure"):
        deep._run_sync(boom())


def test_run_sync_bridges_a_caller_holding_a_running_loop():
    async def inner():
        return 7

    async def caller():
        return deep._run_sync(inner())

    assert asyncio.run(caller()) == 7


def test_run_sync_concurrent_callers_share_one_loop():
    """All coroutines observe the same persistent loop; every caller gets its
    own result back."""
    seen_loops = []
    record_lock = threading.Lock()

    async def observe(idx: int) -> tuple[int, str]:
        with record_lock:
            seen_loops.append(asyncio.get_running_loop())
        return idx, threading.current_thread().name

    outcomes: dict[int, tuple[int, str]] = {}

    def caller(idx: int) -> None:
        outcomes[idx] = deep._run_sync(observe(idx))

    threads = [threading.Thread(target=caller, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len({id(loop) for loop in seen_loops}) == 1
    assert outcomes == {
        i: (i, "vvaharness-llm-deepagents") for i in range(6)
    }


def test_run_sync_concurrent_exceptions_reach_their_own_callers():
    async def boom(idx: int):
        raise ValueError(f"failure-{idx}")

    caught: dict[int, str] = {}

    def caller(idx: int) -> None:
        try:
            deep._run_sync(boom(idx))
        except ValueError as exc:
            caught[idx] = str(exc)

    threads = [threading.Thread(target=caller, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert caught == {i: f"failure-{i}" for i in range(4)}


def test_run_sync_reentrancy_from_the_loop_thread_raises():
    """A harness coroutine calling back into _run_sync would deadlock forever;
    it must raise instead."""
    async def noop():
        return None

    async def reenter():
        return deep._run_sync(noop())

    with pytest.raises(RuntimeError, match="harness loop thread"):
        deep._run_sync(reenter())


def test_run_sync_keyboard_interrupt_cancels_the_future(monkeypatch):
    """Ctrl-C on the waiting thread must cancel the submitted harness call,
    not leave it billing in the background."""
    class _FakeFuture:
        def __init__(self):
            self.cancel_calls = 0

        def result(self):
            raise KeyboardInterrupt

        def cancel(self):
            self.cancel_calls += 1
            return True

    fake_future = _FakeFuture()

    def fake_submit(coro, loop):
        coro.close()
        return fake_future

    monkeypatch.setattr(deep.asyncio, "run_coroutine_threadsafe", fake_submit)

    async def coro():
        return None

    with pytest.raises(KeyboardInterrupt):
        deep._run_sync(coro())
    assert fake_future.cancel_calls == 1


# ── oneshot native-tool exclusion (harness side) ─────────────────────────────

def test_oneshot_excluded_tools_empty_policy_excludes_all_natives_and_task():
    from vvaharness.backends.harness import OneShotOptions
    from vvaharness.backends.harness.deepagents.models import (
        ALL_NATIVE_TOOLS,
        SUBAGENT_DISPATCH_TOOL,
    )
    from vvaharness.backends.harness.deepagents.options.oneshot import (
        _oneshot_excluded_tools,
    )

    options = OneShotOptions(model="m", cwd=Path(), tool_policy=ToolPolicy())
    assert _oneshot_excluded_tools(options) == ALL_NATIVE_TOOLS | {SUBAGENT_DISPATCH_TOOL}


def test_oneshot_excluded_tools_none_policy_keeps_natives_but_withholds_task():
    """A ``None`` policy keeps the legacy native tools, but ``task`` (sub-agent
    dispatch) is withheld on the one-shot path unconditionally."""
    from vvaharness.backends.harness import OneShotOptions
    from vvaharness.backends.harness.deepagents.models import SUBAGENT_DISPATCH_TOOL
    from vvaharness.backends.harness.deepagents.options.oneshot import (
        _oneshot_excluded_tools,
    )

    options = OneShotOptions(model="m", cwd=Path(), tool_policy=None)
    assert _oneshot_excluded_tools(options) == frozenset({SUBAGENT_DISPATCH_TOOL})


def test_oneshot_excluded_tools_keeps_allowed_logicals_but_still_withholds_task():
    from vvaharness.backends.harness import OneShotOptions
    from vvaharness.backends.harness.deepagents.models import (
        ALL_NATIVE_TOOLS,
        SUBAGENT_DISPATCH_TOOL,
    )
    from vvaharness.backends.harness.deepagents.options.oneshot import (
        _oneshot_excluded_tools,
    )

    options = OneShotOptions(
        model="m", cwd=Path(),
        tool_policy=ToolPolicy(allowed_tools=("Read", "Grep")),
    )
    excluded = _oneshot_excluded_tools(options)
    assert excluded == (ALL_NATIVE_TOOLS - {"read_file", "grep"}) | {SUBAGENT_DISPATCH_TOOL}


def test_read_only_middleware_merges_extras_into_single_exclude_entry():
    # langchain's create_agent rejects duplicate middleware instances of one
    # class, so extra exclusions must merge into the existing ExcludeTools.
    from vvaharness.backends.harness.deepagents.exclude_tools import ExcludeTools
    from vvaharness.backends.harness.deepagents.redaction import read_only_middleware

    middleware = read_only_middleware(frozenset({"glob", "ls"}))
    excludes = [m for m in middleware if isinstance(m, ExcludeTools)]
    assert len(excludes) == 1
    assert {"glob", "ls", "delete", "write_file"} <= excludes[0]._excluded


def test_read_only_middleware_default_unchanged():
    from vvaharness.backends.harness.deepagents.exclude_tools import ExcludeTools
    from vvaharness.backends.harness.deepagents.redaction import read_only_middleware
    from vvaharness.backends.harness.models import NATIVE_WRITE_TOOLS

    middleware = read_only_middleware()
    excludes = [m for m in middleware if isinstance(m, ExcludeTools)]
    assert len(excludes) == 1
    assert excludes[0]._excluded == NATIVE_WRITE_TOOLS | {"delete"}
