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

"""Unit tests for vvaharness.backends.llm dispatcher (resolve/prompt/agentic)
and for the shared detection-stage tool guard (validate_detection_tools)."""
import types

import pytest

from vvaharness.backends.llm import registry as llm
from vvaharness.backends.llm.models import (
    DEFAULT_READ_TOOLS,
    validate_detection_tools,
)


# Helpers
class _Cfg:
    """Minimal stand-in for a model config node with attribute access."""

    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, v)


def _make_recording_backend():
    """Return (module-like backend, calls list) recording prompt/agentic calls."""
    calls = []
    backend = types.SimpleNamespace()

    def _prompt(user_prompt, *, model, **kw):
        calls.append(("prompt", user_prompt, model, kw))
        return "PROMPT_RESULT"

    def _agentic(user_prompt, *, model, **kw):
        calls.append(("agentic", user_prompt, model, kw))
        return "AGENTIC_RESULT"

    backend.prompt = _prompt
    backend.agentic = _agentic
    return backend, calls


@pytest.fixture
def patched_backends(monkeypatch):
    """Substitute recording fakes for the three backends.

    Patches ``get_backend``, the dispatcher's single resolution point. The dispatcher no longer
    captures backend modules at import time -- ``_BACKENDS`` holds import paths that are
    resolved on selection -- so there is nothing to patch in that mapping.
    """
    fakes = {via: _make_recording_backend() for via in ("cli", "sdk", "openai")}

    def _get_backend(via, model_id):
        if via not in fakes:
            raise ValueError(f"Unknown backend `via: {via}` for model {model_id}")
        return fakes[via][0]

    monkeypatch.setattr(llm, "get_backend", _get_backend)
    return fakes


# resolve()
def test_resolve_bare_string_routes_to_cli():
    model_id, via, extras = llm.resolve("claude-opus-example")
    assert model_id == "claude-opus-example"
    assert via == "cli"
    assert extras == {}


def test_resolve_id_via_form():
    cfg = _Cfg(id="claude-opus-example", via="sdk")
    model_id, via, extras = llm.resolve(cfg)
    assert model_id == "claude-opus-example"
    assert via == "sdk"
    assert extras == {}


def test_resolve_defaults_via_to_cli_when_absent():
    cfg = _Cfg(id="some-model")
    model_id, via, extras = llm.resolve(cfg)
    assert model_id == "some-model"
    assert via == "cli"
    assert extras == {}


def test_resolve_falsy_via_defaults_to_cli():
    cfg = _Cfg(id="some-model", via=None)
    _, via, _ = llm.resolve(cfg)
    assert via == "cli"


def test_resolve_collects_temperature_extra():
    cfg = _Cfg(id="m", via="sdk", temperature=0.5)
    _, _, extras = llm.resolve(cfg)
    assert extras == {"temperature": 0.5}
    assert isinstance(extras["temperature"], float)


def test_resolve_collects_thinking_budget_and_betas():
    cfg = _Cfg(id="m", via="sdk", thinking_budget=1024, betas=["beta-a", "beta-b"])
    _, _, extras = llm.resolve(cfg)
    assert extras["thinking_budget"] == 1024
    assert isinstance(extras["thinking_budget"], int)
    assert extras["betas"] == ["beta-a", "beta-b"]


def test_resolve_zero_thinking_budget_is_dropped():
    # Source uses `if tb:` so 0 (falsy) must not appear in extras.
    cfg = _Cfg(id="m", via="sdk", thinking_budget=0)
    _, _, extras = llm.resolve(cfg)
    assert "thinking_budget" not in extras


def test_resolve_missing_id_raises():
    cfg = _Cfg(via="sdk")  # no .id
    with pytest.raises(ValueError):
        llm.resolve(cfg)


# prompt() dispatch
def test_prompt_bare_string_dispatches_to_cli(patched_backends):
    out = llm.prompt("hello", model="claude-opus-example")
    assert out == "PROMPT_RESULT"

    _, cli_calls = patched_backends["cli"]
    _, sdk_calls = patched_backends["sdk"]
    assert len(cli_calls) == 1
    assert sdk_calls == []
    kind, up, model_id, kw = cli_calls[0]
    assert kind == "prompt"
    assert up == "hello"
    assert model_id == "claude-opus-example"


def test_prompt_sdk_dispatch(patched_backends):
    cfg = _Cfg(id="claude-opus-example", via="sdk")
    out = llm.prompt("hi", model=cfg)
    assert out == "PROMPT_RESULT"

    _, sdk_calls = patched_backends["sdk"]
    _, cli_calls = patched_backends["cli"]
    assert len(sdk_calls) == 1
    assert cli_calls == []
    assert sdk_calls[0][2] == "claude-opus-example"


def test_prompt_openai_dispatch(patched_backends):
    cfg = _Cfg(id="gpt-example", via="openai")
    out = llm.prompt("hi", model=cfg)
    assert out == "PROMPT_RESULT"

    _, oai_calls = patched_backends["openai"]
    assert len(oai_calls) == 1
    assert oai_calls[0][2] == "gpt-example"


def test_prompt_cli_drops_sdk_only_kwargs(patched_backends):
    # CLI backend has no temperature/thinking/betas flags; dispatcher must strip them.
    llm.prompt(
        "x",
        model="bare-model",
        temperature=0.7,
        thinking_budget=99,
        betas=["b"],
        keep_me="yes",
    )
    _, cli_calls = patched_backends["cli"]
    kw = cli_calls[0][3]
    assert "temperature" not in kw
    assert "thinking_budget" not in kw
    assert "betas" not in kw
    assert kw["keep_me"] == "yes"


def test_prompt_extras_applied_to_sdk(patched_backends):
    cfg = _Cfg(id="m", via="sdk", temperature=0.25)
    llm.prompt("x", model=cfg)
    _, sdk_calls = patched_backends["sdk"]
    kw = sdk_calls[0][3]
    assert kw["temperature"] == 0.25


def test_prompt_caller_kwarg_overrides_extras(patched_backends):
    # extras use setdefault, so an explicit caller kwarg wins.
    cfg = _Cfg(id="m", via="sdk", temperature=0.25)
    llm.prompt("x", model=cfg, temperature=0.99)
    _, sdk_calls = patched_backends["sdk"]
    kw = sdk_calls[0][3]
    assert kw["temperature"] == 0.99


# deepagents is NOT a registry backend
#
# The harness route (backends/llm/deepagents.py) is reached only through explicit
# in-stage branches on the resolved via, never through this dispatcher. These tests
# deliberately do NOT patch above the dispatcher: they exercise the real _BACKENDS
# mapping and the real get_backend(), so re-registering a "deepagents" entry (or
# re-adding provider forwarding to prompt()) must fail here.

def test_registry_backends_are_exactly_cli_openai_sdk():
    # No `deepagents` entry: the registry knows only the three legacy backends.
    assert llm.available() == ["cli", "openai", "sdk"]
    assert set(llm.targets()) == {"cli", "sdk", "openai"}


def test_get_backend_deepagents_raises_unknown_backend():
    # Safety property: a stray registry.prompt()/agentic() call with a
    # via:deepagents model must fail LOUDLY here rather than silently dispatch
    # to some backend. The harness route depends on process-wide configure()
    # state and stage-supplied context that the registry cannot provide, so an
    # unrouted call reaching it would misbehave quietly; every deepagents role
    # goes through its stage's explicit `via` branch instead.
    with pytest.raises(ValueError, match="Unknown backend"):
        llm.get_backend("deepagents", "claude-sonnet-4-6")


def test_prompt_deepagents_via_raises_unknown_backend():
    # Same property one level up: the dispatcher itself refuses via:deepagents.
    cfg = _Cfg(id="claude-sonnet-4-6", via="deepagents")
    with pytest.raises(ValueError, match="Unknown backend"):
        llm.prompt("x", model=cfg)


def test_agentic_deepagents_via_raises_unknown_backend():
    cfg = _Cfg(id="claude-sonnet-4-6", via="deepagents")
    with pytest.raises(ValueError, match="Unknown backend"):
        llm.agentic("x", model=cfg)


@pytest.mark.parametrize("via", ["sdk", "openai", "cli"])
def test_prompt_never_forwards_provider(patched_backends, via):
    # `provider` is a routing hint for preflight and the in-stage harness
    # branches; no registry backend's prompt() accepts it. The dispatcher must
    # never forward it, even when the model config carries one.
    cfg = _Cfg(id="m", via=via, provider="openai")
    llm.prompt("x", model=cfg)
    _, calls = patched_backends[via]
    assert len(calls) == 1
    assert "provider" not in calls[0][3]


def test_prompt_unknown_via_raises(patched_backends):
    cfg = _Cfg(id="m", via="bogus")
    with pytest.raises(ValueError) as ei:
        llm.prompt("x", model=cfg)
    assert "bogus" in str(ei.value)
    # Nothing should have been dispatched.
    for _, calls in patched_backends.values():
        assert calls == []


# agentic() dispatch
def test_agentic_bare_string_dispatches_to_cli(patched_backends):
    out = llm.agentic("go", model="bare-model")
    assert out == "AGENTIC_RESULT"
    _, cli_calls = patched_backends["cli"]
    assert len(cli_calls) == 1
    kind, up, model_id, _ = cli_calls[0]
    assert kind == "agentic"
    assert up == "go"
    assert model_id == "bare-model"


def test_agentic_sdk_dispatch(patched_backends):
    cfg = _Cfg(id="claude-opus-example", via="sdk")
    out = llm.agentic("go", model=cfg)
    assert out == "AGENTIC_RESULT"
    _, sdk_calls = patched_backends["sdk"]
    assert len(sdk_calls) == 1
    assert sdk_calls[0][0] == "agentic"
    assert sdk_calls[0][2] == "claude-opus-example"


def test_agentic_passes_kwargs_through_unmodified(patched_backends):
    # agentic() does NOT strip sdk-only kwargs nor apply extras.
    cfg = _Cfg(id="m", via="sdk", temperature=0.5)
    llm.agentic("go", model=cfg, temperature=0.7, extra="z")
    _, sdk_calls = patched_backends["sdk"]
    kw = sdk_calls[0][3]
    assert kw["temperature"] == 0.7
    assert kw["extra"] == "z"


def test_agentic_unknown_via_raises(patched_backends):
    cfg = _Cfg(id="m", via="nope")
    with pytest.raises(ValueError) as ei:
        llm.agentic("go", model=cfg)
    assert "nope" in str(ei.value)
    for _, calls in patched_backends.values():
        assert calls == []


# validate_detection_tools() — the shared detection-stage allowlist guard
#
# s1/s2/s6 all call this single function (backends/llm/models.py, defined
# beside DEFAULT_READ_TOOLS) inline before any model dispatch. Its truth
# table is pinned HERE, once, over every stage config key and every via;
# each stage test file keeps exactly one integration pin proving the guard
# fires through its run() before any model call and that the stage threads
# the resolved via.
#
# Security property: on `via: sdk` an unsupported or mutating tool (Bash,
# Edit, Write, ...) silently delegates the whole agentic call to the Agent
# SDK backend, which can modify the scanned repository; `via: openai` (and
# any other non-cli via, including deepagents and an unresolved None) gets
# the same strict read-only rule. `via: cli` is legitimately exempt:
# cli.py agentic() forwards the allowlist verbatim via --allowedTools and
# never delegates to another backend — Bash on a via:cli role is a shipped,
# documented capability (see AGENTS.md).

_STAGE_KEYS = [
    "step1.allowed_tools",
    "step2.allowed_tools",
    "step6_verify.allowed_tools",
]
_STRICT_VIAS = [None, "sdk", "openai", "deepagents"]
_ALL_VIAS = [*_STRICT_VIAS, "cli"]


@pytest.mark.parametrize("config_key", _STAGE_KEYS)
@pytest.mark.parametrize("via", _STRICT_VIAS)
@pytest.mark.parametrize("bad_tool", ["Bash", "Edit", "Write", "WebFetch"])
def test_detection_guard_rejects_non_read_tools_on_strict_vias(
        config_key, via, bad_tool):
    # A mutating or unknown tool must fail closed before any model call on
    # every via that cannot honour the allowlist itself. The error names the
    # offending tool.
    with pytest.raises(ValueError, match=bad_tool):
        validate_detection_tools(["Read", bad_tool],
                                 config_key=config_key, via=via)


@pytest.mark.parametrize("config_key", _STAGE_KEYS)
@pytest.mark.parametrize("via", _STRICT_VIAS)
def test_detection_guard_error_names_key_permitted_set_and_via(config_key, via):
    with pytest.raises(ValueError) as exc:
        validate_detection_tools(["Bash"], config_key=config_key, via=via)
    msg = str(exc.value)
    assert config_key in msg                      # names the stage config key
    assert "Bash" in msg                          # names the offender
    assert "Glob" in msg and "Grep" in msg and "Read" in msg  # permitted trio
    assert f"via: {via or 'sdk/openai'}" in msg   # names the via it gated


@pytest.mark.parametrize("config_key", _STAGE_KEYS)
@pytest.mark.parametrize("tools", [["Read", "Glob", "Grep", "Bash"], ["Bash"]])
def test_detection_guard_cli_exemption_returns_the_allowlist_verbatim(
        config_key, tools):
    # cli.py agentic() honours --allowedTools itself and never delegates to
    # another backend, so the guard must not remove the shipped Bash-on-cli
    # capability. Verbatim: same names, same order.
    assert validate_detection_tools(
        tools, config_key=config_key, via="cli") == tools


@pytest.mark.parametrize("config_key", _STAGE_KEYS)
@pytest.mark.parametrize("via", _ALL_VIAS)
def test_detection_guard_defaults_to_the_read_only_triple(config_key, via):
    # Key absent (None) → the shared DEFAULT_READ_TOOLS trio on EVERY via —
    # not any older per-stage fallback that silently included Bash.
    out = validate_detection_tools(None, config_key=config_key, via=via)
    assert out == ["Read", "Glob", "Grep"]
    assert out == list(DEFAULT_READ_TOOLS)


@pytest.mark.parametrize("config_key", _STAGE_KEYS)
@pytest.mark.parametrize("via", _ALL_VIAS)
def test_detection_guard_accepts_a_read_only_subset_verbatim(config_key, via):
    assert validate_detection_tools(
        ["Read", "Grep"], config_key=config_key, via=via) == ["Read", "Grep"]


@pytest.mark.parametrize("config_key", _STAGE_KEYS)
@pytest.mark.parametrize("via", _ALL_VIAS)
def test_detection_guard_rejects_yaml_scalar_on_every_via(config_key, via):
    # `allowed_tools: Read` (a YAML scalar, not a list) used to explode into
    # a per-character tool list; it must raise a clear error naming the key,
    # on every via including cli.
    with pytest.raises(ValueError) as exc:
        validate_detection_tools("Read", config_key=config_key, via=via)
    msg = str(exc.value)
    assert config_key in msg
    assert "list" in msg


@pytest.mark.parametrize("config_key", _STAGE_KEYS)
@pytest.mark.parametrize("via", _ALL_VIAS)
def test_detection_guard_rejects_explicit_empty_list_on_every_via(config_key, via):
    # An explicit [] must NOT silently re-grant the default trio (and,
    # forwarded to via:cli, would omit --allowedTools entirely, granting the
    # CLI's own broader default toolset). Fail closed on every via.
    with pytest.raises(ValueError, match="empty") as exc:
        validate_detection_tools([], config_key=config_key, via=via)
    assert config_key in str(exc.value)


@pytest.mark.parametrize("via", _ALL_VIAS)
def test_detection_guard_rejects_non_string_elements_on_every_via(via):
    # A YAML list with a non-string element (e.g. an unquoted number) is a
    # config error, not a tool grant.
    with pytest.raises(ValueError) as exc:
        validate_detection_tools(["Read", 3],
                                 config_key="step1.allowed_tools", via=via)
    assert "step1.allowed_tools" in str(exc.value)
