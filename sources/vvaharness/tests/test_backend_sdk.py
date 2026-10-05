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

"""Offline unit tests for vvaharness.backends.sdk.

No real network / no real anthropic client: messages.stream is mocked, the
`anthropic` module reference inside sdk is monkeypatched to a fake namespace.
All module-level singletons (sdk._client, sdk._cfg, the _NO_* sets) and the
shared TOKENS counter are reset by an autouse fixture so test order never
matters when the whole suite runs together.
"""
from __future__ import annotations

import os
import ssl
import subprocess
import sys
import types

import pytest

from vvaharness.backends.harness.deepagents.limits import MODEL_MAX_OUTPUT_TOKENS
from vvaharness.backends.harness.models import TruncatedResponseError
from vvaharness.backends.llm import sdk
from vvaharness.util.counters import COUNTERS
from vvaharness.util.tokens import TOKENS

# Fakes

_LAZY_PROBE = (
    "import importlib, sys\n"
    "importlib.import_module('vvaharness.backends.llm.registry')\n"
    "print('LEAKED' if 'anthropic' in sys.modules else 'LAZY')\n"
)


class _FakeBlock:
    def __init__(self, type, text=None):
        self.type = type
        if text is not None:
            self.text = text


class _FakeUsage:
    def __init__(self, data):
        self._data = data

    def model_dump(self):
        return dict(self._data)


class _FakeMessage:
    def __init__(self, content, usage=None, stop_reason="end_turn"):
        self.content = content
        self.usage = usage
        self.stop_reason = stop_reason


class _FakeStream:
    """Context-manager mimicking client.messages.stream(...)."""

    def __init__(self, msg):
        self._msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self._msg


class _FakeMessages:
    def __init__(self, recorder, msg):
        self._recorder = recorder
        self._msg = msg

    def stream(self, **kw):
        self._recorder.append(kw)
        return _FakeStream(self._msg)


class _FakeClient:
    def __init__(self, recorder, msg):
        self.messages = _FakeMessages(recorder, msg)

    def with_options(self, **kw):
        return self


def _install_client(monkeypatch, *, content=None, usage=None,
                    stop_reason="end_turn"):
    """Wire sdk._get_client() to return a fake client. Returns the list that
    captures the kwargs passed to messages.stream()."""
    recorder: list = []
    if content is None:
        content = [_FakeBlock("text", "hello world")]
    msg = _FakeMessage(content,
                       usage=_FakeUsage(usage) if usage is not None else None,
                       stop_reason=stop_reason)
    client = _FakeClient(recorder, msg)
    monkeypatch.setattr(sdk, "_get_client", lambda: client)
    return recorder


# Global-state isolation (critical: full suite runs all files together)

@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    # Reset module singletons / drift sets so order never matters.
    monkeypatch.setattr(sdk, "_client", None)
    monkeypatch.setattr(sdk, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(sdk, "_NO_THINK_MODELS", set())
    # Mirror the module's real _cfg defaults, cache-marker keys included: every
    # consumer reads them through .get() with a default today, but one that
    # indexes directly would fail here for a reason unrelated to its change.
    monkeypatch.setattr(sdk, "_cfg", {
        "api_key": None, "base_url": None, "verify_ssl": True,
        "ca_cert": None, "client_cert": None, "no_proxy": None,
        "allow_api_key_fallback": False,
        "cache_min_block_tokens": None,
        "cache_route": "auto",
        "cache_markers": "on",
    })
    yield


# _supports_temperature / _NO_TEMP_RX matrix

@pytest.mark.parametrize("model", [
    "opus-4-6",
    "claude-opus-4-6",
    "sonnet-4-6",
    "haiku-4-5",
    "claude-sonnet-4-6-20990101",
])
def test_temperature_kept_models(model):
    assert sdk._supports_temperature(model) is True


@pytest.mark.parametrize("model", [
    "opus-4-7",
    "opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "opus-5",
    "sonnet-5",
    "haiku-5",
    "claude-opus-5-0",
    "claude-sonnet-5-1",
])
def test_temperature_dropped_models(model):
    assert sdk._supports_temperature(model) is False


def test_temperature_runtime_blacklist_overrides_regex():
    # A model that the regex would normally allow becomes unsupported once
    # added to the runtime drift set.
    assert sdk._supports_temperature("opus-4-6") is True
    sdk._NO_TEMP_MODELS.add("opus-4-6")
    assert sdk._supports_temperature("opus-4-6") is False


# configure()

def test_configure_stores_cfg_and_clears_client(monkeypatch):
    monkeypatch.setattr(sdk, "_client", object())  # pretend a client exists
    sdk.configure(api_key="sk-ant-EXAMPLE", base_url="https://api.example.test",
                  verify_ssl=False, ca_cert="/tmp/ca.pem",
                  client_cert="/tmp/client.pem")
    assert sdk._cfg["api_key"] == "sk-ant-EXAMPLE"
    assert sdk._cfg["base_url"] == "https://api.example.test"
    assert sdk._cfg["verify_ssl"] is False
    assert sdk._cfg["ca_cert"] == "/tmp/ca.pem"
    assert sdk._cfg["client_cert"] == "/tmp/client.pem"
    # configure() forces a rebuild on next _get_client().
    assert sdk._client is None


def test_configure_stores_no_proxy_without_mutating_environ(monkeypatch):
    # configure() must never touch the real process environment (the fixed bug).
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    sdk.configure(no_proxy="example.com,api.example.test")
    assert sdk._cfg["no_proxy"] == "example.com,api.example.test"
    assert "NO_PROXY" not in os.environ
    assert "no_proxy" not in os.environ


def test_get_client_scopes_no_proxy_env_and_restores_prior_value(monkeypatch):
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setenv("no_proxy", "prior.example")
    mod, _ = _make_fake_anthropic()
    seen: dict[str, str | None] = {}

    class _CapturingAnthropic:
        def __init__(self, **_kw):
            seen["NO_PROXY"] = os.environ.get("NO_PROXY")
            seen["no_proxy"] = os.environ.get("no_proxy")

    mod.Anthropic = _CapturingAnthropic
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    sdk._cfg["no_proxy"] = "example.com"
    sdk._get_client()
    assert seen == {"NO_PROXY": "example.com", "no_proxy": "example.com"}
    # Restored immediately after construction: no permanent global mutation.
    assert "NO_PROXY" not in os.environ
    assert os.environ["no_proxy"] == "prior.example"


def test_configure_partial_does_not_clobber_existing(monkeypatch):
    sdk._cfg["api_key"] = "sk-ant-EXAMPLE-keep"
    sdk.configure(base_url="https://api.example.test")
    # api_key untouched because None was passed for it.
    assert sdk._cfg["api_key"] == "sk-ant-EXAMPLE-keep"
    assert sdk._cfg["base_url"] == "https://api.example.test"


# _get_client — http_client branch logic

class _FakeAnthropicModule(types.SimpleNamespace):
    """Minimal stand-in for the `anthropic` module used by _get_client."""


def _make_fake_anthropic():
    captured = {"anthropic_kw": None, "httpx_kw": None}

    class FakeHttpxClient:
        def __init__(self, **kw):
            captured["httpx_kw"] = kw

    class FakeAnthropic:
        def __init__(self, **kw):
            captured["anthropic_kw"] = kw

    mod = _FakeAnthropicModule(
        DefaultHttpxClient=FakeHttpxClient,
        Anthropic=FakeAnthropic,
    )
    return mod, captured


def test_get_client_no_http_client_when_verify_true(monkeypatch):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    sdk._get_client()
    kw = captured["anthropic_kw"]
    assert "http_client" not in kw  # verify is True, no client_cert
    # Byte-identity pin: the no-TLS-configured construction passes EXACTLY these
    # kwargs — S10's `via: sdk` route must see an unchanged client here.
    assert set(kw) == {"api_key", "max_retries"}
    assert kw["api_key"] == "sk-ant-EXAMPLE"
    assert kw["max_retries"] == 4
    assert captured["httpx_kw"] is None


def test_get_client_uses_oauth_auth_token_and_beta_header(monkeypatch):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-oat-workspace-token")

    sdk._get_client()

    assert captured["anthropic_kw"] == {
        "auth_token": "sk-ant-oat-workspace-token",
        "default_headers": {"anthropic-beta": "oauth-2025-04-20"},
        "max_retries": 4,
    }


def test_get_client_builds_http_client_when_verify_false(monkeypatch, capsys):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    # urllib3 is imported inside the verify-False branch.
    monkeypatch.setitem(__import__("sys").modules, "urllib3",
                        types.SimpleNamespace(
                            exceptions=types.SimpleNamespace(
                                InsecureRequestWarning=Warning)))
    sdk._cfg["verify_ssl"] = False
    sdk._cfg["base_url"] = "https://gateway.internal"
    sdk._get_client()
    assert "http_client" in captured["anthropic_kw"]
    assert captured["httpx_kw"] == {"verify": False}
    # Disabling TLS must NEVER be silent: a loud, endpoint-naming warning fires.
    err = capsys.readouterr().err
    assert "TLS verification DISABLED" in err
    assert "gateway.internal" in err


def _spy_load_cert_chain(monkeypatch):
    """Record SSLContext.load_cert_chain calls (dummy PEMs cannot really parse)."""
    calls: list[tuple] = []
    monkeypatch.setattr(
        ssl.SSLContext, "load_cert_chain", lambda self, *args: calls.append(args))
    return calls


def test_get_client_client_cert_chain_is_actually_loaded(monkeypatch, tmp_path):
    """The kwarg-was-passed assertion this replaces is exactly how the defect
    survived: httpx accepted `cert=` and silently never loaded it. The only
    proof of mTLS is an SSLContext.load_cert_chain call."""
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    cert = tmp_path / "client.pem"
    cert.write_text("dummy")
    calls = _spy_load_cert_chain(monkeypatch)
    sdk._cfg["client_cert"] = str(cert)
    sdk._get_client()
    assert "http_client" in captured["anthropic_kw"]
    # The chain was LOADED, not merely passed along.
    assert calls == [(str(cert),)]
    # httpx ignores `cert=` whenever `verify=` is a str CA path or False, so the
    # kwarg must never be sent; the loaded context rides in as verify=.
    assert "cert" not in captured["httpx_kw"]
    assert isinstance(captured["httpx_kw"]["verify"], ssl.SSLContext)


def test_get_client_ca_bundle_plus_client_cert_loads_the_chain(monkeypatch,
                                                               tmp_path):
    """REGRESSION: with BOTH sdk.ca_cert and sdk.client_cert (the private-CA +
    mTLS gateway deployment), httpx 0.28's create_ssl_context(verify=<str CA
    path>, cert=...) returns before its cert handling — the client certificate
    was silently never presented. The chain must load AND the CA must stay the
    verify basis."""
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    ca = tmp_path / "ca.pem"
    ca.write_text("dummy ca")
    cert = tmp_path / "client.pem"
    cert.write_text("dummy cert")
    key = tmp_path / "client.key"
    key.write_text("dummy key")
    calls = _spy_load_cert_chain(monkeypatch)
    created: dict = {}
    real_context = ssl.create_default_context()

    def capture_create(**kwargs):
        created.update(kwargs)
        return real_context  # a real context; the dummy CA file cannot parse

    monkeypatch.setattr(sdk.httpx, "create_ssl_context", capture_create)
    sdk._cfg["ca_cert"] = str(ca)
    sdk._cfg["client_cert"] = (str(cert), str(key))
    sdk._get_client()
    # CA bundle still the verification basis, client chain actually loaded.
    assert created == {"verify": str(ca), "trust_env": True}
    assert calls == [(str(cert), str(key))]
    assert captured["httpx_kw"] == {"verify": real_context}


def test_get_client_unloadable_client_cert_warns_and_disables_mtls(
        monkeypatch, tmp_path, capsys):
    """A configured client cert that cannot load must fail LOUDLY — the operator
    must never believe mTLS is active when it is not — and must never echo the
    file's contents. Runs against the real load_cert_chain."""
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    cert = tmp_path / "client.pem"
    cert.write_text("not a real pem body")
    sdk._cfg["client_cert"] = str(cert)
    sdk._get_client()
    # verify stayed True and the chain failed -> same shape as no mTLS at all.
    assert "http_client" not in captured["anthropic_kw"]
    err = capsys.readouterr().err
    assert "mTLS is NOT active" in err
    assert str(cert) in err
    assert "not a real pem body" not in err  # path + exception type only


def test_get_client_ca_cert_path_used_as_verify(monkeypatch, tmp_path, capsys):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    ca = tmp_path / "ca.pem"
    ca.write_text("dummy ca")
    sdk._cfg["ca_cert"] = str(ca)
    sdk._get_client()
    # ca_cert path wins over verify_ssl -> passed as verify=<path>.
    assert captured["httpx_kw"]["verify"] == str(ca)
    # Secure path (a CA bundle) must NOT emit the insecure-TLS warning.
    assert "TLS verification DISABLED" not in capsys.readouterr().err


def test_get_client_missing_ca_cert_falls_back(monkeypatch, capsys):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    sdk._cfg["ca_cert"] = "/nonexistent/ca.pem"
    sdk._get_client()
    # Falls back to verify_ssl=True -> no http_client built.
    assert "http_client" not in captured["anthropic_kw"]
    assert "not found" in capsys.readouterr().err


def test_the_dispatcher_does_not_import_this_backend_until_it_is_selected():
    """Replaces a test of the `anthropic is None` guard, which no longer exists.

    That guard was there because importing the dispatcher imported every backend, so a machine
    missing one SDK could run no role at all. The dispatcher now holds import paths and resolves
    one on selection, which is what makes a plain module-level `import anthropic` safe -- so THAT
    is the property worth pinning. In a subprocess, because an import cannot be undone.
    """
    out = subprocess.run(
        [sys.executable, "-c", _LAZY_PROBE], capture_output=True, text=True, check=False
    )
    assert "LAZY" in out.stdout, out.stdout + out.stderr


def test_get_client_caches_singleton(monkeypatch):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    c1 = sdk._get_client()
    c2 = sdk._get_client()
    assert c1 is c2


# prompt() — needs anthropic.APIStatusError / APIConnectionError to exist for
# the except clauses to be importable; install a fake anthropic with those.

@pytest.fixture
def _fake_anthropic_exc(monkeypatch):
    class APIStatusError(Exception):
        def __init__(self, message="", status_code=400):
            super().__init__(message)
            self.message = message
            self.status_code = status_code

    class APIConnectionError(Exception):
        pass

    mod = types.SimpleNamespace(
        APIStatusError=APIStatusError,
        APIConnectionError=APIConnectionError,
    )
    monkeypatch.setattr(sdk, "anthropic", mod)
    return mod


def test_prompt_returns_stripped_text(monkeypatch, _fake_anthropic_exc):
    rec = _install_client(monkeypatch,
                          content=[_FakeBlock("text", "  answer  ")])
    out = sdk.prompt("hi", model="opus-4-6")
    assert out == "answer"
    # default max_tokens applied.
    assert rec[0]["max_tokens"] == 16000
    assert rec[0]["model"] == "opus-4-6"
    assert rec[0]["messages"] == [{"role": "user", "content": "hi"}]


def test_prompt_temperature_kept_for_supporting_model(monkeypatch,
                                                      _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-6", temperature=0.7)
    assert rec[0]["temperature"] == 0.7


def test_prompt_temperature_dropped_for_nontemp_model(monkeypatch, capsys,
                                                      _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-8", temperature=0.7)
    assert "temperature" not in rec[0]
    # model recorded in drift set so subsequent calls skip silently.
    assert "opus-4-8" in sdk._NO_TEMP_MODELS
    assert "does not accept" in capsys.readouterr().err


def test_prompt_thinking_budget_yields_adaptive_and_drops_temperature(
        monkeypatch, _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-6", temperature=0.5, thinking_budget=10000)
    kw = rec[0]
    assert kw["thinking"] == {"type": "adaptive"}
    # temperature is dropped while thinking is on.
    assert "temperature" not in kw


def test_prompt_thinking_budget_bumps_max_tokens_for_headroom(
        monkeypatch, _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    # max_tokens (5000) <= thinking_budget (10000) -> bumped to budget + 8000.
    sdk.prompt("hi", model="opus-4-6", max_tokens=5000, thinking_budget=10000)
    assert rec[0]["max_tokens"] == 18000


def test_prompt_thinking_skipped_for_no_think_model(monkeypatch,
                                                    _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk._NO_THINK_MODELS.add("opus-4-6")
    sdk.prompt("hi", model="opus-4-6", thinking_budget=10000, temperature=0.5)
    assert "thinking" not in rec[0]
    # temperature survives because thinking branch was skipped.
    assert rec[0]["temperature"] == 0.5


def test_prompt_sub_minimum_system_prompt_stays_plain_string(
        monkeypatch, _fake_anthropic_exc):
    # The system-block cache marker is no longer unconditional: it obeys the
    # kill switch + route + per-model minimum gate in _build_system_content.
    # This prompt sits far below every published minimum, so marking it would
    # spend a breakpoint slot while the API silently caches nothing — the
    # correct wire form is the plain string. The full gate matrix (route
    # capability, above-minimum marked list, kill switch, operator overrides)
    # lives in tests/test_backend_cache.py.
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-6", system_prompt="you are helpful")
    assert rec[0]["system"] == "you are helpful"


def test_prompt_betas_set_header(monkeypatch, _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-6", betas=["beta-a", "beta-b"])
    assert rec[0]["extra_headers"] == {"anthropic-beta": "beta-a,beta-b"}


def test_prompt_usage_total_is_input_plus_caches(monkeypatch, capsys,
                                                 _fake_anthropic_exc):
    _install_client(monkeypatch, usage={
        "input_tokens": 100,
        "cache_creation_input_tokens": 30,
        "cache_read_input_tokens": 20,
        "output_tokens": 7,
    })
    sdk.prompt("hi", model="opus-4-6")
    # The printed "in=" reflects fresh + cache_create + cache_read = 150.
    assert "in=150" in capsys.readouterr().err
    # TOKENS headline prompt = fresh + cache_write (not cache_read) = 130.
    snap = TOKENS.snapshot()
    assert snap["prompt"] == 130
    assert snap["completion"] == 7


def test_prompt_usage_none_still_counts_call(monkeypatch, _fake_anthropic_exc):
    _install_client(monkeypatch, usage=None)
    sdk.prompt("hi", model="opus-4-6")
    snap = TOKENS.snapshot()
    assert snap["calls"] == 1
    assert snap["calls_with_usage"] == 0


# prompt() — VVAH-E005: stop_reason="max_tokens" (output budget exhausted)

def _install_seq_client(monkeypatch, msgs):
    """Client whose stream() serves one canned final message per call."""
    recorder: list = []

    class _SeqMessages:
        def stream(self, **kw):
            recorder.append(kw)
            return _FakeStream(msgs[len(recorder) - 1])

    class _SeqClient:
        def __init__(self):
            self.messages = _SeqMessages()

        def with_options(self, **_kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _SeqClient())
    return recorder


def test_prompt_truncated_below_cap_retries_once_then_succeeds(
        monkeypatch, _fake_anthropic_exc):
    cut = _FakeMessage([_FakeBlock("text", "partial")],
                       stop_reason="max_tokens")
    ok = _FakeMessage([_FakeBlock("text", "z" * 400)], stop_reason="end_turn")
    rec = _install_seq_client(monkeypatch, [cut, ok])

    out = sdk.prompt("hi", model="claude-x", max_tokens=16000)

    assert out == "z" * 400
    assert [kw["max_tokens"] for kw in rec] == [16000, 32000]


def test_prompt_truncated_twice_raises_e005_and_bumps_counter(
        monkeypatch, _fake_anthropic_exc):
    cut1 = _FakeMessage([_FakeBlock("text", "p1")], stop_reason="max_tokens")
    cut2 = _FakeMessage([_FakeBlock("text", "p2")], stop_reason="max_tokens")
    rec = _install_seq_client(monkeypatch, [cut1, cut2])

    with pytest.raises(TruncatedResponseError) as ei:
        sdk.prompt("hi", model="claude-x", max_tokens=1000)

    assert "VVAH-E005" in str(ei.value)
    assert [kw["max_tokens"] for kw in rec] == [1000, 2000]
    assert COUNTERS.snapshot().get("llm_truncated_replies", 0) == 1


def test_prompt_truncated_at_model_cap_raises_e005_without_retry(
        monkeypatch, _fake_anthropic_exc):
    """A request already at MODEL_MAX_OUTPUT_TOKENS gets no retry: one send, then fail loud."""
    rec = _install_client(monkeypatch,
                          content=[_FakeBlock("text", "partial")],
                          stop_reason="max_tokens")

    with pytest.raises(TruncatedResponseError) as ei:
        sdk.prompt("hi", model="claude-x",
                   max_tokens=MODEL_MAX_OUTPUT_TOKENS)

    assert "VVAH-E005" in str(ei.value)
    assert len(rec) == 1
    assert str(MODEL_MAX_OUTPUT_TOKENS) in str(ei.value)


def test_prompt_end_turn_never_trips_truncation(monkeypatch,
                                                _fake_anthropic_exc):
    rec = _install_client(monkeypatch,
                          content=[_FakeBlock("text", "w" * 400)],
                          stop_reason="end_turn")
    assert sdk.prompt("hi", model="claude-x") == "w" * 400
    assert len(rec) == 1


def test_prompt_concatenates_text_blocks_only(monkeypatch, _fake_anthropic_exc):
    _install_client(monkeypatch, content=[
        _FakeBlock("thinking", "internal"),  # has .text but type != text
        _FakeBlock("text", "part1 "),
        _FakeBlock("tool_use"),              # no .text attr; skipped by type
        _FakeBlock("text", "part2"),
    ])
    out = sdk.prompt("hi", model="opus-4-6")
    assert out == "part1 part2"


def test_prompt_recovers_after_temperature_rejection(monkeypatch,
                                                     _fake_anthropic_exc):
    # A 400 naming `temperature` drops the param and re-sends; the live-bound
    # retry loop must iterate to the cleaned send rather than abandoning it.
    exc = _fake_anthropic_exc
    calls = {"n": 0}

    class _Stream:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            return _FakeMessage([_FakeBlock("text", "ok")], usage=None)

    class _Messages:
        def stream(self, **kw):
            calls["n"] += 1
            if calls["n"] == 1 and "temperature" in kw:
                raise exc.APIStatusError("unexpected parameter: temperature",
                                         status_code=400)
            return _Stream()

    class _Client:
        messages = _Messages()

        def with_options(self, **k):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    out = sdk.prompt("hi", model="opus-4-6", temperature=0.7)
    assert out == "ok"
    assert calls["n"] == 2  # rejected once on `temperature`, re-sent without it
    assert "opus-4-6" in sdk._NO_TEMP_MODELS


# Transient classifier: retry 429/5xx AND the transients that arrive as an
# APIStatusError with a 200 HTTP status (SDK built-in retry misses them) —
# mid-stream server_error and gateway rate-limit prose; terminal 4xx
# (auth/model/param) are not retried.

def test_is_transient_sdk_retries_5xx_and_midstream_server_error():
    NS = types.SimpleNamespace
    assert sdk._is_transient_sdk(NS(status_code=503, message="unavailable")) is True
    assert sdk._is_transient_sdk(NS(status_code=429, message="slow down")) is True
    assert sdk._is_transient_sdk(NS(status_code=529, message="overloaded")) is True
    assert sdk._is_transient_sdk(NS(status_code=500, message="internal error")) is True
    assert sdk._is_transient_sdk(NS(status_code=504, message="gateway timeout")) is True
    # mid-stream error: HTTP 200 but an error body of type server_error/overloaded
    assert sdk._is_transient_sdk(
        NS(status_code=200, message="{'type': 'error', 'error': {'type': 'server_error'}}")) is True
    assert sdk._is_transient_sdk(NS(status_code=200, message="Overloaded")) is True


def test_is_transient_sdk_does_not_retry_terminal_4xx():
    NS = types.SimpleNamespace
    assert sdk._is_transient_sdk(NS(status_code=400, message="invalid model")) is False
    assert sdk._is_transient_sdk(NS(status_code=401, message="bad key")) is False
    assert sdk._is_transient_sdk(NS(status_code=404, message="no such model")) is False


def test_is_transient_sdk_retries_gateway_rate_limit_prose_under_200():
    """Regression: the gateway reported a rate-limit transient inside
    an HTTP 200 error payload; the old classifier rejected it and S6 permanently
    lost the verification unit."""
    assert sdk._is_transient_sdk(types.SimpleNamespace(
        status_code=200,
        message="Rate limiting temporarily unavailable. Please try again.")) is True


def test_is_transient_sdk_keeps_pre_promotion_coverage():
    """Sharing the classifiers via models.py must not drop a phrase the old
    sdk-only regex (server_error|overloaded|service unavailable) matched."""
    NS = types.SimpleNamespace
    for phrase in ("server_error", "overloaded", "service unavailable"):
        assert sdk._is_transient_sdk(NS(status_code=200, message=phrase)) is True


def test_is_transient_sdk_message_widening_excludes_permanent_errors():
    """A permanent in-band error must not ride the rate-limit prose fallback
    into the backoff ladder."""
    assert sdk._is_transient_sdk(types.SimpleNamespace(
        status_code=200,
        message="{'type': 'error', 'error': {'type': 'invalid_request_error'}}")) is False


@pytest.mark.parametrize("status", [401, 403])
def test_is_transient_sdk_explicit_auth_status_beats_transient_prose(status):
    """Prose may not promote an explicit auth status: a 401/403 cannot heal on a
    retry, however transient its wording, and a proxy/DLP block page returned under
    one routinely says "Service Unavailable". The message fallback exists for
    statuses no set can classify, never to override a definite 401/403.

    Belt and braces with prompt()'s branch order: agentic() has no auth branch at
    all, so without this it would burn its whole ladder on an unhealable status."""
    NS = types.SimpleNamespace
    assert sdk._is_transient_sdk(NS(
        status_code=status,
        message="Rate limiting temporarily unavailable. Please try again.")) is False
    assert sdk._is_transient_sdk(NS(status_code=status,
                                    message="overloaded")) is False


def test_is_transient_sdk_auth_guard_does_not_narrow_status_behaviour():
    """The VVAH-E001 guard is scoped to explicit auth statuses: a genuinely
    retryable STATUS stays transient even with auth prose in the body."""
    from vvaharness.backends.llm.models import RETRYABLE_STATUS

    for status in RETRYABLE_STATUS:
        assert sdk._is_transient_sdk(types.SimpleNamespace(
            status_code=status, message="invalid api key")) is True


def test_prompt_persistent_401_raises_authentication_error_at_production_values(
        monkeypatch, _fake_anthropic_exc):
    """The auth ladder must not consume the whole send budget.

    _AUTH_MAX_RETRIES_SDK and `attempts` were both 3, so all three sends went to a
    `continue` and the AuthenticationError raise was UNREACHABLE: a wrong credential
    exhausted the loop and surfaced as the post-loop "every attempt hit a
    parameter-drop retry" RuntimeError, losing the typed error, the VVAH-E001
    error_code in errors.jsonl and the batch halt. Deliberately does NOT patch the
    retry count -- patching it to 0 is what hid this."""
    from vvaharness.backends.harness.models import AuthenticationError

    err = _fake_anthropic_exc.APIStatusError("unauthorized", status_code=401)

    class _Msgs:
        def stream(self, **kw):
            raise err

    class _Client:
        messages = _Msgs()

        def with_options(self, **kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    monkeypatch.setattr(sdk.time, "sleep", lambda s: None)
    with pytest.raises(AuthenticationError) as ei:
        sdk.prompt("hi", model="opus-4-6")
    assert ei.value.status_code == 401


def test_prompt_retryable_status_with_auth_prose_stays_on_the_transient_ladder(
        monkeypatch, _fake_anthropic_exc):
    """Deciding auth before transient must not steal a healable outage. A 503 whose
    payload happens to say "authentication_failed" is an overload, and the 60s ladder
    is what rides it out -- only a status no retry can help is auth."""
    err = _fake_anthropic_exc.APIStatusError(
        "authentication_failed upstream; service unavailable", status_code=503)
    calls = {"n": 0}

    class _Msgs:
        def stream(self, **kw):
            calls["n"] += 1
            raise err

    class _Client:
        messages = _Msgs()

        def with_options(self, **kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    waits: list[int] = []
    monkeypatch.setattr(sdk.time, "sleep", lambda s: waits.append(s))
    with pytest.raises(RuntimeError):
        sdk.prompt("hi", model="opus-4-6")
    assert calls["n"] == 3            # the full transient budget, not the auth ladder
    assert waits == [60, 60]          # 60s spacing, not the auth backoff 2/4/8


def test_prompt_oversized_prompt_400_is_not_diagnosed_as_auth(
        monkeypatch, _fake_anthropic_exc):
    """`invalid.*token` was unanchored, so a real 400 reading "invalid_request_error
    ... prompt is too long: 300000 tokens > 200000 maximum" matched it and an oversized
    chunk was reported three times as an authentication error -- unfixable from the
    diagnostics. The bound keeps genuine auth prose matching."""
    from vvaharness.backends.harness.models import AuthenticationError

    err = _fake_anthropic_exc.APIStatusError(
        "Error code: 400 - {'type': 'invalid_request_error', 'message': "
        "'prompt is too long: 300000 tokens > 200000 maximum'}", status_code=400)

    class _Msgs:
        def stream(self, **kw):
            raise err

    class _Client:
        messages = _Msgs()

        def with_options(self, **kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    monkeypatch.setattr(sdk.time, "sleep", lambda s: None)
    with pytest.raises(RuntimeError) as ei:
        sdk.prompt("hi", model="opus-4-6")
    assert not isinstance(ei.value, AuthenticationError)
    assert "prompt is too long" in str(ei.value)


def test_prompt_in_band_auth_and_transient_prose_reaches_auth_path(
        monkeypatch, _fake_anthropic_exc):
    """Regression: the in-band-error gateway case, which the status
    guard cannot catch and only branch ORDER fixes.

    An HTTP 200 payload carrying BOTH auth prose and transient prose used to take
    the 60s transient ladder twice, then exit the loop with `msg is None` and die
    on the post-loop parameter-drop guard — losing AuthenticationError, the
    VVAH-E001 error_code, the credential remediation block and the batch halt.
    Deciding auth first must surface it on the first send."""
    from vvaharness.backends.harness.models import AuthenticationError

    monkeypatch.setattr(sdk, "_AUTH_MAX_RETRIES_SDK", 0)  # no backoff sleeps
    calls = {"n": 0}
    err = _fake_anthropic_exc.APIStatusError(
        "unauthorized: token expired. Rate limiting temporarily unavailable. "
        "Please try again.", status_code=200)

    class _Msgs:
        def stream(self, **kw):
            calls["n"] += 1
            raise err

    class _Client:
        messages = _Msgs()

        def with_options(self, **kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    sleeps: list[int] = []
    monkeypatch.setattr(sdk.time, "sleep", lambda s: sleeps.append(s))
    with pytest.raises(AuthenticationError):
        sdk.prompt("hi", model="opus-4-6")
    assert calls["n"] == 1     # straight to the auth branch, no transient ladder
    assert sleeps == []


@pytest.mark.parametrize("phrase", ["Internal server error", "Bad Gateway"])
def test_is_transient_sdk_prose_wrapped_5xx_under_200(phrase, _fake_anthropic_exc):
    """The machine token `server_error` needs its underscore, so a gateway that
    prose-wraps a 500/502 inside an HTTP 200 payload must be matched explicitly or
    the work unit is lost."""
    assert sdk._is_transient_sdk(_fake_anthropic_exc.APIStatusError(
        phrase, status_code=200)) is True


@pytest.mark.parametrize("status,body", [
    (401, "unauthorized; rate limit temporarily unavailable, try again"),
    (403, "invalid api key (rate limited by gateway policy)"),
])
def test_prompt_auth_status_with_transient_prose_takes_auth_path(
        monkeypatch, _fake_anthropic_exc, status, body):
    """Regression: an auth error whose body carries rate-limit
    prose must reach the VVAH-E001 auth path on the FIRST attempt, not burn the
    transient ladder first."""
    from vvaharness.backends.harness.models import AuthenticationError

    monkeypatch.setattr(sdk, "_AUTH_MAX_RETRIES_SDK", 0)  # no backoff sleeps
    calls = {"n": 0}
    err = _fake_anthropic_exc.APIStatusError(body, status_code=status)

    class _Msgs:
        def stream(self, **kw):
            calls["n"] += 1
            raise err

    class _Client:
        messages = _Msgs()

        def with_options(self, **kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    sleeps: list[int] = []
    monkeypatch.setattr(sdk.time, "sleep", lambda s: sleeps.append(s))
    with pytest.raises(AuthenticationError) as ei:
        sdk.prompt("hi", model="opus-4-6")
    assert ei.value.status_code == status
    assert calls["n"] == 1     # first send went straight to the auth branch
    assert sleeps == []        # no 60s transient waits


def test_transport_owning_backends_share_one_retry_set():
    """sdk and openai both own their HTTP transport, so they retry the same statuses."""
    from vvaharness.backends.llm import openai as oai
    from vvaharness.backends.llm.models import CLI_RETRYABLE_STATUS, RETRYABLE_STATUS

    for status in RETRYABLE_STATUS:
        assert sdk._is_transient_sdk(types.SimpleNamespace(status_code=status, message="")) is True
        assert oai._is_transient_oai(types.SimpleNamespace(status_code=status)) is True
    # The CLI's own binary already retried 500/504 before returning.
    assert CLI_RETRYABLE_STATUS == RETRYABLE_STATUS - {500, 504}


def test_sdk_error_body_is_redacted_in_runtimeerror(monkeypatch):
    """A credential reflected in the provider error body must be scrubbed
    before it lands in the raised RuntimeError text."""
    fake_anthropic = types.SimpleNamespace(
        APIStatusError=type("APIStatusError", (Exception,), {}),
        APIConnectionError=type("APIConnectionError", (Exception,), {}),
    )
    monkeypatch.setattr(sdk, "anthropic", fake_anthropic)

    secret = "ghp_" + "a" * 36
    err = fake_anthropic.APIStatusError(f"rejected token={secret}")
    err.message = f"rejected token={secret}"
    err.status_code = 400

    class _Msgs:
        def stream(self, **kw):
            raise err

    class _Client:
        messages = _Msgs()

        def with_options(self, **kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())

    with pytest.raises(RuntimeError) as ei:
        sdk.prompt("hi", model="opus-4-6")
    msg = str(ei.value)
    assert secret not in msg
    assert "[REDACTED" in msg


# Redaction ordering: redact() must see the FULL error body BEFORE any [:400]
# truncation. Truncating first can cut a JWT's third segment (or a PEM end
# marker) below the pattern minimum, after which redact() no longer matches and
# raw credential material survives into the exception message.

_JWT_HEADER = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
_JWT_PAYLOAD = "eyJzdWIiOiJ2dmFoLXNjYW4iLCJleHAiOjIwMDAwMDAwMDB9"
_JWT_SIG = "U2VjcmV0U2lnbmF0dXJlTWF0ZXJpYWw" * 4
_JWT = f"{_JWT_HEADER}.{_JWT_PAYLOAD}.{_JWT_SIG}"


def _assert_no_jwt_fragment(msg: str) -> None:
    """No 12-char window of the token may survive anywhere in `msg`."""
    for i in range(len(_JWT) - 12):
        assert _JWT[i:i + 12] not in msg


def _spy_redact(monkeypatch) -> list[str]:
    """Record every body handed to sdk.redact while keeping real redaction."""
    seen: list[str] = []
    real_redact = sdk.redact

    def spy(text):
        seen.append(text)
        return real_redact(text)

    monkeypatch.setattr(sdk, "redact", spy)
    return seen


def test_auth_error_redacts_full_body_before_truncation(monkeypatch,
                                                        _fake_anthropic_exc):
    """REGRESSION: redact(body[:400]) truncated the JWT's third segment below
    the pattern's 10-char minimum, so redaction missed and ~raw token text
    reached the AuthenticationError (printed by preflight/doctor, recorded in
    *_errors.jsonl). The order must be redact-then-truncate."""
    from vvaharness.backends.harness.models import AuthenticationError

    monkeypatch.setattr(sdk, "_AUTH_MAX_RETRIES_SDK", 0)  # no backoff sleeps
    seen = _spy_redact(monkeypatch)

    body = ("gateway rejected the request; " * 20)[:299] + "presented " + _JWT
    sig_start = body.index(_JWT_SIG)
    # Geometry pin: >400 chars total, and [:400] leaves a <10-char third JWT
    # segment — exactly the shape that defeated truncate-first redaction.
    assert len(body) > 400 > sig_start
    assert 400 - sig_start < 10

    err = _fake_anthropic_exc.APIStatusError(body, status_code=401)

    class _Msgs:
        def stream(self, **kw):
            raise err

    class _Client:
        messages = _Msgs()

        def with_options(self, **kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    with pytest.raises(AuthenticationError) as ei:
        sdk.prompt("hi", model="opus-4-6")
    # The FULL, untruncated body reached redact().
    assert seen and seen[0] == body
    msg = str(ei.value)
    assert "[REDACTED-JWT]" in msg
    _assert_no_jwt_fragment(msg)


def test_proxy_error_redacts_full_cause_chain_before_truncation(
        monkeypatch, _fake_anthropic_exc):
    """Same ordering pin for the ProxyError path, whose text comes from the
    connection error's __cause__ chain."""
    from vvaharness.backends.harness.models import ProxyError

    seen = _spy_redact(monkeypatch)
    cause_text = ("certificate verify failed at the corporate proxy; "
                  * 6)[:288] + "presented " + _JWT
    cause = ValueError(cause_text)
    err = _fake_anthropic_exc.APIConnectionError("connection refused")
    err.__cause__ = cause
    detail = f"ValueError: {cause_text}"
    sig_start = detail.index(_JWT_SIG)
    assert len(detail) > 400 > sig_start
    assert 400 - sig_start < 10

    class _Msgs:
        def stream(self, **kw):
            raise err

    class _Client:
        messages = _Msgs()

        def with_options(self, **kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    with pytest.raises(ProxyError) as ei:
        sdk.prompt("hi", model="opus-4-6")
    # The FULL, untruncated cause chain reached redact().
    assert seen and seen[0] == detail
    msg = str(ei.value)
    assert "[REDACTED-JWT]" in msg
    _assert_no_jwt_fragment(msg)


def test_mtls_pair_pre_check_names_the_member_that_is_actually_missing(
    tmp_path, capsys
):
    """FIX: a pair with an absent KEY must name the key, not the cert.

    Red before: `_mtls_verify` guarded its pre-check with `isinstance(str)`, so
    only the combined-PEM form was existence-checked. A `(cert, key)` pair fell
    through to `load_client_chain`, whose warning names `args[0]` — the cert,
    which was present — sending the operator to inspect the wrong file. Every
    shape now goes through `resolve_client_chain`.
    """
    cert = tmp_path / "client.pem"
    cert.write_text("certificate placeholder", encoding="utf-8")
    missing_key = tmp_path / "absent.key"
    sdk._cfg["client_cert"] = (str(cert), str(missing_key))
    assert sdk._mtls_verify(True) is True  # mTLS disabled, verify unchanged
    err = capsys.readouterr().err
    assert str(missing_key) in err, "the warning must name the MISSING member"
    assert "disabling mTLS" in err
    assert "could not be loaded" not in err, "should not reach the loader at all"



# ─────────────────────────────────────────────────────────────────────────────
# agentic() caller-supplied tools (extra_tools / extra_dispatch), the tool-result
# cap, and the forced-final. These back the exploit-verification attacker loop,
# which drives agentic() with its own http_request tool instead of a parallel loop.
# ─────────────────────────────────────────────────────────────────────────────

class _ToolUseBlock:
    def __init__(self, id, name, input):
        self.type = "tool_use"
        self.id = id
        self.name = name
        self.input = input


def _seq_client(monkeypatch, messages):
    """Wire sdk._get_client() to a fake whose messages.stream() returns the scripted
    `messages` in order (one per turn). Returns the list capturing stream() kwargs."""
    recorder: list = []
    it = iter(messages)

    class _Stream:
        def __init__(self, msg):
            self._m = msg

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            return self._m

    class _Msgs:
        def stream(self, **kw):
            recorder.append(kw)
            result = next(it)
            if isinstance(result, BaseException):
                raise result
            return _Stream(result)

    class _Client:
        messages = _Msgs()

        def with_options(self, **k):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    return recorder


def _probe_schema():
    return {"name": "probe", "description": "x",
            "input_schema": {"type": "object", "properties": {}}}


def _tool_results(stream_kwargs):
    return [b for m in stream_kwargs["messages"] if isinstance(m.get("content"), list)
            for b in m["content"] if isinstance(b, dict) and b.get("type") == "tool_result"]


def test_agentic_dispatches_extra_tool_then_returns_final(monkeypatch):
    rec = _seq_client(monkeypatch, [
        _FakeMessage([_ToolUseBlock("t1", "probe", {"q": "x"})], stop_reason="tool_use"),
        _FakeMessage([_FakeBlock("text", "VERDICT")], stop_reason="end_turn"),
    ])
    seen = []
    out = sdk.agentic("go", model="m", system_prompt="sys", allowed_tools=[], cwd=".",
                      extra_tools=[_probe_schema()],
                      extra_dispatch=lambda n, a: (seen.append((n, a)) or "TOOLOUT"))
    assert out == "VERDICT"
    assert seen == [("probe", {"q": "x"})]                       # caller tool ran
    tr = _tool_results(rec[1])                                   # fed back on turn 2
    assert tr and tr[0]["content"] == "TOOLOUT"
    assert any(t["name"] == "probe" for t in rec[0]["tools"])    # advertised to the model


def test_agentic_extra_dispatch_defers_to_localtools(monkeypatch):
    # extra_dispatch returns None → the name is a localtools tool, executed with cwd.
    calls = []
    monkeypatch.setattr(sdk._localtools, "execute",
                        lambda name, args, *, cwd: calls.append((name, cwd)) or "FILE")
    rec = _seq_client(monkeypatch, [
        _FakeMessage([_ToolUseBlock("t1", "Read", {"path": "app.py"})], stop_reason="tool_use"),
        _FakeMessage([_FakeBlock("text", "ok")], stop_reason="end_turn"),
    ])
    out = sdk.agentic("go", model="m", system_prompt="s", allowed_tools=["Read"], cwd="/repo",
                      extra_tools=[_probe_schema()], extra_dispatch=lambda n, a: None)
    assert out == "ok"
    assert calls == [("Read", "/repo")]                          # localtools ran, right cwd
    assert _tool_results(rec[1])[0]["content"] == "FILE"


def test_agentic_forces_final_at_turn_budget(monkeypatch):
    # The model never converges (always a tool_use); after max_turns the loop forces a
    # final answer with tools disabled and returns its text.
    def tool_turn():
        return _FakeMessage([_ToolUseBlock("t", "probe", {})], stop_reason="tool_use")
    rec = _seq_client(monkeypatch,
                      [tool_turn(), tool_turn(),
                       _FakeMessage([_FakeBlock("text", "FORCED")], stop_reason="end_turn")])
    out = sdk.agentic("go", model="m", system_prompt="s", allowed_tools=[], cwd=".",
                      extra_tools=[_probe_schema()], extra_dispatch=lambda n, a: "R",
                      max_turns=2)
    assert out == "FORCED"
    assert rec[2].get("tool_choice") == {"type": "none"}         # 3rd call = forced-final


def test_agentic_forced_final_retries_transient(monkeypatch):
    class _Transient(Exception):
        status_code = 503
        message = "overloaded"

    monkeypatch.setattr(sdk.anthropic, "APIStatusError", _Transient)
    monkeypatch.setattr(sdk, "_is_transient_sdk", lambda _e: True)
    monkeypatch.setattr(sdk.time, "sleep", lambda _seconds: None)

    def tool_turn():
        return _FakeMessage([_ToolUseBlock("t", "probe", {})], stop_reason="tool_use")

    rec = _seq_client(monkeypatch, [tool_turn(), _Transient(),
                                    _FakeMessage([_FakeBlock("text", "FORCED")])])
    out = sdk.agentic("go", model="m", allowed_tools=[], cwd=".",
                      extra_tools=[_probe_schema()], extra_dispatch=lambda _n, _a: "R",
                      max_turns=1)
    assert out == "FORCED"
    assert rec[1].get("tool_choice") == {"type": "none"}
    assert rec[2].get("tool_choice") == {"type": "none"}


def test_agentic_sdk_transient_budget_resets_per_turn(monkeypatch):
    class _Transient(Exception):
        status_code = 503
        message = "overloaded"

    monkeypatch.setattr(sdk.anthropic, "APIStatusError", _Transient)
    monkeypatch.setattr(sdk, "_is_transient_sdk", lambda _e: True)
    monkeypatch.setattr(sdk.time, "sleep", lambda _seconds: None)

    def tool_turn():
        return _FakeMessage([_ToolUseBlock("t", "probe", {})], stop_reason="tool_use")

    rec = _seq_client(monkeypatch, [_Transient(), tool_turn(), _Transient(),
                                    _FakeMessage([_FakeBlock("text", "DONE")])])
    out = sdk.agentic("go", model="m", allowed_tools=[], cwd=".",
                      extra_tools=[_probe_schema()], extra_dispatch=lambda _n, _a: "R",
                      max_turns=2)
    assert out == "DONE"
    assert len(rec) == 4
