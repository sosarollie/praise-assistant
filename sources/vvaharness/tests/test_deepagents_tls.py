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

"""Optional TLS/mTLS on the deepagents model-building route (Spec §4).

Covers: client-cert plumbing on both vendor branches (through REAL httpx —
``create_ssl_context(verify=<str>)`` returns before its ``cert=`` handling, so
only an explicit ``load_cert_chain`` call proves the chain is loaded), the
ambient-CA scoping (Node/requests CA conventions are OpenAI-branch-only), the
``verify_ssl`` tri-state (shared with ``coerce_verify``) with ``ca_cert``
winning over it (sdk/openai parity), the ambient-``VVAHARNESS_TLS_VERIFY``
rejection, the TLS-aware model cache key, the shared ``tls_carriers_for``
helper (folded into ``backends.llm.deepagents.build_harness_env`` — the
DETECTION-seam env used by detection dispatch and the preflight probe; the
S10/S11 invoker deliberately does NOT merge it, see
``test_s10_plugin_runner_env_is_credentials_only``), the stamped ``no_proxy``
carrier (proxy-bypass parity with via: sdk/openai on the seams that merge
carriers, plus the injected-shape ``http_socket_options=()`` warning knob), the
no-TLS/carrier-less regression guards for S10/S11, the ``ChatAnthropic``
private-surface canary, and the missing/malformed-file paths (missing warns
and continues; malformed CA fails closed). No test opens a socket — the
autouse ``_deny_network`` fixture in conftest.py enforces that.
"""

from __future__ import annotations

import asyncio
import functools
import os
import ssl
import threading
from pathlib import Path
from types import SimpleNamespace

import anthropic
import certifi
import httpx
import pytest
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from vvaharness.backends.harness.deepagents import client as da_client
from vvaharness.backends.harness.deepagents.models import (
    SSL_CERT_DIR_VAR,
    SSL_CERT_FILE_VAR,
    TLS_CLIENT_CERT_VAR,
    TLS_CLIENT_KEY_VAR,
    TLS_VERIFY_VAR,
    CompiledGraph,
)
from vvaharness.backends.harness.deepagents.options import model_building
from vvaharness.backends.harness.models import OneShotOptions, StreamingOptions
from vvaharness.backends.llm import tls
from vvaharness.backends.llm.tls import coerce_verify

#: Derived from the module under test so the clean-env fixture can never drift
#: behind a new name added to the TLS lookup set.
_AMBIENT_TLS_VARS = model_building._TLS_ENV_VARS

#: A real, parseable CA bundle that exists on every test machine (httpx depends
#: on certifi), standing in for a private-CA bundle wherever the code path
#: actually PARSES the file rather than merely checking it exists.
_REAL_CA = certifi.where()


@pytest.fixture(autouse=True)
def _clean_tls_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip ambient TLS env vars so the host machine cannot skew any test."""
    for var in _AMBIENT_TLS_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture()
def _fresh_cache() -> None:
    """Empty the module-level model cache so cache-behaviour tests start clean."""
    model_building._model_cache.clear()


def _write_pem(tmp_path: Path, name: str) -> str:
    """Create a placeholder PEM file and return its path as a string."""
    pem = tmp_path / name
    pem.write_text("certificate placeholder", encoding="utf-8")
    return str(pem)


def _capture_ssl_context(
    monkeypatch: pytest.MonkeyPatch, captured: dict[str, object]
) -> ssl.SSLContext:
    """Stub ``httpx.create_ssl_context`` to record kwargs and return a real context."""
    context = ssl.create_default_context()

    def fake_create(**kwargs: object) -> ssl.SSLContext:
        captured.update(kwargs)
        return context

    monkeypatch.setattr(model_building.httpx, "create_ssl_context", fake_create)
    return context


def _spy_load_cert_chain(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Record ``SSLContext.load_cert_chain`` calls (placeholder PEMs cannot parse)."""
    calls: list[tuple] = []
    monkeypatch.setattr(
        ssl.SSLContext, "load_cert_chain", lambda self, *args: calls.append(args)
    )
    return calls


def _stamped(raw: str) -> str:
    """Wrap *raw* the way ``tls_carriers_for`` emits it: a config-stamped carrier value."""
    return model_building._TLS_VERIFY_STAMP + raw


# Client certificate — OpenAI branch


def test_client_cert_reaches_openai_http_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A combined-PEM client cert is loaded onto the context behind the httpx clients."""
    cert = _write_pem(tmp_path, "client.pem")
    calls = _spy_load_cert_chain(monkeypatch)
    env = {"OPENAI_API_KEY": "sk-test", TLS_CLIENT_CERT_VAR: cert}
    model = model_building.build_model("gpt-4o", env, provider="openai")
    assert calls == [(cert,)]
    assert model.http_client is not None  # type: ignore[attr-defined]
    assert model.http_async_client is not None  # type: ignore[attr-defined]


def test_ca_bundle_plus_client_cert_loads_the_client_chain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """REGRESSION: a CA bundle must not silently drop the client certificate.

    Real httpx 0.28 ``create_ssl_context(verify=<str CA path>, cert=...)``
    returns before its ``cert=`` handling, so passing ``cert=`` as a kwarg never
    loads the chain — the private-CA-gateway-plus-mTLS deployment would proceed
    with silently downgraded authentication. The builder must therefore call
    ``load_cert_chain`` itself. Runs against REAL ``httpx.create_ssl_context``.
    """
    cert = _write_pem(tmp_path, "client.pem")
    key = _write_pem(tmp_path, "client.key")
    calls = _spy_load_cert_chain(monkeypatch)
    env = {
        SSL_CERT_FILE_VAR: _REAL_CA,
        TLS_CLIENT_CERT_VAR: cert,
        TLS_CLIENT_KEY_VAR: key,
    }
    context = model_building._ssl_context(env)
    assert isinstance(context, ssl.SSLContext)
    assert calls == [(cert, key)]


# Client certificate — Anthropic branch


def test_client_cert_injects_anthropic_clients(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A split cert/key pair is loaded onto the context of the pre-seeded clients."""
    cert = _write_pem(tmp_path, "client.pem")
    key = _write_pem(tmp_path, "client.key")
    calls = _spy_load_cert_chain(monkeypatch)
    env = {
        "ANTHROPIC_API_KEY": "sk-ant",
        TLS_CLIENT_CERT_VAR: cert,
        TLS_CLIENT_KEY_VAR: key,
    }
    chat = model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    assert calls == [(cert, key)]
    assert "_client" in chat.__dict__
    assert "_async_client" in chat.__dict__
    # The injection actually took: the anthropic SDK wraps OUR httpx clients.
    assert isinstance(chat._client._client, anthropic.DefaultHttpxClient)
    assert isinstance(chat._async_client._client, anthropic.DefaultAsyncHttpxClient)


def test_injected_clients_keep_stock_httpx_defaults() -> None:
    """FIX: injected clients must behave like the stock (un-injected) ones.

    The stock path (``langchain_anthropic._client_utils`` / the openai SDK's own
    default) builds ``DefaultHttpxClient``: ``follow_redirects=True``, the SDK
    connection limits, TCP-keepalive socket options. Red before this fix: plain
    ``httpx.Client`` dropped all of that, so a gateway answering 3xx worked
    until TLS material was configured and then failed.
    """
    import openai

    env = {"ANTHROPIC_API_KEY": "sk-ant", SSL_CERT_FILE_VAR: _REAL_CA}
    chat = model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    inner = chat._client._client
    assert isinstance(inner, anthropic.DefaultHttpxClient)
    assert inner.follow_redirects is True
    assert isinstance(chat._async_client._client, anthropic.DefaultAsyncHttpxClient)
    oai_env = {"OPENAI_API_KEY": "sk-test", SSL_CERT_FILE_VAR: _REAL_CA}
    model = model_building.build_model("gpt-4o", oai_env, provider="openai")
    assert isinstance(model.http_client, openai.DefaultHttpxClient)
    assert model.http_client.follow_redirects is True
    assert isinstance(model.http_async_client, openai.DefaultAsyncHttpxClient)
    assert model.http_async_client.follow_redirects is True


def test_anthropic_injection_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """If client injection blows up, the build ABORTS — never runs on system trust.

    Red before: this failed OPEN, returning an un-injected model with a warning.
    That silently dropped the operator's CA pin and client chain and continued,
    which buys no availability (a gateway that requires the material rejects the
    un-injected client anyway) while defeating pinning where it does not.
    """
    cert = _write_pem(tmp_path, "client.pem")
    _spy_load_cert_chain(monkeypatch)

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("no clients today")

    monkeypatch.setattr(anthropic, "Client", boom)
    env = {"ANTHROPIC_API_KEY": "sk-ant", TLS_CLIENT_CERT_VAR: cert}
    with pytest.raises(RuntimeError, match="Refusing to continue on SYSTEM TRUST"):
        model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")


def test_partial_injection_closes_sync_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """FIX: async-client failure after a successful sync build closes the sync pool.

    Red before: the handler popped both ``__dict__`` seeds but leaked the
    already-built sync httpx client (a live connection pool) on every failed
    injection. The cleanup must still happen on the fail-closed path — aborting
    is no excuse for leaking a live pool.
    """
    cert = _write_pem(tmp_path, "client.pem")
    _spy_load_cert_chain(monkeypatch)
    built: list[httpx.Client] = []
    real = anthropic.DefaultHttpxClient

    class Recording(real):  # type: ignore[misc,valid-type]
        """DefaultHttpxClient that records every instance the module builds."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            """Record the instance after normal construction."""
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]
            built.append(self)

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("async construction failed")

    monkeypatch.setattr(anthropic, "DefaultHttpxClient", Recording)
    monkeypatch.setattr(anthropic, "AsyncClient", boom)
    env = {"ANTHROPIC_API_KEY": "sk-ant", TLS_CLIENT_CERT_VAR: cert}
    with pytest.raises(RuntimeError, match="TLS client injection"):
        model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    assert len(built) == 1
    assert built[0].is_closed  # the live pool is closed even as we abort


# Ambient-CA scoping — the Node/requests conventions are OpenAI-branch-only.
# NODE_EXTRA_CA_CERTS is ADDITIVE in Node while httpx verify=<file> is
# EXCLUSIVE, so honouring it on the Anthropic branch would break public
# api.anthropic.com on a machine that merely exports it (e.g. via the claude
# installer).


def test_ambient_node_ca_ignored_on_anthropic_branch(tmp_path: Path) -> None:
    """NODE_EXTRA_CA_CERTS alone must NOT pre-seed ChatAnthropic's clients."""
    env = {"ANTHROPIC_API_KEY": "sk-ant", "NODE_EXTRA_CA_CERTS": _REAL_CA}
    chat = model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    assert "_client" not in chat.__dict__
    assert "_async_client" not in chat.__dict__


def test_ambient_process_env_ca_ignored_on_anthropic_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ambient NODE_EXTRA_CA_CERTS/REQUESTS_CA_BUNDLE in os.environ are ignored too."""
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", _REAL_CA)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", _REAL_CA)
    env = {"ANTHROPIC_API_KEY": "sk-ant"}
    chat = model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    assert "_client" not in chat.__dict__
    assert "_async_client" not in chat.__dict__


def test_ambient_node_ca_still_honoured_on_openai_branch() -> None:
    """The OpenAI branch keeps its historical NODE_EXTRA_CA_CERTS behaviour."""
    env = {"OPENAI_API_KEY": "sk-test", "NODE_EXTRA_CA_CERTS": _REAL_CA}
    model = model_building.build_model("gpt-4o", env, provider="openai")
    assert model.http_client is not None  # type: ignore[attr-defined]


def test_configured_ca_carrier_still_reaches_anthropic_branch() -> None:
    """SSL_CERT_FILE — the carrier the harness writes from cfg.sdk.ca_cert — injects."""
    env = {"ANTHROPIC_API_KEY": "sk-ant", SSL_CERT_FILE_VAR: _REAL_CA}
    chat = model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    assert "_client" in chat.__dict__
    assert "_async_client" in chat.__dict__


# verify_ssl tri-state (carried config-stamped — see the ambient-rejection tests)


@pytest.mark.parametrize("raw", ["false", "0", "no", "off", "FALSE", " False "])
def test_verify_false_variants_disable_verification(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], raw: str
) -> None:
    """Every falsey literal coerce_verify accepts disables verification, loudly."""
    assert coerce_verify(raw) is False
    captured: dict[str, object] = {}
    context = _capture_ssl_context(monkeypatch, captured)
    assert model_building._ssl_context({TLS_VERIFY_VAR: _stamped(raw)}) is context
    assert captured["verify"] is False
    assert "TLS verification DISABLED" in capsys.readouterr().err


@pytest.mark.parametrize("raw", ["true", "1", "yes", "on", "TRUE"])
def test_verify_true_variants_leave_defaults_untouched(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    """Every truthy literal coerce_verify accepts is default verification: no context."""
    assert coerce_verify(raw) is True
    _capture_ssl_context(monkeypatch, {})
    assert model_building._ssl_context({TLS_VERIFY_VAR: _stamped(raw)}) is None


def test_verify_path_string_is_a_ca_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A non-boolean string passes through coerce_verify unchanged, as a CA path."""
    ca = _write_pem(tmp_path, "ca.pem")
    assert coerce_verify(ca) == ca
    captured: dict[str, object] = {}
    _capture_ssl_context(monkeypatch, captured)
    assert model_building._ssl_context({TLS_VERIFY_VAR: _stamped(ca)}) is not None
    assert captured["verify"] == ca


def test_ca_cert_wins_over_leftover_verify_false(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """SECURITY: ``ca_cert`` beats ``verify_ssl: false`` — sdk/openai precedence.

    One profile carrying both ``sdk.ca_cert`` and a leftover
    ``sdk.verify_ssl: false`` must verify against the private CA on this route
    exactly as the sibling routes do (``verify = ca or _cfg["verify_ssl"]`` —
    ``backends/llm/sdk.py``, ``backends/llm/openai.py``). Red before the fix:
    ``verify_ssl: false`` won and ``via: deepagents`` roles ran unverified while
    ``via: sdk`` roles verified — an active-MITM exposure on exactly one route.
    """
    block = SimpleNamespace(ca_cert=_REAL_CA, verify_ssl=False)
    carriers = model_building.tls_carriers_for(
        "claude-x", "anthropic", sdk_cfg=block, openai_cfg=None
    )
    resolved = model_building._resolve_verify(carriers, allow_ambient=False)
    assert resolved == (_REAL_CA or coerce_verify(False))  # the sdk route's own formula
    assert resolved == _REAL_CA
    context = model_building._ssl_context(carriers, allow_ambient_ca=False)
    assert isinstance(context, ssl.SSLContext)
    assert "TLS verification DISABLED" not in capsys.readouterr().err


def test_missing_configured_ca_cert_fails_closed() -> None:
    """A configured-but-absent CA bundle must not fall back to weaker trust."""
    block = SimpleNamespace(ca_cert="/nonexistent/ca.pem", verify_ssl=False)
    carriers = model_building.tls_carriers_for(
        "claude-x", "anthropic", sdk_cfg=block, openai_cfg=None
    )
    with pytest.raises(FileNotFoundError, match="CA bundle"):
        model_building._resolve_verify(carriers, allow_ambient=False)


def test_ambient_tls_verify_export_does_not_disable_verification(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """SECURITY: VVAHARNESS_TLS_VERIFY is an internal carrier, not an env knob.

    Every runtime env is built as ``{**os.environ, ...}``, so before the fix a
    plain ``export VVAHARNESS_TLS_VERIFY=false`` (or a ``.env`` in the
    operator's cwd, loaded by ``cli._load_dotenv``) disabled verification for
    every deepagents role. An ambient value must be ignored (with a warning);
    only the stamped value ``tls_carriers_for`` emits from config counts.
    """
    monkeypatch.setenv(TLS_VERIFY_VAR, "false")
    env = {**os.environ, "ANTHROPIC_API_KEY": "sk-ant"}
    assert model_building._resolve_verify(env, allow_ambient=False) is None
    assert model_building._ssl_context(env, allow_ambient_ca=False) is None
    err = capsys.readouterr().err
    assert "TLS verification DISABLED" not in err
    assert "ignoring ambient" in err
    chat = model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    assert "_client" not in chat.__dict__  # construction stays stock


def test_verify_disabled_warning_names_the_resolved_endpoint(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The disable warning names the branch being built, not whichever base rides along.

    An OpenAI-routed role in an env carrying both base URLs must warn about the
    OpenAI gateway, not the Anthropic one.
    """
    env = {
        "ANTHROPIC_BASE_URL": "https://ant.example/",
        "OPENAI_BASE_URL": "https://oai.example/",
        TLS_VERIFY_VAR: _stamped("false"),
    }
    model_building._resolve_verify(env, allow_ambient=True)  # the OpenAI branch
    assert "base_url=https://oai.example/" in capsys.readouterr().err
    model_building._resolve_verify(env, allow_ambient=False)  # the Anthropic branch
    assert "base_url=https://ant.example/" in capsys.readouterr().err


def test_ca_bundle_behaviour_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Default (OpenAI-branch) CA resolution still honours the ambient conventions."""
    ca = _write_pem(tmp_path, "ca.pem")
    captured: dict[str, object] = {}
    context = _capture_ssl_context(monkeypatch, captured)
    assert model_building._ssl_context({"NODE_EXTRA_CA_CERTS": ca}) is context
    assert captured["verify"] == ca
    # cert= is never handed to create_ssl_context: its verify=<str> branch
    # returns before the cert handling, silently dropping the chain.
    assert "cert" not in captured


# Cache behaviour — TLS material is part of the (composite) cache key


@pytest.mark.usefixtures("_fresh_cache")
def test_tls_configured_role_reuses_one_cached_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Identical TLS material pools through the cache — no per-call client leak."""
    cert = _write_pem(tmp_path, "client.pem")
    _spy_load_cert_chain(monkeypatch)
    env = {"ANTHROPIC_API_KEY": "sk-ant", TLS_CLIENT_CERT_VAR: cert}
    first = model_building.build_model_cached("claude-sonnet-4-6", env, "anthropic")
    second = model_building.build_model_cached("claude-sonnet-4-6", env, "anthropic")
    assert first is second
    assert len(model_building._model_cache) == 1


@pytest.mark.usefixtures("_fresh_cache")
@pytest.mark.parametrize("ca_first", [True, False])
def test_ca_only_env_never_shares_a_cached_model(ca_first: bool) -> None:
    """A CA-bundle-only env and a plain env must never share one model.

    Regression: the cache bypass keyed on client-cert/verify only, so whichever
    of the two constructed FIRST poisoned the other — the plain caller got
    CA-injected clients, or the CA-configured caller got un-injected ones.
    """
    base = {"ANTHROPIC_API_KEY": "sk-ant"}
    env_ca = {**base, SSL_CERT_FILE_VAR: _REAL_CA}
    ordered = [env_ca, dict(base)] if ca_first else [dict(base), env_ca]
    first = model_building.build_model_cached("claude-sonnet-4-6", ordered[0], "anthropic")
    second = model_building.build_model_cached("claude-sonnet-4-6", ordered[1], "anthropic")
    assert first is not second
    injected, plain = (first, second) if ca_first else (second, first)
    assert "_client" in injected.__dict__
    assert "_client" not in plain.__dict__


@pytest.mark.usefixtures("_fresh_cache")
def test_unconfigured_role_still_hits_model_cache() -> None:
    """Without TLS material the cache keeps deduplicating identical roles."""
    env = {"ANTHROPIC_API_KEY": "sk-ant"}
    first = model_building.build_model_cached("claude-sonnet-4-6", env, "anthropic")
    second = model_building.build_model_cached("claude-sonnet-4-6", env, "anthropic")
    assert first is second
    assert len(model_building._model_cache) == 1


@pytest.mark.usefixtures("_fresh_cache")
def test_concurrent_first_calls_build_exactly_one_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A thread barrier of first calls yields ONE build and one shared instance.

    Regression: the unlocked read-then-build raced under S4's thread pool, so
    concurrent first calls each constructed a client (duplicate httpx pools;
    on TLS-configured profiles a leaked injected anthropic client pair).
    """
    n_threads = 8
    builds: list[str] = []
    build_gate = threading.Barrier(n_threads)
    sentinel = object()

    def counted_build(
        model_id: str,
        _env: dict[str, str],
        _provider: str | None = None,
        _effort: str | None = None,
        _use_responses_api: bool | None = None,
    ) -> object:
        builds.append(model_id)
        return sentinel

    monkeypatch.setattr(model_building, "build_model", counted_build)
    env = {"ANTHROPIC_API_KEY": "sk-ant"}
    results: list[object] = []

    def caller() -> None:
        build_gate.wait()
        results.append(
            model_building.build_model_cached("claude-sonnet-4-6", env, "anthropic")
        )

    threads = [threading.Thread(target=caller) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert builds == ["claude-sonnet-4-6"]
    assert results == [sentinel] * n_threads
    assert len(model_building._model_cache) == 1


# Shared TLS carriers — merged by the DETECTION seams only (detection adapter,
# preflight probe); the S10/S11 invoker deliberately does not merge them (below).


def test_tls_carriers_pick_vendor_block_by_route() -> None:
    """cfg.sdk feeds Anthropic-routed models; cfg.openai feeds everything else."""
    sdk = SimpleNamespace(ca_cert="/sdk/ca.pem")
    oai = SimpleNamespace(ca_cert="/oai/ca.pem")
    a = model_building.tls_carriers_for("claude-x", "anthropic", sdk_cfg=sdk, openai_cfg=oai)
    o = model_building.tls_carriers_for("gpt-4o", "openai", sdk_cfg=sdk, openai_cfg=oai)
    assert a[SSL_CERT_FILE_VAR] == "/sdk/ca.pem"
    assert o[SSL_CERT_FILE_VAR] == "/oai/ca.pem"


def test_tls_carriers_resolve_relative_paths_against_cfg_dir(tmp_path: Path) -> None:
    """Relative profile cert paths resolve against the config directory.

    Same resolution ``preflight.configure_backends`` applies for via: sdk/openai
    (``_resolve_against``), so a relative ``client_cert`` behaves identically on
    every route.
    """
    block = SimpleNamespace(
        ca_cert="certs/ca.pem",
        client_cert=("certs/client.pem", "certs/client.key"),
        verify_ssl=True,
    )
    carriers = model_building.tls_carriers_for(
        "claude-x", "anthropic", sdk_cfg=block, openai_cfg=None, cfg_dir=tmp_path
    )
    assert carriers[SSL_CERT_FILE_VAR] == str(tmp_path / "certs/ca.pem")
    assert carriers[TLS_CLIENT_CERT_VAR] == str(tmp_path / "certs/client.pem")
    assert carriers[TLS_CLIENT_KEY_VAR] == str(tmp_path / "certs/client.key")
    assert TLS_VERIFY_VAR not in carriers  # True is the default: no carrier


def test_tls_carriers_empty_without_a_block() -> None:
    """No matching vendor block (or no TLS keys on it) emits no carriers."""
    assert model_building.tls_carriers_for(
        "claude-x", "anthropic", sdk_cfg=None, openai_cfg=None
    ) == {}
    assert model_building.tls_carriers_for(
        "claude-x", "anthropic", sdk_cfg=SimpleNamespace(), openai_cfg=None
    ) == {}


def test_tls_carriers_verify_false_emits_stamped_carrier() -> None:
    """verify_ssl: false travels as the internal carrier, YAML-string included.

    The value is stamped so the reader can tell this config-derived carrier
    from an ambient ``export VVAHARNESS_TLS_VERIFY=false`` (which is ignored).
    """
    block = SimpleNamespace(verify_ssl="false")
    carriers = model_building.tls_carriers_for(
        "claude-x", "anthropic", sdk_cfg=block, openai_cfg=None
    )
    assert carriers == {TLS_VERIFY_VAR: _stamped("false")}


# no_proxy parity — a profile-level ``no_proxy`` reaches the deepagents
# detection roles the way ``scoped_no_proxy_env`` gives it to via: sdk/openai.
# Opt-in is per CONSTRUCTION SITE via the same stamped-carrier mechanism as the
# TLS material above: only the seams that merge ``tls_carriers_for`` output (the
# detection dispatch env and the preflight probe) carry it; the frozen S10/S11
# invoker never merges carriers, so its constructions take the unchanged path —
# pinned below and in ``test_s10_plugin_runner_env_is_credentials_only``.


def test_tls_carriers_emit_stamped_no_proxy_carrier() -> None:
    """A profile no_proxy travels as its own config-stamped internal carrier."""
    block = SimpleNamespace(no_proxy="gw.example")
    carriers = model_building.tls_carriers_for(
        "gpt-4o", "openai", sdk_cfg=None, openai_cfg=block
    )
    assert carriers == {model_building.NO_PROXY_VAR: _stamped("gw.example")}


def test_no_proxy_carrier_scopes_injected_openai_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TLS-injected clients honour the config no_proxy: a direct (None) mount.

    httpx reads NO_PROXY exactly once, at client construction; the carrier must
    therefore take effect on the clients this module builds, exactly like the
    incumbent routes' ``scoped_no_proxy_env`` wrapping. The empty
    ``http_socket_options`` rides the same injected shape, silencing the
    library's spurious proxy-shadowing warning (the injected clients are used
    verbatim, so the transport it warns about is never built).
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)  # isolate from an ambient bypass list
    monkeypatch.delenv("no_proxy", raising=False)
    env = {
        "OPENAI_API_KEY": "sk-test",
        SSL_CERT_FILE_VAR: _REAL_CA,
        model_building.NO_PROXY_VAR: _stamped("gw.example"),
    }
    model = model_building.build_model("gpt-4o", env, provider="openai")
    for client in (model.http_client, model.http_async_client):
        assert client is not None
        assert client.trust_env is True  # env-proxy mounts stay on
        mounts = {pattern.pattern: mount for pattern, mount in client._mounts.items()}
        assert "all://*gw.example" in mounts
        assert mounts["all://*gw.example"] is None  # direct: bypasses the proxy
    assert model.http_socket_options == ()
    # The scope really was scoped: nothing leaked into the process env.
    assert "NO_PROXY" not in os.environ


def test_no_proxy_alone_injects_sdk_default_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """no_proxy without TLS material still applies — via SDK-default clients.

    langchain's own default clients are process-cached (lru_cache), so scoping
    THEIR construction would leak the no_proxy into unrelated constructions —
    the frozen paths included. Injecting our own SDK-default-shaped clients
    keeps the scope per cache entry, mirroring via: openai (whose no_proxy
    scope wraps its own client construction too).
    """
    import openai

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    env = {
        "OPENAI_API_KEY": "sk-test",
        model_building.NO_PROXY_VAR: _stamped("gw.example"),
    }
    model = model_building.build_model("gpt-4o", env, provider="openai")
    assert isinstance(model.http_client, openai.DefaultHttpxClient)
    assert model.http_client.follow_redirects is True  # SDK default shape kept
    assert isinstance(model.http_async_client, openai.DefaultAsyncHttpxClient)
    mounts = {p.pattern: m for p, m in model.http_client._mounts.items()}
    assert mounts.get("all://*gw.example", "absent") is None
    assert model.http_socket_options == ()


def test_no_proxy_scopes_injected_anthropic_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Anthropic branch's TLS-injected clients honour the carrier too."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    env = {
        "ANTHROPIC_API_KEY": "sk-ant",
        SSL_CERT_FILE_VAR: _REAL_CA,
        model_building.NO_PROXY_VAR: _stamped("gw.example"),
    }
    chat = model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    inner = chat._client._client
    mounts = {p.pattern: m for p, m in inner._mounts.items()}
    assert mounts.get("all://*gw.example", "absent") is None
    assert "NO_PROXY" not in os.environ  # the scope unwound


def test_no_proxy_alone_leaves_anthropic_construction_stock() -> None:
    """DOCUMENTED GAP: no TLS material means no Anthropic injection to scope.

    The un-injected ChatAnthropic builds its clients lazily inside the SDK,
    out of construction-time reach, so a no_proxy-only profile does not get
    proxy-bypass parity on the Anthropic branch (it does on the OpenAI branch,
    and via: sdk covers the incumbent Anthropic route). Pinned so the
    limitation is a decision, not an accident.
    """
    env = {
        "ANTHROPIC_API_KEY": "sk-ant",
        model_building.NO_PROXY_VAR: _stamped("gw.example"),
    }
    chat = model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    assert "_client" not in chat.__dict__
    assert "_async_client" not in chat.__dict__


def test_ambient_no_proxy_export_is_ignored(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """SECURITY: VVAHARNESS_NO_PROXY is an internal carrier, not an env knob.

    Every runtime env is built as ``{**os.environ, ...}`` — the frozen S10/S11
    env included — so an unstamped ambient export must be ignored (with a
    warning), or a plain ``export`` would re-route traffic on every path.
    Only the stamped value ``tls_carriers_for`` emits from config counts.
    """
    monkeypatch.setenv(model_building.NO_PROXY_VAR, "gw.example")
    env = {**os.environ, "OPENAI_API_KEY": "sk-test"}
    model = model_building.build_model("gpt-4o", env, provider="openai")
    assert model.http_client is None  # construction stays stock
    assert model.http_socket_options is None
    assert "ignoring ambient" in capsys.readouterr().err


@pytest.mark.usefixtures("_fresh_cache")
def test_no_proxy_env_never_shares_a_cached_model() -> None:
    """A carrier-bearing env and a plain env must never share one model.

    This is what keeps the frozen S10/S11 constructions insulated from a
    detection opt-in even through the cache: their carrier-less env has a
    different TLS fingerprint, so they can never be handed a detection-built
    instance (or vice versa).
    """
    base = {"OPENAI_API_KEY": "sk-test"}
    env_np = {**base, model_building.NO_PROXY_VAR: _stamped("gw.example")}
    plain = model_building.build_model_cached("gpt-4o", dict(base), "openai")
    scoped = model_building.build_model_cached("gpt-4o", env_np, "openai")
    assert plain is not scoped
    assert plain.http_client is None
    assert scoped.http_client is not None
    assert len(model_building._model_cache) == 2


def test_s10_plugin_runner_env_is_credentials_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """S10/S11 are deliberately OUT OF SCOPE for this branch's TLS work.

    The profile's ``ca_cert`` / ``client_cert`` / ``verify_ssl`` reach the
    detection deepagents seam (see ``tls_carriers_for`` above) but NOT the
    S10/S11 invoker: its env stays exactly what it has always been — the
    process env plus the credential overrides, nothing more. This asserts that
    non-change, so a future refactor cannot quietly extend the TLS carriers
    into the remediation path without a deliberate decision. Consequence to
    keep in mind: a gateway requiring mTLS is reachable by the detection roles
    and by ``via: sdk`` S10, but not by ``via: deepagents`` S10/S11.

    The fixture configures REAL TLS material and first proves (via
    ``tls_carriers_for``) that this material yields carriers on the seam that
    merges them — so the absence assertions here are load-bearing, not
    vacuous.
    """
    from vvaharness.backends.harness.provider_routing import credential_env_overrides
    from vvaharness.remediation_agent import plugin_runner as pr

    monkeypatch.setattr(pr, "_run_sync", lambda coro: coro)
    monkeypatch.setattr(
        pr, "_consume_deepagents", lambda user, options, *, verbose: options
    )
    # FULL TLS material ON the block (CA bundle, split client pair, verify
    # override), so a future carrier merge into the invoker would visibly
    # perturb options.env. Without configured material this test is vacuous:
    # there would be no carrier that COULD leak, and it would keep passing
    # even if the invoker started merging tls_carriers_for.
    sdk = SimpleNamespace(
        api_key="sk-ant", base_url="https://gw.example/",
        ca_cert=_REAL_CA,
        client_cert=(
            _write_pem(tmp_path, "client.pem"),
            _write_pem(tmp_path, "client.key"),
        ),
        verify_ssl=False,
        no_proxy="gw.example",
    )
    cfg = SimpleNamespace(
        sdk=sdk, openai=None, step_remediate=None,
        _data={"_config_dir": str(tmp_path)},
    )
    # Vacuity guard: the SAME block fed to the seam that DOES merge carriers
    # yields every TLS carrier. This proves the fixture is capable of
    # producing what the assertions below claim is absent — if fixture drift
    # ever stops emitting a carrier, fail here rather than pass vacuously.
    tls_vars = (SSL_CERT_FILE_VAR, TLS_CLIENT_CERT_VAR, TLS_CLIENT_KEY_VAR,
                TLS_VERIFY_VAR, model_building.NO_PROXY_VAR)
    carriers = model_building.tls_carriers_for(
        "claude-x", "anthropic", sdk_cfg=sdk, openai_cfg=None, cfg_dir=tmp_path
    )
    for var in tls_vars:
        assert var in carriers, f"fixture no longer produces the {var} carrier"

    options = pr._invoke_deepagents(
        "hi", model_id="claude-x", repo=tmp_path, mode="report",
        sr=None, cfg=cfg, verbose=False, provider="anthropic",
    )
    # Positive absence: none of the carriers this config emits on the
    # detection seam may reach the S10/S11 plugin-runner env.
    for var in tls_vars:
        assert var not in options.env, f"TLS carrier {var} leaked into S10 env"
    assert options.env == {
        **os.environ,
        **credential_env_overrides(
            "claude-x", "anthropic", sdk_cfg=sdk, openai_cfg=None
        ),
    }


# S10/S11 regression guard


def test_anthropic_construction_unchanged_without_tls() -> None:
    """With no TLS material, ChatAnthropic is built exactly as before: no pre-seeding."""
    env = {"ANTHROPIC_API_KEY": "sk-ant", "ANTHROPIC_BASE_URL": "http://anthropic"}
    chat = model_building.build_model("claude-sonnet-4-6", env, provider="anthropic")
    assert "_client" not in chat.__dict__
    assert "_async_client" not in chat.__dict__


def test_frozen_shape_openai_kwargs_are_byte_identical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE frozen-path constraint test: a carrier-less env takes the unchanged path.

    The S10/S11 plugin-runner env is the process env plus credential overrides
    — never the detection carriers (pinned above). On that shape ``build_model``
    must call ``ChatOpenAI`` with EXACTLY the frozen kwarg set — which includes
    the Responses-transport trio (``use_responses_api``/``store``/
    ``include``) — with no injected clients and no ``http_socket_options`` key
    at all (not even an explicit default), so the library's own default shape —
    including its keepalive transport and its proxy-env bypass — is untouched.
    Asserted on the literal kwargs, not the resulting fields, so an
    always-passed default cannot pass. Runs with a proxy env var set, the exact
    condition under which the detection opt-ins engage elsewhere.
    """
    captured: dict[str, object] = {}
    real = model_building.ChatOpenAI

    class Recording(real):  # type: ignore[misc,valid-type]
        """ChatOpenAI that records the kwargs build_model hands it."""

        def __init__(self, **kwargs: object) -> None:
            """Record then construct normally."""
            captured.update(kwargs)
            super().__init__(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(model_building, "ChatOpenAI", Recording)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    env = {**os.environ, "OPENAI_API_KEY": "sk-test"}
    model = model_building.build_model("gpt-4o", env, provider="openai")
    assert set(captured) == {
        "model", "api_key", "base_url", "timeout", "use_responses_api",
        "store", "include", "http_client", "http_async_client",
    }
    assert captured["use_responses_api"] is True
    assert captured["store"] is False
    assert captured["include"] == ["reasoning.encrypted_content"]
    assert captured["http_client"] is None
    assert captured["http_async_client"] is None
    assert model.http_socket_options is None  # library default, untouched


def test_frozen_shape_openai_kwargs_pinned_off_chat_completions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``use_responses_api: false`` pin builds the Chat Completions kwarg set exactly.

    The Chat Completions shape is the operator escape hatch for models that
    need opaque per-turn state, so it must stay byte-identical to the
    historical constructor call: no ``store``/``include`` keys at all, not
    even explicit defaults.
    """
    captured: dict[str, object] = {}
    real = model_building.ChatOpenAI

    class Recording(real):  # type: ignore[misc,valid-type]
        """ChatOpenAI that records the kwargs build_model hands it."""

        def __init__(self, **kwargs: object) -> None:
            """Record then construct normally."""
            captured.update(kwargs)
            super().__init__(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(model_building, "ChatOpenAI", Recording)
    env = {**os.environ, "OPENAI_API_KEY": "sk-test"}
    model_building.build_model(
        "gpt-4o", env, provider="openai", use_responses_api=False
    )
    assert set(captured) == {
        "model", "api_key", "base_url", "timeout", "use_responses_api",
        "http_client", "http_async_client",
    }
    assert captured["use_responses_api"] is False


def test_frozen_shape_with_ambient_ca_keeps_verbatim_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ambient CA material (no carriers) injects exactly as before, verbatim.

    On this shape — reachable from the frozen paths, since their env inherits
    ``os.environ`` — clients were injected before this change and still are.
    The empty ``http_socket_options`` that now rides along is inert here: the
    SDK clients langchain uses ARE the injected httpx clients (used verbatim,
    socket options never applied to a supplied client), with env-proxy
    detection still on. Executed, not assumed.
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    env = {**os.environ, "OPENAI_API_KEY": "sk-test", "REQUESTS_CA_BUNDLE": _REAL_CA}
    model = model_building.build_model("gpt-4o", env, provider="openai")
    assert model.root_client._client is model.http_client
    assert model.root_async_client._client is model.http_async_client
    assert model.http_client.trust_env is True  # env-proxy mounts intact
    # No no_proxy carrier, so no direct-mount was smuggled in either.
    assert all(m is not None for m in model.http_client._mounts.values())


# Canary — private ChatAnthropic surface the injection relies on


def test_chatanthropic_private_surface_canary() -> None:
    """A langchain-anthropic upgrade that moves the seam must fail CI, not a scan."""
    assert type(ChatAnthropic._client) is functools.cached_property
    assert type(ChatAnthropic._async_client) is functools.cached_property
    chat = ChatAnthropic(
        model_name="claude-canary",
        api_key="sk-ant",  # type: ignore[arg-type]
        timeout=5,
        max_tokens_to_sample=64,
    )
    params = chat._client_params
    assert "api_key" in params
    assert "timeout" in params
    # The injection also relies on the SDK's exported default-client pair.
    assert issubclass(anthropic.DefaultHttpxClient, httpx.Client)
    assert issubclass(anthropic.DefaultAsyncHttpxClient, httpx.AsyncClient)


# Missing/malformed CA paths fail closed; missing client chains degrade with a warning.


def test_missing_client_cert_warns_and_disables_mtls(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A configured-but-absent client cert warns with the path and yields no context."""
    missing = "/nonexistent/client.pem"
    assert model_building._ssl_context({TLS_CLIENT_CERT_VAR: missing}) is None
    err = capsys.readouterr().err
    assert missing in err
    assert "disabling mTLS" in err


def test_missing_ca_file_fails_closed() -> None:
    """A configured-but-absent CA bundle must raise, not use ambient trust."""
    missing = "/nonexistent/ca.pem"
    with pytest.raises(FileNotFoundError, match="CA bundle"):
        model_building._ssl_context({SSL_CERT_FILE_VAR: missing})


def test_missing_ca_dir_fails_closed() -> None:
    """A configured-but-absent CA directory must raise, not use ambient trust."""
    missing = "/nonexistent/certdir"
    with pytest.raises(FileNotFoundError, match="CA directory"):
        model_building._ssl_context({SSL_CERT_DIR_VAR: missing})


def test_ca_paths_reject_wrong_filesystem_type(tmp_path: Path) -> None:
    ca_dir = tmp_path / "certs"
    ca_dir.mkdir()
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("placeholder", encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="CA bundle"):
        model_building._ca_bundle(
            {SSL_CERT_FILE_VAR: str(ca_dir)}, allow_ambient=False)
    with pytest.raises(FileNotFoundError, match="CA directory"):
        model_building._ca_bundle(
            {SSL_CERT_DIR_VAR: str(ca_file)}, allow_ambient=False)


def test_malformed_ca_fails_closed(tmp_path: Path) -> None:
    """SECURITY: a malformed CA bundle raises instead of downgrading to system trust.

    Aligned with ``via: sdk``/``openai``, where the client constructor parses
    the CA and raises. Red before the fix: the context-build failure was warned
    about and the scan continued WITHOUT the configured TLS material — if the
    gateway's certificate happened to chain to a public CA, the operator's CA
    pin was silently gone.
    """
    bad = tmp_path / "corrupt-ca.pem"
    bad.write_text("this is not a certificate", encoding="utf-8")
    with pytest.raises(ssl.SSLError):
        model_building._ssl_context({SSL_CERT_FILE_VAR: str(bad)})


def test_malformed_client_cert_warns_and_keeps_server_auth(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A malformed client chain warns and keeps server-authenticated TLS (sdk parity).

    With only the chain configured there is nothing else to keep, so no context;
    with a CA alongside, the CA-verifying context survives. The warning carries
    path and exception type only — never file contents.
    """
    bad = _write_pem(tmp_path, "corrupt-client.pem")
    assert model_building._ssl_context({TLS_CLIENT_CERT_VAR: bad}) is None
    err = capsys.readouterr().err
    assert "mTLS is NOT active" in err
    assert bad in err
    assert "certificate placeholder" not in err  # file contents never leak
    context = model_building._ssl_context(
        {TLS_CLIENT_CERT_VAR: bad, SSL_CERT_FILE_VAR: _REAL_CA}
    )
    assert isinstance(context, ssl.SSLContext)


# --- Chain SHAPE parity: YAML gives a list, not a tuple -----------------------
# Regression: matching on `tuple` alone raised TypeError for YAML's list shape
# on `via: sdk` — see `tls.chain_paths`' docstring.

@pytest.mark.parametrize("shape", [tuple, list])
def test_resolve_client_chain_accepts_both_pair_shapes(
    tmp_path: Path, shape: type, capsys: pytest.CaptureFixture[str]
) -> None:
    """A present (cert, key) pair survives resolution as either a tuple or a list."""
    cert = _write_pem(tmp_path, "client.pem")
    key = _write_pem(tmp_path, "client.key")
    out = tls.resolve_client_chain(shape([cert, key]), label="sdk")
    assert out is not None
    assert tuple(out) == (cert, key)
    assert capsys.readouterr().err == ""  # nothing missing, so nothing warned


@pytest.mark.parametrize("shape", [tuple, list])
def test_resolve_client_chain_reports_a_missing_member_of_either_shape(
    tmp_path: Path, shape: type, capsys: pytest.CaptureFixture[str]
) -> None:
    """A missing KEY disables mTLS and names the missing path, for both shapes."""
    cert = _write_pem(tmp_path, "client.pem")
    missing = str(tmp_path / "absent.key")
    assert tls.resolve_client_chain(shape([cert, missing]), label="sdk") is None
    err = capsys.readouterr().err
    assert missing in err
    assert "disabling mTLS" in err


def test_load_client_chain_does_not_raise_typeerror_on_a_list_pair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A list-shaped pair reaches load_cert_chain as *args, never as one bad arg.

    The placeholder PEMs cannot actually load, so the contract asserted here is
    the failure MODE: a clean warn-and-return-False (mTLS off, server auth kept),
    never `TypeError` from handing a list to `load_cert_chain` as a single path.
    """
    pair = [_write_pem(tmp_path, "c.pem"), _write_pem(tmp_path, "c.key")]
    context = ssl.create_default_context(cafile=_REAL_CA)
    assert tls.load_client_chain(context, pair, label="sdk") is False
    err = capsys.readouterr().err
    assert "mTLS is NOT active" in err
    assert "TypeError" not in err
    assert "certificate placeholder" not in err  # contents never leak


def test_injection_failure_leaves_the_instance_coherent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The fail-closed path must still unwind its partial seed before raising.

    Kept as a direct unit test because the raise now propagates out of
    `build_model`, so the caller never sees the instance. Without this, deleting
    the two `__dict__.pop` calls would pass the whole suite.
    """
    chat = ChatAnthropic(model="claude-sonnet-4-6", api_key="sk-ant")

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("no clients today")

    monkeypatch.setattr(anthropic, "AsyncClient", boom)
    context = ssl.create_default_context(cafile=_REAL_CA)
    with pytest.raises(RuntimeError, match="Refusing to continue on SYSTEM TRUST"):
        model_building._inject_anthropic_clients(chat, context, "sk-ant")
    assert "_client" not in chat.__dict__, "partial seed left behind"
    assert "_async_client" not in chat.__dict__


class _FakeRejection(Exception):
    """A synthetic gateway 400 naming reasoning_effort."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        """Carry the message and an OpenAI-SDK-shaped status_code."""
        super().__init__(message)
        self.status_code = status_code


@pytest.fixture(autouse=True)
def _clear_learned_effort_state() -> None:
    """Reset the runtime-learned unsupported-value sets around each test."""
    model_building._NO_REASONING_EFFORT.clear()
    da_client._EFFORT_UNSUPPORTED_WARNED.clear()
    yield
    model_building._NO_REASONING_EFFORT.clear()
    da_client._EFFORT_UNSUPPORTED_WARNED.clear()


def test_build_model_applies_reasoning_effort_on_openai(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured effort becomes ChatOpenAI's reasoning_effort on the OpenAI branch."""
    env = {"OPENAI_API_KEY": "sk-test"}
    chat = model_building.build_model("gpt-5.6-sol", env, "openai", "high")
    assert chat.reasoning_effort == "high"


def test_build_model_passes_xhigh_through_on_openai(monkeypatch: pytest.MonkeyPatch) -> None:
    """Confirmed live: gpt-5.5 accepts 'xhigh' directly, so it is not clamped."""
    env = {"OPENAI_API_KEY": "sk-test"}
    chat = model_building.build_model("gpt-5.5", env, "openai", "xhigh")
    assert chat.reasoning_effort == "xhigh"


def test_build_model_passes_max_through_on_openai(monkeypatch: pytest.MonkeyPatch) -> None:
    """MAX is sent as the literal 'max' value — never silently clamped to 'high'."""
    env = {"OPENAI_API_KEY": "sk-test"}
    chat = model_building.build_model("gpt-5.5", env, "openai", "max")
    assert chat.reasoning_effort == "max"


def test_build_model_omits_reasoning_effort_for_a_learned_unsupported_value() -> None:
    """A (model, value) pair already recorded as rejected gets no kwarg."""
    model_building._NO_REASONING_EFFORT.add(("gpt-5.5", "high"))
    env = {"OPENAI_API_KEY": "sk-test"}
    chat = model_building.build_model("gpt-5.5", env, "openai", "high")
    assert chat.reasoning_effort is None


def test_build_model_learned_rejection_is_scoped_to_the_rejected_value() -> None:
    """Rejecting 'max' for a model must not also block 'high' for that same model."""
    model_building._NO_REASONING_EFFORT.add(("gpt-5.5", "max"))
    env = {"OPENAI_API_KEY": "sk-test"}
    chat = model_building.build_model("gpt-5.5", env, "openai", "high")
    assert chat.reasoning_effort == "high"


def test_build_model_omits_reasoning_effort_kwarg_when_unset() -> None:
    """No effort configured means no reasoning_effort is sent at all."""
    env = {"OPENAI_API_KEY": "sk-test"}
    chat = model_building.build_model("gpt-5.5", env, "openai")
    assert chat.reasoning_effort is None


def test_build_model_effort_is_noop_on_anthropic_route() -> None:
    """The Anthropic branch never receives reasoning_effort, whatever effort is set."""
    env = {"ANTHROPIC_API_KEY": "sk-ant"}
    chat = model_building.build_model("claude-sonnet-4-6", env, "anthropic", "high")
    assert getattr(chat, "reasoning_effort", None) is None


def test_build_model_cached_keys_on_effort() -> None:
    """Two different effort values must not share a cached model instance."""
    env = {"OPENAI_API_KEY": "sk-test"}
    low = model_building.build_model_cached("gpt-5.6-sol", env, "openai", "low")
    high = model_building.build_model_cached("gpt-5.6-sol", env, "openai", "high")
    assert low is not high
    assert low.reasoning_effort == "low"
    assert high.reasoning_effort == "high"


def test_is_reasoning_effort_rejection_matches_a_400_naming_the_param() -> None:
    """A 400 whose message names reasoning_effort is recognized as a rejection."""
    exc = _FakeRejection("Error code: 400 - {'error': {'message': \"Unknown parameter: 'reasoning_effort'\"}}")
    assert da_client._is_reasoning_effort_rejection(exc) is True


def test_is_reasoning_effort_rejection_ignores_unrelated_errors() -> None:
    """A 400 about something else, or a non-400, is not a reasoning_effort rejection."""
    assert da_client._is_reasoning_effort_rejection(_FakeRejection("bad request", 400)) is False
    assert da_client._is_reasoning_effort_rejection(_FakeRejection("reasoning_effort", 500)) is False


def test_drop_reasoning_effort_remembers_value_and_warns_once(capsys: pytest.CaptureFixture[str]) -> None:
    """Dropping a (model, value) pair records it and warns exactly once per pair."""
    da_client._drop_reasoning_effort("gpt-5.5", "high")
    da_client._drop_reasoning_effort("gpt-5.5", "high")
    assert ("gpt-5.5", "high") in model_building._NO_REASONING_EFFORT
    err = capsys.readouterr().err
    assert err.count("gpt-5.5") == 1


def _oneshot_options(tmp_path: Path) -> OneShotOptions:
    return OneShotOptions(model="gpt-5.5", cwd=tmp_path, model_provider="openai", effort="high")


def _streaming_options(tmp_path: Path) -> StreamingOptions:
    return StreamingOptions(model="gpt-5.5", cwd=tmp_path, model_provider="openai", effort="high")


class _FakeOneshotGraph:
    """Fake CompiledStateGraph whose first ainvoke rejects reasoning_effort."""

    def __init__(self) -> None:
        """Track how many times ainvoke was called."""
        self.calls = 0

    async def ainvoke(self, *args: object, **kwargs: object) -> dict[str, object]:
        """Reject once, then succeed with an empty terminal state."""
        self.calls += 1
        if self.calls == 1:
            raise _FakeRejection("Error code: 400 - reasoning_effort is not supported")
        return {"messages": []}


def test_run_oneshot_retries_without_effort_after_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A reasoning_effort rejection is retried once, without raising to the caller."""
    fake_graph = _FakeOneshotGraph()
    monkeypatch.setattr(
        da_client,
        "build_oneshot_options",
        lambda options: CompiledGraph(graph=fake_graph, config={}),
    )
    harness = da_client.DeepAgentHarness()

    asyncio.run(harness.run_oneshot("hi", _oneshot_options(tmp_path)))
    assert fake_graph.calls == 2
    assert ("gpt-5.5", "high") in model_building._NO_REASONING_EFFORT


class _FakeStreamingGraph:
    """Fake CompiledStateGraph whose first astream rejects reasoning_effort."""

    def __init__(self) -> None:
        """Track how many times astream was called."""
        self.calls = 0

    async def astream(self, *args: object, **kwargs: object):
        """Reject once (before yielding), then complete with no events."""
        self.calls += 1
        if self.calls == 1:
            raise _FakeRejection("Error code: 400 - reasoning_effort is not supported")
            yield  # pragma: no cover — makes this an async generator
        return
        yield  # pragma: no cover

    async def aget_state(self, *args: object, **kwargs: object) -> object:
        """Report no initialised state, matching a fresh checkpoint."""
        raise ValueError("no state")


def test_run_streaming_retries_without_effort_after_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A reasoning_effort rejection mid-stream is retried once, transparently."""
    fake_graph = _FakeStreamingGraph()
    monkeypatch.setattr(
        da_client,
        "build_streaming_agent",
        lambda options: CompiledGraph(graph=fake_graph, config={}),
    )
    harness = da_client.DeepAgentHarness()

    async def _drain() -> list[object]:
        return [msg async for msg in harness.run_streaming("hi", _streaming_options(tmp_path))]

    messages = asyncio.run(_drain())
    assert fake_graph.calls == 2
    assert ("gpt-5.5", "high") in model_building._NO_REASONING_EFFORT
    assert len(messages) >= 1


def test_effort_retry_rebuilds_through_the_real_model_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The effort retry must construct a SECOND model with the effort dropped.

    Runs the real option builders and ``build_model_cached`` — no graph stubs —
    so a cache keyed on the RAW effort instead of the resolved value would
    serve the stale reasoning_effort instance back to the retry and loop on
    the same 400 until the recursion limit.
    """
    constructions: list[str | None] = []
    real = model_building.ChatOpenAI

    class Probe(real):  # type: ignore[misc,valid-type]
        """ChatOpenAI that records efforts and rejects any effort-carrying call."""

        def __init__(self, **kwargs: object) -> None:
            """Construct normally and record the effort this instance carries."""
            super().__init__(**kwargs)  # type: ignore[arg-type]
            constructions.append(self.reasoning_effort)

        async def _agenerate(
            self,
            messages: list[BaseMessage],
            stop: list[str] | None = None,
            run_manager: object = None,
            **kwargs: object,
        ) -> ChatResult:
            """Reject while reasoning_effort is set; answer plainly without it."""
            del messages, stop, run_manager, kwargs
            if self.reasoning_effort is not None:
                raise _FakeRejection(
                    "Error code: 400 - Unknown parameter: 'reasoning_effort'"
                )
            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content="ok"))]
            )

    monkeypatch.setattr(model_building, "ChatOpenAI", Probe)
    options = OneShotOptions(
        model="gpt-effort-probe",
        model_provider="openai",
        cwd=tmp_path,
        env={"OPENAI_API_KEY": "sk-test"},
        effort="high",
    )
    result = asyncio.run(da_client.DeepAgentHarness().run_oneshot("hi", options))
    assert not result.is_error
    # Exactly two shapes ever built: the effort-carrying original (parent) and
    # the effort-less rebuild the retry must land on. A third construction or
    # a RecursionError means the cache served or rebuilt the wrong instance.
    assert len(constructions) == 2
    assert set(constructions) == {"high", None}
