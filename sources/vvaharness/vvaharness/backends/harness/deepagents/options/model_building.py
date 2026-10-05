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

"""Chat-model resolution: TLS-aware httpx clients (CA/mTLS), model construction, a cache."""

from __future__ import annotations

import os
import ssl
import sys
import threading
from pathlib import Path
from typing import Any, Final

import langchain_anthropic
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel
from langchain_openai import ChatOpenAI

from vvaharness.backends.harness.deepagents.limits import (
    MODEL_MAX_OUTPUT_TOKENS,
    MODEL_TIMEOUT_SECONDS,
)
from vvaharness.backends.harness.deepagents.models import (
    SSL_CERT_DIR_VAR,
    SSL_CERT_FILE_VAR,
    TLS_CLIENT_CERT_VAR,
    TLS_CLIENT_KEY_VAR,
    TLS_VERIFY_VAR,
    ModelKey,
    anthropic_base,
    anthropic_key,
    openai_base,
    openai_key,
)
from vvaharness.backends.harness.models import EffortLevel
from vvaharness.backends.harness.provider_routing import routes_to_anthropic

# Stdlib-only module, so importing it costs nothing extra; reusing it keeps the
# verify_ssl tri-state, missing-cert and client-chain-loading semantics (and the
# warning texts) identical to via: sdk / openai.
from vvaharness.backends.llm.tls import (
    anthropic_auth_kwargs,
    chain_paths,
        is_anthropic_oauth_token,
    coerce_verify,
    load_client_chain,
    resolve_client_chain,
    scoped_no_proxy_env,
    warn_verify_disabled,
)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

#: Value prefix ``tls_carriers_for`` stamps onto ``TLS_VERIFY_VAR`` and
#: :data:`NO_PROXY_VAR` so the reader can tell a harness-emitted (config-derived)
#: carrier from an ambient environment variable.
_TLS_VERIFY_STAMP = "vvaharness-config:"

#: INTERNAL carrier for the resolved vendor block's ``no_proxy`` (proxy-bypass
#: hosts). Emitted config-stamped by :func:`tls_carriers_for`, so it reaches only
#: the seams that merge those carriers — the S0-S9 detection roles and the
#: preflight probe — and never the frozen S10/S11 invoker, whose env is
#: deliberately credentials-only (see ``tls_carriers_for``'s docstring and
#: ``tests/test_deepagents_tls.py::test_s10_plugin_runner_env_is_credentials_only``).
#: That per-construction-site opt-in is what keeps the frozen paths byte-identical:
#: without the carrier, :func:`build_model` takes exactly its historical path.
#: Declared here rather than in ``deepagents/models.py`` because this module is
#: its only writer and reader.
NO_PROXY_VAR = "VVAHARNESS_NO_PROXY"


def _ca_bundle(env: dict[str, str], *, allow_ambient: bool) -> str | None:
    """Return the configured CA bundle path, mirroring httpx's own env lookup order.

    ``allow_ambient=False`` (the Anthropic branch) reads only ``SSL_CERT_FILE`` /
    ``SSL_CERT_DIR`` from *env* — the carrier the harness populates from config,
    plus the two names httpx's own ``trust_env`` honours natively. The Node and
    requests conventions (``NODE_EXTRA_CA_CERTS``, ``REQUESTS_CA_BUNDLE``) are
    ADDITIVE in their home tools, while httpx ``verify=<file>`` is EXCLUSIVE, so
    honouring them ambiently here would break public ``api.anthropic.com`` calls
    on any machine that merely exports them. An explicitly selected CA file or
    directory that is absent raises instead of silently dropping the operator's
    trust configuration.
    """
    if allow_ambient:
        ca_file = (
            env.get(SSL_CERT_FILE_VAR)
            or env.get("REQUESTS_CA_BUNDLE")
            or env.get("NODE_EXTRA_CA_CERTS")
            or os.environ.get(SSL_CERT_FILE_VAR)
            or os.environ.get("REQUESTS_CA_BUNDLE")
            or os.environ.get("NODE_EXTRA_CA_CERTS")
        )
    else:
        ca_file = env.get(SSL_CERT_FILE_VAR)
    if ca_file and not Path(ca_file).is_file():
        raise FileNotFoundError(
            f"DeepAgents CA bundle not found or not a file: {ca_file}"
        )
    ca_dir = env.get(SSL_CERT_DIR_VAR) or (
        os.environ.get(SSL_CERT_DIR_VAR) if allow_ambient else None
    )
    if ca_dir and not Path(ca_dir).is_dir():
        raise FileNotFoundError(
            f"DeepAgents CA directory not found or not a directory: {ca_dir}"
        )
    return ca_file or ca_dir


def _config_verify(env: dict[str, str]) -> str | bool | None:
    """Return the config-level ``verify_ssl`` tri-state, ignoring an ambient carrier.

    ``TLS_VERIFY_VAR`` is an internal carrier, not a user-facing knob (see its
    declaration in ``deepagents/models.py``): disabling TLS verification must stay
    a deliberate config edit. Because every runtime env is built as
    ``{**os.environ, ...}``, a plain ``export VVAHARNESS_TLS_VERIFY=false`` (or a
    ``.env`` in the operator's cwd) would otherwise flow straight in — so only
    values ``tls_carriers_for`` stamped with :data:`_TLS_VERIFY_STAMP` are
    honoured; anything else is warned about and ignored.
    """
    raw = env.get(TLS_VERIFY_VAR)
    if raw is None:
        return None
    if not raw.startswith(_TLS_VERIFY_STAMP):
        print(
            f"WARN [deepagents]: ignoring ambient {TLS_VERIFY_VAR}={raw!r} — it is "
            f"an internal carrier, not a user-facing knob; set verify_ssl in the "
            f"profile config instead",
            file=sys.stderr,
        )
        return None
    return coerce_verify(raw.removeprefix(_TLS_VERIFY_STAMP))


def _config_no_proxy(env: dict[str, str]) -> str | None:
    """Return the config-level ``no_proxy`` hosts, ignoring an ambient carrier.

    Same stamped-carrier discipline as :func:`_config_verify`: only the value
    :func:`tls_carriers_for` emits from the profile config counts, so a plain
    ``export VVAHARNESS_NO_PROXY=...`` (which every runtime env inherits via
    ``{**os.environ, ...}`` — the frozen S10/S11 env included) is warned about
    and ignored rather than silently re-routing traffic. The plain
    ``NO_PROXY``/``no_proxy`` conventions are unaffected: httpx's own
    ``trust_env`` handling keeps honouring them natively on every route.
    """
    raw = env.get(NO_PROXY_VAR)
    if raw is None:
        return None
    if not raw.startswith(_TLS_VERIFY_STAMP):
        print(
            f"WARN [deepagents]: ignoring ambient {NO_PROXY_VAR}={raw!r} — it is "
            f"an internal carrier, not a user-facing knob; set no_proxy in the "
            f"profile config instead",
            file=sys.stderr,
        )
        return None
    return raw.removeprefix(_TLS_VERIFY_STAMP) or None


def _resolve_verify(env: dict[str, str], *, allow_ambient: bool) -> str | bool | None:
    """Return the effective httpx ``verify=`` value, or None when only defaults apply.

    A configured CA bundle WINS over ``verify_ssl`` — the same precedence
    ``via: sdk`` / ``via: openai`` document and apply (``verify = ca or
    _cfg["verify_ssl"]``), so one profile carrying both ``ca_cert`` and a
    leftover ``verify_ssl: false`` verifies against the private CA on every
    route instead of running unverified on this one. Tri-state coercion is
    shared with those routes through :func:`coerce_verify`; *allow_ambient*
    scopes the CA-bundle env conventions per :func:`_ca_bundle` and doubles as
    the vendor branch (``False`` is Anthropic) for naming the right endpoint
    when verification is disabled.
    """
    verify = _ca_bundle(env, allow_ambient=allow_ambient) or _config_verify(env)
    if verify is False:
        warn_verify_disabled(
            openai_base(env) if allow_ambient else anthropic_base(env),
            label="deepagents",
        )
        return False
    # Per coerce_verify, a non-boolean string is a CA-bundle path; True/None are defaults.
    return verify if isinstance(verify, str) else None


def _client_cert(env: dict[str, str]) -> str | tuple[str, ...] | None:
    """Resolve the mTLS client certificate, disabling mTLS when a file is missing.

    Returns a combined-PEM path, a ``(cert, key)`` pair when the key is split out,
    or ``None`` when no client certificate is configured (or its files are absent —
    warned, not raised, via the shared ``tls.resolve_client_chain``, mirroring the
    sdk backend).
    """
    cert = env.get(TLS_CLIENT_CERT_VAR) or os.environ.get(TLS_CLIENT_CERT_VAR)
    if not cert:
        return None
    key = env.get(TLS_CLIENT_KEY_VAR) or os.environ.get(TLS_CLIENT_KEY_VAR)
    return resolve_client_chain(
        (cert, key) if key else cert, label="deepagents", noun="client_cert/key"
    )


def _resolve_cert_path(path: str, cfg_dir: Path | None) -> str:
    """Resolve a profile cert *path* against *cfg_dir*, when one is known.

    Reuses ``_resolve_against`` for its UNC/network-path refusal, so a planted
    config cannot leak credentials over SMB — the same resolution
    ``preflight.configure_backends`` applies to the ``sdk``/``openai``/``cli``
    cert paths.
    """
    if cfg_dir is None:
        return path
    from vvaharness.orchestrator.config_paths import (  # noqa: PLC0415 — lazy: keeps vvaharness.config off this module's import path
        _resolve_against,
    )

    return _resolve_against(cfg_dir, path)


def tls_carriers_for(
    model_id: str,
    provider: str | None,
    *,
    sdk_cfg: object | None,
    openai_cfg: object | None,
    cfg_dir: Path | str | None = None,
) -> dict[str, str]:
    """Build the TLS env carriers :func:`build_model` reads, for the resolved vendor.

    Merged into the DETECTION-seam env only: ``backends.llm.deepagents.build_harness_env``
    (reached via ``dispatch_prompt``/``dispatch_agentic``) and the preflight probe
    (``preflight._probe_deepagents_harness``) fold these in, so ``cfg.sdk`` /
    ``cfg.openai`` TLS material (``ca_cert``, ``client_cert``, ``verify_ssl``)
    behaves identically across the S0-S9 deepagents roles. The S10/S11 invoker
    (``plugin_runner._invoke_deepagents``) deliberately does NOT merge them —
    S10/S11 are frozen on this branch — and
    ``tests/test_deepagents_tls.py::test_s10_plugin_runner_env_is_credentials_only``
    pins that asymmetry. Consequence: an mTLS/private-CA profile reaches the
    detection roles (and ``via: sdk`` S10) but not ``via: deepagents`` S10/S11.

    Vendor-block selection matches ``credential_env_overrides`` exactly; relative
    cert paths resolve against *cfg_dir* (the profile's directory), exactly as
    ``preflight.configure_backends`` resolves them for ``via: sdk``/``openai``. A
    ``(cert, key)`` client pair splits across both carriers; a bare string is a
    combined-PEM path. The ``verify_ssl`` carrier is emitted only when non-default
    (so TLS-configured construction is not falsely triggered) and is stamped with
    :data:`_TLS_VERIFY_STAMP` so :func:`_config_verify` can tell it from an
    ambient export. A configured ``no_proxy`` travels the same way (stamped, onto
    :data:`NO_PROXY_VAR`), giving the detection roles the proxy-bypass parity that
    ``via: sdk``/``openai`` get from ``scoped_no_proxy_env`` — and, by the same
    deliberate non-merge, NOT the frozen S10/S11 invoker.
    """
    block = sdk_cfg if routes_to_anthropic(model_id, provider) else openai_cfg
    if block is None:
        return {}
    directory = Path(cfg_dir) if cfg_dir else None
    carriers: dict[str, str] = {}
    ca = getattr(block, "ca_cert", None)
    if ca:
        carriers[SSL_CERT_FILE_VAR] = _resolve_cert_path(ca, directory)
    cert = getattr(block, "client_cert", None)
    pair = chain_paths(cert) if cert else ()
    for var, path in zip((TLS_CLIENT_CERT_VAR, TLS_CLIENT_KEY_VAR), pair, strict=False):
        carriers[var] = _resolve_cert_path(path, directory)
    verify = coerce_verify(getattr(block, "verify_ssl", None))
    if verify is not None and verify is not True:
        value = "false" if verify is False else _resolve_cert_path(verify, directory)
        carriers[TLS_VERIFY_VAR] = _TLS_VERIFY_STAMP + value
    no_proxy = getattr(block, "no_proxy", None)
    if no_proxy:
        carriers[NO_PROXY_VAR] = _TLS_VERIFY_STAMP + no_proxy
    return carriers


def _ssl_context(
    env: dict[str, str], *, allow_ambient_ca: bool = True
) -> ssl.SSLContext | None:
    """Return an SSL context for the configured TLS material, or None when there is none.

    Handles: a CA bundle or ``verify_ssl`` (the CA wins — see :func:`_resolve_verify`;
    ``false`` disables verification with a loud warning) and an mTLS client
    certificate. ``allow_ambient_ca=False`` (the Anthropic branch) ignores the
    ambient CA env conventions — see :func:`_ca_bundle`. ``None`` keeps the no-TLS
    construction path byte-identical. A malformed/unloadable CA bundle RAISES —
    fail closed, matching ``via: sdk``/``openai`` where the client constructor
    parses the CA: continuing on system trust would silently drop the operator's
    CA pin. An unloadable client chain instead warns and keeps server-authenticated
    TLS (the shared ``tls.load_client_chain``), also matching ``via: sdk``.

    ``cert=`` is never passed to ``create_ssl_context`` — the httpx-0.28.1 trap;
    see ``tls.load_client_chain`` for the full story.
    """
    if httpx is None:
        return None
    verify = _resolve_verify(env, allow_ambient=allow_ambient_ca)
    cert = _client_cert(env)
    if verify is None and cert is None:
        return None
    context = httpx.create_ssl_context(
        verify=True if verify is None else verify, trust_env=True
    )
    if (cert is not None
            and not load_client_chain(context, cert, label="deepagents")
            and verify is None):
        return None  # the chain was the only configured material: stay stock
    return context


def _inject_anthropic_clients(chat: ChatAnthropic, ssl_context: ssl.SSLContext | None,
                              token: str) -> None:
    """Pre-seed *chat*'s anthropic clients with TLS-configured httpx clients.

    ``ChatAnthropic`` has no ``http_client`` field — passed as a constructor kwarg it
    lands in ``model_kwargs`` and is merged into the API request payload, breaking
    every call. ``_client`` / ``_async_client`` are ``functools.cached_property``
    (non-data) descriptors, so seeding the instance ``__dict__`` wins over them while
    ``_client_params`` keeps api_key/base_url/retries/headers/timeout exactly what
    langchain would have built. ``DefaultHttpxClient`` and its async twin are what
    the stock path (``langchain_anthropic._client_utils``) builds too, keeping
    follow_redirects/connection-limits/TCP-keepalive identical to an un-injected
    client — only ``verify`` differs.

    Fails CLOSED. An un-injected client runs on system trust, so the CA pin is
    not enforced and the client chain not presented; a gateway that requires that
    material rejects the un-injected client anyway, so failing open (an earlier
    revision) bought no availability while leaving the run silently unpinned. A
    canary test pins the private surface, so a langchain upgrade breaks CI rather
    than a scan.
    """
    sync_http = None
    try:
        import anthropic  # noqa: PLC0415 — lazy: only needed once TLS material is configured

        params = dict(chat._client_params)
        params.pop("api_key", None)
        http_kwargs: dict[str, object] = {"timeout": MODEL_TIMEOUT_SECONDS}
        if ssl_context is not None:
            http_kwargs["verify"] = ssl_context
        sync_http = anthropic.DefaultHttpxClient(**http_kwargs)
        chat.__dict__["_client"] = anthropic.Client(
            **{**params, **anthropic_auth_kwargs(token), "http_client": sync_http}
        )
        chat.__dict__["_async_client"] = anthropic.AsyncClient(
            **{
                **params,
                **anthropic_auth_kwargs(token),
                "http_client": anthropic.DefaultAsyncHttpxClient(**http_kwargs),
            }
        )
    except Exception as exc:
        # Undo a partial seed so the instance is left coherent, and close the
        # already-built sync pool rather than leak it, BEFORE aborting.
        chat.__dict__.pop("_client", None)
        chat.__dict__.pop("_async_client", None)
        if sync_http is not None:
            sync_http.close()
        version = getattr(langchain_anthropic, "__version__", "unknown")
        raise RuntimeError(
            f"TLS client injection into ChatAnthropic failed "
            f"(langchain-anthropic {version}): {type(exc).__name__}. Refusing to "
            f"continue on SYSTEM TRUST — the configured ca_cert pin would not be "
            f"enforced and any client_cert would not be presented. Remove the "
            f"TLS material from the profile to run unpinned deliberately, or "
            f"pin a langchain-anthropic version this build supports."
        ) from exc


_OPENAI_EFFORT_MAP: dict[EffortLevel, str] = {
    EffortLevel.LOW: "low",
    EffortLevel.MEDIUM: "medium",
    EffortLevel.HIGH: "high",
    EffortLevel.XHIGH: "xhigh",
    EffortLevel.MAX: "max",
}


def _to_openai_reasoning_effort(effort: str | None) -> str | None:
    """Map our ``EffortLevel`` vocabulary to OpenAI's ``reasoning_effort`` literal, or ``None``."""
    parsed = EffortLevel.parse(effort)
    return _OPENAI_EFFORT_MAP.get(parsed) if parsed is not None else None


_NO_REASONING_EFFORT: set[tuple[str, str]] = set()

#: Models learned at runtime to reject their first Responses API call.
_CHAT_COMPLETIONS_ONLY_MODELS: set[str] = set()

#: With ``store=False`` the endpoint keeps no per-turn state; encrypted reasoning replays it.
RESPONSES_INCLUDE_ENCRYPTED_REASONING: Final[tuple[str, ...]] = (
    "reasoning.encrypted_content",
)


def _effort_kwargs(model_id: str, effort: str | None) -> dict[str, Any]:
    """Return the ``reasoning_effort=`` kwarg to splice in, or ``{}`` when inapplicable."""
    mapped = _to_openai_reasoning_effort(effort)
    if mapped is None or (model_id, mapped) in _NO_REASONING_EFFORT:
        return {}
    return {"reasoning_effort": mapped}


def resolve_use_responses_api(
    model_id: str, provider: str | None, override: bool | None
) -> bool | None:
    """Resolve the transport: override, then learned rejection, then Responses; Anthropic → None."""
    if routes_to_anthropic(model_id, provider):
        return None
    if override is not None:
        return override
    return model_id not in _CHAT_COMPLETIONS_ONLY_MODELS


def _transport_kwargs(resolved: bool) -> dict[str, Any]:
    """ChatOpenAI kwargs for the resolved transport, mirroring ``_effort_kwargs``."""
    if not resolved:
        return {"use_responses_api": False}
    return {
        "use_responses_api": True,
        "store": False,
        "include": list(RESPONSES_INCLUDE_ENCRYPTED_REASONING),
    }


def build_model(
    model_id: str,
    env: dict[str, str],
    provider: str | None = None,
    effort: str | None = None,
    use_responses_api: bool | None = None,
) -> BaseChatModel:
    """Resolve a model id to a chat model, per :func:`routes_to_anthropic`.

    Only the OpenAI branch honours the ambient CA env conventions
    (``NODE_EXTRA_CA_CERTS``/``REQUESTS_CA_BUNDLE``), preserving its historical
    behaviour; the Anthropic branch builds a context from explicitly configured
    material only (:func:`_ca_bundle` explains why).

    A config-carried ``no_proxy`` (:func:`_config_no_proxy` — detection-seam
    only, see :data:`NO_PROXY_VAR`) scopes client construction the way
    ``via: sdk``/``openai`` scope theirs: httpx reads ``NO_PROXY`` exactly once,
    when a client is built, so the value applies wherever this function builds
    the clients itself — the OpenAI branch (which injects for the purpose when
    only ``no_proxy`` is configured) and the TLS-injected Anthropic clients. The
    un-injected Anthropic shape builds its clients lazily inside the SDK, out of
    construction-time reach; that residual gap is documented rather than papered
    over. An env without the carrier — every frozen S10/S11 construction —
    takes the historical path unchanged.
    """
    anthropic_route = routes_to_anthropic(model_id, provider)
    ssl_context = _ssl_context(env, allow_ambient_ca=not anthropic_route)
    no_proxy = _config_no_proxy(env)
    if anthropic_route:
        token = anthropic_key(env)
        chat = ChatAnthropic(
            model_name=model_id,
            api_key=token,  # type: ignore[arg-type]
            base_url=anthropic_base(env),
            timeout=MODEL_TIMEOUT_SECONDS,
            # Passed under the field's declared alias; only that alias is visible to a type checker.
            max_tokens_to_sample=MODEL_MAX_OUTPUT_TOKENS,
        )
        if ssl_context is not None or is_anthropic_oauth_token(token):
            with scoped_no_proxy_env(no_proxy):
                _inject_anthropic_clients(chat, ssl_context, token or "")
        return chat
    # OpenAI-compatible endpoints; transport per resolve_use_responses_api.
    http_client = http_async_client = None
    socket_options_kwargs: dict[str, Any] = {}
    if ssl_context is not None or no_proxy:
        import openai  # noqa: PLC0415 — lazy: only needed once TLS/no_proxy material is configured

        # The SDK's own defaults (what an un-injected client gets), verify aside.
        client_kwargs: dict[str, Any] = {"timeout": MODEL_TIMEOUT_SECONDS}
        if ssl_context is not None:
            client_kwargs["verify"] = ssl_context
        with scoped_no_proxy_env(no_proxy):
            http_client = openai.DefaultHttpxClient(**client_kwargs)
            http_async_client = openai.DefaultAsyncHttpxClient(**client_kwargs)
        # Injected clients are used verbatim by langchain-openai — its
        # socket-options transport is never built for this shape, so the resolved
        # options are dead code and their only artifact is a spurious once-per-
        # process WARNING that proxy auto-detection was disabled (it was not: the
        # clients above keep trust_env and their env-proxy mounts). An empty
        # tuple disables the resolution and with it the warning, at zero
        # functional cost — strictly on this injected shape. Never set on the
        # un-injected shape, where the keepalive transport (or the library's own
        # proxy-env bypass) is wanted; and never via the process-wide
        # LANGCHAIN_OPENAI_TCP_KEEPALIVE kill-switch, which would strip TCP
        # keepalive from every un-injected client in the process, the frozen
        # S10/S11 paths included. Guarded on the field existing so an older
        # langchain-openai does not sweep the kwarg into model_kwargs (and from
        # there into the request payload).
        if "http_socket_options" in ChatOpenAI.model_fields:
            socket_options_kwargs["http_socket_options"] = ()
    effort_kwargs = _effort_kwargs(model_id, effort)
    transport_kwargs = _transport_kwargs(
        bool(resolve_use_responses_api(model_id, provider, use_responses_api))
    )
    return ChatOpenAI(
        model=model_id,
        api_key=openai_key(env),  # type: ignore[arg-type]
        base_url=openai_base(env),
        timeout=MODEL_TIMEOUT_SECONDS,
        http_client=http_client,
        http_async_client=http_async_client,
        **socket_options_kwargs,
        **effort_kwargs,
        **transport_kwargs,
    )


#: Every env name that can change the TLS material (or the ``no_proxy`` client
#: scoping) a build resolves. Part of the cache key, so two envs that would build
#: different SSL contexts or proxy mounts never share a model (or its injected
#: clients) — in particular, a detection env carrying the :data:`NO_PROXY_VAR`
#: carrier never shares a cache entry with a frozen S10/S11 env, which lacks it.
#: A superset of what either vendor branch reads is safe: it can only split
#: cache entries more finely, never share them wrongly.
_TLS_ENV_VARS: tuple[str, ...] = (
    TLS_CLIENT_CERT_VAR,
    TLS_CLIENT_KEY_VAR,
    TLS_VERIFY_VAR,
    NO_PROXY_VAR,
    SSL_CERT_FILE_VAR,
    SSL_CERT_DIR_VAR,
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
)

_model_cache: dict[tuple[ModelKey, tuple[str, ...]], BaseChatModel] = {}

#: Serializes cache misses so concurrent first calls (S4's thread pool) share
#: one build instead of each constructing a client — duplicate httpx pools, and
#: on TLS-configured profiles a leaked injected anthropic client pair.
_model_cache_lock = threading.Lock()


def _tls_fingerprint(env: dict[str, str]) -> tuple[str, ...]:
    """Fingerprint the TLS material *env* resolves, mirroring the env-then-ambient lookup.

    Fingerprints the configured PATHS/values, not file contents: editing a cert
    file in place while the process runs still hits the old cached client.
    """
    return tuple(env.get(v) or os.environ.get(v) or "" for v in _TLS_ENV_VARS)


def build_model_cached(
    model_id: str,
    env: dict[str, str],
    provider: str | None = None,
    effort: str | None = None,
    use_responses_api: bool | None = None,
) -> BaseChatModel:
    """Return a model instance, reusing a cached instance when inputs match.

    Transport AND effort are RESOLVED before the key is built: each selects
    request behaviour inside langchain_openai, so a runtime-learned flip
    (Chat-Completions-only, or reasoning_effort-incapable) must be a cache
    miss that rebuilds the model — keying on the raw values would keep
    serving the rejected instance to every retry, forever.
    """
    mapped_effort = _to_openai_reasoning_effort(effort)
    resolved_effort = (
        None
        if mapped_effort is None or (model_id, mapped_effort) in _NO_REASONING_EFFORT
        else effort
    )
    resolved_transport = resolve_use_responses_api(model_id, provider, use_responses_api)
    key = (
        ModelKey.of(model_id, env, provider, resolved_effort, resolved_transport),
        _tls_fingerprint(env),
    )
    cached = _model_cache.get(key)
    if cached is not None:
        return cached
    # Double-checked: the unlocked read above stays the steady-state fast path.
    with _model_cache_lock:
        cached = _model_cache.get(key)
        if cached is not None:
            return cached
        model = build_model(model_id, env, provider, resolved_effort, resolved_transport)
        _model_cache[key] = model
        return model
