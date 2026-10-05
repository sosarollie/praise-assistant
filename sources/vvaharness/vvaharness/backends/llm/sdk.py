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

"""Anthropic SDK backend; mirrors cli.py's prompt()/agentic() surface, routed by registry.py.
Auth: ANTHROPIC_SDK_API_KEY, or configure(api_key=..., base_url=...) once at startup.
Streams to dodge HTTP timeouts on large max_tokens, caches the prompt, auto-retries 429/5xx.

Cache markers are placed only where all three gates agree: the route accepts `cache_control` (see
`_cache_route`), the kill switch is on, and the cumulative prefix clears the model's minimum
cacheable size (see `_cache_prefix_meets_minimum`). `prompt(..., cache_prefix=...)` lets a caller
mark a stable lead portion of the user turn for its own breakpoint, separate from the volatile
remainder; omitting it leaves the request byte-identical to a call without the parameter."""
from __future__ import annotations

import json
import os
import re
import ssl
import sys
import threading
import time
import warnings
from typing import Final, cast
from urllib.parse import urlsplit

# Lazy import: anthropic is optional unless a role actually uses via:sdk.
import anthropic
import httpx  # a hard dependency of anthropic, so always present when this module imports
import urllib3

from vvaharness.backends.harness.deepagents.limits import MODEL_MAX_OUTPUT_TOKENS
from vvaharness.backends.harness.models import (
    AuthenticationError,
    ProxyError,
    TruncatedResponseError,
)
from vvaharness.backends.llm import cache as _cache
from vvaharness.backends.llm import tools as _localtools
from vvaharness.util.scan_progress import is_stage_only
from vvaharness.backends.llm.models import (
    AGENTIC_MAX_TOKENS,
    ANTHROPIC_STOP_MAX_TOKENS,
    DEFAULT_READ_TOOLS,
    RATE_LIMIT_TRANSIENT_RX,
    RETRYABLE_STATUS,
    SERVER_ERROR_TRANSIENT_RX,
    TRUNCATED_REPLIES_COUNTER,
    SdkConfig,
    truncation_retry_max,
)
from vvaharness.backends.llm.tls import (
    anthropic_auth_kwargs,
    coerce_verify,
    load_client_chain,
    resolve_client_chain,
    scoped_no_proxy_env,
    warn_verify_disabled,
)
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.util.counters import COUNTERS
from vvaharness.util.response_quality import check_response_quality, output_tokens_for_gate
from vvaharness.util.tokens import TOKENS, TokenUsage, estimate_tokens
from vvaharness.util.warn_once import warn_once

_AUTH_STATUS_RX = re.compile(
    r"unauthorized|invalid[_ ]api[_ ]key"
    # Bounded, not `.*`: an unanchored wildcard let a 400 reading
    # "invalid_request_error ... prompt is too long: 300000 tokens" match, so an
    # oversized chunk was logged three times as an authentication error and the
    # operator had no way to see the real cause.
    r"|invalid[^\n]{0,24}token|token[^\n]{0,24}(?:expired|invalid|revoked)"
    r"|authentication[_ ]failed",
    re.IGNORECASE,
)
_PROXY_CAUSE_RX = re.compile(
    r"\b407\b|proxy[_ ]auth|tunnel[_ ](?:failed|error)|CONNECT.*failed"
    r"|SSL.*CERTIFICATE|CERTIFICATE.*VERIFY.*FAILED|CERT_VERIFY_FAILED"
    r"|certificate[_ ]verify[_ ]failed",
    re.IGNORECASE,
)
_AUTH_MAX_RETRIES_SDK = 3
_AUTH_BACKOFF_SDK = (2, 4, 8)

# Lazy, thread-safe singleton client (s4/s6 run in ThreadPoolExecutor).

_client = None
_client_lock = threading.Lock()
_cfg: SdkConfig = {"api_key": None, "base_url": None, "verify_ssl": True,
              "ca_cert": None, "client_cert": None, "no_proxy": None,
              # allow_api_key_fallback: sdk borrows the shared ANTHROPIC key only if sole backend.
              "allow_api_key_fallback": False,
              # None means "use the published per-model minimum" (_CACHE_MIN_TOKENS_TABLE); a
              # forced global floor is wrong in both directions, so it needs a measured reason.
              "cache_min_block_tokens": None,
              # "auto" detects the marker regime from base_url and fails closed on anything
              # unrecognised; anthropic/vertex/bedrock declare it; "none" forces no markers.
              "cache_route": "auto",
              # Fail-closed protects an UNKNOWN route from an unsupported field, but cannot
              # protect a KNOWN route from a wrong capability fact — a gateway that silently
              # strips or rejects a marker looks identical to one that honours it. Hence a
              # config switch rather than a code revert.
              "cache_markers": "on"}


def configure(*, api_key: str | None = None, base_url: str | None = None,
              verify_ssl: bool | str | None = None,
              ca_cert: str | None = None,
              client_cert: str | tuple | None = None,
              no_proxy: str | None = None,
              allow_api_key_fallback: bool | None = None,
              cache_min_block_tokens: int | None = None,
              cache_markers: str | None = None,
              cache_route: str | None = None) -> None:
    """Called once by the orchestrator before any SDK step; prefers ANTHROPIC_SDK_API_KEY.
    ca_cert wins over verify_ssl; only orchestrator configuration may enable
    allow_api_key_fallback, and only when sdk/deepagents are the sole backends.
    cache_min_block_tokens overrides the per-model minimum; cache_markers off kills every marker;
    cache_route is auto/anthropic/vertex/bedrock/none."""
    global _client
    with _client_lock:
        if api_key:
            _cfg["api_key"] = api_key
        if base_url:
            _cfg["base_url"] = base_url
        if allow_api_key_fallback is not None:
            _cfg["allow_api_key_fallback"] = bool(allow_api_key_fallback)
        if verify_ssl is not None:
            _cfg["verify_ssl"] = coerce_verify(verify_ssl)
        if ca_cert:
            _cfg["ca_cert"] = ca_cert
        if client_cert:
            _cfg["client_cert"] = client_cert
        if no_proxy:
            _cfg["no_proxy"] = no_proxy
        if cache_min_block_tokens is not None:
            _cfg["cache_min_block_tokens"] = int(cache_min_block_tokens)
        if cache_markers is not None:
            _cfg["cache_markers"] = cache_markers
        if cache_route is not None:
            # PyYAML parses an unquoted `off`/`no` as False, so accept it as the documented
            # "none". An unrecognised value warns and falls back to "auto": the field only ever
            # gates an optimisation, so it must never fail the run.
            v = "none" if cache_route is False else str(cache_route).strip().lower()
            if v not in ("auto", "none",
                         _ROUTE_ANTHROPIC, _ROUTE_VERTEX, _ROUTE_BEDROCK):
                print(f"WARN [sdk]: cache_route={cache_route!r} is not one of "
                      f"auto/anthropic/vertex/bedrock/none — using 'auto' "
                      f"(host detection)", file=sys.stderr)
                v = "auto"
            _cfg["cache_route"] = v
        _client = None  # force rebuild on next call


def _mtls_verify(verify: bool | str) -> bool | str | ssl.SSLContext:
    """Return `verify` upgraded to an SSL context carrying the configured client chain.

    The context is built explicitly and the chain loaded onto it via the shared
    ``tls.load_client_chain`` — never pass ``cert=`` to the httpx client (the
    httpx-0.28.1 trap; see that helper's docstring for the full story). No
    configured client_cert returns `verify` untouched; a missing file warns and
    disables mTLS, and an unloadable chain warns and returns `verify` unchanged
    (server-authenticated TLS only).

    EVERY chain shape is pre-checked, not just the combined-PEM string. An
    earlier revision guarded the pre-check with ``isinstance(str)``, so a
    ``(cert, key)`` pair with an absent KEY fell through to
    ``load_client_chain`` and warned ``client_cert '<cert>' could not be
    loaded`` — naming the file that was present. ``resolve_client_chain`` checks
    each member and names the one actually missing, matching the deepagents
    route.
    """
    client_cert = resolve_client_chain(_cfg["client_cert"], label="sdk")
    if not client_cert:
        return verify
    context = httpx.create_ssl_context(verify=verify, trust_env=True)
    if not load_client_chain(context, client_cert, label="sdk"):
        return verify
    return context


def _get_client():
    global _client
    if _client is not None:
        return _client
    with _client_lock:
        if _client is None:
            kw = {"max_retries": 4}
            # Dedicated env var so sdk can target a different gateway/key than the CLI backend.
            key = _cfg["api_key"] or os.environ.get("ANTHROPIC_SDK_API_KEY")
            if not key and _cfg.get("allow_api_key_fallback"):
                # Sole-sdk profile only: falls back to the shared ANTHROPIC key, not from via:cli.
                key = (os.environ.get("ANTHROPIC_API_KEY")
                       or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
                if key:
                    print("    [sdk] no ANTHROPIC_SDK_API_KEY — falling back to "
                          "ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN (sdk is the "
                          "only backend)", file=sys.stderr)
            kw.update(anthropic_auth_kwargs(key))
            if _cfg["base_url"]:
                kw["base_url"] = _cfg["base_url"]
            # ca_cert (path) wins over verify_ssl (bool); httpx treats str `verify=` as CA bundle.
            ca = _cfg["ca_cert"]
            if ca and not os.path.exists(ca):
                print(f"WARN [sdk]: ca_cert '{ca}' not found — falling back to "
                      f"verify_ssl={_cfg['verify_ssl']!r}", file=sys.stderr)
                ca = None
            verify = ca or _cfg["verify_ssl"]
            if verify is False:
                # TLS is OFF: suppress warning spam, but always warn loudly naming the endpoint.
                warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                warn_verify_disabled(_cfg["base_url"], label="sdk",
                                     default_endpoint="<default Anthropic endpoint>",
                                     ca_hint="sdk.ca_cert")
            # httpx drops `cert=` whenever `verify=` is a str CA path or False, so a
            # configured client cert is loaded onto an explicit context — see _mtls_verify.
            verify = _mtls_verify(verify)
            if verify is not True:
                kw["http_client"] = anthropic.DefaultHttpxClient(verify=verify)
            with scoped_no_proxy_env(_cfg.get("no_proxy")):
                _client = anthropic.Anthropic(**kw)
    return _client


# Cache-marker capability gate.
#
# registry.resolve() only knows the TRANSPORT ("sdk") — Anthropic direct, Vertex and Bedrock all
# resolve to it and are told apart only here, from the base_url the client was actually built
# with. An endpoint we don't recognise gets no markers at all: a rejected field turns a scan into
# a failure, while an ignored one only costs an optimisation.

_ROUTE_ANTHROPIC = "anthropic"   # cache_control
_ROUTE_VERTEX = "vertex"         # cache_control, same shape as Anthropic direct
_ROUTE_BEDROCK = "bedrock"       # no markers here — see _build_cache_prefix_content
_ROUTE_UNKNOWN = "unknown"       # no markers of any kind

# Every marker this module places is gated on this ONE set, so there is a single coherent policy
# rather than some markers failing closed while others go out unconditionally.
_CACHE_CONTROL_ROUTES = (_ROUTE_ANTHROPIC, _ROUTE_VERTEX)

# Anchored on the registrable domain: a bare substring test promoted any corporate hostname merely
# CONTAINING "vertex"/"bedrock" into a marker-capable route — the one direction that risks a
# rejected field rather than a missed optimisation.
_BEDROCK_HOST_RX = re.compile(
    r"(?:^|\.)bedrock[a-z0-9-]*(?:\.[a-z0-9-]+)*\.amazonaws\.com$", re.IGNORECASE)
# The hyphen alternative admits the regional `<region>-aiplatform.…` form real Vertex uses.
_VERTEX_HOST_RX = re.compile(
    r"(?:^|[.-])aiplatform\.googleapis\.com$", re.IGNORECASE)
_ANTHROPIC_HOST_RX = re.compile(r"(?:^|\.)anthropic\.com$", re.IGNORECASE)

#: Route classifications already noted as withholding cache markers, so the
#: notice below prints once per process — and once per repo in batch runs,
#: because this set is registered in ``warn_once._REGISTRY_SITES`` and cleared
#: by ``reset_warn_once_registries()`` between repos. Registering there is not
#: optional: an unregistered set survives the between-repo reset and repo N>1
#: silently loses the note.
_CACHE_ROUTE_NOTED: set[str] = set()


def _cache_route(client) -> str:
    """Classify which cache-marker regime `client` is talking to, from its own resolved base_url.

    Never from the model id or from `via`: at this transport those are indistinguishable. Falls
    back to `_cfg["base_url"]` for a client stand-in without the attribute; an unset base_url means
    the SDK's default endpoint, i.e. Anthropic direct. Anything not recognisably Anthropic, Vertex
    or Bedrock is `_ROUTE_UNKNOWN` — guessing wrong risks a 400 on a strict gateway, so this fails
    closed rather than assuming Anthropic-compatible behaviour from the transport alone.

    An explicit `cache_route` beats detection, because sniffing can only fail CLOSED: a gateway
    that genuinely is Anthropic-Messages-compatible has no other way to say so.
    """
    forced = _cfg.get("cache_route", "auto")
    if forced is False:
        forced = "none"          # a directly-poked _cfg gets configure()'s YAML tolerance too
    forced = str(forced or "auto").strip().lower()
    if forced == "none":
        return _ROUTE_UNKNOWN
    if forced in (_ROUTE_ANTHROPIC, _ROUTE_VERTEX, _ROUTE_BEDROCK):
        return forced
    base_url = getattr(client, "base_url", None) or _cfg.get("base_url") or ""
    host = urlsplit(str(base_url)).hostname or str(base_url)
    host = (host or "").lower()
    if not host:
        return _ROUTE_ANTHROPIC
    if _BEDROCK_HOST_RX.search(host):
        return _ROUTE_BEDROCK
    if _VERTEX_HOST_RX.search(host):
        return _ROUTE_VERTEX
    if _ANTHROPIC_HOST_RX.search(host):
        return _ROUTE_ANTHROPIC
    # Failing closed is correct, but a live run proved it is also SILENT: a
    # full scan through an unrecognised gateway sent ~8.1M prompt tokens
    # uncached, recorded cache_read=0/cache_write=0 at every stage, and the
    # only mechanism that would have named the cause (`doctor --cache-probe`)
    # is opt-in. So the fallthrough itself tells the operator, exactly once —
    # here rather than at a withhold site, because all three withhold sites
    # (the prefix builder _build_cache_prefix_content, the system-block
    # builder _build_system_content, and the agentic history marker
    # _with_cache_marker) gate through this function, and a note at any single
    # site is invisible to profiles that only exercise the others (an
    # agentic-only profile never passes a cache_prefix). Only this
    # auto-detected fallthrough notes: an
    # explicit `cache_route: none` (handled above) is the operator's decision,
    # not a missed one, and `cache_markers: off` likewise, hence the
    # markers-enabled gate. warn_once bounds the cost of this choke point
    # sitting inside the S10 remediation path (plugin_runner calls
    # sdk.agentic → _with_cache_marker → here) to at most ONE informational
    # stderr line per process — and any profile whose detection stages also
    # run on sdk consumes it at preflight/S0, long before S10.
    # No inner markers-enabled check: every caller of this function already
    # gates on _cache_markers_enabled(), so re-testing it here could never be
    # False — dead defensiveness that also hid the real reason the note is
    # bounded (warn_once), and made a pure classifier look conditional.
    #
    # Wording note: markers default to ON when the key is absent, so do NOT
    # quote `cache_markers: on` as though the operator wrote it — they would
    # grep a shipped profile, find nothing, and discount the remedy.
    warn_once(
        _CACHE_ROUTE_NOTED, _ROUTE_UNKNOWN,
        "    [sdk] note: prompt caching is enabled by default, but the "
        "configured endpoint is not recognised as Anthropic, Vertex or "
        "Bedrock (route classification: unknown), so cache markers are "
        "withheld and prompt tokens are billed uncached on this route. If "
        "the gateway is Anthropic-Messages-compatible, set "
        "`cache_route: anthropic` in your config to enable prompt caching. "
        "This affects cost only; scan results are unchanged.")
    return _ROUTE_UNKNOWN


def _cache_markers_enabled() -> bool:
    """The kill switch: `cache_markers: off` suppresses every marker, on every route."""
    return _cache.markers_enabled(_cfg)


# Published per-model minimum cacheable prefix sizes, in REAL tokens. Below the minimum the API
# silently caches nothing — no error, just cache_creation_input_tokens=0 while the marker still
# consumes one of the request's 4 slots — so this table must be right by construction. The
# sequence is NON-MONOTONIC across releases (opus-4-5/4-6 need MORE than 4-7, which needs more
# than 4-8), so no version-ordering heuristic is safe; an unseen model gets the largest published
# minimum. First match wins, so specific minors precede their bare-family catch-alls.
_CACHE_MIN_TOKENS_TABLE: tuple[tuple[re.Pattern, int], ...] = (
    (re.compile(r"opus-5|fable-5", re.IGNORECASE), 512),
    (re.compile(r"opus-4[-.]?[56]|haiku-4[-.]?5", re.IGNORECASE), 4096),
    (re.compile(r"opus-4[-.]?7|haiku-3[-.]?5", re.IGNORECASE), 2048),
    # opus-4, opus-4-1, opus-4-8 and every sonnet-4* / sonnet-5* variant.
    (re.compile(r"opus-4|sonnet-[45]", re.IGNORECASE), 1024),
)
_CACHE_MIN_TOKENS_FALLBACK = 4096


def _cache_min_tokens_for(model: str) -> int:
    """Minimum cacheable prefix size (real tokens) for `model`, or the operator's forced floor."""
    override = _cfg.get("cache_min_block_tokens")
    if override:
        return int(override)
    for rx, floor in _CACHE_MIN_TOKENS_TABLE:
        if rx.search(model or ""):
            return floor
    return _CACHE_MIN_TOKENS_FALLBACK


# Same value and rationale as the openai path, defined once in llm/cache.py.
_CACHE_EST_MARGIN = _cache.CACHE_EST_MARGIN


def _cache_prefix_meets_minimum(text: str, model: str, *,
                                preceding: str = "") -> bool:
    """Whether a breakpoint after `text` is estimated to clear the model's minimum cacheable size.

    The provider evaluates the minimum against the CUMULATIVE prefix — everything rendered before
    the marker, in the order tools -> system -> messages — not the marked block alone, so callers
    pass whatever precedes `text` in `preceding`. Each part is rated on its OWN character mix, so a
    prose system prompt and a dense source prefix are each estimated at their own density.
    """
    floor = _cache_min_tokens_for(model)
    est = estimate_tokens(preceding) + estimate_tokens(text)
    return est * _CACHE_EST_MARGIN >= floor


def _build_cache_prefix_content(client, cache_prefix: str | None,
                                user_prompt: str | list[dict], *,
                                model: str,
                                preceding: str = "") -> str | list[dict]:
    """Decide how to deliver `cache_prefix` + `user_prompt`, in order of preference.

    No `cache_prefix` returns the plain `user_prompt`, byte-identical to a call that never passed
    the parameter. With one, a capable route plus a cumulative prefix over the model's minimum
    earns two blocks with a breakpoint at the boundary. Anything else (unknown route, sub-minimum
    prefix, kill switch off) concatenates into ONE block, prefix first — no breakpoint, but the
    prefix stays leading and stable, so a route with only an implicit cache still benefits. Markers
    are the smaller half of this optimisation; a prompt's prefix is never destabilised to attempt
    one.
    """
    if not cache_prefix:
        return user_prompt

    route = None
    if _cache_markers_enabled():
        candidate = _cache_route(client)
        if (candidate in _CACHE_CONTROL_ROUTES
                and _cache_prefix_meets_minimum(cache_prefix, model,
                                                preceding=preceding)):
            route = candidate

    # Blocks can't be string-concatenated, so both shapes prepend the prefix as its own text
    # block — with cache_control when the gate allows, plain otherwise.
    if isinstance(user_prompt, list):
        prefix_block: dict = {"type": "text", "text": cache_prefix}
        if route is not None and user_prompt:
            prefix_block["cache_control"] = {"type": "ephemeral"}
        return [prefix_block, *user_prompt]

    # An empty trailing text block is rejected by the API, and a prefix equal to the whole prompt
    # leaves nothing behind it — there is nothing to gain from a breakpoint with an empty half.
    if route is not None and user_prompt:
        return [
            {"type": "text", "text": cache_prefix,
             "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": user_prompt},
        ]
    # Bedrock is withheld for a narrower reason than the other unrecognised routes: Anthropic
    # models there DO accept `cache_control` on InvokeModel, but this package only builds a plain
    # Anthropic-Messages client (it cannot sign SigV4), so a Bedrock-looking base_url reached
    # through it is necessarily an intermediary whose marker handling is unverified — and Bedrock
    # reports usage under names this codebase does not parse, so even a working marker would read
    # as zero. An operator fronting it with a normalising gateway declares `cache_route: anthropic`.
    return cache_prefix + user_prompt


def _build_system_content(client, system_prompt: str, model: str, *,
                          tools_text: str = "") -> str | list[dict]:
    """System block for one call: one block carrying a marker when one is worth placing, else the
    plain string (identical semantics on the wire, just no marker).

    The marker used to be unconditional here, which contradicted `_cache_route`'s fail-closed
    rationale: the prefix breakpoint was withheld from an unknown route because "a rejected field
    turns a scan into a failure", yet that same endpoint was sent `cache_control` on the system
    block of every call — a gateway strict enough to 400 would have rejected there first and the
    protection never engaged. Now every marker obeys `_CACHE_CONTROL_ROUTES`.

    The minimum is cumulative and tool schemas render ahead of the system block, so their
    serialized text participates via `tools_text`. s4's system prompt is the borderline case: every
    offline estimate lands just under claude-opus-4-7's 2,048 floor while the real tokenizer
    commonly counts higher, so `_CACHE_EST_MARGIN` resolves that doubt toward marking — a statement
    about this gate's decision, not a promise the provider caches the block.
    """
    if (_cache_markers_enabled()
            and _cache_route(client) in _CACHE_CONTROL_ROUTES
            and _cache_prefix_meets_minimum(system_prompt, model,
                                            preceding=tools_text)):
        return [{
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"},
        }]
    return system_prompt


# `cache_creation` is the typed per-TTL breakdown of cache_creation_input_tokens, whose total that
# field already carries — accounted for, not missed.
_PARSED_USAGE_CACHE_KEYS = frozenset({
    "cache_creation_input_tokens", "cache_read_input_tokens", "cache_creation",
})


def _note_unparsed_cache_keys(usage: dict | None) -> None:
    """Flag cache accounting reported under key names this module does not parse.

    The SDK's usage model is extra='allow' and its streaming accumulator seeds the snapshot from
    message_start's raw payload while message_delta overwrites only TYPED fields, so a gateway's
    foreign names (e.g. Bedrock's cacheReadInputTokens) survive into msg.usage.model_dump()
    alongside the None-valued typed fields — the information is already in memory, it just has to
    be looked at.
    """
    _cache.report_unparsed_cache_keys(usage, _PARSED_USAGE_CACHE_KEYS,
                                      via="sdk", label="sdk")


# prompt() — single-shot, no tools. Same return contract as cli.prompt().

#: Ceiling on total attempts after bounded extra-send grants (param-drop / truncation retry).
_ATTEMPTS_CEILING: Final = 6

_NO_TEMP_MODELS: set[str] = set()
_NO_THINK_MODELS: set[str] = set()
_NO_TEMP_RX = re.compile(
    r"opus-4[-.]?([7-9]|\d{2,})|opus-[5-9]|sonnet-[5-9]|haiku-[5-9]",
    re.IGNORECASE,
)


def _supports_temperature(model: str) -> bool:
    if model in _NO_TEMP_MODELS:
        return False
    return not _NO_TEMP_RX.search(model)


def _cause_chain(e: Exception) -> str:
    """Flatten an exception's __cause__ chain, where a proxy/TLS root cause actually surfaces."""
    parts, c = [], e.__cause__
    while c is not None:
        parts.append(f"{type(c).__name__}: {c}")
        c = c.__cause__
    return " <- ".join(parts)


def _is_transient_sdk(error: anthropic.APIStatusError) -> bool:
    """True for a retryable status, or a transient a gateway reported in the message instead.

    The message fallback is what a status set cannot do: a gateway has delivered "Rate limiting
    temporarily unavailable" as an APIStatusError with status_code=200. Connection-drop prose is
    not matched here — this transport raises dropped sockets as anthropic.APIConnectionError,
    which has its own retry branch.
    """
    if error.status_code in RETRYABLE_STATUS:
        return True
    # Prose may not PROMOTE an explicit auth status: a 401/403 does not heal on a retry, however
    # transient its wording, and a DLP or proxy block page returned under one routinely says
    # "Service Unavailable". Kept even though prompt() now decides auth first, because agentic()
    # has no auth branch at all and would otherwise burn its whole ladder on an unhealable status.
    # openai._is_transient_oai carries the identical rule.
    if error.status_code in (401, 403):
        return False
    return bool(RATE_LIMIT_TRANSIENT_RX.search(error.message)
                or SERVER_ERROR_TRANSIENT_RX.search(error.message))


def prompt(
    user_prompt: str | list[dict],
    *,
    model: str,
    cache_prefix: str | None = None,
    system_prompt: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
    thinking_budget: int | None = None,
    betas: list[str] | None = None,
    # Accepted-but-ignored so the dispatcher can pass through cli.prompt() calls without crashing.
    json_schema: dict | None = None,
    output_format: str = "text",
    cwd: str | None = None,
    max_budget_usd: float | None = None,
    timeout: int | None = None,
    tag: str | None = None,
) -> str:
    client = _get_client()
    max_tok = max_tokens or 16000

    # The system prompt renders ahead of the user turn, so it counts toward the cumulative minimum
    # for the prefix breakpoint. On s4 this is decisive: system + shard prefix clear the model
    # minimum together even when neither would alone.
    user_content = _build_cache_prefix_content(
        client, cache_prefix, user_prompt,
        model=model, preceding=system_prompt or "")

    kw: dict = {
        "model": model,
        "max_tokens": max_tok,
        # user_content, not user_prompt: whatever _build_cache_prefix_content decided — the
        # untouched prompt when no cache_prefix was passed, else prefix-then-remainder with a
        # breakpoint only where the route/minimum/kill-switch gate allows one.
        "messages": [{"role": "user", "content": user_content}],
    }
    if betas:
        kw["extra_headers"] = {"anthropic-beta": ",".join(betas)}
    if thinking_budget and model not in _NO_THINK_MODELS:
        # Current models dropped fixed-budget thinking (400 on budget_tokens); adaptive is the mode.
        if max_tok <= thinking_budget:
            max_tok = thinking_budget + 8000
            kw["max_tokens"] = max_tok
        kw["thinking"] = {"type": "adaptive"}
        temperature = None
    if temperature is not None:
        if _supports_temperature(model):
            kw["temperature"] = temperature
        elif model not in _NO_TEMP_MODELS:
            _NO_TEMP_MODELS.add(model)
            print(f"    [sdk] note: {model} does not accept `temperature`; "
                  f"dropping T={temperature} for this and subsequent calls",
                  file=sys.stderr)
    if system_prompt:
        # s4 reuses this block across chunk×run for cache-read savings, but placement is gated
        # identically to the prefix breakpoint — see _build_system_content.
        kw["system"] = _build_system_content(client, system_prompt, model)

    _up_chars = (
        sum(len(b.get("text", "")) for b in user_prompt if isinstance(b, dict))
        if isinstance(user_prompt, list) else len(user_prompt)
    )
    print(f"    [sdk] prompt -> {model}{f' [{tag}]' if tag else ''} "
          f"({_up_chars} chars, "
          f"max_tokens={max_tok}"
          f"{f', T={temperature}' if 'temperature' in kw else ''}"
          f"{f', thinking={thinking_budget}' if 'thinking' in kw else ''})",
          file=sys.stderr)

    stream_client = client.with_options(timeout=float(timeout)) if timeout else client

    attempts, retry_wait = 3, 60
    auth_attempt = 0
    msg = None
    # VVAH-E005 state: one cap-bounded doubled-budget retry per call, then fail loud.
    trunc_retried = False
    trunc_retry_at = 0
    # `attempts` is read live so a param-drop on the final attempt can grant one bounded extra send.
    attempt = 0
    while attempt < attempts:
        attempt += 1
        try:
            # Stream so large max_tokens (64k) doesn't trip the HTTP timeout; just need final msg.
            with stream_client.messages.stream(**kw) as stream:
                msg = stream.get_final_message()
            if msg.stop_reason == ANTHROPIC_STOP_MAX_TOKENS:
                # Budget exhausted: one doubled retry bounded by the model's own cap, then E005.
                requested_now = kw["max_tokens"]
                retry_at = (None if trunc_retried else truncation_retry_max(
                    requested_now, cap=MODEL_MAX_OUTPUT_TOKENS))
                if retry_at is not None:
                    # A final-attempt truncation still gets its retry, capped like param-drops.
                    if attempt == attempts and attempts < _ATTEMPTS_CEILING:
                        attempts += 1
                    if attempt < attempts:
                        trunc_retried, trunc_retry_at = True, retry_at
                        print(f"    [sdk] truncated reply (stop_reason="
                              f"{ANTHROPIC_STOP_MAX_TOKENS}, max_tokens="
                              f"{requested_now}); retrying once at {retry_at}",
                              file=sys.stderr)
                        _errlog.log(
                            tag or "sdk", tag or "truncation",
                            f"VVAH-E005 warning: reply truncated at "
                            f"max_tokens={requested_now}; retrying once at "
                            f"{retry_at}",
                            error_code=TruncatedResponseError.error_code,
                            recovered=True)
                        kw["max_tokens"] = retry_at
                        msg = None
                        continue
                COUNTERS.bump(TRUNCATED_REPLIES_COUNTER)
                if trunc_retried:
                    trunc_msg = ("reply still hit the output-token budget "
                                 "after the doubled retry")
                elif retry_at is None:
                    trunc_msg = (f"max_tokens={requested_now} is already at "
                                 f"the model output cap "
                                 f"({MODEL_MAX_OUTPUT_TOKENS}); no useful "
                                 f"retry")
                else:
                    trunc_msg = ("reply hit the output-token budget with no "
                                 "retry budget left")
                raise TruncatedResponseError(
                    trunc_msg,
                    stage=tag or "",
                    requested=max_tok,
                    retried=trunc_retry_at,
                )
            break
        except anthropic.APIStatusError as e:
            body = str(getattr(e, "message", e))
            low = body.lower()
            if ("temperature" in kw and "temperature" in low
                    and e.status_code == 400):
                _NO_TEMP_MODELS.add(model)
                print(f"    [sdk] {model} rejected `temperature` — "
                      f"retrying without it", file=sys.stderr)
                kw.pop("temperature", None)
                if attempt == attempts and attempts < _ATTEMPTS_CEILING:
                    attempts += 1  # grant the cleaned request one more send (capped)
                continue
            if ("thinking" in kw and "thinking" in low
                    and ("not supported" in low or "unexpected" in low
                         or "adaptive" in low or e.status_code == 400)):
                _NO_THINK_MODELS.add(model)
                print(f"    [sdk] {model} rejected extended thinking "
                      f"({kw['thinking']}) — retrying without it",
                      file=sys.stderr)
                kw.pop("thinking", None)
                if attempt == attempts and attempts < _ATTEMPTS_CEILING:
                    attempts += 1  # grant the cleaned request one more send (capped)
                continue
            # VVAH-E001: auth is synchronous, so a few fast retries then halt (not the 60s loop).
            # Checked BEFORE the transient arm, matching cli._run_with_retry and openai.prompt --
            # this backend used to have it the other way round, and a gateway that answers with an
            # in-band error payload exposed why: a body carrying BOTH auth prose and transient prose
            # took the 60s ladder twice, then fell out of the loop with `msg is None` and died on the
            # post-loop parameter-drop guard, losing AuthenticationError, the VVAH-E001 error_code in
            # errors.jsonl, the credential remediation block and the batch halt. Auth cannot heal on
            # a retry, so deciding it first is both safer and cheaper. Consequence to know: a
            # retryable STATUS whose body also carries auth prose (a 503 mentioning an expired token)
            # now takes the auth path rather than the transient one.
            # A RETRYABLE status beats prose: a 503/429 whose payload happens to say
            # "authentication_failed" is an outage, and the 60s ladder is what rides
            # one out. Only a status no retry can help — or an explicit 401 — is auth.
            if e.status_code == 401 or (_AUTH_STATUS_RX.search(body)
                                        and e.status_code not in RETRYABLE_STATUS):
                # `attempt < attempts` as well as the auth budget: the two used to be
                # equal (3 and 3), so every send was spent on a `continue` and the
                # raise below was UNREACHABLE — a wrong credential exhausted the loop
                # and surfaced as the post-loop "every attempt hit a parameter-drop
                # retry" RuntimeError instead, with no AuthenticationError, no
                # VVAH-E001 error_code in errors.jsonl and no batch halt. Reserving
                # the final send for the raise is what actually delivers them.
                if auth_attempt < _AUTH_MAX_RETRIES_SDK and attempt < attempts:
                    wait = _AUTH_BACKOFF_SDK[min(auth_attempt,
                                                 len(_AUTH_BACKOFF_SDK) - 1)]
                    print(f"    [sdk] authentication error "
                          f"(status={e.status_code}, attempt "
                          f"{auth_attempt + 1}/{_AUTH_MAX_RETRIES_SDK}); "
                          f"retrying in {wait}s", file=sys.stderr)
                    time.sleep(wait)
                    auth_attempt += 1
                    continue
                # redact() BEFORE [:400]: truncating first can cut a JWT segment / PEM end
                # marker so the pattern no longer matches and raw credential text survives.
                raise AuthenticationError(redact(body)[:400],
                                          status_code=e.status_code,
                                          backend="sdk") from e
            if _is_transient_sdk(e) and attempt < attempts:
                print(f"    [sdk] transient error (status={e.status_code}, "
                      f"attempt {attempt}/{attempts}, model={model}); retrying "
                      f"in {retry_wait}s", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            # Scrub the response body (may reflect auth headers/cookies) before the exception text.
            raise RuntimeError(
                f"Anthropic SDK call failed (status={e.status_code}, model={model}): "
                f"{redact(body)}"
            ) from e
        except anthropic.APIConnectionError as e:
            detail = _cause_chain(e)
            # VVAH-E002: proxy/TLS misconfiguration cannot heal, so don't burn the retry budget.
            if _PROXY_CAUSE_RX.search(detail) or _PROXY_CAUSE_RX.search(str(e)):
                # redact() BEFORE [:400]: truncating first can cut a JWT segment / PEM end
                # marker so the pattern no longer matches and raw credential text survives.
                raise ProxyError(
                    redact(detail or str(e))[:400],
                    status_code=407 if re.search(r"\b407\b", detail) else None,
                    backend="sdk",
                ) from e
            if attempt < attempts:
                print(f"    [sdk] connection error (attempt {attempt}/{attempts}): "
                      f"{e} — retrying in {retry_wait}s", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            raise RuntimeError(
                f"Anthropic SDK connection error after {attempts} attempts "
                f"(model={model}): {redact(str(e))}\n"
                f"  cause: {redact(detail or 'no underlying cause reported')}\n"
                f"  hint: this is a network/TLS/DNS/proxy failure, not an auth/model "
                f"error. On corp networks set SSL_CERT_FILE to your CA bundle, and "
                f"check HTTPS_PROXY / ANTHROPIC_SDK_BASE_URL."
            ) from e

    if msg is None:
        raise RuntimeError(
            f"Anthropic SDK call to {model} exhausted all retries without a "
            f"successful response (every attempt hit a parameter-drop retry). "
            f"Final request kwargs keys: {sorted(kw)}."
        )

    usage = cast("TokenUsage", msg.usage.model_dump()) if msg.usage else None
    _note_unparsed_cache_keys(usage)
    TOKENS.add(usage)
    if usage:
        _in = (usage.get("input_tokens", 0)
               + (usage.get("cache_creation_input_tokens") or 0)
               + (usage.get("cache_read_input_tokens") or 0))
        cr = usage.get("cache_read_input_tokens") or 0
        cw = usage.get("cache_creation_input_tokens") or 0
        out = usage.get("output_tokens", 0)
        cache_info = f" (cache_read={cr}, cache_write={cw})" if (cr or cw) else ""
        print(f"    [sdk] usage: in={_in}{cache_info} out={out}", file=sys.stderr)

    text = "".join(b.text for b in msg.content if b.type == "text")
    # absent-vs-zero matters; see output_tokens_for_gate.
    out_tokens = output_tokens_for_gate(usage)
    check_response_quality(text.strip(), stage=tag or "",
                           output_tokens=out_tokens)
    return text.strip()


# agentic(): read-only tool loop (Read/Glob/Grep); mutation/Bash delegates to agent_sdk.py sandbox.

_AGENTIC_MAX_TOK = AGENTIC_MAX_TOKENS
_AGENTIC_MAX_TURNS = 40


def _assistant_blocks(content) -> list[dict]:
    """Serialize SDK response blocks back into the dict shape the Messages
    API expects on the next turn. Unknown block types are passed through via
    model_dump() so a newer SDK doesn't break the loop."""
    out: list[dict] = []
    for b in content:
        bt = getattr(b, "type", None)
        if bt == "text":
            out.append({"type": "text", "text": b.text})
        elif bt == "tool_use":
            out.append({"type": "tool_use", "id": b.id,
                        "name": b.name, "input": b.input})
        else:
            try:
                d = b.model_dump()
                d.pop("cache_control", None)  # never persist markers in history
                out.append(d)
            except Exception:  # noqa: BLE001
                pass
    return out


def _with_cache_marker(client, msgs: list[dict]) -> list[dict]:
    """Return a copy of `msgs` with cache_control stripped and one ephemeral
    marker placed on the last content block, so stored history stays marker-free
    and can never exceed the API's 4-block cache_control cap.

    Route-gated like every other marker here. No minimum-size check applies: the provider measures
    the CUMULATIVE prefix (tools + system + the whole conversation), which grows monotonically each
    turn, so a first-turn miss is silent, costs only an idle slot, and self-corrects."""
    out: list[dict] = []
    last_block: dict | None = None
    for m in msgs:
        c = m.get("content")
        if isinstance(c, list):
            cc: list = []
            for b in c:
                if isinstance(b, dict):
                    b = {k: v for k, v in b.items() if k != "cache_control"}
                    last_block = b
                cc.append(b)
            out.append({**m, "content": cc})
        else:
            out.append(m)
    if (last_block is not None and _cache_markers_enabled()
            and _cache_route(client) in _CACHE_CONTROL_ROUTES):
        last_block["cache_control"] = {"type": "ephemeral"}
    return out


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,   # accepted for parity; unused
    permission_mode: str = "auto",         # accepted for parity; unused
    max_turns: int | None = None,
    tag: str | None = None,
    # Caller-supplied tools, in addition to the read-only localtools named by
    # `allowed_tools`. `extra_tools` are Anthropic tool schemas; `extra_dispatch(name,
    # input)` runs one and returns its string result, or None to defer (a localtools
    # name, or genuinely unknown). This is how a caller with its own tool — e.g. exploit
    # verification's `http_request` — drives this loop instead of maintaining a parallel
    # one. A caller tool is the caller's to log and (if needed) size-cap in its own
    # dispatch; this loop only logs the localtools IT runs. Everything defaults to today's
    # behavior, so the shipped callers that pass none are byte-identical.
    extra_tools: list[dict] | None = None,
    extra_dispatch=None,
) -> str:
    turns_cap = int(max_turns) if max_turns else _AGENTIC_MAX_TURNS
    # `None` means unspecified (take the read-only default); an EMPTY list means the caller
    # wants no localtools at all. Folding the two together with `or` made that request
    # impossible to express, and silently added read tools a caller supplying its own would
    # then advertise twice — which the API rejects outright.
    allowed = list(DEFAULT_READ_TOOLS) if allowed_tools is None else list(allowed_tools)
    if "Bash" in allowed:
        raise ValueError(
            "sdk.agentic: `Bash` is forbidden on `via: sdk`; remove it from "
            "allowed_tools or switch that role to `via: cli`.")
    ok, missing = _localtools.supported(allowed)
    if missing:
        # The local raw-anthropic loop is read-only (Read/Glob/Grep). A role
        # that needs file-MUTATION tools (Edit/Write — the Remediation Agent's
        # `fix` mode) or Bash is routed to the Claude Agent SDK, which provides
        # those tools natively inside a cwd-confined permission sandbox (the
        # same runtime the `vvaharness validate` agent uses). This keeps
        # `via: sdk` a drop-in for fix-mode remediation instead of forcing
        # via:cli.
        if extra_tools:
            # The Agent SDK path can't carry a caller-supplied tool, so a request that
            # mixes both has no coherent routing. No shipped caller does this.
            raise ValueError(
                "sdk.agentic: extra_tools cannot be combined with mutating/Bash tools "
                f"that route to the Claude Agent SDK ({missing})")

        # Mutation/Bash tools route to the Agent SDK's sandbox, keeping `via: sdk` fix-mode-capable.
        from vvaharness.backends.llm import (  # noqa: PLC0415 — lazy: agent SDK is optional
            agent_sdk as _agent_sdk,
        )
        print(f"    [sdk] agentic requests {missing} (mutating/Bash) — "
              f"delegating to the Claude Agent SDK backend", file=sys.stderr)
        return _agent_sdk.agentic(
            user_prompt, model=model, system_prompt=system_prompt,
            allowed_tools=allowed, cwd=cwd, max_budget_usd=max_budget_usd,
            permission_mode=permission_mode, max_turns=max_turns, tag=tag,
        )
    client = _get_client()
    tools = [*_localtools.anthropic_schemas_for(ok), *(extra_tools or [])]
    advertised = ok + [t.get("name") for t in (extra_tools or [])]

    base_kw: dict = {"model": model, "max_tokens": _AGENTIC_MAX_TOK,
                     "tools": tools}
    if system_prompt:
        # Tool schemas render ahead of the system block and count toward the cumulative minimum,
        # so their serialized size is what precedes it.
        base_kw["system"] = _build_system_content(
            client, system_prompt, model,
            tools_text=json.dumps(tools, default=str))
    messages: list[dict] = [{"role": "user", "content": user_prompt}]

    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [sdk] agentic -> {model}{tag_sfx} (tools={advertised}, "
          f"max_turns={turns_cap}, cwd={cwd})", file=sys.stderr)

    tool_calls_total = 0
    for turn in range(1, turns_cap + 1):
        msg = None
        transients = 0
        while msg is None:
            try:
                with client.messages.stream(messages=_with_cache_marker(client, messages),
                                             **base_kw) as stream:
                    msg = stream.get_final_message()
            except anthropic.APIStatusError as e:
                if _is_transient_sdk(e) and transients < 4:
                    transients += 1
                    print(f"    [sdk] agentic transient (status={e.status_code}, "
                          f"turn={turn}, retry {transients}/4); retrying",
                          file=sys.stderr)
                    time.sleep(min(60, 20 * transients))
                    continue
                # redact() wraps the WHOLE message, not just the provider text:
                # a gateway echoes the presented credential in `message`, and
                # redacting the assembled string cannot miss a field a later
                # edit adds. Applied before any truncation for the same reason
                # the auth/proxy raises are — see _mtls_verify's sibling note.
                raise RuntimeError(redact(
                    f"Anthropic SDK agentic call failed (status={e.status_code}, "
                    f"model={model}, turn={turn}): {getattr(e, 'message', e)}"
                )) from e
            except anthropic.APIConnectionError as e:
                if transients < 4:
                    transients += 1
                    print(f"    [sdk] agentic connection error (turn={turn}, "
                          f"retry {transients}/4); retrying", file=sys.stderr)
                    time.sleep(min(60, 20 * transients))
                    continue
                raise RuntimeError(redact(
                    f"Anthropic SDK agentic connection error (model={model}, "
                    f"turn={turn}): {e}\n  cause: "
                    f"{_cause_chain(e) or 'no underlying cause reported'}"
                )) from e

        if msg.usage:
            turn_usage = cast("TokenUsage", msg.usage.model_dump())
            _note_unparsed_cache_keys(turn_usage)
            TOKENS.add(turn_usage)

        if msg.stop_reason != "tool_use":
            text = "".join(b.text for b in msg.content
                           if getattr(b, "type", None) == "text").strip()
            print(f"    [sdk] agentic done in {turn} turn(s), "
                  f"{tool_calls_total} tool call(s)", file=sys.stderr)
            return text

        messages.append({"role": "assistant",
                         "content": _assistant_blocks(msg.content)})
        results: list[dict] = []
        for b in msg.content:
            if getattr(b, "type", None) != "tool_use":
                continue
            tool_calls_total += 1
            args = dict(b.input or {})
            # A caller-supplied tool goes to extra_dispatch (the caller logs and caps it);
            # a localtools name returns None from it and is executed and logged here, so
            # the log follows whichever layer actually ran the tool. Same precedence as
            # openai.agentic — without it the extra_tools advertised above are offered to
            # the model and then never run.
            out = extra_dispatch(b.name, args) if extra_dispatch is not None else None
            if out is None:
                out = _localtools.execute(b.name, args, cwd=cwd)
                if not is_stage_only():
                    print(f"      [sdk] tool {b.name}({_localtools.summarize_args(b.input)}) -> "
                          f"{len(out)} chars", file=sys.stderr)
            results.append({"type": "tool_result",
                            "tool_use_id": b.id,
                            "content": out})
        # cache_control is applied at request time; history stays marker-free under the 4-block cap.
        messages.append({"role": "user", "content": results})

    # Budget exhausted: force a final answer with tools disabled, same as oai.agentic().
    print(f"    [sdk] WARN: agentic hit max_turns={turns_cap} without a "
          f"final answer (model={model}); forcing one", file=sys.stderr)
    messages.append({
        "role": "user",
        "content": "Tool budget exhausted. Reply now with your final answer "
                   "based on what you have read so far; do not call any tool.",
    })
    final_kw = {k: v for k, v in base_kw.items() if k != "tools"}
    final_kw["tool_choice"] = {"type": "none"}
    final_kw["tools"] = tools  # API requires tools when tool_choice is set
    final_transients = 0
    while True:
        try:
            with client.messages.stream(messages=_with_cache_marker(client, messages),
                                         **final_kw) as stream:
                msg = stream.get_final_message()
            break
        except anthropic.APIStatusError as e:
            if _is_transient_sdk(e) and final_transients < 4:
                final_transients += 1
                print(f"    [sdk] agentic forced-final transient "
                      f"(status={e.status_code}, retry {final_transients}/4); retrying",
                      file=sys.stderr)
                time.sleep(min(60, 20 * final_transients))
                continue
            raise RuntimeError(redact(
                f"Anthropic SDK agentic forced-final failed "
                f"(status={e.status_code}, model={model}): "
                f"{getattr(e, 'message', e)}"
            )) from e
        except anthropic.APIConnectionError as e:
            if final_transients < 4:
                final_transients += 1
                print(f"    [sdk] agentic forced-final connection error "
                      f"(retry {final_transients}/4); retrying", file=sys.stderr)
                time.sleep(min(60, 20 * final_transients))
                continue
            raise RuntimeError(redact(
                f"Anthropic SDK agentic forced-final connection error "
                f"(model={model}): {e}\n  cause: "
                f"{_cause_chain(e) or 'no underlying cause reported'}"
            )) from e
    if msg.usage:
        final_usage = cast("TokenUsage", msg.usage.model_dump())
        _note_unparsed_cache_keys(final_usage)
        TOKENS.add(final_usage)
    return "".join(b.text for b in msg.content
                   if getattr(b, "type", None) == "text").strip()
