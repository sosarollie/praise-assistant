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

"""OpenAI backend; third `via:` option alongside cli/sdk, same surface, set via config.yaml.
Auth: OPENAI_API_KEY or cfg.openai.api_key; base_url defaults to https://api.openai.com/v1.
Streams; newer models (o-series, gpt-5+) need max_completion_tokens, reject temperature.

Prompt caching here rides the provider's IMPLICIT cache, never an explicit breakpoint. OpenAI
does offer `prompt_cache_breakpoint`/`prompt_cache_options`, but they require switching the user
turn to a content-block list — a request-shape change a strict OpenAI-compatible gateway can 400
on with no single error signature to self-heal from, unlike the unknown top-level parameter this
module does send. Implicit caching is automatic from the start of the prompt on gpt-4o and newer,
and `cache_prefix` is already delivered first and byte-stable, so a breakpoint would buy
measurement control rather than hits. `cache_prefix` is accepted for parity with the sdk backend
and concatenated onto the front of the user turn; `prompt_cache_key` (see `_prompt_cache_key`)
lets a provider that load-balances on it route repeat calls back to the same warm cache.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
import warnings
from typing import Final

import httpx
import openai
import urllib3

try:
    import httpx2
except ImportError:  # openai<3 environments are backed by classic httpx only
    httpx2 = None

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
    DEFAULT_READ_TOOLS,
    OPENAI_FINISH_LENGTH,
    RATE_LIMIT_TRANSIENT_RX,
    RETRYABLE_STATUS,
    SERVER_ERROR_TRANSIENT_RX,
    TRUNCATED_REPLIES_COUNTER,
    OpenAiConfig,
    truncation_retry_max,
)
from vvaharness.backends.llm.tls import (
    coerce_verify,
    scoped_no_proxy_env,
    warn_verify_disabled,
)
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.util.counters import COUNTERS
from vvaharness.util.response_quality import check_response_quality, output_tokens_for_gate
from vvaharness.util.scan_progress import get_active_tracker
from vvaharness.util.tokens import TOKENS, TokenUsage, estimate_tokens

# Transport failures that surface RAW from stream iteration. The installed
# openai (>=3) is backed by httpx2, NOT classic httpx (openai/_base_client.py
# and openai/_streaming.py both `import httpx2`), so a mid-stream
# `RemoteProtocolError` is httpx2's class — an `except httpx.X` alone would
# silently never match it. The SDK wraps transport errors into
# APIConnectionError only around request send, and its retry loop ends before
# the stream body is iterated, so nothing upstream catches or retries these.
# Classic httpx stays in the tuple for openai<3 installs, where it is the
# transport actually raising.
_MIDSTREAM_TRANSPORT_ERRORS: tuple[type[Exception], ...] = (
    (httpx2.TransportError, httpx.TransportError) if httpx2 is not None
    else (httpx.TransportError,)
)

_AUTH_STATUS_RX_OAI = re.compile(
    r"unauthorized|invalid[_ ]api[_ ]key"
    # Bounded, not `.*`: an unanchored wildcard let a 400 reading
    # "invalid_request_error ... prompt is too long: 300000 tokens" match, so an
    # oversized chunk was logged three times as an authentication error and the
    # operator had no way to see the real cause.
    r"|invalid[^\n]{0,24}token|token[^\n]{0,24}(?:expired|invalid|revoked)"
    r"|authentication[_ ]failed|incorrect[_ ]api[_ ]key",
    re.IGNORECASE,
)
_PROXY_CAUSE_RX_OAI = re.compile(
    r"\b407\b|proxy[_ ]auth|tunnel[_ ](?:failed|error)|CONNECT.*failed"
    r"|SSL.*CERTIFICATE|CERTIFICATE.*VERIFY.*FAILED|CERT_VERIFY_FAILED"
    r"|certificate[_ ]verify[_ ]failed",
    re.IGNORECASE,
)
_AUTH_MAX_RETRIES_OAI = 3
_AUTH_BACKOFF_OAI = (2, 4, 8)

_REDACT_RX = re.compile(r"(sk-[A-Za-z0-9_-]{6})[A-Za-z0-9_-]+")
# Match a human-readable block reason in a corp-proxy/DLP page: `reason=` param, or rsn span.
_PROXY_REASON_RX = re.compile(
    r'(?:class="[^"]*\brsn\b[^"]*">\s*|class="[^"]*\breason\b[^"]*">\s*|reason=)'
    r'([^<&\n]{1,200})', re.I)


def _summarise_status_error(e) -> str:
    """Collapse a proxy/DLP HTML block page into one actionable line.
    Scrubs secrets it may reflect back (Authorization, Set-Cookie, sk- keys) and caps length."""
    body = ""
    resp = getattr(e, "response", None)
    if resp is not None:
        try:
            body = resp.text
        except Exception:
            body = ""
    body = body or str(getattr(e, "message", "") or e)
    low = body.lower()
    if "dlp" in low or "<html" in low:
        m = _PROXY_REASON_RX.search(body)
        reason = _scrub_secrets((m.group(1).strip() if m else "policy block"))
        return (f"blocked by corporate proxy/DLP — {reason}. "
                f"Request an exception or point openai.base_url at an "
                f"internal gateway; ")
    return redact(_scrub_secrets(body))[:300]


# Bearer tokens/api keys/cookies a proxy may reflect back in an error body; redact before logging.
_SECRET_LINE_RX = re.compile(
    r"(?im)^(.*?\b(authorization|api[-_ ]?key|x-api-key|cookie|set-cookie|"
    r"token|secret|bearer)\b\s*[:=]\s*).+$")
_BEARER_RX = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]+")


def _scrub_secrets(text: str) -> str:
    if not text:
        return text
    text = _REDACT_RX.sub(r"\1***", text)          # sk-XXXXXX… → sk-XXXXXX***
    text = _BEARER_RX.sub(r"\1***", text)          # Bearer <tok> → Bearer ***
    text = _SECRET_LINE_RX.sub(r"\1***", text)     # Header: <val> → Header: ***
    return text


def _cause_chain(e: Exception) -> str:
    parts, c = [], e.__cause__
    while c is not None:
        parts.append(f"{type(c).__name__}: {c}")
        c = c.__cause__
    detail = " <- ".join(parts) or "no underlying cause reported"
    return _REDACT_RX.sub(r"\1***", detail)


def _payload_shape(messages: list[dict], error_body: str) -> str:
    """One bounded line describing the request actually sent, appended to a
    terminal 400 so a vendor message that contradicts the payload is
    diagnosable from the error record alone. Shape metadata only — never
    message content, file contents or credential values.

    Motivating incident: a gateway rejected pure-text requests with an
    "image understanding feature is not available" 400 because the packed
    SOURCE TEXT carried a `data:image/...;base64,` marker (an HTML template
    placeholder). The error blamed images while the payload contained none,
    and diagnosis required reconstructing the payload offline. The counts
    below distinguish "our payload was wrong" (non-text block types present)
    from "the gateway is content-sniffing the text" (text-only, markers > 0)
    at a glance. The 400 itself stays terminal: it is deterministic and
    content-triggered, so a retry would pay twice for the same rejection.
    """
    chars = 0
    block_types: set[str] = set()
    markers = 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, str):
            block_types.add("text")
            chars += len(c)
            markers += c.count("data:image/")
        elif isinstance(c, list):
            for b in c:
                if isinstance(b, dict):
                    block_types.add(str(b.get("type") or "?"))
                    t = b.get("text")
                    if isinstance(t, str):
                        chars += len(t)
                        markers += t.count("data:image/")
    line = (f"payload sent: {len(messages)} message(s), content block "
            f"types={sorted(block_types) or ['none']}, {chars:,} chars, "
            f"data-URI markers in text={markers}")
    if "image" in error_body.lower() and block_types <= {"text"}:
        line += (" — request was text-only; a data:image;base64 marker inside "
                 "packed source can trip a vision-capability gate on some "
                 "gateways (exclude the carrying file from scope or "
                 "neutralise the marker)")
    return line


# Lazy, thread-safe singleton client (s4 runs in a ThreadPoolExecutor).

_client = None
_client_lock = threading.Lock()
# cache_markers "off" suppresses the `prompt_cache_key` field; this route emits no explicit
# breakpoint (see the module docstring), so there is nothing else for the switch to suppress.
_cfg: OpenAiConfig = {"api_key": None, "base_url": None, "verify_ssl": True,
              "ca_cert": None, "organization": None, "no_proxy": None,
              "cache_markers": "on"}


def configure(*, api_key: str | None = None, base_url: str | None = None,
              verify_ssl: bool | str | None = None,
              ca_cert: str | None = None,
              client_cert: str | tuple | list | None = None,
              organization: str | None = None,
              no_proxy: str | None = None,
              cache_markers: str | None = None) -> None:
    """Called once from the orchestrator before any OpenAI step runs. Optional —
    falls back to OPENAI_API_KEY / https://api.openai.com/v1 if never called.
    cache_markers: "on" (default) or "off" to suppress the `prompt_cache_key` field."""
    global _client
    with _client_lock:
        if api_key:
            _cfg["api_key"] = api_key
        if base_url:
            _cfg["base_url"] = base_url
        if verify_ssl is not None:
            _cfg["verify_ssl"] = coerce_verify(verify_ssl)
        if ca_cert:
            _cfg["ca_cert"] = ca_cert
        if client_cert:
            # Accepted only to DIAGNOSE it: this route has no mTLS plumbing, and
            # silently ignoring an operator's client_cert leaves them believing
            # mTLS is active. Mirrors the `via: cli` warning (cli.py:388).
            print("WARN [openai]: client_cert/mTLS is configured but the "
                  "`via: openai` backend cannot present a client certificate. "
                  "Use a `via: sdk` or `via: deepagents` role for mTLS "
                  "gateways.", file=sys.stderr)
        if organization:
            _cfg["organization"] = organization
        if no_proxy:
            _cfg["no_proxy"] = no_proxy
        if cache_markers is not None:
            _cfg["cache_markers"] = cache_markers
        _client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    with _client_lock:
        if _client is None:
            kw: dict = {"max_retries": 4}
            key = _cfg["api_key"] or os.environ.get("OPENAI_API_KEY")
            if key:
                # Env vars from files often carry a trailing newline; httpx rejects Authorization.
                kw["api_key"] = key.strip()
            # `or`-chain: an empty OPENAI_BASE_URL is falsy, falls back to the default endpoint.
            kw["base_url"] = (_cfg["base_url"]
                              or os.environ.get("OPENAI_BASE_URL")
                              or "https://api.openai.com/v1")
            if _cfg["organization"]:
                kw["organization"] = _cfg["organization"]
            ca = _cfg["ca_cert"]
            if ca and not os.path.exists(ca):
                print(f"WARN [openai]: ca_cert '{ca}' not found — falling back "
                      f"to verify_ssl={_cfg['verify_ssl']!r}", file=sys.stderr)
                ca = None
            verify = ca or _cfg["verify_ssl"]
            if verify is not True:
                if verify is False:
                    # TLS is OFF: suppress warning spam, but always warn loudly naming the endpoint.
                    warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                    warn_verify_disabled(kw.get("base_url"), label="openai",
                                         ca_hint="openai.ca_cert")
                kw["http_client"] = openai.DefaultHttpxClient(verify=verify)
            with scoped_no_proxy_env(_cfg.get("no_proxy")):
                _client = openai.OpenAI(**kw)
    return _client


def _cache_markers_enabled() -> bool:
    """Whether `cache_markers` permits the `prompt_cache_key` field this module sends."""
    return _cache.markers_enabled(_cfg)


# OpenAI's server-side cache engages from 1,024 prompt tokens counted CUMULATIVELY from the start
# of the rendered request, and only byte-identical prefixes hit. Deliberately ONE flat floor, not
# a per-model table like sdk.py's: OpenAI documents a single minimum, and a miss on this route
# costs nothing — it only selects a `prompt_cache_key` shard, changing no request field.
_CACHE_MIN_PROMPT_TOKENS = 1024

# Ring size for spreading no-shared-prefix traffic across keys. OpenAI's guidance caps a single
# key near 15 req/min before requests start missing; 8 buckets keeps a stage pool well under it
# even with parallelism raised past the shipped profiles.
_CACHE_KEY_SHARDS = 8

# Same value and rationale as the sdk path, defined once in llm/cache.py.
_CACHE_EST_MARGIN = _cache.CACHE_EST_MARGIN


def _prefix_meets_cache_minimum(text: str | None, *,
                                preceding: str = "") -> bool:
    """Whether a cache prefix ending at `text` is estimated to clear the provider's minimum.

    The provider measures its floor against the CUMULATIVE rendered prefix, so callers pass
    whatever renders ahead of `text` (here, the system message) in `preceding`; each part is
    rated on its own character mix. An empty `text` is never a cacheable prefix.
    """
    if not text:
        return False
    est = estimate_tokens(preceding or "") + estimate_tokens(text)
    return est * _CACHE_EST_MARGIN >= _CACHE_MIN_PROMPT_TOKENS


def _prompt_cache_key(tag: str | None, model: str,
                      cache_prefix: str | None = None, *,
                      preceding: str = "") -> str:
    """Deterministic routing key for `prompt_cache_key`, so a provider can bias load-balancing
    toward a server already holding this prefix.

    The base identity is (stage, repo, model) — stage being `tag`'s first word, repo the active
    tracker's short name, never `repo_root` (an absolute host path). No credential and no prompt
    content enters the key: anything content-derived is SHA-256'd first.

    A bare (stage, repo, model) key is not enough, because a fan-out stage (s4 runs hundreds of
    chunk calls) would push a whole stage through ONE key past the provider's ~15 req/min
    guidance. So it is sharded, stably across runs: a cacheable `cache_prefix` contributes a
    digest of itself, so exactly the calls that can hit each other's cache share a key; a
    sub-minimum prefix has no affinity worth protecting and rides a small fixed ring keyed on the
    rest of the tag; no prefix keeps the legacy per-stage key. `preceding` feeds only the size
    gate, never the digest — within one key base the system prompt is constant, so keeping it out
    means no extra prompt content can influence the key.
    """
    # `tag.split()[0]` raises IndexError on a whitespace-only tag, in the hottest function here.
    fields = (tag or "").split(None, 1)
    stage = fields[0] if fields else ""
    tracker = get_active_tracker()
    repo_name = (getattr(tracker, "repo_name", "") or "") if tracker else ""
    bucket = ""
    if cache_prefix:
        if _prefix_meets_cache_minimum(cache_prefix, preceding=preceding):
            bucket = hashlib.sha256(
                cache_prefix.encode("utf-8")).hexdigest()[:12]
        else:
            rest = fields[1] if len(fields) > 1 else ""
            shard = int(hashlib.sha256(rest.encode("utf-8")).hexdigest(),
                        16) % _CACHE_KEY_SHARDS
            bucket = f"r{shard}"
    raw = f"{stage}:{repo_name}:{model}:{bucket}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# prompt() — single-shot, no tools. Same return contract as cli/sdk.prompt().

#: Chat Completions output-budget parameter names; newer models accept only the second.
_MAX_TOKENS_KEY: Final = "max_tokens"
_MAX_COMPLETION_TOKENS_KEY: Final = "max_completion_tokens"
#: Ceiling on total attempts after bounded extra-send grants (param-drop / truncation retry).
_ATTEMPTS_CEILING: Final = 6

_NO_TEMP_MODELS: set[str] = set()
_USE_LEGACY_MAXTOK: set[str] = set()
# Endpoints that rejected the prompt-cache hint, remembered from a 400 so the rest of the run
# stops sending it.
_NO_CACHE_KEY_MODELS: set[str] = set()

def _is_transient_oai(error: openai.APIStatusError) -> bool:
    """True for a retryable status, or a transient a gateway reported in the message instead.

    The prose fallback mirrors sdk._is_transient_sdk: a gateway can wrap rate-limit/overload
    prose in a status no set can classify (seen as an HTTP 200 error payload). Connection-drop
    prose is not matched here — this transport raises dropped sockets as
    openai.APIConnectionError, which has its own retry branch.
    """
    if error.status_code in RETRYABLE_STATUS:
        return True
    # Prose may not PROMOTE an explicit auth status — see sdk._is_transient_sdk for the rule.
    # It bites harder here: _AUTH_STATUS_RX_OAI matches neither "not authorized" nor "forbidden",
    # so a proxy/DLP 403 block page (the shape _summarise_status_error exists to collapse) would
    # otherwise be read as transient off its own "Service Unavailable" text.
    if error.status_code in (401, 403):
        return False
    # `.message` already IS the body: _make_status_error_from_response builds it as
    # "Error code: {status} - {body}". So this reads the body without the second, guarded
    # `response.text` access that can raise — not instead of it. The prose patterns are
    # therefore matched against gateway text, which is the point, and RATE_LIMIT_TRANSIENT_RX
    # deliberately carries no bare `\b429\b` for exactly that reason: it would promote any
    # terminal error whose body mentions `req-429-...` or "429 tokens".
    body = str(getattr(error, "message", "") or error)
    return bool(RATE_LIMIT_TRANSIENT_RX.search(body)
                or SERVER_ERROR_TRANSIENT_RX.search(body))


def prompt(
    user_prompt: str | list[dict],
    *,
    model: str,
    cache_prefix: str | None = None,
    system_prompt: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
    thinking_budget: int | None = None,   # ignored — OpenAI has no equivalent knob here
    betas: list[str] | None = None,        # ignored
    json_schema: dict | None = None,
    output_format: str = "text",
    cwd: str | None = None,
    max_budget_usd: float | None = None,
    timeout: int | None = None,
    tag: str | None = None,
) -> str:
    client = _get_client()
    max_tok = max_tokens or 16000

    messages: list[dict] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    # OpenAI accepts content arrays but not Anthropic's cache_control, so strip it. A
    # caller-marked `cache_prefix` folds back in prefix-first rather than becoming a second block:
    # this route places no explicit breakpoint, so keeping one string leaves a call that omits the
    # parameter byte-identical to today's, with no request-shape change to be 400'd over.
    if isinstance(user_prompt, list):
        user_content: str | list = [
            {k: v for k, v in b.items() if k != "cache_control"}
            for b in user_prompt
            if isinstance(b, dict)
        ]
        if cache_prefix:
            user_content = [{"type": "text", "text": cache_prefix}, *user_content]
    else:
        user_content = (cache_prefix + user_prompt) if cache_prefix else user_prompt
    messages.append({"role": "user", "content": user_content})

    kw: dict = {
        "model": model,
        "messages": messages,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    if _cache_markers_enabled() and model not in _NO_CACHE_KEY_MODELS:
        # The system message renders ahead of the user turn, so it counts toward the provider's
        # cumulative minimum — system + shard prefix can clear the floor when neither would alone.
        kw["prompt_cache_key"] = _prompt_cache_key(
            tag, model, cache_prefix=cache_prefix,
            preceding=system_prompt or "")
    # Newer models (gpt-5+, o-series) only accept max_completion_tokens.
    if model in _USE_LEGACY_MAXTOK:
        kw["max_tokens"] = max_tok
    else:
        kw["max_completion_tokens"] = max_tok
    if temperature is not None and model not in _NO_TEMP_MODELS:
        kw["temperature"] = temperature
    if json_schema or output_format == "json":
        # Force JSON-object mode so GPT can't return prose/arrays; s4 uses output_format="json".
        kw["response_format"] = {"type": "json_object"}

    _up_chars = (
        sum(len(b.get("text", "")) for b in user_prompt if isinstance(b, dict))
        if isinstance(user_prompt, list) else len(user_prompt)
    )
    print(f"    [openai] prompt -> {model}{f' [{tag}]' if tag else ''} "
          f"({_up_chars} chars, max_tokens={max_tok}"
          f"{f', T={temperature}' if 'temperature' in kw else ''}"
          f"{', json' if 'response_format' in kw else ''})",
          file=sys.stderr)

    # Honor a per-step wall-clock timeout if supplied (parity with CLI/SDK), via with_options().
    req_client = client.with_options(timeout=float(timeout)) if timeout else client

    attempts, retry_wait = 3, 60
    text = None  # guard: three param-drops across attempts left text/usage unbound (NameError).
    usage = None
    auth_attempt = 0
    # VVAH-E005 state: one doubled-budget retry per call, then fail loud.
    trunc_retried = False
    trunc_retry_at = 0
    # `attempts` is read live, so a param-drop on the final try can grant one bounded extra send.
    attempt = 0
    while attempt < attempts:
        attempt += 1
        try:
            stream = req_client.chat.completions.create(**kw)
            parts: list[str] = []
            usage = None
            finish: str | None = None
            for ev in stream:
                if ev.choices:
                    choice = ev.choices[0]
                    delta = choice.delta
                    if delta and delta.content:
                        parts.append(delta.content)
                    # Terminal chunk carries it; keep the last non-None value.
                    finish = getattr(choice, "finish_reason", None) or finish
                if getattr(ev, "usage", None):
                    usage = ev.usage
            if finish == OPENAI_FINISH_LENGTH:
                # Budget exhausted (reasoning can consume all of it): one doubled retry, then E005.
                budget_key = (_MAX_TOKENS_KEY if _MAX_TOKENS_KEY in kw
                              else _MAX_COMPLETION_TOKENS_KEY)
                requested_now = kw[budget_key]
                retry_at = (None if trunc_retried
                            else truncation_retry_max(requested_now))
                if retry_at is not None:
                    # A final-attempt truncation still gets its retry, capped like param-drops.
                    if attempt == attempts and attempts < _ATTEMPTS_CEILING:
                        attempts += 1
                    if attempt < attempts:
                        trunc_retried, trunc_retry_at = True, retry_at
                        print(f"    [openai] truncated reply (finish_reason="
                              f"{OPENAI_FINISH_LENGTH}, {budget_key}="
                              f"{requested_now}); retrying once at {retry_at}",
                              file=sys.stderr)
                        _errlog.log(
                            tag or "openai", tag or "truncation",
                            f"VVAH-E005 warning: reply truncated at "
                            f"{budget_key}={requested_now}; retrying once at "
                            f"{retry_at}",
                            error_code=TruncatedResponseError.error_code,
                            recovered=True)
                        kw[budget_key] = retry_at
                        continue
                COUNTERS.bump(TRUNCATED_REPLIES_COUNTER)
                raise TruncatedResponseError(
                    "reply still hit the output-token budget after the "
                    "doubled retry" if trunc_retried else
                    "reply hit the output-token budget with no retry budget "
                    "left",
                    stage=tag or "",
                    requested=max_tok,
                    retried=trunc_retry_at,
                )
            text = "".join(parts)
            break
        except openai.BadRequestError as e:
            body = str(e).lower()
            if trunc_retried and (_MAX_TOKENS_KEY in body
                                  or _MAX_COMPLETION_TOKENS_KEY in body):
                # This 400 IS the provider's cap: the first send already accepted the param name.
                COUNTERS.bump(TRUNCATED_REPLIES_COUNTER)
                raise TruncatedResponseError(
                    f"provider rejected the doubled output budget as over "
                    f"its cap: {redact(str(e))[:200]}",
                    stage=tag or "",
                    requested=max_tok,
                    retried=trunc_retry_at,
                ) from e
            # Each param-drop branch must guarantee a subsequent send, or text/usage ends unbound.
            dropped = False
            if "temperature" in body and "temperature" in kw:
                _NO_TEMP_MODELS.add(model)
                print(f"    [openai] {model} rejected `temperature` — "
                      f"retrying without it", file=sys.stderr)
                kw.pop("temperature", None)
                dropped = True
            elif "max_completion_tokens" in kw and "max_completion_tokens" in body:
                _USE_LEGACY_MAXTOK.add(model)
                kw["max_tokens"] = kw.pop("max_completion_tokens")
                print(f"    [openai] {model} rejected `max_completion_tokens` — "
                      f"retrying with legacy `max_tokens`", file=sys.stderr)
                dropped = True
            elif "max_tokens" in kw and "max_completion_tokens" in body:
                kw["max_completion_tokens"] = kw.pop("max_tokens")
                print(f"    [openai] {model} requires `max_completion_tokens` — "
                      f"retrying", file=sys.stderr)
                dropped = True
            elif "prompt_cache_key" in body and "prompt_cache_key" in kw:
                # Sent to every OpenAI-compatible endpoint, and a strict gateway may reject an
                # unrecognised parameter outright — fatal on every call of every scan, for a
                # field that is only ever an optimisation. Remembered per model.
                _NO_CACHE_KEY_MODELS.add(model)
                kw.pop("prompt_cache_key", None)
                print(f"    [openai] {model} rejected `prompt_cache_key` — "
                      f"retrying without it", file=sys.stderr)
                dropped = True
            if dropped:
                # Grant one more send, capped so a server that keeps 400-ing can't loop unbounded.
                if attempt == attempts and attempts < _ATTEMPTS_CEILING:
                    attempts += 1
                continue
            raise RuntimeError(
                f"OpenAI call failed (status={e.status_code}, model={model}): {e}\n"
                f"  {_payload_shape(messages, str(e))}"
            ) from e
        except openai.APIStatusError as e:
            # VVAH-E001: auth is synchronous, so a few fast retries then halt (not the 60s loop).
            # A RETRYABLE status beats prose, as in sdk.prompt: a 503/429 payload that
            # happens to mention authentication is an outage, and the transient ladder
            # is what rides one out.
            if e.status_code == 401 or (_AUTH_STATUS_RX_OAI.search(str(e))
                                        and e.status_code not in RETRYABLE_STATUS):
                # `attempt < attempts` as well as the auth budget — see sdk.prompt for
                # the full note. Both were 3, so every send went to a `continue` and the
                # raise below could not be reached: a wrong key exhausted the loop and
                # surfaced as the post-loop parameter-drop RuntimeError, with no
                # AuthenticationError and no VVAH-E001 error_code.
                if auth_attempt < _AUTH_MAX_RETRIES_OAI and attempt < attempts:
                    wait = _AUTH_BACKOFF_OAI[min(auth_attempt,
                                                 len(_AUTH_BACKOFF_OAI) - 1)]
                    print(f"    [openai] authentication error "
                          f"(status={e.status_code}, attempt "
                          f"{auth_attempt + 1}/{_AUTH_MAX_RETRIES_OAI}); "
                          f"retrying in {wait}s", file=sys.stderr)
                    time.sleep(wait)
                    auth_attempt += 1
                    continue
                # redact() BEFORE [:400]: truncating first can cut a JWT segment / PEM end
                # marker so the pattern no longer matches and raw credential text survives.
                raise AuthenticationError(redact(str(e))[:400],
                                          status_code=e.status_code,
                                          backend="openai") from e
            if _is_transient_oai(e) and attempt < attempts:
                print(f"    [openai] transient {e.status_code} (attempt "
                      f"{attempt}/{attempts}, model={model}); retrying in "
                      f"{retry_wait}s", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            raise RuntimeError(
                f"OpenAI call failed (status={e.status_code}, model={model}): "
                f"{_summarise_status_error(e)}"
            ) from e
        except openai.APIConnectionError as e:
            detail = _cause_chain(e)
            # VVAH-E002: proxy/TLS misconfiguration cannot heal, so don't burn the retry budget.
            if (_PROXY_CAUSE_RX_OAI.search(detail)
                    or _PROXY_CAUSE_RX_OAI.search(str(e))):
                # redact() BEFORE [:400]: truncating first can cut a JWT segment / PEM end
                # marker so the pattern no longer matches and raw credential text survives.
                raise ProxyError(
                    redact(detail or str(e))[:400],
                    status_code=407 if re.search(r"\b407\b", detail) else None,
                    backend="openai",
                ) from e
            if attempt < attempts:
                print(f"    [openai] connection error (attempt {attempt}/{attempts}): "
                      f"{detail} — retrying in {retry_wait}s", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            raise RuntimeError(
                f"OpenAI connection error after {attempts} attempts "
                f"(model={model}): {e}\n"
                f"  cause: {detail}\n"
                f"  hint: CERTIFICATE_VERIFY_FAILED → set openai.ca_cert in "
                f"config.yaml; 'Illegal header value' → OPENAI_API_KEY has "
                f"trailing whitespace; otherwise check HTTPS_PROXY / "
                f"OPENAI_BASE_URL."
            ) from e
        except _MIDSTREAM_TRANSPORT_ERRORS as e:
            # Transport died AFTER streaming began (e.g. RemoteProtocolError:
            # "peer closed connection without sending complete message body").
            # These surface raw — never as APIConnectionError — and no library
            # retry covers stream iteration (see _MIDSTREAM_TRANSPORT_ERRORS),
            # so without this clause the truncation escapes every handler above
            # and the whole call's analysis is lost. Retry rather than absorb:
            # this loop re-issues the complete call including the stream drain,
            # the partial text is discarded (it would parse as a truncated
            # body), and the attempt cap bounds the re-spend on a persistently
            # broken upstream. Exhaustion raises, so the caller records the
            # failure instead of a degraded call reporting success.
            if attempt < attempts:
                print(f"    [openai] mid-stream transport error (attempt "
                      f"{attempt}/{attempts}, model={model}): "
                      f"{type(e).__name__}: {e} — retrying whole call in "
                      f"{retry_wait}s", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            raise RuntimeError(
                f"OpenAI stream truncated mid-response after {attempts} "
                f"attempts (model={model}): {type(e).__name__}: {e}\n"
                f"  cause: {_cause_chain(e)}"
            ) from e

    if text is None:
        # All attempts ended in a param-drop `continue`; fail loudly instead of an opaque NameError.
        raise RuntimeError(
            f"OpenAI call to {model} exhausted all retries without a "
            f"successful response (every attempt hit a parameter-drop retry). "
            f"Final request kwargs keys: {sorted(kw)}."
        )

    if usage is not None:
        u = usage.model_dump() if hasattr(usage, "model_dump") else dict(usage)
        # Raw dict, pre-normalisation: the normalised dict fabricates the parsed names, so key
        # presence there proves nothing.
        _note_unparsed_cache_keys(u)
        norm = _normalise_usage(u)
        TOKENS.add(norm)
        written = norm.get("cache_creation_input_tokens")
        print(f"    [openai] usage: in={u.get('prompt_tokens', 0)} "
              f"(cached={norm['cache_read_input_tokens']}"
              f"{f', cache_write={written}' if written is not None else ''}) "
              f"out={u.get('completion_tokens', 0)}",
              file=sys.stderr)
    else:
        TOKENS.add(None)

    # OpenAI spells it completion_tokens; normalise to the shared gate helper
    # so absent-vs-zero behaves identically to the other three routes.
    out_tokens = output_tokens_for_gate(
        None if usage is None else {"output_tokens": u.get("completion_tokens")})
    check_response_quality(text.strip(), stage=tag or "",
                           output_tokens=out_tokens)
    return text.strip()


# agentic(): function-calling loop over local Read/Glob/Grep (cwd-jailed); Bash is unsupported.

_MAX_TURNS = 25  # default tool-loop cap; override per-role via the step's `max_turns` config.
_AGENTIC_MAX_TOK = AGENTIC_MAX_TOKENS


# The cache-ish usage keys this module parses, in the RAW Chat Completions shape. Sub-dict keys
# are namespaced by _note_unparsed_cache_keys, so the set spells them the same way.
_PARSED_USAGE_CACHE_KEYS = frozenset({
    "prompt_tokens_details.cached_tokens",
    "prompt_tokens_details.cache_write_tokens",
})


def _note_unparsed_cache_keys(u: dict | None) -> None:
    """Flag cache accounting reported under key names this module does not parse.

    MUST run on the RAW usage dict BEFORE _normalise_usage(), which fabricates the parsed
    Anthropic names. The `prompt_tokens_details` sub-dict is flattened under a namespaced prefix
    first, since that is where OpenAI-shaped providers put cache accounting.
    """
    if not isinstance(u, dict):
        return
    flat = dict(u)
    ptd = flat.pop("prompt_tokens_details", None)
    if isinstance(ptd, dict):
        for k, v in ptd.items():
            if isinstance(k, str):
                flat[f"prompt_tokens_details.{k}"] = v
    _cache.report_unparsed_cache_keys(flat, _PARSED_USAGE_CACHE_KEYS,
                                      via="openai", label="openai")


def _normalise_usage(u: dict) -> TokenUsage:
    """Normalise a Chat Completions usage payload to the Anthropic names util/tokens.py aggregates.

    `prompt_tokens` counts every input token; `prompt_tokens_details` reports the cache-read
    subset (`cached_tokens`, present even at zero) and — only on models new enough to bill cache
    writes — `cache_write_tokens`. Both are carved OUT of `input_tokens` so fresh + read + write
    adds back up to `prompt_tokens`, letting pricing rate each slice at its own multiplier.

    An ABSENT `cache_write_tokens` means the model bills no cache write, so there is no quantity
    to report — an all-zero write column on gpt-5.x / gpt-4o is correct data, not a reporting gap,
    and `cached_tokens` is the complete picture there. The field is therefore omitted rather than
    zero-filled, so a model that does bill writes is costed from real data. The read discount is
    model-dependent (~0.10x-0.50x of input) and belongs to util/pricing.py, not here.
    """
    ptd = u.get("prompt_tokens_details") or {}
    if not isinstance(ptd, dict):
        ptd = {}
    cached = ptd.get("cached_tokens", 0) or 0
    norm: TokenUsage = {
        "input_tokens": max(0, (u.get("prompt_tokens", 0) or 0) - cached),
        # Deliberately NOT `or 0`: an absent or explicit-null completion count
        # must reach TOKENS.add as None so it lands in the `completion_absent`
        # counter — util/tokens.py does the coercion to 0 itself, after
        # counting it. Coercing here made a gateway's null indistinguishable
        # from a genuine zero and left the counter permanently defeated on
        # this route (the gemini36-oai preflight's `out=None` usage record
        # incremented nothing).
        "output_tokens": u.get("completion_tokens"),
        "cache_read_input_tokens": cached,
    }
    if "cache_write_tokens" in ptd:
        written = ptd.get("cache_write_tokens") or 0
        norm["cache_creation_input_tokens"] = written
        norm["input_tokens"] = max(0, norm["input_tokens"] - written)
    return norm


def _record_usage(usage) -> None:
    if usage is None:
        TOKENS.add(None)
        return
    u = usage.model_dump() if hasattr(usage, "model_dump") else dict(usage)
    _note_unparsed_cache_keys(u)   # raw dict, before normalisation
    TOKENS.add(_normalise_usage(u))


# Per-tool-result cap (~12K tokens) in agentic history, so one large Read can't blow the limit.
_TOOL_RESULT_CAP = 48000
_CTX_OVERFLOW_RX = re.compile(
    r"context.?length|context length|exceed.*(?:token|limit)|too long", re.I)


def _cap_tool_result(result: str) -> str:
    if not result or len(result) <= _TOOL_RESULT_CAP:
        return result
    extra = len(result) - _TOOL_RESULT_CAP
    return (result[:_TOOL_RESULT_CAP]
            + f"\n\n…[truncated {extra} chars to fit context — re-read a "
              f"specific line range with Read offset/limit if you need more]")


def _anthropic_tool_to_openai(t: dict) -> dict:
    """Convert one Anthropic Messages tool schema ({name, description, input_schema})
    to the OpenAI function-tool envelope. Callers supply tools in the Anthropic shape
    (the project's common form, e.g. exploit verification's http_request); this backend
    speaks OpenAI's, so it converts at the boundary rather than pushing the difference
    onto every caller."""
    return {"type": "function",
            "function": {"name": t["name"],
                         "description": t.get("description", ""),
                         "parameters": t.get("input_schema") or {"type": "object"}}}


_EVICTED_MARK = "[evicted to fit context]"


def _shrink_history(messages: list[dict]) -> bool:
    """Evict the oldest not-yet-evicted oversized tool result (short stub) to claw back context.
    Returns True if it shrank something, False once fully evicted, so calls advance not repick."""
    for m in messages:
        c = m.get("content")
        if (m.get("role") == "tool" and isinstance(c, str) and len(c) > 1200
                and not c.endswith(_EVICTED_MARK)):
            m["content"] = c[:800] + "\n…" + _EVICTED_MARK
            return True
    return False


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,
    permission_mode: str = "auto",  # accepted for parity; unused
    max_turns: int | None = None,
    tag: str | None = None,
    # Caller-supplied tools (Anthropic-shape schemas), in addition to the localtools
    # named by `allowed_tools`; `extra_dispatch(name, input)` runs one and returns its
    # string result, or None to defer to localtools. Mirrors backends.sdk.agentic, so a
    # caller with its own tool (e.g. exploit verification's http_request) can drive this
    # loop too. A caller tool is the caller's to log and size-cap in its own dispatch;
    # this loop only caps + logs the localtools IT runs. Defaults leave existing callers
    # unchanged.
    extra_tools: list[dict] | None = None,
    extra_dispatch=None,
) -> str:
    client = _get_client()
    turns_cap = int(max_turns) if max_turns else _MAX_TURNS
    # `None` = unspecified (read-only default); `[]` = the caller wants no localtools. See
    # the same note in backends.llm.sdk.agentic — folding them together makes "none"
    # inexpressible and duplicates the tools of a caller that supplies its own.
    allowed = list(DEFAULT_READ_TOOLS) if allowed_tools is None else list(allowed_tools)
    ok_tools, missing = _localtools.supported(allowed)
    if missing:
        raise NotImplementedError(
            f"via:openai agentic() does not implement tools {missing}. "
            f"Supported: {sorted(ok_tools)}. Keep this role on `via: cli` "
            f"or drop the unsupported tool from allowed_tools."
        )
    tools = [*_localtools.schemas_for(ok_tools),
             *(_anthropic_tool_to_openai(t) for t in (extra_tools or []))]
    advertised = ok_tools + [t.get("name") for t in (extra_tools or [])]

    messages: list[dict] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_prompt})

    print(f"    [openai] agentic -> {model}{f' [{tag}]' if tag else ''} "
          f"(tools={advertised}, cwd={cwd})", file=sys.stderr)

    base_kw: dict = {"model": model, "tools": tools}
    if model in _USE_LEGACY_MAXTOK:
        base_kw["max_tokens"] = _AGENTIC_MAX_TOK
    else:
        base_kw["max_completion_tokens"] = _AGENTIC_MAX_TOK
    # Built ONCE from the stable lead (system + first user turn) and reused unchanged every turn:
    # keying on the growing tail would churn the key each turn, worse than sending none. Only the
    # shared lead caches across turns and calls anyway.
    if _cache_markers_enabled() and model not in _NO_CACHE_KEY_MODELS:
        base_kw["prompt_cache_key"] = _prompt_cache_key(
            tag, model, cache_prefix=user_prompt, preceding=system_prompt or "")

    final_text = ""
    tool_calls_total = 0
    for turn in range(1, turns_cap + 1):
        resp = None
        shrinks = 0
        transients = 0
        while resp is None:
            try:
                resp = client.chat.completions.create(messages=messages, **base_kw)
            except openai.BadRequestError as e:
                low = str(e).lower()
                if "max_completion_tokens" in base_kw and "max_completion_tokens" in low:
                    _USE_LEGACY_MAXTOK.add(model)
                    base_kw["max_tokens"] = base_kw.pop("max_completion_tokens")
                    continue
                # Mirrors prompt()'s branch: never fail the loop over an optimisation-only field.
                if "prompt_cache_key" in base_kw and "prompt_cache_key" in low:
                    _NO_CACHE_KEY_MODELS.add(model)
                    base_kw.pop("prompt_cache_key", None)
                    print(f"    [openai] {model} rejected `prompt_cache_key` — "
                          f"retrying without it", file=sys.stderr)
                    continue
                # Context-window overflow: evict the oldest oversized tool result and retry.
                if (_CTX_OVERFLOW_RX.search(low) and shrinks < 16
                        and _shrink_history(messages)):
                    shrinks += 1
                    print(f"      [openai] context overflow (turn {turn}); "
                          f"evicted oldest tool output [{shrinks}], retrying",
                          file=sys.stderr)
                    continue
                raise RuntimeError(
                    f"OpenAI agentic call failed (model={model}, turn={turn}): {e}"
                ) from e
            except openai.APIStatusError as e:
                if _is_transient_oai(e) and transients < 4:
                    transients += 1
                    wait = min(60, 10 * transients)
                    print(f"      [openai] transient {e.status_code} (turn "
                          f"{turn}, retry {transients}/4); waiting {wait}s",
                          file=sys.stderr)
                    time.sleep(wait)
                    continue
                raise RuntimeError(
                    f"OpenAI agentic call failed (status={e.status_code}, "
                    f"model={model}, turn={turn}): {_summarise_status_error(e)}"
                ) from e
            except openai.APIConnectionError as e:
                if transients < 4:
                    transients += 1
                    wait = min(60, 10 * transients)
                    print(f"      [openai] agentic connection error (turn {turn}, "
                          f"retry {transients}/4); waiting {wait}s", file=sys.stderr)
                    time.sleep(wait)
                    continue
                raise RuntimeError(
                    f"OpenAI agentic connection error (model={model}, turn={turn}): "
                    f"{e}\n  cause: {_cause_chain(e)}"
                ) from e

        _record_usage(getattr(resp, "usage", None))
        msg = resp.choices[0].message
        calls = getattr(msg, "tool_calls", None) or []

        messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [tc.model_dump() for tc in calls] if calls else None,
        })

        if not calls:
            final_text = (msg.content or "").strip()
            print(f"    [openai] agentic done in {turn} turn(s), "
                  f"{tool_calls_total} tool call(s)", file=sys.stderr)
            return final_text

        for tc in calls:
            tool_calls_total += 1
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            # A caller-supplied tool goes to extra_dispatch (the caller logs + caps it); a
            # localtools name returns None and is executed, capped, and logged here —
            # logging/capping follow whichever layer actually ran the tool.
            result = extra_dispatch(name, args) if extra_dispatch is not None else None
            if result is None:
                result = _cap_tool_result(_localtools.execute(name, args, cwd=cwd))
                if not is_stage_only():
                    print(f"      [openai] tool {name}({_localtools.summarize_args(args)}) -> "
                          f"{len(result)} chars", file=sys.stderr)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })

    print(f"    [openai] WARN: agentic hit max_turns={turns_cap} without a "
          f"final answer (model={model})", file=sys.stderr)
    messages.append({
        "role": "user",
        "content": "Tool budget exhausted. Reply now with your final answer "
                   "based on what you have read so far; do not call tools.",
    })
    final_transients = 0
    while True:
        try:
            resp = client.chat.completions.create(
                messages=messages, model=model,
                **{k: v for k, v in base_kw.items()
                   if k != "tools" and k != "model"})
            break
        except openai.APIStatusError as e:
            if _is_transient_oai(e) and final_transients < 4:
                final_transients += 1
                wait = min(60, 10 * final_transients)
                print(f"      [openai] forced-final transient {e.status_code} "
                      f"(retry {final_transients}/4); waiting {wait}s",
                      file=sys.stderr)
                time.sleep(wait)
                continue
            raise RuntimeError(
                f"OpenAI agentic forced-final failed (status={e.status_code}, "
                f"model={model}): {_summarise_status_error(e)}"
            ) from e
        except openai.APIConnectionError as e:
            if final_transients < 4:
                final_transients += 1
                wait = min(60, 10 * final_transients)
                print(f"      [openai] forced-final connection error "
                      f"(retry {final_transients}/4); waiting {wait}s",
                      file=sys.stderr)
                time.sleep(wait)
                continue
            raise RuntimeError(
                f"OpenAI agentic forced-final connection error (model={model}): "
                f"{e}\n  cause: {_cause_chain(e)}"
            ) from e
    _record_usage(getattr(resp, "usage", None))
    return (resp.choices[0].message.content or "").strip()

