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

"""DeepAgents route for the legacy stage call sites.

Deliberately NOT registered in ``registry._BACKENDS``: stages branch on the
resolved ``via`` explicitly (the S10 pattern in
``remediation_agent.plugin_runner._invoke``), so the registry never dispatches
here.

Three layers:
  * harness-shaped primitives (``build_harness_env`` / ``map_allowed_tools`` /
    ``drain_streaming`` / ``run_oneshot`` / ``terminal_text``) — the landing
    spot S10/S11 can migrate onto later;
  * legacy-shaped wrappers (``agentic`` / ``prompt``) mirroring the registry
    backends' signatures AND their result-quality/error taxonomy: degenerate
    output goes through ``check_response_quality`` (VVAH-E003), and provider
    auth / proxy-TLS failures re-raise as ``AuthenticationError`` (VVAH-E001)
    / ``ProxyError`` (VVAH-E002), exactly like ``via: sdk``. These stay
    legacy-shaped permanently; a caller with richer needs uses the primitives
    or stays bespoke;
  * the dispatch seam (``dispatch_prompt`` / ``dispatch_agentic``) — the ONE
    place that branches on the resolved ``via`` and knows how to build this
    route's options from a profile node. A stage migrates onto the DeepAgents
    route by swapping its ``registry.prompt``/``registry.agentic`` call for the
    matching dispatcher; it never rewrites the branch or the option plumbing.

Two invariants every caller inherits and a new stage must respect:

1. Every stage passes the HOST repo root as ``cwd``, while the harness roots
   its virtual filesystem there — so an agent can emit a virtual absolute
   path like ``/src/app.py`` for a file that really lives at
   ``<repo>/src/app.py``. Only S1 normalises that today
   (``s1_preprocess._norm_rel``); a new agentic stage consuming agent-emitted
   paths must normalise them the same way.
2. ``TOKENS`` phase bucketing is correct ONLY because callers block:
   ``_run_sync`` submits to the module's persistent loop thread and waits for
   the result, so the caller's ``TOKENS.phase(...)`` window is still open when
   the translate layer records usage. The hazard is overlapping
   ``TOKENS.phase()`` windows — concurrent calls INSIDE one stage phase are
   fine (S4's pool), concurrent calls across DIFFERENT phases would
   cross-contaminate buckets.

Top-level imports are langchain-free; the harness pulls its SDK in lazily.
"""

from __future__ import annotations

import asyncio
import atexit
import os
import re
import sys
import threading
from collections.abc import Callable, Coroutine, Sequence
from pathlib import Path
from typing import TypeVar

from vvaharness.backends.harness import (
    READ_TOOLS,
    HarnessProcessError,
    HarnessResult,
    OneShotOptions,
    OneShotResult,
    StreamingOptions,
    ToolPolicy,
    get_harness,
)
from vvaharness.backends.harness.models import (
    DEFAULT_GRAPH_NAME,
    LOGICAL_TO_NATIVE,
    AuthenticationError,
    OversizePromptError,
    ProxyError,
)
from vvaharness.backends.harness.provider_routing import (
    credential_env_overrides,
    routes_to_anthropic,
)
from vvaharness.backends.llm import registry
from vvaharness.backends.llm.cache import markers_enabled
from vvaharness.backends.llm.models import (
    AGENTIC_MAX_TOKENS,
    DEEPAGENTS_MAX_PROMPT_TOKENS,
)
from vvaharness.backends.llm.registry import _flatten_blocks, resolve

# The single home of the auth/proxy failure signatures is the sdk backend;
# importing them (rather than copying) keeps one definition for both routes.
from vvaharness.backends.llm.sdk import _AUTH_STATUS_RX, _PROXY_CAUSE_RX, _cause_chain
from vvaharness.report.redact import redact
from vvaharness.util.counters import COUNTERS
from vvaharness.util.response_quality import (
    check_response_quality,
    output_tokens_for_gate,
)
from vvaharness.util.scan_progress import get_active_tracker
from vvaharness.util.tokens import TOKENS, TokenUsage, estimate_tokens
from vvaharness.util.warn_once import warn_once

__all__ = [
    "agentic",
    "build_harness_env",
    "dispatch_agentic",
    "dispatch_prompt",
    "drain_streaming",
    "map_allowed_tools",
    "prompt",
    "run_oneshot",
    "terminal_text",
]

_T = TypeVar("_T")

#: Granted when a caller passes no tool list, matching the harness read set.
_DEFAULT_TOOLS: tuple[str, ...] = ("Read", "Glob", "Grep")

#: Legacy kwargs the harness route accepts-and-ignores WITHOUT a warning.
#: Each has codebase precedent for being silently unhonoured on some route:
#: ``temperature``/``thinking_budget``/``betas`` are silently dropped for the
#: cli backend (``registry._fold_for_cli``); ``stream_cb`` is silently popped
#: for sdk/openai (``registry.agentic``); ``timeout``/``output_format``/
#: ``json_schema``/``max_budget_usd``/``permission_mode`` are accepted-for-
#: parity-and-unused by the sdk/openai backends. None of them changes WHAT is
#: asked of the model on this route.
_ACCEPTED_UNUSED_KW: frozenset[str] = frozenset({
    "betas",
    "json_schema",
    "max_budget_usd",
    "output_format",
    "permission_mode",
    "stream_cb",
    "temperature",
    "thinking_budget",
    "timeout",
})

#: Kwarg names already warned about, so each fires at most once per process.
_WARNED_LEGACY_KW: set[str] = set()


#: Guards lazy start of the persistent harness loop below.
_LOOP_LOCK = threading.Lock()
_loop: asyncio.AbstractEventLoop | None = None
_loop_thread: threading.Thread | None = None


def _shutdown_loop() -> None:
    """Stop the harness loop at interpreter exit and join its thread.

    Without this, abandoned async generators and cached clients spray "Task
    was destroyed" noise when the daemon thread dies at shutdown.
    """
    with _LOOP_LOCK:
        loop, thread = _loop, _loop_thread
    if loop is None or thread is None:
        return
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=5.0)


def _harness_loop() -> asyncio.AbstractEventLoop:
    """Return the module's persistent event loop, starting its daemon thread on first use.

    One loop owns all detection-side harness I/O for the life of the process:
    ``build_model_cached`` hands every call the same async httpx client, and an
    async client is only sound when a single loop drives it — per-call
    throwaway loops (the previous design) reused pooled connections across
    loops, made frequent and concurrent by S4's thread pool.
    """
    global _loop, _loop_thread
    with _LOOP_LOCK:
        if _loop is not None:
            return _loop
        loop = asyncio.new_event_loop()
        thread = threading.Thread(
            target=loop.run_forever, name="vvaharness-llm-deepagents", daemon=True
        )
        thread.start()
        atexit.register(_shutdown_loop)
        _loop, _loop_thread = loop, thread
        return loop


def _run_sync(awaitable: Coroutine[None, None, _T]) -> _T:
    """Run a coroutine on the persistent harness loop, blocking until it completes.

    Callers may hold their own running loop (the call then blocks that loop,
    as the previous thread-join design did) but never the harness loop itself —
    that would deadlock forever, so it raises instead. The S10/S11
    ``plugin_runner._run_sync`` remains a separate per-call ``asyncio.run``
    bridge (frozen; hoisting it here is the S10/S11 primitives follow-up).

    ``TOKENS`` phase bucketing relies on this blocking: the caller's
    ``TOKENS.phase(...)`` window is still open when the harness translate
    layer records usage from the loop thread (module docstring, invariant 2).
    """
    loop = _harness_loop()
    if threading.current_thread() is _loop_thread:
        awaitable.close()
        raise RuntimeError(
            "_run_sync called from the harness loop thread — this would deadlock"
        )
    future = asyncio.run_coroutine_threadsafe(awaitable, loop)
    try:
        return future.result()
    except BaseException:
        # On Ctrl-C the harness call must stop billing, not run on in the
        # background (prior art: s4_deepdive's shard-gate abort handling).
        future.cancel()
        raise


_provider_of = registry.provider_of
_use_responses_api_of = registry.use_responses_api_of


# ── failure classification (VVAH-E001 / VVAH-E002) ───────────────────────────

_HTTP_UNAUTHORIZED: int = 401
_HTTP_PROXY_AUTH: int = 407
_PROXY_407_RX = re.compile(r"\b407\b")

#: Stage tags already warned for missing token usage, so each fires once per process.
_NO_USAGE_WARNED_TAGS: set[str] = set()

#: Counter for VVAH-E004 pre-dispatch refusals; read into ScanMetrics by the
#: metrics builder and rendered as a Pipeline Diagnostics row.
_OVERSIZE_PROMPT_COUNTER = "deepagents_oversize_prompts"


def _check_prompt_ceiling(text: str, *, tag: str | None) -> None:
    """Refuse a prompt whose estimate exceeds the route ceiling, before dispatch.

    The single oversize policy for BOTH deepagents dispatch seams
    (:func:`prompt` / :func:`agentic`): raise VVAH-E004 where the flattened
    prompt (cache prefix included) is in hand, so the owning unit fails loudly
    at stage level — no auto-split, no silent mutation, and no spend on a call
    the provider would refuse. sdk/openai routes are unchanged.
    """
    estimated = estimate_tokens(text)
    if estimated <= DEEPAGENTS_MAX_PROMPT_TOKENS:
        return
    COUNTERS.bump(_OVERSIZE_PROMPT_COUNTER)
    raise OversizePromptError(
        "refused before dispatch; reduce what this call packs "
        "(chunk sizing / per-call caps) and re-run",
        stage=tag or "",
        estimated_tokens=estimated,
        limit=DEEPAGENTS_MAX_PROMPT_TOKENS,
    )


def _exception_chain(exc: BaseException) -> list[BaseException]:
    """Return *exc* plus every ``__cause__`` below it, outermost first.

    The object-level counterpart of the sdk backend's ``_cause_chain`` string
    walk: streaming failures arrive wrapped (``client.py`` raises
    ``HarnessProcessError(...) from error``), so the provider exception is a
    cause, not the exception the caller catches.
    """
    links: list[BaseException] = [exc]
    while links[-1].__cause__ is not None:
        links.append(links[-1].__cause__)
    return links


def _auth_failure(exc: BaseException) -> tuple[int, str] | None:
    """Return ``(status, body)`` when the chain carries a provider auth failure.

    Provider ``APIStatusError`` subclasses (anthropic and openai alike) carry
    ``.status_code``; ``APIConnectionError`` does not, so a connection failure
    can never be misread as one. Matching mirrors ``sdk.prompt``: HTTP 401, or
    the shared ``_AUTH_STATUS_RX`` signature in the error body.
    """
    for err in _exception_chain(exc):
        status = getattr(err, "status_code", None)
        if not isinstance(status, int):
            continue
        body = str(getattr(err, "message", err))
        if status == _HTTP_UNAUTHORIZED or _AUTH_STATUS_RX.search(body):
            return status, body
    return None


def _proxy_failure(exc: BaseException) -> str | None:
    """Return the cause detail when the chain carries a proxy/TLS connection failure.

    Mirrors ``sdk.prompt``'s ``APIConnectionError`` handling: the root cause is
    flattened with the shared ``_cause_chain`` and matched against the shared
    ``_PROXY_CAUSE_RX``. ponytail: connection errors are recognised by class
    NAME so one check covers both provider families (anthropic and openai each
    raise their own ``APIConnectionError``) without importing either SDK here.
    """
    for err in _exception_chain(exc):
        if type(err).__name__ != "APIConnectionError":
            continue
        detail = _cause_chain(err)
        if _PROXY_CAUSE_RX.search(detail) or _PROXY_CAUSE_RX.search(str(err)):
            return detail or str(err)
    return None


def _classify_failure(
    exc: BaseException, *, model_id: str, tag: str | None
) -> AuthenticationError | ProxyError | None:
    """Map a provider failure onto the VVAH taxonomy, or None when unrecognised.

    Only failures positively matched as auth (VVAH-E001) or proxy/TLS
    (VVAH-E002) are relabelled; anything else returns None so the caller
    re-raises the original — a genuine programming error must stay
    recognisable as one. Every message is redacted BEFORE truncation
    (``redact(body)[:400]``, never ``redact(body[:400])``): truncating first
    can bisect a JWT or PEM so the redaction pattern no longer matches and raw
    credential material survives.
    """
    context = f"model={model_id}" + (f", stage={tag}" if tag else "")
    auth = _auth_failure(exc)
    if auth is not None:
        status, body = auth
        return AuthenticationError(
            f"{redact(body)[:400]} ({context})",
            status_code=status,
            backend="deepagents",
        )
    detail = _proxy_failure(exc)
    if detail is not None:
        return ProxyError(
            f"{redact(detail)[:400]} ({context})",
            status_code=_HTTP_PROXY_AUTH if _PROXY_407_RX.search(detail) else None,
            backend="deepagents",
        )
    return None


def _call_classified(call: Callable[[], _T], *, model_id: str, tag: str | None) -> _T:
    """Run a harness call, re-raising provider failures under the VVAH taxonomy.

    An auth failure surfaces as :class:`AuthenticationError` (VVAH-E001) and a
    proxy/TLS failure as :class:`ProxyError` (VVAH-E002), carrying the same
    actionable remediation block ``via: sdk`` produces. Anything unclassified
    (including ``drain_streaming``'s bare ``RuntimeError`` on an error
    terminal) passes through unchanged.
    """
    try:
        result = call()
    except Exception as exc:
        mapped = _classify_failure(exc, model_id=model_id, tag=tag)
        if mapped is None:
            raise
        raise mapped from exc
    return result


def _warn_no_usage(usage: object, *, model_id: str, tag: str | None) -> None:
    """WARN once per stage when a call finishes with no token usage recorded.

    Keyed on the tag's stage prefix (the first whitespace-delimited token:
    ``"s4"`` from ``"s4 chunk-07"``) so a no-usage gateway warns once per
    stage, not once per chunk; the message keeps the first offender's full
    tag.

    ``usage is None`` on the harness result is this route's no-usage signal:
    the translate layer (``translate_final_state`` / ``make_terminal_result``)
    leaves ``usage`` as None — and skips ``TOKENS.add`` entirely — when no
    message carried ``usage_metadata``. That happens systematically on
    third-party gateways: langchain-openai disables ``stream_usage`` whenever
    ``base_url`` is set. Because the skip bypasses ``TOKENS.add`` altogether,
    NEITHER ``totals.calls`` nor ``totals.calls_with_usage`` increments, so a
    zero-usage call on this route is invisible in those counters — this WARN
    is the only signal that usage went unrecorded here. (The
    ``calls_with_usage < calls`` shortfall remains a valid check for
    ``sdk``/``openai``, whose backends call ``TOKENS.add(None)``.)
    """
    if usage is not None:
        return
    tag_text = tag or ""
    stage_key = tag_text.split(maxsplit=1)[0] if tag_text.strip() else ""
    warn_once(
        _NO_USAGE_WARNED_TAGS,
        stage_key,
        f"  [deepagents] WARN: no token usage recorded for stage "
        f"'{tag_text or 'untagged'}' (model={model_id}) — token accounting is "
        f"unavailable for this stage",
    )


def _output_tokens(usage: TokenUsage | None) -> int | None:
    """``output_tokens`` for the quality gate. Delegates so all four routes agree.

    Was ``usage.get("output_tokens") or 0``, which turned "the gateway reported
    usage but not this field" into a hard zero and tripped the token floor on
    every reply.
    """
    return output_tokens_for_gate(usage)


def _usage_of(result: object) -> TokenUsage | None:
    """The result's ``usage`` field, or None when absent.

    ponytail: ``getattr`` rather than an attribute read because callers'
    test doubles fake this seam with plain namespaces; a missing field means
    the same thing as ``usage=None`` — nothing was recorded.
    """
    usage = getattr(result, "usage", None)
    return usage if isinstance(usage, dict) else None


def build_harness_env(
    model_id: str,
    provider: str | None,
    *,
    sdk_cfg: object,
    openai_cfg: object,
    cfg_dir: str | Path | None = None,
) -> dict[str, str]:
    """Process env plus the credential AND TLS overrides the resolved route needs.

    The env definition for the DETECTION deepagents seams only: this module's
    ``prompt()``/``agentic()`` (reached via ``dispatch_prompt``/
    ``dispatch_agentic``) and the preflight probe
    (``preflight._probe_deepagents_harness``) fold these in, so a profile's
    ``ca_cert`` / ``client_cert`` / ``verify_ssl`` behaves identically across
    the S0-S9 deepagents roles. The S10/S11 invoker
    (``plugin_runner._invoke_deepagents``) deliberately does NOT — it builds
    its env from ``credential_env_overrides`` alone (S10/S11 are frozen on
    this branch), and
    ``tests/test_deepagents_tls.py::test_s10_plugin_runner_env_is_credentials_only``
    pins that asymmetry. Consequence: an mTLS/private-CA profile reaches the
    detection roles (and ``via: sdk`` S10) but not ``via: deepagents``
    S10/S11. Relative cert paths resolve against *cfg_dir*
    (the profile's directory, ``cfg._data["_config_dir"]`` as stamped by
    ``config.load``); the default ``None`` keeps absolute paths working and
    existing callers unchanged. With no TLS material configured the result is
    byte-identical to the pre-TLS env (process env + credential overrides).
    """
    from vvaharness.backends.harness.deepagents.options.model_building import (  # noqa: PLC0415 — lazy: model_building imports langchain; `import vvaharness.cli` must stay langchain-free
        tls_carriers_for,
    )

    return {
        **os.environ,
        **credential_env_overrides(
            model_id, provider, sdk_cfg=sdk_cfg, openai_cfg=openai_cfg
        ),
        **tls_carriers_for(
            model_id, provider, sdk_cfg=sdk_cfg, openai_cfg=openai_cfg, cfg_dir=cfg_dir
        ),
    }


def map_allowed_tools(
    allowed_tools: Sequence[str] | None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split a legacy tool list into (granted, stripped) against ``READ_TOOLS``.

    Order-preserving and deduped; ``None`` grants the default read set. A
    stripped name (e.g. ``Bash``) is never an error — the caller warns.
    """
    if allowed_tools is None:
        return _DEFAULT_TOOLS, ()
    names = tuple(dict.fromkeys(allowed_tools))
    granted = tuple(n for n in names if n in READ_TOOLS)
    stripped = tuple(n for n in names if n not in READ_TOOLS)
    return granted, stripped


async def _drain(
    user_prompt: str, options: StreamingOptions
) -> tuple[HarnessResult | None, HarnessProcessError | None]:
    """Drain a streaming session to (terminal, recursion error or None)."""
    terminal: HarnessResult | None = None
    try:
        async for message in get_harness("deepagents").run_streaming(user_prompt, options):
            if isinstance(message, HarnessResult):
                terminal = message
    except HarnessProcessError as exc:
        # The backend yields a terminal snapshot before raising on a
        # GraphRecursionError; returning it is the legacy max-turns
        # force-finalize analog. Anything else propagates.
        if "GraphRecursionError" not in str(exc) or terminal is None:
            raise
        return terminal, exc
    return terminal, None


def drain_streaming(user_prompt: str, options: StreamingOptions) -> HarnessResult:
    """Run a streaming session to completion and return its terminal result."""
    terminal, recursion_error = _run_sync(_drain(user_prompt, options))
    if terminal is None:
        raise RuntimeError("DeepAgents session ended without a terminal result")
    if terminal.is_error and recursion_error is None:
        raise RuntimeError(
            f"DeepAgents session failed: {terminal.subtype or 'unknown error'}"
        )
    return terminal


def run_oneshot(user_prompt: str, options: OneShotOptions) -> OneShotResult:
    """Run a single-turn parser-only invocation synchronously."""
    return _run_sync(get_harness("deepagents").run_oneshot(user_prompt, options))


def terminal_text(result: HarnessResult) -> str:
    """Final assistant text of a terminal; ``structured`` is always None here."""
    return result.result_text or ""


def agentic(
    user_prompt: str,
    *,
    model: object,
    system_prompt: str | None = None,
    allowed_tools: Sequence[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,
    permission_mode: str = "auto",
    max_turns: int | None = None,
    tag: str | None = None,
    graph_name: str = DEFAULT_GRAPH_NAME,
    sdk_cfg: object = None,
    openai_cfg: object = None,
    cfg_dir: str | None = None,
) -> str:
    """Tool-using loop on the DeepAgents harness, legacy ``registry.agentic`` shape.

    ``permission_mode`` is accepted-and-ignored: this route is always
    read-only. ``max_budget_usd`` is forwarded but the harness does not
    enforce a spend budget; ``max_turns`` maps to the recursion limit and
    every model turn is capped at ``AGENTIC_MAX_TOKENS`` output tokens,
    matching the ``via: sdk``/``openai`` agentic ceilings.
    ``cfg_dir`` anchors relative profile cert paths (see ``build_harness_env``).

    ``cwd`` is the HOST repo root, and the harness roots its virtual
    filesystem there — so the agent may emit virtual absolute paths
    (``/src/app.py``) for host files; a caller consuming agent-emitted paths
    must normalise them (module docstring, invariant 1; today only
    ``s1_preprocess._norm_rel`` does).

    Provider failures re-raise as VVAH-E001/E002 and the final text passes
    the VVAH-E003 quality gate, matching the shipped ``via: sdk`` behaviour.
    """
    model_id, _via, _extras = resolve(model)
    provider = _provider_of(model)
    _check_prompt_ceiling(user_prompt, tag=tag)
    granted, stripped = map_allowed_tools(allowed_tools)
    if stripped:
        print(
            f"  [deepagents] WARN: tool(s) not supported on this route, "
            f"stripped: {', '.join(stripped)}",
            file=sys.stderr,
        )
    # response_model/allow_writes defaults keep the read-only redaction stack.
    options = StreamingOptions(
        model=model_id,
        model_provider=provider,
        use_responses_api=_use_responses_api_of(model),
        cwd=Path(cwd),
        env=build_harness_env(
            model_id, provider, sdk_cfg=sdk_cfg, openai_cfg=openai_cfg, cfg_dir=cfg_dir
        ),
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
        system_prompt=system_prompt,
        tool_policy=ToolPolicy(allowed_tools=granted, disallowed_tools=stripped),
        graph_name=graph_name,
        # Executor-seam least-privilege gate (PermitTools at wrap_tool_call):
        # only the natives the granted read logicals resolve to may execute;
        # the graph builder unions in caller-built session tools (none on this
        # path). Derived from the same `granted` the ToolPolicy above carries,
        # so it cannot drift from what is granted. A forged/hallucinated
        # write_file/edit_file/delete/execute call — or any native read the
        # policy never granted — is refused with an error ToolMessage instead
        # of executing. `task` is deliberately NOT permitted: no agentic
        # detection consumer (S1 preprocess, S2 agentic mode) instructs or
        # needs sub-agent dispatch, and everything the gated general-purpose
        # shadow could read the parent reads identically (same redaction).
        # Setting this also aligns ADVERTISEMENT with permission: the
        # streaming builder derives its ExcludeTools set from this same field
        # (options/streaming.py::_extra_excluded_tools), so the model is
        # offered exactly these natives — a refused tool is never on offer.
        permitted_tool_calls=frozenset(
            LOGICAL_TO_NATIVE[t] for t in granted if t in LOGICAL_TO_NATIVE
        ),
        # Per-turn ceiling, parity with the sdk/openai agentic paths (16k);
        # without it this route alone inherits the constructor's 64k.
        max_output_tokens=AGENTIC_MAX_TOKENS,
        cache_markers=markers_on(sdk_cfg),
    )
    terminal = _call_classified(
        lambda: drain_streaming(user_prompt, options), model_id=model_id, tag=tag
    )
    usage = _usage_of(terminal)
    _warn_no_usage(usage, model_id=model_id, tag=tag)
    text = terminal_text(terminal)
    check_response_quality(
        text.strip(), stage=tag or "", output_tokens=_output_tokens(usage)
    )
    return text


def markers_on(sdk_cfg: object) -> bool:
    """Whether the sdk block's `cache_markers` kill switch permits markers here too."""
    value = getattr(sdk_cfg, "cache_markers", None)
    return markers_enabled({} if value is None else {"cache_markers": value})


# Alias kept for the callers that predate the public promotion.
_markers_on = markers_on


def prompt(
    user_prompt: str | list[dict[str, object]],
    *,
    model: object,
    system_prompt: str | None = None,
    max_tokens: int | None = None,
    cwd: str,
    tag: str | None = None,
    graph_name: str = DEFAULT_GRAPH_NAME,
    sdk_cfg: object = None,
    openai_cfg: object = None,
    cfg_dir: str | None = None,
    cache_prefix: str | None = None,
) -> str:
    """Single-turn completion on the DeepAgents harness, legacy ``registry.prompt`` shape.

    ``max_tokens`` is honoured as a per-call output-token cap
    (``OneShotOptions.max_output_tokens``), matching ``via: cli`` and
    ``via: sdk``; ``None`` inherits the harness's own ceiling
    (``MODEL_MAX_OUTPUT_TOKENS``, 64k, on Anthropic; uncapped on
    OpenAI-compatible gateways). Token accounting is not done here —
    the harness translate layer feeds ``TOKENS`` inside the caller's phase,
    which is correct only because ``_run_sync`` blocks the caller while its
    phase window is open (module docstring, invariant 2). ``cwd`` is the HOST
    repo root and doubles as the
    harness's virtual-filesystem root (module docstring, invariant 1).
    ``cfg_dir`` anchors relative profile cert paths (see ``build_harness_env``).

    ``cache_prefix`` is leading user-turn content: on an Anthropic-routed
    request (and unless the sdk block's ``cache_markers`` switch is off) it is
    sent as its own cache_control-marked block; otherwise it folds into the
    turn — content either way, mirroring the sdk backend's policy.

    Provider failures re-raise as VVAH-E001/E002 and the returned text passes
    the VVAH-E003 quality gate, matching the shipped ``via: sdk`` behaviour.
    """
    model_id, _via, _extras = resolve(model)
    provider = _provider_of(model)
    flat = _flatten_blocks(user_prompt)
    prefix = cache_prefix or ""
    if prefix and not (routes_to_anthropic(model_id, provider)
                       and _markers_on(sdk_cfg)):
        # Content is never dropped: an unmarkable prefix folds into the turn.
        flat = prefix + flat
        prefix = ""
    # Ceiling over the FULL user-turn content: a marked prefix is still sent.
    _check_prompt_ceiling(prefix + flat, tag=tag)
    tracker = get_active_tracker()
    if tracker is not None:
        tracker.llm_payload(
            phase=TOKENS.current_phase(),
            backend="deepagents",
            model_id=model_id,
            tag=tag or "",
            user_prompt=prefix + flat,
            system_prompt=system_prompt or "",
        )
    # The explicit empty ToolPolicy excludes the native filesystem tools.
    options = OneShotOptions(
        model=model_id,
        model_provider=provider,
        use_responses_api=_use_responses_api_of(model),
        cwd=Path(cwd),
        env=build_harness_env(
            model_id, provider, sdk_cfg=sdk_cfg, openai_cfg=openai_cfg, cfg_dir=cfg_dir
        ),
        system_prompt=system_prompt,
        tool_policy=ToolPolicy(),
        graph_name=graph_name,
        max_output_tokens=max_tokens,
        cache_prefix=prefix or None,
        cache_markers=markers_on(sdk_cfg),
    )
    result = _call_classified(
        lambda: run_oneshot(flat, options), model_id=model_id, tag=tag
    )
    usage = _usage_of(result)
    _warn_no_usage(usage, model_id=model_id, tag=tag)
    text = result.result_text or ""
    check_response_quality(
        text.strip(), stage=tag or "", output_tokens=_output_tokens(usage)
    )
    return text


# ── the dispatch seam ─────────────────────────────────────────────────────────


def _screen_legacy_kwargs(legacy_kw: dict[str, object]) -> str:
    """Vet legacy-route kwargs for the harness route; return any ``cache_prefix`` text.

    Policy — never silently drop a kwarg that changes the request:
      * ``cache_prefix`` carries prompt CONTENT (for an S4 specialist shard,
        most of it), so it is returned for :func:`prompt` to deliver — as a
        cache_control-marked block on Anthropic-routed requests, folded into
        the user turn otherwise.
      * Names in ``_ACCEPTED_UNUSED_KW`` are ignored silently: each already has
        an accepted-and-unused / silently-dropped precedent on a shipped route.
      * Anything else warns once, so a future kwarg can never vanish silently.
    """
    prefix = legacy_kw.pop("cache_prefix", None)
    for name in legacy_kw:
        if name not in _ACCEPTED_UNUSED_KW:
            warn_once(
                _WARNED_LEGACY_KW,
                name,
                f"WARN [deepagents]: legacy kwarg `{name}` is not supported on "
                f"the deepagents route — ignored",
            )
    return str(prefix) if prefix else ""


def _cfg_blocks(cfg: object) -> tuple[object, object, str | None]:
    """Return ``(sdk_cfg, openai_cfg, cfg_dir)`` off a profile node, all optional.

    ``cfg_dir`` is the profile's directory, stamped by ``config.load`` at
    ``cfg._data["_config_dir"]``; it anchors relative cert paths.
    """
    data = getattr(cfg, "_data", None)
    cfg_dir = data.get("_config_dir") if isinstance(data, dict) else None
    return getattr(cfg, "sdk", None), getattr(cfg, "openai", None), cfg_dir


def dispatch_prompt(
    user_prompt: str | list[dict[str, object]],
    *,
    model: object,
    cfg: object,
    cwd: str,
    system_prompt: str | None = None,
    max_tokens: int | None = None,
    tag: str | None = None,
    graph_name: str = DEFAULT_GRAPH_NAME,
    **legacy_kw: object,
) -> str:
    """Route a single-turn completion by the model's resolved ``via``.

    THE dispatch seam for ``prompt()``-shaped stages: a stage migrates onto the
    DeepAgents route by changing its one ``registry.prompt`` call to this, and
    exactly one place (here) knows how to build this route's options from the
    profile node — reuse, not per-stage rewriting. ``via: deepagents`` calls
    this module's :func:`prompt` with ``cwd``/``graph_name`` and the profile's
    ``sdk``/``openai`` blocks (credentials + TLS, relative cert paths anchored
    at the config directory); every other ``via`` goes through
    ``registry.prompt`` exactly as before — ``cwd``/``graph_name`` are
    deepagents-route concepts no ``registry.prompt`` caller passes today, and
    ``**legacy_kw`` (``timeout``, ``cache_prefix``, …) is forwarded untouched.
    On the deepagents branch legacy kwargs follow the
    :func:`_screen_legacy_kwargs` policy.
    """
    if resolve(model).via != "deepagents":
        return registry.prompt(
            user_prompt, model=model, system_prompt=system_prompt,
            max_tokens=max_tokens, tag=tag, **legacy_kw,
        )
    prefix = _screen_legacy_kwargs(legacy_kw)
    sdk_cfg, openai_cfg, cfg_dir = _cfg_blocks(cfg)
    return prompt(
        user_prompt, model=model, system_prompt=system_prompt,
        max_tokens=max_tokens, cwd=cwd, tag=tag, graph_name=graph_name,
        sdk_cfg=sdk_cfg, openai_cfg=openai_cfg, cfg_dir=cfg_dir,
        cache_prefix=prefix or None,
    )


def dispatch_agentic(
    user_prompt: str,
    *,
    model: object,
    cfg: object,
    cwd: str,
    system_prompt: str | None = None,
    allowed_tools: Sequence[str] | None = None,
    max_turns: int | None = None,
    max_budget_usd: float | None = None,
    tag: str | None = None,
    graph_name: str = DEFAULT_GRAPH_NAME,
    **legacy_kw: object,
) -> str:
    """Route a tool-using loop by the model's resolved ``via``.

    THE dispatch seam for ``agentic()``-shaped stages — same contract as
    :func:`dispatch_prompt`: one call to migrate a stage, one place that builds
    this route's options. ``via: deepagents`` calls this module's
    :func:`agentic`; every other ``via`` goes through ``registry.agentic``
    exactly as before, with ``**legacy_kw`` (``permission_mode``,
    ``stream_cb``, …) forwarded untouched. On the deepagents branch legacy
    kwargs follow the :func:`_screen_legacy_kwargs` policy.
    """
    if resolve(model).via != "deepagents":
        return registry.agentic(
            user_prompt, model=model, system_prompt=system_prompt,
            allowed_tools=allowed_tools, cwd=cwd, max_budget_usd=max_budget_usd,
            max_turns=max_turns, tag=tag, **legacy_kw,
        )
    prefix = _screen_legacy_kwargs(legacy_kw)
    sdk_cfg, openai_cfg, cfg_dir = _cfg_blocks(cfg)
    return agentic(
        # Agentic prompts are always flat text, so the fold is plain prepending.
        prefix + user_prompt if prefix else user_prompt,
        model=model, system_prompt=system_prompt,
        allowed_tools=allowed_tools, cwd=cwd, max_budget_usd=max_budget_usd,
        max_turns=max_turns, tag=tag, graph_name=graph_name,
        sdk_cfg=sdk_cfg, openai_cfg=openai_cfg, cfg_dir=cfg_dir,
    )
