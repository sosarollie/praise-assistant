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

"""Shared contract for the prompt/agentic backends.

The legacy four (`cli`, `sdk`, `openai`, `agent_sdk`) implement both entry points; the
deepagents llm adapter also satisfies `prompt()` but deliberately not `agentic()`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, Final, NamedTuple, NewType, Protocol, TypedDict, runtime_checkable

from vvaharness.util.tokens import TokenUsage

#: A backend module's import path, e.g. ``"vvaharness.backends.llm.cli"``.
ModulePath = NewType("ModulePath", str)

#: Statuses worth retrying for backends that own their HTTP transport (`sdk`, `openai`).
RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504, 529})

#: Narrower for `cli`: the binary already retried 500/504. See test_run_with_retry_500_not_retried.
CLI_RETRYABLE_STATUS: Final[frozenset[int]] = RETRYABLE_STATUS - {500, 504}

#: Rate-limit/overload prose, matched by all three backends: a gateway can report a transient in
#: the message with no retryable status at all — S6 lost a verification unit to "Rate limiting
#: temporarily unavailable" delivered inside an HTTP 200 error payload, which no status set can
#: classify.
#: No bare `\b429\b` here, deliberately. Both SDKs build `.message` as
#: "Error code: {status} - {body}", so matching the message IS matching the body, and a
#: bare number would promote a terminal error whose body merely contains `req-429-...`
#: or "you requested 429 tokens" into a full retry ladder. Status 429 needs no prose
#: help on those routes — it is in RETRYABLE_STATUS and is checked first. Only `cli`,
#: which reads a status it cannot always parse, needs the number; see CLI_STATUS_429_RX.
RATE_LIMIT_TRANSIENT_RX: Final[re.Pattern[str]] = re.compile(
    r"rate.?limit|too many requests|overloaded|temporarily unavailable",
    re.IGNORECASE,
)

#: `cli` only: the subprocess reports a rate limit as text when no envelope status could be
#: parsed, so there the bare number is the only signal available.
CLI_STATUS_429_RX: Final[re.Pattern[str]] = re.compile(r"\b429\b")

#: Mid-stream server-error prose, `sdk`/`openai` only: giving it to `cli` would widen the retry
#: set past what the binary's own retries already cover (the 500/504 carve-out above).
#: `internal server error` and `bad gateway` are spelled out because the machine token
#: `server_error` requires the underscore, so a gateway that prose-wraps a 500 or 502 inside an
#: HTTP 200 payload would otherwise read as terminal, losing the unit.
#: Deliberately NOT a numeric class: `\b50\d\b` would fire on incidental text like "504 tokens".
SERVER_ERROR_TRANSIENT_RX: Final[re.Pattern[str]] = re.compile(
    r"server_error|overloaded|service unavailable"
    r"|internal server error|bad gateway", re.I)

#: Connection-level transients (dropped socket) retry since prompts are idempotent; matched on
#: text, and `cli` only: the subprocess reports transport failures as prose, whereas the
#: `sdk`/`openai` transports raise them as their APIConnectionError — never inside an
#: APIStatusError message — so matching this on those paths would be dead code.
CLI_CONN_TRANSIENT_RX: Final[re.Pattern[str]] = re.compile(
    r"socket connection was closed|connection (?:reset|closed|aborted)"
    r"|ECONNRESET|EPIPE|broken pipe|incomplete(?:ly)? read"
    r"|premature(?:ly)? closed|EOF occurred",
    re.IGNORECASE,
)

#: Tools an agentic call gets when the caller names none. Read-only: `llm.tools` has no shell.
DEFAULT_READ_TOOLS: Final[tuple[str, ...]] = ("Read", "Glob", "Grep")

#: Output cap for one agentic turn.
AGENTIC_MAX_TOKENS: Final = 16_000

#: Estimated-token ceiling for one deepagents dispatch (prompt + cache prefix).
#: Provider-context insurance only: the fail-closed detection backend already
#: makes upstream eviction unreachable, so a prompt past this would fail at the
#: provider anyway — this raises VVAH-E004 BEFORE dispatch (loud, unit-level)
#: instead of paying for a doomed call. No config surface by design.
DEEPAGENTS_MAX_PROMPT_TOKENS: Final = 150_000

#: Truncation-retry factor (VVAH-E005): a dimensionless ratio, never an endpoint token ceiling.
TRUNCATION_RETRY_MULTIPLIER: Final = 2

#: COUNTERS key for confirmed truncations (VVAH-E005), shared by the sdk/openai backends.
TRUNCATED_REPLIES_COUNTER: Final = "llm_truncated_replies"

#: OpenAI ``finish_reason`` value marking an output-budget cutoff.
OPENAI_FINISH_LENGTH: Final = "length"

#: Anthropic ``stop_reason`` value marking an output-budget cutoff.
ANTHROPIC_STOP_MAX_TOKENS: Final = "max_tokens"


def truncation_retry_max(requested: int, cap: int | None = None) -> int | None:
    """Output budget for the one truncation retry; None when a request at *cap* makes it useless."""
    if cap is not None and requested >= cap:
        return None
    doubled = requested * TRUNCATION_RETRY_MULTIPLIER
    return doubled if cap is None else min(doubled, cap)


def _named_tools(tools: Sequence[str] | None, *, config_key: str) -> list[str]:
    """Normalise a configured allowlist, rejecting the YAML shapes that misbehave downstream.

    A bare scalar (``allowed_tools: Read``) would iterate per character; an
    explicit empty list would silently re-grant the defaults here — and worse,
    forwarded onward it makes `cli.py agentic()` omit ``--allowedTools``
    entirely, granting the CLI's own (broader) default toolset. Both raise.

    Args:
        tools: The configured allowlist; ``None`` (key absent) falls back to
            `DEFAULT_READ_TOOLS`.
        config_key: The profile key being validated, named in every error.

    Returns:
        The tool names as a list of `str`.

    Raises:
        ValueError: On a scalar, an explicit empty list, or a non-str element.
    """
    if tools is None:
        return list(DEFAULT_READ_TOOLS)
    if isinstance(tools, str):
        # ValueError, not TypeError: every bad profile *value* raises one
        # catchable type here, whatever shape the YAML mistake took.
        raise ValueError(  # noqa: TRY004 — deliberate single config-error type
            f"{config_key} must be a YAML list of tool names, got the bare "
            f"string {tools!r} — write it as `allowed_tools: [{tools}]`")
    named = list(tools)
    if not named:
        raise ValueError(
            f"{config_key} is an empty list, which would silently grant a "
            f"default toolset instead of none — name the tools explicitly, "
            f"or remove the key to get {sorted(DEFAULT_READ_TOOLS)}")
    if any(not isinstance(t, str) for t in named):
        raise ValueError(
            f"{config_key} must contain only strings, got "
            f"{[t for t in named if not isinstance(t, str)]!r}")
    return named


def validate_detection_tools(
    tools: Sequence[str] | None, *, config_key: str, via: str | None = None,
) -> list[str]:
    """Validate a detection stage's agentic tool allowlist for the backend it targets.

    Detection stages must stay read-only on every via that cannot honour the
    allowlist itself: on `via: sdk` an unsupported or mutating tool (Bash,
    Edit, Write, ...) silently delegates the whole agentic call to the Agent
    SDK backend (`sdk.py agentic()`), which can modify the scanned repository;
    `via: openai` rejects it only mid-stage. This raises up front instead, so
    a bad profile fails closed before any model call. `via: cli` is exempt —
    `cli.py agentic()` forwards the allowlist verbatim via ``--allowedTools``
    without ever handing the call to another backend, and giving a via:cli
    role Bash is a shipped, documented capability.

    Args:
        tools: The configured allowlist; ``None`` (key absent) falls back to
            `DEFAULT_READ_TOOLS`. A bare string or an explicit empty list is
            rejected (see `_named_tools`).
        config_key: The profile key being validated, named in the error —
            e.g. ``"step1.allowed_tools"`` or ``"step6_verify.allowed_tools"``.
        via: The resolved via of the stage's model. When omitted (or anything
            other than ``"cli"``) the strict read-only rule applies.

    Returns:
        The validated tool names.

    Raises:
        ValueError: Naming every offending tool, the permitted set, and why.
    """
    named = _named_tools(tools, config_key=config_key)
    if via == "cli":  # the only via whose agentic() honours the allowlist itself
        return named
    bad = sorted(t for t in named if t not in DEFAULT_READ_TOOLS)
    if bad:
        raise ValueError(
            f"{config_key} contains disallowed tool(s) {bad}: this is a "
            f"detection stage and only read-only tools "
            f"{sorted(DEFAULT_READ_TOOLS)} are permitted on "
            f"`via: {via or 'sdk/openai'}` (on `via: sdk` an unsupported or "
            f"mutating tool delegates to the Agent SDK backend, which could "
            f"modify the scanned repository; only `via: cli` honours a wider "
            f"allowlist itself)")
    return named


class ModelExtras(TypedDict, total=False):
    """Optional per-model tunables a profile may set; only `sdk` reads all three."""

    temperature: float
    thinking_budget: int
    betas: list[str]


class ResolvedModel(NamedTuple):
    """What a profile's model node resolves to. A tuple, so existing unpacking still works."""

    model_id: str
    via: str
    extras: ModelExtras


class EnvelopeResult(NamedTuple):
    """One `claude -p` JSON envelope; *turns*/*usd* are None, not zero, when absent."""

    text: str
    usage: TokenUsage | None
    turns: int | None = None
    usd: float | None = None


#: Tri-state by design: True verifies, False disables, a str is a CA-bundle path.
VerifySsl = bool | str


class CliConfig(TypedDict):
    """Gateway settings `cli.configure()` stores for the subprocess env."""

    verify_ssl: VerifySsl
    ca_cert: str | None
    client_cert: str | tuple[str, str] | None
    no_proxy: str | None
    effort: str


class SdkConfig(TypedDict):
    """Gateway settings `sdk.configure()` stores for the Anthropic client."""

    api_key: str | None
    base_url: str | None
    verify_ssl: VerifySsl
    ca_cert: str | None
    client_cert: str | tuple[str, str] | None
    no_proxy: str | None
    allow_api_key_fallback: bool
    # Prompt-cache switches. `cache_markers` is `str | bool` because PyYAML parses an
    # unquoted `cache_markers: off` as the boolean False -- see cache.markers_enabled,
    # which defends against exactly that. `cache_route` is normalised to one of
    # auto/none/anthropic/vertex/bedrock by configure() before it is stored.
    cache_min_block_tokens: int | None
    cache_route: str
    cache_markers: str | bool


class OpenAiConfig(TypedDict):
    """Gateway settings `openai.configure()` stores for the OpenAI client."""

    api_key: str | None
    base_url: str | None
    verify_ssl: VerifySsl
    ca_cert: str | None
    organization: str | None
    no_proxy: str | None
    # See SdkConfig.cache_markers for why this is `str | bool`.
    cache_markers: str | bool


class GuardrailBlocked(RuntimeError):
    """A provider guardrail declined the request, so retrying the same prompt cannot help."""


@runtime_checkable
class LlmBackend(Protocol):
    """A module serving this family's two calls, so a mis-registered one fails at selection."""

    def prompt(self, user_prompt: str, *, model: str, **kwargs: Any) -> str:
        """Run a single-turn completion and return its text."""
        ...

    def agentic(self, user_prompt: str, *, model: str, **kwargs: Any) -> str:
        """Run a tool-using loop to completion and return its final text."""
        ...


__all__ = [
    "AGENTIC_MAX_TOKENS",
    "ANTHROPIC_STOP_MAX_TOKENS",
    "CLI_CONN_TRANSIENT_RX",
    "CLI_STATUS_429_RX",
    "CLI_RETRYABLE_STATUS",
    "DEEPAGENTS_MAX_PROMPT_TOKENS",
    "DEFAULT_READ_TOOLS",
    "OPENAI_FINISH_LENGTH",
    "RATE_LIMIT_TRANSIENT_RX",
    "RETRYABLE_STATUS",
    "SERVER_ERROR_TRANSIENT_RX",
    "TRUNCATED_REPLIES_COUNTER",
    "TRUNCATION_RETRY_MULTIPLIER",
    "GuardrailBlocked",
    "LlmBackend",
    "ModelExtras",
    "ModulePath",
    "ResolvedModel",
    "truncation_retry_max",
    "validate_detection_tools",
]
