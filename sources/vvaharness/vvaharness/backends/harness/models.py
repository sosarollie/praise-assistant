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

"""The harness family's data contract: vocabularies, options, messages and errors.

One module because these types are only meaningful together; tools have one source of truth here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

from vvaharness.util.tokens import TokenUsage

if TYPE_CHECKING:
    # Imported for the annotation only: PermissionsPolicy is behaviour, so it lives elsewhere.
    from langchain.agents.middleware.types import AgentMiddleware

    from vvaharness.backends.harness.permissions import PermissionsPolicy


#: Logical tool name (profile YAML) to native DeepAgents name; never rebuilt, middleware has it.
LOGICAL_TO_NATIVE: Final[Mapping[str, str]] = {
    "Read": "read_file",
    "Grep": "grep",
    "Glob": "glob",
    "Edit": "edit_file",
    "Write": "write_file",
}

#: Logical tools that only read.
READ_TOOLS: Final[frozenset[str]] = frozenset({"Read", "Grep", "Glob"})

#: Logical tools that orchestrate rather than touch the filesystem.
ORCHESTRATION_TOOLS: Final[frozenset[str]] = frozenset({"Agent", "Task", "TodoWrite", "Skill"})

#: Logical tools that mutate, denied in a read-only session.
MUTATING_TOOLS: Final[frozenset[str]] = frozenset({"Bash", "Edit", "NotebookEdit", "Write"})

#: Logical tools a read-only session may call without a path check; Write is gated per-path instead.
READ_ONLY_TOOLS: Final[frozenset[str]] = READ_TOOLS | ORCHESTRATION_TOOLS

#: Logical mutating tools denied outright; derived so a new tool above can't desync the two.
UNCONDITIONALLY_DENIED_TOOLS: Final[frozenset[str]] = MUTATING_TOOLS - {"Write", "Bash"}

#: Native names of the mutating tools. Derived, so adding a tool above cannot desync the two.
NATIVE_WRITE_TOOLS: Final[frozenset[str]] = frozenset(
    LOGICAL_TO_NATIVE[name] for name in MUTATING_TOOLS if name in LOGICAL_TO_NATIVE
)

#: Native tools whose results carry file content; ``glob``/``ls`` return only paths.
NATIVE_CONTENT_TOOLS: Final[frozenset[str]] = frozenset({"read_file", "grep"})

#: Legacy custom dispatch tool. Native subagents are used instead, so it is never granted.
LEGACY_AGENT_TOOL: Final = "Agent"

#: Prefix marking a tool supplied by an MCP server, which the permission gate allows.
MCP_TOOL_PREFIX: Final = "mcp__"


class EffortLevel(StrEnum):
    """Reasoning-effort tier accepted by the agent backend."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"

    @classmethod
    def parse(cls, value: str | None) -> EffortLevel | None:
        """Map a string to an effort tier, returning None when absent or invalid."""
        try:
            return cls(value)
        except ValueError:
            return None


class SettingSource(StrEnum):
    """Origin of a settings layer the agent backend may load."""

    USER = "user"
    PROJECT = "project"
    LOCAL = "local"


class Provider(StrEnum):
    """Which vendor's chat model a role resolves to. Anthropic, or an OpenAI-compatible endpoint."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"


@dataclass(frozen=True)
class ToolPolicy:
    """Declarative allowed/disallowed tool list for a harness session."""

    allowed_tools: tuple[str, ...] = ()
    disallowed_tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class SubagentDefinition:
    """SDK-insulated subagent definition for a named agent in a streaming session."""

    name: str
    description: str
    prompt: str
    tools: tuple[str, ...] | None = None
    disallowed_tools: tuple[str, ...] | None = None
    model: str | None = None
    skills: tuple[str, ...] | None = None
    output_schema: dict[str, Any] | None = None
    # Pydantic class for structured output; separate since ToolStrategy needs a class, not dict.
    response_model: type | None = None


@dataclass(frozen=True)
class PermissionDecision:
    """Result of a single permission evaluation: allow/deny with an optional reason."""

    allow: bool
    reason: str = ""
    interrupt: bool = False


# Builds a session's concrete tool objects; typed loosely so the contract skips SDK tool types.
ToolBuilder = Callable[..., list[Any]]

#: Cosmetic name for the compiled agent graph when a consumer does not name it.
DEFAULT_GRAPH_NAME: Final = "agent"


@dataclass
class SessionOptions:
    """What every harness invocation needs, whichever shape it takes.

    Extracted because OneShotOptions/StreamingOptions duplicated fifteen fields verbatim.
    """

    model: str
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    # deepagents backend selector: "openai" | "anthropic"; None => infer from name.
    model_provider: str | None = None
    effort: str | None = None
    #: OpenAI-branch transport OVERRIDE (config-pinned); None resolves: learned, then Responses.
    use_responses_api: bool | None = None
    system_prompt: str | None = None
    tool_policy: ToolPolicy | None = None
    cli_path: str | None = None  # absolute path to the claude executable (pin)
    #: Pydantic model *class* for structured output (None = none).
    response_model: type | None = None
    #: Builds the session's tools (None = the backend's generic readers).
    tool_builder: ToolBuilder | None = None
    #: Extra tool names granted to subagents beyond the policy.
    fact_tools: tuple[str, ...] = ()
    #: When False, write/edit tools are denied.
    allow_writes: bool = False
    #: Paths writes may target when allow_writes is True.
    writable_paths: tuple[str, ...] = ()
    #: Directory of agent skill packages to load (None = none).
    skill_root: Path | None = None
    graph_name: str = DEFAULT_GRAPH_NAME
    #: Per-model-call output-token cap (``CapOutputTokens``). ``None`` inherits
    #: the model's own ceiling — ``MODEL_MAX_OUTPUT_TOKENS`` (64k) on the
    #: Anthropic branch, uncapped on OpenAI-compatible gateways. The frozen
    #: S10/S11 option builders never set it, so their behaviour is unchanged;
    #: only detection sites opt in — the one-shot parser threads its
    #: ``max_tokens`` and ``agentic()`` pins ``AGENTIC_MAX_TOKENS`` for parity
    #: with ``via: sdk``/``openai``.
    max_output_tokens: int | None = None
    #: Whether ``BlockMarkerPromptCaching`` places cache markers; wired from the
    #: config's ``sdk:`` block ``cache_markers`` key by every construction site.
    cache_markers: bool = True


@dataclass
class OneShotOptions(SessionOptions):
    """Options for a parser-only single-turn invocation."""

    max_turns: int = 15
    output_schema: Mapping[str, object] | None = None
    #: Cacheable leading user-turn CONTENT (never a hint): sent as prefix+prompt
    #: with a cache_control breakpoint, or folded verbatim where markers are
    #: unsupported.
    cache_prefix: str | None = None


@dataclass
class StreamingOptions(SessionOptions):
    """Options for a full streaming session."""

    max_turns: int | None = None
    max_budget_usd: float | None = None
    setting_sources: tuple[str, ...] | None = None
    permissions: PermissionsPolicy | None = None
    agents: dict[str, SubagentDefinition] = field(default_factory=dict)
    output_schema: dict[str, object] | None = None
    #: Caller-specific middleware applied only to the parent graph. This lets a
    #: workflow enforce its orchestration protocol without changing subagents.
    parent_middleware: tuple[AgentMiddleware, ...] = ()
    #: NATIVE tool-call names the executor may run, fed to the ``PermitTools``
    #: gate at the ``wrap_tool_call`` seam: any tool_call outside the set is
    #: answered with a synthetic error ToolMessage instead of executing (fail
    #: closed). The graph builder unions in the caller-built session tools, so
    #: this carries only the natives the caller's policy actually granted —
    #: the streaming counterpart of ``_oneshot_permitted_tools``. ``None``
    #: (the default) installs NO gate: the frozen S10 remediation and S11
    #: validation option builders never set it, so those paths are inert by
    #: construction; only the detection ``agentic()`` construction site
    #: (``backends/llm/deepagents.py``) passes a set.
    permitted_tool_calls: frozenset[str] | None = None


@dataclass
class HarnessSessionInit:
    """Session-init event carrying the session ID and raw SDK payload."""

    kind: Literal["session_init"] = "session_init"
    session_id: str = ""
    raw: dict[str, object] = field(default_factory=dict)


# Optional provenance tags for backends streaming nested subagents; other backends leave both None.
@dataclass
class HarnessAssistantText:
    """A streamed text block emitted by the assistant."""

    kind: Literal["assistant_text"] = "assistant_text"
    text: str = ""
    agent: str | None = None
    namespace: tuple[str, ...] | None = None


@dataclass
class HarnessToolUse:
    """A tool-invocation request emitted by the assistant."""

    kind: Literal["tool_use"] = "tool_use"
    tool_id: str = ""
    name: str = ""
    input: dict[str, object] = field(default_factory=dict)
    agent: str | None = None
    namespace: tuple[str, ...] | None = None


@dataclass
class HarnessToolResult:
    """The result returned by a tool after a HarnessToolUse."""

    kind: Literal["tool_result"] = "tool_result"
    is_error: bool = False
    content: object = None
    agent: str | None = None
    namespace: tuple[str, ...] | None = None


@dataclass
class HarnessResult:
    """Terminal message marking the end of a streaming session.

    Deliberately NOT frozen: ClaudeHarness sets state after yielding, how persona reports reach it.
    """

    kind: Literal["result"] = "result"
    subtype: str = ""
    is_error: bool = False
    session_id: str | None = None
    result_text: str | None = None
    structured: object = None
    # The only channel separating schema-validation exhaustion from a fallback retracting output.
    errors: list[str] | None = None
    # Cumulative session token usage/cost from the SDK ResultMessage.
    usage: TokenUsage | None = None
    total_cost_usd: float | None = None
    # Backend-specific terminal state; DeepAgents uses it for host-side subagent report extraction.
    state: object = None


HarnessMessage = (
    HarnessSessionInit
    | HarnessAssistantText
    | HarnessToolUse
    | HarnessToolResult
    | HarnessResult
)


@dataclass
class OneShotResult:
    """Result of a single-turn parser-only invocation."""

    is_error: bool = False
    subtype: str = ""
    result_text: str | None = None
    structured: object = None
    # Cumulative session token usage/cost from the SDK ResultMessage.
    usage: TokenUsage | None = None
    total_cost_usd: float | None = None


class HarnessError(Exception):
    """Base class for all harness-level failures."""


class HarnessCLINotFoundError(HarnessError):
    """Underlying CLI binary is missing. Fatal for the whole batch."""


class HarnessConnectionError(HarnessError):
    """Connection to the underlying agent runtime failed."""


class HarnessProcessError(HarnessError):
    """Agent process exited abnormally. Carries exit_code and stderr tail."""

    def __init__(
        self,
        message: str,
        exit_code: int | None = None,
        stderr: str | None = None,
    ) -> None:
        """Store message, exit_code, and stderr tail."""
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class HarnessJSONDecodeError(HarnessError):
    """JSON decode failure on agent output."""


class HarnessMessageParseError(HarnessError):
    """Message parsing failed mid-stream."""


_AUTH_REMEDIATION = """\
  Credential options (pick the one that matches your profile):
    CLI backend (default):   run `claude /login`  or export CLAUDE_CODE_OAUTH_TOKEN=<fresh-token>
    SDK / API backend:       export ANTHROPIC_SDK_API_KEY=<key>  or  ANTHROPIC_API_KEY=<key>
    Gateway / JWT backend:   regenerate your JWT and set ANTHROPIC_BASE_URL=https://<gateway>/

  Then run:  vvaharness doctor
  To continue from the last checkpoint:  add --resume to your scan command."""

_PROXY_REMEDIATION = """\
  Check the following environment variables:
    ANTHROPIC_BASE_URL   — gateway / proxy base URL  (e.g. https://proxy.corp.example.com/)
    HTTPS_PROXY          — corporate HTTPS proxy      (e.g. http://proxy:3128)
    NODE_EXTRA_CA_CERTS  — path to CA bundle for the CLI backend
    SSL_CERT_FILE        — path to CA bundle for the SDK / Python backend
    CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1  — if the gateway rejects beta headers

  Verify connectivity:  vvaharness doctor"""


class AuthenticationError(HarnessError):
    """Authentication with the LLM provider failed (VVAH-E001)."""

    error_code: str = "VVAH-E001"

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        backend: str = "",
    ) -> None:
        """Build the operator-facing message, appending the credential remediation block."""
        full = (
            f"[{self.error_code}] Authentication failed"
            + (f" (HTTP {status_code})" if status_code else "")
            + (f" [{backend}]" if backend else "")
            + f": {message}\n"
            + _AUTH_REMEDIATION
        )
        super().__init__(full)
        self.status_code = status_code
        self.backend = backend


class ProxyError(HarnessConnectionError):
    """Proxy / TLS / network configuration error (VVAH-E002); raised without retry."""

    error_code: str = "VVAH-E002"

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        backend: str = "",
    ) -> None:
        """Build the operator-facing message, appending the proxy/TLS remediation block."""
        full = (
            f"[{self.error_code}] Proxy/network error"
            + (f" (HTTP {status_code})" if status_code else "")
            + (f" [{backend}]" if backend else "")
            + f": {message}\n"
            + _PROXY_REMEDIATION
        )
        super().__init__(full)
        self.status_code = status_code
        self.backend = backend


class DegenerateResponseError(HarnessError):
    """LLM returned 200 OK but the content is degenerate (VVAH-E003)."""

    error_code: str = "VVAH-E003"

    def __init__(
        self,
        message: str,
        *,
        stage: str = "",
        response_len: int = 0,
        threshold: int = 0,
        consecutive: int = 0,
    ) -> None:
        """Build the message; a single short response is a warning, so only repeats reach here."""
        detail = (
            (f" | stage={stage}" if stage else "")
            + (f" | len={response_len} (threshold={threshold})" if threshold else "")
            + (f" | consecutive={consecutive}" if consecutive else "")
        )
        full = f"[{self.error_code}] Degenerate LLM response{detail}: {message}"
        super().__init__(full)
        self.stage = stage
        self.response_len = response_len
        self.threshold = threshold
        self.consecutive = consecutive


class OversizePromptError(HarnessError):
    """Prompt exceeds the deepagents route's context ceiling (VVAH-E004).

    Raised BEFORE dispatch, so the owning unit (chunk, dedup pass, chain pass)
    fails loudly instead of the prompt being silently mutated in flight. NOT a
    halt error: stage-level handlers record it and the scan continues.
    """

    error_code: str = "VVAH-E004"

    def __init__(
        self,
        message: str,
        *,
        stage: str = "",
        estimated_tokens: int = 0,
        limit: int = 0,
    ) -> None:
        """Build the operator-facing message with the measured size and ceiling."""
        detail = (
            (f" | stage={stage}" if stage else "")
            + (f" | estimated_tokens={estimated_tokens} (limit={limit})" if limit else "")
        )
        full = f"[{self.error_code}] Prompt too large for the deepagents route{detail}: {message}"
        super().__init__(full)
        self.stage = stage
        self.estimated_tokens = estimated_tokens
        self.limit = limit


class TruncatedResponseError(HarnessError):
    """LLM reply cut off by its output-token budget despite one retry (VVAH-E005); non-halt."""

    error_code: str = "VVAH-E005"

    def __init__(
        self,
        message: str,
        *,
        stage: str = "",
        requested: int = 0,
        retried: int = 0,
    ) -> None:
        """Build the operator-facing message with the budgets that truncated."""
        detail = (
            (f" | stage={stage}" if stage else "")
            + (f" | requested={requested}" if requested else "")
            + (f" | retried_at={retried}" if retried else "")
        )
        full = f"[{self.error_code}] Truncated LLM response{detail}: {message}"
        super().__init__(full)
        self.stage = stage
        self.requested = requested
        self.retried = retried


def is_halt_error(exc: BaseException) -> bool:
    """True for VVAH-E001/E002, which must abort the scan immediately.

    Stage-level ``except Exception`` handlers use this to re-raise auth and
    proxy/TLS failures instead of logging them as recoverable stage errors.

    Deliberately lives HERE, next to the classes it tests, rather than in a
    separate module that redefines them. A copy of this predicate paired with a
    copy of the hierarchy silently returns False for every real backend error —
    the classes are compared by identity, so a duplicate ``AuthenticationError``
    is simply a different class — which turns every caller's halt guard into a
    no-op that still reads as protection.
    """
    return isinstance(exc, (AuthenticationError, ProxyError))


def is_token_error(exc: BaseException) -> bool:
    """True when the error is the normalized provider token failure."""
    return isinstance(exc, AuthenticationError)


__all__ = [
    "DEFAULT_GRAPH_NAME",
    "LEGACY_AGENT_TOOL",
    "LOGICAL_TO_NATIVE",
    "MCP_TOOL_PREFIX",
    "MUTATING_TOOLS",
    "NATIVE_CONTENT_TOOLS",
    "NATIVE_WRITE_TOOLS",
    "ORCHESTRATION_TOOLS",
    "READ_ONLY_TOOLS",
    "READ_TOOLS",
    "UNCONDITIONALLY_DENIED_TOOLS",
    "AuthenticationError",
    "DegenerateResponseError",
    "EffortLevel",
    "HarnessAssistantText",
    "HarnessCLINotFoundError",
    "HarnessConnectionError",
    "HarnessError",
    "HarnessJSONDecodeError",
    "HarnessMessage",
    "HarnessMessageParseError",
    "HarnessProcessError",
    "HarnessResult",
    "HarnessSessionInit",
    "HarnessToolResult",
    "HarnessToolUse",
    "OneShotOptions",
    "OneShotResult",
    "OversizePromptError",
    "PermissionDecision",
    "ProxyError",
    "SessionOptions",
    "SettingSource",
    "StreamingOptions",
    "SubagentDefinition",
    "ToolBuilder",
    "ToolPolicy",
    "TruncatedResponseError",
    "is_halt_error",
    "is_token_error",
]
