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

"""The DeepAgents backend's own data contract: env keys, cache key, subagent/graph shapes.

Separate from harness.models since nothing here is backend-neutral; the options package uses it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, NamedTuple, NotRequired, TypedDict

from deepagents import HarnessProfile
from deepagents.middleware.filesystem import FilesystemPermission
from langchain.agents.middleware.types import AgentMiddleware
from langchain.agents.structured_output import ToolStrategy
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage
from langchain_core.tools import BaseTool
from langgraph.graph.state import CompiledStateGraph

from vvaharness.backends.harness.models import NATIVE_WRITE_TOOLS
from vvaharness.util.tokens import TokenUsage

#: Environment variables OpenSSL/httpx read for a custom CA bundle.
SSL_CERT_FILE_VAR = "SSL_CERT_FILE"
SSL_CERT_DIR_VAR = "SSL_CERT_DIR"

#: mTLS client certificate: a combined-PEM path, or the cert half of a split pair.
TLS_CLIENT_CERT_VAR = "VVAHARNESS_TLS_CLIENT_CERT"
#: Optional private-key path when the client certificate above is split, not combined.
TLS_CLIENT_KEY_VAR = "VVAHARNESS_TLS_CLIENT_KEY"
#: INTERNAL carrier for the config-level ``verify_ssl`` tri-state — populated from
#: config by the harness itself, NOT a user-facing knob: disabling TLS verification
#: must stay a deliberate config edit, never a convenient environment variable.
#: Enforced by value-stamping: ``tls_carriers_for`` prefixes what it emits, and the
#: reader ignores (with a warning) any unstamped — i.e. ambient — value.
TLS_VERIFY_VAR = "VVAHARNESS_TLS_VERIFY"


def anthropic_key(env: dict[str, str]) -> str | None:
    """Return the Anthropic credential from *env*, preferring the API key."""
    return env.get("ANTHROPIC_API_KEY") or env.get("ANTHROPIC_AUTH_TOKEN")


def anthropic_base(env: dict[str, str]) -> str | None:
    """Return the Anthropic base URL from *env*, if set."""
    return env.get("ANTHROPIC_BASE_URL")


def openai_key(env: dict[str, str]) -> str | None:
    """Return the OpenAI credential from *env*, if set."""
    return env.get("OPENAI_API_KEY")


def openai_base(env: dict[str, str]) -> str | None:
    """Return the OpenAI base URL from *env*, if set."""
    return env.get("OPENAI_BASE_URL")


@dataclass(frozen=True, slots=True)
class ModelKey:
    """Hashable key for a resolved model that avoids keeping the env dict alive.

    Frozen so equality/hashing derive from the fields rather than hand-written dunders.
    """

    model_id: str
    provider: str
    openai_key: str
    openai_base: str
    anthropic_key: str
    anthropic_base: str
    effort: str | None = None
    #: RESOLVED transport, never the raw override — a learned flip must miss the cache.
    use_responses_api: bool | None = None

    @classmethod
    def of(
        cls,
        model_id: str,
        env: dict[str, str],
        provider: str | None,
        effort: str | None = None,
        use_responses_api: bool | None = None,
    ) -> ModelKey:
        """Build a key from the credentials *env* currently resolves to."""
        return cls(
            model_id=model_id,
            provider=provider or "",
            openai_key=openai_key(env) or "",
            openai_base=openai_base(env) or "",
            anthropic_key=anthropic_key(env) or "",
            anthropic_base=anthropic_base(env) or "",
            effort=effort,
            use_responses_api=use_responses_api,
        )


#: Canonical read-only value (compat/tests only); not global since that would suppress writes.
READ_ONLY_HARNESS_PROFILE = HarnessProfile(excluded_tools=NATIVE_WRITE_TOOLS)

# Runs without DOTGLOB: ** skips leading-dot paths, so /** alone leaves .git/.env writable.
READ_ONLY_PERMISSIONS: list[FilesystemPermission] = [
    FilesystemPermission(
        operations=["write"],
        paths=["/**", "/.*", "/.*/**", "/**/.*", "/**/.*/**"],
        mode="deny",
    ),
]

#: A write-mode session still must never reach .git internals: the harness itself
#: shells out to git in this tree, so a write to e.g. .git/config (core.fsmonitor,
#: core.sshCommand, a [url] rewrite) is remote code execution, not a scoped file
#: edit. Applied even when the session is otherwise fully write-enabled, so fix
#: mode keeps write_file/edit_file live for ordinary files while still refusing
#: this one directory. Nested (submodule) .git dirs are covered too.
GIT_INTERNALS_DENY: list[FilesystemPermission] = [
    FilesystemPermission(
        operations=["write"],
        paths=["/.git", "/.git/**", "/**/.git", "/**/.git/**"],
        mode="deny",
    ),
]

#: deepagents 0.7 registers this unconditionally; write sessions withhold it explicitly.
DELETE_TOOL_NAME: Final = "delete"

#: The sub-agent dispatch tool deepagents' SubAgentMiddleware registers. NOT in
#: ALL_NATIVE_TOOLS: it is added whenever the graph has any sub-agent — including
#: the ungated ``general-purpose`` one deepagents auto-adds when no ``subagents=``
#: specs are supplied — so a path that grants no tools must still withhold it by name.
SUBAGENT_DISPATCH_TOOL: Final = "task"

#: Every native tool deepagents' FilesystemMiddleware/backend can register on a graph.
ALL_NATIVE_TOOLS: Final[frozenset[str]] = frozenset(
    {"ls", "read_file", "write_file", "edit_file", "glob", "grep", "delete", "execute"}
)


class SubagentSpec(TypedDict):
    """Native DeepAgents subagent spec passed to ``create_deep_agent(subagents=...)``."""

    name: str
    description: str
    system_prompt: str
    model: BaseChatModel
    tools: list[BaseTool]
    middleware: NotRequired[list[AgentMiddleware]]
    response_format: NotRequired[ToolStrategy | type]


class GraphConfigurable(TypedDict):
    """Per-thread identity carried inside a LangGraph invoke config."""

    thread_id: str


class GraphInvokeConfig(TypedDict):
    """LangGraph invoke config: thread identity plus an optional recursion cap."""

    configurable: GraphConfigurable
    recursion_limit: NotRequired[int]


class CompiledGraph(NamedTuple):
    """A compiled LangGraph agent paired with its invoke config."""

    graph: CompiledStateGraph
    config: GraphInvokeConfig


class DeepAgentsGraphState(TypedDict, total=False):
    """Terminal/delta LangGraph state; field names mirror validation's HarnessTerminalState."""

    messages: list[BaseMessage]
    structured_response: object
    usage: TokenUsage
    sdk_persona_reports: list[dict[str, object]]


class StreamEvent(NamedTuple):
    """One LangGraph ``subgraphs=True`` stream update: a namespace paired with its payload."""

    namespace: tuple[str, ...]
    payload: Mapping[str, DeepAgentsGraphState]


__all__ = [
    "ALL_NATIVE_TOOLS",
    "DELETE_TOOL_NAME",
    "GIT_INTERNALS_DENY",
    "READ_ONLY_HARNESS_PROFILE",
    "READ_ONLY_PERMISSIONS",
    "SSL_CERT_DIR_VAR",
    "SSL_CERT_FILE_VAR",
    "SUBAGENT_DISPATCH_TOOL",
    "TLS_CLIENT_CERT_VAR",
    "TLS_CLIENT_KEY_VAR",
    "TLS_VERIFY_VAR",
    "CompiledGraph",
    "DeepAgentsGraphState",
    "GraphConfigurable",
    "GraphInvokeConfig",
    "ModelKey",
    "StreamEvent",
    "SubagentSpec",
    "anthropic_base",
    "anthropic_key",
    "openai_base",
    "openai_key",
]
