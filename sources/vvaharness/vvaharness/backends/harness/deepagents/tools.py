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

"""Logical->native tool-name resolution for the DeepAgents backend.

The profile YAML uses backend-agnostic names (Read/Grep/Glob/Edit/Write). This module
resolves them onto the tools DeepAgents' FilesystemMiddleware already exposes, so the
model sees exactly one tool per job with one path convention. The mapping itself lives
in ``harness.models.LOGICAL_TO_NATIVE`` -- the family's single tool vocabulary.

Imports no ``deepagents`` symbol, so it stays importable on 3.10; that is pinned by
``test_deepagents_optional``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from langchain_core.tools import BaseTool

from vvaharness.backends.harness.models import (
    LOGICAL_TO_NATIVE,
    MCP_TOOL_PREFIX,
    MUTATING_TOOLS,
    ORCHESTRATION_TOOLS,
    StreamingOptions,
    ToolPolicy,
)
from vvaharness.util.warn_once import warn_once

if TYPE_CHECKING:
    from collections.abc import Sequence

#: Logical names deliberately absent from ``LOGICAL_TO_NATIVE``, so never warned
#: about: the orchestration vocabulary (``Agent``/``Task``/``TodoWrite``/``Skill``
#: — dispatch and bookkeeping the graph shape itself provides, not filesystem
#: tools) and the mutating vocabulary (``Bash``/``NotebookEdit`` have no native
#: counterpart on this backend by design; ``Edit``/``Write`` are mapped and
#: merely gated elsewhere). Derived from the shared vocabularies so a new name
#: added there cannot desync this set.
_UNMAPPED_BY_DESIGN: Final[frozenset[str]] = ORCHESTRATION_TOOLS | MUTATING_TOOLS

#: Unknown names already warned about, so each fires at most once per process
#: (these resolvers run per stage and per sub-agent; repeating would flood stderr).
_WARNED_UNKNOWN_TOOLS: set[str] = set()


def _warn_unknown_tools(options: StreamingOptions, allowed: set[str]) -> None:
    """WARN once per distinct allow-listed name that resolves to no tool at all.

    Fail-safe stays fail-safe: an unrecognised name still contributes NOTHING
    (a missing tool, never an extra one) and never raises — a profile typo must
    not abort a scan — but it is no longer invisible. Quiet by design for the
    ``_UNMAPPED_BY_DESIGN`` vocabulary, for the session's declared
    ``fact_tools`` (extra names a consumer's ``tool_builder`` constructs
    itself, e.g. validation's DiffTouched), and for ``mcp__``-prefixed tools.
    Only the tool NAME is printed — never argument, credential or file content.
    """
    known = LOGICAL_TO_NATIVE.keys() | _UNMAPPED_BY_DESIGN | set(options.fact_tools)
    for name in sorted(allowed - known):
        if name.startswith(MCP_TOOL_PREFIX):
            continue
        warn_once(
            _WARNED_UNKNOWN_TOOLS,
            name,
            f"WARN [deepagents]: unrecognised tool name {name!r} in the "
            f"allow-list — it maps to no tool on this backend and is ignored",
        )


def _allowed_tool_names(
    options: StreamingOptions, allowed_tools: Sequence[str] | None
) -> set[str]:
    """Resolve the effective allow-list: explicit *allowed_tools* else the policy's."""
    policy = options.tool_policy if options.tool_policy is not None else ToolPolicy()
    return set(allowed_tools if allowed_tools is not None else policy.allowed_tools)


def native_tool_names(
    options: StreamingOptions, allowed_tools: Sequence[str] | None
) -> tuple[str, ...]:
    """Resolve the logical allow-list to the native names this backend exposes."""
    allowed = _allowed_tool_names(options, allowed_tools)
    _warn_unknown_tools(options, allowed)
    return tuple(
        native for logical, native in LOGICAL_TO_NATIVE.items() if logical in allowed
    )


def session_tool_names(tools: Sequence[BaseTool]) -> frozenset[str]:
    """Names of the caller-built session tools, for the executor permit set.

    Shared by ``_oneshot_permitted_tools`` (options/oneshot.py) and
    ``_permitted_tool_calls`` (options/streaming.py), which union this into the
    set fed to the ``PermitTools`` executor-seam gate — extracted from their two
    verbatim copies so the one-shot and streaming permit computations cannot
    drift.

    Defensive by design, despite ``BaseTool.name`` being a required ``str``
    field: the entries come from ``_build_session_tools``, whose injected
    ``tool_builder`` is typed ``Callable[..., list[Any]]`` precisely so
    consumers may return SDK tool shapes — so an entry without a string
    ``name`` must contribute NOTHING (fail closed: a missing name never widens
    the permitted set) rather than crash the graph build. Deliberately narrower
    than ``exclude_tools._tool_name``: that helper also reads a dict-shaped
    spec's ``"name"`` key, which is right for an advertisement DENYLIST but
    would WIDEN this execution allowlist for dict entries, so it is not reused
    here.

    The native name space is RESERVED. A session tool named after a gated native
    (say a caller tool literally called ``write_file``) would land in the permit
    set and re-permit that native at the executor seam, silently undoing the
    gate — so a collision raises here rather than widening. This is a
    programming error in a ``tool_builder``, not operator input: session tools
    come from code, so failing at graph build surfaces it in CI, never mid-scan.
    """
    from vvaharness.backends.harness.deepagents.models import (  # noqa: PLC0415 — lazy: `.models` imports the deepagents distribution; a top-level import would break tests/test_deepagents_optional.py
        ALL_NATIVE_TOOLS,
    )

    names = frozenset(
        name
        for name in (getattr(tool, "name", None) for tool in tools)
        if isinstance(name, str)
    )
    reserved = names & ALL_NATIVE_TOOLS
    if reserved:
        raise ValueError(
            f"session tool name(s) {sorted(reserved)} collide with reserved "
            f"native tool names; rename them — permitting a native by way of a "
            f"session tool would bypass the executor-seam gate"
        )
    return names


def build_tools(
    options: StreamingOptions,
    *,
    allowed_tools: Sequence[str] | None,
) -> list[BaseTool]:
    """Build only the tools DeepAgents does not already provide.

    Logical names in :data:`LOGICAL_TO_NATIVE` resolve to native middleware tools
    (see :func:`native_tool_names`), so nothing is built for them. Consumers that
    need extra tools (e.g. validation's deterministic fact tools) supply a
    ``tool_builder`` that wraps this function and appends their own.

    This is the resolver production sessions actually reach (via
    ``_build_session_tools``), so it shares :func:`native_tool_names`'s
    unknown-name WARN: a name that neither maps to a native tool nor is
    unmapped by design would otherwise vanish without a trace.
    """
    _warn_unknown_tools(options, _allowed_tool_names(options, allowed_tools))
    return []


__all__ = ["build_tools", "native_tool_names", "session_tool_names"]
