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

"""Shared agent-harness abstraction.

A backend-neutral contract (:class:`Harness`, the ``models`` dataclasses, the permission
gate, and the ``get_harness`` registry) plus concrete backends (deepagents, claude).
Any consumer — validation, remediation, orchestrator — configures a run purely
through the contract types here; validation-specific values (its output schema,
fact tools, read-only policy) are injected by the caller, never hardwired.

This module is the family's public surface: import from ``vvaharness.backends.harness``
rather than reaching into a submodule, so a later reshuffle inside the family cannot
break consumers.
"""

from vvaharness.backends.harness.harness import Harness
from vvaharness.backends.harness.models import (
    DEFAULT_GRAPH_NAME,
    LEGACY_AGENT_TOOL,
    LOGICAL_TO_NATIVE,
    MCP_TOOL_PREFIX,
    MUTATING_TOOLS,
    NATIVE_CONTENT_TOOLS,
    NATIVE_WRITE_TOOLS,
    ORCHESTRATION_TOOLS,
    READ_ONLY_TOOLS,
    READ_TOOLS,
    UNCONDITIONALLY_DENIED_TOOLS,
    EffortLevel,
    HarnessAssistantText,
    HarnessCLINotFoundError,
    HarnessConnectionError,
    HarnessError,
    HarnessJSONDecodeError,
    HarnessMessage,
    HarnessMessageParseError,
    HarnessProcessError,
    HarnessResult,
    HarnessSessionInit,
    HarnessToolResult,
    HarnessToolUse,
    OneShotOptions,
    OneShotResult,
    PermissionDecision,
    Provider,
    SessionOptions,
    SettingSource,
    StreamingOptions,
    SubagentDefinition,
    ToolBuilder,
    ToolPolicy,
)
from vvaharness.backends.harness.permission_rules import evaluate_write
from vvaharness.backends.harness.permissions import PermissionsPolicy
from vvaharness.backends.harness.provider_routing import routes_to_anthropic
from vvaharness.backends.harness.registry import get_harness

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
    "EffortLevel",
    "Harness",
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
    "PermissionDecision",
    "PermissionsPolicy",
    "Provider",
    "SessionOptions",
    "SettingSource",
    "StreamingOptions",
    "SubagentDefinition",
    "ToolBuilder",
    "ToolPolicy",
    "evaluate_write",
    "get_harness",
    "routes_to_anthropic",
]
