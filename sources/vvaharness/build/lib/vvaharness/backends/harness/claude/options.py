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

"""Translate harness option dataclasses into ``ClaudeAgentOptions``."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, cast

from claude_agent_sdk import (
    AgentDefinition,
    CanUseTool,
    ClaudeAgentOptions,
    PermissionResultAllow,
    PermissionResultDeny,
    ToolPermissionContext,
)
from claude_agent_sdk.types import SettingSource as SdkSettingSource

from vvaharness.backends.harness.models import (
    EffortLevel,
    OneShotOptions,
    SettingSource,
    StreamingOptions,
    SubagentDefinition,
)
from vvaharness.backends.harness.permissions import PermissionsPolicy

# SDK effort contract at the translation boundary; runtime values come from EffortLevel.
_SdkEffort = Literal["low", "medium", "high", "xhigh", "max"]


def _to_effort(effort: str | None) -> _SdkEffort | None:
    """Validate an effort string via EffortLevel, returning the SDK literal or None."""
    parsed = EffortLevel.parse(effort)
    return cast(_SdkEffort, parsed.value) if parsed is not None else None


def _to_setting_sources(sources: tuple[str, ...]) -> list[SdkSettingSource]:
    """Validate setting-source strings via SettingSource and return SDK literals."""
    out: list[SdkSettingSource] = []
    for s in sources:
        try:
            member = SettingSource(s)
        except ValueError:
            raise ValueError(f"invalid setting_source: {s!r}") from None
        out.append(cast(SdkSettingSource, member.value))
    return out


def _permissions_callback(policy: PermissionsPolicy) -> CanUseTool:
    """Wrap a PermissionsPolicy as the SDK CanUseTool async callback."""
    async def gate(
        tool_name: str,
        input_data: dict[str, object],
        _context: ToolPermissionContext,
    ) -> PermissionResultAllow | PermissionResultDeny:
        decision = policy.evaluate(tool_name, input_data)
        if decision.allow:
            return PermissionResultAllow(updated_input=input_data)
        return PermissionResultDeny(
            message=decision.reason, interrupt=decision.interrupt,
        )

    return cast(CanUseTool, gate)


def _to_agent_definition(subagent: SubagentDefinition) -> AgentDefinition:
    """Convert a SubagentDefinition to the SDK AgentDefinition shape."""
    return AgentDefinition(
        description=subagent.description,
        prompt=subagent.prompt,
        tools=list(subagent.tools) if subagent.tools is not None else None,
        disallowedTools=list(subagent.disallowed_tools)
            if subagent.disallowed_tools is not None else None,
        model=subagent.model,
        skills=list(subagent.skills) if subagent.skills is not None else None,
    )


def _build_output_format(schema: Mapping[str, object]) -> dict[str, object]:
    """Wrap a JSON schema mapping as the SDK output_format dict."""
    return {"type": "json_schema", "schema": dict(schema)}


def _sanitize_schema(schema: Mapping[str, object]) -> dict[str, object]:
    """Copy *schema* without any ``$schema`` dialect declaration.

    The CLI validates schemas as draft-07 and fails at startup on a newer dialect.
    """
    return {key: value for key, value in schema.items() if key != "$schema"}


def _resolve_output_schema(
    options: OneShotOptions | StreamingOptions,
) -> dict[str, object] | None:
    """Pick the JSON schema for structured output, or None when unset.

    An explicit output_schema wins; else derive from response_model, since this SDK takes only dict.
    """
    if options.output_schema is not None:
        return _sanitize_schema(options.output_schema)
    dump = getattr(options.response_model, "model_json_schema", None)
    if not callable(dump):
        return None
    # Duck-typed call, so confirm the return is really a mapping before handing it to the CLI.
    schema = dump()
    return _sanitize_schema(schema) if isinstance(schema, Mapping) else None


def _base_opts(options: OneShotOptions | StreamingOptions) -> ClaudeAgentOptions:
    """Create SDK options from fields shared by all option types."""
    opts = ClaudeAgentOptions(
        model=options.model,
        cwd=options.cwd,
        env=options.env,
        effort=_to_effort(options.effort),
    )
    # Pin the claude executable to an absolute path, not a bare name via PATH (CWE-426/427).
    if options.cli_path:
        opts.cli_path = options.cli_path
    if options.system_prompt is not None:
        opts.system_prompt = options.system_prompt
    if options.tool_policy is not None:
        opts.allowed_tools = list(options.tool_policy.allowed_tools)
        opts.disallowed_tools = list(options.tool_policy.disallowed_tools)
    return opts


def _apply_agents(opts: ClaudeAgentOptions, options: StreamingOptions) -> None:
    """Attach agent definitions to opts if any are configured."""
    if options.agents:
        opts.agents = {name: _to_agent_definition(a) for name, a in options.agents.items()}


def build_oneshot_sdk_options(options: OneShotOptions) -> ClaudeAgentOptions:
    """Translate OneShotOptions into ClaudeAgentOptions for a single-turn invocation."""
    opts = _base_opts(options)
    opts.max_turns = options.max_turns
    opts.permission_mode = "default"
    opts.setting_sources = None
    schema = _resolve_output_schema(options)
    if schema is not None:
        opts.output_format = _build_output_format(schema)
    return opts


def build_streaming_sdk_options(options: StreamingOptions) -> ClaudeAgentOptions:
    """Translate StreamingOptions into ClaudeAgentOptions for a streaming session."""
    opts = _base_opts(options)
    if options.max_turns is not None:
        opts.max_turns = options.max_turns
    if options.max_budget_usd is not None:
        opts.max_budget_usd = options.max_budget_usd
    if options.setting_sources is not None:
        opts.setting_sources = _to_setting_sources(options.setting_sources)
    if options.permissions is not None:
        opts.can_use_tool = _permissions_callback(options.permissions)
    # Served via a synthetic StructuredOutput tool that bypasses can_use_tool (CLI 2.1.220).
    schema = _resolve_output_schema(options)
    if schema is not None:
        opts.output_format = _build_output_format(schema)
    _apply_agents(opts, options)
    return opts
