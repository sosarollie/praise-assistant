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

"""Claude Agent SDK backend for the Remediation Agent's fix mode (`via: sdk`); sdk.py is read-only.
Deny-by-default gate: Read/Glob/Grep OK, Edit/Write cwd-confined, Bash denied (RCE + exfil risk).
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import cast

from vvaharness.backends.llm.models import DEFAULT_READ_TOOLS
from vvaharness.report.redact import redact_counts
from vvaharness.util.tokens import TOKENS, TokenUsage

# Read-only tools are always safe; only file-mutation tools are gated to cwd.
_WRITE_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
# Read-only inspection tools — always permitted (output is redaction-hooked).
_READ_TOOLS = frozenset({"Read", "Glob", "Grep", "LS", "NotebookRead"})
# Masked by the PostToolUse hook so on-disk secrets/PII aren't egressed unredacted.
_REDACT_TOOLS = _READ_TOOLS | frozenset({"Bash"})


def _resolve_within_root(root: Path, raw: object) -> Path | None:
    """Resolve *raw* to a real path confined to *root*, or None if unresolvable/escaping/a symlink.
    Hands back the RESOLVED path (not the raw name); a symlinked part is refused unfollowed.
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        candidate = Path(raw) if os.path.isabs(raw) else (root / raw)
        # Refuse a symlinked final component without following it — the redirect primitive denied.
        if candidate.is_symlink():
            return None
        target = candidate.resolve()
        target.relative_to(root)
    except (OSError, ValueError):
        return None
    return target


def _within_root(root: Path, raw: object) -> bool:
    """Return True iff *raw* resolves to a non-symlinked path inside (or equal
    to) *root*. Thin bool wrapper over :func:`_resolve_within_root` used where
    only an allow/deny decision is needed."""
    return _resolve_within_root(root, raw) is not None


def _sdk_env() -> dict[str, str]:
    """Inherit the ambient environment, forwarding the SDK-specific key as the
    standard ANTHROPIC_API_KEY when only the former is set so a single
    credential authenticates the Agent-SDK-spawned CLI."""
    env = dict(os.environ)
    if not env.get("ANTHROPIC_API_KEY"):
        fallback = (env.get("ANTHROPIC_AUTH_TOKEN")
                    or env.get("ANTHROPIC_SDK_API_KEY"))
        if fallback:
            env["ANTHROPIC_API_KEY"] = fallback
    sdk_base = env.get("ANTHROPIC_SDK_BASE_URL")
    if sdk_base and not env.get("ANTHROPIC_BASE_URL"):
        env["ANTHROPIC_BASE_URL"] = sdk_base
    return env


def _redact_tool_output(payload: object) -> object:
    """Mask secret/PII in *payload* (str/list/dict) via redact_counts(); unknown shapes pass."""
    if isinstance(payload, str):
        masked, _ = redact_counts(payload)
        return masked
    if isinstance(payload, list):
        return [_redact_tool_output(item) for item in payload]
    if isinstance(payload, dict):
        out = dict(payload)
        for key in ("text", "content", "stdout", "stderr", "output"):
            if key in out:
                out[key] = _redact_tool_output(out[key])
        return out
    return payload


def _build_redaction_hooks():
    """Build a PostToolUse hook masking Read/Grep/Bash; best-effort, None if HookMatcher missing."""
    try:
        from claude_agent_sdk import HookMatcher  # type: ignore  # noqa: PLC0415 — optional SDK
    except Exception:  # noqa: BLE001 — optional/older SDK without hooks
        return None

    async def _post_tool_use(input_data, tool_use_id, context):  # noqa: ANN001, ARG001
        try:
            tool_name = (input_data or {}).get("tool_name")
            if tool_name not in _REDACT_TOOLS:
                return {}
            response = (input_data or {}).get("tool_response")
            if response is None:
                return {}
            masked = _redact_tool_output(response)
            if masked == response:
                return {}
            # `updatedToolOutput` is the only key the CLI honours; the old name leaked cleartext.
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": masked,
                }
            }
        except Exception:  # noqa: BLE001 — a redaction hook must never break a run
            return {}

    try:
        return {"PostToolUse": [HookMatcher(hooks=[_post_tool_use])]}  # type: ignore[list-item]
    except Exception:  # noqa: BLE001 — SDK HookMatcher shape guard
        return None


def _build_options(*, model: str, system_prompt: str | None,
                   allowed_tools: list[str], cwd: str,
                   max_budget_usd: float | None, max_turns: int | None):
    """Compose ClaudeAgentOptions with a cwd-confined write gate; lazy import keeps SDK optional."""
    from claude_agent_sdk import (  # noqa: PLC0415 — lazy: SDK stays optional
        ClaudeAgentOptions,
        PermissionResultAllow,
        PermissionResultDeny,
    )

    root = Path(cwd).resolve()

    async def _gate(tool_name, input_data, context):  # noqa: ANN001, ARG001
        # File-mutation tools: allow only when the target stays inside the repo.
        if tool_name in _WRITE_TOOLS:
            raw = key_used = None
            for key in ("file_path", "path", "notebook_path"):
                val = input_data.get(key)
                if val:
                    raw, key_used = val, key
                    break
            resolved = _resolve_within_root(root, raw)
            if resolved is None:
                return PermissionResultDeny(
                    message=(f"{tool_name} target {raw!r} is outside the "
                             f"repository root, unresolvable, or a symlink — "
                             f"edits are confined to {root}"),
                    interrupt=False,
                )
            # Hand the SDK the resolved path, not the raw name, so an alias can't redirect it.
            safe_input = dict(input_data)
            safe_input[key_used] = str(resolved)
            return PermissionResultAllow(updated_input=safe_input)
        # Read-only inspection tools: always allowed.
        if tool_name in _READ_TOOLS:
            return PermissionResultAllow(updated_input=input_data)
        # DENY-BY-DEFAULT, esp. Bash: host-shell RCE + credential exfil; re-adding it can't run.
        return PermissionResultDeny(
            message=(f"{tool_name} is not permitted in remediation fix mode — "
                     f"only Read/Glob/Grep and cwd-confined Edit/Write are "
                     f"allowed (Bash and other tools are denied by default)."),
            interrupt=False,
        )

    redaction_hooks = _build_redaction_hooks()

    opts = ClaudeAgentOptions(
        model=model,
        cwd=str(root),
        env=_sdk_env(),
        # Programmatic gate decides every tool call; no interactive prompts or project settings.
        permission_mode="default",
        setting_sources=None,
        can_use_tool=_gate,
        allowed_tools=list(allowed_tools),
    )
    # PostToolUse redaction mirrors the read-only localtools loop; set defensively for older SDKs.
    if redaction_hooks is not None:
        try:
            opts.hooks = redaction_hooks  # type: ignore[assignment]
        except (AttributeError, TypeError):  # pragma: no cover - SDK shape guard
            pass

    if system_prompt is not None:
        opts.system_prompt = system_prompt
    if max_turns is not None:
        opts.max_turns = int(max_turns)
    if max_budget_usd is not None:
        opts.max_budget_usd = float(max_budget_usd)
    return opts


async def _run(*, user_prompt: str, opts) -> str:  # noqa: ANN001
    """Stream one agentic session to completion and return the final text."""
    from claude_agent_sdk import (  # noqa: PLC0415 — lazy: SDK stays optional
        AssistantMessage,
        ClaudeSDKClient,
        ResultMessage,
        TextBlock,
    )

    text_parts: list[str] = []
    result_text: str | None = None
    async with ClaudeSDKClient(options=opts) as client:
        await client.query(user_prompt)
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        text_parts.append(block.text)
            elif isinstance(message, ResultMessage):
                if message.usage:
                    TOKENS.add(cast("TokenUsage", message.usage))
                result_text = message.result
                break
    # ResultMessage.result holds the final answer; fall back to accumulated text blocks if unset.
    return (result_text or "".join(text_parts)).strip()


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,
    permission_mode: str = "auto",   # accepted for parity; gate handles policy
    max_turns: int | None = None,
    tag: str | None = None,
) -> str:
    """Run an agentic loop with native Edit/Write/Bash via the Agent SDK; writes cwd-confined."""
    try:
        import claude_agent_sdk  # noqa: F401, PLC0415 — availability probe
    except ImportError as e:
        raise RuntimeError(
            "An agentic role is configured `via: sdk` and requests file-editing "
            "tools (Edit/Write/Bash), which require the Claude Agent SDK. "
            "Reinstall vvaharness to pull it in (pip install .), or "
            "set this role to `via: cli`."
        ) from e
    # `None` = unspecified (read-only default); `[]` = no localtools wanted. Same note as
    # backends.llm.sdk.agentic — the two must stay distinguishable.
    allowed = list(DEFAULT_READ_TOOLS) if allowed_tools is None else list(allowed_tools)
    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [agent-sdk] agentic -> {model}{tag_sfx} (tools={allowed}, "
          f"max_turns={max_turns}, cwd={cwd})", file=sys.stderr)

    opts = _build_options(
        model=model, system_prompt=system_prompt, allowed_tools=allowed,
        cwd=cwd, max_budget_usd=max_budget_usd, max_turns=max_turns,
    )
    return asyncio.run(_run(user_prompt=user_prompt, opts=opts))
