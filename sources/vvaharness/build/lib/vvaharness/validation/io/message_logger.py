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

"""Drain a Harness streaming session to session.jsonl and return exit status."""

from __future__ import annotations

import dataclasses
import json
import logging
import sys
from collections.abc import AsyncIterator, Callable, Mapping
from pathlib import Path
from typing import cast

from vvaharness.backends.harness import (
    HarnessAssistantText,
    HarnessMessage,
    HarnessResult,
    HarnessSessionInit,
    HarnessToolResult,
    HarnessToolUse,
)
from vvaharness.validation.constants.artifacts import SESSION_LOG_FILENAME

log = logging.getLogger(__name__)


def _serialize(message: HarnessMessage) -> Mapping[str, object]:
    return dataclasses.asdict(message)


def _agent_desc(message: HarnessToolUse) -> str:
    """Extract the agent description from an Agent tool-use input."""
    if not isinstance(message.input, dict):
        return "sub-agent"
    raw = message.input.get("description")
    return raw if isinstance(raw, str) else "sub-agent"


def _log_key_event(message: HarnessMessage) -> None:
    if isinstance(message, HarnessToolUse):
        log.info("Tool call: %s", message.name)
        if message.name == "Agent":
            log.info("Agent spawned: %s", _agent_desc(message))
    elif isinstance(message, HarnessSessionInit):
        log.info("Session initialized")
    elif isinstance(message, HarnessResult):
        log.info("Session completed: %s", message.subtype)


def _format_tool_use(message: HarnessToolUse) -> str:
    """Render a one-line live preview for a tool-use message."""
    tid = (message.tool_id or "")[-8:]
    if message.name == "Agent":
        return f"  ++ agent  {_agent_desc(message)}  [{tid}]"
    return f"  >> {message.name}  [{tid}]"


def _format_assistant_text(message: HarnessAssistantText) -> list[str]:
    """Render a one-line live preview for assistant text, empty when blank."""
    text = message.text.strip()
    return [f"     {text.replace(chr(10), ' ')}"] if text else []


def _format_terminal(message: HarnessMessage) -> list[str]:
    """Render tool-result and session-complete previews; empty for other types."""
    if isinstance(message, HarnessToolResult):
        return [f"  << result  {'ERROR' if message.is_error else 'ok'}"]
    if isinstance(message, HarnessResult):
        return [f"  == session complete ({message.subtype})"]
    return []


def _fmt_session_init(message: HarnessMessage) -> list[str]:
    m = cast(HarnessSessionInit, message)
    sid = m.session_id[:12] if m.session_id else ""
    return [f"  .. init  session={sid}"]


def _fmt_tool_use(message: HarnessMessage) -> list[str]:
    return [_format_tool_use(cast(HarnessToolUse, message))]


def _fmt_assistant_text(message: HarnessMessage) -> list[str]:
    return _format_assistant_text(cast(HarnessAssistantText, message))


_LIVE_FORMATTERS: dict[type, Callable[[HarnessMessage], list[str]]] = {
    HarnessSessionInit: _fmt_session_init,
    HarnessToolUse: _fmt_tool_use,
    HarnessAssistantText: _fmt_assistant_text,
}


def _format_live(message: HarnessMessage) -> list[str]:
    return _LIVE_FORMATTERS.get(type(message), _format_terminal)(message)


def _print_live(message: HarnessMessage) -> None:
    for line in _format_live(message):
        print(line, file=sys.stderr, flush=True)


def _process_message(
    message: HarnessMessage, observed_sid: str, live: bool,
) -> tuple[int | None, str]:
    """Process one streamed message; return (exit_code_or_None, updated_session_id)."""
    _log_key_event(message)
    if live:
        _print_live(message)
    if isinstance(message, HarnessSessionInit) and message.session_id:
        observed_sid = message.session_id
    if isinstance(message, HarnessResult):
        observed_sid = message.session_id or observed_sid
        if message.subtype == "error_max_budget_usd":
            log.warning("Validation session halted: max_budget_usd exceeded")
        return 0 if message.subtype == "success" else 1, observed_sid
    return None, observed_sid


async def stream_and_log(
    messages: AsyncIterator[HarnessMessage],
    log_dir: Path,
    session_id: str,
    live: bool,
) -> tuple[int, str]:
    """Drain messages to session.jsonl; return (exit_code, session_id)."""
    log_dir.mkdir(parents=True, exist_ok=True)
    session_log = log_dir / SESSION_LOG_FILENAME
    exit_code = 1
    observed_sid = session_id
    with session_log.open("w") as f:
        async for message in messages:
            f.write(json.dumps(_serialize(message), default=str) + "\n")
            f.flush()
            new_code, observed_sid = _process_message(message, observed_sid, live)
            if new_code is not None:
                exit_code = new_code
    return exit_code, observed_sid
