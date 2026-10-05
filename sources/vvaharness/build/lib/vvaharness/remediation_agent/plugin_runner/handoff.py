# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""S10's executor-side contract for dispatching work to the fixer subagent."""
from __future__ import annotations

import json
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any

from langchain.agents.middleware.types import AgentMiddleware, ToolCallRequest
from langchain_core.messages import ToolMessage
from langgraph.types import Command

from vvaharness.remediation_agent.models import FixerResult

_TASK_TOOL = "task"
_FIXER = "fixer"
_REQUIRED_SECTIONS = (
    "VULNERABILITY CONTEXT:",
    "TARGET FILES:",
    "EDIT INSTRUCTIONS:",
    "SUCCESS CRITERIA:",
)


class FixerDispatchGuard(AgentMiddleware):
    """Validate, enrich, and bound S10 fixer dispatches at execution time."""

    def __init__(self, *, finding_context: str, primary_file: str = "") -> None:
        super().__init__()
        self._finding_context = finding_context
        self._primary_file = primary_file
        self._attempts = 0
        self._retry_allowed = False
        self._terminal = False
        self._malformed_rejections = 0

    def _refusal(self, request: ToolCallRequest, detail: str) -> ToolMessage:
        print(f"WARN [remediation]: fixer dispatch refused — {detail}", file=sys.stderr)
        return ToolMessage(
            content=f"Fixer dispatch was not executed: {detail}",
            name=_TASK_TOOL,
            tool_call_id=request.tool_call.get("id") or "",
            status="error",
        )

    def _prepare(self, request: ToolCallRequest) -> ToolCallRequest | ToolMessage:
        call = request.tool_call
        if call.get("name") != _TASK_TOOL:
            return request
        args = call.get("args")
        if not isinstance(args, Mapping):
            self._terminal = True
            return self._refusal(request, "task arguments were not an object; return Not Fixed")
        if args.get("subagent_type") != _FIXER:
            self._terminal = True
            return self._refusal(request, "S10 permits only subagent_type='fixer'")
        if self._terminal:
            return self._refusal(
                request, "the fixer already returned a completed result; do not retry")
        if self._attempts and not self._retry_allowed:
            return self._refusal(
                request, "a retry is allowed only after an explicit transient tool error")

        description = args.get("description")
        problem = _invalid_spec(description, self._primary_file)
        if problem:
            # A malformed dispatch never reached the fixer, so it isn't a real
            # verdict about the finding — e.g. the orchestrator can legitimately
            # name a different file than the SAST-reported one when the actual
            # fix belongs elsewhere. Give it one bounded corrected re-dispatch
            # before treating it the same as a genuine terminal outcome.
            self._malformed_rejections += 1
            if self._malformed_rejections >= 2:
                self._terminal = True
                return self._refusal(
                    request,
                    f"incomplete edit specification ({problem}); "
                    "no further attempts permitted; return Not Fixed")
            return self._refusal(
                request,
                f"incomplete edit specification ({problem}); "
                "one corrected re-dispatch is permitted")
        assert isinstance(description, str)  # narrowed by _invalid_spec

        self._attempts += 1
        self._retry_allowed = False
        enriched = (
            f"{description.rstrip()}\n\n"
            "=== AUTHORITATIVE SAST FINDING CONTEXT ===\n"
            f"{self._finding_context.strip()}\n"
            "=== END AUTHORITATIVE CONTEXT ==="
        )
        amended_args = {**args, "description": enriched}
        print(
            f"  [remediation] dispatching complete fixer specification "
            f"(attempt {self._attempts}/2, {len(enriched)} chars)",
            file=sys.stderr,
        )
        return request.override(tool_call={**call, "args": amended_args})

    def _observe(self, result: ToolMessage | Command[Any]) -> None:
        message = _result_message(result)
        if message is None:
            self._terminal = True
            return
        if getattr(message, "status", "success") == "error":
            self._record_transient()
            return
        parsed = _fixer_result(message.content)
        if parsed is not None and parsed.status == "tool_error" and parsed.retryable:
            self._record_transient()
            return
        # Applied, already-applied, not-applied, malformed, and non-retryable
        # results are all completed outcomes. None may trigger another dispatch.
        self._terminal = True
        if parsed is None:
            print(
                "WARN [remediation]: fixer returned an invalid result; "
                "no retry permitted",
                file=sys.stderr,
            )
        elif parsed.status != "applied":
            print(
                f"WARN [remediation]: fixer completed with status "
                f"{parsed.status!r}; no retry permitted",
                file=sys.stderr,
            )

    def _record_transient(self) -> None:
        if self._attempts < 2:
            self._retry_allowed = True
            print(
                "WARN [remediation]: fixer reported a transient tool error — "
                "one retry is permitted",
                file=sys.stderr,
            )
        else:
            self._terminal = True
            print(
                "WARN [remediation]: fixer transient retry exhausted — "
                "return Not Fixed",
                file=sys.stderr,
            )

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        """Apply the handoff contract around synchronous task execution."""
        if request.tool_call.get("name") != _TASK_TOOL:
            return handler(request)
        prepared = self._prepare(request)
        if isinstance(prepared, ToolMessage):
            return prepared
        try:
            result = handler(prepared)
        except Exception as exc:  # one bounded retry is intentional
            self._record_transient()
            return self._refusal(
                request,
                f"transient fixer tool error ({type(exc).__name__}); "
                f"{'retry once' if self._retry_allowed else 'retry exhausted'}",
            )
        if request.tool_call.get("name") == _TASK_TOOL:
            self._observe(result)
        return result

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command[Any]]],
    ) -> ToolMessage | Command[Any]:
        """Apply the handoff contract around asynchronous task execution."""
        if request.tool_call.get("name") != _TASK_TOOL:
            return await handler(request)
        prepared = self._prepare(request)
        if isinstance(prepared, ToolMessage):
            return prepared
        try:
            result = await handler(prepared)
        except Exception as exc:  # one bounded retry is intentional
            self._record_transient()
            return self._refusal(
                request,
                f"transient fixer tool error ({type(exc).__name__}); "
                f"{'retry once' if self._retry_allowed else 'retry exhausted'}",
            )
        if request.tool_call.get("name") == _TASK_TOOL:
            self._observe(result)
        return result


def _invalid_spec(description: object, primary_file: str) -> str:
    """Return why a task description is incomplete, or an empty string."""
    if not isinstance(description, str) or not description.strip():
        return "missing description"
    folded = description.casefold()
    markers = [section.casefold() for section in _REQUIRED_SECTIONS]
    missing = [section for section, marker in zip(_REQUIRED_SECTIONS, markers)
               if marker not in folded]
    if missing:
        return f"missing section(s): {', '.join(missing)}"
    positions = [folded.index(marker) for marker in markers]
    if positions != sorted(positions):
        return "required sections are out of order"
    bodies: dict[str, str] = {}
    for index, (section, marker) in enumerate(zip(_REQUIRED_SECTIONS, markers)):
        start = positions[index] + len(marker)
        end = positions[index + 1] if index + 1 < len(positions) else len(description)
        bodies[section] = description[start:end].strip()
        if not bodies[section]:
            return f"section {section} is empty"
    target_files = bodies["TARGET FILES:"].casefold()
    if primary_file and primary_file.casefold() not in target_files:
        return f"TARGET FILES does not name {primary_file}"
    for section in ("VULNERABILITY CONTEXT:", "EDIT INSTRUCTIONS:",
                    "SUCCESS CRITERIA:"):
        if len(bodies[section]) < 12:
            return f"section {section} is not substantive"
    return ""


def _result_message(result: ToolMessage | Command[Any]) -> ToolMessage | None:
    if isinstance(result, ToolMessage):
        return result
    update = getattr(result, "update", None)
    messages = update.get("messages", []) if isinstance(update, Mapping) else []
    if isinstance(messages, Sequence):
        return next((m for m in reversed(messages) if isinstance(m, ToolMessage)), None)
    return None


def _fixer_result(content: object) -> FixerResult | None:
    if not isinstance(content, str):
        return None
    try:
        return FixerResult.model_validate(json.loads(content))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


__all__ = ["FixerDispatchGuard"]
