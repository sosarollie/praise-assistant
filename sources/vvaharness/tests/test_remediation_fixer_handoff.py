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

"""Regression coverage for the S10 orchestrator-to-fixer handoff."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from langchain.agents.middleware.types import ToolCallRequest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from fixtures.deepagents_scaffolding import patch_models
from vvaharness.remediation_agent import plugin_runner
from vvaharness.remediation_agent.plugin_runner.handoff import FixerDispatchGuard
from vvaharness.remediation_agent.prompts import FIXER_SYSTEM, ORCHESTRATOR_SYSTEM


def _spec() -> str:
    return """VULNERABILITY CONTEXT:
An attacker controls configFilePath and it reaches Files.readString.
TARGET FILES:
src/CaaSTools.java
EDIT INSTRUCTIONS:
Resolve and normalize the path, then reject it unless it remains below configRoot.
SUCCESS CRITERIA:
Both read sites reject absolute paths and traversal outside configRoot.
"""


def _request(description: str, call_id: str = "task-1") -> ToolCallRequest:
    return ToolCallRequest(
        tool_call={
            "name": "task",
            "args": {"description": description, "subagent_type": "fixer"},
            "id": call_id,
            "type": "tool_call",
        },
        tool=None,
        state={},
        runtime=None,  # type: ignore[arg-type]
    )


def _result(status: str, call_id: str = "task-1", *, retryable: bool = False) -> ToolMessage:
    return ToolMessage(
        json.dumps({
            "status": status,
            "files_changed": ["src/CaaSTools.java"] if status == "applied" else [],
            "summary": status,
            "error": "temporary write failure" if status == "tool_error" else "",
            "retryable": retryable,
        }),
        name="task",
        tool_call_id=call_id,
    )


def test_orchestrator_prompt_uses_real_task_schema_and_complete_template():
    assert 'subagent_type="fixer"' in ORCHESTRATOR_SYSTEM
    assert "`description`" in ORCHESTRATOR_SYSTEM
    assert 'task(agent="fixer"' not in ORCHESTRATOR_SYSTEM
    for heading in (
        "VULNERABILITY CONTEXT:", "TARGET FILES:",
        "EDIT INSTRUCTIONS:", "SUCCESS CRITERIA:",
    ):
        assert heading in ORCHESTRATOR_SYSTEM


def test_deepagents_prompts_leave_schema_enforcement_to_response_format():
    for prompt in (FIXER_SYSTEM, ORCHESTRATOR_SYSTEM):
        assert "structured" in prompt and "configured" in prompt
        assert "validates against this JSON Schema" not in prompt
        assert '"properties"' not in prompt


def test_guard_refuses_title_only_handoff_without_launching_fixer(capsys):
    guard = FixerDispatchGuard(
        finding_context="full finding", primary_file="src/CaaSTools.java")
    called = 0

    def handler(request):
        nonlocal called
        called += 1
        return _result("applied")

    result = guard.wrap_tool_call(_request("Fix the arbitrary file read"), handler)

    assert called == 0
    assert isinstance(result, ToolMessage) and result.status == "error"
    assert "incomplete edit specification" in str(result.content)
    assert "fixer dispatch refused" in capsys.readouterr().err


def _spec_naming(target_files: str) -> str:
    return f"""VULNERABILITY CONTEXT:
An attacker controls task_id and it reaches an unauthenticated write sink.
TARGET FILES:
{target_files}
EDIT INSTRUCTIONS:
Add an auth dependency gating the mutating endpoints.
SUCCESS CRITERIA:
Requests without a valid token are rejected before the write occurs.
"""


def test_malformed_dispatch_gets_one_corrected_retry():
    """A dispatch naming a different (architecturally correct) file than the
    SAST-reported primary file is malformed, not a verdict on the finding —
    the orchestrator must get one chance to re-dispatch with the primary file
    named too, rather than being locked out immediately."""
    guard = FixerDispatchGuard(
        finding_context="full finding", primary_file="app/schemas/events.py")
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return _result("applied", request.tool_call["id"])

    first = guard.wrap_tool_call(
        _request(_spec_naming("app/routers/events.py"), "task-1"), handler)
    assert isinstance(first, ToolMessage) and first.status == "error"
    assert "one corrected re-dispatch is permitted" in str(first.content)
    assert calls == 0

    second = guard.wrap_tool_call(
        _request(
            _spec_naming("app/routers/events.py\napp/schemas/events.py"),
            "task-2"),
        handler)
    assert isinstance(second, ToolMessage) and second.status == "success"
    assert calls == 1


def test_malformed_dispatch_retry_is_bounded():
    """A second, still-malformed dispatch must not retry indefinitely."""
    guard = FixerDispatchGuard(
        finding_context="full finding", primary_file="app/schemas/events.py")
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return _result("applied", request.tool_call["id"])

    bad_spec = _spec_naming("app/routers/events.py")
    first = guard.wrap_tool_call(_request(bad_spec, "task-1"), handler)
    second = guard.wrap_tool_call(_request(bad_spec, "task-2"), handler)

    assert first.status == "error"
    assert "one corrected re-dispatch is permitted" in str(first.content)
    assert second.status == "error"
    assert "no further attempts permitted" in str(second.content)
    assert calls == 0


def test_guard_forwards_full_spec_and_authoritative_finding_context():
    guard = FixerDispatchGuard(
        finding_context="ORIGINAL FINDING BODY", primary_file="src/CaaSTools.java")
    seen = {}

    def handler(request):
        seen.update(request.tool_call["args"])
        return _result("applied")

    guard.wrap_tool_call(_request(_spec()), handler)

    assert _spec().strip() in seen["description"]
    assert "ORIGINAL FINDING BODY" in seen["description"]
    assert "AUTHORITATIVE SAST FINDING CONTEXT" in seen["description"]


def test_guard_does_not_intercept_unrelated_parent_tools():
    guard = FixerDispatchGuard(
        finding_context="full finding", primary_file="src/CaaSTools.java")
    request = ToolCallRequest(
        tool_call={
            "name": "read_file",
            "args": {"file_path": "src/CaaSTools.java"},
            "id": "read-1",
            "type": "tool_call",
        },
        tool=None,
        state={},
        runtime=None,  # type: ignore[arg-type]
    )
    expected = ToolMessage("source", name="read_file", tool_call_id="read-1")

    assert guard.wrap_tool_call(request, lambda received: expected) is expected


def test_real_task_dispatch_delivers_complete_context_to_fixer(tmp_path, monkeypatch):
    """Exercise the native task tool: the fixer's sole user turn is complete."""
    requests: list[list[object]] = []
    script = [
        AIMessage(content="", tool_calls=[{
            "name": "task",
            "args": {"description": _spec(), "subagent_type": "fixer"},
            "id": "task-1",
            "type": "tool_call",
        }]),
        AIMessage(content="", tool_calls=[{
            "name": "FixerResult",
            "args": {
                "status": "applied",
                "files_changed": ["src/CaaSTools.java"],
                "summary": "bounded both reads",
            },
            "id": "fixer-result-1",
            "type": "tool_call",
        }]),
        AIMessage(content="", tool_calls=[{
            "name": "RemediationVerdict",
            "args": {"verdict": "Fixed", "summary": "fixed"},
            "id": "verdict-1",
            "type": "tool_call",
        }]),
    ]

    class CaptureModel(GenericFakeChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

        def _generate(self, messages, *args, **kwargs):
            requests.append(list(messages))
            return super()._generate(messages, *args, **kwargs)

    patch_models(monkeypatch, CaptureModel(messages=iter(script)))
    cfg = SimpleNamespace(
        step_remediate=SimpleNamespace(
            allowed_tools=None, max_turns=10, max_budget_usd=1.0),
        sdk=None,
        openai=None,
    )
    context = "ORIGINAL-FINDING-SENTINEL\nPRIMARY FILE: src/CaaSTools.java"

    plugin_runner._invoke_deepagents(
        context, model_id="claude-test", repo=tmp_path, mode="fix",
        sr=cfg.step_remediate, cfg=cfg, verbose=False,
        primary_file="src/CaaSTools.java")

    fixer_inputs = [
        message.content
        for request in requests
        for message in request
        if isinstance(message, HumanMessage)
        and "AUTHORITATIVE SAST FINDING CONTEXT" in str(message.content)
    ]
    assert len(fixer_inputs) == 1
    assert _spec().strip() in str(fixer_inputs[0])
    assert "ORIGINAL-FINDING-SENTINEL" in str(fixer_inputs[0])


def test_completed_noop_is_terminal_and_cannot_be_retried(capsys):
    guard = FixerDispatchGuard(
        finding_context="full finding", primary_file="src/CaaSTools.java")
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return _result("not_applied", request.tool_call["id"])

    first = guard.wrap_tool_call(_request(_spec()), handler)
    second = guard.wrap_tool_call(_request(_spec(), "task-2"), handler)

    assert isinstance(first, ToolMessage) and first.status == "success"
    assert isinstance(second, ToolMessage) and second.status == "error"
    assert calls == 1
    assert "completed result; do not retry" in str(second.content)
    assert "no retry permitted" in capsys.readouterr().err


def test_one_async_retry_is_allowed_only_for_transient_tool_error(capsys):
    guard = FixerDispatchGuard(
        finding_context="full finding", primary_file="src/CaaSTools.java")
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        return _result("tool_error", request.tool_call["id"], retryable=True)

    async def run():
        first = await guard.awrap_tool_call(_request(_spec()), handler)
        second = await guard.awrap_tool_call(_request(_spec(), "task-2"), handler)
        third = await guard.awrap_tool_call(_request(_spec(), "task-3"), handler)
        return first, second, third

    first, second, third = asyncio.run(run())

    assert isinstance(first, ToolMessage)
    assert isinstance(second, ToolMessage)
    assert isinstance(third, ToolMessage)
    assert calls == 2
    assert third.status == "error"
    assert "completed result; do not retry" in str(third.content)
    err = capsys.readouterr().err
    assert "one retry is permitted" in err
    assert "retry exhausted" in err
