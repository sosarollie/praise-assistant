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

"""Shared scaffolding for the DeepAgents tool-gate / tool-exposure test files.

Extracted verbatim from the near-identical private helpers that grew in
parallel across:

    tests/test_oneshot_task_executor_gate.py
    tests/test_oneshot_mutating_tool_gate.py
    tests/test_oneshot_least_privilege.py
    tests/test_agentic_detection_permit_gate.py
    tests/test_deepagents_tool_exposure.py

This module holds SCAFFOLDING ONLY — fake models, option builders, forged
tool_call construction, graph driving/collection, and the gate-disable lever.
It makes NO assertions: what each file asserts (and why) stays in that file,
because those docstrings are the record of separate security findings.

The one deliberate design point: helpers that can serve both gate-enabled and
gate-disabled callers take that as an EXPLICIT, REQUIRED parameter
(``run_collecting_tool_messages(..., disable_gate=...)``) so each test's
intent is readable at its own call site. In particular,
tests/test_oneshot_mutating_tool_gate.py runs with the ``PermitTools`` gate
deliberately DISABLED to exercise the lower defence-in-depth layers on their
own — a default here must never quietly flip that.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

import vvaharness.backends.harness.deepagents.options as _da_options
import vvaharness.backends.harness.deepagents.options.graph_builder as _da_graph_builder
import vvaharness.backends.harness.deepagents.options.oneshot as _da_oneshot
import vvaharness.backends.harness.deepagents.options.subagents as _da_subagents
from vvaharness.backends.harness import OneShotOptions, ToolPolicy
from vvaharness.backends.harness.deepagents.options import build_oneshot_options

# Long enough to clear the VVAH-E003 degenerate-response floor if it were graded.
HEALTHY_TEXT = "finding: " + "x" * 160

# A credential-shaped secret that must never surface unredacted in any result.
CRED = "AKIAIOSFODNN7EXAMPLE aws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# The synthetic-refusal marker PermitTools emits at the ``wrap_tool_call`` seam.
# Distinct from the READ_ONLY_PERMISSIONS text ("permission denied for write")
# and the no-sandbox text, so the layer that refused is identifiable.
REFUSED = "is not permitted in this session"

#: Every module whose ``build_model_cached`` a one-shot / streaming graph build
#: may consult to resolve a chat model. Patch all three to substitute a fake.
MODEL_RESOLUTION_MODULES = (_da_graph_builder, _da_subagents, _da_options)


def fake_model(script: list[AIMessage]) -> GenericFakeChatModel:
    """A fake chat model that replays *script* one AIMessage per generation.

    ``bind_tools`` is a no-op returning self: callers of this helper do not
    care what is advertised (the recording models in the exposure/permit-gate
    files own that seam) — they force tool_calls the model was never offered
    and observe what the EXECUTOR does with them.
    """

    class _Model(GenericFakeChatModel):
        def bind_tools(self, tools, **_kwargs):  # noqa: ANN001, ANN003
            return self

    return _Model(messages=iter(script))


def patch_models(monkeypatch, model) -> None:
    """Substitute *model* wherever the graph builders resolve a chat model."""
    for module in MODEL_RESOLUTION_MODULES:
        monkeypatch.setattr(module, "build_model_cached", lambda *a, **k: model)


def disable_permit_tools_gate(monkeypatch) -> None:
    """Make the one-shot builder install NO ``PermitTools`` gate.

    ``_create_agent(permitted_tool_calls=None)`` skips the executor-seam gate,
    which is the exact PRE-FIX executor shape: a forged tool_call the model was
    never advertised reaches the tool node and is stopped (or not) purely by
    the LOWER layers — ``READ_ONLY_PERMISSIONS`` and the non-sandbox
    ``FilesystemBackend``. Two files pull this lever for different reasons:
    tests/test_oneshot_least_privilege.py as a RED-PROOF toggle (prove the gate
    is what refuses, then re-enable), and
    tests/test_oneshot_mutating_tool_gate.py as the PRECONDITION for exercising
    the lower layers directly. See each file's docstrings for that intent.
    """
    monkeypatch.setattr(_da_oneshot, "_oneshot_permitted_tools", lambda *_a, **_k: None)


def oneshot_options(cwd: Path, policy: ToolPolicy | None = ToolPolicy()) -> OneShotOptions:
    """OneShotOptions built exactly as ``backends/llm/deepagents.py::prompt`` does.

    The production detection one-shot path constructs
    ``OneShotOptions(..., tool_policy=ToolPolicy())`` — an explicit EMPTY
    policy, which is what makes ``_oneshot_excluded_tools`` subtract every
    native AND ``task`` from what is advertised, and (``allow_writes``
    defaulting False) what makes ``_filesystem_permissions`` return the
    ``READ_ONLY_PERMISSIONS`` deny rules over a read-only
    ``FilesystemBackend``. Tests may override *policy* to probe the granted
    and legacy (``None``) branches.
    """
    return OneShotOptions(
        model="claude-test",
        model_provider=None,
        cwd=cwd,
        env={},
        system_prompt=None,
        tool_policy=policy,
    )


def forged(name: str, args: dict, call_id: str) -> AIMessage:
    """An assistant turn emitting a tool_call the model was never advertised."""
    return AIMessage(
        content="",
        tool_calls=[{"name": name, "args": args, "id": call_id, "type": "tool_call"}],
    )


def collect_tool_messages(graph, config) -> list[tuple[tuple[str, ...], ToolMessage]]:  # noqa: ANN001
    """Drive a compiled one-shot graph; collect every ToolMessage, tagged by namespace.

    ``subgraphs=True`` surfaces sub-agent (``task``) steps under their own
    namespace, so a sub-agent's internal tool calls are observable here — the
    empty top-level namespace ``()`` is the parent agent, a non-empty
    namespace is the ``task``-dispatched sub-agent.
    """
    collected: list[tuple[tuple[str, ...], ToolMessage]] = []

    async def drive() -> None:
        async for namespace, payload in graph.astream(
            {"messages": [HumanMessage(content="parse this")]},
            config=config,
            stream_mode="updates",
            subgraphs=True,
        ):
            for update in (payload or {}).values():
                messages = update.get("messages", []) if isinstance(update, dict) else []
                for message in messages:
                    if isinstance(message, ToolMessage):
                        collected.append((namespace, message))

    asyncio.run(drive())
    return collected


def run_collecting_tool_messages(
    monkeypatch,
    cwd: Path,
    script: list[AIMessage],
    *,
    policy: ToolPolicy | None = ToolPolicy(),
    disable_gate: bool,
) -> list[tuple[tuple[str, ...], ToolMessage]]:
    """Build and drive the real one-shot graph; return the tagged ToolMessages.

    *disable_gate* is REQUIRED so the gate-enabled/-disabled intent is stated
    at every call site. ``disable_gate=True`` removes the ``PermitTools``
    executor-seam gate (see :func:`disable_permit_tools_gate`) so forged calls
    reach the tool node and only the lower layers can refuse them;
    ``disable_gate=False`` keeps the production shape.
    """
    if disable_gate:
        disable_permit_tools_gate(monkeypatch)
    patch_models(monkeypatch, fake_model(script))
    graph, config = build_oneshot_options(oneshot_options(cwd, policy))
    return collect_tool_messages(graph, config)
