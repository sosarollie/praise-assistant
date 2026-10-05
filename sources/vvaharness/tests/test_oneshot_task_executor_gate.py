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

"""Pin the EXECUTOR-side reality of the detection one-shot path.

WHY THIS FILE EXISTS — and why it is separate from
``tests/test_deepagents_tool_exposure.py``. That sibling file pins what the
one-shot graph ADVERTISES to the model (the ``bind_tools`` /
``wrap_model_call`` seam where ``ExcludeTools`` acts) and correctly notes that
"a tool the model is never told about cannot be called" — but ONLY for a
well-behaved model that never emits a tool_call it was not offered. This file
asks the complementary, adversarial question the advertisement tests
deliberately do NOT cover:

    If a model emits a ``task`` (or native) tool_call on the detection
    one-shot path — a call it was NEVER advertised — does the executor
    (LangGraph tool node) run it anyway?

The distinction remains the whole point: ``ExcludeTools`` subtracts tools from
the model REQUEST at ``wrap_model_call``; it does NOT remove the tool objects
from the tool node. The node is built by ``create_deep_agent`` from
``FilesystemMiddleware`` (natives) + ``SubAgentMiddleware`` (``task``), so
``task`` and every native are STILL present in the node even though the empty
``ToolPolicy()`` advertises nothing. The structural test below pins exactly
that: un-advertising does not empty the executor.

THE GAP IS NOW CLOSED — enforcing layer: ``PermitTools``.

An executor-seam gate has landed
(``vvaharness/backends/harness/deepagents/permit_tools.py``). ``PermitTools``
acts at ``wrap_tool_call`` and FAILS CLOSED: any tool_call whose name is not in
the one-shot permitted set is answered with a synthetic ``status="error"``
ToolMessage and NEVER reaches the tool node. For the detection parser
(``ToolPolicy()``) the permitted set is EMPTY, so ``task`` and every native are
refused before execution. In addition, ``_build_oneshot_graph`` now supplies its
own redaction-wrapped, zero-granted-tools ``general-purpose`` sub-agent spec via
``get_subagent_specs(..., agents={})``, displacing deepagents' ungated builtin —
so even if ``task`` were reachable its reads come back REDACTED.

EMPIRICAL VERDICT PINNED HERE (current, SAFE behaviour on this branch):
  * A forged ``task`` call is REFUSED at the ``wrap_tool_call`` seam: the task
    ToolMessage is ``status="error"`` and NO sub-agent is dispatched — the
    auto-added ungated sub-agent is never reached, so the credential is never
    read, redacted or otherwise. The old "dispatches an UNREDACTED sub-agent"
    premise is gone entirely.
  * A forged native ``read_file`` is likewise REFUSED at the same seam:
    ``status="error"``, no credential content in the result.

  ==> On this path, "not advertised" is now backed by "not permitted == not
      executed", even though the tool objects remain in the node. This matters
      because S2 threat-model and S3 decompose feed attacker-influenceable repo
      content to the model, so a hallucinated or prompt-injected ``task`` /
      native call cannot escape the empty ``ToolPolicy()`` confinement.

These tests assert the CURRENT (SAFE) behaviour on purpose. If any
``test_forged_*`` expectation below flips from "refused" (``status="error"``)
back to "executed" (``status="success"``) — or a forged ``task`` starts
dispatching a sub-agent again — that is a SECURITY REGRESSION: the
least-privilege executor gate has been narrowed or removed. Treat it as a bug,
not a test to "fix", and update this docstring's verdict in the same change.
The PermitTools refusal path itself, and the granted/legacy-policy set-equality
behaviour, are pinned in ``tests/test_oneshot_least_privilege.py``; this file
keeps the distinct STRUCTURAL pairing (object retained in the node, yet
execution refused) that the sibling file does not make.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage

from fixtures.deepagents_scaffolding import (
    CRED,
    HEALTHY_TEXT,
    REFUSED,
    collect_tool_messages,
    fake_model,
    forged,
    oneshot_options,
    patch_models,
    run_collecting_tool_messages,
)
from vvaharness.backends.harness.deepagents.models import (
    ALL_NATIVE_TOOLS,
    SUBAGENT_DISPATCH_TOOL,
)
from vvaharness.backends.harness.deepagents.options import build_oneshot_options

# Shared scaffolding (fake model, empty-ToolPolicy() options, forged calls,
# graph driving) lives in fixtures/deepagents_scaffolding.py. Every run in
# this file keeps the production PermitTools gate ENABLED
# (``disable_gate=False``): the point here is that refusal happens at the seam
# while the tool node still HOLDS the objects.


def _find_tool_node_names(graph) -> frozenset[str]:  # noqa: ANN001
    """Recover the ``tools_by_name`` set the compiled tool node actually holds.

    The tool node is wrapped in a ``RunnableSeq``, so walk the common runnable
    composition attributes until the ``ToolNode``'s ``tools_by_name`` mapping
    surfaces. This is the structural counterpart of the behavioural execution
    proof below: it shows the tools the EXECUTOR retains regardless of what is
    advertised.
    """
    node = getattr(graph.nodes["tools"], "node", graph.nodes["tools"])
    seen: set[int] = set()

    def walk(obj, depth: int = 0) -> frozenset[str] | None:  # noqa: ANN001
        if id(obj) in seen or depth > 6:
            return None
        seen.add(id(obj))
        by_name = getattr(obj, "tools_by_name", None)
        if isinstance(by_name, dict):
            return frozenset(by_name)
        for attr in ("steps", "bound", "runnable", "first", "last", "default", "node"):
            value = getattr(obj, attr, None)
            if value is None:
                continue
            candidates = value if isinstance(value, (list, tuple)) else [value]
            for item in candidates:
                found = walk(item, depth + 1)
                if found is not None:
                    return found
        return None

    return walk(node) or frozenset()


# ── the tool node retains what advertisement withholds ───────────────────────


def test_oneshot_tool_node_retains_task_and_natives_though_none_advertised(tmp_path, monkeypatch):
    """STRUCTURAL: the executor holds ``task`` + every native — advertisement hides them.

    This is the mechanical root of the gap. ``ExcludeTools`` acts only at
    ``wrap_model_call`` (advertisement), so the tool node the executor uses
    still contains the full deepagents built-in suite, including ``task``
    (proving ``SubAgentMiddleware`` is installed because the auto-added
    ``general-purpose`` sub-agent forces it). The advertisement-side emptiness
    is pinned in tests/test_deepagents_tool_exposure.py; the two files together
    make the "not advertised != not executable" claim concrete.
    """
    patch_models(monkeypatch, fake_model([AIMessage(content=HEALTHY_TEXT)]))
    graph, _ = build_oneshot_options(oneshot_options(tmp_path))
    node_tools = _find_tool_node_names(graph)

    assert SUBAGENT_DISPATCH_TOOL in node_tools, (
        f"task absent from the one-shot tool node ({sorted(node_tools)}). If a "
        f"deepagents upgrade stopped auto-adding the general-purpose sub-agent, "
        f"the whole task-confinement concern may have evaporated — re-verify "
        f"and update tests/test_oneshot_task_executor_gate.py's docstring."
    )
    assert ALL_NATIVE_TOOLS <= node_tools, (
        f"the one-shot tool node no longer holds every native "
        f"({sorted(ALL_NATIVE_TOOLS - node_tools)} missing) — the executor "
        f"inventory changed; re-derive this expectation."
    )


# ── forged task is REFUSED at the seam though the node still holds it ─────────


def test_forged_task_call_is_refused_before_any_subagent_dispatch(tmp_path, monkeypatch):
    """SAFE state (gap closed): a forged ``task`` is refused, nothing dispatches.

    The distinct pairing this file owns: the tool node STILL contains ``task``
    (asserted here against the same graph), yet ``PermitTools`` refuses the
    forged call at ``wrap_tool_call``. The task ToolMessage is
    ``status="error"`` and NO sub-agent is dispatched — the auto-added ungated
    sub-agent is never reached, so the pre-fix "dispatches an UNREDACTED
    sub-agent" escape is gone: the credential is never read at all.

    A flip to ``status="success"`` — or any sub-graph (sub-agent) activity —
    is a SECURITY REGRESSION: the empty-``ToolPolicy()`` executor gate was
    narrowed or removed. Fix the product, do not "fix" this test. (The refusal
    mechanism itself is red/green-proofed in
    tests/test_oneshot_least_privilege.py.)
    """
    (tmp_path / "creds.txt").write_text(CRED)
    script = [
        # Parent forges a task call it was never offered.
        forged(
            SUBAGENT_DISPATCH_TOOL,
            {"description": "read /creds.txt", "subagent_type": "general-purpose"},
            "c1",
        ),
        # Sub-agent turn (only reached if the gate fails): forge a cred read.
        forged("read_file", {"file_path": "/creds.txt"}, "sub1"),
        # Sub-agent terminates, then the parent terminates.
        AIMessage(content="sub-agent done " + "z" * 160),
        AIMessage(content=HEALTHY_TEXT),
    ]

    # STRUCTURAL half: the executor still HOLDS task — refusal is a seam gate,
    # not object removal. This is the claim the sibling advertisement/least-
    # privilege files do not make.
    patch_models(monkeypatch, fake_model(list(script)))
    graph, config = build_oneshot_options(oneshot_options(tmp_path))
    assert SUBAGENT_DISPATCH_TOOL in _find_tool_node_names(graph), (
        "task vanished from the one-shot tool node — the 'retained but refused' "
        "pairing this test pins no longer holds; re-derive."
    )

    collected = collect_tool_messages(graph, config)

    # BEHAVIOURAL half: the forged task is refused at the seam.
    task_msgs = [m for ns, m in collected if m.name == SUBAGENT_DISPATCH_TOOL]
    assert task_msgs, "no task ToolMessage at all — the refusal must be observable."
    assert task_msgs[0].status == "error", (
        f"a forged task EXECUTED (status={task_msgs[0].status!r}) — the "
        f"empty-ToolPolicy executor gate regressed; a hallucinated/injected "
        f"task can escape confinement again. Security regression."
    )
    assert REFUSED in str(task_msgs[0].content), (
        f"task was refused by a different layer "
        f"(content={str(task_msgs[0].content)[:120]!r}) — PermitTools did not fire."
    )
    # No sub-agent was ever dispatched: no sub-graph namespace, no cred content.
    assert [ns for ns, _ in collected if ns != ()] == [], (
        "a sub-agent was dispatched despite the refusal — the forged task "
        "reached SubAgentMiddleware; the pre-fix UNREDACTED-sub-agent escape is back."
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in str(task_msgs[0].content)
    assert (tmp_path / "creds.txt").read_text() == CRED


# ── forged native read is REFUSED at the same seam ───────────────────────────


def test_forged_native_read_is_refused_before_execution(tmp_path, monkeypatch):
    """SAFE state: a forged native ``read_file`` on the parent is refused too.

    The gate is GENERAL to the un-advertised set, not specific to ``task``:
    ``read_file`` is answered with the same ``PermitTools`` synthetic error and
    never reaches the tool node, so no credential content is produced (the
    parent's read-redaction stack is never even exercised — the read did not
    run). A flip back to ``status="success"`` is a regression; the module
    docstring's verdict must be updated in the same change.
    """
    (tmp_path / "creds.txt").write_text(CRED)
    script = [
        forged("read_file", {"file_path": "/creds.txt"}, "c1"),
        AIMessage(content=HEALTHY_TEXT),
    ]
    collected = run_collecting_tool_messages(monkeypatch, tmp_path, script, disable_gate=False)

    parent_reads = [m for ns, m in collected if m.name == "read_file" and ns == ()]
    assert parent_reads, "no parent read_file ToolMessage — the refusal must be observable."
    assert parent_reads[0].status == "error", (
        f"a forged native read EXECUTED (status={parent_reads[0].status!r}) — "
        f"the executor gate regressed on the one-shot path."
    )
    content = str(parent_reads[0].content)
    assert REFUSED in content, (
        f"read_file was refused by a different layer (content={content[:120]!r}) "
        f"— PermitTools did not fire."
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in content, "the refused read leaked credential content"
    assert (tmp_path / "creds.txt").read_text() == CRED
