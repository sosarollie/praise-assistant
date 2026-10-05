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

"""Pin the DEFENCE-IN-DEPTH lower layers under the four MUTATING tools.

WHY THIS FILE EXISTS — and how it relates to its two siblings.

``tests/test_oneshot_least_privilege.py`` pins the OUTERMOST layer: on the
detection one-shot path (``OneShotOptions(..., tool_policy=ToolPolicy())``),
``PermitTools`` at the ``wrap_tool_call`` seam refuses EVERY forged tool_call —
``task``, the read natives, AND ``write_file`` / ``edit_file`` / ``delete`` /
``execute`` — with a synthetic ``status="error"`` ToolMessage, before the call
reaches the tool node. That is now the FIRST thing that stops a forged mutating
call, and it is fully covered there (parametrized over all four mutating tools,
parent path). This file does NOT re-prove that.

``tests/test_oneshot_task_executor_gate.py`` pins the read/task seam behaviour.

This file pins the layers that sit BENEATH ``PermitTools`` and would be the last
line of defence if that gate were ever narrowed or removed:

    With ``PermitTools`` DISABLED (so a forged mutating call reaches the tool
    node exactly as it did pre-fix), does a read-only detection scan still
    refuse to WRITE, DELETE, or EXECUTE — on the parent path AND inside the
    ``task``-dispatched ``general-purpose`` sub-agent?

Every test here therefore DISABLES the gate (via ``disable_gate=True`` on the
shared runner — the same lever ``tests/test_oneshot_least_privilege.py`` uses
for its red-proof) so the forged call reaches the executor, then asserts the
lower layer refuses it. This is deliberately testing the lower layers DIRECTLY
rather than incidentally: if someone later narrows ``PermitTools``, these are
the layers that still stop a disaster, and they must be proven on their own.
Consequence, stated honestly: because the gate is off here, this file does NOT
fail if ``PermitTools`` is reverted wholesale — that failure belongs to the
gate-enabled siblings.

EMPIRICAL VERDICT PINNED HERE (current behaviour on this branch — with the
executor gate disabled, both lower layers still refuse all four, on BOTH paths):

  PARENT one-shot agent:
    * ``write_file`` / ``edit_file`` / ``delete`` → REFUSED. The tool RUNS but
      returns a ``status="error"`` ToolMessage ("permission denied for write
      on <path>"), because ``_filesystem_permissions`` installs
      ``READ_ONLY_PERMISSIONS`` — a ``deny`` rule on the ``write`` operation for
      ``/**`` and the dot-path globs. deepagents maps ``delete`` to the
      ``write`` operation too (``_DEFAULT_FS_TOOL_OPS``), so it is covered.
      Nothing is created / modified / removed on disk.
    * ``execute`` → REFUSED by a DIFFERENT mechanism: the session backend is a
      ``FilesystemBackend`` (not a ``SandboxBackendProtocol``), so ``execute``
      returns "Execution not available. This agent's backend does not support
      command execution". The command never runs; no marker file appears.

  ``task``-dispatched ``general-purpose`` SUB-AGENT: IDENTICAL refusals for all
  four. The ``permissions`` and the ``FilesystemBackend`` are graph-wide (passed
  once to ``create_deep_agent`` and shared by the sub-agent), so the deny rules
  and the missing sandbox both still apply. Note the sub-agent is now the gated,
  redaction-wrapped shadow supplied by ``get_subagent_specs(..., agents={})`` —
  but that only masks READS; the write/delete/execute refusals proven here come
  from the graph-wide permissions and non-sandbox backend, independent of the
  gate and of read redaction. (The sub-agent READ-redaction dimension lives in
  ``tests/test_oneshot_least_privilege.py``; this file owns the sub-agent
  WRITE/DELETE/EXECUTE dimension, which that file does not cover.)

  ==> Even with the least-privilege gate removed, a forged mutating call cannot
      write, delete, or execute on the read-only detection path. If any
      expectation here flips from "refused" to "executed", a lower layer
      regressed (``READ_ONLY_PERMISSIONS`` dropped, or a sandbox/shell backend
      wired into the read-only session): treat it as a security regression on an
      attacker-influenceable path (S2 threat-model / S3 decompose feed untrusted
      repo content to the model), not a test to "fix", and update this module
      docstring's verdict in the same change.
"""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, ToolMessage

from fixtures.deepagents_scaffolding import (
    HEALTHY_TEXT,
    forged,
    oneshot_options,
    run_collecting_tool_messages,
)
from vvaharness.backends.harness.deepagents.models import SUBAGENT_DISPATCH_TOOL

# Shared scaffolding (fake model, empty-ToolPolicy() options, forged calls,
# graph driving, the gate-disable lever) lives in
# fixtures/deepagents_scaffolding.py. Every run in this file passes
# ``disable_gate=True``: here disabling ``PermitTools`` is the *precondition*
# for exercising the lower layers directly — the exact PRE-FIX executor shape,
# where the forged call reaches the tool node and is stopped (or not) purely by
# ``READ_ONLY_PERMISSIONS`` and the non-sandbox ``FilesystemBackend`` — not a
# red-proof toggle. The outer ``PermitTools`` refusal is proven in
# tests/test_oneshot_least_privilege.py.

# A credential-shaped value a mutating tool must never be able to plant on disk.
_PAYLOAD = "PWNED-BY-FORGED-TOOL-CALL"


def _parent_msgs(collected, name: str) -> list[ToolMessage]:
    return [m for ns, m in collected if m.name == name and ns == ()]


def _subagent_msgs(collected, name: str) -> list[ToolMessage]:
    return [m for ns, m in collected if m.name == name and ns != ()]


# The refusal substrings we pin. If deepagents rewords these, the assertions
# below will point at the new text — but the safe INTENT (write denied / no
# shell) must be re-confirmed before loosening them.
_WRITE_DENIED = "permission denied for write"
_NO_SANDBOX = "does not support command execution"


# ── PARENT PATH (gate disabled): the LOWER layer still refuses every mutation ─
#
# With PermitTools disabled by ``disable_gate=True``, the forged call reaches
# the tool node — the pre-fix executor shape — so what refuses it here is
# `READ_ONLY_PERMISSIONS` (writes) / the non-sandbox backend (execute), not
# the gate. These tests exist to prove that defence-in-depth layer holds on its
# own; the gate's own refusal is proven in tests/test_oneshot_least_privilege.py.


def test_forged_write_file_on_parent_is_denied_and_creates_nothing(tmp_path, monkeypatch):
    """``write_file`` reaches the node (gate off) but READ_ONLY_PERMISSIONS refuses it.

    Pins the SAFE lower-layer state. If this ever produces ``status="success"``
    or the file appears on disk, a read-only detection scan can now WRITE to an
    attacker-influenceable checkout even with the gate removed — a regression,
    not a test to update.
    """
    target = tmp_path / "pwned.txt"
    script = [
        forged("write_file", {"file_path": "/pwned.txt", "content": _PAYLOAD}, "c1"),
        AIMessage(content=HEALTHY_TEXT),
    ]
    collected = run_collecting_tool_messages(monkeypatch, tmp_path, script, disable_gate=True)

    msgs = _parent_msgs(collected, "write_file")
    assert msgs, "forged write_file produced no ToolMessage — executor path changed; re-derive."
    assert msgs[0].status == "error", (
        f"write_file was NOT refused on the parent path (status={msgs[0].status!r}, "
        f"content={str(msgs[0].content)[:160]!r}). READ_ONLY_PERMISSIONS no longer "
        f"denies writes on the one-shot path — this is a WRITE escape regression."
    )
    assert _WRITE_DENIED in str(msgs[0].content)
    assert not target.exists(), f"a read-only scan created {target} on disk"


def test_forged_edit_file_on_parent_is_denied_and_leaves_content(tmp_path, monkeypatch):
    """``edit_file`` is refused by the write deny rule; the target is unmodified."""
    target = tmp_path / "target.txt"
    target.write_text("ORIGINAL CONTENT")
    script = [
        forged(
            "edit_file",
            {"file_path": "/target.txt", "old_string": "ORIGINAL", "new_string": _PAYLOAD},
            "c1",
        ),
        AIMessage(content=HEALTHY_TEXT),
    ]
    collected = run_collecting_tool_messages(monkeypatch, tmp_path, script, disable_gate=True)

    msgs = _parent_msgs(collected, "edit_file")
    assert msgs, "forged edit_file produced no ToolMessage — executor path changed; re-derive."
    assert msgs[0].status == "error", (
        f"edit_file was NOT refused on the parent path (status={msgs[0].status!r}). "
        f"A read-only scan can now MODIFY files — WRITE escape regression."
    )
    assert _WRITE_DENIED in str(msgs[0].content)
    assert target.read_text() == "ORIGINAL CONTENT", "edit_file mutated the file on disk"


def test_forged_delete_on_parent_is_denied_and_file_survives(tmp_path, monkeypatch):
    """``delete`` maps to the ``write`` operation, so the deny rule refuses it."""
    victim = tmp_path / "victim.txt"
    victim.write_text("DO NOT DELETE")
    script = [
        forged("delete", {"file_path": "/victim.txt"}, "c1"),
        AIMessage(content=HEALTHY_TEXT),
    ]
    collected = run_collecting_tool_messages(monkeypatch, tmp_path, script, disable_gate=True)

    msgs = _parent_msgs(collected, "delete")
    assert msgs, "forged delete produced no ToolMessage — executor path changed; re-derive."
    assert msgs[0].status == "error", (
        f"delete was NOT refused on the parent path (status={msgs[0].status!r}). "
        f"deepagents may have stopped classifying delete as a write operation — "
        f"a read-only scan can now DELETE files. Regression."
    )
    assert _WRITE_DENIED in str(msgs[0].content)
    assert victim.exists(), "delete removed a real file from disk"


def test_forged_execute_on_parent_is_refused_no_command_runs(tmp_path, monkeypatch):
    """``execute`` is refused because the read-only backend is not a sandbox.

    PROOF that no command ran is a marker file the forged ``execute`` tries to
    ``touch`` inside ``tmp_path``: a fake success could not create it, so its
    ABSENCE is un-fakeable evidence the shell never executed. Nothing networked
    or destructive is attempted; the ``_deny_network`` conftest fixture is not
    challenged.
    """
    marker = tmp_path / "marker_should_not_exist.txt"
    script = [
        forged("execute", {"command": f"touch {marker}"}, "c1"),
        AIMessage(content=HEALTHY_TEXT),
    ]
    collected = run_collecting_tool_messages(monkeypatch, tmp_path, script, disable_gate=True)

    msgs = _parent_msgs(collected, "execute")
    assert msgs, "forged execute produced no ToolMessage — executor path changed; re-derive."
    assert msgs[0].status == "error", (
        f"execute was NOT refused on the parent path (status={msgs[0].status!r}). "
        f"A SandboxBackendProtocol backend may have been wired into the read-only "
        f"session — a read-only scan can now RUN SHELL COMMANDS. Regression."
    )
    assert _NO_SANDBOX in str(msgs[0].content)
    assert not marker.exists(), (
        f"execute actually ran a shell command and created {marker} — "
        f"command execution escaped on a read-only path."
    )


# ── SUB-AGENT PATH (gate disabled): the task sub-agent is STILL write/exec-gated ─
#
# With the gate disabled the forged ``task`` DISPATCHES (that is the precondition
# for exercising the sub-agent at all), so we can probe mutations inside it. The
# dispatched sub-agent is the gated, redaction-wrapped ``general-purpose`` shadow
# — but that only masks READS. These tests pin the WRITE/DELETE/EXECUTE
# dimension, which no sibling covers: the sub-agent inherits the graph-wide
# permissions and the non-sandbox backend, so forged write/edit/delete/execute
# inside it are refused exactly as on the parent, INDEPENDENT of the gate and of
# read redaction. A future change that gives the sub-agent its own looser
# permissions, or wires it a sandbox backend, would flip these — a write/delete/
# execute escape through the sub-agent path.


def _dispatch_then_forge(name: str, args: dict) -> list[AIMessage]:
    """Script: parent forges ``task``; the sub-agent forges *name*; both finish."""
    return [
        forged(
            SUBAGENT_DISPATCH_TOOL,
            {"description": f"perform {name}", "subagent_type": "general-purpose"},
            "t1",
        ),
        forged(name, args, "s1"),
        AIMessage(content="sub-agent done " + "z" * 160),
        AIMessage(content=HEALTHY_TEXT),
    ]


def _assert_task_dispatched(collected) -> None:
    task_msgs = [m for ns, m in collected if m.name == SUBAGENT_DISPATCH_TOOL]
    assert task_msgs and task_msgs[0].status == "success", (
        "the forged task did not dispatch a sub-agent (so the sub-agent-side "
        "mutation was never actually exercised). These tests run with the "
        "PermitTools gate DISABLED so task MUST dispatch here; if it does not, "
        "the dispatch mechanism changed — re-derive this harness."
    )


def test_subagent_forged_write_file_is_denied_and_creates_nothing(tmp_path, monkeypatch):
    """Inside the ungated ``task`` sub-agent, ``write_file`` is still write-denied."""
    target = tmp_path / "subpwned.txt"
    collected = run_collecting_tool_messages(
        monkeypatch, tmp_path, _dispatch_then_forge("write_file",
        {"file_path": "/subpwned.txt", "content": _PAYLOAD}), disable_gate=True,
    )
    _assert_task_dispatched(collected)

    msgs = _subagent_msgs(collected, "write_file")
    assert msgs, (
        "the dispatched sub-agent issued no observable write_file — if the "
        "sub-agent no longer runs forged tools, re-derive this expectation."
    )
    assert msgs[0].status == "error", (
        f"write_file SUCCEEDED inside the task sub-agent (status={msgs[0].status!r}). "
        f"The auto-added general-purpose sub-agent escaped the write deny rules — "
        f"a read-only scan can WRITE through a sub-agent. Serious regression."
    )
    assert _WRITE_DENIED in str(msgs[0].content)
    assert not target.exists(), f"sub-agent write_file created {target} on disk"


def test_subagent_forged_edit_file_is_denied_and_leaves_content(tmp_path, monkeypatch):
    """Inside the ``task`` sub-agent, ``edit_file`` is still write-denied."""
    target = tmp_path / "sub_target.txt"
    target.write_text("ORIGINAL CONTENT")
    collected = run_collecting_tool_messages(
        monkeypatch, tmp_path, _dispatch_then_forge("edit_file",
        {"file_path": "/sub_target.txt", "old_string": "ORIGINAL", "new_string": _PAYLOAD}),
        disable_gate=True,
    )
    _assert_task_dispatched(collected)

    msgs = _subagent_msgs(collected, "edit_file")
    assert msgs, "the dispatched sub-agent issued no observable edit_file — re-derive."
    assert msgs[0].status == "error", (
        f"edit_file SUCCEEDED inside the task sub-agent (status={msgs[0].status!r}) — "
        f"sub-agent write escape regression."
    )
    assert _WRITE_DENIED in str(msgs[0].content)
    assert target.read_text() == "ORIGINAL CONTENT", "sub-agent edit_file mutated the file"


def test_subagent_forged_delete_is_denied_and_file_survives(tmp_path, monkeypatch):
    """Inside the ``task`` sub-agent, ``delete`` is still refused by the write deny rule."""
    victim = tmp_path / "sub_victim.txt"
    victim.write_text("DO NOT DELETE")
    collected = run_collecting_tool_messages(
        monkeypatch, tmp_path, _dispatch_then_forge("delete", {"file_path": "/sub_victim.txt"}),
        disable_gate=True,
    )
    _assert_task_dispatched(collected)

    msgs = _subagent_msgs(collected, "delete")
    assert msgs, "the dispatched sub-agent issued no observable delete — re-derive."
    assert msgs[0].status == "error", (
        f"delete SUCCEEDED inside the task sub-agent (status={msgs[0].status!r}) — "
        f"sub-agent delete escape regression."
    )
    assert _WRITE_DENIED in str(msgs[0].content)
    assert victim.exists(), "sub-agent delete removed a real file from disk"


def test_subagent_forged_execute_is_refused_no_command_runs(tmp_path, monkeypatch):
    """Inside the ``task`` sub-agent, ``execute`` is still refused (no sandbox backend).

    Same un-fakeable marker proof as the parent test: the marker's absence shows
    the shell never ran. No networked/destructive command is attempted.
    """
    marker = tmp_path / "sub_marker_should_not_exist.txt"
    collected = run_collecting_tool_messages(
        monkeypatch, tmp_path, _dispatch_then_forge("execute", {"command": f"touch {marker}"}),
        disable_gate=True,
    )
    _assert_task_dispatched(collected)

    msgs = _subagent_msgs(collected, "execute")
    assert msgs, "the dispatched sub-agent issued no observable execute — re-derive."
    assert msgs[0].status == "error", (
        f"execute SUCCEEDED inside the task sub-agent (status={msgs[0].status!r}) — "
        f"a sandbox backend reached the sub-agent; shell execution escaped. Regression."
    )
    assert _NO_SANDBOX in str(msgs[0].content)
    assert not marker.exists(), (
        f"sub-agent execute ran a shell command and created {marker} — "
        f"command execution escaped through the task sub-agent."
    )


# ── guard: the SAFE verdict rests on the read-only session shape ──────────────


def test_oneshot_readonly_session_has_write_denies_and_no_sandbox(tmp_path, monkeypatch):
    """STRUCTURAL anchor for the two refusal mechanisms this file pins.

    The parent/sub-agent refusals above hold because the read-only one-shot
    session (a) installs a ``write``-operation ``deny`` rule (READ_ONLY_PERMISSIONS)
    and (b) uses a ``FilesystemBackend`` that is not a SandboxBackendProtocol.
    Pin both so a refactor that drops either is caught even if the behavioural
    tests were somehow skipped.
    """
    from deepagents.backends import FilesystemBackend

    from vvaharness.backends.harness.deepagents.options.filesystem import (
        _filesystem_permissions,
        _session_backend,
    )

    options = oneshot_options(tmp_path)
    perms = _filesystem_permissions(options)
    assert perms, "read-only one-shot session installs NO filesystem permissions — writes are open."
    assert any(
        "write" in rule.operations and rule.mode == "deny" for rule in perms
    ), f"no write-deny rule in the read-only permissions ({perms}) — writes are open."

    backend = _session_backend(options)
    assert isinstance(backend, FilesystemBackend), (
        f"read-only session backend is {type(backend).__name__}, not FilesystemBackend; "
        f"if it now implements SandboxBackendProtocol, execute may run — re-verify."
    )


if __name__ == "__main__":  # pragma: no cover - convenience only
    raise SystemExit(pytest.main([__file__, "-q"]))
