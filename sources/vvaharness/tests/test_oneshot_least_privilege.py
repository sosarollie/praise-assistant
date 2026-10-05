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

"""Least-privilege enforcement on the detection one-shot path.

Complements the executor-reality probes in
``tests/test_oneshot_task_executor_gate.py`` (which pinned the PRE-FIX gap:
forged tool_calls execute, and a ``task``-dispatched sub-agent read returns
UNREDACTED) and ``tests/test_oneshot_mutating_tool_gate.py`` (which pinned the
pre-existing refusals of the four mutating tools). This file pins the FIX,
which has two independent layers:

1. ``PermitTools`` (``vvaharness/backends/harness/deepagents/permit_tools.py``)
   at the ``wrap_tool_call`` seam: on the one-shot path, any tool_call whose
   name is outside ``_oneshot_permitted_tools`` is REFUSED with a synthetic
   ``status="error"`` ToolMessage — it never reaches the tool node. For the
   production detection parser (``ToolPolicy()``) that permitted set is EMPTY,
   so every forged call — ``task`` and all natives — is refused. Fail closed.

2. A gated ``general-purpose`` sub-agent spec supplied via
   ``get_subagent_specs(..., agents={})``: deepagents only auto-adds its
   UNGATED, UNREDACTED builtin when no spec of that name is supplied, so even
   if layer 1 were absent (red-proofed below by disabling it), a dispatched
   sub-agent's reads come back REDACTED through ``read_only_middleware``.

The streaming builder (``options/streaming.py``) — used by S10 fix mode and
S11 validation — is untouched: ``_create_agent`` installs ``PermitTools`` only
when ``permitted_tool_calls`` is not None, and no streaming caller passes it.
"""

from __future__ import annotations

import asyncio

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from fixtures.deepagents_scaffolding import (
    CRED,
    HEALTHY_TEXT,
    MODEL_RESOLUTION_MODULES,
    REFUSED,
    disable_permit_tools_gate,
    fake_model,
    forged,
    oneshot_options,
    run_collecting_tool_messages,
)
from vvaharness.backends.harness import ToolPolicy
from vvaharness.backends.harness.deepagents.models import SUBAGENT_DISPATCH_TOOL
from vvaharness.backends.harness.deepagents.options import build_oneshot_options
from vvaharness.backends.harness.deepagents.options.subagents import get_subagent_specs
from vvaharness.backends.harness.deepagents.permit_tools import PermitTools
from vvaharness.backends.harness.deepagents.redaction import RedactToolResults
from vvaharness.backends.harness.models import StreamingOptions

# Shared scaffolding (fake model, option builder, forged calls, graph driving,
# the gate-disable lever) lives in fixtures/deepagents_scaffolding.py. In THIS
# file ``disable_permit_tools_gate`` / ``disable_gate=True`` is a RED-PROOF
# lever: ``_create_agent(permitted_tool_calls=None)`` skips the gate — the
# exact pre-fix executor shape — used below to prove the gate is what refuses
# (red/green) and to exercise the sub-agent redaction layer on its own.


# ── layer 1: the executor-seam gate refuses every forged call (fail closed) ───


@pytest.mark.parametrize(
    ("name", "args"),
    [
        (SUBAGENT_DISPATCH_TOOL, {"description": "spy", "subagent_type": "general-purpose"}),
        ("read_file", {"file_path": "/creds.txt"}),
        ("grep", {"pattern": "AKIA", "path": "/"}),
        ("glob", {"pattern": "**/*.txt"}),
        ("ls", {"path": "/"}),
        ("write_file", {"file_path": "/gate_pwned.txt", "content": "x"}),
        ("edit_file", {"file_path": "/creds.txt", "old_string": "AKIA", "new_string": "x"}),
        ("delete", {"file_path": "/creds.txt"}),
        ("execute", {"command": "touch /tmp/should_not_exist_gate.txt"}),
    ],
)
def test_forged_call_is_refused_on_detection_oneshot(tmp_path, monkeypatch, name, args):
    """Every forged tool_call on the empty-policy one-shot path is REFUSED.

    The permitted set for the detection parser is EMPTY, so ``task``, the read
    natives, and the mutating natives are all answered with PermitTools'
    synthetic error ToolMessage — none reaches the tool node.
    """
    (tmp_path / "creds.txt").write_text(CRED)
    marker = tmp_path / "gate_marker.txt"
    if name == "execute":
        args = {"command": f"touch {marker}"}
    script = [forged(name, args, "c1"), AIMessage(content=HEALTHY_TEXT)]
    collected = run_collecting_tool_messages(monkeypatch, tmp_path, script, disable_gate=False)

    msgs = [m for ns, m in collected if m.name == name and ns == ()]
    assert msgs, f"forged {name} produced no ToolMessage at all — refusal must be observable"
    assert msgs[0].status == "error", (
        f"forged {name} was EXECUTED (status={msgs[0].status!r}) — the "
        f"least-privilege gate regressed on the detection one-shot path."
    )
    assert REFUSED in str(msgs[0].content), (
        f"forged {name} was refused by a different layer "
        f"(content={str(msgs[0].content)[:120]!r}); the PermitTools gate did not fire."
    )
    # The refusal is pre-execution: no credential content, no sub-agent
    # activity, no disk change, no marker.
    assert "AKIAIOSFODNN7EXAMPLE" not in str(msgs[0].content)
    assert [ns for ns, _ in collected if ns != ()] == [], (
        f"forged {name} produced sub-graph activity — something was dispatched."
    )
    assert (tmp_path / "creds.txt").read_text() == CRED, "the target file changed on disk"
    assert not (tmp_path / "gate_pwned.txt").exists()
    assert not marker.exists()


def test_granted_read_policy_permits_exactly_the_mapped_natives(tmp_path, monkeypatch):
    """A one-shot policy granting ``Read`` permits ``read_file`` (redacted) only.

    Least privilege is a set equality, not just an empty set: what the policy
    maps to executes; what it does not — here ``grep`` and ``write_file`` —
    is refused by the gate.
    """
    (tmp_path / "creds.txt").write_text(CRED)
    policy = ToolPolicy(allowed_tools=("Read",))
    script = [
        forged("read_file", {"file_path": "/creds.txt"}, "c1"),
        forged("grep", {"pattern": "AKIA", "path": "/"}, "c2"),
        forged("write_file", {"file_path": "/pwned.txt", "content": "x"}, "c3"),
        AIMessage(content=HEALTHY_TEXT),
    ]
    collected = run_collecting_tool_messages(
        monkeypatch, tmp_path, script, policy=policy, disable_gate=False
    )
    by_name = {m.name: m for ns, m in collected if ns == ()}

    assert by_name["read_file"].status == "success"
    read_content = str(by_name["read_file"].content)
    assert "AKIAIOSFODNN7EXAMPLE" not in read_content and "REDACTED" in read_content, (
        "a granted read on the one-shot path lost its redaction"
    )
    assert by_name["grep"].status == "error" and REFUSED in str(by_name["grep"].content)
    assert by_name["write_file"].status == "error"
    assert REFUSED in str(by_name["write_file"].content)
    assert not (tmp_path / "pwned.txt").exists()


def test_legacy_none_policy_keeps_natives_but_still_refuses_task(tmp_path, monkeypatch):
    """``tool_policy=None`` (the preflight probe shape) keeps natives callable.

    The legacy contract is preserved — natives execute (reads redacted) — but
    ``task`` is refused at the executor too, matching its unconditional
    advertisement-level exclusion.
    """
    (tmp_path / "creds.txt").write_text(CRED)
    script = [
        forged("read_file", {"file_path": "/creds.txt"}, "c1"),
        forged(
            SUBAGENT_DISPATCH_TOOL,
            {"description": "spy", "subagent_type": "general-purpose"},
            "c2",
        ),
        AIMessage(content=HEALTHY_TEXT),
    ]
    collected = run_collecting_tool_messages(
        monkeypatch, tmp_path, script, policy=None, disable_gate=False
    )
    by_name = {m.name: m for ns, m in collected if ns == ()}

    assert by_name["read_file"].status == "success"
    assert "REDACTED" in str(by_name["read_file"].content)
    task_msg = by_name[SUBAGENT_DISPATCH_TOOL]
    assert task_msg.status == "error" and REFUSED in str(task_msg.content)


# ── red-proof: disabling the gate reopens execution, re-enabling closes it ────


def test_red_proof_without_gate_forged_read_executes_with_gate_it_is_refused(
    tmp_path, monkeypatch
):
    """The gate is the refusing layer: off → forged read executes; on → refused.

    The green half re-runs WITHOUT the disabling monkeypatch in the same test,
    so the pair cannot silently drift apart.
    """
    (tmp_path / "creds.txt").write_text(CRED)
    script = [
        forged("read_file", {"file_path": "/creds.txt"}, "c1"),
        AIMessage(content=HEALTHY_TEXT),
    ]

    # RED: gate disabled — the pre-fix executor reality returns.
    with pytest.MonkeyPatch.context() as mp:
        for module in MODEL_RESOLUTION_MODULES:
            mp.setattr(module, "build_model_cached", lambda *a, **k: fake_model(list(script)))
        disable_permit_tools_gate(mp)
        graph, config = build_oneshot_options(oneshot_options(tmp_path))
        result = asyncio.run(
            graph.ainvoke({"messages": [HumanMessage(content="parse this")]}, config=config)
        )
        reads = [
            m
            for m in result["messages"]
            if isinstance(m, ToolMessage) and m.name == "read_file"
        ]
        assert reads and reads[0].status == "success", (
            "with the gate disabled the forged read did NOT execute — the "
            "red-proof no longer demonstrates the gate is the refusing layer"
        )

    # GREEN: gate enabled (production shape) — the same forged read is refused.
    collected = run_collecting_tool_messages(
        monkeypatch, tmp_path, list(script), disable_gate=False
    )
    msgs = [m for ns, m in collected if m.name == "read_file" and ns == ()]
    assert msgs and msgs[0].status == "error" and REFUSED in str(msgs[0].content)


# ── layer 2: the gated general-purpose sub-agent reads REDACTED ───────────────


def test_task_dispatched_subagent_reads_are_redacted_even_without_gate(
    tmp_path, monkeypatch
):
    """The supplied ``general-purpose`` spec displaces deepagents' unredacted builtin.

    Exercised with the PermitTools gate DISABLED (``disable_gate=True``) so the
    ``task`` dispatch actually runs: this is the defence-in-depth layer that
    holds even if the gate is bypassed. Pre-fix, this exact scenario returned
    the credential UNREDACTED (pinned in tests/test_oneshot_task_executor_gate.py).
    """
    (tmp_path / "creds.txt").write_text(CRED)
    script = [
        forged(
            SUBAGENT_DISPATCH_TOOL,
            {"description": "read /creds.txt", "subagent_type": "general-purpose"},
            "c1",
        ),
        forged("read_file", {"file_path": "/creds.txt"}, "sub1"),
        AIMessage(content="sub-agent done " + "z" * 160),
        AIMessage(content=HEALTHY_TEXT),
    ]
    collected = run_collecting_tool_messages(monkeypatch, tmp_path, script, disable_gate=True)

    task_msgs = [m for ns, m in collected if m.name == SUBAGENT_DISPATCH_TOOL]
    assert task_msgs and task_msgs[0].status == "success", (
        "the forged task did not dispatch — the sub-agent redaction layer was "
        "never exercised; re-derive this test"
    )
    subagent_reads = [m for ns, m in collected if m.name == "read_file" and ns != ()]
    assert subagent_reads, "the dispatched sub-agent issued no observable read_file"
    content = str(subagent_reads[0].content)
    assert "AKIAIOSFODNN7EXAMPLE" not in content and "REDACTED" in content, (
        f"the task-dispatched sub-agent read came back UNREDACTED "
        f"(content={content[:120]!r}) — the gated general-purpose spec no "
        f"longer displaces deepagents' builtin; the unredacted-read hole is open."
    )
    # The final task result must not carry the credential either.
    assert "AKIAIOSFODNN7EXAMPLE" not in str(task_msgs[0].content)


def test_oneshot_general_purpose_spec_is_read_only_and_redaction_wrapped(tmp_path):
    """STRUCTURAL: the one-shot sub-agent specs are exactly one gated shadow.

    ``get_subagent_specs(..., agents={})`` — what ``_build_oneshot_graph``
    passes — must yield a single ``general-purpose`` spec with no granted
    tools, wrapped by ``read_only_middleware`` (``RedactToolResults`` present),
    so deepagents' auto-add is displaced by a redacting equivalent.
    """
    options = StreamingOptions(
        model="claude-test",
        cwd=tmp_path,
        env={},
        tool_policy=ToolPolicy(),
    )
    specs = get_subagent_specs(options, agents={})
    assert [spec["name"] for spec in specs] == ["general-purpose"]
    spec = specs[0]
    assert spec["tools"] == [], "the one-shot general-purpose shadow must grant no tools"
    middleware_types = [type(m).__name__ for m in spec.get("middleware", [])]
    assert any(isinstance(m, RedactToolResults) for m in spec.get("middleware", [])), (
        f"general-purpose spec lacks RedactToolResults ({middleware_types}) — "
        f"its reads would return unredacted"
    )


# ── S10/S11 neutrality: no streaming caller installs the gate ─────────────────


def test_streaming_builder_never_installs_the_permit_tools_gate(monkeypatch, tmp_path):
    """A streaming caller that does not OPT IN gets no PermitTools gate.

    S10/S11 and agentic detection all compile through ``build_streaming_agent``.
    ``_create_agent`` installs PermitTools only when ``permitted_tool_calls``
    is not None, and ``options/streaming.py`` forwards
    ``StreamingOptions.permitted_tool_calls`` — default ``None``. The frozen
    S10/S11 option builders never set the field, so their graphs stay ungated;
    only the detection ``agentic()`` construction site passes a set. This test
    pins the default-shape half (an S10 fix-mode-shaped options object with the
    field unset must hand ``None`` to ``_create_agent``); the per-construction-
    site pins — the REAL S10/S11 builders yield None, the detection site yields
    exactly the granted read natives — live in
    tests/test_agentic_detection_permit_gate.py.
    """
    import vvaharness.backends.harness.deepagents.options.streaming as _da_streaming

    captured: dict = {}
    real = _da_streaming._create_agent

    def spy(*args, **kwargs):  # noqa: ANN002, ANN003
        captured.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(_da_streaming, "_create_agent", spy)
    for module in MODEL_RESOLUTION_MODULES:
        monkeypatch.setattr(
            module,
            "build_model_cached",
            lambda *a, **k: fake_model([AIMessage(content=HEALTHY_TEXT)]),
        )
    from vvaharness.backends.harness.deepagents.options import build_streaming_agent

    options = StreamingOptions(
        model="claude-test",
        cwd=tmp_path,
        env={},
        tool_policy=ToolPolicy(allowed_tools=("Read", "Grep", "Glob")),
        allow_writes=True,  # the S10 fix-mode shape
        writable_paths=(str(tmp_path),),
    )
    build_streaming_agent(options)
    assert captured.get("permitted_tool_calls") is None, (
        f"a streaming caller that never set permitted_tool_calls reached "
        f"_create_agent with {captured.get('permitted_tool_calls')!r} — the "
        f"executor gate would reach S10 fix mode / S11 validation; a "
        f"non-opted-in path must stay ungated"
    )


if __name__ == "__main__":  # pragma: no cover - convenience only
    raise SystemExit(pytest.main([__file__, "-q"]))


# ── The executor gate reaches the SUB-AGENT tier too ──────────────────────────

def test_subagent_specs_install_the_permit_gate_when_the_parent_is_gated(tmp_path):
    """FIX: `PermitTools` extends to sub-agent specs, not just the parent graph.

    Red before: sub-agent specs carried `ExcludeTools`/`read_only_middleware`
    only. Those un-advertise, which fails OPEN against a forged or hallucinated
    tool call, so the fail-closed executor seam stopped at the parent — inside a
    dispatched sub-agent nothing refused execution. Unreachable in practice
    because `task` is never permitted on a gated path, but the layer must not
    depend on that staying true.
    """
    options = StreamingOptions(
        model="claude-test",
        cwd=tmp_path,
        env={},
        tool_policy=ToolPolicy(),
        permitted_tool_calls=frozenset({"read_file"}),
    )
    spec = get_subagent_specs(options, agents={})[0]
    gates = [m for m in spec.get("middleware", []) if isinstance(m, PermitTools)]
    assert gates, (
        "a gated parent must gate its sub-agents: "
        f"{[type(m).__name__ for m in spec.get('middleware', [])]}"
    )


def test_subagent_specs_stay_ungated_for_s10_s11(tmp_path):
    """S10/S11 pass no permitted set, so sub-agent specs must gain no gate.

    Same per-construction-site opt-in as the parent graph: `None` installs
    nothing, which is what keeps remediation and validation byte-identical.
    """
    options = StreamingOptions(
        model="claude-test",
        cwd=tmp_path,
        env={},
        tool_policy=ToolPolicy(),
    )
    assert options.permitted_tool_calls is None, "precondition: ungated construction"
    spec = get_subagent_specs(options, agents={})[0]
    assert not [m for m in spec.get("middleware", []) if isinstance(m, PermitTools)], (
        "S10/S11 sub-agent specs must carry no PermitTools gate"
    )
