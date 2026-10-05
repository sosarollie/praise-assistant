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

"""Lock the EXACT model-visible tool set of every DeepAgents call shape.

WHY THIS FILE EXISTS — do not delete it as redundant with the option-builder
unit tests. Tool exposure on the DeepAgents route is a DENYLIST bolted onto an
allowlist: the native filesystem tools are injected by deepagents' own
FilesystemMiddleware (not by vvaharness), the sub-agent dispatch tool ``task``
is injected by its SubAgentMiddleware, and vvaharness only SUBTRACTS unwanted
tools with ExcludeTools at the wrap_model_call seam. That subtraction is only
as complete as the hand-maintained enumerations in
``vvaharness/backends/harness/deepagents/models.py`` (``ALL_NATIVE_TOOLS``,
``SUBAGENT_DISPATCH_TOOL``), so ANY new deepagents built-in tool — a new
filesystem tool, a memory tool, an async sub-agent dispatch tool — fails OPEN
on a dependency upgrade (the pin is ``deepagents>=0.7.13,<0.8``). That is not
hypothetical: ``task`` was missing from the enumeration and let a parser-only
one-shot call dispatch an ungated, unredacted sub-agent until it was closed by
an unconditional exclusion in ``options/oneshot.py``.

These tests therefore compile the REAL graphs through the REAL option
builders — the same code paths S1 detection, S10 fix-mode remediation and S11
validation execute — drive them with a fake chat model that records the tool
names bound to every model request, and assert set EQUALITY (not subset) per
request. A future deepagents version that injects a new built-in changes an
observed set and fails these tests loudly in CI instead of silently widening
production tool exposure. The pinned S10/S11 sequences double as the
neutrality proof required when the exposure seams are refactored.

The recording fake model is local to this file (see the note above
``_recording_model``); its scripted message sequence lets sub-agents actually
be dispatched so their model requests are observed too.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage

from fixtures.deepagents_scaffolding import HEALTHY_TEXT, patch_models
from vvaharness.backends.harness import OneShotOptions, StreamingOptions, get_harness
from vvaharness.backends.harness.deepagents import tools as da_tools
from vvaharness.backends.harness.deepagents.models import (
    ALL_NATIVE_TOOLS,
    DELETE_TOOL_NAME,
    SUBAGENT_DISPATCH_TOOL,
)
from vvaharness.backends.harness.models import (
    LOGICAL_TO_NATIVE,
    MUTATING_TOOLS,
    NATIVE_WRITE_TOOLS,
    ORCHESTRATION_TOOLS,
)

# HEALTHY_TEXT (long enough to clear the VVAH-E003 degenerate-response floor)
# and patch_models are shared scaffolding from fixtures/deepagents_scaffolding.py.
# The recording model below stays LOCAL on purpose: its bind/call event stream
# (folded by _per_request_toolsets) is this file's whole measurement, and the
# shared replay-only fake deliberately observes nothing.

# ── the recording fake model ──────────────────────────────────────────────────


def _recording_model(sink: list[tuple[str, frozenset[str] | None]], script: list[AIMessage]):
    """A fake chat model that records the tool names bound to each model request.

    The scripted *script* lets the parent dispatch real sub-agents (via
    ``task`` tool calls) so each sub-agent's own model request is compiled,
    issued and recorded. ``bind_tools`` appends ``("bind", names)`` and returns self;
    every generation appends ``("call", None)``, so per-request tool sets can
    be reconstructed even for a request that bound no tools at all.
    """

    class _Recorder(GenericFakeChatModel):
        def bind_tools(self, tools, **_kwargs):  # noqa: ANN001, ANN003
            names = {
                getattr(t, "name", None) or (t.get("name") if isinstance(t, dict) else None)
                for t in tools
            }
            sink.append(("bind", frozenset(n for n in names if n)))
            return self

        def _generate(self, *args, **kwargs):  # noqa: ANN002, ANN003
            sink.append(("call", None))
            return super()._generate(*args, **kwargs)

    return _Recorder(messages=iter(script))


def _per_request_toolsets(
    sink: list[tuple[str, frozenset[str] | None]],
) -> list[frozenset[str]]:
    """Fold the recorder's event stream into one tool set per model request."""
    requests: list[frozenset[str]] = []
    current: frozenset[str] = frozenset()
    for kind, names in sink:
        if kind == "bind":
            current = names or frozenset()
        else:
            requests.append(current)
            current = frozenset()
    return requests


def _task_call(subagent: str, call_id: str,
               description: str = "delegate") -> AIMessage:
    """Parent turn dispatching *subagent* through deepagents' ``task`` tool."""
    return AIMessage(
        content="",
        tool_calls=[{
            "name": SUBAGENT_DISPATCH_TOOL,
            "args": {"description": description, "subagent_type": subagent},
            "id": call_id,
            "type": "tool_call",
        }],
    )


def _structured_call(tool_name: str, args: dict, call_id: str) -> AIMessage:
    """Terminal turn emitting the ToolStrategy structured-output tool call."""
    return AIMessage(
        content="",
        tool_calls=[{"name": tool_name, "args": args, "id": call_id, "type": "tool_call"}],
    )


# ── the four call shapes, executed through the real production entry points ──


def _run_oneshot_detection(tmp_path, monkeypatch) -> list[frozenset[str]]:
    """(a) One-shot ``prompt()`` detection, exactly as backends/llm/deepagents.py builds it."""
    from vvaharness.backends.llm import deepagents as deep

    sink: list = []
    patch_models(monkeypatch, _recording_model(sink, [AIMessage(content=HEALTHY_TEXT)]))
    deep.prompt(
        "parse this",
        model=SimpleNamespace(id="claude-test", via="deepagents"),
        cwd=str(tmp_path),
        tag="tool-exposure oneshot",
    )
    return _per_request_toolsets(sink)


def _run_oneshot_probe(tmp_path, monkeypatch) -> list[frozenset[str]]:
    """(a') One-shot with ``tool_policy=None`` — the preflight-probe / legacy shape.

    Mirrors ``orchestrator/preflight.py::_probe_deepagents_harness``'s
    (def at `~preflight.py:511`) OneShotOptions (no tool_policy field set,
    so it stays ``None``).
    """
    sink: list = []
    patch_models(monkeypatch, _recording_model(sink, [AIMessage(content=HEALTHY_TEXT)]))
    options = OneShotOptions(
        model="claude-test", cwd=tmp_path, env={}, model_provider=None, max_turns=2
    )
    asyncio.run(get_harness("deepagents").run_oneshot("ping", options))
    return _per_request_toolsets(sink)


def _run_detection_agentic(tmp_path, monkeypatch) -> list[frozenset[str]]:
    """(b) Detection ``agentic()``, exactly as backends/llm/deepagents.py builds it.

    The parent ATTEMPTS a general-purpose sub-agent dispatch, but the detection
    agentic path is executor-gated (``StreamingOptions.permitted_tool_calls``
    feeds PermitTools; ``task`` is never permitted there — no detection
    consumer needs sub-agents), so the dispatch is refused with an error
    ToolMessage and NO sub-agent model request is ever issued. The refused
    attempt is kept in the script deliberately: it pins that refusal at this
    seam too. The gated general-purpose spec's own advertised set stays
    observed via the S10/S11 shapes; execution-level refusals are pinned in
    tests/test_agentic_detection_permit_gate.py.
    """
    from vvaharness.backends.llm import deepagents as deep

    sink: list = []
    script = [
        _task_call("general-purpose", "t1"),
        AIMessage(content=HEALTHY_TEXT),
    ]
    patch_models(monkeypatch, _recording_model(sink, script))
    deep.agentic(
        "explore the repo",
        model=SimpleNamespace(id="claude-test", via="deepagents"),
        cwd=str(tmp_path),
        tag="tool-exposure agentic",
        max_turns=10,
    )
    return _per_request_toolsets(sink)


def _run_s10_fix_mode(tmp_path, monkeypatch) -> list[frozenset[str]]:
    """(c) S10 fix mode, through the real ``plugin_runner._invoke_deepagents``."""
    from vvaharness.remediation_agent.plugin_runner import _invoke_deepagents

    sink: list = []
    fixer_spec = """VULNERABILITY CONTEXT:
Untrusted input reaches a file-read sink.
TARGET FILES:
app.py
EDIT INSTRUCTIONS:
Normalize the input and reject paths outside the trusted root.
SUCCESS CRITERIA:
Traversal and absolute paths cannot reach the read operation.
"""
    script = [
        _task_call("fixer", "t1", fixer_spec),
        _structured_call(
            "FixerResult",
            {"status": "applied", "files_changed": ["app.py"], "summary": "fixed"},
            "f1",
        ),
        _structured_call("RemediationVerdict", {"verdict": "Needs Review"}, "t2"),
    ]
    patch_models(monkeypatch, _recording_model(sink, script))
    cfg = SimpleNamespace(
        step_remediate=SimpleNamespace(
            allowed_tools=None, max_turns=10, max_budget_usd=1.0
        ),
        sdk=None,
        openai=None,
    )
    _invoke_deepagents(
        "fix the finding",
        model_id="claude-test",
        repo=tmp_path,
        mode="fix",
        sr=cfg.step_remediate,
        cfg=cfg,
        verbose=False,
        provider=None,
    )
    return _per_request_toolsets(sink)


def _run_s11_validation(tmp_path, monkeypatch) -> list[frozenset[str]]:
    """(d) S11 validation: real ``build_validation_options`` + real harness stream."""
    from vvaharness.backends.harness import HarnessResult
    from vvaharness.validation.config import load_config
    from vvaharness.validation.models import Manifest
    from vvaharness.validation.session.launcher import build_validation_options

    def persona_report(name: str, call_id: str) -> AIMessage:
        return _structured_call(
            "PersonaReport",
            {"persona": name, "tracking_id": "TEST-1", "gates": []},
            call_id,
        )

    sink: list = []
    script = [
        _task_call("security-architect", "t1"),
        persona_report("security-architect", "p1"),
        _task_call("penetration-tester", "t2"),
        persona_report("penetration-tester", "p2"),
        _task_call("cross-repo-analyzer", "t3"),
        persona_report("cross-repo-analyzer", "p3"),
        _task_call("general-purpose", "t4"),
        AIMessage(content="sub-agent done"),
        _structured_call(
            "ValidationOutput",
            {"target_jira_status": "Validated", "findings": [], "synthesized_gates": []},
            "t5",
        ),
    ]
    patch_models(monkeypatch, _recording_model(sink, script))
    options = build_validation_options(
        config=load_config(),
        manifest=Manifest(jira_key="TEST-1", session_id="s1"),
        workspace=tmp_path,
        output_dir=tmp_path / "out",
        system_prompt=None,
    )

    async def drain():
        async for message in get_harness("deepagents").run_streaming("validate", options):
            if isinstance(message, HarnessResult) and message.is_error:
                raise AssertionError(f"validation stream errored: {message.subtype}")

    asyncio.run(drain())
    return _per_request_toolsets(sink)


# ── expected inventory: the exact model-visible tool set per request ─────────

_NATIVE_READ = frozenset({"ls", "read_file", "glob", "grep"})
#: What the detection agentic parent is offered: the natives its granted read
#: logicals (Read/Grep/Glob) resolve to — the same set its PermitTools gate
#: permits. `ls` has no granting logical, so it is neither permitted nor offered.
_GRANTED_READ_NATIVES = frozenset(
    LOGICAL_TO_NATIVE[t] for t in ("Read", "Grep", "Glob")
)
_FACT_TOOLS = frozenset(
    {"DiffTouched", "ChangedLines", "DiffImpactMap", "PatternScan", "TestInventory"}
)
_PERSONA_SET = _NATIVE_READ | _FACT_TOOLS | {"PersonaReport"}

#: shape -> (runner, ordered per-request expectation as (agent, exact tool set)).
#: The structured-output tool names (RemediationVerdict/ValidationOutput/
#: PersonaReport) ARE model-visible tools: ToolStrategy binds them into the
#: request, and the policy granted them via ``response_model``.
_SHAPES = {
    "oneshot-detection(a)": (
        _run_oneshot_detection,
        [("parser", frozenset())],  # NOTHING — no natives, no task.
    ),
    "oneshot-probe-policy-none(a')": (
        _run_oneshot_probe,
        [("parser", _NATIVE_READ)],  # legacy natives kept; task still withheld.
    ),
    "detection-agentic(b)": (
        _run_detection_agentic,
        [
            # Advertisement is ALIGNED with the executor gate: the streaming
            # builder derives its ExcludeTools set from the same
            # ``permitted_tool_calls`` the PermitTools gate enforces
            # (options/streaming.py::_extra_excluded_tools), so the model is
            # offered exactly the granted read natives — no `ls`, no `task`.
            # The scripted task dispatch is still a FORGED call and is REFUSED
            # at wrap_tool_call (PermitTools; advertisement alone never gates
            # execution), so no general-purpose sub-agent request appears.
            ("orchestrator", _GRANTED_READ_NATIVES),
            ("orchestrator", _GRANTED_READ_NATIVES),
        ],
    ),
    "s10-fix-mode(c)": (
        _run_s10_fix_mode,
        [
            # Orchestrator: read-redacted, plans only; never edits directly.
            ("orchestrator", _NATIVE_READ | {SUBAGENT_DISPATCH_TOOL, "RemediationVerdict"}),
            # Fixer: legitimately KEEPS write_file/edit_file (fix mode) and is
            # deliberately NOT read-redacted — edit_file requires a byte-exact
            # old_string from its own reads. It still never sees delete/task.
            ("fixer", _NATIVE_READ | {"write_file", "edit_file", "FixerResult"}),
            ("orchestrator", _NATIVE_READ | {SUBAGENT_DISPATCH_TOOL, "RemediationVerdict"}),
        ],
    ),
    "s11-validation(d)": (
        _run_s11_validation,
        [
            ("orchestrator", _NATIVE_READ | {SUBAGENT_DISPATCH_TOOL, "ValidationOutput"}),
            ("security-architect", _PERSONA_SET),
            ("orchestrator", _NATIVE_READ | {SUBAGENT_DISPATCH_TOOL, "ValidationOutput"}),
            ("penetration-tester", _PERSONA_SET),
            ("orchestrator", _NATIVE_READ | {SUBAGENT_DISPATCH_TOOL, "ValidationOutput"}),
            ("cross-repo-analyzer", _PERSONA_SET),
            ("orchestrator", _NATIVE_READ | {SUBAGENT_DISPATCH_TOOL, "ValidationOutput"}),
            # fact_tools are granted to EVERY validation sub-agent by
            # _subagent_tool_names (SessionOptions.fact_tools), so the shadowed
            # general-purpose agent holds the read-only fact tools too — but no
            # PersonaReport (it returns no structured report) and no task.
            ("general-purpose", _NATIVE_READ | _FACT_TOOLS),
            ("orchestrator", _NATIVE_READ | {SUBAGENT_DISPATCH_TOOL, "ValidationOutput"}),
        ],
    ),
}


def _explain(shape: str, agent: str, index: int, expected: frozenset, offered: frozenset) -> str:
    """Failure message telling a maintainer exactly what changed and what to do."""
    leaked = sorted(offered - expected)
    lost = sorted(expected - offered)
    lines = [
        f"model-visible tool set changed for shape {shape!r}, request #{index} "
        f"(agent: {agent}).",
        f"  offered : {sorted(offered)}",
        f"  expected: {sorted(expected)}",
    ]
    if leaked:
        lines.append(
            f"  LEAKED (offered but never granted): {leaked} — this is the "
            f"fail-open class this file guards. If a deepagents upgrade added a "
            f"new built-in tool, it must be added to ALL_NATIVE_TOOLS (or "
            f"excluded like SUBAGENT_DISPATCH_TOOL) in "
            f"vvaharness/backends/harness/deepagents/models.py and withheld at "
            f"the ExcludeTools seam BEFORE updating this expectation."
        )
    if lost:
        lines.append(
            f"  WITHHELD (granted but no longer offered): {lost} — an exclusion "
            f"now over-subtracts; S10 remediation/S11 validation may have lost a "
            f"tool they rely on."
        )
    return "\n".join(lines)


@pytest.mark.parametrize("shape", sorted(_SHAPES))
def test_exact_tool_set_per_model_request(shape, tmp_path, monkeypatch):
    """Every model request of every call shape offers EXACTLY the pinned tool set."""
    runner, expected = _SHAPES[shape]
    observed = runner(tmp_path, monkeypatch)
    assert len(observed) == len(expected), (
        f"shape {shape!r}: expected {len(expected)} model request(s) "
        f"({[a for a, _ in expected]}), observed {len(observed)}: "
        f"{[sorted(s) for s in observed]} — the scripted run no longer drives "
        f"the same agents; re-derive the sequence before trusting tool sets."
    )
    for index, ((agent, want), got) in enumerate(zip(expected, observed)):
        assert got == want, _explain(shape, agent, index, want, got)


def test_oneshot_graph_never_offers_task_to_the_model(tmp_path, monkeypatch):
    """The one-shot detection graph advertises NO tools to the model at all.

    Strengthened from the older ``task not in offered`` form — this file is
    now the canonical home for the empty-advertised-set pin: an
    empty offered set trivially satisfies "no task", so asserting only the
    absence of ``task`` cannot distinguish "everything correctly withheld"
    from "natives leaked but task happened to be excluded". The one-shot
    detection route builds an explicit empty ToolPolicy, and
    ``_oneshot_excluded_tools`` must therefore subtract every
    FilesystemMiddleware native AND SubAgentMiddleware's ``task`` — the model
    request must bind an EMPTY tool set.

    Precision of the claim: this asserts what is ADVERTISED to the model
    (``bind_tools``, the wrap_model_call seam where ExcludeTools acts). The
    executor still holds the tool objects, and advertisement is NOT the only
    gate: the executor-side guarantee (forged calls refused at the
    ``wrap_tool_call`` seam by ``PermitTools``) is pinned in
    tests/test_oneshot_task_executor_gate.py and
    tests/test_oneshot_least_privilege.py.
    """
    observed = _run_oneshot_detection(tmp_path, monkeypatch)
    assert observed, "the one-shot detection run issued no model request"
    offered = frozenset().union(*observed)
    assert offered == set(), (
        f"the one-shot detection graph advertised tools to the model: "
        f"{sorted(offered)} — it must advertise NONE (no natives, no "
        f"{SUBAGENT_DISPATCH_TOOL!r})."
    )


def test_injected_but_ungranted_tools_reach_no_model_request(tmp_path, monkeypatch):
    """The property that makes the denylist design safe, asserted globally.

    A tool deepagents injects but the policy never granted must be absent from
    every model request: ``delete`` everywhere, the native write tools
    everywhere except the S10 fixer, ``task`` on the one-shot shapes and inside
    every sub-agent. The closed-world check at the end is the tripwire for a
    FUTURE deepagents built-in: a new injected tool (memory, async task, a new
    filesystem verb) cannot belong to the granted universe, so its very first
    appearance in any request fails here even before the per-shape exact sets
    are consulted.
    """
    granted_universe = (
        ALL_NATIVE_TOOLS
        | {SUBAGENT_DISPATCH_TOOL}
        | _FACT_TOOLS
        | {"FixerResult", "RemediationVerdict", "ValidationOutput", "PersonaReport"}
    )
    for shape, (runner, expected) in sorted(_SHAPES.items()):
        observed = runner(tmp_path / shape.replace("'", ""), monkeypatch)
        oneshot = shape.startswith("oneshot")
        for index, (offered, (agent, _)) in enumerate(zip(observed, expected)):
            ctx = f"shape {shape!r} request #{index} (agent {agent}): {sorted(offered)}"
            assert DELETE_TOOL_NAME not in offered, f"delete leaked — {ctx}"
            if not (shape.startswith("s10") and agent == "fixer"):
                assert not (offered & NATIVE_WRITE_TOOLS), f"write tool leaked — {ctx}"
            if oneshot or agent != "orchestrator":
                assert SUBAGENT_DISPATCH_TOOL not in offered, f"task leaked — {ctx}"
            unknown = offered - granted_universe
            assert not unknown, (
                f"tool(s) outside the granted universe offered to the model: "
                f"{sorted(unknown)} — {ctx}. A deepagents middleware is "
                f"injecting a tool vvaharness's exclusion seams do not know "
                f"about; extend ALL_NATIVE_TOOLS / the ExcludeTools seams in "
                f"vvaharness/backends/harness/deepagents before accepting it."
            )


def test_all_native_tools_still_covers_every_deepagents_filesystem_builtin():
    """Canary: the hand-maintained ALL_NATIVE_TOOLS enumeration has not drifted.

    ExcludeTools can only subtract tools it knows by name, so ALL_NATIVE_TOOLS
    must remain a superset of everything deepagents' FilesystemMiddleware can
    register. Reads deepagents' own enumeration so a dependency upgrade that
    grows it fails HERE, loudly, instead of failing open in production. If the
    private symbol moves, this import error is itself the loud signal to
    re-verify the enumeration against the new deepagents version.
    """
    from deepagents.middleware.filesystem import _ALL_FS_TOOL_NAMES

    new_builtins = frozenset(_ALL_FS_TOOL_NAMES) - ALL_NATIVE_TOOLS
    assert not new_builtins, (
        f"deepagents now registers filesystem tool(s) {sorted(new_builtins)} "
        f"that ALL_NATIVE_TOOLS does not enumerate — the ExcludeTools denylist "
        f"fails OPEN for them. Add them to ALL_NATIVE_TOOLS in "
        f"vvaharness/backends/harness/deepagents/models.py and re-derive the "
        f"per-shape expectations in this file."
    )


# ── unknown logical tool names warn once instead of vanishing silently ───────


@pytest.fixture
def _fresh_unknown_tool_warnings(monkeypatch):
    """Observe the one-time per-process unknown-name warnings from a clean slate."""
    monkeypatch.setattr(da_tools, "_WARNED_UNKNOWN_TOOLS", set())


def _options(**kwargs) -> StreamingOptions:
    return StreamingOptions(model="m", cwd=Path("/tmp"), **kwargs)


def test_unknown_tool_name_warns_once_and_is_still_dropped(
    capsys, _fresh_unknown_tool_warnings
):
    """A typo'd name warns by name, once per process — and still grants nothing."""
    options = _options()
    resolved = da_tools.native_tool_names(options, ("Read", "Raed"))
    assert resolved == ("read_file",)  # fail safe: dropped, never granted, no raise
    da_tools.native_tool_names(options, ("Read", "Raed"))
    err = capsys.readouterr().err
    assert err.count("unrecognised tool name 'Raed'") == 1
    assert "WARN [deepagents]" in err


def test_known_and_deliberately_unmapped_names_stay_silent(
    capsys, _fresh_unknown_tool_warnings
):
    """Names that are mapped, unmapped by design, fact tools, or MCP never warn."""
    options = _options(fact_tools=("DiffTouched", "PatternScan"))
    allowed = (
        *LOGICAL_TO_NATIVE,  # Read/Grep/Glob/Edit/Write — mapped
        *sorted(ORCHESTRATION_TOOLS),  # Agent/Task/TodoWrite/Skill — by design
        *sorted(MUTATING_TOOLS),  # Bash/NotebookEdit unmapped by design
        "DiffTouched", "PatternScan",  # consumer fact tools (tool_builder's job)
        "mcp__server__lookup",  # MCP tools live outside the native mapping
    )
    resolved = da_tools.native_tool_names(options, allowed)
    assert set(resolved) == set(LOGICAL_TO_NATIVE.values())
    assert da_tools.build_tools(options, allowed_tools=allowed) == []
    assert capsys.readouterr().err == ""


def test_build_tools_warns_for_unknown_names_too(capsys, _fresh_unknown_tool_warnings):
    """build_tools is the resolver sessions actually reach; it shares the warning."""
    options = _options()
    assert da_tools.build_tools(options, allowed_tools=("Grpe",)) == []
    assert da_tools.build_tools(options, allowed_tools=("Grpe",)) == []
    err = capsys.readouterr().err
    assert err.count("unrecognised tool name 'Grpe'") == 1


# --- The native tool name space is reserved -----------------------------------

def test_session_tool_names_refuses_a_name_that_collides_with_a_native() -> None:
    """A session tool named after a gated native would re-permit that native.

    `session_tool_names` feeds the `PermitTools` executor allowlist. A caller
    tool whose `.name` equals a native's (say `write_file`) would be unioned
    into the permitted set and quietly undo the gate for that native, so the
    collision must fail the graph build instead of widening the allowlist.
    """
    from vvaharness.backends.harness.deepagents.models import ALL_NATIVE_TOOLS

    native = sorted(ALL_NATIVE_TOOLS)[0]
    with pytest.raises(ValueError, match="collide with reserved"):
        da_tools.session_tool_names([SimpleNamespace(name=native)])


def test_session_tool_names_keeps_ordinary_names_and_still_drops_nameless() -> None:
    """Non-colliding names pass; an entry with no string name contributes nothing."""
    out = da_tools.session_tool_names(
        [SimpleNamespace(name="vvah_fact_lookup"), SimpleNamespace(other="x")]
    )
    assert out == frozenset({"vvah_fact_lookup"})
