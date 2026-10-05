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

"""Executor-seam least-privilege gate on the AGENTIC detection path, by execution.

The one-shot detection path is already PermitTools-gated (options/oneshot.py).
This file proves the same property for the streaming/agentic detection path
(``backends/llm/deepagents.py::agentic``, used by S1 preprocess and S2's
agentic mode): the REAL graph is compiled through the REAL production entry
point and driven with a fake chat model that FORGES tool calls the policy
never granted. ExcludeTools only un-advertises tools (wrap_model_call); the
LangGraph tool node keeps every registered tool object, so without the
executor gate a forged call still executes. Each forged call must be answered
with a synthetic ``status="error"`` ToolMessage and never execute — while a
GRANTED read tool must keep working, because breaking legitimate S1/S2
operation would be as bad as the leak.

Also pinned here: the S10 remediation and S11 validation option builders pass
NO permitted set (``permitted_tool_calls`` stays ``None`` all the way into
``_create_agent``), so the frozen fix/validation paths install no gate — inert
by construction, not by argument. A future edit that silently starts gating
remediation fails these pins loudly.

Fake-model technique follows tests/test_deepagents_tool_exposure.py; all
filesystem targets live inside ``tmp_path`` (the harness roots its virtual
filesystem at ``cwd``), nothing shells out, and no sockets are opened.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage

import vvaharness.backends.harness.deepagents.options.streaming as _da_streaming
from fixtures.deepagents_scaffolding import HEALTHY_TEXT, REFUSED, patch_models
from vvaharness.backends.harness import StreamingOptions
from vvaharness.backends.harness.models import LOGICAL_TO_NATIVE

# HEALTHY_TEXT (long enough to clear the VVAH-E003 degenerate-response floor),
# the PermitTools REFUSED marker, and patch_models are shared scaffolding from
# fixtures/deepagents_scaffolding.py. The recording model below stays LOCAL on
# purpose: it observes the bind_tools/_generate seams (what the model is
# OFFERED and SHOWN), which the shared replay-only fake deliberately ignores.

_SENTINEL = "GRANTED-READ-SENTINEL-9731"


# ── fake model: scripted turns, records every message it is shown ────────────


def _scripted_model(
    seen: list, script: list[AIMessage], binds: list | None = None
) -> GenericFakeChatModel:
    """A fake chat model that records the message list of every model request.

    When *binds* is given, the tool NAMES bound to each request are recorded
    there too (the wrap_model_call seam ExcludeTools acts on) — what the model
    is actually OFFERED, as opposed to what the executor would permit.
    """

    class _Recorder(GenericFakeChatModel):
        def bind_tools(self, tools, **_kwargs):  # noqa: ANN001, ANN003
            if binds is not None:
                names = {
                    getattr(t, "name", None)
                    or (t.get("name") if isinstance(t, dict) else None)
                    for t in tools
                }
                binds.append(frozenset(n for n in names if isinstance(n, str)))
            return self

        def _generate(self, messages, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
            seen.append(list(messages))
            return super()._generate(messages, *args, **kwargs)

    return _Recorder(messages=iter(script))


def _tool_messages(seen: list) -> dict[str, ToolMessage]:
    """All ToolMessages the model was ever shown, keyed by tool_call_id."""
    out: dict[str, ToolMessage] = {}
    for messages in seen:
        for message in messages:
            if isinstance(message, ToolMessage):
                out[message.tool_call_id] = message
    return out


def _call(name: str, args: dict, call_id: str) -> dict:
    return {"name": name, "args": args, "id": call_id, "type": "tool_call"}


def _run_agentic(tmp_path: Path, monkeypatch, script: list[AIMessage]) -> list:
    """Drive the REAL detection agentic() entry point with a scripted model."""
    from vvaharness.backends.llm import deepagents as deep

    seen: list = []
    patch_models(monkeypatch, _scripted_model(seen, script))
    out = deep.agentic(
        "explore the repo",
        model=SimpleNamespace(id="claude-test", via="deepagents"),
        cwd=str(tmp_path),
        tag="permit-gate agentic",
        max_turns=12,
    )
    assert out == HEALTHY_TEXT
    return seen


def _seed_repo(tmp_path: Path) -> None:
    (tmp_path / "readable.txt").write_text(f"hello {_SENTINEL} world\n")
    (tmp_path / "keep.txt").write_text("must survive\n")


#: Forged, never-granted calls: two mutating natives, command execution,
#: sub-agent dispatch, and a native READ (`ls`) outside the granted set.
_FORGED = [
    _call("write_file", {"file_path": "/pwned.txt", "content": "owned"}, "f-write_file"),
    _call("delete", {"file_path": "/keep.txt"}, "f-delete"),
    _call("execute", {"command": "touch /executed.txt"}, "f-execute"),
    _call(
        "task",
        {"description": "delegate", "subagent_type": "general-purpose"},
        "f-task",
    ),
    _call("ls", {"path": "/"}, "f-ls"),
]

_FORGED_NAMES = ("write_file", "delete", "execute", "task", "ls")


# ── the refusal matrix, plus the granted-read positive case ──────────────────


def test_forged_ungranted_calls_are_refused_and_granted_read_still_works(
    tmp_path, monkeypatch, capsys
):
    """Every forged un-granted call is refused; the granted read executes."""
    _seed_repo(tmp_path)
    script = [
        AIMessage(content="", tool_calls=list(_FORGED)),
        AIMessage(
            content="",
            tool_calls=[_call("read_file", {"file_path": "/readable.txt"}, "g-read")],
        ),
        AIMessage(content=HEALTHY_TEXT),
    ]
    seen = _run_agentic(tmp_path, monkeypatch, script)
    results = _tool_messages(seen)

    # Refusals: synthetic error ToolMessage per forged call, none executed.
    for name in _FORGED_NAMES:
        message = results[f"f-{name}"]
        assert message.status == "error", f"forged {name!r} was not refused"
        assert REFUSED in str(message.content), (
            f"forged {name!r}: refusal did not come from the PermitTools gate: "
            f"{message.content!r}"
        )
    err = capsys.readouterr().err
    for name in _FORGED_NAMES:
        assert f"refused tool call {name!r}" in err, f"no WARN for {name!r}"

    # Nothing executed: no file created, deleted, or spawned.
    assert not (tmp_path / "pwned.txt").exists(), "forged write_file executed"
    assert (tmp_path / "keep.txt").exists(), "forged delete executed"
    assert not (tmp_path / "executed.txt").exists(), "forged execute executed"

    # The positive case: the GRANTED read tool still works — the gate must not
    # break legitimate S1/S2 operation.
    granted = results["g-read"]
    assert granted.status != "error", f"granted read_file refused: {granted.content!r}"
    assert _SENTINEL in str(granted.content), "granted read returned no file content"


# ── RED/GREEN: gate disabled ⇒ the forge executes; restored ⇒ refused ─────────


def _ls_probe_script() -> list[AIMessage]:
    return [
        AIMessage(content="", tool_calls=[_call("ls", {"path": "/"}, "f-ls")]),
        AIMessage(content=HEALTHY_TEXT),
    ]


def test_red_green_gate_off_forged_ls_executes_gate_on_refused(
    tmp_path, monkeypatch, capsys
):
    """Disable the gate: the forged un-granted `ls` executes. Restore: refused.

    `ls` is the right RED probe: unlike write_file/edit_file/delete (denied by
    READ_ONLY_PERMISSIONS) and execute (no sandbox), NO lower layer blocks it,
    so its success is unambiguous proof the gate — and only the gate — is what
    refuses un-granted natives on this path.
    """
    _seed_repo(tmp_path)

    # RED: simulate the ungated path by having the streaming builder pass None.
    with monkeypatch.context() as patch:
        patch.setattr(_da_streaming, "_permitted_tool_calls", lambda *a, **k: None)
        seen = _run_agentic(tmp_path, patch, _ls_probe_script())
    red = _tool_messages(seen)["f-ls"]
    assert red.status != "error", f"gate disabled, yet ls was refused: {red.content!r}"
    assert REFUSED not in str(red.content)
    assert "readable.txt" in str(red.content), "ls did not actually list the repo"
    assert "refused tool call" not in capsys.readouterr().err

    # GREEN: same forged call through the unpatched production path — refused.
    seen = _run_agentic(tmp_path, monkeypatch, _ls_probe_script())
    green = _tool_messages(seen)["f-ls"]
    assert green.status == "error"
    assert REFUSED in str(green.content)
    assert "refused tool call 'ls'" in capsys.readouterr().err


# ── advertisement equals permission: offered set == permitted set, by execution ──


def test_advertised_set_equals_permitted_set_on_detection_agentic(
    tmp_path, monkeypatch
):
    """On the detection agentic path the model is OFFERED exactly what the
    executor PERMITS — set equality, both directions, observed at the real
    bind_tools seam of a real run — and a granted read still works end to end.

    Least privilege at the advertisement seam: a tool PermitTools would refuse
    (`ls`, `task`, the write natives) must never be on offer, or the model
    burns a turn on a recoverable refusal; and nothing permitted may be
    withheld, or S1/S2/S6 lose a capability they are entitled to. Equality is
    asserted against the ACTUAL permitted set captured from the production
    ``_create_agent`` call, not a hardcoded copy, so this cannot drift.
    """
    from vvaharness.backends.llm import deepagents as deep

    _seed_repo(tmp_path)
    seen: list = []
    binds: list[frozenset[str]] = []
    script = [
        AIMessage(
            content="",
            tool_calls=[_call("read_file", {"file_path": "/readable.txt"}, "g-read")],
        ),
        AIMessage(content=HEALTHY_TEXT),
    ]
    patch_models(monkeypatch, _scripted_model(seen, script, binds=binds))
    permitted_seen = _spy_create_agent(monkeypatch)
    out = deep.agentic(
        "explore the repo",
        model=SimpleNamespace(id="claude-test", via="deepagents"),
        cwd=str(tmp_path),
        tag="advertise-align agentic",
        max_turns=8,
    )
    assert out == HEALTHY_TEXT

    assert permitted_seen and permitted_seen[0] is not None
    permitted = permitted_seen[0]
    assert binds, "the run bound no tools to any model request"
    for index, offered in enumerate(binds):
        over = sorted(offered - permitted)
        under = sorted(permitted - offered)
        assert offered == permitted, (
            f"request #{index}: advertised != permitted; offered-but-refused "
            f"{over}, permitted-but-withheld {under}"
        )

    # End to end: the granted read really executed and returned file content.
    granted = _tool_messages(seen)["g-read"]
    assert granted.status != "error", f"granted read refused: {granted.content!r}"
    assert _SENTINEL in str(granted.content)


# ── the permitted set is DERIVED from the grant, not hardcoded ────────────────


def _captured_options(monkeypatch, tmp_path, **agentic_kwargs) -> StreamingOptions:
    """Capture the StreamingOptions agentic() builds, via the harness seam."""
    from vvaharness.backends.harness.models import HarnessResult
    from vvaharness.backends.llm import deepagents as deep

    captured: list[StreamingOptions] = []

    class _FakeHarness:
        async def run_streaming(self, prompt, options):  # noqa: ANN001
            captured.append(options)
            yield HarnessResult(subtype="success", result_text=HEALTHY_TEXT)

    monkeypatch.setattr(deep, "get_harness", lambda _via: _FakeHarness())
    deep.agentic(
        "p",
        model=SimpleNamespace(id="claude-test", via="deepagents"),
        cwd=str(tmp_path),
        **agentic_kwargs,
    )
    return captured[0]


def test_permitted_set_tracks_the_granted_read_tools(tmp_path, monkeypatch):
    """agentic() permits exactly the natives its granted logicals resolve to."""
    options = _captured_options(monkeypatch, tmp_path)  # default grant
    assert options.permitted_tool_calls == frozenset({"read_file", "glob", "grep"})
    assert options.permitted_tool_calls == frozenset(
        LOGICAL_TO_NATIVE[t] for t in options.tool_policy.allowed_tools
    )

    narrowed = _captured_options(
        monkeypatch, tmp_path, allowed_tools=["Read", "Bash"]
    )
    assert narrowed.permitted_tool_calls == frozenset({"read_file"})


# ── S10 / S11 neutrality: the frozen builders pass NO permitted set ───────────


def _spy_create_agent(monkeypatch) -> list:
    """Record the permitted_tool_calls kwarg of every real _create_agent call."""
    captured: list = []
    real = _da_streaming._create_agent

    def spy(*args, **kwargs):  # noqa: ANN002, ANN003
        captured.append(kwargs.get("permitted_tool_calls", "MISSING"))
        return real(*args, **kwargs)

    monkeypatch.setattr(_da_streaming, "_create_agent", spy)
    return captured


def test_s11_validation_builder_passes_no_permitted_set(tmp_path, monkeypatch):
    """The real S11 option builder sets no permitted set, down into _create_agent."""
    from vvaharness.backends.harness.deepagents.options.streaming import (
        build_streaming_agent,
    )
    from vvaharness.validation.config import load_config
    from vvaharness.validation.models import Manifest
    from vvaharness.validation.session.launcher import build_validation_options

    options = build_validation_options(
        config=load_config(),
        manifest=Manifest(jira_key="TEST-1", session_id="s1"),
        workspace=tmp_path,
        output_dir=tmp_path / "out",
        system_prompt=None,
    )
    assert options.permitted_tool_calls is None

    patch_models(monkeypatch, _scripted_model([], []))
    captured = _spy_create_agent(monkeypatch)
    build_streaming_agent(options)
    assert captured == [None], (
        f"S11 validation graph was built with a permitted set: {captured} — "
        f"the frozen S11 path must install NO PermitTools gate"
    )


def test_s10_remediation_builder_passes_no_permitted_set(tmp_path, monkeypatch):
    """The real S10 fix-mode invoker sets no permitted set, down into _create_agent."""
    from vvaharness.backends.harness.deepagents.options.streaming import (
        build_streaming_agent,
    )
    from vvaharness.remediation_agent import plugin_runner

    captured_options: list[StreamingOptions] = []

    async def capture(user, options, *, verbose):  # noqa: ANN001
        captured_options.append(options)
        return "captured"

    monkeypatch.setattr(plugin_runner, "_consume_deepagents", capture)
    cfg = SimpleNamespace(
        step_remediate=SimpleNamespace(
            allowed_tools=None, max_turns=10, max_budget_usd=1.0
        ),
        sdk=None,
        openai=None,
    )
    plugin_runner._invoke_deepagents(
        "fix the finding",
        model_id="claude-test",
        repo=tmp_path,
        mode="fix",
        sr=cfg.step_remediate,
        cfg=cfg,
        verbose=False,
        provider=None,
    )
    options = captured_options[0]
    assert options.permitted_tool_calls is None
    assert options.allow_writes is True  # this really is the fix-mode shape

    patch_models(monkeypatch, _scripted_model([], []))
    captured = _spy_create_agent(monkeypatch)
    build_streaming_agent(options)
    assert captured == [None], (
        f"S10 fix-mode graph was built with a permitted set: {captured} — "
        f"the frozen S10 path must install NO PermitTools gate"
    )
