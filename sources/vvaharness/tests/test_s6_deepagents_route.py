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

"""S6 via:deepagents route tests — stage branching and verdict parse parity.

S6 calls ``_deepagents.dispatch_agentic``; the via branch lives in that
dispatcher, so these tests patch its two legs — the module-level deepagents
wrapper (``_deepagents.agentic``) and the legacy registry
(``_deepagents.registry.agentic``) — arming whichever leg must NOT fire to
fail, so a routing regression cannot pass silently.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.backends.llm import cli
from vvaharness.models import ContextPackage, Finding, VulnClass
from vvaharness.pipeline.stages import s6_verify


@pytest.fixture(autouse=True)
def _isolate():
    # cli._ABORT is a process-global Event; clear before and after every test
    # so this file is order independent within the full suite.
    cli.reset_abort()
    yield
    cli.reset_abort()


def _finding() -> Finding:
    return Finding(
        chunk_id="chunk-01",
        file="src/app.py",
        line_start=10,
        line_end=12,
        vuln_class=VulnClass.INJECTION,
        title="SQL injection in handler",
        description="user input flows into a raw query",
        code_snippet="cur.execute('SELECT ' + user_in)",
        confidence=0.8,
    )


def _ctx() -> ContextPackage:
    return ContextPackage(repo_root="/nonexistent-repo", language="python")


def _cfg(model_node) -> SimpleNamespace:
    return SimpleNamespace(
        step6_verify=SimpleNamespace(
            parallel=1, min_confidence=7,
            allowed_tools=["Read", "Grep"],
            max_budget_usd=1.0, max_turns=6,
        ),
        models=SimpleNamespace(verify=model_node),
        sdk=SimpleNamespace(api_key="sk-test"),
    )


_TP_REPLY = (
    "The handler concatenates user input into SQL with no upstream defence.\n"
    "VERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable from /search\n"
    "CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
)


def _fail_registry(monkeypatch):
    monkeypatch.setattr(
        s6_verify._deepagents.registry, "agentic",
        lambda *_a, **_k: pytest.fail("legacy dispatcher was called"),
    )


def _fail_wrapper(monkeypatch):
    monkeypatch.setattr(
        s6_verify._deepagents, "agentic",
        lambda *_a, **_k: pytest.fail("deepagents wrapper was called"),
    )


def test_deepagents_via_routes_through_wrapper(monkeypatch):
    _fail_registry(monkeypatch)
    node = SimpleNamespace(id="claude-test", via="deepagents")
    cfg = _cfg(node)
    captured = {}

    def fake_agentic(user_prompt, **kw):
        captured["user_prompt"] = user_prompt
        captured.update(kw)
        return _TP_REPLY

    monkeypatch.setattr(s6_verify._deepagents, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), cfg)

    assert [f.verdict for f in verified] == ["TRUE_POSITIVE"]
    assert dropped == []
    assert verified[0].verdict_confidence == 9
    assert verified[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert captured["model"] is node
    assert captured["system_prompt"] is s6_verify.SYSTEM
    # Equality, not identity: _verify_one passes a fresh list(tools) per call.
    assert captured["allowed_tools"] == ["Read", "Grep"]
    assert captured["cwd"] == "/nonexistent-repo"
    assert captured["max_budget_usd"] == 1.0
    assert captured["max_turns"] == 6
    assert captured["tag"] == "s6 verify#0"
    assert captured["graph_name"] == "s6-verify"
    assert captured["sdk_cfg"] is cfg.sdk
    assert captured["openai_cfg"] is None
    assert "FINDING TO VERIFY" in captured["user_prompt"]


def test_legacy_via_keeps_exact_kwargs(monkeypatch):
    _fail_wrapper(monkeypatch)
    node = SimpleNamespace(id="claude-test", via="sdk")
    cfg = _cfg(node)
    captured = {}

    def fake_agentic(user_prompt, **kw):
        captured["user_prompt"] = user_prompt
        captured.update(kw)
        return _TP_REPLY

    monkeypatch.setattr(s6_verify._deepagents.registry, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), cfg)

    assert [f.verdict for f in verified] == ["TRUE_POSITIVE"]
    assert dropped == []
    # The legacy leg keeps the registry signature: no deepagents-only kwargs
    # (graph_name/sdk_cfg/openai_cfg/cfg_dir) leak in.
    assert set(captured) == {"user_prompt", "model", "system_prompt",
                             "allowed_tools", "cwd", "max_budget_usd",
                             "max_turns", "tag"}
    assert captured["model"] is node


def test_deepagents_unparseable_reply_drops_as_verify_error(monkeypatch):
    """Verdict parse parity on the route: a reply with no VERDICT trailer is
    an undetermined result and must drop as VERIFY_ERROR, exactly as on the
    legacy vias — the route only moves transport, never the parser."""
    _fail_registry(monkeypatch)
    cfg = _cfg(SimpleNamespace(id="claude-test", via="deepagents"))
    monkeypatch.setattr(s6_verify._deepagents, "agentic",
                        lambda *_a, **_k: "I could not reach a conclusion.")

    verified, dropped = s6_verify.run([_finding()], _ctx(), cfg)

    assert verified == []
    assert [d.reason for d in dropped] == ["VERIFY_ERROR"]
    assert dropped[0].detail == "verifier output unparseable"


def test_deepagents_via_mutating_tool_fails_closed(monkeypatch):
    """A mutating tool on the deepagents via must raise in run() before any
    model call — the strict read-only rule applies to every non-cli via."""
    _fail_registry(monkeypatch)
    _fail_wrapper(monkeypatch)
    cfg = _cfg(SimpleNamespace(id="claude-test", via="deepagents"))
    cfg.step6_verify.allowed_tools = ["Read", "Bash"]

    with pytest.raises(ValueError, match=r"step6_verify\.allowed_tools"):
        s6_verify.run([_finding()], _ctx(), cfg)
