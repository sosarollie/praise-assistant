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

"""EV verify flow — shim wiring + end-to-end verify_finding.

Hermetic: ``agent.run_loop`` is stubbed (or its delegate ``backends.llm.registry.agentic``
patched) and the HTTP send (``executor._core._send``) is faked; no LLM, no sockets.
The end-to-end tests exercise the two-tier flow: deterministic first-set → oracle →
adaptive loop. The adaptive loop itself now lives in ``backends.llm.sdk.agentic`` (the
attacker loop delegates to it); its mechanics are tested in tests/test_backend_sdk.py.
"""
from __future__ import annotations

import html
from types import SimpleNamespace

import pytest

from vvaharness.exploit_verification.auth import AuthConfig
from vvaharness.exploit_verification.collection.model import EndpointHint
from vvaharness.exploit_verification.executor import EvResponse
import vvaharness.exploit_verification.executor._core as core_mod
from vvaharness.exploit_verification.mapping import EndpointMatch
from vvaharness.exploit_verification.options import EVOptions
from vvaharness.backends.llm import deepagents as _da_backend
from vvaharness.exploit_verification.verify import _da_attacker
from vvaharness.exploit_verification.verify import agent
from vvaharness.exploit_verification.verify import agent as agent_mod
from vvaharness.exploit_verification.verify import run as run_mod
from vvaharness.exploit_verification.verify.model import Verdict
from vvaharness.report.cvss import score as cvss_score
from test_ev_config import ev_block


# ── fake model messages ──────────────────────────────────────────────────────

def _text(t):
    return SimpleNamespace(type="text", text=t)


def _tool(id, name, inp):
    return SimpleNamespace(type="tool_use", id=id, name=name, input=inp)


def _msg(stop, content):
    return SimpleNamespace(stop_reason=stop, content=content, usage=None)


# ── loop mechanics (agent.run_loop in isolation) ─────────────────────────────

def test_attacker_system_prompt_carries_the_auth_posture():
    """The attacker is told the run's posture so it tests auth deliberately."""
    from vvaharness.exploit_verification.verify import prompt
    p = prompt.system_prompt("No credential is configured this run.")
    assert "AUTH POSTURE." in p and "No credential is configured this run." in p
    # omitted → a neutral note, never an empty section
    assert "auth presented" in prompt.system_prompt().lower()


def test_run_loop_delegates_to_llm_agentic_with_ev_tools(monkeypatch):
    """run_loop is a thin adapter over backends.llm.registry.agentic: it hands the loop
    http_request tool (plus any extras) and a dispatch that routes http_request to the
    handler, defers other names to extra_dispatch, and rejects the unknown. llm.agentic
    dispatches on the model node's via (sdk/openai); the loop mechanics live in the
    backend and are tested in tests/test_backend_sdk.py and tests/test_backend_oai.py."""
    from vvaharness.backends.llm import registry as llm
    captured = {}

    def fake_agentic(user, **kw):
        captured.update(kw)
        captured["user"] = user
        return "FINAL"

    monkeypatch.setattr(llm, "agentic", fake_agentic)
    extra = {"name": "attack_path", "description": "x",
             "input_schema": {"type": "object", "properties": {}}}
    out = agent.run_loop(
        "SYS", "USR", lambda a: "H" * 9000, model="m",
        max_turns=7, max_tool_result_chars=200,
        extra_tools=[extra],
        extra_dispatch=lambda n, a: ("P" * 9000) if n == "attack_path" else None)

    assert out == "FINAL"
    # No read tools were supplied here, so none are named for the runtime to advertise
    assert captured["allowed_tools"] == []
    assert captured["system_prompt"] == "SYS" and captured["user"] == "USR"
    assert captured["max_turns"] == 7
    # the backend seam is just tools + dispatch — no cap / log / max_tokens flags
    for k in ("max_tokens", "max_tool_result_chars", "log_tools"):
        assert k not in captured
    names = [t["name"] for t in captured["extra_tools"]]
    assert names[0] == agent.SCHEMA["name"] and "attack_path" in names   # http first
    d = captured["extra_dispatch"]
    # http_request -> handler, capped on EV's side (head+tail, middle elided)
    r_http = d(agent.SCHEMA["name"], {"path": "/x"})
    assert r_http.startswith("H") and len(r_http) < 9000 and "elided by EV" in r_http
    # extra tool -> extra_dispatch, also capped on EV's side
    r_path = d("attack_path", {})
    assert r_path.startswith("P") and len(r_path) < 9000 and "elided by EV" in r_path
    assert d("bogus", {}).startswith("ERROR")                     # unknown -> not capped


def test_run_loop_never_advertises_a_tool_name_twice(monkeypatch):
    """Regression: read tools are the RUNTIME's to advertise and EV's to execute.

    `build_loop_tools` hands run_loop schemas for Read/Glob/Grep, and the backend adds
    localtools for the names in `allowed_tools`. Passing the read schemas through
    `extra_tools` as well put each name in the request twice, and the Anthropic API rejects
    a duplicate name outright ("tools: Tool names must be unique") — which killed the whole
    adaptive loop on turn 1, on every finding, for both `via: sdk` and `via: openai`.

    So: read names go to `allowed_tools` (advertised once, rooted at the repo), everything
    the runtime cannot supply goes to `extra_tools`, and EV's dispatch still executes the
    read tools itself so the per-result cap survives.
    """
    from vvaharness.backends.llm import registry as llm
    from vvaharness.backends.llm.models import DEFAULT_READ_TOOLS
    captured = {}
    monkeypatch.setattr(llm, "agentic", lambda user, **kw: captured.update(kw) or "FINAL")

    def _schema(name):
        return {"name": name, "description": "x",
                "input_schema": {"type": "object", "properties": {}}}

    agent.run_loop(
        "SYS", "USR", lambda a: "H", model="m", repo_root="/repo",
        extra_tools=[*(_schema(n) for n in DEFAULT_READ_TOOLS), _schema("attack_path")],
        extra_dispatch=lambda n, a: "OUT")

    advertised = (list(captured["allowed_tools"])
                  + [t["name"] for t in captured["extra_tools"]])
    assert len(advertised) == len(set(advertised)), f"duplicate tool names: {advertised}"
    assert list(captured["allowed_tools"]) == list(DEFAULT_READ_TOOLS)
    # EV advertises only what no runtime can supply
    assert [t["name"] for t in captured["extra_tools"]] == [agent.SCHEMA["name"],
                                                            "attack_path"]
    # and the read tools are rooted at the target repo, not the harness cwd
    assert captured["cwd"] == "/repo"
    # EV still executes them, so its cap and logging remain in force
    assert captured["extra_dispatch"]("Read", {"path": "app.py"}) == "OUT"


def _finding():
    return SimpleNamespace(file="app.py", line_start=46, title="Reflected XSS via name",
                           description="xss in name", cwe="CWE-79", vuln_class="injection",
                           exploit_scenario="GET /greet?name=x", code_snippet="", sink_ref="app.py:47")


def _match():
    ep = EndpointHint(method="GET", path="/greet", query_params={"name": "guest"})
    return EndpointMatch(endpoint=ep, method="GET", param="name", location="query")


def _opts():
    return EVOptions(enabled=True, target_url="http://127.0.0.1:5000",
                     safe_mode=True)


def _cfg():
    # models.verify is a bare string → via:cli → no via:sdk node → the adaptive loop
    # is off. The tier-2 tests below turn it on by patching `run._ev_model`.
    return SimpleNamespace(models=SimpleNamespace(verify="m"),
                           step6_exploit_verification=ev_block())


def test_first_set_reflection_without_a_judge_does_not_confirm(monkeypatch):
    """The oracle DETECTS the reflected marker (subtype/param preserved), but a live verdict
    is the judge's to give — with no judge configured, `_cfg()` here reaches no live verdict
    and the finding is INCONCLUSIVE, falling to static. The confirm path, with a judge that
    ratifies the tell, is test_deterministic_backed_when_tell_fires_and_judge_agrees; the
    oracle's detection in isolation is test_ev_oracle.test_xss_marker_reflected_confirms."""
    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        payload = " ".join(str(v) for v in (params or {}).values())
        return EvResponse(200, f"<html>hi {payload}</html>", url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)

    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE" and v.subtype == "xss"       # detected, not confirmed
    assert "requires the confirmation authority" in v.evidence


def test_first_set_escaped_without_a_judge_is_inconclusive_not_refuted(monkeypatch):
    """A live verdict — including NOT_CONFIRMED — is the judge's to give. Without a judge the
    oracle's deterministic 'escaped → not confirmed' is not published as a refutation either;
    the outcome is INCONCLUSIVE and falls to static. (Oracle refutation in isolation:
    test_ev_oracle.test_xss_escaped_refuted.)"""
    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        payload = " ".join(str(v) for v in (params or {}).values())
        return EvResponse(200, f"<html>hi {html.escape(payload)}</html>", url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)

    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"


def test_no_endpoint_is_inconclusive():
    v = run_mod.verify_candidate(_finding(), [], _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"


def test_one_request_budget_is_shared_across_a_findings_mapped_endpoints(monkeypatch):
    """`max_requests_per_finding` is per FINDING, spanning every endpoint it maps to — not
    per endpoint. verify_candidate threads one budget through each verify_finding call, so a
    finding that confirms on none of its endpoints cannot exceed the single cap however many
    endpoints it maps to. Without the shared budget each endpoint would spend a fresh cap."""
    sent: list = []

    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        sent.append(url)
        return EvResponse(200, "ok", url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)

    cfg = SimpleNamespace(models=SimpleNamespace(verify="m"),
                          step6_exploit_verification=ev_block(**{"max_requests_per_finding": 3}))
    ep1 = EndpointHint(method="GET", path="/greet", query_params={"name": "guest"})
    ep2 = EndpointHint(method="GET", path="/hello", query_params={"name": "guest"})
    matches = [EndpointMatch(endpoint=ep1, method="GET", param="name", location="query"),
               EndpointMatch(endpoint=ep2, method="GET", param="name", location="query")]
    run_mod.verify_candidate(_finding(), matches, _opts(), AuthConfig(), cfg=cfg)
    assert len(sent) <= 3               # ONE budget across both endpoints, not 3 per endpoint


# ── tier-2: the INDEPENDENT judge rules on the transcript ─────────────────────
#
# The attacker never confirms itself: run_loop only sends payloads (they land in
# the transcript), and a separate judge decides — then only when a real request
# reached the app. These tests stub the loop to send a request and stub the judge.

#: What the attacker claims it achieved. `run.py` discards run_loop's final text, so
#: this string must never reach the judge — the judge rules on the transcript alone.
_NARRATION = "I-SUCCESSFULLY-EXPLOITED-THIS-TRUST-ME"


def _loop_that_lands(monkeypatch, status=200, text="app-specific success"):
    """Enable the loop and have it send one request with the given response."""
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))

    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        return EvResponse(status, text, url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)

    def fake_run_loop(system, user, handler, *, model, max_turns=15, client=None, **kw):
        handler({"method": "GET", "path": "/greet", "query": {"name": "probe"}})
        return _NARRATION                               # deliberately not consulted
    monkeypatch.setattr(agent_mod, "run_loop", fake_run_loop)


def test_tier2_judge_confirms_with_live_signal(monkeypatch):
    _loop_that_lands(monkeypatch)
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "exploited", "why_not_benign": "the marker came back unescaped", "proof_index": None,
                                         "evidence": "leaked other users' data", "reasoning": "x"})
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED" and v.confidence == "medium" and v.method == "agent-judged"
    assert "leaked other users' data" in v.evidence


def test_tier2_judge_says_no_is_not_confirmed(monkeypatch):
    _loop_that_lands(monkeypatch)
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "refuted", "proof_index": None,
                                         "evidence": "response is a normal 200", "reasoning": "x"})
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status != "CONFIRMED"


def test_tier2_judge_not_called_without_live_signal(monkeypatch):
    # a flat 404 is not a live signal → the judge must not even be consulted
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(core_mod, "_send",
                        lambda m, url, **k: EvResponse(404, "nope", url=url, method=m))
    monkeypatch.setattr(agent_mod, "run_loop",
                        lambda s, u, h, *, model, max_turns=15, client=None, **kw:
                        (h({"method": "GET", "path": "/greet", "query": {"name": "p"}}), "")[1])
    called = []
    monkeypatch.setattr(run_mod.judge, "judge", lambda *a, **k: called.append(1) or {"verdict": "exploited", "why_not_benign": "the marker came back unescaped"})
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status != "CONFIRMED" and called == []


def test_tier2_judge_failure_does_not_confirm(monkeypatch):
    # judge returns None (call failed / unparseable) → no confirmation, no fallback to yes
    _loop_that_lands(monkeypatch)
    monkeypatch.setattr(run_mod.judge, "judge", lambda *a, **k: None)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status != "CONFIRMED"


def test_attacker_narration_never_reaches_the_judge(monkeypatch):
    """`run_loop`'s final text is discarded, so the judge cannot be talked into a yes.

    The loop returns a boast; the judge must receive only the finding, the match and
    the transcript. Asserted over every argument it is handed, positional or keyword.
    """
    _loop_that_lands(monkeypatch)
    seen = {}

    def spy_judge(*args, **kwargs):
        seen["args"], seen["kwargs"] = args, kwargs
        return {"verdict": "refuted", "proof_index": None, "evidence": "e", "reasoning": "r"}
    monkeypatch.setattr(run_mod.judge, "judge", spy_judge)

    run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert seen, "the judge was never called — the narration guard proves nothing"
    handed = repr(seen["args"]) + repr(seen["kwargs"])
    assert _NARRATION not in handed


# ── judge is the authority; the oracle tell is evidence ───────────────────────

def _reflecting_send(monkeypatch):
    """A send that echoes the payload back — the xss marker reflects, so the oracle
    tell fires on the first set."""
    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        payload = " ".join(str(v) for v in (params or {}).values())
        return EvResponse(200, f"<html>hi {payload}</html>", url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)


def test_deterministic_backed_when_tell_fires_and_judge_agrees(monkeypatch):
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(agent_mod, "run_loop", lambda *a, **k: "")   # loop always runs now; keep it hermetic
    _reflecting_send(monkeypatch)
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "exploited", "why_not_benign": "the marker came back unescaped", "proof_index": None,
                                         "evidence": "reflected", "reasoning": "x",
                                         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                         "cvss_score": 6.1})
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED" and v.method == "deterministic-backed"
    assert v.confidence == "high"                 # keeps the oracle's calibrated confidence
    assert v.cvss_vector.startswith("CVSS:3.1") and v.cvss_score == 6.1


def test_judge_confidence_carries_onto_the_verdict(monkeypatch):
    """The judge's 0-10 confidence flows onto the verdict as judge_confidence, whatever the
    outcome — here an agent-judged confirm."""
    _judge_says(monkeypatch, confidence=8)
    _loop_that_lands(monkeypatch)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED" and v.judge_confidence == 8


def test_confidence_score_falls_back_to_the_proof_tier(monkeypatch):
    """When the judge gave no number (a self-evidencing tell that stood without a ruling, or
    a pre-judge exit), the router derives a 0-10 from the proof tier so a live-tested finding
    always carries one."""
    from vvaharness.exploit_verification.verify import router
    from vvaharness.exploit_verification.verify.model import Verdict
    assert router._confidence_score(Verdict(judge_confidence=6, confidence="low")) == 6  # judge wins
    assert router._confidence_score(Verdict(judge_confidence=None, confidence="high")) == 9
    assert router._confidence_score(Verdict(judge_confidence=None, confidence="medium")) == 6
    assert router._confidence_score(Verdict(judge_confidence=None, confidence="low")) == 3


def test_the_probe_agent_cannot_self_report_confidence():
    """judge_confidence is the judge's, derived from the real transcript — the attacker-side
    agent must not be able to score its own certainty, so it is absent from the probe schema."""
    from vvaharness.exploit_verification.verify.model import Verdict
    assert "judge_confidence" not in Verdict.schema_json_compact()


def test_judge_overturns_a_deterministic_tell(monkeypatch):
    # judge is the authority: an explicit "not exploited" overrides a fired tell.
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(agent_mod, "run_loop", lambda *a, **k: "")   # no extra probes
    _reflecting_send(monkeypatch)
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "refuted", "evidence": "just an echo"})
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status != "CONFIRMED"


def test_judge_no_ruling_confirms_nothing_even_with_a_self_evidencing_tell(monkeypatch):
    """A live verdict is the judge's to give. When the judge returns no usable verdict
    (model down / unparseable), EV reaches none — not even a self-evidencing tell (a marker
    WE minted, reflected back) is published as a confirmation in the judge's place. The tell
    is recorded as evidence; the outcome is INCONCLUSIVE and the finding falls to static.

    Regression: the no-ruling branch used to stamp a self-evidencing tell CONFIRMED with no
    confirmation authority behind it."""
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(agent_mod, "run_loop", lambda *a, **k: "")   # loop always runs now; keep it hermetic
    _reflecting_send(monkeypatch)
    monkeypatch.setattr(run_mod.judge, "judge", lambda *a, **k: None)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"
    assert v.method != "deterministic-backed"
    assert "requires the judge" in v.evidence


def test_judge_no_ruling_confirms_nothing_with_an_inferential_tell(monkeypatch):
    """The same rule for a weaker tell: a `medium` inference (authz differential, timing,
    missing header) also yields INCONCLUSIVE when the judge is absent. Neither strength of
    tell confirms without the confirmation authority."""
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(run_mod.agent, "run_loop", lambda *a, **k: "")
    monkeypatch.setattr(run_mod.judge, "judge", lambda *a, **k: None)
    # An oracle that fires at `medium` — the shape of authz / headers / time-based.
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="CONFIRMED", subtype="authz", confidence="medium",
        evidence="no credential was presented and the endpoint returned 200 with data"))
    _reflecting_send(monkeypatch)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"
    assert v.method != "deterministic-backed"


# ── one judge, at the end; the loop always runs first ─────────────────────────
#
# There is no mid-judge and no deterministic short-circuit: even a finding the first set
# already tells on goes through the attacker loop, so the loop can raise a mechanism-only
# tell to the claimed consequence. The judge then rules exactly once, on the fullest
# transcript.

def test_the_loop_runs_even_when_the_first_set_already_confirms(monkeypatch):
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    _reflecting_send(monkeypatch)                     # first-set marker reflects → oracle CONFIRMED
    called = []
    monkeypatch.setattr(agent_mod, "run_loop",
                        lambda *a, **k: called.append(1) or "")
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "exploited",
                                         "why_not_benign": "the marker came back unescaped",
                                         "evidence": "reflected"})
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert called == [1]                              # the loop ran despite the first-set tell
    assert v.status == "CONFIRMED"


def test_the_judge_is_called_exactly_once(monkeypatch):
    """The mid-judge is gone: a live transcript is adjudicated once, at the end."""
    _loop_that_lands(monkeypatch)
    calls = []
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: calls.append(1) or {"verdict": "refuted",
                                                            "evidence": "normal 200"})
    run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert calls == [1]


# ── CVSS: PR:N is impossible when the proving request was credentialed ────────
#
# The judge scores from the transcript, which shows requests and responses but not what
# authenticated them — so an exploit only reachable with a valid credential can be
# scored as needing none. `auth_applied` is measured, so it settles the question.

def _judge_vector(monkeypatch, vector):
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(run_mod.agent, "run_loop", lambda *a, **k: "")
    monkeypatch.setattr(run_mod.judge, "judge", lambda *a, **k: {
        "verdict": "exploited", "why_not_benign": "the marker came back unescaped", "proof_index": 0, "control_index": None,
        "evidence": "malformed input returned 500", "reasoning": "r",
        "cvss_vector": vector, "cvss_score": 7.5})


def _send_500_with_credential(monkeypatch, auth_applied=("header:authorization",)):
    """A send whose request is recorded as having presented a credential."""
    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        return EvResponse(500, "Internal Server Error", url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)
    real = core_mod.auth_mod.channels_present
    monkeypatch.setattr(core_mod.auth_mod, "channels_present",
                        lambda h, p, a, **k: frozenset(auth_applied) or real(h, p, a, **k))


def test_pr_none_is_corrected_when_the_proving_request_was_credentialed(monkeypatch):
    _judge_vector(monkeypatch, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L")
    _send_500_with_credential(monkeypatch)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED"
    assert "/PR:L/" in v.cvss_vector and "/PR:N/" not in v.cvss_vector
    assert v.cvss_score == cvss_score(v.cvss_vector)     # rescored, not left stale
    assert "CVSS corrected" in v.evidence


def test_pr_none_is_left_alone_when_the_request_presented_nothing(monkeypatch):
    """The access-control case: an unauthenticated request IS the exploit, so PR:N is
    correct and must not be clamped."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    _judge_vector(monkeypatch, vector)
    _send_500_with_credential(monkeypatch, auth_applied=())
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.cvss_vector == vector
    assert "CVSS corrected" not in v.evidence


# ── the judge must rule out the innocent reading before it confirms ───────────
#
# A succeeding request cannot by itself show a check is missing: an AUTHORIZED caller's
# request succeeds too, and the two are indistinguishable on the wire. So the judge names
# the most plausible benign reading and what in the bytes rules it out, and a confirm that
# rules out nothing becomes `insufficient_evidence`. One rule for every finding class —
# no per-class conditions.

def _judge_says(monkeypatch, **reply):
    base = {"verdict": "exploited", "why_not_benign": "the marker came back unescaped", "proof_index": 0, "control_index": None,
            "evidence": "two permitted values produced different scores", "reasoning": "r",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", "cvss_score": 4.3}
    base.update(reply)
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(run_mod.agent, "run_loop", lambda *a, **k: "")
    monkeypatch.setattr(run_mod.judge, "judge", lambda *a, **k: base)
    _reflecting_send(monkeypatch)


def test_the_prompt_demands_the_benign_reading_be_ruled_out():
    """The prompt must pose the question the contract enforces, and offer the third
    answer — that combination is what replaces the per-CWE branches."""
    from vvaharness.exploit_verification.verify import judge as J
    low = J._SYSTEM.lower()
    assert "insufficient_evidence" in low            # the third answer exists
    assert "benign_explanation" in low and "why_not_benign" in low
    assert "authorized" in low and "succeed" in low   # the access-control trap
    assert "not exploitation" in low                  # the behaviour-vs-violation trap


def test_the_attacker_is_briefed_to_the_judges_bar():
    """The attacker's stop condition must match what the judge will accept, or it quits on
    mechanism-only evidence the judge then rejects — after the budget is already spent."""
    from vvaharness.exploit_verification.verify import prompt as P
    low = P._SYSTEM.lower()
    assert "mechanism" in low and "consequence" in low   # mechanism ≠ the claim
    assert "not disclosure" in low                       # your own input coming back
    assert "not a leak" in low                           # a generic error body
    assert "turn budget" in low and "not the finish line" in low   # do not stop early
    # and it still must not render the verdict itself
    assert "do not decide the verdict" in low


def test_what_ruled_out_the_benign_reading_is_surfaced(monkeypatch):
    _judge_says(monkeypatch, why_not_benign="invoice 4021 came back with a foreign owner_id")
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED"
    assert "benign reading ruled out by: invoice 4021 came back" in v.evidence


def test_insufficient_evidence_is_inconclusive_not_refuted(monkeypatch):
    """The answer a binary contract could not express. NOT_CONFIRMED means refuted; a
    transcript that merely fails to settle the question is INCONCLUSIVE."""
    _judge_says(monkeypatch, verdict="insufficient_evidence",
                benign_explanation="html.escape neutralised the payload")
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="NOT_CONFIRMED", subtype="", confidence="low"))
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"
    assert "does not establish it" in v.evidence
    assert "html.escape neutralised the payload" in v.evidence


def test_a_confirm_with_no_reason_is_downgraded_at_the_boundary(monkeypatch):
    """The rule lives in the judge's parse, so a caller cannot forget to apply it:
    verdict "exploited" with nothing ruling out the benign reading IS
    insufficient_evidence by the time anyone sees it."""
    from vvaharness.exploit_verification.verify import judge as J
    import json as _json
    out = J.judge(_finding(), _match(),
                  [SimpleNamespace(payload_label="p", method="GET", url="http://t/x",
                                   params={}, body=None, injection_point="", authed=True,
                                   response=SimpleNamespace(status=200, text="ok",
                                                            headers={}, elapsed=0.1,
                                                            error=None))],
                  model="m",
                  call=lambda s, u, *, model: _json.dumps(
                      {"verdict": "exploited", "why_not_benign": None}))
    assert out["verdict"] == "insufficient_evidence"


def test_a_self_evidencing_tell_does_not_override_an_insufficient_judge(monkeypatch):
    """The judge is handed the tell as strong proof; if it weighs it and still rules the
    evidence insufficient, the oracle does NOT overturn that verdict — a tell only backs a
    confirmation the judge makes, it never manufactures one the judge declined.

    Regression: a minted marker echoed in a JSON response (not an HTML sink) was stamped
    CONFIRMED over the judge's correct 'insufficient'. The judge saw the same bytes and
    read them right; the deterministic override was the bug. Contrast
    test_judge_no_ruling_confirms_nothing_even_with_a_self_evidencing_tell — a judge that
    cannot rule at all is the separate fallback, and now also yields INCONCLUSIVE."""
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(run_mod.agent, "run_loop", lambda *a, **k: "")
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "insufficient_evidence",
                                         "benign_explanation": "the marker reflected into a JSON body, not an HTML sink"})
    _reflecting_send(monkeypatch)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"
    assert v.method != "deterministic-backed"
    assert "does not establish it" in v.evidence


def test_an_inferential_tell_does_not_survive_insufficient_evidence(monkeypatch):
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(run_mod.agent, "run_loop", lambda *a, **k: "")
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "insufficient_evidence"})
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="CONFIRMED", subtype="authz", confidence="medium",
        evidence="an unauthenticated 200"))
    _reflecting_send(monkeypatch)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"


# ── four model purposes, resolved independently ──────────────────────────────
#
# EV does four different jobs and used to point all of them at one role (`deepdive` by
# default), which meant the ATTACKER and the JUDGE were necessarily the same model — so
# the judge's independence was structural only and could not be configured. It also
# demanded `via: sdk` for every purpose, though only the attacker needs it, which is why
# a login-only profile silently lost its confirmation authority and let the deterministic
# oracle decide alone.

def _models(**purposes):
    """A cfg whose models.exploit_verification carries exactly these sub-roles."""
    return SimpleNamespace(
        models=SimpleNamespace(exploit_verification=SimpleNamespace(**purposes)),
        step6_exploit_verification=ev_block())


def _node(via, mid="m-1"):
    return SimpleNamespace(id=mid, via=via)


def test_each_purpose_resolves_its_own_model():
    cfg = _models(attacker=_node("sdk", "atk"), judge=_node("cli", "jdg"),
                  classify=_node("openai", "cls"), mapper=_node("cli", "map"))
    got = {p: run_mod._model_id(run_mod._ev_model(cfg, p))
           for p in run_mod._EV_PURPOSES}
    assert got == {"attacker": "atk", "judge": "jdg",
                   "classify": "cls", "mapper": "map"}


@pytest.mark.parametrize("via", ["cli", "openai"])
def test_the_judge_runs_on_any_backend(via):
    """The point of the split. Adjudication is a one-shot prompt — every backend's
    `prompt()` takes a system prompt — so pinning it to sdk only ever cost coverage."""
    assert run_mod._ev_model(_models(judge=_node(via)), "judge") is not None


@pytest.mark.parametrize("via", ["sdk", "openai", "deepagents"])
def test_attacker_allowed_on_tool_carrying_backends(via):
    """The adaptive loop supplies its own `http_request` tool. The Messages/Chat backends
    (sdk, openai) carry it directly; `deepagents` carries it via a tool_builder on the
    DeepAgents runtime — so the attacker is allowed on all three."""
    assert run_mod._ev_model(_models(attacker=_node(via)), "attacker") is not None


@pytest.mark.parametrize("via", ["cli", "no-such-backend"])
def test_attacker_refused_off_tool_carrying_backends(via):
    """`via: cli` runs its loop in a subprocess and cannot carry a caller-supplied tool
    (an unknown backend can't either), so the attacker stands down and the deterministic
    oracle takes over."""
    assert run_mod._ev_model(_models(attacker=_node(via)), "attacker") is None


def test_run_loop_routes_a_deepagents_attacker_to_the_da_runner(monkeypatch):
    """A `via: deepagents` attacker node drives the DeepAgents runner (not the shared
    sdk/openai loop), threading repo_root + provider + creds, and hands it the SAME capped,
    logged dispatch closure: http_request -> handler, extra tools -> extra_dispatch, else
    an error string. The runner is stubbed, so this is hermetic."""
    captured = {}

    def fake_run(*, system, user, model, dispatch, http_schema, extra_tools,
                 max_turns, repo_root, model_provider, cfg):
        captured.update(
            system=system, user=user, http_schema=http_schema, extra_tools=extra_tools,
            max_turns=max_turns, repo_root=repo_root, model_provider=model_provider,
            cfg=cfg)
        captured["http_out"] = dispatch("http_request", {"method": "GET", "path": "/"})
        captured["extra_out"] = dispatch("attack_path", {})
        captured["unknown_out"] = dispatch("bogus", {})
        return "final-text"

    monkeypatch.setattr(_da_attacker, "run", fake_run)

    def handler(args):
        return "HTTP 200 ok"

    def extra_dispatch(name, args):
        return "PATH-JSON" if name == "attack_path" else None

    cfg = SimpleNamespace(sdk="SDK", openai="OAI")
    out = agent.run_loop(
        "SYS", "USER", handler, model=SimpleNamespace(id="m", via="deepagents"),
        max_turns=7, tool_schema={"name": "http_request", "input_schema": {}},
        extra_tools=[{"name": "attack_path", "input_schema": {}}],
        extra_dispatch=extra_dispatch, max_tool_result_chars=0,
        repo_root="/repo", model_provider="anthropic", cfg=cfg)

    assert out == "final-text"
    assert captured["system"] == "SYS" and captured["user"] == "USER"
    assert captured["max_turns"] == 7 and captured["repo_root"] == "/repo"
    assert captured["model_provider"] == "anthropic"
    assert captured["cfg"] is cfg
    assert captured["http_out"] == "HTTP 200 ok"        # http_request -> handler
    assert captured["extra_out"] == "PATH-JSON"          # other -> extra_dispatch
    assert "unknown tool" in captured["unknown_out"]     # unrecognised -> error string


@pytest.mark.parametrize("cfg", [
    None,
    SimpleNamespace(models=None),
    SimpleNamespace(models=SimpleNamespace()),                       # no EV block
    SimpleNamespace(models=SimpleNamespace(exploit_verification=SimpleNamespace())),
    SimpleNamespace(models=SimpleNamespace(                          # malformed node
        exploit_verification=SimpleNamespace(judge=SimpleNamespace(via="cli")))),
], ids=["no cfg", "no models", "no ev block", "no purpose", "node without id"])
def test_an_unusable_config_is_simply_absent(cfg):
    """Every "not configured" shape answers None rather than raising — callers degrade."""
    assert run_mod._ev_model(cfg, "judge") is None


def test_the_retired_single_model_field_is_ignored():
    """`step6_exploit_verification.model` was a role *pointer* and is no longer read;
    a config still carrying it must not resurrect the old one-model-for-everything path."""
    cfg = SimpleNamespace(
        models=SimpleNamespace(deepdive=_node("sdk", "deep")),
        step6_exploit_verification=ev_block(model="deepdive"))
    assert all(run_mod._ev_model(cfg, p) is None for p in run_mod._EV_PURPOSES)


def test_no_attacker_keeps_the_judge_and_drops_only_the_loop(monkeypatch):
    """A login-only deployment can configure a judge without an sdk attacker. EV then
    runs the deterministic set and adjudicates it; only the extra probes are lost."""
    cfg = _models(judge=_node("cli"))                # no attacker at all
    called = []
    monkeypatch.setattr(run_mod.agent, "run_loop",
                        lambda *a, **k: called.append(1) or "")
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "exploited",
                                         "why_not_benign": "the marker came back unescaped",
                                         "evidence": "reflected"})
    _reflecting_send(monkeypatch)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=cfg)
    assert v.status == "CONFIRMED"                   # the judge still ruled
    assert called == []                              # the loop never ran


def test_no_judge_configured_confirms_nothing(monkeypatch):
    """With no judge role configured, the confirmation authority cannot run, and a live
    verdict is the judge's to give — so EV confirms nothing on the oracle alone. A fired
    tell is recorded as evidence, but the finding is INCONCLUSIVE and falls to the static
    verifier. (All shipped profiles declare a judge; this is the stripped-config path.)"""
    _reflecting_send(monkeypatch)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(),
                               cfg=_models(attacker=_node("sdk")))     # judge role omitted
    assert v.status == "INCONCLUSIVE"
    assert v.method != "deterministic-backed"
    assert "requires the confirmation authority" in v.evidence


# ── the judge cannot overturn a refusal on principle ─────────────────────────
#
# The oracle has two distinct reasons to return INCONCLUSIVE, and only it can tell them
# apart: "I found no tell" (the judge should decide) versus "this transcript cannot
# settle the claim at all" (nobody can decide). `_adjudicate` read only
# `status == "CONFIRMED"`, so both looked identical and a judge reasoning from the
# transcript could confirm what was never testable — an unauthenticated 200 on a run
# where no credential was ever presented, where the "authenticated" baseline IS the
# unauthenticated request.

_REFUSALS = [
    ("no credential to omit", "authz",
     "no credential was presented on any request, so dropping credentials cannot "
     "test authorization"),
    ("host tell speaks to no finding", "headers",
     "a host-level headers observation cannot speak to this finding"),
    ("subtype has no confirm path", "idor",
     "no reliable confirm path yet for this subtype"),
]


@pytest.mark.parametrize("label,subtype,why", _REFUSALS, ids=[r[0] for r in _REFUSALS])
def test_an_unverifiable_refusal_caps_a_judge_confirm(monkeypatch, label, subtype, why):
    """Whatever the judge says, a refused comparison cannot become CONFIRMED."""
    _judge_says(monkeypatch, why_not_benign="the response returned another user's row")
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="INCONCLUSIVE", subtype=subtype, confidence="low",
        unverifiable=True, evidence=why))
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE", label
    assert v.unverifiable is True                     # the reason survives downstream
    assert why in v.evidence                          # and says what was missing
    assert "cannot stand" in v.evidence


def test_a_withheld_noauth_tell_is_not_a_refusal_and_still_confirms(monkeypatch):
    """A mislabelled finding must not lose a real confirmation.

    An information-disclosure finding on a public endpoint can be classified `noauth` (its
    preconditions say "no authentication required", and the missing-auth tell fires on any
    public endpoint). The oracle rightly withholds that tell — the finding does not claim a
    missing-auth defect — but the transcript is a route-bound payload set that may still
    prove the disclosure, and the judge reads it independently. So the withheld tell must
    behave like "no tell", not like a refusal: `unverifiable` is reserved for claims no
    evidence could settle. See `oracle.confirm` and
    test_ev_oracle.test_noauth_inconclusive_without_corroboration for the other half.
    """
    _judge_says(monkeypatch,
                why_not_benign="the response body returned a plaintext password we never sent")
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="INCONCLUSIVE", subtype="noauth", confidence="low",
        evidence="the missing-authentication tell was withheld: this finding does not "
                 "claim a missing-authentication defect"))     # unverifiable stays False
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED" and v.method == "agent-judged"


def test_no_tell_available_is_not_a_refusal_and_still_confirms(monkeypatch):
    """The other half of the rule. A subtype with no deterministic coverage at all (the
    agentic route) is not a refusal — there is nothing to check, so the judge remains the
    authority and its confirmation stands."""
    _judge_says(monkeypatch, why_not_benign="the injected marker came back verbatim")
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="INCONCLUSIVE", subtype="", confidence="low",
        evidence="no tell for this subtype"))        # unverifiable defaults to False
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED" and v.method == "agent-judged"


# ── a confirmation must be CLAIMED, not merely left unrefuted ─────────────────
#
# `_adjudicate` tests for "refuted", then for "insufficient_evidence", then reads the rest
# of the reply as a yes. `judge.judge` does guarantee that much — it validates at the parse
# boundary and returns None for anything outside the three-value enum, which `_adjudicate`
# turns into INCONCLUSIVE before it looks at the verdict at all. So these do not re-test
# that validation; they pin the DIRECTION the chain fails in if a reply ever gets past it,
# because the two mistakes do not cost the same. An unconfirmed finding is still verified
# statically downstream; a CONFIRMED assembled from the ABSENCE of a no is the one outcome
# EV must never reach, and "not refuted and not insufficient" would otherwise reach it.

_UNUSABLE_VERDICTS = [
    ("no verdict key at all",     {"evidence": "e", "confidence": 9}),
    ("verdict is null",           {"verdict": None, "why_not_benign": "x"}),
    ("verdict is unrecognised",   {"verdict": "definitely_pwned", "why_not_benign": "x"}),
    ("verdict is the wrong type", {"verdict": ["exploited"], "why_not_benign": "x"}),
]


@pytest.mark.parametrize("label,reply", _UNUSABLE_VERDICTS,
                         ids=[r[0] for r in _UNUSABLE_VERDICTS])
def test_a_reply_with_no_usable_verdict_never_becomes_a_confirmation(monkeypatch, label,
                                                                    reply):
    """Reached only by bypassing `judge.judge`'s own validation — which is exactly the
    scenario worth pinning, since that is what a future change to it would do."""
    _judge_says(monkeypatch)                    # wire the stubs, then replace the reply
    monkeypatch.setattr(run_mod.judge, "judge", lambda *a, **k: reply)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE", label
    assert "explicit confirmation" in v.evidence
    assert v.method != "agent-judged"           # nothing was judged, so nothing is stamped


def test_an_explicit_exploited_still_confirms(monkeypatch):
    """The control for the four above: the guard is an affirmative test, so it must not
    disturb the one verdict that does claim exploitation."""
    _judge_says(monkeypatch, why_not_benign="the response returned a row we never sent")
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED"


def test_the_probe_agent_cannot_self_report_unverifiable():
    """It is the oracle's soundness flag; an attacker-side agent must not be able to
    clear it, so it is absent from the schema the loop is shown."""
    assert "unverifiable" not in Verdict.schema_json_compact()


# ── a confirmation that scores 0.0 contradicts itself ────────────────────────

def test_a_confirm_scored_at_zero_impact_is_not_a_confirm(monkeypatch):
    """The judge said "exploited" and then scored every impact metric None. That is its
    own arithmetic disagreeing with its verdict, not a finding."""
    _judge_says(monkeypatch,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N",
                cvss_score=0.0)
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"
    assert "scored every impact metric None" in v.evidence


# ── a claim needing a second principal cannot be settled by one identity ──────
#
# Distinct from `unverifiable` above, which is the ORACLE refusing a comparison it was
# asked to make. This fires on the CLAIM, with no tell involved: some findings are only
# settled by showing what a DIFFERENT authenticated identity could reach, and EV runs as
# one identity, so no transcript it can produce today holds that comparison. A judge
# reading responses alone will take "a record came back for the id I sent" for the
# cross-principal claim it superficially resembles.

def test_a_claim_needing_a_second_identity_cannot_be_confirmed(monkeypatch):
    _judge_says(monkeypatch, requires_second_identity=True,
                why_not_benign="the response carries another tenant's record")
    # no self-evidencing tell — a cross-principal claim has none, and the guard only
    # spares hard proof (see the dedicated test below)
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="NOT_CONFIRMED", subtype="", confidence="low"))
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"
    assert v.unverifiable is True
    assert "single identity" in v.evidence


def test_the_second_identity_cap_outranks_an_inferential_tell(monkeypatch):
    """An inferential tell (medium — a differential, a timing delta) does not rescue the
    claim: it answers a different question than a cross-principal claim asks, and it is not
    unfakeable proof, so the cap stands."""
    _judge_says(monkeypatch, requires_second_identity=True)
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="CONFIRMED", subtype="authz", confidence="medium",
        evidence="an uncredentialed request returned 200 with data"))
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"


def test_the_second_identity_cap_does_not_discard_a_self_evidencing_tell(monkeypatch):
    """A fallible judge flag must not throw away unfakeable proof. A self-evidencing tell
    (a marker WE minted, an OOB callback) is evidence of THIS finding; no cross-principal
    claim has one, so this guard only ever refuses a malfunctioning judge — never a real
    second-identity case, which has no such tell to begin with."""
    _judge_says(monkeypatch, requires_second_identity=True)
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="CONFIRMED", subtype="xss", confidence="high",     # high == self-evidencing
        evidence="our minted marker reflected unescaped"))
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED" and v.method == "deterministic-backed"


def test_an_ordinary_confirm_is_not_capped(monkeypatch):
    """The other half of the rule: the default is False, so nothing changes for a finding
    whose claim one identity can settle."""
    _judge_says(monkeypatch)                     # requires_second_identity absent
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED"


# ── mechanism confirmed, claimed property not shown ──────────────────────────

def test_mechanism_only_is_recorded_distinctly_from_nothing_observed(monkeypatch):
    """"The defect is real, its claimed impact was not shown" and "nothing was observed"
    are different messages to a reviewer. A bare INCONCLUSIVE reads as the second."""
    _judge_says(monkeypatch, verdict="insufficient_evidence", mechanism_confirmed=True,
                evidence="status 500 with a generic body where the control returns 200")
    # no tell — a self-evidencing one legitimately outranks insufficient_evidence, which
    # is a different rule and already has its own test above
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="NOT_CONFIRMED", subtype="", confidence="low"))
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"
    assert v.mechanism_only is True
    assert "security consequence this finding claims was not shown" in v.evidence


def test_insufficient_evidence_without_a_mechanism_stays_the_plain_message(monkeypatch):
    _judge_says(monkeypatch, verdict="insufficient_evidence", mechanism_confirmed=False,
                benign_explanation="the caller was authorized")
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="NOT_CONFIRMED", subtype="", confidence="low"))
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "INCONCLUSIVE"
    assert v.mechanism_only is False
    assert "does not establish it" in v.evidence


def test_the_probe_agent_cannot_self_report_mechanism_only():
    """Like `unverifiable`, it is a soundness signal the attacker-side agent must not be
    able to clear."""
    assert "mechanism_only" not in Verdict.schema_json_compact()


# ── a confirm says why it matters, in plain language ─────────────────────────

def test_a_confirm_carries_the_plain_consequence(monkeypatch):
    """A confirmation a reviewer cannot act on is half-delivered: the evidence sentence
    quotes bytes, which shows THAT the property was violated without saying what it costs."""
    _judge_says(monkeypatch,
                plain_consequence="any logged-in user can read other customers' totals")
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED"
    assert "why it matters: any logged-in user can read other customers' totals" in v.evidence


def test_a_tell_backed_confirm_also_carries_it(monkeypatch):
    _judge_says(monkeypatch, plain_consequence="an unauthenticated caller reads the record")
    monkeypatch.setattr(run_mod.oracle, "confirm", lambda *a, **k: Verdict(
        status="CONFIRMED", subtype="authz", confidence="high", evidence="tell fired"))
    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED" and v.method == "deterministic-backed"
    assert "why it matters: an unauthenticated caller reads the record" in v.evidence


# ── probe logging: the payload must be visible, credentials must not be ───────
#
# Two send paths log a probe: the deterministic first set (`_log_probe_record`, from the
# transcript record) and the adaptive loop (`_logged_handler`, from the tool args). Both
# now render the request BODY — the actual payload on a JSON/POST target, previously
# omitted so a body-based probe showed only `POST /path -> 200`. The body is payload-only;
# credentials are injected as headers in `perform_request` and never reach these renderers.

def test_deterministic_probe_log_shows_the_body_payload(capsys):
    rec = SimpleNamespace(
        payload_label="sqli-1", method="post", url="http://t/api/score?x=1",
        params={"x": "1"}, body={"q": "1' OR '1'='1"},
        response=SimpleNamespace(status=200, error=None, elapsed=0.12))
    run_mod._log_probe_record(rec)
    line = capsys.readouterr().err
    assert "[sqli-1]" in line and "POST /api/score" in line
    assert "body={\"q\":\"1' OR '1'='1\"}" in line      # the injection is visible
    assert "HTTP 200" in line


def test_adaptive_handler_log_includes_the_body(capsys):
    handler = run_mod._logged_handler(lambda args: "HTTP 200 (12ms)")
    handler({"method": "post", "path": "/api/score", "body": {"name": "{{7*7}}"}})
    line = capsys.readouterr().err
    assert "POST /api/score" in line
    assert 'body={"name":"{{7*7}}"}' in line


def test_probe_body_is_truncated_and_empty_body_is_blank():
    assert run_mod._fmt_body(None) == "" and run_mod._fmt_body({}) == ""
    long = run_mod._fmt_body("A" * 500)
    assert long.endswith("…") and len(long) < 260       # capped, not the full 500


def test_baseline_record_is_labelled_baseline(capsys):
    from vvaharness.exploit_verification.verify.model import BASELINE_LABEL
    rec = SimpleNamespace(payload_label=BASELINE_LABEL, method="get", url="http://t/u",
                          params={}, body=None,
                          response=SimpleNamespace(status=200, error=None, elapsed=0.0))
    run_mod._log_probe_record(rec)
    assert "[baseline]" in capsys.readouterr().err


# The attacker loop now drives backends.llm.registry.agentic (see verify/agent.py); its
# cache-marker gate is covered by tests/test_backend_cache.py and its loop
# mechanics (tool dispatch, forced-final, tool-result cap) by tests/test_backend_sdk.py.


# ── probe sink: verify_finding hands its full transcript to the collector ─────
#
# The opt-in ev_probes log is fed by this sink — adding NO model calls (it reads the
# transcript EV already built). It must fire whatever the outcome, so every probe is
# captured, not just a confirmed finding's.

def test_verify_finding_feeds_the_probe_sink(monkeypatch):
    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        payload = " ".join(str(v) for v in (params or {}).values())
        return EvResponse(200, f"<html>hi {payload}</html>", url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)

    seen = []
    def sink(finding, match, subtype, cls_value, transcript, verdict):
        seen.append((subtype, cls_value, list(transcript), verdict.status))

    run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg(),
                           probe_sink=sink)
    assert seen, "sink was never called"
    subtype, cls_value, transcript, status = seen[-1]
    assert subtype == "xss"                     # the routed subtype was passed through
    assert transcript, "the sink got no probes"  # the deterministic set landed in it
    assert status in ("CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE")


def test_probe_sink_fires_even_when_not_confirmed(monkeypatch):
    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        payload = " ".join(str(v) for v in (params or {}).values())
        return EvResponse(200, f"<html>hi {html.escape(payload)}</html>", url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)
    seen = []
    run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg(),
                           probe_sink=lambda *a: seen.append(a))
    # The point is that the sink fires WHATEVER the outcome; with no judge configured the
    # verdict is INCONCLUSIVE (a live verdict needs the judge), and the transcript is still
    # captured for a later manual review.
    assert seen and seen[-1][-1].status == "INCONCLUSIVE"


# ── credentials must never reach the probe log ────────────────────────────────
#
# A payload can carry a token — EV_AUTH-injected, shipped in the collection, or one the
# attacker agent found in the target's own code and sent as a payload. The probe logger
# prints the request, so it must redact.

_JWT = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ0ZXN0LTEyMyJ9.c3ludGhldGljX3Rlc3Rfc2ln"


def test_probe_log_redacts_a_token_in_the_query(capsys):
    rec = SimpleNamespace(payload_label="", method="get",
                          url="http://t/api/session", params={"SESSIONID": _JWT},
                          body=None, response=SimpleNamespace(status=200, text="ok",
                                                              elapsed=0.1, error=None))
    run_mod._log_probe_record(rec)
    line = capsys.readouterr().err
    assert _JWT not in line and "SESSIONID=[REDACTED]" in line


def test_probe_log_redacts_a_jwt_in_the_body(capsys):
    handler = run_mod._logged_handler(lambda args: "HTTP 200 (5ms)")
    handler({"method": "post", "path": "/x", "body": {"note": _JWT, "password": "hunter2"}})
    line = capsys.readouterr().err
    assert _JWT not in line and "[REDACTED" in line and "hunter2" not in line


# ── nor the attacker's PROMPT, which leaves the machine ───────────────────────
#
# The block above is a local log; this one is egress. `_tried_block` renders the
# deterministic set's real responses into the attacker's user prompt — up to twenty of
# them, which is the largest single piece of target data the loop sends to a provider.

def _tx_rec(text="", error=None):
    return SimpleNamespace(payload_label="p1", injection_point="query.id",
                           response=SimpleNamespace(status=200, text=text,
                                                    elapsed=0.1, error=error))


def test_the_attacker_prompt_redacts_the_responses_it_replays():
    from vvaharness.exploit_verification import safety
    from vvaharness.exploit_verification.verify import prompt
    tok = "sess-9f2b1c7d4e8a0b3f6c2d"
    safety.register_secret(tok)
    block = "\n".join(prompt._tried_block([_tx_rec(text=f'{{"echoed":"{tok}"}}'),
                                          _tx_rec(error=f"ConnectError: token={tok}")]))
    assert tok not in block
    assert "[REDACTED]" in block


def test_the_attacker_prompt_masks_before_it_cuts_each_response():
    """Per-probe bodies are cut to `_TRIED_BODY_CAP`, and masking has to happen first: a
    credential straddling that cut would otherwise survive as a fragment no layer matches.
    Same trap as the sinks in test_ev_safety.py, on the prompt path."""
    from vvaharness.exploit_verification import safety
    from vvaharness.exploit_verification.verify import prompt
    tok = "sess-9f2b1c7d4e8a0b3f6c2d"
    safety.register_secret(tok)
    cap = prompt._TRIED_BODY_CAP
    body = "x" * (cap - 12) + tok                  # starts 12 bytes before the cut
    assert body.index(tok) == cap - 12             # the fixture itself must straddle
    block = "\n".join(prompt._tried_block([_tx_rec(text=body)]))
    assert tok[:12] not in block, "cut before masking — leaked a credential prefix"


def test_the_attacker_prompt_keeps_the_tell_it_must_adapt_from():
    """The counterweight: the point of replaying responses is that the loop reasons from
    them, so an error signature has to survive."""
    from vvaharness.exploit_verification.verify import prompt
    block = "\n".join(prompt._tried_block([_tx_rec(text="syntax error at or near \"'\"")]))
    assert "syntax error" in block


# ── profile knob → module wiring ───────────────────────────────────────────────
#
# Companion to the router-side wiring tests: the attacker and judge blocks are read in
# `verify_finding`, so their hand-off is pinned here. A dropped keyword is silent — the
# callee's signature default equals the shipped default, so nothing looks wrong until a
# tuned profile has no effect.

def test_attacker_knobs_reach_the_loop(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(run_mod, "_ev_model",
                        lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(core_mod, "_send",
                        lambda m, url, **k: EvResponse(200, "ok", url=url, method=m))

    def fake_run_loop(system, user, handler, *, model, **kw):
        seen.update(kw)
        return ""
    monkeypatch.setattr(agent_mod, "run_loop", fake_run_loop)
    monkeypatch.setattr(run_mod.judge, "judge", lambda *a, **k: None)

    cfg = SimpleNamespace(models=SimpleNamespace(verify="m"),
                          step6_exploit_verification=ev_block(**{
                              "attacker.max_turns": 4,
                              "attacker.max_tool_result_chars": 333}))
    run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=cfg)
    assert seen["max_turns"] == 4
    assert seen["max_tool_result_chars"] == 333


def test_the_attacker_block_can_switch_the_loop_off(monkeypatch):
    """`attacker.enabled: false` is the old flat `adaptive_loop: false`."""
    monkeypatch.setattr(run_mod, "_ev_model",
                        lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(core_mod, "_send",
                        lambda m, url, **k: EvResponse(200, "ok", url=url, method=m))
    monkeypatch.setattr(agent_mod, "run_loop",
                        lambda *a, **k: pytest.fail("the loop must not run"))
    monkeypatch.setattr(run_mod.judge, "judge", lambda *a, **k: None)

    cfg = SimpleNamespace(models=SimpleNamespace(verify="m"),
                          step6_exploit_verification=ev_block(**{"attacker.enabled": False}))
    run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=cfg)


def test_judge_knobs_reach_the_ruling(monkeypatch):
    seen: dict = {}
    _loop_that_lands(monkeypatch)

    def spy_judge(finding, match, transcript, **kw):
        seen.update(kw)
        return None
    monkeypatch.setattr(run_mod.judge, "judge", spy_judge)

    cfg = SimpleNamespace(models=SimpleNamespace(verify="m"),
                          step6_exploit_verification=ev_block(**{
                              "judge.max_tokens": 444, "judge.max_records": 5}))
    run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=cfg)
    assert seen["max_tokens"] == 444
    assert seen["max_records"] == 5


# ── the DeepAgents attacker runner (verify._da_attacker) ──────────────────────
# The attacker is the one role the read-only `deepagents.agentic` cannot carry, so it
# drives the adapter primitives with a tool_builder. Two seams, both hermetic: the
# Anthropic-schema -> LangChain-tool converter, and the StreamingOptions the runner
# hands the adapter (drain_streaming is stubbed, so no model / LangGraph runtime runs).

def _da_http_schema():
    return {
        "name": "http_request",
        "description": "send a request",
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "HTTP verb"},
                "path": {"type": "string"},
                "query": {"type": "object"},
            },
            "required": ["method", "path"],
        },
    }


def test_da_attacker_tool_from_schema_builds_a_named_tool_backed_by_dispatch():
    def dispatch(name, args):
        return "RESULT"

    tool = _da_attacker._tool_from_schema(_da_http_schema(), dispatch)

    assert tool.name == "http_request"
    assert tool.description == "send a request"
    # Every declared property becomes a field; required-ness is preserved.
    fields = tool.args_schema.model_fields
    assert set(fields) == {"method", "path", "query"}
    assert fields["method"].is_required() and fields["path"].is_required()
    assert not fields["query"].is_required()


def test_da_attacker_tool_invocation_routes_through_dispatch_and_drops_unset_optionals():
    seen = {}

    def dispatch(name, args):
        seen["call"] = (name, args)
        return "RESULT"

    tool = _da_attacker._tool_from_schema(_da_http_schema(), dispatch)
    out = tool.invoke({"method": "GET", "path": "/x"})

    assert out == "RESULT"
    # `query` was never set, so it is not forwarded to the executor.
    assert seen["call"] == ("http_request", {"method": "GET", "path": "/x"})


def test_da_attacker_run_builds_streaming_options_and_excludes_native_read_tools(monkeypatch):
    captured = {}

    def fake_drain(user, options):
        captured["user"] = user
        captured["options"] = options
        return SimpleNamespace()  # a terminal; terminal_text is stubbed below

    monkeypatch.setattr(_da_backend, "drain_streaming", fake_drain)
    monkeypatch.setattr(_da_backend, "build_harness_env", lambda *a, **k: {"E": "1"})
    monkeypatch.setattr(_da_backend, "terminal_text", lambda t: "final")

    out = _da_attacker.run(
        system="S", user="U", model=SimpleNamespace(id="m1", via="deepagents"),
        dispatch=lambda n, a: "x", http_schema=_da_http_schema(),
        extra_tools=[{"name": "attack_path", "input_schema": {}},
                     {"name": "Read", "input_schema": {}}],
        max_turns=9, repo_root="/repo", model_provider="openai",
        cfg=SimpleNamespace(sdk="S", openai="O"))

    assert out == "final" and captured["user"] == "U"
    opts = captured["options"]
    assert opts.model == "m1" and opts.model_provider == "openai"
    assert str(opts.cwd) == "/repo" and opts.max_turns == 9
    assert opts.system_prompt == "S" and opts.allow_writes is False
    assert opts.graph_name == "s6-ev-attacker"
    # Read tools are declared in the policy (served natively), not rebuilt.
    assert opts.tool_policy.allowed_tools == ("Read", "Glob", "Grep")
    # The tool_builder yields only the caller tools; the native Read is excluded.
    tools = opts.tool_builder(opts, allowed_tools=("Read", "Glob", "Grep"))
    assert sorted(t.name for t in tools) == ["attack_path", "http_request"]


def test_da_attacker_run_without_a_repo_declares_no_read_tools(monkeypatch):
    captured = {}
    monkeypatch.setattr(_da_backend, "drain_streaming",
                        lambda user, options: captured.setdefault("options", options))
    monkeypatch.setattr(_da_backend, "build_harness_env", lambda *a, **k: {})
    monkeypatch.setattr(_da_backend, "terminal_text", lambda t: "")

    _da_attacker.run(system="S", user="U", model=SimpleNamespace(id="m1", via="deepagents"),
                     dispatch=lambda n, a: "x", http_schema=_da_http_schema(),
                     extra_tools=None, max_turns=5, repo_root=None, model_provider=None)

    opts = captured["options"]
    assert opts.tool_policy.allowed_tools == ()      # no repo => no native read tools
    assert str(opts.cwd) == "."
    # http_request is still built even with no repo/extra tools.
    tools = opts.tool_builder(opts, allowed_tools=())
    assert [t.name for t in tools] == ["http_request"]
