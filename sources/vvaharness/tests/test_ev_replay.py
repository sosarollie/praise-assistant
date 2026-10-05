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

"""Replay-to-re-check (``ev-replay``): capture a confirming exchange, store it, and
re-decide whether a finding was remediated.

Hermetic: the HTTP send (``executor._core._send``) is faked and no model runs; the
capture tests build a transcript directly.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from types import SimpleNamespace

import pytest

import vvaharness.exploit_verification.executor._core as core_mod
from vvaharness.exploit_verification.executor import EvResponse
from vvaharness.exploit_verification.executor.model import RequestRecord
from vvaharness.exploit_verification.collection.model import EndpointHint
from vvaharness.exploit_verification.mapping import EndpointMatch
from vvaharness.exploit_verification.options import EVOptions
from vvaharness.exploit_verification.payloads.markers import mint_markers
from vvaharness.exploit_verification.replay.capture import bundle_from
from vvaharness.exploit_verification.replay.model import (MAX_BODY, ReplayBundle,
                                                         ReplayOutcome)
from vvaharness.exploit_verification.verify.model import BASELINE_LABEL, Verdict
from vvaharness.exploit_verification.verify.repro import detail_from_record
from vvaharness.exploit_verification.auth import AuthConfig
from vvaharness.exploit_verification.verify import run as run_mod


_BASE = "http://127.0.0.1:5000"


def _finding(**kw):
    base = dict(file="app.py", line_start=46, title="Reflected XSS via name",
                description="xss in name", cwe="CWE-79", vuln_class="injection",
                exploit_scenario="GET /greet?name=x", code_snippet="", sink_ref="app.py:47")
    base.update(kw)
    return SimpleNamespace(**base)


def _opts():
    return EVOptions(enabled=True, target_url=_BASE)


def _rec(label, params, *, body="", status=200, injection_point="", authed=True,
         sent_headers=None, url=f"{_BASE}/greet", method="GET", oob_nonce="",
         seq=0, auth_applied=()):
    return RequestRecord(
        method=method, url=url, params=params, authed=authed,
        payload_label=label, injection_point=injection_point,
        sent_headers=sent_headers or {}, oob_nonce=oob_nonce,
        seq=seq, auth_applied=frozenset(auth_applied),
        response=EvResponse(status, body, url=url, method=method, elapsed=0.01))


# ── capture: what gets stored ────────────────────────────────────────────────

def _confirmed_transcript(marker):
    baseline = _rec(BASELINE_LABEL, {"name": "guest"}, body="<html>hi guest</html>")
    payload = _rec("xss-0", {"name": marker}, injection_point="query.name",
                   sent_headers={"X-Probe": "1"}, body=f"<html>hi {marker}</html>")
    return [baseline, payload], payload


def test_bundle_captures_baseline_and_the_confirming_payload():
    f = _finding()
    markers = mint_markers(f)
    transcript, payload = _confirmed_transcript(markers.xss)
    verdict = Verdict(status="CONFIRMED", subtype="xss", param="name", category="active",
                      method="deterministic-backed", confidence="high",
                      repro_detail=detail_from_record(payload, "name"))

    b = bundle_from(f, None, transcript, verdict, _opts(), markers=markers)
    assert b is not None
    assert [r.payload_label for r in b.requests] == [BASELINE_LABEL, "xss-0"]
    assert b.requests[1].path == "/greet"                    # url re-based to route-only
    assert b.requests[1].query == {"name": markers.xss}
    assert b.requests[1].identity == "primary"
    assert b.requests[1].injection_point == "query.name"
    assert b.subtype == "xss" and b.cls == "active"
    assert b.ev_method == "deterministic-backed" and b.ev_confidence == "high"


def test_capture_picks_the_record_by_identity_not_by_value():
    """Two records identical in method/url/params/body but differing in identity are
    different probes. Matching on values alone returned whichever came first — the
    credentialed baseline — so an access-control bundle stored the wrong request as its
    "confirming" one and a replay re-sent the baseline, testing nothing.
    """
    f = _finding()
    markers = mint_markers(f)
    same = {"name": "guest"}
    baseline = _rec(BASELINE_LABEL, same, body="secret", seq=1,
                    auth_applied={"header:authorization"})
    unauthed = _rec("no_credentials", same, body="secret", seq=2, authed=False)
    verdict = Verdict(status="CONFIRMED", subtype="authz", method="deterministic-backed",
                      confidence="medium", repro_detail=detail_from_record(unauthed))

    b = bundle_from(f, None, [baseline, unauthed], verdict, _opts(), markers=markers)
    assert b.requests[-1].payload_label == "no_credentials"    # not the baseline
    assert b.requests[-1].identity == "none"
    assert b.authed is False


def test_bundle_stores_the_control_of_a_differential_proof():
    """A differential proof ("500 here, 200 there") is only reproducible if the other
    half is stored and identifiable. The control is often NOT the baseline."""
    f = _finding()
    markers = mint_markers(f)
    baseline = _rec(BASELINE_LABEL, {"v": "ok"}, body="fine", seq=1)
    control = _rec("well_formed", {"v": "3.1"}, body="fine", seq=2)
    proof = _rec("type_confusion", {"v": "3.1-as-float"}, status=500,
                 body="Internal Server Error", seq=3)
    verdict = Verdict(status="CONFIRMED", subtype="", method="agent-judged",
                      confidence="medium", control_seq=2,
                      repro_detail=detail_from_record(proof))

    b = bundle_from(f, None, [baseline, control, proof], verdict, _opts(), markers=markers)
    assert b.roles == ["baseline", "control", "confirming"]
    assert b.confirming_index() == 2 and b.control_index() == 1
    assert b.original[b.control_index()].status == 200
    assert b.original[b.confirming_index()].status == 500


def test_a_control_that_is_the_baseline_is_not_stored_twice():
    f = _finding()
    markers = mint_markers(f)
    baseline = _rec(BASELINE_LABEL, {"n": "g"}, body="secret", seq=1,
                    auth_applied={"header:authorization"})
    unauthed = _rec("no_credentials", {"n": "g"}, body="secret", seq=2, authed=False)
    verdict = Verdict(status="CONFIRMED", subtype="authz", control_seq=1,
                      method="deterministic-backed", confidence="medium",
                      repro_detail=detail_from_record(unauthed))
    b = bundle_from(f, None, [baseline, unauthed], verdict, _opts(), markers=markers)
    assert b.roles == ["baseline", "confirming"]
    assert b.confirming_index() == 1


def test_a_roleless_bundle_still_resolves_its_confirming_request():
    """Bundles written before roles existed keep replaying: baseline first, confirming
    last."""
    from vvaharness.exploit_verification.replay.model import (ReplayBundle, ReplayRequest)
    b = ReplayBundle(requests=[ReplayRequest(path="/a"), ReplayRequest(path="/b")])
    assert b.role_of(0) == "baseline" and b.role_of(1) == "confirming"
    assert b.confirming_index() == 1 and b.control_index() is None


def test_bundle_stores_the_minted_markers_not_a_remint():
    # The stored markers must be the ones baked into the stored payload — a re-mint
    # after remediation moves lines and would yield canaries that never match.
    f = _finding()
    markers = mint_markers(f)
    transcript, payload = _confirmed_transcript(markers.xss)
    verdict = Verdict(status="CONFIRMED", subtype="xss",
                      repro_detail=detail_from_record(payload, "name"))
    b = bundle_from(f, None, transcript, verdict, _opts(), markers=markers)
    assert b.markers["xss"] == markers.xss
    assert b.markers["token"] == markers.token


def test_bundle_caps_the_body_and_hashes_the_full_response():
    f = _finding()
    markers = mint_markers(f)
    long_body = "A" * 600                                     # > MAX_BODY
    baseline = _rec(BASELINE_LABEL, {"name": "guest"}, body="ok")
    payload = _rec("xss-0", {"name": markers.xss}, injection_point="query.name",
                   body=long_body)
    verdict = Verdict(status="CONFIRMED", subtype="xss",
                      repro_detail=detail_from_record(payload, "name"))
    b = bundle_from(f, None, [baseline, payload], verdict, _opts(), markers=markers)

    stored = b.original[1]
    assert len(stored.body) == MAX_BODY and stored.truncated is True
    assert stored.body_sha256 == hashlib.sha256(long_body.encode()).hexdigest()


def test_bundle_never_stores_credentials():
    # Only payload-controlled (pre-auth) headers are recorded; the executor never puts
    # auth on the record, so no bundle field should carry a credential.
    f = _finding()
    markers = mint_markers(f)
    payload = _rec("xss-0", {"name": markers.xss}, injection_point="query.name",
                   sent_headers={"X-Probe": "1"}, body=f"<html>{markers.xss}</html>")
    verdict = Verdict(status="CONFIRMED", subtype="xss",
                      repro_detail=detail_from_record(payload, "name"))
    b = bundle_from(f, None, [payload], verdict, _opts(), markers=markers)
    blob = b.model_dump_json().lower()
    assert "authorization" not in blob and "bearer" not in blob
    assert b.requests[0].headers == {"X-Probe": "1"}


def test_bundle_redacts_a_token_echoed_in_the_judge_evidence():
    # The judge quotes proving bytes from the raw response, so a token the target echoed
    # back can sit in verdict.evidence. Capture must scrub it before it lands in the
    # ev_replays row and the ev-replay report — the test above checks only the headers,
    # so an unredacted evidence string used to reach the store.
    f = _finding()
    markers = mint_markers(f)
    payload = _rec("xss-0", {"name": markers.xss}, injection_point="query.name", body="ok")
    jwt = "eyJhbGciOi.eyJzdWIiOi.aBcDeFgHiJ"                 # obviously-fake JWT shape
    verdict = Verdict(status="CONFIRMED", subtype="xss", method="agent-judged",
                      evidence=f"the auth endpoint echoed the token {jwt} in its body",
                      repro_detail=detail_from_record(payload, "name"))
    b = bundle_from(f, None, [payload], verdict, _opts(), markers=markers)
    assert jwt not in b.ev_evidence                          # raw token must not persist
    assert "[REDACTED-JWT]" in b.ev_evidence                 # masked with the JWT marker


def test_bundle_falls_back_to_best_effort_when_no_repro():
    # An agent-judged confirm may carry a repro_detail we can't match exactly; capture
    # falls back to the last landing payload rather than storing nothing.
    f = _finding()
    markers = mint_markers(f)
    payload = _rec("xss-0", {"name": markers.xss}, injection_point="query.name",
                   body="ok")
    verdict = Verdict(status="CONFIRMED", subtype="xss", repro_detail=None)
    b = bundle_from(f, None, [payload], verdict, _opts(), markers=markers)
    assert b is not None and b.requests[-1].payload_label == "xss-0"


def test_bundle_is_none_when_nothing_landed():
    f = _finding()
    verdict = Verdict(status="CONFIRMED", subtype="xss", repro_detail=None)
    assert bundle_from(f, None, [], verdict, _opts(), markers=mint_markers(f)) is None


# ── the bundle survives serialization (checkpoint-safety) ───────────────────

def test_bundle_round_trips_through_model_dump():
    f = _finding()
    markers = mint_markers(f)
    transcript, payload = _confirmed_transcript(markers.xss)
    verdict = Verdict(status="CONFIRMED", subtype="xss",
                      repro_detail=detail_from_record(payload, "name"))
    b = bundle_from(f, None, transcript, verdict, _opts(), markers=markers)
    b2 = ReplayBundle.model_validate(json.loads(b.model_dump_json()))
    assert b2.requests[1].query == {"name": markers.xss}
    assert b2.markers == b.markers


def test_replay_outcome_values():
    assert {o.value for o in ReplayOutcome} == {
        "remediated", "still_vulnerable", "inconclusive"}


# ── the Verdict field is not exposed to the probe agent ───────────────────────

def test_replay_bundle_is_absent_from_the_probe_schema():
    s = json.loads(Verdict.schema_json_compact())
    assert "replay_bundle" not in s.get("properties", {})
    assert "ReplayBundle" not in s.get("$defs", {})


# ── end-to-end: verify_finding attaches a bundle on CONFIRMED ─────────────────

def _match():
    ep = EndpointHint(method="GET", path="/greet", query_params={"name": "guest"})
    return EndpointMatch(endpoint=ep, method="GET", param="name", location="query")


def _cfg():
    return SimpleNamespace(models=SimpleNamespace(verify="m"),
                           step6_exploit_verification=ev_block())


def _confirming_judge(monkeypatch):
    """Configure a judge that ratifies the tell — the production confirm path. A live
    verdict is the judge's to give, so a bundle is only captured once the judge confirms."""
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(run_mod.agent, "run_loop", lambda *a, **k: "")
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "exploited",
                                         "why_not_benign": "the marker came back unescaped",
                                         "evidence": "reflected"})


def test_verify_finding_attaches_a_replay_bundle_on_confirm(monkeypatch):
    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        payload = " ".join(str(v) for v in (params or {}).values())
        return EvResponse(200, f"<html>hi {payload}</html>", url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)
    _confirming_judge(monkeypatch)                           # CONFIRMED now requires the judge

    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "CONFIRMED"
    assert v.replay_bundle is not None
    labels = [r.payload_label for r in v.replay_bundle.requests]
    assert BASELINE_LABEL in labels                          # baseline captured for the diff
    assert v.replay_bundle.subtype == "xss"


def test_verify_finding_leaves_no_bundle_when_not_confirmed(monkeypatch):
    import html
    def fake_send(method, url, *, params, headers, data, opts, **_kw):
        payload = " ".join(str(v) for v in (params or {}).values())
        return EvResponse(200, f"<html>hi {html.escape(payload)}</html>", url=url, method=method)
    monkeypatch.setattr(core_mod, "_send", fake_send)
    # Judge present and rules against it — the escaped payload is refuted, so NOT_CONFIRMED
    # and no bundle. (Without a judge the outcome would be INCONCLUSIVE — also no bundle.)
    monkeypatch.setattr(run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(run_mod.agent, "run_loop", lambda *a, **k: "")
    monkeypatch.setattr(run_mod.judge, "judge",
                        lambda *a, **k: {"verdict": "refuted", "evidence": "html.escape neutralised it"})

    v = run_mod.verify_finding(_finding(), _match(), _opts(), AuthConfig(), cfg=_cfg())
    assert v.status == "NOT_CONFIRMED" and v.replay_bundle is None


# ── persistence: the ev_replays table ───────────────────────────────────────
#
# Bundles are stored so a SEPARATE `ev-replay` invocation (after the fix is deployed)
# can reuse them. The load-bearing property: they SURVIVE a fresh rescan's reset_run.

from vvaharness.orchestrator import store            # noqa: E402


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "state"))
    return tmp_path / "state"


def _bundle_bytes(marker="<evx>"):
    f = _finding()
    markers = mint_markers(f)
    transcript, payload = _confirmed_transcript(marker)
    verdict = Verdict(status="CONFIRMED", subtype="xss",
                      repro_detail=detail_from_record(payload, "name"))
    return bundle_from(f, None, transcript, verdict, _opts(),
                       markers=markers).model_dump_json().encode()


def test_save_and_load_replays_round_trip(state_dir):
    store.save_replays("run1", [("k1", _bundle_bytes()), ("k2", _bundle_bytes())])
    rows = store.load_replays("run1")
    assert {k for k, _ in rows} == {"k1", "k2"}
    b = ReplayBundle.model_validate_json(dict(rows)["k1"])
    assert b.subtype == "xss"


def test_prune_replays_drops_bundles_for_findings_dedup_collapsed(state_dir):
    """Bundles are stored at the end of S6, before S7 collapses duplicates — so without
    pruning the table can hold a bundle for a finding that never reaches the report, and
    `ev-replay` would then re-check something the operator cannot look up."""
    store.save_replays("run1", [("keep", _bundle_bytes()), ("collapsed", _bundle_bytes())])
    assert store.prune_replays("run1", {"keep"}) == 1
    assert {k for k, _ in store.load_replays("run1")} == {"keep"}


def test_prune_replays_is_a_no_op_when_everything_survives(state_dir):
    store.save_replays("run1", [("a", _bundle_bytes()), ("b", _bundle_bytes())])
    assert store.prune_replays("run1", {"a", "b"}) == 0
    assert {k for k, _ in store.load_replays("run1")} == {"a", "b"}


def test_save_replays_replaces_the_whole_set(state_dir):
    store.save_replays("run1", [("k1", _bundle_bytes()), ("k2", _bundle_bytes())])
    store.save_replays("run1", [("k3", _bundle_bytes())])       # re-run: new ground truth
    assert {k for k, _ in store.load_replays("run1")} == {"k3"}


def test_empty_save_clears_the_set(state_dir):
    store.save_replays("run1", [("k1", _bundle_bytes())])
    store.save_replays("run1", [])                              # EV ran, nothing confirmed
    assert store.load_replays("run1") == []


def test_replays_survive_reset_run(state_dir):
    # THE headline property: a fresh rescan wipes checkpoints but must keep replay
    # bundles, or replay-after-remediate-and-rescan is impossible.
    store.register_run("run1", repo_root="/r")
    store.save_replays("run1", [("k1", _bundle_bytes())])
    store.reset_run("run1")
    assert {k for k, _ in store.load_replays("run1")} == {"k1"}


def test_replays_die_with_delete_run(state_dir):
    store.register_run("run1", repo_root="/r")
    store.save_replays("run1", [("k1", _bundle_bytes())])
    store.delete_run("run1")
    assert store.load_replays("run1") == []                     # FK cascade reaped them


def test_delete_replays_clears_only_that_run(state_dir):
    store.save_replays("run1", [("k1", _bundle_bytes())])
    store.save_replays("run2", [("k2", _bundle_bytes())])
    assert store.delete_replays("run1") == 1
    assert store.load_replays("run1") == []
    assert {k for k, _ in store.load_replays("run2")} == {"k2"}


def test_oversized_bundle_is_skipped_not_persisted(state_dir, capsys):
    store.save_replays("run1", [("big", b"x" * (store._REPLAY_MAX_BYTES + 1)),
                                ("ok", _bundle_bytes())])
    assert {k for k, _ in store.load_replays("run1")} == {"ok"}
    assert "not persisted" in capsys.readouterr().err


def test_migration_v2_to_v3_adds_the_ev_tables(state_dir):
    """A pre-EV database (v2: neither table) gains both on connect(), in one step.

    Both arrive together because neither has shipped, so no database outside development
    sits between them — there is no intermediate version to migrate through."""
    p = store.db_path()
    con = sqlite3.connect(p)
    con.executescript(store._DDL)
    con.execute("DROP TABLE ev_replays")
    con.execute("DROP TABLE ev_probes")
    con.execute("PRAGMA user_version = 2")
    con.commit()
    con.close()

    c = store.connect()
    try:
        assert c.execute("PRAGMA user_version").fetchone()[0] == store._SCHEMA_VERSION
        tables = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        c.close()
    assert {"ev_replays", "ev_probes"} <= tables


# ── router → store: a confirmed finding's bundle is persisted ─────────────────

from vvaharness.exploit_verification.verify import router as R      # noqa: E402
from vvaharness.exploit_verification.collection.model import NormalizedCollection  # noqa: E402
from vvaharness.pipeline.stages import s6_verify                    # noqa: E402
from vvaharness.models import Finding, VulnClass                    # noqa: E402
from vvaharness.orchestrator.checkpoints import run_id_for          # noqa: E402


def _router_cfg():
    return SimpleNamespace(models=SimpleNamespace(verify="m"),
                           step6_exploit_verification=ev_block())


_ROUTER_MATCH = [_match()]


def _wire_router(monkeypatch, verdict):
    monkeypatch.setattr(R, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(R.ev_llm, "refine", lambda findings, table, **k: dict(table))
    monkeypatch.setattr(R, "build_index", lambda col, ctx, **k: SimpleNamespace(located=[1]))
    monkeypatch.setattr(R, "map_to_endpoints",
                        lambda cands, *a, **k: {fid: _ROUTER_MATCH for fid, _f, _st in cands})
    monkeypatch.setattr(R, "verify_candidate", lambda f, m, opts, auth, **kw: verdict)
    monkeypatch.setattr(s6_verify, "run", lambda findings, ctx, cfg: (list(findings), []))


def _router_finding():
    return Finding(chunk_id="c", file="app.py", line_start=1, line_end=2,
                   vuln_class=VulnClass.INJECTION, cwe="CWE-89", title="SQLi via id",
                   description="d", code_snippet="x", confidence=1.0)


def _ctx_with_repo(repo):
    return SimpleNamespace(ev_collection=NormalizedCollection().model_dump(),
                           repo_root=str(repo))


def test_router_persists_a_confirmed_bundle(monkeypatch, state_dir, tmp_path):
    b = ReplayBundle.model_validate_json(_bundle_bytes())
    _wire_router(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", param="id",
                                      evidence="SQL error", confidence="high",
                                      method="deterministic-backed", replay_bundle=b))
    repo = tmp_path / "repo"
    R.run([_router_finding()], _ctx_with_repo(repo),
          SimpleNamespace(models=SimpleNamespace(verify="m"),
                          step6_exploit_verification=ev_block()))
    rows = store.load_replays(run_id_for(repo))
    assert len(rows) == 1
    assert ReplayBundle.model_validate_json(rows[0][1]).subtype == "xss"


def test_router_with_no_confirms_clears_prior_bundles(monkeypatch, state_dir, tmp_path):
    repo = tmp_path / "repo"
    store.save_replays(run_id_for(repo), [("stale", _bundle_bytes())])
    _wire_router(monkeypatch, Verdict(status="NOT_CONFIRMED", subtype="sqli",
                                      evidence="no signal"))
    R.run([_router_finding()], _ctx_with_repo(repo),
          SimpleNamespace(models=SimpleNamespace(verify="m"),
                          step6_exploit_verification=ev_block()))
    assert store.load_replays(run_id_for(repo)) == []          # re-run cleared stale ground truth


# ── the replay ladder: re-send + re-decide (deterministic tiers) ─────────────

from vvaharness.exploit_verification.executor.oob import OOBManager     # noqa: E402
from vvaharness.exploit_verification.replay import run as replay_run_mod  # noqa: E402
from vvaharness.exploit_verification.replay.model import ReplayRequest    # noqa: E402


def _sqli_bundle(*, authed=True, oob_nonces=None, auth_strategy="none"):
    # auth_strategy defaults to "none" to match the default replay AuthConfig(), so the
    # principal-change flag is off unless a test opts into a mismatch (auth_strategy="bearer").
    f = _finding(title="SQLi via id", cwe="CWE-89")
    markers = mint_markers(f)
    return ReplayBundle(
        finding_title="SQLi via id", finding_file="app.py", finding_line=10,
        finding_cwe="CWE-89", subtype="sqli", cls="active",
        markers={k: v for k, v in vars(markers).items()},
        requests=[
            ReplayRequest(method="GET", path="/user", query={"id": "1"},
                          identity="primary", payload_label=BASELINE_LABEL),
            ReplayRequest(method="GET", path="/user", query={"id": "1'"},
                          identity=("primary" if authed else "none"),
                          payload_label="sqli-0", injection_point="query.id"),
        ],
        oob_nonces=oob_nonces or [], authed=authed, auth_strategy=auth_strategy,
        target_base=_BASE, ev_method="deterministic-backed", ev_confidence="high",
        ev_evidence="SQL error surfaced by the injected payload")


def _replay_opts():
    return EVOptions(enabled=True, target_url=_BASE)


def _replay_cfg():
    return SimpleNamespace(step6_exploit_verification=ev_block())


def _run_one(bundle, send, monkeypatch, auth=None, cfg=None):
    monkeypatch.setattr(core_mod, "_send", send)
    oob = OOBManager(enabled=False)
    return replay_run_mod._replay_one(bundle, _replay_opts(),
                                      auth or AuthConfig(), oob, cfg or _replay_cfg())


def _send_const(status, body, error=None):
    def send(method, url, *, params, headers, opts, json=None, data=None, **_kw):
        return EvResponse(status, body, url=url, method=method, elapsed=0.01, error=error)
    return send


def test_still_vulnerable_when_the_stored_tell_fires_again(monkeypatch):
    # The SQL error is back for the quote payload → deterministic, NO model needed.
    r = _run_one(_sqli_bundle(), _send_const(200, "You have an error in your SQL syntax"),
                 monkeypatch)
    assert r.outcome is ReplayOutcome.STILL_VULNERABLE
    assert r.method == "deterministic"


def test_endpoint_now_404_is_inconclusive_not_remediated(monkeypatch):
    r = _run_one(_sqli_bundle(), _send_const(404, "not found"), monkeypatch)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE
    assert "removal" in r.reason and "drift" in r.reason


def test_all_errors_is_inconclusive(monkeypatch):
    r = _run_one(_sqli_bundle(), _send_const(None, "", error="ConnectError"), monkeypatch)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE
    assert "no diagnostic response" in r.reason


def test_tell_gone_is_inconclusive_until_variation_and_judge(monkeypatch):
    # Absence of the tell is NOT remediated on its own — variation + judge decide.
    r = _run_one(_sqli_bundle(), _send_const(200, "ok, nothing to see"), monkeypatch)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE


def test_principal_change_is_flagged(monkeypatch):
    # Confirmed under a bearer credential, replayed with none → untrustworthy comparison.
    r = _run_one(_sqli_bundle(authed=True, auth_strategy="bearer"),
                 _send_const(200, "ok"), monkeypatch, auth=AuthConfig())
    assert r.principal_changed is True


# ── the command wrapper (replay_run) ─────────────────────────────────────────

def test_replay_run_no_bundles_is_a_clean_noop(state_dir, tmp_path, capsys):
    rc = replay_run_mod.replay_run(tmp_path / "repo", [], _replay_cfg())
    assert rc == 0
    assert "no stored replay bundles" in capsys.readouterr().err


def test_replay_run_requires_a_target_url(state_dir, tmp_path, monkeypatch):
    monkeypatch.delenv("EV_TARGET_URL", raising=False)
    repo = tmp_path / "repo"
    store.save_replays(run_id_for(repo),
                       [("k", _sqli_bundle().model_dump_json().encode())])
    assert replay_run_mod.replay_run(repo, [], _replay_cfg()) == 2


def test_replay_run_refuses_a_non_local_oob_callback_base(state_dir, tmp_path, monkeypatch,
                                                          capsys):
    """`ev-replay` does not run the offline gate, so it repeats the gate's EV_OOB_URL
    locality check itself rather than inheriting it."""
    monkeypatch.setenv("EV_TARGET_URL", _BASE)
    monkeypatch.setenv("EV_OOB_URL", "http://192.168.1.50:9090")
    repo = tmp_path / "repo"
    store.save_replays(run_id_for(repo),
                       [("k", _sqli_bundle().model_dump_json().encode())])
    assert replay_run_mod.replay_run(repo, [], _replay_cfg()) == 2
    assert "EV_OOB_URL" in capsys.readouterr().err


def test_replay_run_accepts_a_loopback_oob_callback_base(state_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("EV_TARGET_URL", _BASE)
    monkeypatch.setenv("EV_OOB_URL", "http://127.0.0.1:9090")
    monkeypatch.setattr(core_mod, "_send", _send_const(404, ""))
    repo = tmp_path / "repo"
    store.save_replays(run_id_for(repo),
                       [("k", _sqli_bundle().model_dump_json().encode())])
    assert replay_run_mod.replay_run(repo, [], _replay_cfg()) != 2


def test_replay_run_reports_and_exits_1_when_still_vulnerable(state_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("EV_TARGET_URL", _BASE)
    monkeypatch.setattr(core_mod, "_send",
                        _send_const(200, "You have an error in your SQL syntax"))
    repo = tmp_path / "repo"
    store.save_replays(run_id_for(repo),
                       [("k", _sqli_bundle().model_dump_json().encode())])

    rc = replay_run_mod.replay_run(repo, [], _replay_cfg())
    assert rc == 1
    reports = list((repo / "security-scan").glob("*_ev-replay.md"))
    assert len(reports) == 1
    assert "STILL VULNERABLE" in reports[0].read_text()


def test_replay_run_bills_the_judge_to_its_own_phase(state_dir, tmp_path, monkeypatch):
    """The remediation judge's model call is billed to `s6-ev-replay`, not `unscoped` —
    ev-replay is a separate command from a scan, doing different work, so its spend
    needs its own row in the report rather than falling into the catch-all bucket."""
    from vvaharness.util.tokens import TOKENS, DEFAULT_PHASE

    monkeypatch.setenv("EV_TARGET_URL", _BASE)
    monkeypatch.setattr(core_mod, "_send", _send_const(200, "ok, nothing to see"))

    def fake_judge(**kw):
        TOKENS.add({"input_tokens": 12, "output_tokens": 4})
        return {"verdict": "remediated", "reasoning": "clean"}
    monkeypatch.setattr(replay_run_mod, "_ev_model",
                        lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(replay_run_mod, "judge_remediation", lambda **kw: fake_judge(**kw))

    repo = tmp_path / "repo"
    store.save_replays(run_id_for(repo),
                       [("k", _sqli_bundle().model_dump_json().encode())])

    replay_run_mod.replay_run(repo, [], _replay_cfg())

    snap = TOKENS.snapshot()
    assert snap["by_phase"]["s6-ev-replay"]["calls"] == 1
    assert snap["by_phase"]["s6-ev-replay"]["prompt"] == 12
    assert DEFAULT_PHASE not in snap["by_phase"]
    assert TOKENS._phase == DEFAULT_PHASE        # restored once replay_run() returns


# ── bounded variation: the anti-"error suppressed" guard ─────────────────────

def _send_suppressed_error_but_timing(method, url, *, params, headers, opts,
                                      json=None, data=None, **_kw):
    """A fix that swallows the SQL error: the stored error-based payload now looks
    clean, but a timing payload (SLEEP) still delays — the bug is not fixed."""
    blob = " ".join(str(v) for v in (params or {}).values()).lower()
    if "sleep" in blob:
        return EvResponse(200, "ok", url=url, method=method, elapsed=5.0)
    return EvResponse(200, "ok, clean output", url=url, method=method, elapsed=0.02)


def test_variation_catches_a_suppressed_error(monkeypatch):
    # THE headline case: absence of the original tell must NOT read as remediated when
    # another variant of the same bug still fires.
    r = _run_one(_sqli_bundle(), _send_suppressed_error_but_timing, monkeypatch)
    assert r.outcome is ReplayOutcome.STILL_VULNERABLE
    assert r.method == "variation"
    assert r.variants_tried > 0


def test_variation_clean_stays_inconclusive_not_remediated(monkeypatch):
    # Every same-subtype variant comes up empty → still NOT a pass here; the judge has
    # the final say, and variation finding nothing stays INCONCLUSIVE.
    r = _run_one(_sqli_bundle(), _send_const(200, "clean, no sql, no delay"), monkeypatch)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE
    assert r.variants_tried > 0


def test_variation_can_be_disabled(monkeypatch):
    cfg = SimpleNamespace(step6_exploit_verification=ev_block(ev_replay_variants=False))
    r = _run_one(_sqli_bundle(), _send_const(200, "clean"), monkeypatch, cfg=cfg)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE
    assert r.variants_tried == 0


def test_variation_does_not_fold_in_an_unrelated_signal(monkeypatch):
    # A reflected value at the endpoint is not a SQL signal — variation for `sqli` must
    # not report still-vulnerable off an unrelated reflection (that would be a NEW
    # finding, not this one's verdict).
    def echo(method, url, *, params, headers, opts, json=None, data=None, **_kw):
        blob = " ".join(str(v) for v in (params or {}).values())
        return EvResponse(200, f"you searched for {blob}", url=url, method=method, elapsed=0.02)
    # no judge model is wired for this test, so the run stops after variation and the
    # outcome isolates what variation itself decided
    r = _run_one(_sqli_bundle(), echo, monkeypatch)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE


# ── the remediation judge ────────────────────────────────────────────────────

from vvaharness.exploit_verification.verify.judge import judge_remediation   # noqa: E402
from test_ev_config import ev_block


def _finding_ns(title="SQLi via id", cwe="CWE-89"):
    return SimpleNamespace(title=title, cwe=cwe, description="")


def _reply(text):
    def call(system, user, *, model, **_kw):
        _reply.last_user = user
        _reply.last_kw = dict(_kw)
        return text
    return call


def test_judge_remediation_maps_a_clean_verdict():
    j = judge_remediation(
        finding=_finding_ns(), subtype="sqli", original_evidence="SQL error",
        old_response={"status": 200, "body": "SQL syntax error near"},
        new_response={"status": 200, "body": "ok"}, variants_tried=3,
        principal_changed=False, model="m",
        call=_reply('{"verdict":"remediated","reasoning":"input now parameterised"}'))
    assert j["verdict"] == "remediated"
    assert "variant" in _reply.last_user            # the variation note reached the judge


def test_judge_remediation_is_told_about_a_principal_change():
    judge_remediation(
        finding=_finding_ns(), subtype="authz", original_evidence="200 without creds",
        old_response={"status": 200, "body": "secret"},
        new_response={"status": 200, "body": "secret"}, variants_tried=0,
        principal_changed=True, model="m",
        call=_reply('{"verdict":"unclear","reasoning":"x"}'))
    assert "different or absent credential" in _reply.last_user


def test_judge_remediation_rejects_garbage_and_unknown_verdicts():
    assert judge_remediation(
        finding=_finding_ns(), subtype="sqli", original_evidence="",
        old_response={}, new_response={}, variants_tried=0, principal_changed=False,
        model="m", call=_reply("not json at all")) is None
    assert judge_remediation(
        finding=_finding_ns(), subtype="sqli", original_evidence="",
        old_response={}, new_response={}, variants_tried=0, principal_changed=False,
        model="m", call=_reply('{"verdict":"maybe"}')) is None


def _agent_judged_bundle():
    b = _sqli_bundle()
    b.ev_method = "agent-judged"           # no deterministic tell → straight to the judge
    return b


def _wire_judge(monkeypatch, verdict_dict):
    monkeypatch.setattr(replay_run_mod, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(replay_run_mod, "judge_remediation",
                        lambda **kw: verdict_dict)


def test_judge_confirms_remediation_when_tell_and_variants_are_gone(monkeypatch):
    _wire_judge(monkeypatch, {"verdict": "remediated", "reasoning": "now rejected"})
    r = _run_one(_sqli_bundle(), _send_const(200, "clean"), monkeypatch)
    assert r.outcome is ReplayOutcome.REMEDIATED and r.method == "agent-judged"


def test_agent_judged_bundle_goes_straight_to_the_judge(monkeypatch):
    _wire_judge(monkeypatch, {"verdict": "vulnerable", "reasoning": "still leaks"})
    r = _run_one(_agent_judged_bundle(), _send_const(200, "secret data"), monkeypatch)
    assert r.outcome is ReplayOutcome.STILL_VULNERABLE


def test_judge_none_is_inconclusive(monkeypatch):
    _wire_judge(monkeypatch, None)
    r = _run_one(_sqli_bundle(), _send_const(200, "clean"), monkeypatch)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE


def test_a_remediated_verdict_under_a_changed_principal_is_not_a_pass(monkeypatch):
    # Confirmed authed, replayed with no credential: even a "remediated" judge call
    # cannot be trusted — the finding must not be marked fixed.
    _wire_judge(monkeypatch, {"verdict": "remediated", "reasoning": "looks fine"})
    r = _run_one(_sqli_bundle(authed=True, auth_strategy="bearer"),
                 _send_const(200, "clean"), monkeypatch, auth=AuthConfig())
    assert r.principal_changed is True
    assert r.outcome is ReplayOutcome.INCONCLUSIVE


# ── ev_probes: the opt-in full probe log (distinct from confirmed ev_replays) ──

def test_a_fresh_database_gets_the_ev_tables_without_migrating(state_dir):
    """A v0 database is built from _DDL in one shot, so the EV tables must be in there and
    not only in the migration script — otherwise a first-ever run has nowhere to store a
    bundle."""
    c = store.connect()
    try:
        assert c.execute("PRAGMA user_version").fetchone()[0] == store._SCHEMA_VERSION
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        c.close()
    assert {"ev_replays", "ev_probes"} <= tables


def test_ev_probes_round_trip_and_replace(state_dir):
    rid = "run-xyz"
    store.register_run(rid, repo_root="/tmp/x")
    row = {"finding_key": "k1", "finding_title": "SSTI via name", "file": "app/main.py",
           "line_start": 38, "line_end": 41, "cwe": "CWE-94", "vuln_class": "injection",
           "ev_class": "active", "ev_subtype": "ssti", "ev_verdict": "CONFIRMED",
           "endpoint_method": "GET", "endpoint_path": "/", "payload_label": "ssti-1",
           "injection_point": "query.name", "req_method": "GET", "req_url": "http://t/",
           "req_query": '{"name":"{{7*7}}"}', "req_body": "", "authed": 0,
           "auth_applied": "", "resp_status": 200, "resp_ms": 12,
           "resp_snippet": "<h1>Hello, 49!</h1>"}
    assert store.save_ev_probes(rid, [row, {**row, "payload_label": "ssti-2"}]) == 2
    got = store.load_ev_probes(rid)
    assert len(got) == 2
    assert got[0]["finding_title"] == "SSTI via name" and got[0]["cwe"] == "CWE-94"
    assert got[0]["ev_subtype"] == "ssti" and got[0]["resp_status"] == 200
    # replace-per-run: a second save overwrites, it does not append
    assert store.save_ev_probes(rid, [row]) == 1
    assert len(store.load_ev_probes(rid)) == 1


def test_ev_probes_never_store_a_credential(state_dir):
    """auth_applied carries channel NAMES only; no token/body field should hold a secret
    the caller didn't put in the payload. This pins that the writer stores what it's given
    and nothing injected — the row has only channel names, never a value."""
    rid = "run-cred"
    store.register_run(rid, repo_root="/tmp/x")
    store.save_ev_probes(rid, [{"finding_key": "k", "auth_applied": "header:authorization",
                                "req_body": '{"q":"1"}', "resp_snippet": "ok"}])
    got = store.load_ev_probes(rid)[0]
    assert got["auth_applied"] == "header:authorization"     # the NAME, not a token
    assert "Bearer" not in (got["req_body"] or "") and "eyJ" not in (got["resp_snippet"] or "")


# ── the stored replay response must not carry a credential ────────────────────

def test_replay_response_capture_redacts_the_body_but_keeps_the_raw_hash():
    from vvaharness.exploit_verification.replay.capture import _response_from_record
    jwt = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ0ZXN0LTEyMyJ9.c3ludGhldGljX3Rlc3Rfc2ln"
    raw = '{"name":"testuser","token":"' + jwt + '"}'
    rec = RequestRecord(method="GET", url="http://t/api/session",
                        response=EvResponse(200, raw, url="http://t/api/session",
                                            method="GET", elapsed=0.01))
    stored = _response_from_record(rec)
    assert jwt not in stored.body and "redacted" in stored.body.lower()   # body scrubbed
    assert stored.body_sha256 == hashlib.sha256(raw.encode()).hexdigest()  # hash over RAW


# ── baseline evidence, unchanged responses, and report accuracy ───────────────
#
# These populate `original` (what the target answered THEN); the fixtures above leave it
# empty, which is what exercises the no-history fallbacks.

from vvaharness.exploit_verification.replay.model import (ReplayResponse,      # noqa: E402
                                                          ReplayResult)
from vvaharness.exploit_verification.replay.report import _markdown            # noqa: E402


def _bundle_with_history(*, baseline=(200, '{"users":[{"id":1,"name":"alice"}]}'),
                         confirming=(200, "You have an error in your SQL syntax"),
                         ev_method="deterministic-backed"):
    b = _sqli_bundle()
    b.ev_method = ev_method
    b.roles = ["baseline", "confirming"]
    b.original = [ReplayResponse(status=baseline[0], body=baseline[1]),
                  ReplayResponse(status=confirming[0], body=confirming[1])]
    return b


def _judge_must_not_run(monkeypatch):
    def boom(**_kw):
        raise AssertionError("the judge was consulted for a decision the code can make")
    monkeypatch.setattr(replay_run_mod, "judge_remediation", boom)


def test_a_broken_baseline_makes_the_recheck_inconclusive_without_a_model(monkeypatch):
    """200 then, 500 now on a benign request means the target is failing on all traffic, so
    a quiet tell proves nothing — and a model asked this invents a reason about the fix."""
    _judge_must_not_run(monkeypatch)
    r = _run_one(_bundle_with_history(), _send_const(500, "Internal Server Error"),
                 monkeypatch)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE
    assert "failing on all traffic" in r.reason
    assert r.variants_tried == 0          # settled before variation spends the budget


def test_a_baseline_that_was_already_broken_is_not_read_as_drift(monkeypatch):
    """Drift is a CHANGE: a baseline already erroring then says nothing new."""
    seen = {}

    def fake_judge(**kw):
        seen.update(kw)
        return {"verdict": "unclear", "reasoning": "no signal either way"}
    monkeypatch.setattr(replay_run_mod, "judge_remediation", fake_judge)
    monkeypatch.setattr(replay_run_mod, "_ev_model",
                        lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    r = _run_one(_bundle_with_history(baseline=(500, "Internal Server Error")),
                 _send_const(500, "Internal Server Error"), monkeypatch)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE
    assert seen, "the judge should still have been asked"


def test_the_baseline_pair_is_shown_to_the_judge_when_there_is_no_control(monkeypatch):
    """Alone, the payload response cannot separate "now rejected" from "answers nobody"."""
    seen = {}

    def fake_judge(**kw):
        seen.update(kw)
        return {"verdict": "remediated", "reasoning": "parameterised"}
    monkeypatch.setattr(replay_run_mod, "judge_remediation", fake_judge)
    monkeypatch.setattr(replay_run_mod, "_ev_model",
                        lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    b = _bundle_with_history(ev_method="agent-judged")     # no tell, so straight to the judge
    r = _run_one(b, _send_const(200, '{"users":[]}'), monkeypatch)
    assert r.outcome is ReplayOutcome.REMEDIATED
    assert seen["old_baseline"] == {"status": 200,
                                    "body": '{"users":[{"id":1,"name":"alice"}]}'}
    assert seen["new_baseline"] == {"status": 200, "body": '{"users":[]}'}
    assert seen["old_control"] is None and seen["new_control"] is None


def test_an_unchanged_response_is_still_vulnerable_without_a_model(monkeypatch):
    """Same status, same body: nothing was fixed. The judge sees the same truncated excerpt,
    so it cannot decide this better than a comparison — it can only claim it did."""
    _judge_must_not_run(monkeypatch)
    b = _bundle_with_history(ev_method="agent-judged",
                             confirming=(200, '{"query":"SELECT 1","rows":[[1]]}'))
    r = _run_one(b, _send_const(200, '{"query":"SELECT 1","rows":[[1]]}'), monkeypatch)
    assert r.outcome is ReplayOutcome.STILL_VULNERABLE
    assert r.method == "deterministic"
    assert "unchanged since confirmation" in r.reason


def test_two_empty_bodies_are_not_treated_as_an_unchanged_response(monkeypatch):
    """Blank matching blank holds whether or not the flaw is there, so the judge decides."""
    monkeypatch.setattr(replay_run_mod, "judge_remediation",
                        lambda **kw: {"verdict": "unclear", "reasoning": "nothing to read"})
    monkeypatch.setattr(replay_run_mod, "_ev_model",
                        lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    b = _bundle_with_history(ev_method="agent-judged", confirming=(200, ""))
    r = _run_one(b, _send_const(200, ""), monkeypatch)
    assert r.outcome is ReplayOutcome.INCONCLUSIVE


def test_the_judges_prose_is_scrubbed_before_it_reaches_the_report(monkeypatch):
    """The judge quotes what it saw, so its prose can carry a token into the report."""
    token = "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"
    monkeypatch.setattr(replay_run_mod, "judge_remediation",
                        lambda **kw: {"verdict": "vulnerable",
                                      "reasoning": f"still returns {token} to anyone"})
    monkeypatch.setattr(replay_run_mod, "_ev_model",
                        lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    b = _bundle_with_history(ev_method="agent-judged", confirming=(200, "old body"))
    r = _run_one(b, _send_const(200, "new body"), monkeypatch)
    assert token not in r.reason
    assert "[REDACTED-JWT]" in r.reason


def test_the_configured_judge_max_tokens_reaches_the_model_call():
    """A raised ceiling has to reach the judge: a reply cut off mid-JSON costs a verdict."""
    judge_remediation(
        finding=_finding_ns(), subtype="sqli", original_evidence="SQL error",
        old_response={"status": 200, "body": "old"},
        new_response={"status": 200, "body": "new"}, variants_tried=0,
        principal_changed=False, model="m", max_tokens=4321,
        call=_reply('{"verdict":"unclear","reasoning":"x"}'))
    assert _reply.last_kw["max_tokens"] == 4321


def _result(**kw):
    base = dict(finding_title="SQLi via id", finding_file="app.py", finding_line=10,
                subtype="sqli", outcome=ReplayOutcome.REMEDIATED, reason="looks fixed",
                method="agent-judged")
    base.update(kw)
    return ReplayResult(**base)


def test_the_report_does_not_promise_variation_it_did_not_run():
    """Variation runs only for a tell-backed confirmation, so a blanket "variations found
    nothing" claim is false for exactly the thinnest passes."""
    md = _markdown([_result(variants_tried=0)], _BASE, "2026-01-01T00:00:00Z")
    assert "a bounded set of variations also found nothing" not in md
    assert "no variation was run for this finding" in md

    md = _markdown([_result(variants_tried=10)], _BASE, "2026-01-01T00:00:00Z")
    assert "no variation was run for this finding" not in md
    assert "10 variation(s) tried" in md


def test_a_still_vulnerable_finding_gets_no_evidence_caveat():
    """The caveat is about a PASS; on a still-vulnerable finding it would read as doubt."""
    md = _markdown([_result(outcome=ReplayOutcome.STILL_VULNERABLE, variants_tried=0)],
                   _BASE, "2026-01-01T00:00:00Z")
    assert "no variation was run for this finding" not in md


def test_variation_builds_its_baseline_from_the_benign_stored_request(monkeypatch):
    """The plan's own baseline has to be CLEAN: rebuilt from the confirming request it
    carries that payload, so the oracle's only reference is itself an injection."""
    from vvaharness.exploit_verification.replay import variation as var_mod

    match = var_mod._match_from(_sqli_bundle())
    assert match.endpoint.query_params == {"id": "1"}      # not the stored "1'"
    assert match.param == "id" and match.location == "query"

    sent: list = []

    def capture(method, url, *, params, headers, opts, json=None, data=None, **_kw):
        sent.append(dict(params or {}))
        return EvResponse(200, "clean", url=url, method=method, elapsed=0.02)
    _run_one(_sqli_bundle(), capture, monkeypatch)
    # sent[0] and [1] are the stored re-send; the variation plan's baseline follows it.
    assert sent[2] == {"id": "1"}


def test_variation_falls_back_to_the_confirming_request_without_a_stored_baseline():
    """A bundle with only the confirming request still has to yield a usable plan."""
    from vvaharness.exploit_verification.replay import variation as var_mod

    b = _sqli_bundle()
    b.requests = [b.requests[1]]                  # confirming only
    b.roles = ["confirming"]
    match = var_mod._match_from(b)
    assert match is not None
    assert match.endpoint.query_params == {"id": "1'"}


# ── a benign baseline for an agent-judged confirmation ────────────────────────
#
# The loop's probes carry no payload label, so such a bundle used to store the confirming
# request alone, leaving replay no benign reference.

def _loop_captured_bundle(first_probe):
    """A loop-style transcript: an unlabelled opening probe, then the confirming one."""
    f = _finding(title="Credentials returned to an unauthenticated caller", cwe="CWE-200")
    markers = mint_markers(f)
    confirming = _rec("", {"id": "1 OR 1=1"}, url=f"{_BASE}/user",
                      body='{"rows":[[1,"alice","secret"]]}', seq=2)
    transcript = [first_probe, confirming]
    verdict = Verdict(status="CONFIRMED", subtype="", category="active",
                      method="agent-judged", confidence="medium",
                      repro_detail=detail_from_record(confirming, "id"))
    return bundle_from(f, None, transcript, verdict, _opts(), markers=markers), markers


def test_a_plain_loop_probe_becomes_the_baseline_for_an_agent_judged_confirm():
    b, _ = _loop_captured_bundle(_rec("", {"id": "1"}, url=f"{_BASE}/user",
                                     body='{"rows":[[1,"alice"]]}', seq=1))
    assert b.roles == ["baseline", "confirming"]
    assert b.baseline_index() == 0
    assert b.requests[0].query == {"id": "1"}
    assert b.original[0].status == 200


def test_an_injected_probe_is_never_adopted_as_the_baseline():
    """Replay shows a baseline to the judge as "well-formed, no payload", so a mislabelled
    one lets a payload's success read as a healthy endpoint."""
    b, _ = _loop_captured_bundle(_rec("", {"id": "0 OR 1=1"}, url=f"{_BASE}/user", seq=1))
    assert b.roles == ["confirming"]
    assert b.baseline_index() is None


def test_a_marker_carrying_probe_is_never_adopted_as_the_baseline():
    f = _finding()
    markers = mint_markers(f)
    probe = _rec("", {"id": markers.xss}, url=f"{_BASE}/user", seq=1)
    confirming = _rec("", {"id": "1 OR 1=1"}, url=f"{_BASE}/user", seq=2)
    verdict = Verdict(status="CONFIRMED", subtype="", method="agent-judged",
                      repro_detail=detail_from_record(confirming, "id"))
    b = bundle_from(f, None, [probe, confirming], verdict, _opts(), markers=markers)
    assert b.roles == ["confirming"]


def test_a_probe_that_never_landed_is_not_a_baseline():
    """A baseline says whether the endpoint works; one with no response says nothing."""
    probe = _rec("", {"id": "1"}, url=f"{_BASE}/user", seq=1)
    probe.response = None
    b, _ = _loop_captured_bundle(probe)
    assert b.roles == ["confirming"]


# ── redaction must not read as a target change ─────────────────────────────────

def test_a_legacy_marker_in_a_stored_body_normalises_for_comparison():
    """A bundle captured before the redactor unified on the bracketed vocabulary still holds
    the retired `<redacted-jwt>` marker. `_stored_body` maps it to the current one, so an
    OLD-vs-NEW comparison is not decided by which redactor version wrote the bundle."""
    old = SimpleNamespace(body="tok <redacted-jwt> end")
    assert replay_run_mod._stored_body(old) == "tok [REDACTED-JWT] end"


def test_a_stored_body_is_re_redacted_so_masking_cannot_look_like_a_fix():
    """The decisive case for ev-replay. An older bundle stored a value the redactor of the
    day did not mask (here a card number, under a JWT-only redactor). Re-applying the CURRENT
    redactor to the stored side makes it match the freshly-redacted new body, so the
    "unchanged since confirmation" check and the remediation judge both see a masking
    difference for what it is — nothing the fix did."""
    from vvaharness.exploit_verification import safety
    raw = '{"pan":"4111111111111111","note":"ok"}'
    old = SimpleNamespace(body=raw)                      # stored unmasked by an older pass
    fresh = safety.redact_secrets(raw)                   # what the new excerpt looks like
    assert "[REDACTED-PAN]" in fresh                     # the new side masks it
    assert replay_run_mod._stored_body(old) == fresh     # ...and so does the old side now
