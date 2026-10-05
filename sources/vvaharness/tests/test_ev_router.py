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

"""S6 EV router — route live_candidates to verify vs static, stamp confirmed.

Hermetic: mapping (build_index + map_to_endpoints), verify_candidate and
s6_verify.run are all faked; no LLM, no network.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from vvaharness.exploit_verification.auth import AuthConfig, AuthStrategy
from vvaharness.exploit_verification.auth_provider import Freshness
from vvaharness.exploit_verification.classify import Classification, VerifyClass
from vvaharness.exploit_verification.classify import llm as ev_llm
from vvaharness.exploit_verification.collection.model import EndpointHint, NormalizedCollection
from vvaharness.exploit_verification.mapping import EndpointMatch
from vvaharness.exploit_verification.safety import register_secret
from vvaharness.exploit_verification.verify import router as R
from vvaharness.exploit_verification.verify.model import Verdict
from vvaharness.models import Finding, VulnClass
from vvaharness.pipeline.stages import s6_verify
from test_ev_config import ev_block


def _key(f):
    """Finding identity, ignoring the ``ev_*`` stamp — EV annotates the findings it
    routes to static, so identity comparisons cannot use equality any more."""
    return (f.chunk_id, f.file, f.line_start, f.title)


def _f(vuln_class=VulnClass.INJECTION, cwe="CWE-89", title="SQLi via id"):
    return Finding(chunk_id="c", file="app.py", line_start=1, line_end=2,
                   vuln_class=vuln_class, cwe=cwe, title=title, description="d",
                   code_snippet="x", confidence=1.0)


def _ctx(collection=True):
    ev = NormalizedCollection().model_dump() if collection else None
    return SimpleNamespace(ev_collection=ev)


def _cfg():
    return SimpleNamespace(models=SimpleNamespace(verify="m"),
                           step6_exploit_verification=ev_block())


_MATCH = [EndpointMatch(endpoint=EndpointHint(method="GET", path="/user"),
                        method="GET", param="id", location="query")]


@pytest.fixture(autouse=True)
def _classifier_is_a_noop(monkeypatch):
    """Keep the LLM classification pass out of the routing tests.

    EV stands down when classification cannot be resolved, so without a resolvable
    model every test below would land in the static verifier before reaching the
    behaviour it is checking. Tests that care about the pass itself override these
    (see the classification section at the bottom); its own logic lives in the LLM
    refinement section of ``test_ev_classify.py``.
    """
    monkeypatch.setattr(R, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(R.ev_llm, "refine", lambda findings, table, **k: dict(table))


@pytest.fixture
def spy_static(monkeypatch):
    """Fake s6_verify.run that records the static bucket and 'verifies' it."""
    seen = {}

    def fake(findings, ctx, cfg):
        seen["bucket"] = list(findings)
        return list(findings), []
    monkeypatch.setattr(s6_verify, "run", fake)
    return seen


def _fake_map(monkeypatch, matches):
    """Fake the Part 1+2 route-bound mapping: every route-bound finding → matches."""
    monkeypatch.setattr(R, "build_index", lambda col, ctx, **k: SimpleNamespace(located=[1]))
    monkeypatch.setattr(R, "map_to_endpoints",
                        lambda cands, *a, **k: {fid: matches for fid, _f, _st in cands})


def _fake_map_passive(monkeypatch, matches):
    monkeypatch.setattr(R, "map_passive", lambda f, col: matches)


def _fake_verify(monkeypatch, verdict):
    # **kw so the stub tolerates the router passing new keywords (e.g. the routing
    # `classification`) without every router test failing on the signature.
    monkeypatch.setattr(R, "verify_candidate",
                        lambda f, m, opts, auth, **kw: verdict)


def test_hard_proof_overrides_and_skips_static_in_legacy_mode(monkeypatch, spy_static):
    # ev_overrides_static=true (legacy): a hard deterministic-backed proof stamps the
    # verdict + CVSS from EV's table and skips the static verifier.
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", param="id",
                                      evidence="SQL error", repro="GET /user [id]",
                                      confidence="high", method="deterministic-backed"))
    verified, dropped = R.run([_f()], _ctx(), _cfg_llm(ev_overrides_static=True))
    assert spy_static["bucket"] == []          # hard proof + override → skipped static
    assert len(verified) == 1
    v = verified[0]
    assert v.ev_status == "CONFIRMED" and v.verdict == "TRUE_POSITIVE"
    assert v.verdict_confidence == 10 and v.cvss_score == 9.8      # high → 10; sqli default CVSS
    assert v.ev_evidence == "SQL error"
    assert v.ev_method == "deterministic-backed" and v.ev_confidence == "high"


def test_confirmed_goes_through_static_by_default(monkeypatch, spy_static):
    # default (ev_overrides_static=false): even a hard deterministic-backed proof is
    # additive — stamped, but still statically verified, and EV does not set the verdict.
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", param="id",
                                      evidence="SQL error", repro="GET /user [id]",
                                      confidence="high", method="deterministic-backed"))
    verified, dropped = R.run([_f()], _ctx(), _cfg())
    assert len(spy_static["bucket"]) == 1      # went through static, not around it
    v = verified[0]
    assert v.ev_status == "CONFIRMED" and v.ev_method == "deterministic-backed"
    assert v.ev_evidence == "SQL error"
    assert v.verdict_confidence is None        # EV did not override; static owns the verdict


def test_agent_judged_confirm_still_faces_the_static_verifier(monkeypatch, spy_static):
    """A soft confirm records its evidence but must NOT override the verdict.

    Overriding is what lets a finding skip static verification, so it is reserved
    for a hard deterministic proof. An agent-judged outcome corroborates instead:
    ev_* is stamped, and the static verifier still owns verdict/cvss.
    """
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", param="id",
                                      evidence="agent-judged", confidence="medium",
                                      method="agent-judged"))
    f = _f()
    verified, _ = R.run([f], _ctx(), _cfg())
    assert len(spy_static["bucket"]) == 1                 # went through static, not around it
    v = verified[0]
    assert v.ev_status == "CONFIRMED"                     # evidence survives (model_copy)
    assert v.ev_method == "agent-judged" and v.ev_confidence == "medium"
    assert v.verdict_reason != "exploit-verified live (agent-judged, sqli)"
    assert v.verdict_confidence is None                  # static's to set, not EV's


def test_hard_deterministic_proof_skips_static_in_legacy_mode(monkeypatch, spy_static):
    # legacy: a minted marker / SQL error / OOB callback outweighs a code read
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", param="id",
                                      evidence="SQL error", confidence="high",
                                      method="deterministic-backed"))
    v = R.run([_f()], _ctx(), _cfg_llm(ev_overrides_static=True))[0][0]
    assert spy_static["bucket"] == []
    assert v.verdict_confidence == 10 and v.ev_method == "deterministic-backed"


def test_medium_confirm_is_corroborating_not_authoritative(monkeypatch, spy_static):
    # a differential/timing inference is real evidence but not a hard proof — even in
    # legacy mode it stays additive (only hard proofs override static).
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="headers",
                                      evidence="missing security headers",
                                      confidence="medium", method="deterministic-backed"))
    verified, _ = R.run([_f()], _ctx(), _cfg_llm(ev_overrides_static=True))
    assert len(spy_static["bucket"]) == 1
    assert verified[0].ev_status == "CONFIRMED" and verified[0].verdict_confidence is None


def test_not_confirmed_falls_to_static(monkeypatch, spy_static):
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="NOT_CONFIRMED", subtype="sqli"))
    f = _f()
    verified, dropped = R.run([f], _ctx(), _cfg())
    # Routed to static with the same identity, but now carrying WHY EV did not confirm:
    # a probed finding must be distinguishable from one EV never looked at.
    assert [_key(x) for x in spy_static["bucket"]] == [_key(f)]
    assert verified[0].ev_status == "NOT_CONFIRMED"
    assert verified[0].verdict is None          # static still owns the verdict


def test_not_eligible_category_skips_ev(monkeypatch, spy_static):
    # a hardcoded secret lands in a class that is not on the live path → not route-bound
    # → never mapped
    monkeypatch.setattr(R, "map_to_endpoints",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("mapped")))
    f = _f(vuln_class=VulnClass.INFO_LEAK, cwe="CWE-798", title="Hardcoded secret")
    R.run([f], _ctx(), _cfg())
    assert [_key(x) for x in spy_static["bucket"]] == [_key(f)]
    assert spy_static["bucket"][0].ev_status == "NOT_TESTED"
    # a deterministic table routed it, so the reason is the per-class wording and the
    # provenance says a rule (not a model) decided
    assert "nor the triage pass could place this finding" in (
        spy_static["bucket"][0].ev_evidence)
    assert spy_static["bucket"][0].ev_reason_source == "rule"


def test_unmapped_falls_to_static(monkeypatch, spy_static):
    _fake_map(monkeypatch, [])                  # eligible but maps to nothing
    f = _f()
    R.run([f], _ctx(), _cfg())
    assert [_key(x) for x in spy_static["bucket"]] == [_key(f)]
    assert spy_static["bucket"][0].ev_status == "NOT_TESTED"
    assert "no endpoint" in spy_static["bucket"][0].ev_evidence


def test_unmapped_route_bound_findings_are_surfaced_as_a_coverage_gap(
        monkeypatch, capsys, spy_static):
    # A live-testable finding with no endpoint in the collection must not vanish
    # silently into static — EV names it and its route so the operator can add it.
    _fake_map(monkeypatch, [])                  # eligible, but the collection has no route
    f = _f(title="IDOR on /admin/report/{saId}")
    R.run([f], _ctx(), _cfg())
    err = capsys.readouterr().err
    assert "coverage gap: 1 live-testable finding(s) have NO matching endpoint" in err
    assert "no endpoint for app.py:1" in err
    assert "IDOR on /admin/report/{saId}" in err


def test_posture_routed_through_map_passive(monkeypatch, spy_static):
    # PASSIVE (CORS) routes through map_passive, not the route-bound scorer.
    _fake_map_passive(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="cors",
                                      evidence="wildcard CORS with credentials",
                                      confidence="high", method="deterministic-backed"))
    f = _f(vuln_class=VulnClass.OTHER, cwe="CWE-942", title="CORS misconfiguration")
    verified, _ = R.run([f], _ctx(), _cfg())
    assert verified[0].ev_status == "CONFIRMED"        # confirmed via the posture path
    assert len(spy_static["bucket"]) == 1              # additive — still statically verified


# ── progress output ───────────────────────────────────────────────────────────
#
# The EV phase used to print nothing at all — a long silence between the "Step 6"
# banner and the first static verdict, indistinguishable from a hang. These pin the
# shape of the progress it now emits.

def test_progress_announces_the_candidate_count_before_working(monkeypatch, capsys, spy_static):
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="NOT_CONFIRMED", subtype="sqli", evidence="no signal"))
    eligible, skipped = _f(), _f(vuln_class=VulnClass.INFO_LEAK, cwe="CWE-798",
                                title="Hardcoded secret")
    R.run([eligible, skipped], _ctx(), _cfg())
    err = capsys.readouterr().err
    # the denominator is known up front, from the cheap classify+map pre-pass
    assert "[s6-ev] 1 of 2 findings are live-verifiable" in err
    assert "1 straight to static" in err


def test_progress_names_the_target_before_each_candidate(monkeypatch, capsys, spy_static):
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="NOT_CONFIRMED", subtype="sqli", evidence="no signal"))
    R.run([_f()], _ctx(), _cfg())
    err = capsys.readouterr().err
    # printed BEFORE the work, so a slow candidate still shows liveness
    assert "1/1 app.py:1 sqli vs GET /user …" in err
    assert "1/1 NOT_CONFIRMED — no signal" in err


def test_progress_marks_an_additive_confirm(monkeypatch, capsys, spy_static):
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", evidence="judged",
                                      confidence="medium", method="agent-judged"))
    R.run([_f()], _ctx(), _cfg())
    err = capsys.readouterr().err
    assert "additive — static still decides" in err
    assert "done: 1 corroborating" in err


def test_progress_summary_separates_hard_proof_in_legacy_mode(monkeypatch, capsys, spy_static):
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", evidence="SQL error",
                                      confidence="high", method="deterministic-backed"))
    R.run([_f()], _ctx(), _cfg_llm(ev_overrides_static=True))
    assert "done: 1 hard-proof" in capsys.readouterr().err


def test_progress_goes_to_stderr_not_stdout(monkeypatch, capsys, spy_static):
    # stdout may be redirected to capture a report; progress must not land in it
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="NOT_CONFIRMED", subtype="sqli"))
    R.run([_f()], _ctx(), _cfg())
    out, err = capsys.readouterr()
    assert "[s6-ev]" in err and "[s6-ev]" not in out


def test_s6_logs_the_two_phase_timings_separately(monkeypatch, capsys, spy_static):
    """EV and static run sequentially, so each phase gets its own wall clock — the split
    the combined Step-6 stage timer cannot give."""
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", evidence="judged",
                                      confidence="medium", method="agent-judged"))
    R.run([_f()], _ctx(), _cfg())
    err = capsys.readouterr().err
    assert "s6-ev complete in" in err          # exploit-verification portion
    assert "s6-verify complete in" in err       # static portion, timed on its own


def test_s6_emits_a_reconciled_funnel_summary(monkeypatch, capsys, spy_static):
    """One plain, copyable line after both phases finish — the whole funnel reconciled,
    since the per-finding probe lines interleave and scroll away."""
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", evidence="judged",
                                      confidence="medium", method="agent-judged"))
    R.run([_f()], _ctx(), _cfg())
    err = capsys.readouterr().err
    assert "S6 funnel:" in err
    for tok in ("into=", "live-tested=", "confirmed=", "static: tp=", "fp=", "time: ev "):
        assert tok in err, tok


def test_cvss_table_covers_every_confirmable_subtype():
    """Regression: the table kept the pre-rename keys ("access", "posture") after
    the subtype taxonomy changed, so 9 of 14 subtypes fell through to the 7.5
    default — publishing a missing-security-headers confirmation as 7.5/High."""
    from vvaharness.exploit_verification.verify.oracle import _TELLS
    assert set(_TELLS) - set(R._CVSS_BY_SUBTYPE) == set(), "subtype has no CVSS score"
    assert set(R._CVSS_BY_SUBTYPE) - set(_TELLS) == set(), "CVSS score for a dead subtype"


def test_host_posture_is_not_scored_high():
    # a missing header is not a High on its own
    assert R._CVSS_BY_SUBTYPE["headers"] < 7.0
    assert R._CVSS_BY_SUBTYPE["cmd"] >= 9.0        # ...and RCE is not a 7.5


def test_no_collection_is_plain_static(monkeypatch):
    called = {}

    def fake(findings, ctx, cfg):
        called["yes"] = True
        return list(findings), []
    monkeypatch.setattr(s6_verify, "run", fake)
    f = _f()
    verified, dropped = R.run([f], _ctx(collection=False), _cfg())
    assert called.get("yes") and verified == [f] and verified[0].ev_status is None


# ── LLM classification refinement wiring ──────────────────────────────────────
#
# The refinement always runs (no flag); its only fallback is an unresolvable model.
# The refined verdict has to reach `verify_candidate` — `verify_finding` used to
# re-derive it with its own `classify()` call, which silently discarded the
# refinement and fired the template payloads for a subtype the pass had rejected.

def _cfg_llm(**kw):
    return SimpleNamespace(models=SimpleNamespace(verify="m"),
                           step6_exploit_verification=ev_block(**kw))


def test_no_classify_model_stands_ev_down(monkeypatch, spy_static, capsys):
    """No model means no classification, and there is no table fallback: the CWE
    tables are what this pass exists to correct, so attacking on their say-so is
    the one outcome worse than not attacking. EV stands down, SAST is unaffected."""
    monkeypatch.setattr(R, "_ev_model", lambda cfg, purpose: None)   # no classify role
    _fake_map(monkeypatch, _MATCH)
    monkeypatch.setattr(R, "verify_candidate",
                        lambda *a, **k: pytest.fail("nothing may be attacked"))
    f = _f()
    verified, _ = R.run([f], _ctx(), _cfg_llm())
    assert spy_static["bucket"] == [f]                           # all to static
    assert len(verified) == 1                                    # still reported
    assert "standing down" in capsys.readouterr().err


def test_unresolvable_classification_stands_ev_down(monkeypatch, spy_static, capsys):
    """Same for a model that answers but never parseably — retries are exhausted
    inside `refine`, which raises rather than reverting to the tables."""
    def _raise(findings, table, **k):
        raise R.ev_llm.ClassificationUnavailable("no parseable verdicts")
    monkeypatch.setattr(R.ev_llm, "refine", _raise)
    _fake_map(monkeypatch, _MATCH)
    monkeypatch.setattr(R, "verify_candidate",
                        lambda *a, **k: pytest.fail("nothing may be attacked"))
    f = _f()
    verified, _ = R.run([f], _ctx(), _cfg_llm())
    assert spy_static["bucket"] == [f]          # stood down before any routing/stamping
    assert len(verified) == 1
    assert "standing down" in capsys.readouterr().err


def test_a_refined_skip_sends_the_finding_to_static(monkeypatch, spy_static):
    """The pass narrows: an ACTIVE finding it rejects reaches the static verifier
    and is still returned — never dropped."""
    from vvaharness.exploit_verification.classify import VerifyClass as VC
    from vvaharness.exploit_verification.classify.categories import Classification

    monkeypatch.setattr(R, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(R.ev_llm, "refine",
                        lambda findings, table, **k: {k2: Classification(VC.STATIC, None)
                                                     for k2 in table})
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli",
                                      confidence="high", method="deterministic"))
    f = _f()
    verified, _ = R.run([f], _ctx(), _cfg_llm())
    # went to static despite a CONFIRMED stub — the refined STATIC class means it was
    # never attacked, and the stamp records that rather than leaving it unexplained
    assert [_key(x) for x in spy_static["bucket"]] == [_key(f)]
    assert spy_static["bucket"][0].ev_status == "NOT_TESTED"
    assert len(verified) == 1                 # and is still in the output


def test_the_refined_classification_reaches_verify_candidate(monkeypatch, spy_static):
    """Regression: `verify_finding` re-called `classify()` and threw the refinement
    away, so a rejected subtype still drove the deterministic payload set."""
    from vvaharness.exploit_verification.classify import VerifyClass as VC
    from vvaharness.exploit_verification.classify.categories import Classification

    refined = Classification(VC.ACTIVE, None)      # the agentic route
    monkeypatch.setattr(R, "_ev_model", lambda cfg, purpose: SimpleNamespace(id="claude-x", via="sdk"))
    monkeypatch.setattr(R.ev_llm, "refine",
                        lambda findings, table, **k: {k2: refined for k2 in table})
    _fake_map(monkeypatch, _MATCH)

    seen = {}

    def _capture(f, m, opts, auth, **kw):
        seen["classification"] = kw.get("classification")
        return Verdict(status="NOT_CONFIRMED")
    monkeypatch.setattr(R, "verify_candidate", _capture)

    R.run([_f()], _ctx(), _cfg_llm())
    assert seen["classification"] == refined       # NOT the table's ACTIVE/sqli


# ── Pass 2 worker pool ──────────────────────────────────────────────────────────
#
# The confirm pass streams findings through `parallel` workers. These pin the two
# properties that make that safe: findings really do overlap, and buckets/report are
# assembled in candidate order regardless of which worker finished first.

def _cfg_par(parallel, **extra):
    return SimpleNamespace(models=SimpleNamespace(verify="m"),
                           step6_exploit_verification=ev_block(parallel=parallel, **extra))


def test_candidates_are_verified_concurrently(monkeypatch, spy_static):
    """With parallel>=N the findings overlap. A barrier is the deterministic proof:
    were the pass serial, the first worker would block on peers that were never
    dispatched and the barrier would break."""
    _fake_map(monkeypatch, _MATCH)
    barrier = threading.Barrier(4, timeout=10)

    def _verify(f, m, opts, auth, **kw):
        barrier.wait()                            # BrokenBarrierError unless parallel
        return Verdict(status="NOT_CONFIRMED", subtype="sqli")
    monkeypatch.setattr(R, "verify_candidate", _verify)

    findings = [_f(title=f"SQLi {i}") for i in range(4)]
    verified, _ = R.run(findings, _ctx(), _cfg_par(4))
    assert len(spy_static["bucket"]) == 4         # all reached static, none lost


def test_buckets_are_assembled_in_candidate_order(monkeypatch, spy_static):
    """Concurrency must not reach the report: the static bucket follows candidate
    order even when the first finding finishes last."""
    _fake_map(monkeypatch, _MATCH)
    gate = threading.Event()

    def _verify(f, m, opts, auth, **kw):
        if f.title == "SQLi 0":
            gate.wait(timeout=10)                 # first candidate finishes last
        else:
            gate.set()
        return Verdict(status="NOT_CONFIRMED", subtype="sqli")
    monkeypatch.setattr(R, "verify_candidate", _verify)

    findings = [_f(title=f"SQLi {i}") for i in range(4)]
    R.run(findings, _ctx(), _cfg_par(4))
    assert [b.title for b in spy_static["bucket"]] == [f"SQLi {i}" for i in range(4)]


def test_one_failing_finding_does_not_sink_the_others(monkeypatch, spy_static):
    """A worker that raises drops only its own finding to the static verifier; the
    rest still confirm. Uses legacy override so hard proofs skip static, making the
    isolation observable in the buckets."""
    _fake_map(monkeypatch, _MATCH)

    def _verify(f, m, opts, auth, **kw):
        if f.title == "SQLi 1":
            raise RuntimeError("verifier blew up")
        return Verdict(status="CONFIRMED", subtype="sqli", param="id",
                       confidence="high", method="deterministic-backed")
    monkeypatch.setattr(R, "verify_candidate", _verify)

    findings = [_f(title=f"SQLi {i}") for i in range(4)]
    verified, _ = R.run(findings, _ctx(), _cfg_par(4, ev_overrides_static=True))
    # the raising finding fell to static (as itself); the other 3 are hard-proof confirmed.
    assert [b.title for b in spy_static["bucket"]] == ["SQLi 1"]
    assert len(verified) == 4                     # 3 stamped + the 1 static


def test_serial_confirm_isolates_a_raising_finding_to_static(monkeypatch, spy_static):
    """The SERIAL confirm path (parallel<=1) must isolate a raising finding the same way
    the pool does: only that finding falls to the static verifier, the rest still confirm.
    Without the per-finding guard the exception unwinds the whole loop, so the static
    verifier never runs for ANY finding and the scan loses dedup/ranking/reporting."""
    _fake_map(monkeypatch, _MATCH)

    def _verify(f, m, opts, auth, **kw):
        if f.title == "SQLi 1":
            raise RuntimeError("verifier blew up")
        return Verdict(status="CONFIRMED", subtype="sqli", param="id",
                       confidence="high", method="deterministic-backed")
    monkeypatch.setattr(R, "verify_candidate", _verify)

    findings = [_f(title=f"SQLi {i}") for i in range(4)]
    # parallel=1 takes the serial branch, which the test above never reaches.
    verified, _ = R.run(findings, _ctx(), _cfg_par(1, ev_overrides_static=True))
    assert [b.title for b in spy_static["bucket"]] == ["SQLi 1"]
    assert len(verified) == 4                     # 3 stamped + the 1 static, none lost


# ── credential-freshness gate (S6 pre-check) ─────────────────────────────────

def _bearer_auth(monkeypatch):
    """Force a non-none strategy so the freshness gate actually runs."""
    monkeypatch.setattr(R, "load_auth_from_env",
                        lambda env=None: AuthConfig(strategy=AuthStrategy.BEARER, token="t"))


def _classify_by_title(monkeypatch):
    def fake(f):
        sub = "authz" if "authz" in (f.title or "") else "sqli"
        return Classification(VerifyClass.ACTIVE, sub)
    monkeypatch.setattr(R, "classify", fake)


def test_degrade_routes_auth_dependent_findings_to_static(monkeypatch, spy_static):
    # default policy: a credential we can't establish must not yield authz verdicts,
    # but auth-agnostic findings (sqli) still verify live.
    _bearer_auth(monkeypatch)
    _classify_by_title(monkeypatch)
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", param="id",
                                      evidence="SQL error", confidence="high",
                                      method="deterministic"))
    monkeypatch.setattr(R, "ensure_fresh",
                        lambda p, reachable, **k: Freshness.UNREFRESHABLE_EXPIRED)
    verified, _ = R.run([_f(title="authz bypass on /admin"), _f(title="SQLi via id")],
                        _ctx(), _cfg())
    # additive default: both reach static, but only the auth-agnostic sqli is
    # EV-confirmed; the degraded authz finding is routed to static WITHOUT an EV verdict.
    titles = [b.title for b in spy_static["bucket"]]
    assert "authz bypass on /admin" in titles and "SQLi via id" in titles
    assert any(getattr(x, "title", "") == "SQLi via id"
               and getattr(x, "ev_status", "") == "CONFIRMED" for x in verified)
    assert not any(getattr(x, "title", "") == "authz bypass on /admin"
                   and getattr(x, "ev_status", "") == "CONFIRMED" for x in verified)


def test_abort_policy_stands_ev_down(monkeypatch, spy_static):
    _bearer_auth(monkeypatch)
    _classify_by_title(monkeypatch)
    _fake_map(monkeypatch, _MATCH)
    called = {"n": 0}

    def spy_verify(f, m, opts, auth, **kw):
        called["n"] += 1
        return Verdict(status="CONFIRMED", subtype="sqli", confidence="high",
                       method="deterministic")
    monkeypatch.setattr(R, "verify_candidate", spy_verify)
    monkeypatch.setattr(R, "ensure_fresh", lambda p, reachable, **k: Freshness.ACQUIRE_FAILED)
    cfg = SimpleNamespace(models=SimpleNamespace(verify="m"),
                          step6_exploit_verification=ev_block(on_auth_failure="abort"))
    verified, _ = R.run([_f(title="SQLi via id"), _f(title="authz bypass")], _ctx(), cfg)
    assert called["n"] == 0                       # stood down before verifying anything
    assert len(spy_static["bucket"]) == 2         # every finding went to static


def test_fresh_credential_proceeds_normally(monkeypatch, spy_static):
    _bearer_auth(monkeypatch)
    _classify_by_title(monkeypatch)
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", param="id",
                                      evidence="SQL error", confidence="high",
                                      method="deterministic-backed"))
    monkeypatch.setattr(R, "ensure_fresh", lambda p, reachable, **k: Freshness.FRESH)
    verified, _ = R.run([_f(title="authz bypass"), _f(title="SQLi via id")],
                        _ctx(), _cfg())
    # fresh creds → nothing forced to static by the gate; both are EV-confirmed and
    # (additive default) both still go through the static verifier.
    assert len(spy_static["bucket"]) == 2
    assert sum(getattr(x, "ev_status", "") == "CONFIRMED" for x in verified) == 2


# ── rescue: an EV-confirmed finding the static verifier rejects still lives ────

def test_ev_confirmed_finding_static_rejects_is_rescued(monkeypatch):
    """Default additive: a finding EV confirmed but the static verifier drops as
    FALSE_POSITIVE is KEPT (rescued) with both verdicts visible — not dropped, and
    not counted as a static true positive."""
    from vvaharness.models import DroppedFinding
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", param="id",
                                      evidence="SQL error", confidence="high",
                                      method="deterministic-backed"))

    def fake_static(findings, ctx, cfg):
        dropped = [DroppedFinding(file=f.file, line=f.line_start, vuln_class=f.vuln_class,
                                  title=f.title, chunk_id=f.chunk_id,
                                  reason="FALSE_POSITIVE", detail="looks benign to static")
                   for f in findings]
        return [], dropped
    monkeypatch.setattr(s6_verify, "run", fake_static)

    verified, dropped = R.run([_f()], _ctx(), _cfg())
    assert dropped == []                                # not left in the dropped bin
    assert len(verified) == 1
    v = verified[0]
    assert v.ev_status == "CONFIRMED"                   # EV stamp survives
    assert v.verdict == "FALSE_POSITIVE"                # static's verdict shown alongside
    assert "static verifier: false_positive" in (v.verdict_reason or "")


def test_legacy_mode_does_not_rescue(monkeypatch):
    """With ev_overrides_static=true a non-hard confirm sent to static keeps the old
    behaviour: if static drops it, it is dropped (no rescue)."""
    from vvaharness.models import DroppedFinding
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="CONFIRMED", subtype="sqli", evidence="judged",
                                      confidence="medium", method="agent-judged"))

    def fake_static(findings, ctx, cfg):
        return [], [DroppedFinding(file=f.file, line=f.line_start, vuln_class=f.vuln_class,
                                   title=f.title, chunk_id=f.chunk_id,
                                   reason="FALSE_POSITIVE", detail="x") for f in findings]
    monkeypatch.setattr(s6_verify, "run", fake_static)

    verified, dropped = R.run([_f()], _ctx(), _cfg_llm(ev_overrides_static=True))
    assert verified == [] and len(dropped) == 1         # dropped, not rescued


# ── token accounting: EV and the static verifier bill to separate phases ──────

def test_ev_and_static_calls_land_in_separate_phase_buckets(monkeypatch):
    """`router.run` wraps its own work in the `s6-ev` phase and re-labels every
    delegation to the static verifier back to `s6-verify`, so the report's two S6 rows
    show what each side actually cost — not one row mixing both."""
    from vvaharness.util.tokens import TOKENS, DEFAULT_PHASE

    _fake_map(monkeypatch, _MATCH)

    def fake_verify_candidate(f, m, opts, auth, **kw):
        TOKENS.add({"input_tokens": 10, "output_tokens": 5})
        return Verdict(status="NOT_CONFIRMED", subtype="sqli", evidence="no tell")
    monkeypatch.setattr(R, "verify_candidate", fake_verify_candidate)

    def fake_static(findings, ctx, cfg):
        TOKENS.add({"input_tokens": 20, "output_tokens": 3})
        return list(findings), []
    monkeypatch.setattr(s6_verify, "run", fake_static)

    R.run([_f()], _ctx(), _cfg_llm())

    snap = TOKENS.snapshot()
    assert snap["by_phase"]["s6-ev"]["calls"] == 1
    assert snap["by_phase"]["s6-ev"]["prompt"] == 10
    assert snap["by_phase"]["s6-verify"]["calls"] == 1
    assert snap["by_phase"]["s6-verify"]["prompt"] == 20
    assert TOKENS._phase == DEFAULT_PHASE        # restored once run() returns


def test_stand_down_bills_only_to_the_static_phase(monkeypatch):
    """No classify model → EV stands down before making a single call of its own. Every
    call this run makes is the static verifier's, so the report must not show an `s6-ev`
    row with nothing behind it."""
    from vvaharness.util.tokens import TOKENS

    monkeypatch.setattr(R, "_ev_model", lambda cfg, purpose: None)   # no classify role
    _fake_map(monkeypatch, _MATCH)

    def fake_static(findings, ctx, cfg):
        TOKENS.add({"input_tokens": 7, "output_tokens": 1})
        return list(findings), []
    monkeypatch.setattr(s6_verify, "run", fake_static)

    R.run([_f()], _ctx(), _cfg_llm())

    snap = TOKENS.snapshot()
    assert "s6-ev" not in snap["by_phase"]
    assert snap["by_phase"]["s6-verify"]["calls"] == 1


# ── ev_probes: flatten a transcript into rows, and the store_probes gate ──────

def test_probe_rows_flatten_a_transcript(monkeypatch):
    f = _f(cwe="CWE-94", title="SSTI via name")
    f.line_end = 41
    match = _MATCH[0]
    rec = SimpleNamespace(method="get", url="http://t/greet", params={"name": "{{7*7}}"},
                          body=None, authed=False, auth_applied=frozenset(),
                          payload_label="ssti-1", injection_point="query.name",
                          response=SimpleNamespace(status=200, text="<h1>Hello, 49!</h1>",
                                                   elapsed=0.012, error=None))
    verdict = Verdict(status="CONFIRMED", subtype="ssti")
    rows = R._probe_rows(f, match, "ssti", "active", [rec], verdict)
    assert len(rows) == 1
    row = rows[0]
    assert row["finding_title"] == "SSTI via name" and row["cwe"] == "CWE-94"
    assert row["ev_class"] == "active" and row["ev_subtype"] == "ssti"
    assert row["ev_verdict"] == "CONFIRMED"
    assert row["endpoint_method"] == "GET" and row["endpoint_path"] == "/user"
    assert row["req_query"] == '{"name":"{{7*7}}"}' and row["injection_point"] == "query.name"
    assert row["resp_status"] == 200 and row["resp_ms"] == 12
    assert row["authed"] == 0 and row["auth_applied"] == ""


def test_probe_snippet_is_capped():
    assert len(R._snip("x" * 9000)) < R._PROBE_SNIPPET_CAP + 120
    assert "elided" in R._snip("x" * 9000)


def test_store_probes_flag_gates_persistence(monkeypatch, spy_static):
    calls = {"n": 0}
    monkeypatch.setattr("vvaharness.orchestrator.store.save_ev_probes",
                        lambda run_id, rows: calls.__setitem__("n", calls["n"] + 1) or len(rows))
    monkeypatch.setattr("vvaharness.orchestrator.store.save_replays", lambda *a, **k: 0)
    _fake_map(monkeypatch, _MATCH)
    _fake_verify(monkeypatch, Verdict(status="NOT_CONFIRMED", subtype="sqli"))
    ctx = SimpleNamespace(ev_collection=NormalizedCollection().model_dump(), repo_root="/tmp/r")

    # off (default) → not persisted
    R.run([_f()], ctx, _cfg())
    assert calls["n"] == 0
    # on → persisted (the gate fires even if this run's fake verify produced no rows)
    cfg_on = SimpleNamespace(models=SimpleNamespace(verify="m"),
                             step6_exploit_verification=ev_block(store_probes=True))
    R.run([_f()], ctx, cfg_on)
    assert calls["n"] == 1


# ── stored probes must never persist a credential ─────────────────────────────

def test_probe_rows_redact_credentials(monkeypatch):
    jwt = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ0ZXN0LTEyMyJ9.c3ludGhldGljX3Rlc3Rfc2ln"
    rec = SimpleNamespace(method="get", url="http://t/api/session",
                          params={"SESSIONID": jwt}, body={"password": "hunter2"},
                          authed=True, auth_applied=frozenset({"header:authorization"}),
                          payload_label="p", injection_point="query.SESSIONID",
                          response=SimpleNamespace(status=200, text=f"set-cookie: {jwt}",
                                                   elapsed=0.1, error=None))
    rows = R._probe_rows(_f(), _MATCH[0], "authz", "active", [rec], Verdict(status="CONFIRMED"))
    blob = str(rows)
    assert jwt not in blob and "hunter2" not in blob          # nothing secret persisted
    assert "[REDACTED]" in rows[0]["req_query"]               # SESSIONID key masked
    assert "[REDACTED" in rows[0]["resp_snippet"]             # JWT in response scrubbed


def test_probe_rows_snippet_masks_a_secret_straddling_its_own_cap():
    """`resp_snippet` is snipped head+tail, so a credential can span the cut. Redaction runs
    first — the mask-then-cap invariant `tests/test_ev_safety.py` checks at every other sink.
    This is the sixth sink, tested here where its fixtures live."""
    secret = "sess-9f2b1c7d4e8a0b3f6c2d"
    register_secret(secret)
    head = (R._PROBE_SNIPPET_CAP * 2) // 3            # where `_snip` cuts
    body = "x" * (head - 12) + secret + "y" * R._PROBE_SNIPPET_CAP
    rec = SimpleNamespace(method="get", url="http://127.0.0.1/api/x", params=None, body=None,
                          authed=False, auth_applied=frozenset(),
                          payload_label="p", injection_point="query.id",
                          response=SimpleNamespace(status=200, text=body,
                                                   elapsed=0.01, error=None))
    snippet = R._probe_rows(_f(), _MATCH[0], "authz", "active", [rec],
                            Verdict(status="CONFIRMED"))[0]["resp_snippet"]
    assert secret not in snippet and secret[:12] not in snippet
    assert "[REDACTED]" in snippet


def test_probe_rows_redact_a_secret_in_the_url_path(monkeypatch):
    """A credential can land in a URL PATH segment, not just the query or body. The stored
    ``req_url`` must mask it with the same marker as its siblings — otherwise store_probes
    persists the secret verbatim while req_query and req_body around it are scrubbed."""
    secret = "tok_deadbeefdeadbeef"
    register_secret(secret)                       # EV registers the credentials it injects
    rec = SimpleNamespace(method="get", url=f"http://127.0.0.1/api/{secret}/profile",
                          params=None, body=None, authed=False, auth_applied=frozenset(),
                          payload_label="p", injection_point="path",
                          response=SimpleNamespace(status=200, text="ok",
                                                   elapsed=0.01, error=None))
    rows = R._probe_rows(_f(), _MATCH[0], "authz", "active", [rec], Verdict(status="CONFIRMED"))
    url = rows[0]["req_url"]
    assert secret not in url                      # path-segment credential not persisted raw
    assert "[REDACTED]" in url                    # same marker as req_query / req_body
    assert "/profile" in url and "/api/" in url   # harmless URL structure survives


# ── profile knob → module wiring ───────────────────────────────────────────────
#
# The per-module sub-blocks (`classify:`, `mapper:`, `attacker:`, `judge:`) are only
# worth having if their values actually reach the module. Reading them correctly is
# not the same as passing them on, and a dropped keyword is invisible: the module
# quietly falls back to its own signature default, which equals the shipped default,
# so every observable number stays right until someone tunes a profile and nothing
# happens. These pin the hand-off at each seam.

def test_classify_knobs_reach_the_refinement(monkeypatch, spy_static):
    seen: dict = {}

    def spy_refine(findings, table, *, model, **kw):
        seen.update(kw)
        raise ev_llm.ClassificationUnavailable("stop after the hand-off")

    monkeypatch.setattr(R, "_ev_model", lambda cfg, purpose: "m")
    monkeypatch.setattr(ev_llm, "refine", spy_refine)
    R.run([_f()], _ctx(), _cfg_llm(**{"classify.batch": 5,
                                      "classify.parallel": 2}))
    assert (seen["batch"], seen["parallel"]) == (5, 2)
    # the triage output cap is NOT config — `batch` already bounds that output, so a
    # second dial could only be set out of step with the first.
    assert "max_tokens" not in seen


def test_mapper_knobs_reach_both_mapping_stages(monkeypatch, spy_static):
    index_kw: dict = {}
    map_kw: dict = {}

    def spy_index(col, ctx, **kw):
        index_kw.update(kw)
        return SimpleNamespace(located=[1])

    def spy_map(cands, *a, **kw):
        map_kw.update(kw)
        return {}

    monkeypatch.setattr(R, "build_index", spy_index)
    monkeypatch.setattr(R, "map_to_endpoints", spy_map)
    R.run([_f()], _ctx(), _cfg_llm(**{
        "mapper.max_turns": 7, "mapper.parallel": 2,
        "mapper.endpoint_index.chunk": 3,
        "mapper.finding_map.chunk": 2, "mapper.finding_map.max_endpoints": 1,
    }))
    # stage 1 takes its OWN chunk size; both stages share max_turns/parallel
    assert (index_kw["chunk"], index_kw["max_turns"], index_kw["parallel"]) == (3, 7, 2)
    assert (map_kw["chunk"], map_kw["max_turns"], map_kw["parallel"]) == (2, 7, 2)
    assert map_kw["max_endpoints"] == 1
