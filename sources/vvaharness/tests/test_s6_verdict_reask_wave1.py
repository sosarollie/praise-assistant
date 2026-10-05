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

"""Wave-1 tests for the S6 one-shot verdict parse-repair re-ask.

S6 used to drop a finding the instant `_parse_verdict` failed — which the
live-test campaign proved discards *committed* true positives (a
`TRUE_POSITIVE (confidence: 9/10) — Confirmed:` reply missing only the literal
`VERDICT:` prefix; an unauth arbitrary-file-write RCE at pygoat's apis.py:61).
`_verify_one` now makes exactly one bounded repair re-ask through the same
dispatch seam before falling through to today's VERIFY_ERROR drop, matching the
house pattern S2/S4 already use.

Offline + deterministic: the agentic call is monkeypatched (bare-string model →
via "cli" → `_deepagents.dispatch_agentic` routes to `registry.agentic`); no
real subprocess is spawned. The abort global is reset per test.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.backends.llm import cli, registry
from vvaharness.models import ContextPackage, Finding, VulnClass
from vvaharness.pipeline.stages import s6_verify


@pytest.fixture(autouse=True)
def _isolate():
    cli.reset_abort()
    yield
    cli.reset_abort()


def _finding(**kw) -> Finding:
    base = dict(
        chunk_id="chunk-01",
        file="introduction/apis.py",
        line_start=61,
        line_end=61,
        vuln_class=VulnClass.INJECTION,
        title="Unauthenticated arbitrary file write",
        description="attacker POST fields written straight to a .py file",
        code_snippet="f.write(log_code)",
        confidence=0.9,
    )
    base.update(kw)
    return Finding(**base)


def _ctx() -> ContextPackage:
    return ContextPackage(repo_root="/tmp/repo", language="python")


def _cfg(**step6) -> SimpleNamespace:
    defaults = dict(parallel=1, min_confidence=7, allowed_tools=["Read", "Grep"],
                    max_budget_usd=1.0, max_turns=None)
    defaults.update(step6)
    return SimpleNamespace(
        step6_verify=SimpleNamespace(**defaults),
        models=SimpleNamespace(verify="model-verify-test"),
    )


_GOOD_CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# A conforming repair reply — the two required contract lines.
_REPAIRED_TP = (
    "VERDICT: TRUE_POSITIVE (confidence: 9/10) — unauth arbitrary file write\n"
    f"CVSS: {_GOOD_CVSS}\n"
)
# The exact campaign loss: a committed TP that lacks the `VERDICT:` prefix, so
# the strict parser (correctly) rejects it as unparseable.
_PREFIXLESS_TP = "TRUE_POSITIVE (confidence: 9/10) — Confirmed: reachable and unauth\n"


def _is_repair(kw) -> bool:
    # The re-ask is tagged distinctly from the primary call.
    return "verdict-repair" in str(kw.get("tag", ""))


# 1. A prefix-less committed TP survives and is recorded as a true positive
#    once the re-ask restates it in the contract's shape.

def test_prefixless_true_positive_recovered_by_reask(monkeypatch):
    def fake_agentic(user, **kw):
        return _REPAIRED_TP if _is_repair(kw) else _PREFIXLESS_TP
    monkeypatch.setattr(registry, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg(min_confidence=7))

    assert dropped == []
    assert len(verified) == 1
    f = verified[0]
    assert f.verdict == "TRUE_POSITIVE"
    assert f.verdict_confidence == 9
    assert f.cvss_vector == _GOOD_CVSS


# 2. The re-ask happens AT MOST once: one primary call + one repair call, no
#    more, even when the repair also fails to parse.

def test_reask_happens_at_most_once(monkeypatch):
    calls = {"primary": 0, "repair": 0}

    def fake_agentic(user, **kw):
        if _is_repair(kw):
            calls["repair"] += 1
        else:
            calls["primary"] += 1
        # Carries a verdict TOKEN (so the gate lets the re-ask fire) but is still
        # unparseable (no `VERDICT:` footer), on BOTH attempts — never parses.
        return "TRUE_POSITIVE — still weighing it, no footer line here\n"
    monkeypatch.setattr(registry, "agentic", fake_agentic)

    s6_verify.run([_finding()], _ctx(), _cfg())

    assert calls["primary"] == 1
    assert calls["repair"] == 1   # exactly one re-ask, never a loop


# 3. A reply still unparseable after the re-ask keeps today's VERIFY_ERROR drop
#    record byte-for-byte — the recovery attempt precedes the drop, not replaces
#    it (models/_scan.py counts VERIFY_ERROR separately from false positives).

def test_still_unparseable_after_reask_drops_verify_error(monkeypatch):
    def fake_agentic(user, **kw):
        return "prose with no committed verdict, on both attempts\n"
    monkeypatch.setattr(registry, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg())

    assert verified == []
    assert len(dropped) == 1
    assert dropped[0].reason == "VERIFY_ERROR"
    assert dropped[0].reason != "FALSE_POSITIVE"
    assert "unparseable" in dropped[0].detail


# 4. A reply that parses first time triggers NO re-ask — no extra model call.

def test_parseable_first_reply_triggers_no_reask(monkeypatch):
    calls = {"primary": 0, "repair": 0}

    def fake_agentic(user, **kw):
        if _is_repair(kw):
            calls["repair"] += 1
            pytest.fail("re-ask fired for an already-parseable reply")
        calls["primary"] += 1
        return ("traced it\n"
                "VERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable\n"
                f"CVSS: {_GOOD_CVSS}\n")
    monkeypatch.setattr(registry, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg(min_confidence=7))

    assert calls == {"primary": 1, "repair": 0}
    assert len(verified) == 1
    assert dropped == []


# 5. F1 REGRESSION — an empty / verdict-free primary reply must NOT trigger the
#    repair re-ask (a fresh, context-free session cannot "restate" a conclusion
#    that was never reached — it would FABRICATE one, re-laundering the finding
#    into a confirmed FALSE_POSITIVE or shipping an invented TRUE_POSITIVE). It
#    goes straight to VERIFY_ERROR — correct AND cheaper. Fails on pre-fix code,
#    which fired the re-ask on any unparseable reply.

def test_verdict_free_primary_makes_no_repair_call(monkeypatch):
    calls = {"primary": 0, "repair": 0}

    def fake_agentic(user, **kw):
        if _is_repair(kw):
            calls["repair"] += 1
            pytest.fail("re-ask fired on a verdict-free reply — nothing to restate")
        calls["primary"] += 1
        return ""   # empty / hard-truncated: no verdict token anywhere
    monkeypatch.setattr(registry, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg())

    assert calls == {"primary": 1, "repair": 0}
    assert verified == []
    assert len(dropped) == 1
    assert dropped[0].reason == "VERIFY_ERROR"
    assert dropped[0].reason != "FALSE_POSITIVE"


# 6. F1 ADOPTION RULE — when the primary committed to exactly one verdict, the
#    repair may not flip it to the opposite. A primary that reads FALSE_POSITIVE
#    (no `VERDICT:` prefix) with a repair returning TRUE_POSITIVE is rejected as
#    inconsistent and drops VERIFY_ERROR — never adopted as a (fabricated) TP.

def test_repair_may_not_flip_a_committed_verdict(monkeypatch):
    def fake_agentic(user, **kw):
        if _is_repair(kw):
            return _REPAIRED_TP                       # tries to flip FP -> TP
        return "FALSE_POSITIVE (confidence: 6/10) — no external caller found\n"
    monkeypatch.setattr(registry, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg())

    assert verified == []                             # the flip is not adopted
    assert len(dropped) == 1
    assert dropped[0].reason == "VERIFY_ERROR"


# 7. F1 ADOPTION RULE — a primary that discusses BOTH verdicts in prose (the 3-of-4
#    real campaign shape) never committed to the contract's shape, so the repair is
#    the legitimate disambiguation and its committed verdict is adopted.

def test_repair_disambiguates_prose_mentioning_both_verdicts(monkeypatch):
    def fake_agentic(user, **kw):
        if _is_repair(kw):
            return _REPAIRED_TP
        return ("Weighing TRUE_POSITIVE vs FALSE_POSITIVE: the sink is reachable "
                "but I have not yet ruled out an upstream guard...\n")   # no footer
    monkeypatch.setattr(registry, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg(min_confidence=7))

    assert dropped == []
    assert len(verified) == 1
    assert verified[0].verdict == "TRUE_POSITIVE"


# 8. F2 — a CONFORMING two-line repair reply is only ~120 chars / ~30 tokens, which
#    trips the default VVAH-E003 floors (150 chars / 30 tokens). _verify_one wraps
#    the repair dispatch in stage_floors(), so the backend quality gate (simulated
#    here — monkeypatching registry.agentic bypasses the real one) must NOT WARN or
#    emit a recovered errlog record on the healthy repair path.

def test_short_conforming_repair_not_flagged_degenerate(monkeypatch, capsys):
    from vvaharness.util import response_quality

    response_quality.reset_counters()
    assert len(_REPAIRED_TP.strip()) < response_quality._DEFAULT_MIN_CHARS

    errlog_calls = []
    monkeypatch.setattr(response_quality._errlog, "log",
                        lambda *a, **k: errlog_calls.append((a, k)))

    def fake_agentic(user, **kw):
        if _is_repair(kw):
            # exactly what a real backend does on the agentic return path, and it
            # runs inside _verify_one's `with stage_floors(...)` scope.
            response_quality.check_response_quality(
                _REPAIRED_TP.strip(), stage=kw["tag"], output_tokens=30)
            return _REPAIRED_TP
        return _PREFIXLESS_TP
    monkeypatch.setattr(registry, "agentic", fake_agentic)

    verified, dropped = s6_verify.run([_finding()], _ctx(), _cfg(min_confidence=7))

    assert len(verified) == 1                      # still recovered normally
    assert errlog_calls == []                       # no recovered VVAH-E003 record
    assert "VVAH-E003" not in capsys.readouterr().err
