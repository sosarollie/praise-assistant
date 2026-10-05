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

"""Finding classification.

Two tiers: the deterministic CWE / vuln-class tables, and the LLM refinement pass
that narrows what the tables leave ambiguous.
"""

from __future__ import annotations
import json
import threading
from types import SimpleNamespace
import pytest
from vvaharness.exploit_verification.classify import (
    ACTIVE_SUBTYPES,
    PASSIVE_SUBTYPES,
    VerifyClass,
    _tables,
    classify,
)
from vvaharness.exploit_verification.verify.oracle import _INCONCLUSIVE_ONLY, _TELLS
from vvaharness.exploit_verification.classify.categories import Classification
from vvaharness.exploit_verification._util import json_objects
from vvaharness.exploit_verification.classify.llm import (
    CONFIRMABLE,
    TELL_DOC,
    ClassificationUnavailable,
    finding_id,
    refine,
)


# ════ deterministic tables ════

def _f(vuln_class="other", cwe=None, title="", description=""):
    return SimpleNamespace(vuln_class=vuln_class, cwe=cwe, title=title, description=description)


# ── primary: vuln_class -> class ─────────────────────────────────────────────

@pytest.mark.parametrize("vuln_class,cls", [
    ("injection", VerifyClass.ACTIVE),
    ("unsafe-deserialization", VerifyClass.ACTIVE),
    # info-leak observability is context-dependent (log vs. response) -> UNCLASSIFIED,
    # so the LLM decides rather than a hard STATIC gate.
    ("info-leak", VerifyClass.UNCLASSIFIED),
    # memory-safety / concurrency family is parked -> UNCLASSIFIED.
    ("use-after-free", VerifyClass.UNCLASSIFIED),
    ("heap-overflow", VerifyClass.UNCLASSIFIED),
    ("stack-overflow", VerifyClass.UNCLASSIFIED),
    ("format-string", VerifyClass.UNCLASSIFIED),
    ("integer-overflow", VerifyClass.UNCLASSIFIED),
    ("type-confusion", VerifyClass.UNCLASSIFIED),
    # race/TOCTOU -> STATIC: unconfirmable while the loop sends serially (no burst).
    ("race-condition", VerifyClass.STATIC),
])
def test_vuln_class_maps_to_class(vuln_class, cls):
    assert classify(_f(vuln_class=vuln_class)).cls is cls


def test_unsafe_deserialization_carries_subtype():
    # a specific-enough vuln_class fixes the subtype without needing a CWE.
    r = classify(_f(vuln_class="unsafe-deserialization"))
    assert r.cls is VerifyClass.ACTIVE and r.subtype == "deser"


def test_ambiguous_vuln_class_defaults_unclassified():
    # logic-flaw / other carry no confident class and no refinement signal.
    for vc in ("logic-flaw", "other"):
        r = classify(_f(vuln_class=vc))
        assert r.cls is VerifyClass.UNCLASSIFIED and r.subtype is None


def test_vuln_class_is_normalized():
    r = classify(_f(vuln_class="  INJECTION "))
    assert r.cls is VerifyClass.ACTIVE


def test_vuln_class_enum_value_accepted():
    # classify must handle a vuln_class carrying a .value (real enum) too.
    r = classify(_f(vuln_class=SimpleNamespace(value="injection")))
    assert r.cls is VerifyClass.ACTIVE


# ── confident-but-coarse class: the CWE fills the subtype ─────────────────────

@pytest.mark.parametrize("cwe,subtype", [
    ("CWE-89", "sqli"), ("CWE-79", "xss"), ("CWE-78", "cmd"),
    ("CWE-22", "path"), ("CWE-918", "ssrf"), ("CWE-611", "xxe"),
    ("CWE-601", "open_redirect"), ("CWE-1336", "ssti"),
    ("CWE-639", "idor"), ("CWE-862", "noauth"),
])
def test_injection_class_gets_subtype_from_cwe(cwe, subtype):
    # vuln_class=injection fixes ACTIVE; the CWE supplies the specific subtype.
    r = classify(_f(vuln_class="injection", cwe=cwe))
    assert r.cls is VerifyClass.ACTIVE and r.subtype == subtype


def test_injection_without_signal_has_no_subtype():
    # class known (ACTIVE) but nothing pins the subtype -> None (LLM resolves later).
    r = classify(_f(vuln_class="injection"))
    assert r.cls is VerifyClass.ACTIVE and r.subtype is None


def test_prose_alone_no_longer_fills_a_subtype():
    """Title/description prose must NOT pick a subtype — the keyword tier is gone.

    The subtype selects the payload template, the oracle tell, AND the published
    CVSS, so guessing it from a substring is three wrong decisions at once. An
    unresolved subtype on a live class is the honest answer and routes to the
    agentic path (see ``_engine._fill_subtype``).
    """
    r = classify(_f(vuln_class="injection", title="Reflected XSS in name param"))
    assert r.cls is VerifyClass.ACTIVE and r.subtype is None


# ── CWE is the authority for an ambiguous vuln_class ─────────────────────────

@pytest.mark.parametrize("cwe,subtype", [
    ("CWE-89", "sqli"), ("CWE-79", "xss"), ("CWE-78", "cmd"),
    ("CWE-22", "path"), ("CWE-918", "ssrf"), ("CWE-601", "open_redirect"),
    ("CWE-502", "deser"), ("CWE-639", "idor"),
    ("CWE-284", "authz"), ("CWE-862", "noauth"), ("CWE-863", "authz"),
])
def test_cwe_resolves_ambiguous_to_active(cwe, subtype):
    r = classify(_f(vuln_class="other", cwe=cwe))
    assert r.cls is VerifyClass.ACTIVE and r.subtype == subtype


@pytest.mark.parametrize("cwe,subtype", [
    ("CWE-942", "cors"), ("CWE-346", "cors"),
    ("CWE-614", "cookies"), ("CWE-1021", "headers"),
])
def test_cwe_resolves_ambiguous_to_passive(cwe, subtype):
    r = classify(_f(vuln_class="other", cwe=cwe))
    assert r.cls is VerifyClass.PASSIVE and r.subtype == subtype


@pytest.mark.parametrize("cwe", ["CWE-295", "CWE-599", "CWE-319", "CWE-523", "CWE-693"])
def test_outbound_tls_and_transport_cwes_are_unclassified(cwe):
    """TLS/transport defects are usually off-wire (295/599 = outbound cert validation,
    319/523 = cleartext config, 693 = broad parent), so they must NOT auto-route to a
    PASSIVE/headers wire tell. But observability is context-dependent, so they are
    UNCLASSIFIED (the LLM decides) rather than hard STATIC — the LLM routes the genuinely
    off-wire ones back to static without a table pre-empting the call."""
    r = classify(_f(vuln_class="other", cwe=cwe))
    assert r.cls is VerifyClass.UNCLASSIFIED and r.subtype is None


@pytest.mark.parametrize("cwe", ["CWE-416", "CWE-787", "CWE-119", "CWE-476"])
def test_cwe_resolves_memory_safety_to_unclassified(cwe):
    # Memory-safety CWEs stay parked -> UNCLASSIFIED (dropped to semantic verify).
    r = classify(_f(vuln_class="other", cwe=cwe))
    assert r.cls is VerifyClass.UNCLASSIFIED and r.subtype is None


@pytest.mark.parametrize("cwe", ["CWE-400", "CWE-770", "CWE-1333", "CWE-674", "CWE-834"])
def test_cwe_resolves_dos_and_redos_to_static(cwe):
    # Resource-exhaustion / DoS / ReDoS -> STATIC: never attacked on the wire, since
    # a confirming probe wedges the shared target and poisons other findings.
    r = classify(_f(vuln_class="other", cwe=cwe))
    assert r.cls is VerifyClass.STATIC and r.subtype is None


@pytest.mark.parametrize("cwe", ["CWE-362", "CWE-367"])
def test_cwe_resolves_race_to_static(cwe):
    # Race / TOCTOU -> STATIC: not dangerous, but unconfirmable while the adaptive
    # loop sends serially (no burst → the window is never hit). Reported by the
    # static verifier, not attacked. Revisit when within-finding concurrency lands.
    r = classify(_f(vuln_class="other", cwe=cwe))
    assert r.cls is VerifyClass.STATIC and r.subtype is None


@pytest.mark.parametrize("cwe", ["CWE-798", "CWE-327", "CWE-330", "CWE-200"])
def test_cwe_resolves_secrets_crypto_info_to_unclassified(cwe):
    # Secrets (798), weak crypto/RNG (327/330), info exposure (200): observability is
    # context-dependent, so these are UNCLASSIFIED (sent to the LLM) rather than the
    # HARD-STATIC tier reserved for DoS/race. The LLM skips genuinely off-wire ones.
    r = classify(_f(vuln_class="other", cwe=cwe))
    assert r.cls is VerifyClass.UNCLASSIFIED and r.subtype is None


def test_cwe_does_not_override_a_confident_vuln_class():
    # vuln_class is primary: a parked memory class stays UNCLASSIFIED even with a
    # payload-looking CWE, and injection stays ACTIVE even with a static-only CWE
    # (the mismatched CWE cannot even lend its subtype).
    r = classify(_f(vuln_class="heap-overflow", cwe="CWE-89"))
    assert r.cls is VerifyClass.UNCLASSIFIED
    r = classify(_f(vuln_class="injection", cwe="CWE-798"))
    assert r.cls is VerifyClass.ACTIVE and r.subtype is None


# ── no keyword tier: prose never decides a class ──────────────────────────────

@pytest.mark.parametrize("vuln_class,title,description", [
    ("other", "SQL injection via id parameter", ""),
    ("logic-flaw", "", "Broken access control on /admin"),
    ("other", "Hardcoded API secret in source", ""),
])
def test_prose_alone_stays_unclassified(vuln_class, title, description):
    """With an ambiguous vuln_class and no usable CWE, the answer is UNCLASSIFIED.

    These three used to resolve to ACTIVE/sqli, ACTIVE/authz and STATIC purely
    from a substring. "access control" appearing in prose is not evidence the
    finding is an authz defect on the endpoint we happen to map it to — that
    inference is how a wrong-endpoint confirmation gets published. Resolving
    these is now :mod:`..classify.llm`'s job, which reads the whole finding.
    """
    r = classify(_f(vuln_class=vuln_class, title=title, description=description))
    assert r.cls is VerifyClass.UNCLASSIFIED and r.subtype is None


def test_unknown_cwe_defaults_unclassified():
    r = classify(_f(vuln_class="other", cwe="CWE-99999",
                    title="something odd", description="n/a"))
    assert r.cls is VerifyClass.UNCLASSIFIED and r.subtype is None


# ── invariants ───────────────────────────────────────────────────────────────

def test_is_live_matches_class():
    assert classify(_f(vuln_class="injection")).is_live is True
    assert classify(_f(vuln_class="other", cwe="CWE-942")).is_live is True
    assert classify(_f(vuln_class="info-leak")).is_live is False
    assert classify(_f(vuln_class="other")).is_live is False


def test_subtypes_are_in_the_declared_vocabulary():
    # every subtype the classifier can emit must be in the class's vocabulary --
    # that vocabulary is the contract downstream switches on.
    for vc, cwe, _t, _e, sub in _GOLDEN:
        r = classify(_f(vuln_class=vc, cwe=cwe, title=_t))
        if r.subtype is None:
            continue
        if r.cls is VerifyClass.ACTIVE:
            assert r.subtype in ACTIVE_SUBTYPES
        elif r.cls is VerifyClass.PASSIVE:
            assert r.subtype in PASSIVE_SUBTYPES


# ── golden corpus: (vuln_class, cwe, title) → expected (class, subtype) ───────
# A representative table covering every (vuln_class, cwe) pairing the classifier
# must place, one row apiece. Locks in the expected (class, subtype) so a table
# edit can't silently regress. Titles are illustrative and fully generic —
# classify() decides from vuln_class + cwe, never from prose (see
# test_prose_alone_stays_unclassified), so a title carries no test weight beyond
# documenting the row.
_GOLDEN = [
    # (vuln_class, cwe, title, expected class, expected subtype)
    # -- ACTIVE: injection family + access/authz -------------------------------
    ("injection", "CWE-89", "Unsanitized user input concatenated into a backend query", "ACTIVE", "sqli"),
    ("injection", "CWE-78", "OS command injection via an unsanitized path argument", "ACTIVE", "cmd"),
    ("injection", "CWE-79", "Reflected XSS via an unsanitized `name` parameter in HTML", "ACTIVE", "xss"),
    ("injection", "CWE-918", "Unsanitized identifier appended to an outbound request URL", "ACTIVE", "ssrf"),
    ("injection", "CWE-22", "Path traversal via an attacker-controlled name parameter", "ACTIVE", "path"),
    ("logic-flaw", "CWE-306", "Sensitive API endpoints lack authentication checks", "ACTIVE", "noauth"),
    ("logic-flaw", "CWE-862", "Unauthenticated resource-key validation endpoint", "ACTIVE", "noauth"),
    ("logic-flaw", "CWE-863", "Middleware bypasses auth for all non-/api/ paths", "ACTIVE", "authz"),
    ("logic-flaw", "CWE-287", "Hardcoded `if True` makes an auth branch always execute", "ACTIVE", "authz"),
    ("logic-flaw", "CWE-918", "URL scheme check still allows SSRF to arbitrary hosts", "ACTIVE", "ssrf"),
    ("logic-flaw", "CWE-601", "Open redirect via a hardcoded client-side location assignment", "ACTIVE", "open_redirect"),
    ("other", "CWE-22", "Unauthenticated path traversal via an SPA catch-all route", "ACTIVE", "path"),
    ("other", "CWE-306", "Search endpoint requires no authentication", "ACTIVE", "noauth"),
    ("other", "CWE-639", "Unauthenticated resource discovery via a listing endpoint", "ACTIVE", "idor"),
    ("other", "CWE-918", "Unauthenticated-reachable SSRF with redirect following", "ACTIVE", "ssrf"),
    # -- STATIC: resource-exhaustion / DoS / ReDoS (never attacked on the wire) --
    ("logic-flaw", "CWE-400", "Unbounded id list enables resource exhaustion", "STATIC", None),
    ("other", "CWE-770", "Unbounded identifier array drives an expensive DB query", "STATIC", None),
    ("other", "CWE-400", "In-memory pending-request dict grows unbounded — DoS", "STATIC", None),
    # -- STATIC: race / TOCTOU (unconfirmable while the loop sends serially) -------
    ("race-condition", "CWE-362", "In-process dict for session state breaks multi-worker deploys", "STATIC", None),
    ("race-condition", "CWE-367", "TOCTOU race between a pre-check and the parallel work it guards", "STATIC", None),
    # -- PASSIVE: host-level / transport ---------------------------------------
    ("logic-flaw", "CWE-942", "Wildcard CORS origin combined with allow_credentials=True", "PASSIVE", "cors"),
    ("other", "CWE-942", "Wildcard CORS with credentials enables cross-origin reads", "PASSIVE", "cors"),
    ("other", "CWE-1021", "Missing X-Frame-Options allows clickjacking of a served page", "PASSIVE", "headers"),
    # -- UNCLASSIFIED: outbound TLS / transport — usually off-wire, but context-
    # dependent, so the LLM gates observability (it must NOT auto-route to a
    # PASSIVE/headers wire tell, which once mis-"confirmed" a Dockerfile CA finding).
    ("other", "CWE-319", "Hardcoded HTTP (plaintext) service URLs committed to the repo", "UNCLASSIFIED", None),
    ("logic-flaw", "CWE-295", "Single-cert PEM bundle silently disables CA verification", "UNCLASSIFIED", None),
    # -- UNCLASSIFIED: secrets / crypto / disclosure — observability is context-
    # dependent (off-wire in a log/source vs. returned in a response), LLM decides ----
    ("info-leak", "CWE-798", "Hardcoded API key and database password in source", "UNCLASSIFIED", None),
    ("info-leak", "CWE-532", "Untrusted LLM prompt content written to a world-readable log", "UNCLASSIFIED", None),
    ("info-leak", "CWE-200", "Unauthenticated credential-validation oracle exposes valid users", "UNCLASSIFIED", None),
    ("other", "CWE-798", "Hardcoded default session-signing key enables session compromise", "UNCLASSIFIED", None),
    ("other", "CWE-327", "Non-cryptographic hash used for a security-relevant value", "UNCLASSIFIED", None),
    ("other", "CWE-522", "Credentials sourced from world-readable .env files", "UNCLASSIFIED", None),
    ("logic-flaw", "CWE-330", "Predictable MD5-based token allows token forgery", "UNCLASSIFIED", None),
    # -- UNCLASSIFIED: correctness / logic bugs not live-confirmable -----------
    ("logic-flaw", "CWE-703", "KeyError on a missing field in an error fallback path", "UNCLASSIFIED", None),
    ("logic-flaw", "CWE-269", "Request model lets the caller self-assign any role", "UNCLASSIFIED", None),
    ("logic-flaw", "CWE-613", "Refresh endpoint does not verify the token audience", "UNCLASSIFIED", None),
    ("other", "CWE-1104", "All dependencies unpinned; no lockfile present", "UNCLASSIFIED", None),
]


@pytest.mark.parametrize("vuln_class,cwe,title,cls,subtype", _GOLDEN,
                         ids=[f"{v}:{c}" for v, c, _t, _e, _s in _GOLDEN])
def test_golden_corpus(vuln_class, cwe, title, cls, subtype):
    r = classify(_f(vuln_class=vuln_class, cwe=cwe, title=title))
    assert r.cls.name == cls
    assert r.subtype == subtype


# ── classifier ↔ oracle contract ──────────────────────────────────────────────
#
# The classifier's `subtype` is the single value the payload builder and the
# oracle both switch on. Nothing enforced that the two agree, so a subtype could
# be emitted that `oracle._TELLS` has no entry for — EV would then route the
# finding to the LIVE path, build payloads, spend its request budget against the
# target, and return NOT_CONFIRMED by construction. That is strictly worse than
# routing it to the static verifier, which at least renders a verdict.
#
# Concretely: CWE-639 classifies to ACTIVE/idor while `_t_idor` returns None
# unconditionally, so it could never confirm. That gap is legitimate but must be
# *declared* in `oracle._INCONCLUSIVE_ONLY` rather than discovered at runtime —
# these tests make the declaration mandatory.


_DECLARED_SUBTYPES = ACTIVE_SUBTYPES | PASSIVE_SUBTYPES


def test_every_declared_subtype_has_a_tell():
    """A subtype the classifier may emit must be dispatchable by the oracle."""
    assert _DECLARED_SUBTYPES - set(_TELLS) == set()


def test_no_orphan_tells():
    """And no tell exists for a subtype the classifier can never produce."""
    assert set(_TELLS) - _DECLARED_SUBTYPES == set()


def _table_subtypes():
    """Every subtype reachable from the real lookup tables (not the vocabulary).

    Walks `_VULNCLASS` / `_CWE` so a typo'd or newly-added table entry is caught
    here rather than at runtime against a live target.
    """
    return {subtype
            for _cls, subtype in (*_tables._VULNCLASS.values(), *_tables._CWE.values())
            if subtype is not None}


def test_table_subtypes_are_all_declared_and_dispatchable():
    table = _table_subtypes()
    assert table - _DECLARED_SUBTYPES == set(), "table emits an undeclared subtype"
    assert table - set(_TELLS) == set(), "table emits a subtype the oracle cannot dispatch"


def test_inconclusive_only_is_declared_and_minimal():
    """The known-unconfirmable set must be real subtypes, and stay explicit.

    Pinned deliberately: adding a stub tell (one that cannot fire in-band)
    without listing it here would let EV attack a finding it can never confirm.
    """
    assert _INCONCLUSIVE_ONLY <= _DECLARED_SUBTYPES
    assert set(_INCONCLUSIVE_ONLY) == {"idor", "deser"}


def test_confirmable_subtypes_are_the_declared_set_minus_known_gaps():
    """The set EV can actually prove — the denominator for any routing change."""
    confirmable = _DECLARED_SUBTYPES - set(_INCONCLUSIVE_ONLY)
    assert confirmable == {
        "sqli", "xss", "ssrf", "xxe", "cmd", "path",
        "open_redirect", "ssti", "authz", "noauth",
        "cors", "headers", "cookies",
    }


# ════ LLM refinement pass ════

def _llmf(file="app.py", line=1, cwe=None, vuln_class="other", title="", description="",
          scenario=""):
    return SimpleNamespace(file=file, line_start=line, cwe=cwe, vuln_class=vuln_class,
                           title=title, description=description,
                           exploit_scenario=scenario, impact="")


def _table(findings):
    return {finding_id(f, i): classify(f) for i, f in enumerate(findings)}


def _reply(*objs):
    """A model stub returning the given answer objects as its JSON array."""
    payload = json.dumps(list(objs))
    return lambda system, user, *, model: payload


# ── the prompt must describe every subtype it offers ──────────────────────────

def test_every_offered_subtype_is_documented_for_the_model():
    """"Can this be confirmed?" is unanswerable without saying what confirmation is.

    So each subtype the prompt offers must carry its tell. A subtype in the menu
    with no description invites the model to guess at what we can prove.
    """
    assert set(CONFIRMABLE) - set(TELL_DOC) == set()


def test_the_menu_excludes_subtypes_we_cannot_prove():
    """`idor`/`deser` are declared unconfirmable, so offering them would let the
    model route a finding onto a path defined to return INCONCLUSIVE."""
    assert set(CONFIRMABLE) & set(_INCONCLUSIVE_ONLY) == set()
    assert CONFIRMABLE <= set(_TELLS)


# ── never delete: a skip becomes static, not a disappearance ──────────────────

def test_skip_routes_to_static_and_never_drops_the_finding():
    f = _llmf(cwe="CWE-89", vuln_class="injection", title="SQLi in login")
    table = _table([f])
    fid = finding_id(f, 0)
    assert table[fid].is_live                          # table wanted to attack it

    out = refine([f], table, model="m",
                 call=_reply({"id": fid, "action": "skip", "reason": "not on the wire"}))
    assert (out[fid].cls, out[fid].subtype) == (VerifyClass.STATIC, None)
    assert set(out) == set(table)                      # same findings in, same out


# ── HARD STATIC is final: the model never sees it, so it cannot put it on the wire ──
# (Hard static = DoS/ReDoS + race, where a confirming probe is harmful/unconfirmable.)

def test_a_table_static_finding_is_never_sent_to_the_model():
    f = _llmf(cwe="CWE-400", title="Unbounded id list — resource exhaustion")  # table -> hard STATIC
    table = _table([f])
    seen = {}

    def _spy(system, user, *, model):
        seen["user"] = user
        return "[]"

    refine([f], table, model="m", call=_spy)
    assert "user" not in seen           # nothing sendable -> no call at all


def test_the_model_cannot_widen_a_table_static_finding():
    """Even if the model insists, a finding the tables ruled harmful-to-attack (DoS)
    stays off the wire.

    Enforced structurally: hard STATIC is never sent, so its id is not in the batch
    and the answer has nothing to attach to.
    """
    static_f = _llmf(cwe="CWE-400", title="Unbounded id list — resource exhaustion")
    live_f = _llmf(file="b.py", cwe="CWE-89", vuln_class="injection", title="SQLi")
    table = _table([static_f, live_f])
    sid, lid = finding_id(static_f, 0), finding_id(live_f, 1)

    out = refine([static_f, live_f], table, model="m",
                 call=_reply({"id": sid, "action": "attack", "subtype": "sqli"},
                             {"id": lid, "action": "attack", "subtype": "sqli"}))
    assert out[sid] == Classification(VerifyClass.STATIC, None)   # unchanged
    assert out[lid] == Classification(VerifyClass.ACTIVE, "sqli")


# ── only STATIC is final; UNCLASSIFIED is a question, not an answer ───────────

def test_unclassified_is_sent_to_the_model():
    """`UNCLASSIFIED` means "no rule matched / family parked" — i.e. we don't know.

    Regression: filtering on `is_live` excluded it, so wire-observable findings the
    tables cannot place (a business-logic bug with no matching subtype) were dropped
    before the model saw them. A parked/unresolved family is a statement about our
    tell coverage, not about the finding. (Race and DoS/ReDoS are the exception —
    they are STATIC, not UNCLASSIFIED, so they are deliberately NOT sent.)
    """
    from vvaharness.exploit_verification.classify.llm import _sendable
    f = _llmf(cwe=None, vuln_class="other", title="Coupon reused via caller-supplied user_id")
    table = _table([f])
    fid = finding_id(f, 0)
    assert table[fid].cls is VerifyClass.UNCLASSIFIED
    assert _sendable(table[fid])                      # sent, unlike STATIC

    sent = {}
    refine([f], table, model="m",
           call=lambda s, u, *, model: sent.update(user=u) or json.dumps(
               [{"id": fid, "action": "attack", "subtype": None}]))
    assert fid in sent["user"]                        # it really was in the batch


def test_the_model_may_promote_an_unclassified_finding():
    """Promoting from "we don't know" is not a reversal, so it is allowed — unlike
    STATIC, which asserts a negative the tables can actually support. A business-logic
    bug with no matching CWE is the live example: the tables leave it UNCLASSIFIED,
    the model routes it to the agentic path (observable over HTTP, but no subtype
    fits)."""
    f = _llmf(cwe=None, vuln_class="other", title="Coupon reused via caller-supplied user_id")
    table = _table([f])
    fid = finding_id(f, 0)
    assert table[fid].cls is VerifyClass.UNCLASSIFIED

    out = refine([f], table, model="m",
                 call=_reply({"id": fid, "action": "attack", "subtype": None,
                              "reason": "the repeated discount is observable over HTTP"}))
    assert (out[fid].cls, out[fid].subtype) == (VerifyClass.ACTIVE, None)


def test_info_exposure_is_sendable_and_promotable():
    """The split's whole point: a response-exposure finding (CWE-200) is UNCLASSIFIED
    now, so the LLM sees it and can promote it live — instead of a hard STATIC gate
    hiding it from the model."""
    from vvaharness.exploit_verification.classify.llm import _sendable
    f = _llmf(cwe="CWE-200", vuln_class="info-leak",
              title="Endpoint returns rows including the plaintext password column")
    table = _table([f])
    fid = finding_id(f, 0)
    assert table[fid].cls is VerifyClass.UNCLASSIFIED and _sendable(table[fid])
    out = refine([f], table, model="m",
                 call=_reply({"id": fid, "action": "attack", "subtype": None,
                              "reason": "password is returned in the response body"}))
    assert (out[fid].cls, out[fid].subtype) == (VerifyClass.ACTIVE, None)


def test_secret_in_source_is_sendable_but_the_model_skips_it():
    """A hardcoded secret is now UNCLASSIFIED (sent), but the prompt tells the model to
    skip off-wire exposure — so it lands back at STATIC by the model's judgment, not a
    table gate."""
    f = _llmf(cwe="CWE-798", vuln_class="info-leak", title="Hardcoded AWS key in source")
    table = _table([f])
    fid = finding_id(f, 0)
    assert table[fid].cls is VerifyClass.UNCLASSIFIED
    out = refine([f], table, model="m",
                 call=_reply({"id": fid, "action": "skip", "reason": "never leaves source"}))
    assert (out[fid].cls, out[fid].subtype) == (VerifyClass.STATIC, None)


def test_static_is_final_and_never_sendable():
    from vvaharness.exploit_verification.classify.llm import _sendable
    f = _llmf(cwe="CWE-400", title="Unbounded id list — resource exhaustion")
    assert _table([f])[finding_id(f, 0)].cls is VerifyClass.STATIC
    assert not _sendable(_table([f])[finding_id(f, 0)])


# ── subtype discipline ────────────────────────────────────────────────────────

@pytest.mark.parametrize("subtype", ["idor", "deser", "race", "redos", "nonsense", ""])
def test_an_unprovable_or_invented_subtype_degrades_to_the_agentic_route(subtype):
    """A subtype we cannot prove must never load a template.

    `idor`/`deser` are declared unconfirmable and `race`/`redos`/`nonsense` do not
    exist, so honouring any of them would spend the request budget on a path that
    cannot confirm. The finding stays live but with no subtype, which is the
    agentic route — capped downstream at agent-judged/medium.
    """
    f = _llmf(cwe="CWE-89", vuln_class="injection", title="something")
    table = _table([f])
    fid = finding_id(f, 0)
    out = refine([f], table, model="m",
                 call=_reply({"id": fid, "action": "attack", "subtype": subtype}))
    assert (out[fid].cls, out[fid].subtype) == (VerifyClass.ACTIVE, None)


def test_null_subtype_is_the_agentic_route():
    """The answer for "observable over HTTP, but none of your tells fit" — e.g. a
    Werkzeug debug console. Live, no subtype, so no template is loaded."""
    f = _llmf(cwe="CWE-94", vuln_class="other",
              title="Werkzeug interactive debugger enabled in production")
    table = _table([f])
    fid = finding_id(f, 0)
    assert table[fid] == Classification(VerifyClass.ACTIVE, "cmd")   # the bad table guess

    out = refine([f], table, model="m",
                 call=_reply({"id": fid, "action": "attack", "subtype": None,
                              "reason": "confirmed by GET /console, not a cmd payload"}))
    assert (out[fid].cls, out[fid].subtype) == (VerifyClass.ACTIVE, None)


def test_classifier_reason_is_carried_onto_the_verdict():
    """The model's one-clause reason rides on the Classification, so a finding that
    never gets live-tested can say WHY in the report (router._stamp_untested) instead
    of a generic "classified static"."""
    f = _llmf(cwe="CWE-319", vuln_class="other", title="Cleartext transport to Artifactory")
    fid = finding_id(f, 0)
    out = refine([f], _table([f]), model="m",
                 call=_reply({"id": fid, "action": "skip",
                              "reason": "requires network MitM position; not observable over HTTP"}))
    assert out[fid].cls is VerifyClass.STATIC
    assert out[fid].reason == "requires network MitM position; not observable over HTTP"


def test_a_passive_subtype_gets_the_passive_class():
    """The class must follow the subtype, or `headers` would be mapped as a
    route-bound injection point instead of through `map_passive`."""
    f = _llmf(cwe="CWE-1021", vuln_class="other", title="Missing X-Frame-Options")
    table = _table([f])
    fid = finding_id(f, 0)
    out = refine([f], table, model="m",
                 call=_reply({"id": fid, "action": "attack", "subtype": "headers"}))
    assert (out[fid].cls, out[fid].subtype) == (VerifyClass.PASSIVE, "headers")


# ── failure modes: retry the parseable ones, then refuse — never the tables ──────

def _live_one():
    f = _llmf(cwe="CWE-89", vuln_class="injection", title="SQLi in login")
    return f, _table([f]), finding_id(f, 0)


def test_a_raising_model_refuses_rather_than_using_the_tables():
    """No table fallback: the CWE tables are what this pass exists to correct, so
    attacking a live target on their say-so is worse than not attacking. The router
    turns this into "EV stands down, everything to the static verifier".

    Not retried either — the SDK already retries transport failures four times
    inside one call, so an exception here is a real outage.
    """
    f, table, fid = _live_one()
    calls = []

    def _boom(system, user, *, model):
        calls.append(1)
        raise RuntimeError("api down")

    with pytest.raises(ClassificationUnavailable):
        refine([f], table, model="m", call=_boom)
    assert calls == [1]                       # exactly one attempt, no re-entry


@pytest.mark.parametrize("text", ["", "no json here", "{not: json}", "[", "null", "{}"])
def test_an_unparseable_reply_is_retried_then_refuses(text):
    """HTTP 200 with an unusable body is invisible to the SDK's retry and is often
    transient (a prose preamble, a truncated array), so it IS re-asked — then
    refused rather than falling back to the tables."""
    f, table, fid = _live_one()
    calls = []

    def _bad(system, user, *, model):
        calls.append(1)
        return text

    with pytest.raises(ClassificationUnavailable):
        refine([f], table, model="m", call=_bad, attempts=3)
    assert len(calls) == 3                    # retried, unlike the raising case


def test_a_retry_that_succeeds_is_used():
    f, table, fid = _live_one()
    replies = iter(["oops, no JSON here",
                    json.dumps([{"id": fid, "action": "skip"}])])

    out = refine([f], table, model="m",
                 call=lambda s, u, *, model: next(replies), attempts=3)
    assert (out[fid].cls, out[fid].subtype) == (VerifyClass.STATIC, None)


def test_an_omitted_finding_keeps_its_table_verdict():
    """A partial answer must not silently re-route the findings it left out."""
    a = _llmf(file="a.py", cwe="CWE-89", vuln_class="injection", title="SQLi")
    b = _llmf(file="b.py", cwe="CWE-22", vuln_class="injection", title="Traversal")
    table = _table([a, b])
    aid, bid = finding_id(a, 0), finding_id(b, 1)

    out = refine([a, b], table, model="m",
                 call=_reply({"id": aid, "action": "skip"}))       # b omitted
    assert out[aid] == Classification(VerifyClass.STATIC, None)
    assert out[bid] == table[bid]                                  # untouched


def test_an_unknown_id_cannot_affect_another_finding():
    f, table, fid = _live_one()
    out = refine([f], table, model="m",
                 call=_reply({"id": "who-is-this", "action": "skip"}))
    assert out[fid] == table[fid]


def test_an_unrecognised_action_keeps_the_table_verdict():
    f, table, fid = _live_one()
    out = refine([f], table, model="m",
                 call=_reply({"id": fid, "action": "maybe?", "subtype": "sqli"}))
    assert out[fid] == table[fid]


def test_refine_does_not_mutate_the_table_it_was_given():
    f, table, fid = _live_one()
    before = dict(table)
    refine([f], table, model="m", call=_reply({"id": fid, "action": "skip"}))
    assert table == before


# ── ids must be unique, or one verdict lands on two findings ─────────────────

def test_two_findings_at_the_same_location_get_distinct_ids():
    """`Finding.id` is not populated on every path into S6, and the file:line
    fallback collides for two findings on the same line — which would apply one
    model verdict to both. The batch index disambiguates."""
    a = _llmf(file="app.py", line=131, title="password logged at DEBUG")
    b = _llmf(file="app.py", line=131, title="password logged at INFO")
    assert finding_id(a, 0) != finding_id(b, 1)


def test_an_explicit_finding_id_is_preferred():
    f = _llmf()
    f.id = "FND-42"
    assert finding_id(f, 7) == "FND-42"


# ── chunking ──────────────────────────────────────────────────────────────────
#
# The input side is comfortable at any size (~350 tokens/finding), but one verdict
# is ~40 output tokens against a 4000 cap, so a single call carrying a real repo's
# findings would be truncated mid-array — `_parse` returns nothing and, with no
# table fallback, the entire run loses EV. Chunking bounds that blast radius.

def _many(n, cwe="CWE-89"):
    return [_llmf(file=f"m{i}.py", cwe=cwe, vuln_class="injection", title=f"SQLi {i}")
            for i in range(n)]


def test_findings_are_split_into_batches():
    findings = _many(25)
    table = _table(findings)
    sizes = []

    def _call(system, user, *, model):
        got = json.loads(user.split("Findings to triage:\n", 1)[1])
        sizes.append(len(got))
        return json.dumps([{"id": g["id"], "action": "attack", "subtype": "sqli"}
                           for g in got])

    refine(findings, table, model="m", call=_call, batch=10)
    # sorted(): the chunks are sent concurrently, so which one answers first is not
    # ours to predict. The sizes are still the contract; their arrival order is not.
    assert sorted(sizes) == [5, 10, 10]


def test_every_finding_is_answered_across_batches():
    findings = _many(25)
    table = _table(findings)

    def _call(system, user, *, model):
        got = json.loads(user.split("Findings to triage:\n", 1)[1])
        return json.dumps([{"id": g["id"], "action": "skip"} for g in got])

    out = refine(findings, table, model="m", call=_call, batch=10)
    assert all(v == Classification(VerifyClass.STATIC, None) for v in out.values())
    assert len(out) == 25


def test_one_bad_batch_costs_only_its_own_findings():
    """A chunk that cannot be classified goes to the static verifier — it is NOT
    attacked on its table verdict, and it does not take the other chunks down."""
    findings = _many(20)
    table = _table(findings)
    bad = []

    def _call(system, user, *, model):
        got = json.loads(user.split("Findings to triage:\n", 1)[1])
        # Keyed off the chunk's CONTENT, not a call ordinal: the chunks are sent
        # concurrently, so "the first three calls" no longer picks out one chunk —
        # its attempts interleave with the other chunk's.
        if any(g["id"].startswith("m0.py:") for g in got):
            bad.append(1)
            return "sorry, no JSON"
        return json.dumps([{"id": g["id"], "action": "attack", "subtype": "sqli"}
                           for g in got])

    out = refine(findings, table, model="m", call=_call, batch=10, attempts=3)
    verdicts = [out[finding_id(f, i)] for i, f in enumerate(findings)]
    assert all(v == Classification(VerifyClass.STATIC, None) for v in verdicts[:10])
    assert all(v == Classification(VerifyClass.ACTIVE, "sqli") for v in verdicts[10:])
    assert len(bad) == 3                  # the failing chunk retried, alone


def test_all_batches_failing_stands_ev_down():
    findings = _many(20)
    with pytest.raises(ClassificationUnavailable):
        refine(findings, _table(findings), model="m",
               call=lambda s, u, *, model: "no JSON", batch=10, attempts=2)


def test_chunks_are_sent_concurrently():
    """The chunks are independent, so they go out together rather than one round-trip
    at a time. A barrier is the deterministic proof: were `refine` serial, the first
    chunk would block waiting on siblings that have not been dispatched yet and the
    barrier would break instead of releasing."""
    findings = _many(25)                      # 3 chunks at batch=10
    table = _table(findings)
    barrier = threading.Barrier(3, timeout=10)

    def _call(system, user, *, model):
        got = json.loads(user.split("Findings to triage:\n", 1)[1])
        barrier.wait()                        # BrokenBarrierError unless parallel
        return json.dumps([{"id": g["id"], "action": "attack", "subtype": "sqli"}
                           for g in got])

    out = refine(findings, table, model="m", call=_call, batch=10, parallel=3)
    assert all(v == Classification(VerifyClass.ACTIVE, "sqli") for v in out.values())


def test_a_raising_chunk_stands_ev_down_even_with_siblings_in_flight():
    """`_ask` raises only after the SDK's own four retries, i.e. a real outage — and
    an outage is global, not per-chunk. So one raising chunk abandons its siblings
    and stands EV down, rather than letting their verdicts through."""
    findings = _many(25)
    table = _table(findings)

    def _call(system, user, *, model):
        got = json.loads(user.split("Findings to triage:\n", 1)[1])
        if any(g["id"].startswith("m0.py:") for g in got):
            raise RuntimeError("connection reset by peer")
        return json.dumps([{"id": g["id"], "action": "attack", "subtype": "sqli"}
                           for g in got])

    with pytest.raises(ClassificationUnavailable):
        refine(findings, table, model="m", call=_call, batch=10, attempts=3)


# ── the fields we spend tokens on ─────────────────────────────────────────────

def test_preconditions_are_sent_and_joined_as_prose():
    """`preconditions` states what must already be true to exploit — "read access
    to the source code", "attacker can reach port 5000 via SSRF" — which IS the
    observability question. It is a list on the real Finding, so it must be joined
    rather than str()'d, or Python repr punctuation ships as prompt tokens.
    """
    f = _llmf(cwe="CWE-94", vuln_class="other", title="Werkzeug debugger enabled")
    f.preconditions = ["Attacker can reach port 5000 on 127.0.0.1 via SSRF",
                       "Application must raise an unhandled exception"]
    table = _table([f])
    sent = {}
    refine([f], table, model="m",
           call=lambda s, u, *, model: sent.update(user=u) or json.dumps(
               [{"id": finding_id(f, 0), "action": "skip"}]))
    assert "via SSRF; Application must raise" in sent["user"]
    assert "['" not in sent["user"]            # no list repr leaked


def test_a_finding_without_preconditions_still_works():
    f = _llmf(cwe="CWE-89", vuln_class="injection", title="SQLi")   # no attribute at all
    table = _table([f])
    out = refine([f], table, model="m",
                 call=_reply({"id": finding_id(f, 0), "action": "attack",
                              "subtype": "sqli"}))
    assert out[finding_id(f, 0)] == Classification(VerifyClass.ACTIVE, "sqli")


# ════ reply parsing (exploit_verification._util.json_objects) ════
#
# The three EV array-parsers (classify + both mapping stages) share one helper now.
# It is the outer-bracket scan they always used, moved to one place — NOT the house
# `util.json_extract`, which was tried and rejected: on an object-wrapped array
# (``{"verdicts": [...]}``) extract_json returns the outer dict, so every verdict is
# dropped. `test_parse_recovers_an_object_wrapped_array` is the guard against that
# swap being reintroduced; the rest pin the degrade-not-raise contract callers lean on.

def test_parse_reads_a_plain_array():
    assert json_objects('[{"id": "x"}]') == [{"id": "x"}]


def test_parse_reads_an_array_around_prose():
    assert json_objects('Here are the verdicts:\n[{"id": "a", "action": "keep"}] — done.') == \
        [{"id": "a", "action": "keep"}]


def test_parse_recovers_an_object_wrapped_array():
    # A model that wraps its array in an object still yields its verdicts. This is the
    # case the house extract_json got wrong (it returns the outer dict); the outer-`[`
    # scan reaches the inner array. If this ever regresses to [], the parser was swapped.
    assert json_objects('{"verdicts": [{"id": "a"}, {"id": "b"}]}') == [{"id": "a"}, {"id": "b"}]


def test_parse_drops_non_dict_members_without_failing_the_reply():
    # A stray scalar costs that element, not every verdict beside it.
    assert json_objects('[{"id": "a"}, "oops", 3, {"id": "b"}]') == [{"id": "a"}, {"id": "b"}]


@pytest.mark.parametrize("reply", [
    "",                              # nothing
    "no json here",                  # prose only
    "[",                             # truncated open
    '[{"id": "a"},',                 # truncated mid-array
    '{"id": "a"}',                   # a bare object, not an array
    "null",                          # valid JSON, not a list
])
def test_parse_returns_empty_on_an_unusable_reply(reply):
    # `[]` is the single "no verdicts" answer — it routes the chunk to static rather
    # than raising, which is what keeps a bad reply from taking down the pass.
    assert json_objects(reply) == []
