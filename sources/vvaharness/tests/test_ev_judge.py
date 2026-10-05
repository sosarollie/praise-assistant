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

"""The confirmation judge — independent verdict on a transcript.

Hermetic: the model is a scripted ``call`` seam; no network, no SDK. The theme is
that the judge sees ONLY the finding + the real transcript (never the attacker's
narration), and never fabricates a yes.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vvaharness.exploit_verification.collection.model import EndpointHint
from vvaharness.exploit_verification.mapping.model import EndpointMatch
from vvaharness.exploit_verification.verify import judge as J


def _resp(status, text="", headers=None, elapsed=0.0, error=None):
    return SimpleNamespace(status=status, text=text, headers=headers or {},
                           elapsed=elapsed, error=error)


def _rec(label, method="GET", url="http://t/x", params=None, body=None,
         injection_point="", authed=True, resp=None, auth_applied=()):
    return SimpleNamespace(payload_label=label, method=method, url=url,
                           params=params or {}, body=body, injection_point=injection_point,
                           authed=authed, response=resp,
                           auth_applied=frozenset(auth_applied))


#: Another model's prose, carried on the real Finding. The judge must never be shown
#: it — a second opinion is not evidence, and echoing one is how two models agree
#: themselves into a false positive.
_OTHER_MODEL_PROSE = "STATIC-VERIFIER-SAID-EXPLOITABLE"


def _finding():
    return SimpleNamespace(title="IDOR on invoice", description="user_id not checked",
                           exploit_scenario="GET /invoice/9999 returns others' data",
                           cwe="CWE-639", impact="another tenant's invoice total is returned",
                           preconditions=["caller holds any valid session"],
                           code_snippet="rows = Invoice.objects.filter(id=req.id)",
                           sink_ref="app.py:82", source_ref=None,
                           verifier_reasoning=_OTHER_MODEL_PROSE,
                           verdict_reason=_OTHER_MODEL_PROSE)


def _match():
    ep = EndpointHint(method="GET", path="/invoice/{id}")
    return EndpointMatch(endpoint=ep, method="GET", param="id", location="path")


def _reply(**obj):
    return lambda system, user, *, model: json.dumps(obj)


# ── CVSS scoring (advisory; static owns ranking) ──────────────────────────────

def test_judge_scores_cvss_from_its_reply():
    tx = [_rec("p", resp=_resp(200, "secret data"))]
    out = J.judge(_finding(), _match(), tx, subtype="authz", model="m",
                  call=_reply(verdict="exploited", why_not_benign="foreign data returned",
                              proof_index=0, evidence="e",
                              cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"))
    assert out["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert out["cvss_score"] == 7.5           # computed by report.cvss, not the model


def test_judge_tolerates_a_missing_or_bad_cvss_vector():
    tx = [_rec("p", resp=_resp(200, "x"))]
    out = J.judge(_finding(), _match(), tx, model="m",
                  call=_reply(verdict="exploited", why_not_benign="foreign data returned",
                              proof_index=0, evidence="e",
                              cvss_vector="not a vector"))
    assert out["cvss_vector"] == "" and out["cvss_score"] is None


def test_a_fired_tell_is_shown_to_the_judge_as_evidence():
    tx = [_rec("p", resp=_resp(200, "x"))]
    seen = {}

    def spy(system, user, *, model):
        seen["user"] = user
        return json.dumps({"verdict": "exploited", "why_not_benign": "the marker came back unescaped"})
    J.judge(_finding(), _match(), tx, model="m", tell="SQL error surfaced", call=spy)
    assert "Deterministic signal already detected" in seen["user"]
    assert "SQL error surfaced" in seen["user"]


# ── decision plumbing ─────────────────────────────────────────────────────────

def test_exploited_true_is_parsed_with_evidence_and_index():
    tx = [_rec("__baseline__", resp=_resp(200, "your invoice")),
          _rec("idor", resp=_resp(200, "owner_id: 2, amount: 99999"))]
    out = J.judge(_finding(), _match(), tx, subtype="authz", model="m",
                  call=_reply(verdict="exploited", proof_index=1,
                              benign_explanation="9999 is the caller's own invoice",
                              why_not_benign="owner_id 2 differs from the caller's",
                              evidence="response 1 returned another owner's invoice",
                              reasoning="differs from baseline"))
    assert out["verdict"] == "exploited"
    assert out["proof_index"] == 1
    assert "another owner" in out["evidence"]


def test_exploited_false_is_respected():
    tx = [_rec("p", resp=_resp(200, '{"status":"ok"}'))]
    out = J.judge(_finding(), _match(), tx, model="m",
                  call=_reply(verdict="refuted", proof_index=None, evidence="normal 200"))
    assert out["verdict"] == "refuted"


def test_a_failed_call_returns_none_never_a_yes():
    tx = [_rec("p", resp=_resp(200, "x"))]

    def boom(system, user, *, model):
        raise RuntimeError("api down")
    assert J.judge(_finding(), _match(), tx, model="m", call=boom) is None


def test_an_unparseable_reply_returns_none():
    tx = [_rec("p", resp=_resp(200, "x"))]
    assert J.judge(_finding(), _match(), tx, model="m",
                   call=lambda s, u, *, model: "no json here") is None


def test_empty_transcript_is_not_judged():
    called = []
    assert J.judge(_finding(), _match(), [], model="m",
                   call=lambda *a, **k: called.append(1) or "{}") is None
    assert called == []


def test_a_bad_proof_index_becomes_none():
    tx = [_rec("p", resp=_resp(200, "x"))]
    out = J.judge(_finding(), _match(), tx, model="m",
                  call=_reply(verdict="exploited", why_not_benign="x",
                              proof_index="not-an-int", evidence="e"))
    assert out["verdict"] == "exploited" and out["proof_index"] is None


# ── what the judge is shown (independence + grounding) ────────────────────────

def test_judge_sees_the_transcript_but_not_another_model_s_prose():
    tx = [_rec("__baseline__", resp=_resp(200, "baseline body")),
          _rec("payload-1", url="http://t/invoice/9999", injection_point="path.id",
               resp=_resp(200, "SECRET-OWNER-DATA"))]
    seen = {}

    def spy(system, user, *, model):
        seen["system"], seen["user"] = system, user
        return json.dumps({"verdict": "refuted"})
    J.judge(_finding(), _match(), tx, subtype="authz", model="m", call=spy)
    u = seen["user"]
    # the real responses are present …
    assert "SECRET-OWNER-DATA" in u and "baseline body" in u
    assert "payload-1" in u and "path.id" in u
    # … and the finding context is present
    assert "IDOR on invoice" in u
    # … but no other model's conclusion rides along, in either prompt half
    assert _OTHER_MODEL_PROSE not in u
    assert _OTHER_MODEL_PROSE not in seen["system"]


def test_response_bodies_are_windowed_in_the_view():
    """A body still gets bounded — the prompt cannot grow without limit — but at the
    judge's own budget, not the report's disclosure cap, and head+tail so the end of the
    document survives."""
    big = "A" * 5000 + "TAILMARK"
    tx = [_rec("p", resp=_resp(200, big))]
    seen = {}

    def spy(system, user, *, model):
        seen["user"] = user
        return json.dumps({"verdict": "refuted"})
    J.judge(_finding(), _match(), tx, model="m", call=spy)
    from vvaharness.exploit_verification.verify.model import JUDGE_MAX_BODY
    assert ("A" * (JUDGE_MAX_BODY // 2)) in seen["user"]          # generous head
    assert ("A" * (JUDGE_MAX_BODY + 1)) not in seen["user"]       # still bounded
    assert "TAILMARK" in seen["user"]                            # tail preserved


def test_transport_error_response_is_shown_as_error():
    tx = [_rec("p", resp=_resp(None, "", error="connection refused"))]
    seen = {}
    J.judge(_finding(), _match(), tx, model="m",
            call=lambda s, u, *, model: seen.update(user=u) or json.dumps({"verdict": "refuted"}))
    assert "connection refused" in seen["user"]


# ── the judge's evidence window ───────────────────────────────────────────────
#
# The judge decides the verdict, so how much of a response it can see decides findings.
# Its window is deliberately separate from `MAX_BODY`, which is a DISCLOSURE cap on a
# shareable report and far too small here: a multi-kilobyte JSON response was 90%
# invisible, and "no evidence in the response" could mean nothing more than "the field
# was past the cut".

def _big_body(tail='"summary":{"line_total":42.0,"discount_applied":true}'):
    return '{"total":3,' + "x" * 6000 + "," + tail + "}"


def test_a_short_body_is_shown_whole():
    body = '{"a":1}'
    assert J._window(body) == (body, False)


def test_an_oversized_body_keeps_its_head_and_its_tail():
    """Front-truncation is the worst choice for JSON: the field that decides the verdict
    is as likely to be the last key as the first."""
    shown, windowed = J._window(_big_body())
    assert windowed is True
    assert shown.startswith('{"total":3,')          # head survives
    assert "discount_applied" in shown              # and so does the tail
    assert "chars elided" in shown                  # the gap is named, not silent


def test_the_window_stays_within_its_budget():
    from vvaharness.exploit_verification.verify.model import JUDGE_MAX_BODY
    shown, _ = J._window(_big_body())
    # head+tail of real content == the budget; the elision marker is the only extra
    assert JUDGE_MAX_BODY <= len(shown) <= JUDGE_MAX_BODY + 40


def test_the_judge_view_is_not_capped_at_the_reports_disclosure_limit():
    """Regression: the transcript view used MAX_BODY (512), so a 5 KB response reached
    the confirmation authority with the deciding field cut off."""
    from vvaharness.exploit_verification.verify.model import JUDGE_MAX_BODY, MAX_BODY
    assert JUDGE_MAX_BODY > MAX_BODY
    view = J._transcript_view([_rec("p1", resp=_resp(200, _big_body()))])
    shown = view[0]["response"]["body"]
    assert len(shown) > MAX_BODY
    assert "discount_applied" in shown              # the deciding field is visible
    assert view[0]["response"]["body_truncated"] is True


def test_the_view_shows_cors_and_security_headers():
    """The judge must see the exact bytes a CORS/security-header finding is ABOUT,
    not just the generic set. Regression: `_RESP_HEADERS` used to omit every
    Access-Control-* and security header, so whenever the oracle's own deterministic
    tell did not fire and the judge had to rule independently, it saw a response view
    that could never contain the evidence — it would report "no ACAO header" even
    when one was actually sent, because it was stripped before the judge saw it."""
    resp = _resp(200, "{}", headers={
        "Access-Control-Allow-Origin": "https://evil.example",
        "Access-Control-Allow-Credentials": "true",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
    })
    view = J._transcript_view([_rec("p1", resp=resp)])
    hdrs = view[0]["response"]["headers"]
    assert hdrs["Access-Control-Allow-Origin"] == "https://evil.example"
    assert hdrs["Access-Control-Allow-Credentials"] == "true"
    assert hdrs["X-Frame-Options"] == "DENY"
    assert hdrs["Content-Security-Policy"] == "default-src 'self'"
    assert hdrs["Strict-Transport-Security"] == "max-age=63072000"


# ── the judge prompt is a disclosure boundary too ─────────────────────────────
# The view leaves the process for a model provider, so the standing guarantee — a
# credential is presented on the wire and nowhere else — has to hold here as well.
# Redaction is value-level on purpose: the judge still has to be able to rule.

def test_no_credential_reaches_the_judge_view():
    """Every free-text field is redacted: the URL, each parameter value, the request body,
    the response body, and `Set-Cookie` (which `_RESP_HEADERS` deliberately keeps)."""
    from vvaharness.exploit_verification import safety
    tok = "sess-9f2b1c7d4e8a0b3f6c2d"
    safety.register_secret(tok)
    resp = _resp(200, f'{{"echoed":"{tok}"}}',
                 headers={"Set-Cookie": f"SID={tok}; Path=/; HttpOnly"})
    rec = _rec("p1", url=f"http://t/x?t={tok}", params={"t": tok},
               body=f'{{"t":"{tok}"}}', resp=resp)

    v = J._transcript_view([rec])[0]
    assert tok not in json.dumps(v)                  # nothing anywhere in the record
    for field in (v["url"], v["params"]["t"], v["body"],
                  v["response"]["body"], v["response"]["headers"]["Set-Cookie"]):
        assert "[REDACTED]" in field


def test_a_target_minted_session_cookie_does_not_reach_the_judge_view():
    """The cookie EV never sent is the one that leaked.

    The test above covers a credential EV registered, which layer 3 masks by literal. A
    session id the TARGET minted is registered nowhere and has no shape layer 1 recognises,
    so it passed through verbatim to the model provider — while the code comment claimed
    "the session id itself goes".
    """
    sid = "9f2b1c7d4e8a0b3f6c2d1e5a"          # opaque, target-minted, never registered
    resp = _resp(200, "ok", headers={"Set-Cookie": f"sessionid={sid}; Path=/; HttpOnly"})
    v = J._transcript_view([_rec("p1", resp=resp)])[0]
    assert sid not in json.dumps(v)


def test_cookie_attributes_survive_so_the_cookies_subtype_stays_judgeable():
    """The counterweight to the test above: masking the cookie whole would delete the
    evidence. Whether a session cookie carries `HttpOnly` / `Secure` IS the `cookies`
    finding, so the name and every attribute have to remain readable."""
    resp = _resp(200, "ok", headers={"Set-Cookie": "sessionid=abc123def456; Path=/; SameSite=Lax"})
    cookie = J._transcript_view([_rec("p1", resp=resp)])[0]["response"]["headers"]["Set-Cookie"]
    assert "abc123def456" not in cookie
    assert cookie.startswith("sessionid=")            # which cookie it was
    assert "Path=/" in cookie and "SameSite=Lax" in cookie
    assert "HttpOnly" not in cookie                   # the absence the judge must still see


def test_redaction_does_not_hide_the_payload_the_judge_must_rule_on():
    """The counterweight, and why this is value-level rather than key-name masking: an
    injection point can BE a field named `token` or `password`, and the flags a cookie
    finding is about sit in the same header as the session id. Masking by key name would
    delete the evidence and quietly cost confirmations."""
    from vvaharness.exploit_verification import safety
    safety.register_secret("sess-9f2b1c7d4e8a0b3f6c2d")
    resp = _resp(200, "syntax error at or near \"'\"",
                 headers={"Set-Cookie": "SID=sess-9f2b1c7d4e8a0b3f6c2d; Path=/; HttpOnly"})
    rec = _rec("p1", params={"token": "1' OR '1'='1"},
               body='{"password":"admin\' --"}', resp=resp)

    v = J._transcript_view([rec])[0]
    assert v["params"]["token"] == "1' OR '1'='1"           # the payload survives
    assert "admin' --" in v["body"]
    assert "HttpOnly" in v["response"]["headers"]["Set-Cookie"]   # and the cookie flags
    assert "syntax error" in v["response"]["body"]                # and the tell


def test_view_carries_the_measured_auth_presented():
    """The judge must decide `requires_second_identity` from the MEASURED auth each
    request carried, not guess it. The view exposes `auth_presented` per record."""
    tx = [_rec("__baseline__", resp=_resp(200, "data"),
               auth_applied={"header:authorization", "mtls"}),
          _rec("p1", authed=False, resp=_resp(200, "data"), auth_applied=())]
    by = {v["index"]: v for v in J._transcript_view(tx)}
    assert by[0]["auth_presented"] == "header:authorization, mtls"
    assert by[1]["auth_presented"] == "none (unauthenticated)"


# ══ the corpus: ONE rule has to separate all of these ══
#
# Nine judge replies spanning the ways a confirm can be wrong and the ways it can be
# right, each paired with what an independent static verifier would conclude about the
# same finding. The findings are invented; what matters is the SHAPE of each reply.
#
# Three shapes must NOT confirm however confident the verdict field is: an "exploited"
# whose `why_not_benign` is null, and one whose `why_not_benign` is a non-answer ("nothing")
# — a model asked for a reason it does not have will fill the field rather than leave it
# empty. Five name a real discriminator in the response bytes and must confirm. One is an
# honest refutation.
#
# Kept as a table because it is the regression net for the contract: remove the single
# rule and exactly the rows with no discriminator start confirming again — no per-CWE
# branch separates them, and none should have to.

_CORPUS = [
    # (label, reply, expect_verdict, static_would_say)
    ("escaped reflection",
     {"verdict": "exploited", "benign_explanation": "html.escape neutralised the payload",
      "why_not_benign": None},
     "insufficient_evidence", "FALSE_POSITIVE"),
    ("rounding discrepancy",
     {"verdict": "exploited",
      "benign_explanation": "the rounding rule is deliberate and stated in the response",
      "why_not_benign": None},
     "insufficient_evidence", "FALSE_POSITIVE"),
    ("access control, no denial ever seen",
     {"verdict": "exploited",
      "benign_explanation": "the caller is authorized for both invoice ids",
      "why_not_benign": "nothing"},
     "insufficient_evidence", "FALSE_POSITIVE"),
    ("cross-tenant record",
     {"verdict": "exploited", "benign_explanation": "invoice 4021 is the caller's own",
      "why_not_benign": "invoice 4021 comes back with owner_id 77 while the caller's own "
                        "invoices all carry owner_id 12"},
     "exploited", "TRUE_POSITIVE"),
    ("policy waves a value through",
     {"verdict": "exploited", "benign_explanation": "an empty tier is a permitted value",
      "why_not_benign": "an empty tier drops the discount ceiling entirely — every limit "
                        "in the response comes back unset"},
     "exploited", "TRUE_POSITIVE"),
    ("IDOR on an attachment id",
     {"verdict": "exploited", "benign_explanation": "the attachment is the caller's own",
      "why_not_benign": "the body carries another tenant's filename and byte size"},
     "exploited", "TRUE_POSITIVE"),
    ("total ignores a field",
     {"verdict": "exploited", "benign_explanation": "total differences are normal",
      "why_not_benign": "quantity 2 returns the unit price unchanged, so quantity is "
                        "absent from the computed total"},
     "exploited", "TRUE_POSITIVE"),
    ("malformed input crashes",
     {"verdict": "exploited", "benign_explanation": "a 500 is just an error",
      "why_not_benign": "malformed input 500s where the valid control returns 200"},
     "exploited", "TRUE_POSITIVE"),
    ("sanitiser demonstrably worked",
     {"verdict": "refuted", "benign_explanation": "the payload was neutralised"},
     "refuted", "FALSE_POSITIVE"),
]


@pytest.mark.parametrize("label,reply,expected,static_would_say",
                         _CORPUS, ids=[c[0] for c in _CORPUS])
def test_the_contract_separates_the_corpus(label, reply, expected, static_would_say):
    tx = [_rec("p", resp=_resp(200, "body"))]
    out = J.judge(_finding(), _match(), tx, subtype="authz", model="m", call=_reply(**reply))
    assert out["verdict"] == expected, label
    # and the answer lines up with what the independent static verdict would be
    agrees = (out["verdict"] == "exploited") == (static_would_say == "TRUE_POSITIVE")
    assert agrees, f"{label}: judge said {out['verdict']}, static {static_would_say}"


# ══ mechanism vs property: the claim, not the code path ══
#
# The corpus above is about a confirm that rules out no benign reading. This is the
# adjacent failure and it needs a separate rule: the judge is sure, and RIGHT, about
# something the finding did not claim. The parser did break; the string was echoed; a
# record did come back. Each is a true observation and none is the finding.
#
# So the judge answers two questions instead of one blended one, and a confirm needs the
# second. Defaults matter as much as the rule: a reply that predates these fields has to
# land exactly where it landed before, which is what keeps the corpus above meaningful.

def test_mechanism_without_the_claimed_property_is_not_a_confirm():
    """The shape behind the echoed probe string, the generic 500 body, and "some record
    came back for the id I sent" — all three are mechanism, none is the claim."""
    tx = [_rec("p", resp=_resp(500, "Internal Server Error"))]
    out = J.judge(_finding(), _match(), tx, subtype="authz", model="m",
                  call=_reply(verdict="exploited", mechanism_confirmed=True,
                              property_violated=False,
                              why_not_benign="a 500 where the control returns 200",
                              evidence="status 500 vs 200"))
    assert out["verdict"] == "insufficient_evidence"
    assert out["mechanism_confirmed"] is True      # the real observation survives …
    assert out["property_violated"] is False       # … labelled as what it is


def test_mechanism_and_property_together_still_confirm():
    tx = [_rec("p", resp=_resp(200, "owner_id 77"))]
    out = J.judge(_finding(), _match(), tx, subtype="authz", model="m",
                  call=_reply(verdict="exploited", mechanism_confirmed=True,
                              property_violated=True,
                              why_not_benign="owner_id 77 is not the caller's 12",
                              evidence="owner_id 77 returned"))
    assert out["verdict"] == "exploited"


def test_a_reply_omitting_the_new_fields_is_unchanged():
    """Backward compatibility is the whole reason the defaults are asymmetric: an older
    pinned prompt, or a model that answers only part of the schema, must not be downgraded
    by a field it never knew to send."""
    tx = [_rec("p", resp=_resp(200, "body"))]
    out = J.judge(_finding(), _match(), tx, subtype="authz", model="m",
                  call=_reply(verdict="exploited", why_not_benign="a real discriminator"))
    assert out["verdict"] == "exploited"           # not downgraded by a missing key
    assert out["property_violated"] is True        # inert default
    assert out["requires_second_identity"] is False
    assert out["mechanism_confirmed"] is False


@pytest.mark.parametrize("sent,expected", [(True, True), ("true", True),
                                           (False, False), ("false", False),
                                           (None, True), ("maybe", True)])
def test_property_violated_tolerates_a_stringly_typed_bool(sent, expected):
    """Models return "false" as often as false. A string that is neither falls back to the
    inert default rather than being read as a downgrade."""
    tx = [_rec("p", resp=_resp(200, "body"))]
    out = J.judge(_finding(), _match(), tx, model="m",
                  call=_reply(verdict="exploited", why_not_benign="x",
                              property_violated=sent))
    assert out["property_violated"] is expected


def test_the_prompt_asks_for_mechanism_and_property_separately():
    assert "mechanism_confirmed" in J._SYSTEM and "property_violated" in J._SYSTEM
    # and says which one a confirm needs
    assert "requires property_violated" in J._SYSTEM


def test_the_prompt_requires_endpoint_to_reach_the_sink():
    # F2: a wrong mapping must not confirm — the judge is shown sink + attacked_endpoint and
    # told to answer insufficient_evidence when the endpoint cannot reach the described sink.
    low = J._SYSTEM.lower()
    assert "sink" in low and "attacked_endpoint" in J._SYSTEM
    assert "cannot plausibly reach" in low


def test_the_prompt_ties_reflection_to_the_rendering_context():
    # F1: a reflected marker is the property only in a context a browser renders as markup;
    # a JSON/text echo is mechanism-only. General guidance, not a hardcoded content-type list.
    low = J._SYSTEM.lower()
    assert "content-type" in low and "application/json" in low and "renders" in low


# ══ the claim that needs a principal we do not have ══

def test_requires_second_identity_is_reported():
    tx = [_rec("p", resp=_resp(200, "some record"))]
    out = J.judge(_finding(), _match(), tx, subtype="authz", model="m",
                  call=_reply(verdict="exploited", why_not_benign="a record came back",
                              requires_second_identity=True, evidence="record returned"))
    # the judge's own verdict is preserved here — `run._adjudicate` owns the cap, so the
    # signal must survive parsing intact for it to act on
    assert out["requires_second_identity"] is True


def test_the_prompt_asks_whether_a_second_identity_is_needed():
    assert "requires_second_identity" in J._SYSTEM
    assert "another tenant" in J._SYSTEM.lower()


# ══ describe before ruling, and say why it matters ══

def test_observed_is_requested_before_the_verdict():
    """The priming fix: a claim's vocabulary is easy to adopt as a conclusion, so the
    responses are described first. Order in the schema is the mechanism."""
    assert J._SYSTEM.index('"observed"') < J._SYSTEM.index('"verdict"')


def test_observed_and_plain_consequence_are_returned():
    tx = [_rec("p", resp=_resp(200, "owner_id 77"))]
    out = J.judge(_finding(), _match(), tx, model="m",
                  call=_reply(verdict="exploited", why_not_benign="owner_id 77 is foreign",
                              observed="index 0 returns a JSON body carrying owner_id 77",
                              plain_consequence="any logged-in user can read other "
                                                "customers' invoice totals"))
    assert "owner_id 77" in out["observed"]
    assert "other customers" in out["plain_consequence"]


# ══ the judge now sees what the attacker sees — and still not another model's verdict ══

def test_the_judge_sees_the_findings_own_impact_and_code():
    """`property_violated` is judged against `impact`, and the code is what stops a
    claim's vocabulary standing in for evidence — both were previously withheld from the
    one stage that decides the verdict, while the attacker had them all along."""
    seen = {}

    def spy(system, user, *, model):
        seen["user"] = user
        return json.dumps({"verdict": "refuted"})
    J.judge(_finding(), _match(), [_rec("p", resp=_resp(200, "b"))], model="m", call=spy)
    u = seen["user"]
    assert "another tenant's invoice total is returned" in u    # impact
    assert "caller holds any valid session" in u                # preconditions
    assert "Invoice.objects.filter" in u                        # code_snippet
    assert "CWE-639" in u                                       # cwe
    # and the invariant above it still holds — no second opinion rides along
    assert _OTHER_MODEL_PROSE not in u


def test_preconditions_are_joined_as_prose_not_python_repr():
    seen = {}
    f = _finding()
    f.preconditions = ["holds a valid certificate", "knows a component id"]

    def spy(system, user, *, model):
        seen["user"] = user
        return json.dumps({"verdict": "refuted"})
    J.judge(f, _match(), [_rec("p", resp=_resp(200, "b"))], model="m", call=spy)
    assert "holds a valid certificate; knows a component id" in seen["user"]
    assert "['holds" not in seen["user"]
