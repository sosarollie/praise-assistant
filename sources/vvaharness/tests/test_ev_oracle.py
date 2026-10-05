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

"""EV confirmation oracle — per-subtype tells over a real transcript.

The oracle is the authority for CONFIRMED: a tell must fire on an actual recorded
response. Transcripts are built in-memory; a fake OOB manager stands in for the
listener.
"""
from __future__ import annotations

import pytest

from vvaharness.exploit_verification.executor import EvResponse, RequestRecord
from vvaharness.exploit_verification.payloads.markers import Markers
from vvaharness.exploit_verification.verify import oracle

M = Markers(token="abcd1234", xss="<evxabcd1234>", ssti_expr="100*200",
            ssti_expected="20000", redirect_host="evredir-abcd1234.invalid")


class _OOB:
    """Fake listener: reports a callback only for the registered nonce."""
    def __init__(self, hit_nonce=None):
        self._n = hit_nonce

    def interactions_for(self, nonce):
        return [object()] if nonce and nonce == self._n else []


def _rec(status=200, text="", headers=None, params=None, body=None, authed=True,
         label="p1", injection_point="query.p", elapsed=0.0, oob_nonce="", sent_headers=None,
         url="http://t/x", seq=0, auth_applied=(), method="GET", error=None):
    return RequestRecord(
        method=method, url=url, params=params or {}, body=body, authed=authed,
        payload_label=label, injection_point=injection_point, oob_nonce=oob_nonce,
        sent_headers=sent_headers or {}, seq=seq, auth_applied=frozenset(auth_applied),
        response=EvResponse(status=status, text=text, headers=headers or {},
                            elapsed=elapsed, url=url, error=error))


#: A credentialed request on the default route — the half an authz comparison needs.
def _authed_rec(status=200, text="ok", **kw):
    kw.setdefault("auth_applied", {"header:authorization"})
    return _rec(status=status, text=text, authed=True, label="__baseline__", seq=1, **kw)


class _Finding:
    """Minimal finding stand-in for the host-level relevance gate."""
    def __init__(self, title="t", description="d", cwe=""):
        self.title, self.description, self.cwe = title, description, cwe


def _c(tx, subtype, oob=None, finding=None, credentialed=True):
    # Host-level subtypes (headers/cookies/cors) require a corroborating finding;
    # payload-bound subtypes ignore it. ``credentialed`` gates authz (a credential
    # must exist to omit); defaults True so non-authz tests are unaffected.
    return oracle.confirm(tx, subtype=subtype, markers=M, oob=oob, finding=finding,
                          credentialed=credentialed)


# ── injection: reflection / error / marker ────────────────────────────────────

def test_sqli_error_confirms_high():
    v = _c([_rec(status=500, text="sqlite3.OperationalError: near \"'\": syntax error",
                 params={"p": "1'"})], "sqli")
    assert v.status == "CONFIRMED" and v.confidence == "high"


def test_sqli_no_error_refuted():
    assert _c([_rec(text="normal page", params={"p": "1'"})], "sqli").status == "NOT_CONFIRMED"


def test_sqli_time_based_confirms_medium():
    v = _c([_rec(label="time_based_mysql_5s", elapsed=5.0, params={"p": "' AND SLEEP(5)"})], "sqli")
    assert v.status == "CONFIRMED" and v.confidence == "medium"


def test_sqli_time_based_confirms_on_delta_over_a_fast_baseline():
    # F5: baseline-relative — a 5s payload over a fast baseline is a real delta.
    tx = [_rec(label="__baseline__", elapsed=0.2),
          _rec(label="time_based_mysql_5s", elapsed=5.1, params={"p": "' AND SLEEP(5)"})]
    v = _c(tx, "sqli")
    assert v.status == "CONFIRMED" and v.confidence == "medium"


def test_sqli_time_based_not_confirmed_when_baseline_is_equally_slow():
    # F5: a naturally slow endpoint (heavy query / cold start) must not read as an injected
    # sleep. With an equally-slow baseline the payload adds no meaningful delta → no tell.
    tx = [_rec(label="__baseline__", elapsed=5.0),
          _rec(label="time_based_mysql_5s", elapsed=5.2, params={"p": "' AND SLEEP(5)"})]
    assert _c(tx, "sqli").status != "CONFIRMED"


def test_sqli_time_based_ignores_a_timed_out_request():
    # A timed-out request comes back with no status and error set, but its `elapsed` sits
    # at the full timeout — a naive delta would read that dead/hung request as an injected
    # sleep. It carries no evidence either way, so it must NOT confirm; the honest outcome
    # is INCONCLUSIVE, and the finding still reaches the static verifier.
    tx = [_rec(label="__baseline__", elapsed=0.2),
          _rec(label="time_based_mysql_5s", status=None, elapsed=15.0,
               error="ReadTimeout: timed out", params={"p": "' AND SLEEP(5)"})]
    assert _c(tx, "sqli").status != "CONFIRMED"


def test_cmd_time_based_ignores_a_timed_out_request():
    # Same guard on the command-injection timing branch: both tells share `_slow`, and a
    # timed-out probe must not fire either of them.
    tx = [_rec(label="__baseline__", elapsed=0.2),
          _rec(label="time_based_sleep_5s", status=None, elapsed=15.0,
               error="ReadTimeout: timed out", body="x; sleep 5")]
    assert _c(tx, "cmd").status != "CONFIRMED"


def test_sqli_time_based_not_confirmed_on_slow_baseline_with_modest_spike():
    # A slow, jittery endpoint (baseline ~8s) with a modest +3s spike clears the flat
    # absolute margin but NOT the proportional one (0.5 × 8s = 4s), so it is not read as an
    # injected sleep — the case a fixed 3s delta would have false-confirmed.
    tx = [_rec(label="__baseline__", elapsed=8.0),
          _rec(label="time_based_mysql_5s", elapsed=11.0, params={"p": "' AND SLEEP(5)"})]
    assert _c(tx, "sqli").status != "CONFIRMED"


def test_sqli_time_based_confirms_real_sleep_over_a_slow_baseline():
    # The proportional margin does not swallow a genuine injected sleep: a full +5s over
    # the same slow baseline clears max(3s, 4s) and still confirms.
    tx = [_rec(label="__baseline__", elapsed=8.0),
          _rec(label="time_based_mysql_5s", elapsed=13.5, params={"p": "' AND SLEEP(5)"})]
    v = _c(tx, "sqli")
    assert v.status == "CONFIRMED" and v.confidence == "medium"


def test_sqli_time_based_confirms_when_the_BASELINE_timed_out():
    # The mirror of the timed-out-payload guard, and it fails the opposite way. A baseline
    # that timed out carries the full timeout in `elapsed`; feeding that in as the
    # comparison raised the bar to max(3s, 0.5 x 15s) = 7.5s, which no 5s sleep can clear —
    # so every real timing tell on that endpoint was suppressed rather than one invented.
    # A dead baseline is no baseline: fall back to the absolute floor.
    tx = [_rec(label="__baseline__", status=None, elapsed=15.0,
               error="ReadTimeout: timed out"),
          _rec(label="time_based_mysql_5s", elapsed=5.2, params={"p": "' AND SLEEP(5)"})]
    v = _c(tx, "sqli")
    assert v.status == "CONFIRMED" and v.confidence == "medium"


def test_sqli_time_based_confirms_when_the_payload_sleeps_then_errors():
    # A time-based injection that sleeps and THEN raises answers 5xx after the delay. The
    # delay is the whole evidence for the subtype, so requiring a sub-500 status here threw
    # it away. "The target answered at all" is the right test for a timing tell; "answered
    # usefully" is the right one for a content tell.
    tx = [_rec(label="__baseline__", elapsed=0.1),
          _rec(label="time_based_mysql_5s", status=500, elapsed=5.2,
               params={"p": "' AND SLEEP(5)"})]
    v = _c(tx, "sqli")
    assert v.status == "CONFIRMED" and v.confidence == "medium"


def test_sqli_time_based_margin_never_exceeds_what_a_payload_injects():
    # Uncapped, the proportional margin grew past the payload's own 5s sleep once the
    # baseline passed ~10s, so on the endpoints most likely to be slow a real injected delay
    # became unreachable by construction. The cap keeps the tell attainable.
    tx = [_rec(label="__baseline__", elapsed=14.0),
          _rec(label="time_based_mysql_5s", elapsed=19.0, params={"p": "' AND SLEEP(5)"})]
    v = _c(tx, "sqli")
    assert v.status == "CONFIRMED" and v.confidence == "medium"


def test_sqli_error_not_confirmed_when_it_is_only_the_reflected_payload():
    # F6: an app that mirrors the request back must not self-fire the SQL-error tell — the
    # error signature has to be the target's, not the payload echoed.
    err = "you have an error in your SQL syntax"
    v = _c([_rec(text=f"echo: {err}", params={"p": f"1' {err}"})], "sqli")
    assert v.status != "CONFIRMED"


def test_xss_marker_reflected_confirms():
    v = _c([_rec(text=f"<b>{M.xss}</b>", params={"p": M.xss})], "xss")
    assert v.status == "CONFIRMED" and v.param == "p"


def test_xss_reflection_reports_the_content_type_for_the_judge():
    # F1: the tell still fires (the reflection is a fact), but it reports the response
    # Content-Type so the judge rules on context — a marker echoed into application/json is
    # not XSS, and that call is the judge's, not a hardcoded allowlist's in the oracle.
    v = _c([_rec(text=f'{{"name":"{M.xss}"}}', params={"p": M.xss},
                 headers={"Content-Type": "application/json; charset=utf-8"})], "xss")
    assert v.status == "CONFIRMED"
    assert "application/json" in v.evidence


def test_xss_escaped_refuted():
    assert _c([_rec(text="&lt;evxabcd1234&gt;", params={"p": M.xss})], "xss").status == "NOT_CONFIRMED"


def test_ssti_evaluated_confirms_but_not_from_baseline():
    tx = [_rec(label="__baseline__", text="hello"),
          _rec(text="result 20000 ok", params={"p": M.ssti_expr})]
    assert _c(tx, "ssti").status == "CONFIRMED"


def test_path_passwd_confirms():
    assert _c([_rec(text="root:x:0:0:root:/root:/bin/bash")], "path").status == "CONFIRMED"


def test_open_redirect_to_canary_confirms():
    v = _c([_rec(status=302, headers={"Location": f"https://{M.redirect_host}/"})], "open_redirect")
    assert v.status == "CONFIRMED"


def test_open_redirect_evidence_redacts_the_location_it_quotes():
    """The tell quotes the whole `Location` header so a reader can see where it pointed —
    and that is unbounded target text which can carry a token in its query. Evidence is
    stamped onto the report AND spliced into the judge's prompt, so it is masked here, at
    the one place the header enters a string that leaves the process."""
    from vvaharness.exploit_verification import safety
    tok = "sess-9f2b1c7d4e8a0b3f6c2d"
    safety.register_secret(tok)
    loc = f"https://{M.redirect_host}/cb?token={tok}"
    v = _c([_rec(status=302, headers={"Location": loc})], "open_redirect")
    assert v.status == "CONFIRMED"                 # still confirms — the tell is intact
    assert tok not in v.evidence
    assert M.redirect_host in v.evidence           # the canary is what proves it


# ── cmd: reflection / OOB / timing ────────────────────────────────────────────

def test_cmd_output_reflected_confirms():
    assert _c([_rec(text="uid=0(root) gid=0(root) groups=0(root)")], "cmd").status == "CONFIRMED"


def test_cmd_oob_callback_confirms():
    v = _c([_rec(oob_nonce="cmd0001x")], "cmd", oob=_OOB("cmd0001x"))
    assert v.status == "CONFIRMED"


# ── ssrf / xxe with reflection guard + OOB ────────────────────────────────────

def test_ssrf_oob_confirms():
    assert _c([_rec(oob_nonce="ssrf01x")], "ssrf", oob=_OOB("ssrf01x")).status == "CONFIRMED"


def test_ssrf_metadata_fetched_confirms():
    v = _c([_rec(status=200, text="ami-1234abcd instance-id i-0", params={"url": "http://x"})], "ssrf")
    assert v.status == "CONFIRMED"


def test_ssrf_reflected_metadata_does_not_confirm():
    # the signature is only present because we asked for it (echoed) → not fetched
    v = _c([_rec(status=200, text="instance-id", params={"url": "instance-id"})], "ssrf")
    assert v.status != "CONFIRMED"


def test_xxe_file_read_confirms():
    assert _c([_rec(text="root:x:0:0:root:/root:/bin/sh", body="<xml/>")], "xxe").status == "CONFIRMED"


# ── authz ─────────────────────────────────────────────────────────────────────

def _authz_pair(**payload_kw):
    """A credentialed baseline plus an uncredentialed payload on the SAME route —
    the only shape that lets authz confirm."""
    payload_kw.setdefault("status", 200)
    payload_kw.setdefault("text", "secret admin data")
    return [_authed_rec(),
            _rec(authed=False, label="no_credentials", seq=2, **payload_kw)]


def test_authz_confirms_on_a_credentialed_uncredentialed_pair():
    """The confirming shape: one route, two identities, and the one that presented
    nothing still returns data."""
    v = _c(_authz_pair(), "authz")
    assert v.status == "CONFIRMED"
    assert v.control_seq == 1                    # points at the credentialed half
    assert "no credential was presented" in v.evidence


def test_authz_enforced_refuted():
    v = _c([_rec(authed=False, status=403, text="forbidden", label="no_credentials")],
           "authz", credentialed=True)
    assert v.status == "NOT_CONFIRMED"


def test_authz_is_inconclusive_when_no_credential_was_presented():
    """Dropping credentials only tests authorization if a credential actually went
    out. When none did, the "authenticated" baseline and the unauthenticated payload
    are the identical request, so a 200 here would "confirm" any public endpoint —
    the honest verdict is INCONCLUSIVE.

    Regression: on a run with no EV_AUTH_* set this vacuously confirmed every authz
    finding, because the gate asked whether a credential was *configured*
    (``has_credential`` answers True for strategy ``none``) instead of whether one was
    *presented*.
    """
    tx = [_rec(authed=False, status=200, text="secret admin data", label="no_credentials")]
    v = _c(tx, "authz", credentialed=False)
    assert v.status == "INCONCLUSIVE"
    assert "no credential was presented" in v.evidence


#: The wire shape shared by both causes: the baseline goes out as the primary identity and
#: attaches nothing, then the uncredentialed payload follows. Which cause it is cannot be
#: read from these records — only from whether the run configured a credential.
def _authed_but_empty_tx():
    return [_rec(authed=True, status=200, text="data", label="__baseline__", seq=1),
            _rec(authed=False, status=200, text="secret admin data",
                 label="no_credentials", seq=2)]


def test_authz_says_so_when_a_configured_credential_never_reached_the_wire():
    """A credential IS set up and did not go out — a login/OAuth2 flow that never minted,
    or an api-key location that attaches nothing. The comparison is unsound either way, but
    the cause is the opposite of "none configured", and it is the cause that decides what
    the reader does next: the general wording tells an operator who already set EV_AUTH_*
    to set EV_AUTH_*.
    """
    v = oracle.confirm(_authed_but_empty_tx(), subtype="authz", markers=M,
                       credentialed=False, credential_configured=True)
    assert v.status == "INCONCLUSIVE" and v.unverifiable is True
    assert "sent as authenticated but presented no credential" in v.evidence
    assert "never minted" in v.evidence            # names the actionable cause
    assert "Set EV_AUTH_*" not in v.evidence       # NOT the misdiagnosis


def test_authz_does_not_claim_a_credential_was_configured_when_none_was():
    """The same wire shape with NO auth configured, which is the common case and must keep
    the general advice. Every request carries `authed=True` by default and
    `EV_AUTH_STRATEGY=none` attaches nothing, so this transcript is identical to the one
    above — telling those two apart is why the config half is passed in rather than
    inferred. Claiming "a credential is configured" here would be simply false.
    """
    v = oracle.confirm(_authed_but_empty_tx(), subtype="authz", markers=M,
                       credentialed=False, credential_configured=False)
    assert v.status == "INCONCLUSIVE"
    assert "Set EV_AUTH_*" in v.evidence
    assert "credential is configured" not in v.evidence


def test_authz_still_says_set_ev_auth_when_nothing_was_configured():
    """The default: a caller that cannot say gets the general wording."""
    tx = [_rec(authed=False, status=200, text="secret admin data", label="no_credentials")]
    v = _c(tx, "authz", credentialed=False)
    assert v.status == "INCONCLUSIVE"
    assert "Set EV_AUTH_*" in v.evidence
    assert "sent as authenticated" not in v.evidence


def test_authed_without_credential_is_measured_not_configured():
    """The predicate itself: it reads the wire, so it is true for a credential that stopped
    working mid-run as well as one that never worked, and false once one really went out."""
    applied = [_rec(authed=True, auth_applied={"header:authorization"})]
    assert oracle.authed_without_credential(applied) is False
    assert oracle.authed_without_credential([_rec(authed=True, auth_applied=())]) is True
    # a deliberately unauthenticated probe is not a failure — it never claimed otherwise
    assert oracle.authed_without_credential([_rec(authed=False, auth_applied=())]) is False
    assert oracle.authed_without_credential([]) is False


def test_authz_does_not_confirm_when_no_record_carried_a_credential():
    """Belt and braces for the case above: even told ``credentialed=True``, the tell
    re-checks the records themselves and finds no credentialed half to compare
    against, so it cannot confirm."""
    tx = [_rec(authed=True, status=200, text="data", label="__baseline__", seq=1),
          _rec(authed=False, status=200, text="secret admin data",
               label="no_credentials", seq=2)]
    assert _c(tx, "authz", credentialed=True).status != "CONFIRMED"


def test_authz_needs_the_credentialed_counterpart_on_the_same_route():
    """Two unrelated requests are not a differential. The credentialed record must be
    on the same method+route, or what is being compared is two endpoints."""
    tx = [_authed_rec(url="http://t/other"),
          _rec(authed=False, status=200, text="secret admin data",
               label="no_credentials", seq=2)]
    assert _c(tx, "authz", credentialed=True).status != "CONFIRMED"


@pytest.mark.parametrize("body", ["null", "{}", "[]", '""', "   "])
def test_authz_rejects_an_empty_response_as_data(body):
    """"Returned 200 with data" is the whole claim, so an empty-ish body must not
    satisfy it. A handler that falls off the end without returning serialises to
    ``null`` — four bytes that are truthy as a string and mean the opposite of data
    disclosure. Regression: three false confirmations rested on a 200 ``null``."""
    assert _c(_authz_pair(text=body), "authz").status != "CONFIRMED"


def test_authz_never_uses_the_invalid_credential_probe_as_evidence():
    """``invalid_bearer_token`` is a CONTROL — it characterises the endpoint. It rides
    ``identity: none`` but still sends an Authorization header, so it is not an
    uncredentialed request and must never be returned as the confirming record."""
    tx = [_authed_rec(),
          _rec(authed=False, status=200, text="secret admin data", seq=2,
               label="invalid_bearer_token", auth_applied={"header:authorization"})]
    assert _c(tx, "authz", credentialed=True).status != "CONFIRMED"


def test_authz_confirms_only_at_medium_so_static_still_decides():
    """A request cannot tell a *public* endpoint from a *broken-authz* one — both
    answer 200 with data anonymously. So authz is evidence, not proof: `medium`
    keeps it out of `_is_hard_proof`, and the static verifier keeps the verdict.

    Regression: at `high` this overrode static verification, so a finding
    mis-mapped onto an unrelated endpoint could publish that endpoint's ordinary
    behaviour as exploit-verified at CVSS 7.5.
    """
    from vvaharness.exploit_verification.verify.router import _is_hard_proof
    v = _c(_authz_pair(), "authz")
    assert v.status == "CONFIRMED"
    assert v.confidence == "medium"
    assert _is_hard_proof(v) is False       # -> _stamp_evidence, not _stamp


# ── noauth: missing authentication (single unauthenticated request) ────────────
#
# The other proof shape for auth: the endpoint requires NO credential at all, so a
# single unauthenticated request that succeeds is the proof — no credential to drop,
# no second identity. Distinct from `authz`, which is a differential.

#: A finding that genuinely claims a missing-auth defect (so `_corroborates` passes).
_MISSING_AUTH = _Finding(title="Endpoint requires no authentication", cwe="CWE-306")


def test_noauth_confirms_on_an_anonymous_state_change():
    """An unauthenticated POST the server accepts (2xx) is the tell — the privileged
    action ran with no credential. `medium`, so static still owns the verdict."""
    tx = [_rec(method="POST", authed=False, status=201, text="created",
               label="no_credentials")]
    v = _c(tx, "noauth", finding=_MISSING_AUTH, credentialed=False)
    assert v.status == "CONFIRMED"
    assert v.confidence == "medium"
    assert "unauthenticated" in v.evidence


def test_noauth_confirms_on_an_anonymous_get_with_data():
    tx = [_rec(method="GET", authed=False, status=200, text="secret catalog",
               label="no_credentials")]
    assert _c(tx, "noauth", finding=_MISSING_AUTH, credentialed=False).status == "CONFIRMED"


def test_an_empty_transcript_says_nothing_was_sent():
    """When the adaptive loop does not run, a subtype with no deterministic payload template
    can reach the oracle with an EMPTY transcript. The no-diagnostic wording ("every response
    was a transport error or a 5xx") is vacuously true of no responses at all and reads as a
    claim about the target, so the empty case gets its own sentence."""
    v = _c([], "", finding=None, credentialed=False)
    assert v.status == "INCONCLUSIVE"
    assert "no live request reached the target" in v.evidence
    assert "transport error" not in v.evidence


def test_noauth_inconclusive_without_corroboration():
    """The tell fires on any public endpoint, so the finding must actually CLAIM a
    missing-auth defect. A finding that does not is INCONCLUSIVE, not confirmed —
    the endpoint may be public by design.

    But it is NOT `unverifiable`: a failed noauth corroboration says the subtype is wrong,
    not that no evidence exists. This arrives on a route-bound active finding whose
    transcript may well prove the defect it does claim, so the tell is withheld and the
    judge keeps its authority over the rest — unlike the host-level subtypes, whose
    passive transcript holds nothing else and which do refuse outright."""
    unrelated = _Finding(title="Slow regex causes ReDoS", description="catastrophic backtracking",
                         cwe="CWE-400")
    tx = [_rec(method="GET", authed=False, status=200, text="data", label="no_credentials")]
    v = _c(tx, "noauth", finding=unrelated, credentialed=False)
    assert v.status != "CONFIRMED"
    assert v.unverifiable is False
    assert "tell was withheld" in v.evidence


@pytest.mark.parametrize("body", ["null", "{}", "[]", '""', "   "])
def test_noauth_confirms_on_an_empty_get_body(body):
    """Missing-authentication is proven by ACCESS, not by DATA: being served 200
    instead of turned away IS the tell, whether or not this particular call had
    anything to return. An empty test database must not sink an otherwise-genuine
    missing-auth confirm. Regression: this used to require `_has_content` and so
    wrongly fell to INCONCLUSIVE on a real no-auth endpoint whose response happened
    to be empty."""
    tx = [_rec(method="GET", authed=False, status=200, text=body, label="no_credentials")]
    v = _c(tx, "noauth", finding=_MISSING_AUTH, credentialed=False)
    assert v.status == "CONFIRMED"
    assert v.confidence == "medium"
    assert "no data to return" in v.evidence


def test_noauth_confirms_with_data_uses_the_data_wording():
    """The evidence sentence still names data when it was present, distinct from the
    served-but-empty wording above."""
    tx = [_rec(method="GET", authed=False, status=200, text="secret catalog",
               label="no_credentials")]
    v = _c(tx, "noauth", finding=_MISSING_AUTH, credentialed=False)
    assert v.status == "CONFIRMED"
    assert "with data" in v.evidence


def test_noauth_does_not_confirm_on_an_auth_rejection():
    """A 401/403 to the unauthenticated request means the control DID run — the
    opposite of the finding's claim — so it must not confirm regardless of body."""
    for status in (401, 403):
        tx = [_rec(method="GET", authed=False, status=status, text="",
                   label="no_credentials")]
        assert _c(tx, "noauth", finding=_MISSING_AUTH, credentialed=False).status != "CONFIRMED"


def test_noauth_ignores_a_request_that_presented_a_credential():
    """The tell is about UNauthenticated access, so a record that applied a credential
    is not evidence for it."""
    tx = [_rec(method="POST", authed=True, status=201, text="created",
               label="no_credentials", auth_applied={"header:authorization"})]
    assert _c(tx, "noauth", finding=_MISSING_AUTH).status != "CONFIRMED"


# ── passive: cors / headers / cookies ─────────────────────────────────────────

def _cors_tx():
    return [_rec(sent_headers={"Origin": "https://evil.example"},
                 headers={"Access-Control-Allow-Origin": "https://evil.example",
                          "Access-Control-Allow-Credentials": "true"})]


def test_cors_reflected_origin_with_credentials_confirms():
    f = _Finding(title="Wildcard CORS with credentials")
    assert _c(_cors_tx(), "cors", finding=f).status == "CONFIRMED"


def test_headers_missing_confirms():
    f = _Finding(title="Missing security headers allow clickjacking")
    v = _c([_rec(label="__baseline__", status=200, headers={"Content-Type": "text/html"})],
           "headers", finding=f)
    assert v.status == "CONFIRMED" and v.confidence == "medium"


def test_cookies_missing_flags_confirms():
    f = _Finding(title="Session cookie missing HttpOnly")
    v = _c([_rec(headers={"Set-Cookie": "sid=abc; Path=/"})], "cookies", finding=f)
    assert v.status == "CONFIRMED"


# ── host-level relevance gate ─────────────────────────────────────────────────
#
# headers/cookies/cors tells describe the TARGET, not any payload, so they fire
# for whatever finding happens to be routed to them. These pin that a hit only
# counts when the finding actually claims that class of defect.

def test_headers_tell_rejected_for_an_unrelated_finding():
    # the real regression: a Dockerfile CA-trust finding "confirmed" because the
    # host was missing X-Frame-Options
    f = _Finding(title="Unverified CA certificates copied into container trust store",
                 description="COPY certs/ into the OS trust store with no integrity check",
                 cwe="CWE-295")
    v = _c([_rec(label="__baseline__", status=200, headers={"Content-Type": "text/html"})],
           "headers", finding=f)
    assert v.status == "INCONCLUSIVE" and "cannot speak to this finding" in v.evidence


def test_cors_tell_rejected_for_an_unrelated_finding():
    f = _Finding(title="Plaintext mysql:// URL in ConfigMap", description="no TLS")
    assert _c(_cors_tx(), "cors", finding=f).status == "INCONCLUSIVE"


def test_host_level_tell_fails_closed_without_a_finding():
    v = _c([_rec(label="__baseline__", status=200, headers={"Content-Type": "text/html"})],
           "headers")
    assert v.status == "INCONCLUSIVE"


def test_broad_origin_cwe_still_needs_corroborating_prose():
    """CWE-346 (Origin Validation Error) covers cache keying, postMessage and
    Referer checks too, so it must not be treated as definitionally CORS — a
    *caching* finding carrying 346 must not route to the cors tell."""
    f = _Finding(title="Refresh flag ignored: response served from cache",
                 description="the response is served from cache", cwe="CWE-346")
    assert _c(_cors_tx(), "cors", finding=f).status == "INCONCLUSIVE"


def test_cors_prose_corroborates_a_broad_cwe():
    f = _Finding(title="Permissive CORS policy reflects any Origin", cwe="CWE-346")
    assert _c(_cors_tx(), "cors", finding=f).status == "CONFIRMED"


def test_bare_word_origin_does_not_corroborate_cors():
    # "original" must not read as a CORS claim
    f = _Finding(title="Cache returns the original response", description="stale data")
    assert _c(_cors_tx(), "cors", finding=f).status == "INCONCLUSIVE"


def test_definitional_cwe_corroborates_without_matching_prose():
    # CWE-1021 *is* clickjacking, so it must not need the word in its description
    f = _Finding(title="Dashboard can be framed", description="no protection", cwe="CWE-1021")
    v = _c([_rec(label="__baseline__", status=200, headers={"Content-Type": "text/html"})],
           "headers", finding=f)
    assert v.status == "CONFIRMED"


def test_payload_bound_tell_needs_no_finding():
    # sqli et al are self-evidencing — the tell fires on OUR payload coming back
    v = _c([_rec(status=500, text="sqlite3.OperationalError: syntax error",
                 params={"p": "1'"})], "sqli")
    assert v.status == "CONFIRMED"


# ── absence-based tells must not fire on an error page ────────────────────────

def test_headers_tell_ignores_an_error_page():
    """A 404 legitimately omits headers a served page sets, so confirming off one
    reflects probing an unrouted path (map_passive's host-root fallback) rather
    than a real defect."""
    f = _Finding(title="Missing security headers")
    v = _c([_rec(label="__baseline__", status=404, headers={"Content-Type": "application/json"})],
           "headers", finding=f)
    assert v.status != "CONFIRMED"


def test_headers_tell_prefers_a_served_response_over_a_404_baseline():
    f = _Finding(title="Missing security headers")
    tx = [_rec(label="__baseline__", status=404, headers={}),
          _rec(label="p1", status=200, headers={"Content-Type": "text/html"})]
    v = _c(tx, "headers", finding=f)
    assert v.status == "CONFIRMED" and v.repro_detail.resp_status == 200


# ── conservative subtypes + fallback ──────────────────────────────────────────

def test_idor_is_inconclusive():
    v = _c([_rec(status=200, text="data")], "idor")
    assert v.status == "INCONCLUSIVE"


def test_deser_without_oob_is_inconclusive():
    assert _c([_rec(status=200, text="ok")], "deser").status == "INCONCLUSIVE"


def test_deser_with_oob_confirms():
    assert _c([_rec(oob_nonce="deser1x")], "deser", oob=_OOB("deser1x")).status == "CONFIRMED"


def test_empty_transcript_is_inconclusive():
    assert _c([], "sqli").status == "INCONCLUSIVE"


def test_diagnostic_but_no_tell_is_not_confirmed():
    assert _c([_rec(status=200, text="ok", params={"p": "x"})], "sqli").status == "NOT_CONFIRMED"
