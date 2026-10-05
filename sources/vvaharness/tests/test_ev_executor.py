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

"""The safety-gated executor.

Covers ``send`` + the ``http_request`` tool (policy gates, auth injection,
transcript), reactive re-auth, transport TLS wiring, the deterministic
``execute_specs`` path, the concurrency limiter, the rate limiter, and the
out-of-band listener.
"""

from __future__ import annotations
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import certifi
import httpx
import pytest
from vvaharness.exploit_verification.auth import AuthConfig, AuthStrategy
from vvaharness.exploit_verification.executor import (ConcurrencyLimiter, OOBManager,
                                                      RateLimiter, RequestSpec,
                                                      execute_specs, make_handler,
                                                      resolve_oob, send)
from vvaharness.exploit_verification.executor import oob as oob_mod
from vvaharness.exploit_verification.options import EVOptions


# ════ send / http_request tool / re-auth / TLS wiring ════

def _opts(**kw):
    base = dict(enabled=True, target_url="http://127.0.0.1:5000", timeout_s=5.0)
    base.update(kw)
    return EVOptions(**base)


class _FakeResp:
    def __init__(self, status, text="", headers=None, url="http://127.0.0.1:5000/"):
        self.status_code, self.text, self.headers, self.url = status, text, headers or {}, url


def _install_httpx(monkeypatch, responder):
    """Patch httpx.Client so send() hits `responder(method, url, kwargs)`."""
    captured = {}

    class _FakeClient:
        def __init__(self, **kw):
            captured["client_kw"] = kw

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, method, url, **kw):
            captured["req"] = {"method": method, "url": url, **kw}
            return responder(method, url, kw)

    # Patched on the module: `safety.hardened_client` — which `probe._client`, and so
    # `send`, builds through — resolves `httpx.Client` at call time.
    monkeypatch.setattr(httpx, "Client", _FakeClient)
    return captured


# ── send: localhost-only + never-raises ──────────────────────────────────────

def test_send_refuses_non_local_host():
    r = send("GET", "https://api.example/x", opts=_opts())
    assert r.status is None and "not local" in (r.error or "")


def test_send_refuses_private_lan_host():
    r = send("GET", "http://192.168.1.10:5000/x", opts=_opts())
    assert r.status is None and "not local" in (r.error or "")


def test_send_success(monkeypatch):
    _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok", {"X": "1"}))
    r = send("GET", "http://127.0.0.1:5000/x", opts=_opts())
    assert r.status == 200 and r.text == "ok" and r.headers == {"X": "1"}


# ── the tool result surfaces the auth the request actually presented ──────────

def test_format_response_appends_the_presented_auth():
    """The attacker must SEE whether the request carried auth (so it can reason about
    an authz differential) rather than guess. Trailing line, so the HTTP status stays
    the first line the probe logger reads."""
    from vvaharness.exploit_verification.executor._core import format_response
    from vvaharness.exploit_verification.executor.model import EvResponse
    r = EvResponse(status=200, text="body", headers={}, elapsed=0.01, url="http://127.0.0.1/x")
    out = format_response(r, frozenset({"header:authorization", "mtls"}))
    assert out.splitlines()[0].startswith("HTTP 200")          # status stays first
    assert out.rstrip().endswith("auth presented: header:authorization, mtls")


def test_format_response_marks_unauthenticated_and_omits_when_unknown():
    from vvaharness.exploit_verification.executor._core import format_response
    from vvaharness.exploit_verification.executor.model import EvResponse
    r = EvResponse(status=200, text="b", headers={}, elapsed=0.0, url="http://127.0.0.1/x")
    assert "auth presented: none (unauthenticated)" in format_response(r, frozenset())
    assert "auth presented" not in format_response(r)          # None → no line


# ── the tool result is a disclosure boundary: it goes to a model provider ─────
#
# The judge's transcript view redacted the target's responses field by field while this
# result — the same bytes, on the other model-bound path — was only size-capped, so target
# data reached the provider verbatim on every run with the adaptive loop on. These pin both
# directions: nothing sensitive survives, and nothing a probe needs to see is masked away.
# The body's mask-then-cap ordering is covered by the `_SINKS` table in test_ev_safety.py.

def _fmt(text="", headers=None, error=None, status=200):
    from vvaharness.exploit_verification.executor._core import format_response
    from vvaharness.exploit_verification.executor.model import EvResponse
    return format_response(EvResponse(status=status, text=text, headers=headers or {},
                                      elapsed=0.01, url="http://127.0.0.1/x", error=error))


def test_no_credential_reaches_the_attacker_tool_result():
    """The body, the kept headers and the transport error are all masked — the same
    guarantee `test_ev_judge.py` makes for the judge view, on the other egress path."""
    from vvaharness.exploit_verification import safety
    tok = "sess-9f2b1c7d4e8a0b3f6c2d"
    safety.register_secret(tok)
    out = _fmt(text=f'{{"echoed":"{tok}"}}',
               headers={"Set-Cookie": f"SID={tok}; Path=/; HttpOnly",
                        "Location": f"http://127.0.0.1/next?token={tok}"})
    assert tok not in out
    assert "[REDACTED]" in out
    assert tok not in _fmt(error=f"ConnectError: refused for token={tok}")


def test_a_target_minted_session_cookie_does_not_reach_the_attacker():
    """The cookie EV never sent is the one that leaked. A session id the TARGET minted is
    registered nowhere and has no shape layer 1 recognises, so before the shared
    `safety.redact_resp_header` it went to the provider verbatim."""
    sid = "9f2b1c7d4e8a0b3f6c2d1e5a"          # opaque, target-minted, never registered
    assert sid not in _fmt(headers={"Set-Cookie": f"sessionid={sid}; Path=/; HttpOnly"})


def test_cookie_attributes_survive_so_the_cookies_subtype_stays_probeable():
    """The counterweight: masking the cookie whole would delete the evidence. Whether a
    session cookie carries `HttpOnly` / `Secure` IS the `cookies` finding, and the attacker
    has to read it to know whether the finding is worth another probe."""
    out = _fmt(headers={"Set-Cookie": "sessionid=abc123def456; Path=/; SameSite=Lax"})
    assert "abc123def456" not in out
    assert "sessionid=" in out                        # which cookie it was
    assert "Path=/" in out and "SameSite=Lax" in out
    assert "HttpOnly" not in out                      # the absence a probe must still see


def test_redaction_does_not_hide_the_evidence_the_attacker_probes_for():
    """Redaction must not cost the loop its signal: it masks credential SHAPES and values
    EV registered, not arbitrary text. A tell, reflected marker and error signature are
    none of those, so all three survive — this is what makes the fix free of evidence."""
    from vvaharness.exploit_verification import safety
    safety.register_secret("sess-9f2b1c7d4e8a0b3f6c2d")
    out = _fmt(text="syntax error at or near \"'\" | uid=0(root) gid=0(root) | EVMARK7f3a",
               headers={"Content-Type": "text/html"})
    assert "syntax error" in out                       # the SQLi tell
    assert "uid=0(root)" in out                        # the command-injection tell
    assert "EVMARK7f3a" in out                         # a reflected marker
    assert "text/html" in out                          # content type still readable


def test_the_presented_auth_line_is_names_only():
    """The suffix names credential CHANNELS, never values — so the line that tells the
    attacker whether auth went out cannot itself become the leak."""
    from vvaharness.exploit_verification import safety
    from vvaharness.exploit_verification.executor._core import format_response
    from vvaharness.exploit_verification.executor.model import EvResponse
    tok = "sess-9f2b1c7d4e8a0b3f6c2d"
    safety.register_secret(tok)
    r = EvResponse(status=200, text="ok", headers={}, elapsed=0.01, url="http://127.0.0.1/x")
    out = format_response(r, frozenset({"header:authorization", "query:api_key", "mtls"}))
    assert "auth presented: header:authorization, mtls, query:api_key" in out
    assert tok not in out


def test_send_never_raises(monkeypatch):
    def boom(m, u, kw):
        raise httpx.ConnectError("refused")
    _install_httpx(monkeypatch, boom)
    r = send("GET", "http://127.0.0.1:5000/x", opts=_opts())
    assert r.status is None and "ConnectError" in (r.error or "")


# ── tool handler: policy gates + auth + transcript ───────────────────────────

def test_tool_blocks_state_changing_method_by_default():
    tx = []
    h = make_handler(_opts(), AuthConfig(), tx)
    assert "not permitted" in h({"method": "DELETE", "path": "/x"})
    assert tx == []                       # never sent


# ── the two method tiers ─────────────────────────────────────────────────────
#
# The line is drawn on REVERSIBILITY, not on the REST convention of which verbs change
# state — POST is always allowed and can create records or trigger jobs, so treating
# PATCH as categorically more dangerous never made sense. What PATCH being refused DID
# do was make a whole class of finding unverifiable: "this endpoint also accepts PATCH"
# can only be proven by sending PATCH.

@pytest.mark.parametrize("method", ["PUT", "PATCH"])
def test_mutating_methods_need_only_allow_state_changing(monkeypatch, method):
    _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx = []
    h = make_handler(_opts(), AuthConfig(), tx, allow_state_changing=True)
    assert h({"method": method, "path": "/x"}).startswith("HTTP 200")
    assert len(tx) == 1


def test_delete_also_needs_safe_mode_off(monkeypatch):
    """Nothing undoes a delete, so it takes a second, deliberate opt-in."""
    _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx = []
    blocked = make_handler(_opts(), AuthConfig(), tx, allow_state_changing=True)
    out = blocked({"method": "DELETE", "path": "/x"})
    assert "not permitted" in out and "safe_mode: false" in out   # names the gate
    assert tx == []

    allowed = make_handler(_opts(), AuthConfig(), tx, allow_state_changing=True,
                           safe_mode=False)
    assert allowed({"method": "DELETE", "path": "/x"}).startswith("HTTP 200")
    assert len(tx) == 1


def test_a_refusal_names_the_flag_to_flip():
    """The refusal used to say only "state-changing methods are disabled", so the log
    (and the judge, which never sees the refused request at all) gave no hint that a
    config flag was the blocker rather than the target."""
    h = make_handler(_opts(), AuthConfig(), [])
    assert "allow_state_changing_methods: true" in h({"method": "PATCH", "path": "/x"})


@pytest.mark.parametrize("allow_sc,safe_mode,expected", [
    (False, True, {"GET", "POST", "HEAD", "OPTIONS"}),
    (True, True, {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH"}),
    (True, False, {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"}),
    (False, False, {"GET", "POST", "HEAD", "OPTIONS"}),   # safe_mode alone opens nothing
])
def test_the_advertised_enum_matches_the_policy(allow_sc, safe_mode, expected):
    """The tool schema and the executor must agree. When they didn't, the enum offered
    all seven methods while three were refused, so the agent spent turns on a method it
    could never send — and a refused request leaves no transcript record, so the judge
    concluded it had never tried."""
    from vvaharness.exploit_verification.executor import schema_for
    schema = schema_for(allow_state_changing=allow_sc, safe_mode=safe_mode)
    assert set(schema["input_schema"]["properties"]["method"]["enum"]) == expected
    # and the module-level SCHEMA is untouched by the copy
    from vvaharness.exploit_verification.executor import SCHEMA
    assert len(SCHEMA["input_schema"]["properties"]["method"]["enum"]) == 7


def test_schema_for_appends_the_auth_posture_to_the_authenticated_field():
    """The `authenticated` toggle carries the run's posture, so it is a deliberate
    choice, not a blind switch. Omitting posture leaves the base description."""
    from vvaharness.exploit_verification.executor import schema_for, SCHEMA
    base = SCHEMA["input_schema"]["properties"]["authenticated"]["description"]
    with_posture = schema_for(posture="No credential is configured this run.")
    desc = with_posture["input_schema"]["properties"]["authenticated"]["description"]
    assert desc.startswith(base) and "No credential is configured this run." in desc
    # no posture → unchanged, and SCHEMA itself is never mutated
    assert schema_for()["input_schema"]["properties"]["authenticated"]["description"] == base
    assert SCHEMA["input_schema"]["properties"]["authenticated"]["description"] == base


def test_tool_refuses_destructive_token():
    tx = []
    h = make_handler(_opts(), AuthConfig(), tx)
    assert "destructive token" in h({"method": "GET", "path": "/x",
                                     "query": {"q": "1; DROP TABLE users"}})
    assert tx == []


def test_perform_request_refuses_destructive_token_in_a_header():
    # regression: a destructive token in a payload-controlled header (a template
    # `set_headers` value) must be refused like one in the query/body — the coarse
    # net used to scan only path/query/body, letting a header slip through.
    from vvaharness.exploit_verification.executor._core import (SAFE_METHODS,
                                                                perform_request)
    tx = []
    out = perform_request(
        method="GET", path="/x", query={}, body=None, authed=False,
        opts=_opts(), auth=AuthConfig(), transcript=tx,
        allowed_methods=SAFE_METHODS, state={"n": 0}, max_requests=5,
        extra_headers={"X-Attack": "1; DROP TABLE users"})
    assert "destructive token" in out
    assert tx == []                       # refused before the send


def test_tool_request_cap(monkeypatch):
    _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx = []
    h = make_handler(_opts(), AuthConfig(), tx, max_requests=1)
    assert h({"method": "GET", "path": "/a"}).startswith("HTTP 200")
    assert "budget exhausted" in h({"method": "GET", "path": "/b"})
    assert len(tx) == 1


def test_one_budget_is_shared_across_both_execution_paths(monkeypatch):
    """``max_requests_per_finding`` means per FINDING. Both paths used to mint their own
    counter, so the configured cap was really a per-phase cap and a finding could send
    twice what it said — which matters a lot more now that PUT/PATCH are permitted.
    """
    _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx: list = []
    budget: dict = {"n": 0}
    specs = [RequestSpec(method="GET", path="/a"), RequestSpec(method="GET", path="/b")]
    execute_specs(specs, _opts(), AuthConfig(), tx, max_requests=3, state=budget)
    assert len(tx) == 2                                  # 2 of 3 spent by the first set

    h = make_handler(_opts(), AuthConfig(), tx, max_requests=3, state=budget)
    assert h({"method": "GET", "path": "/c"}).startswith("HTTP 200")   # the 3rd
    assert "budget exhausted" in h({"method": "GET", "path": "/d"})    # loop sees it
    assert len(tx) == 3


def test_an_omitted_state_still_gets_its_own_counter(monkeypatch):
    """Sharing is opt-in: a caller that passes no ``state`` keeps an independent budget,
    so direct callers and tests are unaffected."""
    _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx: list = []
    execute_specs([RequestSpec(method="GET", path="/a")], _opts(), AuthConfig(), tx,
                  max_requests=1)
    h = make_handler(_opts(), AuthConfig(), tx, max_requests=1)
    assert h({"method": "GET", "path": "/b"}).startswith("HTTP 200")
    assert len(tx) == 2


def test_tool_holds_the_concurrency_limiter_around_the_send(monkeypatch):
    """Every request through the handler passes through the shared limiter, keyed on
    method + base path (query stripped). This is the funnel the worker pool relies
    on to bound target load."""
    from contextlib import contextmanager

    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    held = []

    class _SpyLimiter:
        @contextmanager
        def hold(self, method, path):
            held.append((method, path))
            assert "sent" not in cap, "limiter must be held BEFORE the send"
            yield
            cap["sent"] = True

    tx = []
    h = make_handler(_opts(), AuthConfig(), tx, limiter=_SpyLimiter())
    out = h({"method": "GET", "path": "/u?id=1", "query": {"x": "y"}})
    assert out.startswith("HTTP 200") and len(tx) == 1
    assert held == [("GET", "/u")]        # base path, query dropped
    assert cap.get("sent") is True        # released after the send


def test_tool_injects_auth_but_transcript_has_no_secret(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    auth = AuthConfig(strategy=AuthStrategy.BEARER, token="s3cr3t")
    tx = []
    h = make_handler(_opts(), auth, tx)
    h({"method": "GET", "path": "/u?id=1", "query": {"x": "y"}})
    # auth header was sent on the wire ...
    assert cap["req"]["headers"].get("Authorization") == "Bearer s3cr3t"
    # ... but the transcript records only the payload params, never the credential
    rec = tx[0]
    assert rec.params == {"id": "1", "x": "y"}
    assert "s3cr3t" not in str(rec.params)


def test_tool_unauthenticated_sends_no_auth(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    auth = AuthConfig(strategy=AuthStrategy.BEARER, token="s3cr3t")
    tx = []
    h = make_handler(_opts(), auth, tx)
    h({"method": "GET", "path": "/u", "authenticated": False})
    assert "Authorization" not in (cap["req"]["headers"] or {})
    assert tx[0].authed is False


# ── JSON body: a dict body must reach a JSON API as JSON, not form ────────────
# Regression: FastAPI/Pydantic answers a form-encoded body with 422, so a finding on a
# JSON write endpoint could never be confirmed — every payload got a validation error
# instead of the handler. The body goes out via httpx `json=` when the endpoint's
# content_type is JSON.

def test_send_json_uses_the_json_kwarg(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    send("POST", "http://127.0.0.1:5000/x", json={"a": 1}, opts=_opts())
    assert cap["req"].get("json") == {"a": 1}       # JSON body
    assert cap["req"].get("data") is None           # NOT form-encoded


def test_tool_sends_json_body_by_default(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx = []
    h = make_handler(_opts(), AuthConfig(), tx, allow_state_changing=True)  # default ct = json
    h({"method": "POST", "path": "/api/items", "body": {"priority": "high"}})
    assert cap["req"].get("json") == {"priority": "high"}
    assert cap["req"].get("data") is None
    assert tx[0].content_type == "application/json"  # recorded for the repro curl


def test_tool_endpoint_form_content_type_sends_form(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx = []
    # a form endpoint (collection declared it) → the handler's default is form
    h = make_handler(_opts(), AuthConfig(), tx, allow_state_changing=True,
                     content_type="application/x-www-form-urlencoded")
    h({"method": "POST", "path": "/login", "body": {"u": "a"}})
    assert cap["req"].get("json") is None
    assert cap["req"].get("data") == {"u": "a"}      # form-encoded path, unchanged


def test_tool_model_can_override_content_type_to_form(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx = []
    h = make_handler(_opts(), AuthConfig(), tx, allow_state_changing=True)  # default json
    h({"method": "POST", "path": "/login", "body": {"u": "a"},
       "content_type": "application/x-www-form-urlencoded"})
    assert cap["req"].get("data") == {"u": "a"} and cap["req"].get("json") is None


# ── mid-run reactive re-auth (a credential that dies during S6) ───────────────
# A lightweight stub isolates the executor's retry logic; the real provider's
# acquire/refresh/budget behaviour is covered in test_ev_auth.py.

class _StubProvider:
    def __init__(self, can_mint=True, reauth_result=1):
        self.version = 0
        self._can = can_mint
        self._reauth_result = reauth_result   # None = budget spent / re-mint failed
        self.reauth_calls = 0

    def can_mint(self):
        return self._can

    def reauth(self, seen_version):
        self.reauth_calls += 1
        return self._reauth_result


def _seq_responder(*statuses):
    it = iter(statuses)
    calls = {"n": 0}

    def responder(m, u, kw):
        calls["n"] += 1
        return _FakeResp(next(it), "ok")
    return responder, calls


def test_reauths_and_retries_on_authed_401(monkeypatch, capsys):
    responder, calls = _seq_responder(401, 200)
    _install_httpx(monkeypatch, responder)
    tx = []
    prov = _StubProvider()
    h = make_handler(_opts(), AuthConfig(), tx, provider=prov)
    out = h({"method": "GET", "path": "/x"})          # authed by default
    assert out.startswith("HTTP 200")                 # retry landed
    assert prov.reauth_calls == 1 and calls["n"] == 2 # one re-auth, one retry send
    assert tx[0].response.status == 200               # the final response is recorded
    err = capsys.readouterr().err                     # the re-mint is visible, not silent
    assert "re-minted the credential" in err and "got 401 mid-run" in err


def test_reauth_retry_is_counted_against_the_request_budget(monkeypatch):
    """The re-auth retry is a second live send, so it must consume the request budget.
    Uncounted, one request that re-auths spends two sends unmetered and a finding can
    exceed max_requests_per_finding. A cap of 2 leaves no room for a third send."""
    responder, calls = _seq_responder(401, 200, 200)  # the 3rd fires only if unmetered
    _install_httpx(monkeypatch, responder)
    tx: list = []
    budget: dict = {"n": 0}
    prov = _StubProvider()
    h = make_handler(_opts(), AuthConfig(), tx, max_requests=2, provider=prov, state=budget)
    assert h({"method": "GET", "path": "/a"}).startswith("HTTP 200")  # 401 → reauth → lands
    assert budget["n"] == 2                           # BOTH the send and the retry counted
    assert "budget exhausted" in h({"method": "GET", "path": "/b"})   # cap reached
    assert calls["n"] == 2                            # the third live send never happened


def test_unauthenticated_401_never_reauths(monkeypatch):
    responder, calls = _seq_responder(401)
    _install_httpx(monkeypatch, responder)
    tx = []
    prov = _StubProvider()
    h = make_handler(_opts(), AuthConfig(), tx, provider=prov)
    out = h({"method": "GET", "path": "/x", "authenticated": False})
    assert out.startswith("HTTP 401")
    assert prov.reauth_calls == 0 and calls["n"] == 1   # 401 is the authz signal here


def test_reauth_budget_exhausted_does_not_retry(monkeypatch, capsys):
    responder, calls = _seq_responder(401, 200)   # a 200 is queued but must NOT be reached
    _install_httpx(monkeypatch, responder)
    tx = []
    prov = _StubProvider(reauth_result=None)      # budget spent / re-mint failed
    h = make_handler(_opts(), AuthConfig(), tx, provider=prov)
    out = h({"method": "GET", "path": "/x"})
    assert out.startswith("HTTP 401")             # no retry
    assert prov.reauth_calls == 1 and calls["n"] == 1
    assert "could not be re-minted" in capsys.readouterr().err   # exhaustion is visible


def test_no_reauth_when_provider_cannot_mint(monkeypatch):
    responder, calls = _seq_responder(401)
    _install_httpx(monkeypatch, responder)
    tx = []
    prov = _StubProvider(can_mint=False)          # static credential — nothing to re-mint
    h = make_handler(_opts(), AuthConfig(), tx, provider=prov)
    out = h({"method": "GET", "path": "/x"})
    assert out.startswith("HTTP 401")
    assert prov.reauth_calls == 0 and calls["n"] == 1


# ── transport TLS / mTLS wiring: EV builds the right httpx `verify=` ─────────
# The real mTLS handshake is exercised in test_ev_auth.py; here we prove the
# server-trust selection and — crucially — that a client cert is NOT passed as a
# separate `cert=` (httpx 0.28 drops it), but rides inside `verify=`.

def test_ssl_verify_selection_without_client_cert():
    from vvaharness.exploit_verification.probe import _ssl_context
    ca = certifi.where()                                        # a real, loadable CA bundle
    assert _ssl_context(_opts()) is True                       # default: verify on
    assert _ssl_context(_opts(verify_ssl=False)) is False       # explicit skip
    # a private CA is loaded into an SSLContext, not passed to httpx as a raw path
    # string (deprecated in httpx 0.28+).
    assert isinstance(_ssl_context(_opts(ca_cert=ca)), ssl.SSLContext)
    # the client-cert branch builds a real SSLContext (load_cert_chain needs real
    # files) and is proven end-to-end by the mTLS handshake in test_ev_auth.py.


def test_send_passes_verify_and_no_separate_cert(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    send("GET", "http://127.0.0.1:5000/x", opts=_opts(ca_cert=certifi.where()))
    assert isinstance(cap["client_kw"]["verify"], ssl.SSLContext)  # CA loaded into a context
    # regression guard: a client cert must ride inside verify= (an SSLContext), never a
    # separate cert=, which httpx 0.28 accepts and then silently drops — the handshake
    # then completes with no certificate presented.
    assert "cert" not in cap["client_kw"]
    assert cap["client_kw"]["follow_redirects"] is False       # allow-list can't be dodged via 30x
    assert cap["client_kw"]["trust_env"] is False              # nor via a proxy in the env


# ── egress: the localhost check is on the URL, so the client must not be redirectable ──
# `check_allowed` reads the host out of the URL. httpx trusts the environment by default,
# so a loopback URL that passed the check would still be routed through HTTP_PROXY — the
# live payload leaves the machine, and the proxy's reply is read back as the target's.
# Behavioural rather than kwarg-level on purpose. Three call paths reach the wire:
# `run_probe`, `send`, and the OOB self-test. The first two share `probe._client`, so the
# test below covers that client for both; the self-test builds its own from
# `safety.hardened_client`, which is why it gets a second proxy test of its own (further
# down, with the listener it calls). That every one of them is the SAME hardened client, and
# that no fourth path can appear, is `test_ev_safety.py`'s job — a property of the package
# rather than of any one request.

def _recording_server():
    """A loopback socket that answers one line of HTTP and records the request line."""
    seen: list[str] = []
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:                       # closed by the test
                return
            seen.append(conn.recv(4096).split(b"\r\n")[0].decode("latin1"))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1], seen


@pytest.mark.parametrize("var", ["HTTP_PROXY", "http_proxy", "ALL_PROXY"])
def test_send_ignores_a_proxy_in_the_environment(monkeypatch, var):
    """An operator with a proxy exported in their shell still sends only to the target."""
    target, target_port, target_seen = _recording_server()
    proxy, proxy_port, proxy_seen = _recording_server()
    try:
        for k in ("NO_PROXY", "no_proxy", "HTTP_PROXY", "http_proxy",
                  "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv(var, f"http://127.0.0.1:{proxy_port}")

        url = f"http://127.0.0.1:{target_port}/user"
        r = send("GET", url, opts=_opts(target_url=f"http://127.0.0.1:{target_port}"))

        assert proxy_seen == [], f"{var} redirected an EV request off the target"
        assert r.status == 200 and r.text == "ok"
        assert target_seen == ["GET /user HTTP/1.1"]     # origin-form: not sent to a proxy
    finally:
        target.close()
        proxy.close()


# ════ deterministic execute_specs ════

def test_executes_each_spec_and_records_labels(monkeypatch):
    _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx: list = []
    specs = [
        RequestSpec(method="GET", path="/a?id=1'", payload_label="sqli#1",
                    injection_point="query.id"),
        RequestSpec(method="POST", path="/b", body={"x": "<xss>"},
                    payload_label="xss#1", injection_point="body.x"),
    ]
    out = execute_specs(specs, _opts(), AuthConfig(), tx)
    assert len(out) == 2 and len(tx) == 2
    assert tx[0].payload_label == "sqli#1" and tx[0].injection_point == "query.id"
    assert tx[0].params == {"id": "1'"}                # payload param recorded, pre-auth


def test_unauthenticated_identity_sends_no_auth(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    auth = AuthConfig(strategy=AuthStrategy.BEARER, token="s3cr3t")
    tx: list = []
    execute_specs([RequestSpec(method="GET", path="/x", identity="none")],
                  _opts(), auth, tx)
    assert "Authorization" not in (cap["req"]["headers"] or {})
    assert tx[0].authed is False


def test_request_cap_is_shared_across_specs(monkeypatch):
    _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx: list = []
    execute_specs([RequestSpec(method="GET", path="/a"),
                   RequestSpec(method="GET", path="/b")],
                  _opts(), AuthConfig(), tx, max_requests=1)
    assert len(tx) == 1                                # second spec hit the budget


def test_oob_placeholder_resolved_at_send(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    m = OOBManager(enabled=True, advertised_host="127.0.0.1")
    m.advertised_url = "http://127.0.0.1:9090"         # no server needed for substitution
    tx: list = []
    execute_specs([RequestSpec(method="GET", path="/fetch", query={"u": "{{OOB_URL}}"})],
                  _opts(), AuthConfig(), tx, oob=m, oob_family="ssrf")
    sent = cap["req"]["params"]
    assert sent["u"].startswith("http://127.0.0.1:9090/ssrf") and "{{OOB_URL}}" not in sent["u"]
    assert m._nonces                                    # a nonce was registered for correlation


# ── JSON vs form body (deterministic path honours the spec's content_type) ────

def test_json_spec_sends_json_body(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx: list = []
    execute_specs([RequestSpec(method="POST", path="/api/items",
                               body={"priority": "high"},
                               content_type="application/json")],
                  _opts(), AuthConfig(), tx, allow_state_changing=True)
    assert cap["req"].get("json") == {"priority": "high"}       # JSON, not 422-inducing form
    assert cap["req"].get("data") is None
    assert tx[0].content_type == "application/json"


def test_form_spec_still_sends_form_body(monkeypatch):
    cap = _install_httpx(monkeypatch, lambda m, u, kw: _FakeResp(200, "ok"))
    tx: list = []
    execute_specs([RequestSpec(method="POST", path="/login", body={"u": "a"},
                               content_type="application/x-www-form-urlencoded")],
                  _opts(), AuthConfig(), tx, allow_state_changing=True)
    assert cap["req"].get("data") == {"u": "a"} and cap["req"].get("json") is None


# ════ concurrency limiter ════

def _peak_under(limiter, *, calls, method_path):
    """Run `calls` holds concurrently through `limiter`; return the peak number
    seen inside a hold at once. `method_path` is a fn(i) -> (method, path)."""
    inside = 0
    peak = 0
    lock = threading.Lock()

    def one(i):
        nonlocal inside, peak
        m, p = method_path(i)
        with limiter.hold(m, p):
            with lock:
                inside += 1
                peak = max(peak, inside)
            time.sleep(0.02)          # hold the slot long enough for peers to pile up
            with lock:
                inside -= 1

    with ThreadPoolExecutor(max_workers=calls) as ex:
        list(ex.map(one, range(calls)))
    return peak


def test_target_axis_caps_total_in_flight():
    lim = ConcurrencyLimiter(target=2, per_endpoint=0)
    # 6 callers, every one a DIFFERENT endpoint, so only the target axis can bind.
    peak = _peak_under(lim, calls=6, method_path=lambda i: ("GET", f"/e{i}"))
    assert peak == 2


def test_endpoint_axis_caps_per_endpoint():
    lim = ConcurrencyLimiter(target=0, per_endpoint=2)
    # 6 callers, all the SAME endpoint, target axis off -> endpoint cap binds.
    peak = _peak_under(lim, calls=6, method_path=lambda i: ("GET", "/same"))
    assert peak == 2


def test_endpoints_are_independent():
    lim = ConcurrencyLimiter(target=0, per_endpoint=1)
    # Two endpoints, one slot each -> one request per endpoint can run at once, so
    # two run in parallel overall. If the endpoint axis were global this would be 1.
    peak = _peak_under(lim, calls=6, method_path=lambda i: ("GET", f"/e{i % 2}"))
    assert peak == 2


def test_both_axes_zero_is_a_noop():
    lim = ConcurrencyLimiter(target=0, per_endpoint=0)
    peak = _peak_under(lim, calls=5, method_path=lambda i: ("GET", "/same"))
    assert peak == 5                  # nothing throttled


def test_the_tighter_axis_wins():
    # target 4 but only 1 per endpoint, all hitting one route -> endpoint binds at 1.
    lim = ConcurrencyLimiter(target=4, per_endpoint=1)
    peak = _peak_under(lim, calls=6, method_path=lambda i: ("GET", "/same"))
    assert peak == 1


def test_a_request_waits_it_is_never_dropped():
    """The cap blocks, it does not discard: every one of the 8 holds must complete
    even though only 2 may be inside at a time."""
    lim = ConcurrencyLimiter(target=2, per_endpoint=0)
    done = []
    lock = threading.Lock()

    def one(i):
        with lim.hold("GET", f"/e{i}"):
            time.sleep(0.01)
        with lock:
            done.append(i)

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(one, range(8)))
    assert sorted(done) == list(range(8))


def test_method_and_path_together_key_the_endpoint():
    # GET /x and POST /x are different endpoints, so per_endpoint=1 lets them run
    # at the same time (peak 2), while two GET /x would serialise (peak 1).
    lim = ConcurrencyLimiter(target=0, per_endpoint=1)
    peak = _peak_under(lim, calls=6,
                       method_path=lambda i: (("GET", "/x") if i % 2 else ("POST", "/x")))
    assert peak == 2


# ════ out-of-band listener ════

def _mgr():
    return OOBManager(enabled=True, advertised_host="127.0.0.1",
                      advertised_port=0, bind_host="127.0.0.1")   # port 0 → auto-pick


# ── auto-addressing (resolve_oob) ─────────────────────────────────────────────

def test_resolve_localhost_target_enabled():
    m = resolve_oob(EVOptions(target_url="http://127.0.0.1:5000", oob_mode="auto"))
    assert m.enabled and m._adv_host == "127.0.0.1"


def test_resolve_remote_target_off_without_url():
    m = resolve_oob(EVOptions(target_url="https://api.example.com", oob_mode="auto"))
    assert not m.enabled


def test_resolve_explicit_url_used_verbatim():
    m = resolve_oob(EVOptions(target_url="http://127.0.0.1:5000", oob_mode="auto",
                              oob_url="http://127.0.0.1:9091"))
    assert m.enabled and m._adv_host == "127.0.0.1" and m._adv_port == 9091


def test_resolve_off_mode_disables():
    m = resolve_oob(EVOptions(target_url="http://127.0.0.1:5000", oob_mode="off"))
    assert not m.enabled


# ── the listener is never widened by inference ────────────────────────────────
# The advertised address says where the target should call; it does not decide which
# interfaces to accept on. Only EV_OOB_BIND does that, so an unauthenticated listener on
# every interface is always something an operator asked for in as many words. A
# non-loopback EV_OOB_URL is refused before this point (gate + ev-replay), and is included
# here to prove that even if one arrived the bind would not follow it.

@pytest.mark.parametrize("kw", [
    {},                                                  # auto-addressed from the target
    {"oob_url": "http://127.0.0.1:9090"},                # explicit loopback base
    {"oob_url": "http://192.168.1.50:9090"},             # refused upstream; bind still local
    {"oob_port": 9099},
])
def test_listener_binds_loopback_unless_bind_is_named(kw):
    m = resolve_oob(EVOptions(target_url="http://127.0.0.1:5000", oob_mode="auto", **kw))
    assert m.enabled and m._bind[0] == "127.0.0.1"


def test_explicit_oob_bind_is_still_honoured():
    """The escape hatch stays: a stated interface is an operator decision, not inference."""
    m = resolve_oob(EVOptions(target_url="http://127.0.0.1:5000", oob_mode="auto",
                              oob_bind="0.0.0.0"))
    assert m.enabled and m._bind[0] == "0.0.0.0"


def test_a_non_loopback_target_has_no_callback_address():
    """Nothing to derive: this release refuses such a target well before OOB addressing."""
    for host in ("192.168.1.50", "10.0.0.5", "api.example"):
        assert not resolve_oob(EVOptions(target_url=f"http://{host}:8000",
                                         oob_mode="auto")).enabled


# ── recorded interactions are bounded, but never at a real callback's expense ──

def test_unmatched_interactions_are_capped():
    m = OOBManager(enabled=True, advertised_host="127.0.0.1")
    for i in range(oob_mod._MAX_INTERACTIONS + 50):
        m._record("127.0.0.1", "GET", f"/noise/{i}")
    assert m.total_interactions() == oob_mod._MAX_INTERACTIONS


def test_a_minted_callback_is_recorded_even_when_the_cap_is_full():
    """The cap must never cost a confirmation: a nonce-carrying hit is always kept, or a
    blind finding would silently fall to REQUIRES REVIEW under unrelated traffic."""
    m = OOBManager(enabled=True, advertised_host="127.0.0.1")
    nonce, _url = m.mint("finding-1", "ssrf")
    for i in range(oob_mod._MAX_INTERACTIONS + 50):        # fill it with unmatched noise
        m._record("127.0.0.1", "GET", f"/noise/{i}")
    assert m.total_interactions() == oob_mod._MAX_INTERACTIONS

    m._record("127.0.0.1", "GET", f"/cb/{nonce}")          # the real callback, past the cap
    assert len(m.interactions_for(nonce)) == 1
    assert m.total_interactions() == oob_mod._MAX_INTERACTIONS + 1


# ── listener lifecycle + correlation ──────────────────────────────────────────

def test_self_test_passes_on_localhost():
    m = _mgr().start()
    try:
        assert m.self_test() is True
        assert m.advertised_url.startswith("http://127.0.0.1:")
    finally:
        m.stop()


@pytest.mark.parametrize("var", ["HTTP_PROXY", "http_proxy", "ALL_PROXY"])
def test_self_test_ignores_a_proxy_in_the_environment(monkeypatch, var):
    """The self-test carries a freshly minted callback nonce, so it is the one EV request
    that most needs to stay on the machine — and it is issued from the listener rather than
    from `send`, which is how it once ended up outside the hardened client and travelling
    through an operator's proxy. The functional cost was its own tell: the callback never
    reached the listener, so the self-test reported the listener unreachable and sent the
    operator after a firewall that was working correctly.

    Behavioural rather than kwarg-level, because that is the assertion the earlier
    source-shape check could not make."""
    proxy, proxy_port, proxy_seen = _recording_server()
    m = _mgr().start()
    try:
        for k in ("NO_PROXY", "no_proxy", "HTTP_PROXY", "http_proxy",
                  "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv(var, f"http://127.0.0.1:{proxy_port}")

        assert m.self_test() is True, f"{var} kept the callback from the listener"
        assert proxy_seen == [], f"{var} carried a minted OOB nonce off the target"
    finally:
        m.stop()
        proxy.close()


def test_self_test_refuses_a_non_local_callback_base(monkeypatch):
    """Defence in depth on the one EV request whose destination was not vetted before it
    was sent. `run_probe` and `send` each call `check_allowed` on their own URL; the
    self-test did not, and rested entirely on the offline gate having refused a non-loopback
    `EV_OOB_URL` upstream. So this is not the operator's error path — the gate still owns
    that, with a message naming the variable — but the guarantee that no EV request is
    exempt from the envelope on account of where in the code it is issued.

    The assertion is that no request is BUILT, not merely that the self-test fails: with no
    listener bound, `self_test` returns False either way, so a `False` on its own would pass
    just as happily with the host check deleted — the shape of vacuous test this whole
    change exists to stop."""
    def _never_built(**kw):
        pytest.fail("a non-local callback base was sent a request")

    monkeypatch.setattr(oob_mod, "hardened_client", _never_built)
    m = OOBManager(enabled=True, advertised_host="169.254.169.254", advertised_port=80)
    m.ready = True                                    # no listener: the host is refused first
    m.advertised_url = "http://169.254.169.254"
    assert m.self_test() is False


def test_records_and_correlates_callback():
    m = _mgr().start()
    try:
        nonce, url = m.mint("F1", "ssrf")
        httpx.get(url, timeout=2.0)
        for _ in range(40):                    # let the threaded server record it
            if m.interactions_for(nonce):
                break
            time.sleep(0.05)
        hits = m.interactions_for(nonce)
        assert hits and hits[0].nonce == nonce and m.total_interactions() >= 1
    finally:
        m.stop()


def test_substitute_replaces_placeholders():
    m = _mgr().start()
    try:
        out = m.substitute("fetch {{OOB_URL}} for {{NONCE}}", "F1", "ssrf")
        assert m.advertised_url in out
        assert "{{OOB_URL}}" not in out and "{{NONCE}}" not in out
    finally:
        m.stop()


def test_disabled_manager_is_noop():
    m = OOBManager(enabled=False)
    m.start()                                   # no server started
    assert m.ready is False
    assert m.substitute("hit {{OOB_URL}}", "F", "x") == "hit {{OOB_URL}}"
    assert m.self_test() is False


# ── nonce entropy ─────────────────────────────────────────────────────────────
#
# A callback is the strongest evidence a blind finding can produce — the oracle reads one
# as proof of *that* finding — so a nonce anyone could recompute would be a way to
# manufacture a confirmation. The tail must therefore be random, not a function of inputs
# (the finding id, a counter) that are themselves public.

def test_nonce_is_not_reproducible_across_managers():
    """Two listeners, identical inputs in identical order → different nonces. A tail
    derived from the finding id and a sequence number is byte-identical here."""
    first, _ = OOBManager(enabled=True).mint("app/api.py:42", "ssrf")
    second, _ = OOBManager(enabled=True).mint("app/api.py:42", "ssrf")
    assert first != second


def test_nonce_is_a_family_prefix_plus_a_random_tail():
    nonce, url = OOBManager(enabled=True).mint("app/api.py:42", "cmd")
    assert re.fullmatch(r"cmd[0-9a-f]{24}", nonce)      # 12 random bytes → 24 hex chars
    assert url.endswith(f"/{nonce}")


def test_nonce_family_falls_back_when_none_is_given():
    nonce, _ = OOBManager(enabled=True).mint("app/api.py:42", "")
    assert nonce.startswith("oob")


def test_minted_nonces_are_distinct_and_never_nest():
    """`_record` correlates by substring, so one nonce appearing inside another would
    mis-attribute a callback to the wrong finding."""
    m = OOBManager(enabled=True)
    nonces = [m.mint("app/api.py:42", "ssrf")[0] for _ in range(50)]
    assert len(set(nonces)) == 50
    assert not [(a, b) for a in nonces for b in nonces if a != b and a in b]


# ── adopting a foreign nonce (the ev-replay path) ─────────────────────────────

def test_adopt_correlates_a_nonce_this_listener_never_minted():
    """`ev-replay` re-sends a stored payload whose nonce the ORIGINAL run minted, so a
    fresh listener has to recognise it. Nothing derives or validates the format, which
    is what keeps bundles captured by an earlier version replayable."""
    m = _mgr().start()
    try:
        foreign = "ssrf" + "9f" * 12                    # minted by an earlier run
        m.adopt(foreign, "app/api.py:42", "ssrf")
        httpx.get(f"{m.advertised_url}/{foreign}", timeout=2.0)
        for _ in range(40):                             # let the threaded server record it
            if m.interactions_for(foreign):
                break
            time.sleep(0.05)
        assert m.interactions_for(foreign)
    finally:
        m.stop()


def test_adopt_is_a_noop_when_disabled():
    m = OOBManager(enabled=False)
    m.adopt("ssrf" + "9f" * 12, "app/api.py:42", "ssrf")
    assert not m._nonces


# ── listener resource bounds ──────────────────────────────────────────────────
#
# Anything that can reach the advertised URL can open a connection to it. A stock
# ThreadingHTTPServer answers that with a thread per connection and no read deadline, so a
# client that connects and never finishes its request line holds a thread for the life of
# the process. Both halves are bounded: how long one connection can cost, and how many.

def _connect(mgr):
    """A raw TCP client to the listener that sends nothing at all."""
    host, port = mgr._server.server_address[:2]
    s = socket.create_connection((host, port), timeout=5.0)
    s.settimeout(5.0)
    return s


def _await(predicate, timeout=5.0):
    """Poll until `predicate()` is true; return whether it became true."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_the_handler_carries_the_connection_timeout():
    """StreamRequestHandler.setup() reads `timeout` off the handler class and applies it
    to the connection, so this attribute is what bounds a stalled read."""
    handler = oob_mod._make_handler(lambda *a: None)
    assert handler.timeout == oob_mod._CONN_TIMEOUT_S


def test_oob_locality_agrees_with_the_safety_envelope():
    """One rule for "is this the local machine", not two.

    A local three-string set disagreed with the safety envelope, which accepts all of
    ``127.0.0.0/8`` and a trailing-dot ``localhost.``. A target the gate had already allowed
    then failed this narrower test and the run silently proceeded with no OOB listener,
    telling the operator a loopback address was not loopback.
    """
    from vvaharness.exploit_verification import safety as safety_mod
    for host in ("127.0.0.1", "127.0.0.2", "127.1.2.3", "localhost", "localhost.",
                 "::1", "10.0.0.5", "example.invalid", ""):
        assert oob_mod._is_loopback(host) == safety_mod._is_local(host), host


def test_an_ipv6_callback_host_builds_a_usable_url():
    """``::1`` has to be bracketed inside a URL.

    Unbracketed it produces ``http://::1:8081``, whose port cannot be parsed — so every
    payload carries an unusable callback and no blind confirmation can correlate. Reachable
    from configuration, since the gate accepts ``::1`` for ``EV_OOB_URL``.
    """
    m = oob_mod.OOBManager(enabled=True, advertised_host="::1",
                           advertised_port=0, bind_host="127.0.0.1")
    m.advertised_url = f"http://{oob_mod._authority('::1', 8081)}"
    assert urlparse(m.advertised_url).port == 8081
    assert urlparse(m.advertised_url).hostname == "::1"


def test_a_slow_drip_connection_is_expired_at_the_deadline(monkeypatch):
    """`timeout` is per socket OPERATION, so any byte resets it.

    A client sending one byte per interval under it therefore held a handler thread for as
    long as it liked, and `_MAX_WORKERS` of those wedge the listener — after which a real
    callback is refused and every blind finding degrades. The deadline bounds the connection
    as a whole, so the per-operation timeout is set LONGER here to prove which one fires.
    """
    monkeypatch.setattr(oob_mod, "_CONN_DEADLINE_S", 1.0)
    monkeypatch.setattr(oob_mod, "_CONN_TIMEOUT_S", 30.0)
    m = _mgr().start()
    try:
        s = _connect(m)
        try:
            def drip():
                try:
                    for ch in b"GET /never-finishes":
                        s.sendall(bytes([ch]))
                        time.sleep(0.2)          # each byte resets the per-op timeout
                except OSError:
                    pass
            threading.Thread(target=drip, daemon=True).start()
            s.settimeout(10)
            assert s.recv(1) == b""              # expired by the deadline, not the timeout
        finally:
            s.close()
        assert _await(lambda: m._server._active == 0)   # and its slot came back
    finally:
        m.stop()


def test_a_silent_connection_is_closed_rather_than_held(monkeypatch):
    """The regression: with no socket timeout this connection is never closed and its
    handler thread never returns."""
    monkeypatch.setattr(oob_mod, "_CONN_TIMEOUT_S", 0.3)
    m = _mgr().start()                          # builds the handler class, reading the patch
    try:
        s = _connect(m)
        try:
            assert s.recv(1) == b""             # server hung up; not a client-side timeout
        finally:
            s.close()
    finally:
        m.stop()


def test_a_stalled_connection_releases_its_worker_slot(monkeypatch):
    # 1s rather than the 0.3s above: the slot has to still be held when first observed,
    # so the window to see it must survive a slow machine descheduling this thread.
    monkeypatch.setattr(oob_mod, "_CONN_TIMEOUT_S", 1.0)
    m = _mgr().start()
    try:
        s = _connect(m)
        try:
            assert _await(lambda: m._server._active == 1)
            assert _await(lambda: m._server._active == 0)   # timed out, slot handed back
        finally:
            s.close()
    finally:
        m.stop()


def test_connections_past_the_cap_are_refused_not_queued(monkeypatch):
    """A queue would only move the unbounded growth from threads into a list, so the
    listener closes the excess connection unserved."""
    monkeypatch.setattr(oob_mod, "_CONN_TIMEOUT_S", 5.0)    # the first connection stays parked
    monkeypatch.setattr(oob_mod, "_MAX_WORKERS", 1)
    m = _mgr().start()
    try:
        parked = _connect(m)
        try:
            assert _await(lambda: m._server._active == 1)   # the only slot is taken
            excess = _connect(m)
            try:
                assert excess.recv(1) == b""               # closed without being served
            finally:
                excess.close()
            assert m._server._active == 1                   # the refusal cost no slot
        finally:
            parked.close()
    finally:
        m.stop()


def test_a_served_callback_returns_its_slot_so_the_cap_is_not_a_run_budget(monkeypatch):
    """The cap bounds concurrency, not the number of callbacks a run may record — a slot
    that is never handed back would silently stop confirming blind findings."""
    monkeypatch.setattr(oob_mod, "_MAX_WORKERS", 1)
    m = _mgr().start()
    try:
        for _ in range(3):                                  # more callbacks than slots
            # The slot is released after the response is written, so a client can be back
            # before the handler has returned it. Waiting is the property under test: with
            # a leaked slot this never reaches 0 and the next callback is refused.
            assert _await(lambda: m._server._active == 0)
            nonce, url = m.mint("app/api.py:42", "ssrf")
            httpx.get(url, timeout=2.0)
            assert _await(lambda: bool(m.interactions_for(nonce)))
        assert m.total_interactions() >= 3
    finally:
        m.stop()


# ════ rate limiter ════

def test_disabled_when_rps_non_positive():
    rl = RateLimiter(0)
    t0 = time.monotonic()
    for _ in range(5):
        rl.wait()
    assert time.monotonic() - t0 < 0.05        # no throttling


def test_spaces_calls_to_rate():
    rl = RateLimiter(50)                        # 20ms between calls
    t0 = time.monotonic()
    for _ in range(4):                          # first is free, 3 waits ≈ 60ms
        rl.wait()
    assert time.monotonic() - t0 >= 0.05


# ── Accept: ask for JSON unless told otherwise ───────────────────────────────
#
# httpx defaults to `Accept: */*`, which is wrong for an API client and is not what a
# collection's own examples send. A handler that content-negotiates can answer `*/*` with
# nothing at all, leaving EV to verify against an empty body it cannot explain — a whole
# endpoint's worth of findings then fail for a reason that looks like the app's fault.

def _sent_headers(monkeypatch, *, authed=True, method="POST", **kw):
    """Capture the headers one real perform_request puts on the wire."""
    import vvaharness.exploit_verification.executor._core as core
    from vvaharness.exploit_verification.executor._core import (SAFE_METHODS,
                                                                perform_request)
    from vvaharness.exploit_verification.executor.model import EvResponse
    seen = {}

    def fake(m, url, *, params=None, headers=None, data=None, json=None,
             opts=None, **_kw):
        seen.update(headers or {})
        return EvResponse(200, "ok", {}, 0.01, url, m)
    monkeypatch.setattr(core, "_send", fake)
    perform_request(method=method, path="/x", query={}, body={"a": 1}, authed=authed,
                    opts=_opts(), auth=AuthConfig(), transcript=[],
                    allowed_methods=SAFE_METHODS, state={"n": 0}, max_requests=5, **kw)
    return seen


def test_accept_defaults_to_json(monkeypatch):
    assert _sent_headers(monkeypatch)["Accept"] == "application/json"


def test_accept_is_the_bare_media_type(monkeypatch):
    """Not `application/json, */*`: servers compare this header for equality often
    enough that a hedged value fails exactly where the plain one works."""
    assert "," not in _sent_headers(monkeypatch)["Accept"]


@pytest.mark.parametrize("given", ["Accept", "accept", "ACCEPT"])
def test_an_explicit_accept_is_respected_whatever_its_case(monkeypatch, given):
    seen = _sent_headers(monkeypatch, extra_headers={given: "application/xml"})
    assert seen[given] == "application/xml"
    assert len([k for k in seen if k.lower() == "accept"]) == 1   # not duplicated


def test_accept_rides_on_an_unauthenticated_request_too(monkeypatch):
    """An identity="none" probe still has to be able to read the response it gets."""
    assert _sent_headers(monkeypatch, authed=False)["Accept"] == "application/json"


def test_the_defaulted_accept_is_recorded_so_the_repro_reproduces(monkeypatch):
    """A repro that omits the Accept EV actually sent does not reproduce: a
    content-negotiating endpoint answers the replay with an empty body, which is exactly
    the confusion the default exists to remove."""
    import vvaharness.exploit_verification.executor._core as core
    from vvaharness.exploit_verification.executor._core import (SAFE_METHODS,
                                                                perform_request)
    from vvaharness.exploit_verification.executor.model import EvResponse
    monkeypatch.setattr(core, "_send",
                        lambda m, url, **kw: EvResponse(200, "ok", {}, 0.01, url, m))
    tx: list = []
    perform_request(method="POST", path="/x", query={}, body={"a": 1}, authed=True,
                    opts=_opts(), auth=AuthConfig(), transcript=tx,
                    allowed_methods=SAFE_METHODS, state={"n": 0}, max_requests=5)
    assert tx[0].sent_headers.get("Accept") == "application/json"


def test_defaulting_accept_does_not_mutate_the_callers_header_dict(monkeypatch):
    import vvaharness.exploit_verification.executor._core as core
    from vvaharness.exploit_verification.executor._core import (SAFE_METHODS,
                                                                perform_request)
    from vvaharness.exploit_verification.executor.model import EvResponse
    monkeypatch.setattr(core, "_send",
                        lambda m, url, **kw: EvResponse(200, "ok", {}, 0.01, url, m))
    caller = {"X-Api-Version": "3"}
    perform_request(method="GET", path="/x", query={}, body=None, authed=True,
                    opts=_opts(), auth=AuthConfig(), transcript=[],
                    allowed_methods=SAFE_METHODS, state={"n": 0}, max_requests=5,
                    extra_headers=caller)
    assert caller == {"X-Api-Version": "3"}      # no Accept written back
