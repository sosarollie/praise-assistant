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

"""Exploit-verification auth, end to end:

  * unit    — strategy resolution, credential validation, header/query construction;
  * provider— OAuth2 / login-flow acquisition, freshness, single-flight/budgeted
              refresh, ensure_fresh matrix (send faked);
  * live    — a real localhost server enforcing every scheme over real sockets;
  * mTLS    — a real mutual-TLS handshake, including a passphrase-protected client
              key (throwaway certs; skips if cryptography is unavailable).
"""

from __future__ import annotations
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse
import pytest
from vvaharness.exploit_verification import auth
from vvaharness.exploit_verification import safety
from vvaharness.exploit_verification import auth_provider as ap
from vvaharness.exploit_verification.auth import AuthConfig, AuthStrategy
from vvaharness.exploit_verification.auth_provider import (AuthAcquireError,
                                                           CredentialProvider,
                                                           Freshness, ensure_fresh)
from vvaharness.exploit_verification import gate, probe
from vvaharness.exploit_verification.errors import EVInputError
from vvaharness.exploit_verification.executor._core import SAFE_METHODS, perform_request
from vvaharness.exploit_verification.executor.model import EvResponse
from vvaharness.exploit_verification.options import EVOptions
import datetime
import ipaddress
import ssl
from vvaharness.exploit_verification.executor import send


# ═══════════════════════ unit: pure functions, no network ═══════════════════

def test_describe_presented_renders_channels_or_unauthenticated():
    """Human-readable rendering of measured auth, shown to the attacker + judge."""
    assert auth.describe_presented(frozenset()) == "none (unauthenticated)"
    assert auth.describe_presented(None) == "none (unauthenticated)"
    assert (auth.describe_presented(frozenset({"mtls", "header:authorization"}))
            == "header:authorization, mtls")


def test_describe_posture_reflects_configured_identities():
    """The run posture handed to the attacker + tool. No credential → 'unauthenticated';
    a credential and/or mTLS → names them and how to drop them."""
    none = auth.describe_posture(AuthConfig(strategy=AuthStrategy.NONE))
    assert "unauthenticated" in none.lower() and "nothing to drop" in none.lower()

    bearer = auth.describe_posture(AuthConfig(strategy=AuthStrategy.BEARER, token="t"))
    assert "bearer credential" in bearer and "authenticated:false" in bearer

    mtls = auth.describe_posture(AuthConfig(strategy=AuthStrategy.NONE), mtls=True)
    assert "mTLS client certificate" in mtls


def test_resolve_strategy_env_wins_then_declared_then_none():
    assert auth.resolve_strategy(AuthStrategy.BEARER, "basic") == AuthStrategy.BEARER
    assert auth.resolve_strategy(AuthStrategy.NONE, "apikey") == AuthStrategy.API_KEY_HEADER
    assert auth.resolve_strategy(AuthStrategy.NONE, "cookie") == AuthStrategy.SESSION_COOKIE
    assert auth.resolve_strategy(AuthStrategy.NONE, None) == AuthStrategy.NONE


@pytest.mark.parametrize("env,missing", [
    ({"EV_AUTH_STRATEGY": "none"}, []),
    ({"EV_AUTH_STRATEGY": "bearer"}, ["EV_AUTH_TOKEN"]),
    ({"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t"}, []),
    ({"EV_AUTH_STRATEGY": "basic", "EV_AUTH_USERNAME": "u"}, ["EV_AUTH_PASSWORD"]),
    ({"EV_AUTH_STRATEGY": "api_key_header"}, ["EV_AUTH_API_KEY"]),
    ({"EV_AUTH_STRATEGY": "session_cookie"}, ["EV_AUTH_TOKEN"]),
    ({"EV_AUTH_STRATEGY": "oauth2_client_credentials", "EV_AUTH_CLIENT_ID": "c"},
     ["EV_AUTH_TOKEN_URL"]),
])
def test_missing_required(env, missing):
    cfg = auth.load_auth_from_env(env)
    assert auth.missing_required(cfg) == missing


def test_misspelled_strategy_is_an_error_not_no_auth():
    """A typo must not degrade to `none` — that sends the whole run unauthenticated."""
    with pytest.raises(EVInputError) as exc:
        auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearrer", "EV_AUTH_TOKEN": "t"})
    assert "bearrer" in str(exc.value) and "bearer" in str(exc.value)

    # Blank / unset still means no auth, which is a legitimate configuration.
    assert auth.load_auth_from_env({}).strategy is auth.AuthStrategy.NONE
    assert (auth.load_auth_from_env({"EV_AUTH_STRATEGY": "  "}).strategy
            is auth.AuthStrategy.NONE)
    # Case and surrounding whitespace are still tolerated on a valid value.
    assert (auth.load_auth_from_env({"EV_AUTH_STRATEGY": " Bearer "}).strategy
            is auth.AuthStrategy.BEARER)


def test_has_credential():
    assert auth.has_credential(auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer",
                                                        "EV_AUTH_TOKEN": "t"}))
    assert not auth.has_credential(auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer"}))


def test_build_headers_per_scheme():
    bearer = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t"})
    assert auth.build_headers(bearer)["Authorization"] == "Bearer t"

    basic = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "basic",
                                     "EV_AUTH_USERNAME": "u", "EV_AUTH_PASSWORD": "p"})
    assert auth.build_headers(basic)["Authorization"].startswith("Basic ")

    apikey = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "api_key_header",
                                      "EV_AUTH_API_KEY": "k", "EV_AUTH_HEADER_NAME": "X-Key"})
    assert auth.build_headers(apikey)["X-Key"] == "k"

    cookie = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "session_cookie",
                                      "EV_AUTH_TOKEN": "abc", "EV_AUTH_COOKIE_NAME": "SID"})
    assert auth.build_headers(cookie)["Cookie"] == "SID=abc"


def test_build_query_for_apikey_in_query():
    q = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "api_key_header", "EV_AUTH_API_KEY": "k",
                                 "EV_AUTH_HEADER_NAME": "api_key", "EV_AUTH_API_KEY_LOCATION": "query"})
    assert auth.build_query(q) == {"api_key": "k"}
    assert auth.build_headers(q) == {}     # not a header when located in query


# ── bearer-prefix hardening ──────────────────────────────────────────────────

def test_bearer_prefix_not_doubled_when_token_already_carries_it():
    # a token pasted as "Bearer x" must not become "Bearer Bearer x"
    a = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "Bearer x"})
    assert auth.build_headers(a)["Authorization"] == "Bearer x"


def test_bearer_prefix_custom_scheme():
    a = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "x",
                                 "EV_AUTH_BEARER_PREFIX": "Token"})
    assert auth.build_headers(a)["Authorization"] == "Token x"


def test_bearer_prefix_empty_sends_raw_token():
    a = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "x",
                                 "EV_AUTH_BEARER_PREFIX": ""})
    assert auth.build_headers(a)["Authorization"] == "x"


def test_oauth2_token_renders_as_bearer_once_fetched():
    a = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "oauth2_client_credentials",
                                 "EV_AUTH_TOKEN_URL": "http://h/t", "EV_AUTH_CLIENT_ID": "c"})
    a.token = "minted"                                     # provider sets this after fetch
    assert auth.build_headers(a)["Authorization"] == "Bearer minted"


# ── login-flow validation ────────────────────────────────────────────────────

def test_login_flow_requires_credentials_not_just_url():
    # a bare login_url no longer counts as "credential present"
    a = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer",
                                 "EV_AUTH_LOGIN_URL": "http://h/login"})
    assert auth.missing_required(a) == ["EV_AUTH_USERNAME", "EV_AUTH_PASSWORD"]
    a2 = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_LOGIN_URL": "http://h/login",
                                  "EV_AUTH_USERNAME": "u", "EV_AUTH_PASSWORD": "p"})
    assert auth.missing_required(a2) == []
    assert a2.uses_login_flow() is True


def test_static_token_is_not_a_login_flow():
    a = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t",
                                 "EV_AUTH_LOGIN_URL": "http://h/login"})
    assert a.uses_login_flow() is False    # a static token wins; no fetch needed


# ═══════════ provider: acquisition, freshness, refresh (send faked) ══════════

def _p_opts():
    return EVOptions(enabled=True, target_url="http://127.0.0.1:5000",
                     timeout_s=5.0)


def _resp(status, text="", headers=None):
    return EvResponse(status, text, headers or {}, 0.01, "http://127.0.0.1:5000/", "POST")


def _fake_send(monkeypatch, responder):
    """Patch the `send` the provider calls; capture each call's (method, url, kwargs)."""
    calls = []

    def stub(method, url, *, params=None, headers=None, data=None, json=None,
             opts=None, **_kw):
        calls.append({"method": method, "url": url, "headers": headers or {},
                      "data": data, "json": json})
        return responder(calls[-1])

    monkeypatch.setattr(ap, "send", stub)
    return calls


def _jwt(exp):
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'none'})}.{b64({'exp': exp})}.sig"


# ── OAuth2 client-credentials ────────────────────────────────────────────────

def test_oauth2_acquire_sets_bearer_and_expiry(monkeypatch):
    _fake_send(monkeypatch,
               lambda c: _resp(200, json.dumps({"access_token": "AT", "expires_in": 3600})))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/oauth/token", client_id="c", client_secret="s")
    p = CredentialProvider(a, _p_opts())
    p.acquire()
    assert a.token == "AT" and p.version == 1
    assert p.is_fresh(skew=60) is True          # expires_in gave a known expiry


def test_oauth2_basic_client_auth_sends_authorization_header(monkeypatch):
    calls = _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "AT"})))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c", client_secret="s",
                   oauth_client_auth="basic")
    CredentialProvider(a, _p_opts()).acquire()
    sent = calls[0]
    assert sent["headers"]["Authorization"].startswith("Basic ")
    creds = base64.b64decode(sent["headers"]["Authorization"].split()[1]).decode()
    assert creds == "c:s"
    assert sent["data"]["grant_type"] == "client_credentials"


def test_oauth2_body_client_auth_puts_client_id_in_body(monkeypatch):
    calls = _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "AT"})))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c", client_secret="s",
                   oauth_client_auth="body")
    CredentialProvider(a, _p_opts()).acquire()
    assert calls[0]["data"]["client_id"] == "c" and calls[0]["data"]["client_secret"] == "s"
    assert "Authorization" not in calls[0]["headers"]


def test_oauth2_http_error_raises(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(401, "nope"))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c")
    with pytest.raises(AuthAcquireError):
        CredentialProvider(a, _p_opts()).acquire()


def test_oauth2_unreachable_raises(monkeypatch):
    _fake_send(monkeypatch, lambda c: EvResponse(None, "", {}, 0.0, "u", "POST", error="ConnectError"))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c")
    with pytest.raises(AuthAcquireError):
        CredentialProvider(a, _p_opts()).acquire()


def test_oauth2_missing_access_token_raises(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"nope": 1})))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c")
    with pytest.raises(AuthAcquireError):
        CredentialProvider(a, _p_opts()).acquire()


# ── login-URL flow ───────────────────────────────────────────────────────────

def test_login_extracts_token_via_dotted_path(monkeypatch):
    calls = _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"data": {"token": "LT"}})))
    a = AuthConfig(strategy=AuthStrategy.BEARER, login_url="http://127.0.0.1:5000/login",
                   username="u", password="p", login_token_path="data.token")
    p = CredentialProvider(a, _p_opts())
    assert p.can_mint() and a.uses_login_flow()
    p.acquire()
    assert a.token == "LT"
    assert calls[0]["json"] == {"username": "u", "password": "p"}   # JSON body by default


def test_login_form_content_type_sends_form(monkeypatch):
    calls = _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "LT"})))
    a = AuthConfig(strategy=AuthStrategy.BEARER, login_url="http://127.0.0.1:5000/login",
                   username="u", password="p", login_content_type="form")
    CredentialProvider(a, _p_opts()).acquire()
    assert calls[0]["data"] == {"username": "u", "password": "p"} and calls[0]["json"] is None


def test_login_cookie_extraction(monkeypatch):
    _fake_send(monkeypatch,
               lambda c: _resp(200, "", {"Set-Cookie": "SID=abc123; Path=/; HttpOnly"}))
    a = AuthConfig(strategy=AuthStrategy.SESSION_COOKIE, login_url="http://127.0.0.1:5000/login",
                   username="u", password="p", login_token_path="cookie")
    CredentialProvider(a, _p_opts()).acquire()
    assert a.token == "SID=abc123"                 # attributes stripped


def test_login_http_error_raises(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(403, "denied"))
    a = AuthConfig(strategy=AuthStrategy.BEARER, login_url="http://127.0.0.1:5000/login",
                   username="u", password="p")
    with pytest.raises(AuthAcquireError):
        CredentialProvider(a, _p_opts()).acquire()


def test_login_missing_token_path_raises(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"other": 1})))
    a = AuthConfig(strategy=AuthStrategy.BEARER, login_url="http://127.0.0.1:5000/login",
                   username="u", password="p", login_token_path="access_token")
    with pytest.raises(AuthAcquireError):
        CredentialProvider(a, _p_opts()).acquire()


# ── freshness reads ──────────────────────────────────────────────────────────

def test_is_fresh_from_jwt_exp():
    import time
    a = AuthConfig(strategy=AuthStrategy.BEARER, token=_jwt(time.time() + 3600))
    assert CredentialProvider(a, _p_opts()).is_fresh(skew=60) is True
    a.token = _jwt(time.time() - 10)
    assert CredentialProvider(a, _p_opts()).is_fresh(skew=60) is False


def test_is_fresh_unknown_for_opaque_token():
    a = AuthConfig(strategy=AuthStrategy.BEARER, token="opaque-not-a-jwt")
    assert CredentialProvider(a, _p_opts()).is_fresh(skew=60) is None


# ── single-flight refresh ────────────────────────────────────────────────────

def test_refresh_is_single_flight(monkeypatch):
    calls = _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "AT"})))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c")
    p = CredentialProvider(a, _p_opts())
    p.acquire()                                    # version 1, one fetch
    assert len(calls) == 1
    # two workers both saw version 1 and ask to refresh; only the first re-fetches
    v_a = p.refresh(seen_version=1)
    v_b = p.refresh(seen_version=1)
    assert v_a == 2 and v_b == 2
    assert len(calls) == 2                         # NOT 3 — the second adopted the first


# ── ensure_fresh: status matrix ──────────────────────────────────────────────

def test_ensure_fresh_no_auth():
    p = CredentialProvider(AuthConfig(strategy=AuthStrategy.NONE), _p_opts())
    assert ensure_fresh(p, reachable=[]) is Freshness.NO_AUTH


def test_ensure_fresh_mints_when_possible(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "AT"})))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c")
    assert ensure_fresh(CredentialProvider(a, _p_opts()), reachable=[]) is Freshness.REFRESHED


def test_ensure_fresh_acquire_failed(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(500, "boom"))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c")
    assert ensure_fresh(CredentialProvider(a, _p_opts()), reachable=[]) is Freshness.ACQUIRE_FAILED


def test_ensure_fresh_static_expired_jwt():
    import time
    a = AuthConfig(strategy=AuthStrategy.BEARER, token=_jwt(time.time() - 10))
    # no monkeypatch needed: this never reaches the network, because the decoded
    # `exp` already says the token is dead.
    assert ensure_fresh(CredentialProvider(a, _p_opts()),
                        reachable=["/x"]) is Freshness.UNREFRESHABLE_EXPIRED


def test_ensure_fresh_static_live_ping_rejected(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(401, "unauth"))
    a = AuthConfig(strategy=AuthStrategy.BEARER, token="opaque")
    assert ensure_fresh(CredentialProvider(a, _p_opts()),
                        reachable=["/me"]) is Freshness.UNREFRESHABLE_EXPIRED


def test_ensure_fresh_static_live_ping_ok(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(200, "ok"))
    a = AuthConfig(strategy=AuthStrategy.BEARER, token="opaque")
    assert ensure_fresh(CredentialProvider(a, _p_opts()), reachable=["/me"]) is Freshness.FRESH


def test_ensure_fresh_static_live_ping_forbidden_is_fresh(monkeypatch):
    """A 403 on the validation ping is authenticated-but-forbidden, not a dead credential:
    the ping can land on a route a valid credential is correctly denied. Reading it as
    expired degrades every authz finding on a run whose credential is perfectly live."""
    _fake_send(monkeypatch, lambda c: _resp(403, "forbidden"))
    a = AuthConfig(strategy=AuthStrategy.BEARER, token="opaque")
    assert ensure_fresh(CredentialProvider(a, _p_opts()),
                        reachable=["/me"]) is Freshness.FRESH   # 403 is not a rejection


def test_ensure_fresh_static_no_reachable_is_fresh_by_default(monkeypatch):
    # opaque token, nothing to ping → we cannot disprove freshness, so proceed
    called = _fake_send(monkeypatch, lambda c: _resp(200, "ok"))
    a = AuthConfig(strategy=AuthStrategy.BEARER, token="opaque")
    assert ensure_fresh(CredentialProvider(a, _p_opts()), reachable=[]) is Freshness.FRESH
    assert called == []                             # no network without a target endpoint


# ── request-shape + budget edges (send faked) ────────────────────────────────

def test_oauth2_scope_is_sent_in_the_token_request(monkeypatch):
    calls = _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "AT"})))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c", scope="read write")
    CredentialProvider(a, _p_opts()).acquire()
    assert calls[0]["data"]["scope"] == "read write"


def test_login_extra_fields_are_posted(monkeypatch):
    calls = _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "LT"})))
    a = AuthConfig(strategy=AuthStrategy.BEARER, login_url="http://127.0.0.1:5000/login",
                   username="u", password="p", login_extra={"tenant": "acme"})
    CredentialProvider(a, _p_opts()).acquire()
    assert calls[0]["json"] == {"tenant": "acme", "username": "u", "password": "p"}


def test_login_extra_env_parses_json_and_tolerates_garbage():
    ok = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer",
                                  "EV_AUTH_LOGIN_EXTRA": '{"tenant": "acme"}'})
    assert ok.login_extra == {"tenant": "acme"}
    bad = auth.load_auth_from_env({"EV_AUTH_STRATEGY": "bearer",
                                   "EV_AUTH_LOGIN_EXTRA": "not json"})
    assert bad.login_extra is None                  # malformed → ignored, never raises


def test_reauth_respects_budget(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "AT"})))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c")
    p = CredentialProvider(a, _p_opts(), max_reauth=1)
    p.acquire()                                     # version 1 (acquire is not a re-auth)
    assert p.reauth(seen_version=1) == 2            # first mid-run re-auth allowed
    assert p.reauth(seen_version=2) is None          # budget (max_reauth=1) spent


def test_reauth_adopts_a_peer_refresh_without_refetching(monkeypatch):
    calls = _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "AT"})))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c")
    p = CredentialProvider(a, _p_opts())
    p.acquire()                                     # version 1, one fetch
    assert p.reauth(seen_version=0) == 1            # a peer already refreshed → adopt, no fetch
    assert len(calls) == 1


def test_reauth_returns_none_when_acquire_fails(monkeypatch):
    _fake_send(monkeypatch, lambda c: _resp(500, "boom"))
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="c")
    assert CredentialProvider(a, _p_opts()).reauth(seen_version=0) is None


def test_ensure_fresh_static_ping_error_is_inconclusive_not_dead(monkeypatch):
    # a transport error on the validation ping must NOT be read as an expired token
    _fake_send(monkeypatch,
               lambda c: EvResponse(None, "", {}, 0.0, "u", "GET", error="ConnectError"))
    a = AuthConfig(strategy=AuthStrategy.BEARER, token="opaque")
    assert ensure_fresh(CredentialProvider(a, _p_opts()), reachable=["/me"]) is Freshness.FRESH


# ═══════════════ live: real localhost server, real sockets ══════════════════

# ── the credentials the fake target enforces ────────────────────────────────
BEARER = "bearer-tok"
BASIC_USER, BASIC_PASS = "alice", "hunter2"
API_KEY, API_KEY_NAME = "key-123", "X-API-Key"
COOKIE_VAL = "SID=sess-abc"
OAUTH_CLIENT, OAUTH_SECRET = "cid", "csecret"
LOGIN_USER, LOGIN_PASS = "luser", "lpass"
LOGIN_TOKEN = "login-at"
LOGIN_COOKIE = "SID=login-sess"
LOGIN_FIELD_USER, LOGIN_FIELD_PASS = "username", "password"


def _body_fields(raw: bytes) -> dict:
    """Parse a request body as JSON, falling back to form-encoding."""
    try:
        obj = json.loads(raw or b"{}")
        if isinstance(obj, dict):
            return obj
    except Exception:  # noqa: BLE001
        pass
    return {k: v[0] for k, v in parse_qs(raw.decode()).items()}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):          # keep pytest output clean
        pass

    # — helpers —
    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj, headers=None):
        self._send(code, json.dumps(obj).encode(),
                   {"Content-Type": "application/json", **(headers or {})})

    def _read(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _cookies(self):
        raw = self.headers.get("Cookie") or ""
        return dict(p.strip().split("=", 1) for p in raw.split(";") if "=" in p)

    def _authed(self, qs) -> bool:
        """Accept any credential the server considers currently valid."""
        st = self.server.state
        authz = self.headers.get("Authorization") or ""
        if authz.startswith("Bearer "):
            if authz[7:] in {BEARER, LOGIN_TOKEN, st.get("token")}:
                return True
        if authz.startswith("Basic "):
            try:
                u, _, p = base64.b64decode(authz[6:]).decode().partition(":")
                if u == BASIC_USER and p == BASIC_PASS:
                    return True
            except Exception:  # noqa: BLE001
                pass
        if self.headers.get(API_KEY_NAME) == API_KEY:
            return True
        if qs.get(API_KEY_NAME, [None])[0] == API_KEY:
            return True
        if self._cookies().get(API_KEY_NAME) == API_KEY:
            return True
        cookie_hdr = self.headers.get("Cookie") or ""
        if COOKIE_VAL in cookie_hdr or LOGIN_COOKIE in cookie_hdr:
            return True
        return False

    # — routes —
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/whoami":
            ok = self._authed(parse_qs(u.query))
            return self._send(200 if ok else 401, b"ok" if ok else b"denied")
        return self._send(404, b"nope")

    def do_POST(self):
        u = urlparse(self.path)
        raw = self._read()
        if u.path == "/oauth/token":
            authz = self.headers.get("Authorization") or ""
            ok = False
            if authz.startswith("Basic "):
                try:
                    cid, _, sec = base64.b64decode(authz[6:]).decode().partition(":")
                    ok = (cid == OAUTH_CLIENT and sec == OAUTH_SECRET)
                except Exception:  # noqa: BLE001
                    ok = False
            else:
                form = parse_qs(raw.decode())
                ok = (form.get("client_id", [None])[0] == OAUTH_CLIENT
                      and form.get("client_secret", [None])[0] == OAUTH_SECRET)
            if not ok:
                return self._send(401, b"bad client")
            return self._json(200, {"access_token": self.server.state["token"],
                                    "expires_in": 3600})
        if u.path == "/login":
            data = _body_fields(raw)
            if data.get(LOGIN_FIELD_USER) == LOGIN_USER and data.get(LOGIN_FIELD_PASS) == LOGIN_PASS:
                return self._json(200, {"access_token": LOGIN_TOKEN})
            return self._send(401, b"bad login")
        if u.path == "/login-cookie":
            data = _body_fields(raw)
            if data.get(LOGIN_FIELD_USER) == LOGIN_USER and data.get(LOGIN_FIELD_PASS) == LOGIN_PASS:
                return self._send(200, b"", {"Set-Cookie": f"{LOGIN_COOKIE}; Path=/; HttpOnly"})
            return self._send(401, b"bad login")
        return self._send(404, b"nope")


@pytest.fixture
def target():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.state = {"token": "oauth-at"}          # the currently-valid OAuth token
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield httpd, base
    finally:
        httpd.shutdown()
        httpd.server_close()


def _live_opts(base: str) -> EVOptions:
    return EVOptions(enabled=True, target_url=base, timeout_s=5.0)


def _whoami(base, auth, *, provider=None, authed=True, opts=None, headers=None):
    """One real GET /whoami through the full executor; return the record."""
    tx: list = []
    perform_request(method="GET", path="/whoami", query={}, body=None, authed=authed,
                    opts=opts or _live_opts(base), auth=auth, transcript=tx,
                    allowed_methods=SAFE_METHODS, state={"n": 0}, max_requests=5,
                    provider=provider, extra_headers=headers)
    return tx[-1]


# ── static strategies land on the wire ───────────────────────────────────────

def test_bearer_authenticates_live(target):
    _, base = target
    rec = _whoami(base, AuthConfig(strategy=AuthStrategy.BEARER, token=BEARER))
    assert rec.response.status == 200


def test_basic_authenticates_live(target):
    _, base = target
    rec = _whoami(base, AuthConfig(strategy=AuthStrategy.BASIC,
                                   username=BASIC_USER, password=BASIC_PASS))
    assert rec.response.status == 200


def test_api_key_header_authenticates_live(target):
    _, base = target
    rec = _whoami(base, AuthConfig(strategy=AuthStrategy.API_KEY_HEADER,
                                   api_key=API_KEY, header_name=API_KEY_NAME,
                                   api_key_location="header"))
    assert rec.response.status == 200


def test_api_key_query_authenticates_live(target):
    _, base = target
    rec = _whoami(base, AuthConfig(strategy=AuthStrategy.API_KEY_HEADER,
                                   api_key=API_KEY, header_name=API_KEY_NAME,
                                   api_key_location="query"))
    assert rec.response.status == 200


def test_api_key_cookie_authenticates_live(target):
    _, base = target
    rec = _whoami(base, AuthConfig(strategy=AuthStrategy.API_KEY_HEADER,
                                   api_key=API_KEY, header_name=API_KEY_NAME,
                                   api_key_location="cookie"))
    assert rec.response.status == 200


def test_session_cookie_authenticates_live(target):
    _, base = target
    rec = _whoami(base, AuthConfig(strategy=AuthStrategy.SESSION_COOKIE, token=COOKIE_VAL))
    assert rec.response.status == 200


def test_wrong_bearer_is_rejected_live(target):
    _, base = target
    rec = _whoami(base, AuthConfig(strategy=AuthStrategy.BEARER, token="wrong"))
    assert rec.response.status == 401       # sanity: the target really enforces auth


# ── auth_applied: what a request REALLY presented ────────────────────────────
#
# Every access-control verdict rests on comparing a request that carried a credential
# with one that did not, so the transcript has to record which is which. Configuration
# cannot answer it: `has_credential` reports whether the strategy *could* be satisfied,
# so it is True for strategy `none`, for a login flow that never minted a token, and for
# a mistyped api-key location that attaches nothing. These pin the measurement.

@pytest.mark.parametrize("auth,expected", [
    (AuthConfig(strategy=AuthStrategy.NONE), set()),
    (AuthConfig(strategy=AuthStrategy.BEARER, token=BEARER), {"header:authorization"}),
    (AuthConfig(strategy=AuthStrategy.BASIC, username=BASIC_USER, password=BASIC_PASS),
     {"header:authorization"}),
    (AuthConfig(strategy=AuthStrategy.SESSION_COOKIE, token=COOKIE_VAL), {"header:cookie"}),
    (AuthConfig(strategy=AuthStrategy.API_KEY_HEADER, api_key=API_KEY,
                header_name=API_KEY_NAME, api_key_location="header"),
     {f"header:{API_KEY_NAME.lower()}"}),
    (AuthConfig(strategy=AuthStrategy.API_KEY_HEADER, api_key=API_KEY,
                header_name=API_KEY_NAME, api_key_location="query"),
     {f"query:{API_KEY_NAME.lower()}"}),
    (AuthConfig(strategy=AuthStrategy.API_KEY_HEADER, api_key=API_KEY,
                header_name=API_KEY_NAME, api_key_location="cookie"),
     {"header:cookie"}),
])
def test_auth_applied_records_the_channel_that_went_out(target, auth, expected):
    _, base = target
    assert set(_whoami(base, auth).auth_applied) == expected


def test_auth_applied_is_empty_when_a_token_flow_never_minted(target):
    """A configured-but-unminted credential attaches nothing. `has_credential` is True
    here (username+password are present for the login flow), which is exactly why the
    authz gate must not ask it."""
    _, base = target
    cfg = AuthConfig(strategy=AuthStrategy.BEARER, login_url=f"{base}/login",
                     username="u", password="p")           # token never fetched
    assert auth.has_credential(cfg) is True
    assert set(_whoami(base, cfg).auth_applied) == set()


def test_auth_applied_is_empty_for_a_mistyped_api_key_location(target):
    """A location outside header/query/cookie silently sends nothing — the credential is
    in the config and absent from the request. Caught at the gate now, pinned here."""
    _, base = target
    cfg = AuthConfig(strategy=AuthStrategy.API_KEY_HEADER, api_key=API_KEY,
                     header_name=API_KEY_NAME, api_key_location="headers")    # typo
    assert auth.has_credential(cfg) is True
    assert set(_whoami(base, cfg).auth_applied) == set()


def test_an_unauthenticated_request_presents_nothing(target):
    _, base = target
    rec = _whoami(base, AuthConfig(strategy=AuthStrategy.BEARER, token=BEARER),
                  authed=False)
    assert set(rec.auth_applied) == set()
    assert rec.response.status == 401        # and the target agrees it was unauthenticated


def test_a_hand_written_auth_header_is_measured_even_when_identity_is_none(target):
    """The agent loop picks its own `authenticated` flag and can set arbitrary headers,
    so a request could claim to be unauthenticated while carrying a credential. Measuring
    the outbound headers — rather than trusting the flag — keeps the transcript honest,
    and the authz tell then rejects such a record as a control rather than evidence."""
    _, base = target
    rec = _whoami(base, AuthConfig(strategy=AuthStrategy.NONE), authed=False,
                  headers={"Authorization": "Bearer invalid_token_12345"})
    assert set(rec.auth_applied) == {"header:authorization"}


def test_seq_numbers_the_transcript(target):
    """`seq` is how a verdict names the record it came from; two look-alike requests must
    still be distinguishable."""
    _, base = target
    tx: list = []
    state = {"n": 0}
    for _ in range(3):
        perform_request(method="GET", path="/whoami", query={}, body=None, authed=False,
                        opts=_live_opts(base), auth=AuthConfig(), transcript=tx,
                        allowed_methods=SAFE_METHODS, state=state, max_requests=5)
    assert [r.seq for r in tx] == [1, 2, 3]


# ── OAuth2 client-credentials: fetch then use ────────────────────────────────

def test_oauth2_basic_client_auth_fetches_and_authenticates(target):
    _, base = target
    auth = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                      token_url=f"{base}/oauth/token", client_id=OAUTH_CLIENT,
                      client_secret=OAUTH_SECRET, oauth_client_auth="basic")
    CredentialProvider(auth, _live_opts(base)).acquire()
    assert auth.token == "oauth-at"                       # fetched over the socket
    assert _whoami(base, auth).response.status == 200      # and accepted by the target


def test_oauth2_body_client_auth_fetches(target):
    _, base = target
    auth = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                      token_url=f"{base}/oauth/token", client_id=OAUTH_CLIENT,
                      client_secret=OAUTH_SECRET, oauth_client_auth="body")
    CredentialProvider(auth, _live_opts(base)).acquire()
    assert auth.token == "oauth-at"


def test_oauth2_wrong_secret_raises(target):
    _, base = target
    auth = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                      token_url=f"{base}/oauth/token", client_id=OAUTH_CLIENT,
                      client_secret="wrong")
    with pytest.raises(AuthAcquireError):
        CredentialProvider(auth, _live_opts(base)).acquire()


# ── login flow: JSON token and Set-Cookie ────────────────────────────────────

def test_login_flow_json_token_authenticates(target):
    _, base = target
    auth = AuthConfig(strategy=AuthStrategy.BEARER, login_url=f"{base}/login",
                      username=LOGIN_USER, password=LOGIN_PASS)
    CredentialProvider(auth, _live_opts(base)).acquire()
    assert auth.token == LOGIN_TOKEN
    assert _whoami(base, auth).response.status == 200


def test_login_flow_form_body_authenticates(target):
    _, base = target
    auth = AuthConfig(strategy=AuthStrategy.BEARER, login_url=f"{base}/login",
                      username=LOGIN_USER, password=LOGIN_PASS, login_content_type="form")
    CredentialProvider(auth, _live_opts(base)).acquire()
    assert auth.token == LOGIN_TOKEN


def test_login_flow_cookie_authenticates(target):
    _, base = target
    auth = AuthConfig(strategy=AuthStrategy.SESSION_COOKIE, login_url=f"{base}/login-cookie",
                      username=LOGIN_USER, password=LOGIN_PASS, login_token_path="cookie")
    CredentialProvider(auth, _live_opts(base)).acquire()
    assert auth.token == LOGIN_COOKIE                      # extracted from Set-Cookie
    assert _whoami(base, auth).response.status == 200


# ── freshness + mid-run re-auth over real sockets ────────────────────────────

def test_freshness_static_valid_is_fresh(target):
    _, base = target
    auth = AuthConfig(strategy=AuthStrategy.BEARER, token=BEARER)
    assert ensure_fresh(CredentialProvider(auth, _live_opts(base)),
                        reachable=["/whoami"]) is Freshness.FRESH


def test_freshness_static_rejected_is_expired(target):
    _, base = target
    auth = AuthConfig(strategy=AuthStrategy.BEARER, token="wrong")   # /whoami 401s it
    assert ensure_fresh(CredentialProvider(auth, _live_opts(base)),
                        reachable=["/whoami"]) is Freshness.UNREFRESHABLE_EXPIRED


def test_mid_run_reauth_recovers_from_expired_token(target):
    httpd, base = target
    auth = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                      token_url=f"{base}/oauth/token", client_id=OAUTH_CLIENT,
                      client_secret=OAUTH_SECRET)
    prov = CredentialProvider(auth, _live_opts(base))
    prov.acquire()                                    # version 1, token "oauth-at"
    httpd.state["token"] = "oauth-at-2"               # server rotates → old token now 401s
    rec = _whoami(base, auth, provider=prov)          # 401 → reauth → retry with new token
    assert rec.response.status == 200
    assert prov.version == 2 and auth.token == "oauth-at-2"


# ════ mutual TLS (real handshake) ════

#: Passphrase protecting the throwaway client key generated below. Test-local
#: material for a certificate that exists only inside a tmp dir.
CLI_KEY_PASSPHRASE = "correct horse battery staple"


def _make_certs(dirpath):
    """A self-signed CA that signs a server cert (SAN 127.0.0.1) and a client cert.

    The client key is written three ways — plain, passphrase-encrypted, and
    encrypted inside a combined cert+key PEM — plus a junk file, so every branch of
    the cert loader has real material to work on.

    Skips the calling test when ``cryptography`` is unavailable — the guard lives
    here rather than at module scope so the rest of this file still runs without it.
    """
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def _key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    # These extensions are not decoration — OpenSSL 3.x verifies them strictly and refuses
    # a chain without them ("Missing Authority Key Identifier", "CA cert does not include
    # key usage extension"). A real CA issues all of them, so the fixture must too, or the
    # test measures the fixture's shortcuts rather than EV's mTLS handling.
    ca_key = _key()
    ca_cert = (x509.CertificateBuilder()
               .subject_name(_name("EV Test CA")).issuer_name(_name("EV Test CA"))
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=False, content_commitment=False,
                   key_encipherment=False, data_encipherment=False, key_agreement=False,
                   key_cert_sign=True, crl_sign=True,
                   encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                              critical=False)
               .sign(ca_key, hashes.SHA256()))

    def _leaf(cn, ip=None):
        k = _key()
        b = (x509.CertificateBuilder()
             .subject_name(_name(cn)).issuer_name(ca_cert.subject)
             .public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(
                 digital_signature=True, content_commitment=False,
                 key_encipherment=True, data_encipherment=False, key_agreement=False,
                 key_cert_sign=False, crl_sign=False,
                 encipher_only=False, decipher_only=False), critical=True)
             # One leaf shape serves both ends: the server cert authenticates the listener
             # and the client cert is presented for mTLS.
             .add_extension(x509.ExtendedKeyUsage([
                 ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH,
             ]), critical=False)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()),
                            critical=False)
             .add_extension(
                 x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                 critical=False))
        if ip:
            b = b.add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
                critical=False)
        return k, b.sign(ca_key, hashes.SHA256())

    srv_key, srv_cert = _leaf("127.0.0.1", ip="127.0.0.1")
    cli_key, cli_cert = _leaf("ev-client")

    def _w(name, data):
        p = dirpath / name
        p.write_bytes(data)
        return str(p)

    pem = serialization.Encoding.PEM
    keyfmt = serialization.PrivateFormat.TraditionalOpenSSL
    noenc = serialization.NoEncryption()
    # The same client key, passphrase-protected — and a combined cert+key PEM, the
    # shape a CA often hands out (one file, encrypted key, no separate key file).
    enc_key = cli_key.private_bytes(
        pem, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(CLI_KEY_PASSPHRASE.encode()))
    return {
        "ca": _w("ca.pem", ca_cert.public_bytes(pem)),
        "srv_cert": _w("srv.pem", srv_cert.public_bytes(pem)),
        "srv_key": _w("srv.key", srv_key.private_bytes(pem, keyfmt, noenc)),
        "cli_cert": _w("cli.pem", cli_cert.public_bytes(pem)),
        "cli_key": _w("cli.key", cli_key.private_bytes(pem, keyfmt, noenc)),
        "cli_key_enc": _w("cli-enc.key", enc_key),
        "cli_combined_enc": _w("cli-combined.pem", cli_cert.public_bytes(pem) + enc_key),
        "not_a_pem": _w("junk.pem", b"this is not a certificate\n"),
    }


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def mtls_server(tmp_path):
    certs = _make_certs(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certs["srv_cert"], certs["srv_key"])
    ctx.load_verify_locations(certs["ca"])
    ctx.verify_mode = ssl.CERT_REQUIRED               # mutual TLS: client cert required

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"https://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base, certs
    finally:
        httpd.shutdown()
        httpd.server_close()


def _mtls_opts(base, **kw):
    return EVOptions(enabled=True, target_url=base, timeout_s=5.0, **kw)


def test_mtls_with_client_cert_succeeds(mtls_server):
    base, certs = mtls_server
    r = send("GET", base + "/whoami",
             opts=_mtls_opts(base, ca_cert=certs["ca"],
                             client_cert=certs["cli_cert"], client_key=certs["cli_key"]))
    assert r.status == 200 and r.text == "ok"       # client cert negotiated → accepted


def test_mtls_without_client_cert_is_refused(mtls_server):
    base, certs = mtls_server
    # trusts the server (ca_cert) but presents NO client cert → the required-cert
    # handshake fails, and send() surfaces it as an error rather than a response.
    r = send("GET", base + "/whoami", opts=_mtls_opts(base, ca_cert=certs["ca"]))
    assert r.status is None and r.error


def test_mtls_untrusted_server_is_rejected(mtls_server):
    base, certs = mtls_server
    # present the client cert but do NOT trust the server's CA (verify_ssl stays on,
    # no ca_cert) → server-cert verification fails, no request is completed.
    r = send("GET", base + "/whoami",
             opts=_mtls_opts(base, client_cert=certs["cli_cert"], client_key=certs["cli_key"]))
    assert r.status is None and r.error


# ── the client certificate is a credential, and identity="none" drops it ─────
#
# A client certificate authenticates the request as surely as a bearer token, so an
# "unauthenticated" probe that still presents one is not unauthenticated. When the
# target's auth IS mTLS, that made every credentialed-vs-uncredentialed comparison
# compare two authenticated requests, and an ordinary 200 then looked like a bypass.

def test_client_cert_is_withheld_from_an_unauthenticated_request(mtls_server):
    """The handshake itself is the assertion: this server requires a client cert, so if
    the cert were still being presented the request would succeed."""
    base, certs = mtls_server
    opts = _mtls_opts(base, ca_cert=certs["ca"], client_cert=certs["cli_cert"],
                      client_key=certs["cli_key"])
    assert send("GET", base + "/whoami", opts=opts).status == 200          # authed: works
    r = send("GET", base + "/whoami", opts=opts, client_cert=False)
    assert r.status is None and r.error                                    # unauthed: refused


def test_ssl_context_never_loads_client_material_when_cert_is_withheld(mtls_server,
                                                                       monkeypatch):
    """Checked directly rather than through a handshake: a target that happens to accept
    anonymous clients would let a still-attached certificate pass unnoticed."""
    _base, certs = mtls_server
    opts = _mtls_opts("https://127.0.0.1", ca_cert=certs["ca"],
                      client_cert=certs["cli_cert"], client_key=certs["cli_key"])
    loaded = []
    monkeypatch.setattr(probe, "_load_client_cert", lambda ctx, o: loaded.append(o))
    probe._ssl_context(opts, client_cert=False)
    assert loaded == []                       # nothing presented
    probe._ssl_context(opts)
    assert len(loaded) == 1                   # and the default path is unchanged


def test_mtls_counts_as_a_credential_in_auth_applied(mtls_server):
    """An mTLS-only run has a credential to omit, so authz becomes testable rather than
    vacuous: the authed request records `mtls`, the unauthenticated one records nothing."""
    base, certs = mtls_server
    opts = _mtls_opts(base, ca_cert=certs["ca"], client_cert=certs["cli_cert"],
                      client_key=certs["cli_key"])
    authed = _whoami(base, AuthConfig(), opts=opts)
    assert set(authed.auth_applied) == {"mtls"}
    unauthed = _whoami(base, AuthConfig(), opts=opts, authed=False)
    assert set(unauthed.auth_applied) == set()


# ── encrypted client key: EV_TARGET_CLIENT_KEY_PASSPHRASE ────────────────────

def test_mtls_with_encrypted_key_and_passphrase(mtls_server):
    base, certs = mtls_server
    r = send("GET", base + "/whoami",
             opts=_mtls_opts(base, ca_cert=certs["ca"], client_cert=certs["cli_cert"],
                             client_key=certs["cli_key_enc"],
                             client_key_passphrase=CLI_KEY_PASSPHRASE))
    assert r.status == 200 and r.text == "ok"       # key unlocked → cert negotiated


def test_mtls_with_combined_pem_and_passphrase(mtls_server):
    base, certs = mtls_server
    # cert + encrypted key in ONE file: only client_cert is set, no client_key.
    r = send("GET", base + "/whoami",
             opts=_mtls_opts(base, ca_cert=certs["ca"],
                             client_cert=certs["cli_combined_enc"],
                             client_key_passphrase=CLI_KEY_PASSPHRASE))
    assert r.status == 200 and r.text == "ok"


def test_encrypted_key_without_passphrase_says_which_var_to_set(tmp_path):
    certs = _make_certs(tmp_path)
    opts = _mtls_opts("https://127.0.0.1", client_cert=certs["cli_cert"],
                      client_key=certs["cli_key_enc"])
    with pytest.raises(EVInputError) as ei:
        probe._ssl_context(opts)                    # never prompts on the terminal
    assert "EV_TARGET_CLIENT_KEY_PASSPHRASE" in str(ei.value)
    assert "passphrase-protected" in str(ei.value)


def test_wrong_passphrase_is_reported_without_echoing_it(tmp_path):
    certs = _make_certs(tmp_path)
    opts = _mtls_opts("https://127.0.0.1", client_cert=certs["cli_cert"],
                      client_key=certs["cli_key_enc"], client_key_passphrase="wrong-one")
    with pytest.raises(EVInputError) as ei:
        probe._ssl_context(opts)
    assert "could not unlock" in str(ei.value)
    assert "wrong-one" not in str(ei.value)         # the secret never lands in a message


def test_missing_cert_path_names_the_variable(tmp_path):
    opts = _mtls_opts("https://127.0.0.1", client_cert=str(tmp_path / "absent.pem"))
    with pytest.raises(EVInputError) as ei:
        probe._ssl_context(opts)
    assert "EV_TARGET_CLIENT_CERT" in str(ei.value)


def test_unencrypted_but_unloadable_cert_reports_the_format(tmp_path):
    certs = _make_certs(tmp_path)
    opts = _mtls_opts("https://127.0.0.1", client_cert=certs["not_a_pem"])
    with pytest.raises(EVInputError) as ei:
        probe._ssl_context(opts)
    # not encrypted, so the passphrase is not blamed — the format is.
    assert "Expected PEM" in str(ei.value)
    assert "PASSPHRASE" not in str(ei.value)


def test_gate_check_row_confirms_a_combined_encrypted_pem(tmp_path):
    certs = _make_certs(tmp_path)
    lvl, msg = gate._tls_material_check(
        _mtls_opts("https://127.0.0.1", ca_cert=certs["ca"],
                   client_cert=certs["cli_combined_enc"],
                   client_key_passphrase=CLI_KEY_PASSPHRASE))
    assert lvl == gate.OK
    assert "combined PEM" in msg and "EV_TARGET_CLIENT_KEY_PASSPHRASE" in msg
    assert CLI_KEY_PASSPHRASE not in msg            # the checklist is printed — no secret in it


def test_gate_check_row_fails_on_a_locked_key(tmp_path):
    certs = _make_certs(tmp_path)
    lvl, msg = gate._tls_material_check(
        _mtls_opts("https://127.0.0.1", client_cert=certs["cli_cert"],
                   client_key=certs["cli_key_enc"]))       # encrypted, no passphrase
    assert lvl == gate.FAIL and "EV_TARGET_CLIENT_KEY_PASSPHRASE" in msg


def test_plain_key_ignores_a_stray_passphrase(mtls_server):
    base, certs = mtls_server
    # A passphrase set against an unencrypted key is simply unused (OpenSSL never
    # invokes the callback) — it must not turn a working cert into a failure.
    r = send("GET", base + "/whoami",
             opts=_mtls_opts(base, ca_cert=certs["ca"], client_cert=certs["cli_cert"],
                             client_key=certs["cli_key"],
                             client_key_passphrase="unused"))
    assert r.status == 200


# ── layer 3: every form of a credential EV puts on the wire ──────────────────
# The known-value layer masks by literal, so it only protects the exact bytes it was
# given. These pin the forms EV itself produces — a base64 blob, a percent-encoded
# query value, and the two credentials spent before `build_headers` ever runs.

def test_the_basic_blob_is_registered_not_only_the_raw_password():
    """`Basic <blob>` is masked by shape only while it carries its prefix; a target that
    echoes the bare blob back would otherwise leak the credential in a form no layer sees."""
    a = AuthConfig(strategy=AuthStrategy.BASIC, username="svc-scanner",
                   password="Str0ng-P@ss-9f2b1c")
    blob = auth.build_headers(a)["Authorization"].split(" ", 1)[1]
    assert blob not in safety.redact_secrets(f'{{"seen":"{blob}"}}')
    assert "Str0ng-P@ss-9f2b1c" not in safety.redact_secrets("echo Str0ng-P@ss-9f2b1c")


def test_an_api_key_is_masked_in_its_percent_encoded_form():
    """An api key can travel as a query parameter, so the URL that reaches a log or an
    ev_probes row carries the encoded bytes, not the literal.

    The value is shape-anonymous and the surrounding text names nothing credential-like, so
    the only layer that can mask it here is the known-value one — a `?api_key=` context would
    be masked by the shape layer regardless of registration, proving nothing.
    """
    key = "opaque-9f2b/1c7d+4e8a=0b3f"
    safety.register_secret(key)
    encoded = quote(key, safe="")
    assert encoded != key                                    # the transform is real
    assert encoded not in safety.redact_secrets(f"GET /search?q={encoded}")


def test_oauth2_client_secret_is_registered_at_the_token_fetch(monkeypatch):
    """The client secret never passes through `build_headers` — it is spent only on the
    token request — so registration has to happen at the fetch."""
    _fake_send(monkeypatch, lambda c: _resp(200, json.dumps({"access_token": "AT"})))
    secret = "cs-7d4e8a0b3f6c2d19"
    a = AuthConfig(strategy=AuthStrategy.OAUTH2_CLIENT_CREDENTIALS,
                   token_url="http://127.0.0.1:5000/t", client_id="svc-scanner",
                   client_secret=secret, oauth_client_auth="body")
    CredentialProvider(a, _p_opts()).acquire()
    assert secret not in safety.redact_secrets(f'{{"debug_echo":"{secret}"}}')


def test_login_password_is_registered_before_the_login_request(monkeypatch):
    """The login POST is the FIRST place the password goes on the wire, ahead of any request
    that would register it, so an error body echoing it back must still be masked.

    Asserted DURING the request rather than after `acquire()` returns: the end state is
    reached either way once anything calls `build_headers`, so only the timing distinguishes
    a credential that was protected for this request from one protected after it.
    """
    pw = "Str0ng-P@ss-9f2b1c"
    masked_at_send: list[bool] = []

    def responder(_call):
        masked_at_send.append(pw not in safety.redact_secrets(f'{{"echoed":"{pw}"}}'))
        return _resp(200, json.dumps({"access_token": "AT"}))

    _fake_send(monkeypatch, responder)
    a = AuthConfig(strategy=AuthStrategy.BEARER, login_url="http://127.0.0.1:5000/login",
                   username="alice", password=pw)
    CredentialProvider(a, _p_opts()).acquire()
    assert masked_at_send == [True]


def test_login_extra_fields_are_not_registered_as_credentials():
    """`EV_AUTH_LOGIN_EXTRA` carries caller-chosen fields such as a tenant id, not secrets;
    masking them by value would corrupt the transcript for no gain."""
    a = AuthConfig(strategy=AuthStrategy.BEARER, login_url="http://127.0.0.1:5000/login",
                   username="alice", password="Str0ng-P@ss-9f2b1c",
                   login_extra={"tenant": "acme-tenant-002"})
    auth.build_headers(a)
    assert "acme-tenant-002" in safety.redact_secrets('{"tenant":"acme-tenant-002"}')
