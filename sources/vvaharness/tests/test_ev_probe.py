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

"""Exploit-verification ONLINE reachability probe.

Network is faked by monkeypatching ``httpx.Client`` — no real socket, no local
server, since none of this needs one. Verifies classification, the
nothing-reachable hard fail, and the on_unreachable drop/abort policies.
"""
from __future__ import annotations

import httpx
import pytest

from vvaharness.exploit_verification import auth, probe
from vvaharness.exploit_verification.collection.model import EndpointHint, NormalizedCollection
from vvaharness.exploit_verification.errors import EVUnreachableError
from vvaharness.exploit_verification.options import EVOptions, OnUnreachable


def _col(*eps):
    return NormalizedCollection(endpoints=[EndpointHint(**e) for e in eps])


def _opts(**kw):
    base = dict(enabled=True, api_collection_path="/c",
                target_url="http://127.0.0.1:5000")
    base.update(kw)
    return EVOptions(**base)


class _Resp:
    def __init__(self, code):
        self.status_code = code


def _install_fake_client(monkeypatch, router, calls=None):
    """router(method, url) -> int status | Exception to raise. ``calls`` (a list)
    records every ``(method, url, kwargs)`` sent, for asserting what went on the wire."""
    class FakeClient:
        def __init__(self, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, method, url, **kw):
            if calls is not None:
                calls.append((method, url, kw))
            out = router(method, url)
            if isinstance(out, Exception):
                raise out
            return _Resp(out)

    monkeypatch.setattr(httpx, "Client", FakeClient)


_NOAUTH = auth.AuthConfig()


def test_classifies_and_returns_collection(monkeypatch):
    _install_fake_client(monkeypatch, lambda m, u: 404 if "/login" in u else 200)
    col = _col({"method": "GET", "path": "/api/users/{id}", "path_params": {"id": "1"}},
               {"method": "POST", "path": "/api/login"})
    out = probe.run_probe(col, _opts(), _NOAUTH)
    assert out is not None
    assert out.reachability["/api/users/{*}"] == "exists"
    # POST is probed with its real method now (not OPTIONS); a 404 on a no-param route
    # means the route is genuinely missing → dead.
    assert out.reachability["/api/login"] == "dead"


def test_probe_uses_the_real_method_and_sends_the_example_body(monkeypatch):
    # The probe hits what the collection declares — a POST endpoint gets a real POST
    # carrying its example JSON body, not an OPTIONS stand-in.
    calls: list = []
    _install_fake_client(monkeypatch, lambda m, u: 200, calls=calls)
    col = _col({"method": "POST", "path": "/api/score",
                "body_template": {"cve": "CVE-1"}, "content_type": "application/json"})
    out = probe.run_probe(col, _opts(), _NOAUTH)
    assert out.reachability["/api/score"] == "exists"
    method, url, kw = calls[0]
    assert method == "POST" and url.endswith("/api/score")
    assert kw.get("json") == {"cve": "CVE-1"}       # the collection's body went on the wire


def test_delete_endpoint_is_probed_without_a_real_delete_on_the_wire(monkeypatch):
    # A DELETE route the run has not opted into is downgraded to OPTIONS for the
    # reachability probe. Preflight runs before every safety gate, so it must never fire
    # a destructive request just to learn whether the route exists.
    calls: list = []
    _install_fake_client(monkeypatch, lambda m, u: 200, calls=calls)
    col = _col({"method": "DELETE", "path": "/api/records/{id}", "path_params": {"id": "1"}})
    out = probe.run_probe(col, _opts(), _NOAUTH)             # defaults: not opted in
    assert out.reachability["/api/records/{*}"] == "exists"  # route still classified
    method, _url, _kw = calls[0]
    assert method == "OPTIONS"                              # downgraded, not a real DELETE
    assert all(m != "DELETE" for m, _u, _k in calls)        # nothing destructive on the wire


def test_put_endpoint_goes_on_the_wire_when_the_run_opts_into_state_changing(monkeypatch):
    # The complement: once the run opts in, a PUT probes as a real PUT carrying its example
    # body — the policy downgrades only what the run has not permitted.
    calls: list = []
    _install_fake_client(monkeypatch, lambda m, u: 200, calls=calls)
    col = _col({"method": "PUT", "path": "/api/records/{id}", "path_params": {"id": "1"},
                "body_template": {"name": "n"}, "content_type": "application/json"})
    probe.run_probe(col, _opts(), _NOAUTH, allow_state_changing=True)
    method, url, kw = calls[0]
    assert method == "PUT" and url.endswith("/api/records/1")   # real PUT, not a stand-in
    assert kw.get("json") == {"name": "n"}                      # the example body went out


def test_nothing_reachable_raises(monkeypatch):
    _install_fake_client(monkeypatch, lambda m, u: httpx.ConnectError("down"))
    with pytest.raises(EVUnreachableError):
        probe.run_probe(_col({"method": "GET", "path": "/a"}), _opts(), _NOAUTH)


def test_drop_policy_prunes_dead(monkeypatch):
    _install_fake_client(monkeypatch, lambda m, u: 404 if u.endswith("/gone") else 200)
    col = _col({"method": "GET", "path": "/live"},
               {"method": "GET", "path": "/gone"})
    out = probe.run_probe(col, _opts(on_unreachable=OnUnreachable.DROP), _NOAUTH)
    paths = [e.path for e in out.endpoints]
    assert paths == ["/live"]                       # dead /gone pruned
    assert out.reachability["/gone"] == "dead"


def test_abort_policy_disables_ev(monkeypatch):
    _install_fake_client(monkeypatch, lambda m, u: 404 if u.endswith("/gone") else 200)
    col = _col({"method": "GET", "path": "/live"},
               {"method": "GET", "path": "/gone"})
    out = probe.run_probe(col, _opts(on_unreachable=OnUnreachable.ABORT), _NOAUTH)
    assert out is None                              # some dead + abort → EV disabled this run


def test_missing_target_url_raises(monkeypatch):
    _install_fake_client(monkeypatch, lambda m, u: 200)
    with pytest.raises(EVUnreachableError):
        probe.run_probe(_col({"method": "GET", "path": "/a"}),
                        _opts(target_url=""), _NOAUTH)


def test_all_skipped_by_non_local_target_raises_with_hint(monkeypatch):
    _install_fake_client(monkeypatch, lambda m, u: 200)
    # non-local target → the safety envelope skips every endpoint, none is probed.
    opts = _opts(target_url="https://api.example")
    with pytest.raises(EVUnreachableError) as e:
        probe.run_probe(_col({"method": "GET", "path": "/a"}), opts, _NOAUTH)
    assert "localhost" in str(e.value)


# ── endpoints with an unusable body are dropped, loudly ──────────────────────
#
# The alternative was sending `{"_raw": "<text we could not parse>"}`, which the server
# rejects — and that rejection then became the baseline every payload on the endpoint
# was compared against. Dropping is loud because only the operator can fix the source.

def test_an_endpoint_with_an_unparsed_body_is_dropped_and_named(monkeypatch, capsys):
    sent: list = []
    _install_fake_client(monkeypatch, lambda m, u: 200, calls=sent)
    col = _col({"method": "POST", "path": "/ok"},
               {"method": "POST", "path": "/broken",
                "body_unparsed": "body is not valid JSON and declares no raw language"})
    out = probe.run_probe(col, _opts(), _NOAUTH)
    assert [e.path for e in out.endpoints] == ["/ok"]
    assert all("/broken" not in u for _m, u, _kw in sent)   # never probed either
    err = capsys.readouterr().err
    assert "dropping 1 endpoint(s) with an unusable request body" in err
    assert "POST /broken" in err and "not valid JSON" in err


def test_all_bodies_unparsed_raises_rather_than_probing_nothing(monkeypatch):
    _install_fake_client(monkeypatch, lambda m, u: 200)
    col = _col({"method": "POST", "path": "/a", "body_unparsed": "bad body"})
    with pytest.raises(EVUnreachableError) as e:
        probe.run_probe(col, _opts(), _NOAUTH)
    assert "unusable request body" in str(e.value)


# ── login-flow credential minted at probe time ───────────────────────────────
#
# A login-flow config (bearer + login_url, no static token) can_mint(): the probe mints
# once up front so authenticated endpoints probe as themselves rather than as 401s, and a
# broken login flow surfaces at preflight (--stop-after ev) instead of only at S6. The
# mint POSTs through auth_provider.send (not the probe's httpx.Client), so it is stubbed
# here at CredentialProvider.acquire; build_headers then injects the token it sets.

def _login_auth():
    return auth.AuthConfig(strategy=auth.AuthStrategy.BEARER,
                           login_url="http://127.0.0.1:5000/login",
                           username="u", password="p")


def test_probe_mints_a_login_credential_and_authenticates(monkeypatch, capsys):
    from vvaharness.exploit_verification.auth_provider import CredentialProvider
    monkeypatch.setattr(CredentialProvider, "acquire",
                        lambda self: setattr(self.auth, "token", "minted-tok"))
    calls: list = []
    _install_fake_client(monkeypatch, lambda m, u: 200, calls=calls)
    probe.run_probe(_col({"method": "GET", "path": "/me"}), _opts(), _login_auth())
    hdrs = calls[-1][2].get("headers") or {}
    assert hdrs.get("Authorization") == "Bearer minted-tok"   # the minted token went out
    err = capsys.readouterr().err
    assert "minted a fresh credential via the login flow" in err   # ...and the mint is logged
    assert "minted-tok" not in err                                 # never the value


def test_probe_does_not_mint_when_a_static_token_is_present(monkeypatch):
    # A static token satisfies bearer outright (can_mint() is False), so no login POST.
    from vvaharness.exploit_verification.auth_provider import CredentialProvider
    monkeypatch.setattr(CredentialProvider, "acquire",
                        lambda self: (_ for _ in ()).throw(AssertionError("must not mint")))
    calls: list = []
    _install_fake_client(monkeypatch, lambda m, u: 200, calls=calls)
    static = auth.AuthConfig(strategy=auth.AuthStrategy.BEARER, token="static-tok")
    probe.run_probe(_col({"method": "GET", "path": "/me"}), _opts(), static)  # no raise
    assert (calls[-1][2].get("headers") or {}).get("Authorization") == "Bearer static-tok"


def test_probe_mint_failure_is_non_fatal(monkeypatch, capsys):
    from vvaharness.exploit_verification.auth_provider import (AuthAcquireError,
                                                               CredentialProvider)
    def _boom(self):
        raise AuthAcquireError("login endpoint returned 401")
    monkeypatch.setattr(CredentialProvider, "acquire", _boom)
    # /me probes unauthenticated -> 401 (classified 'exists'); /pub -> 200. Nothing dead.
    _install_fake_client(monkeypatch, lambda m, u: 401 if u.endswith("/me") else 200)
    out = probe.run_probe(_col({"method": "GET", "path": "/me"},
                               {"method": "GET", "path": "/pub"}), _opts(), _login_auth())
    assert out is not None                                    # the probe completed
    assert "could not mint a credential" in capsys.readouterr().err


# ── env-loaded auth adopts the collection-declared scheme ─────────────────────
#
# With no auth passed in, run_probe loads it from EV_AUTH_*. If the operator left
# EV_AUTH_STRATEGY unset the env strategy is NONE — but a collection that DECLARES a
# scheme must still authenticate, matching the effective strategy the offline gate
# validated. Without adopting the declared scheme onto the runtime AuthConfig,
# build_headers keys off NONE and every request goes out unauthenticated after a green
# "credential present" preflight.

def test_env_loaded_auth_adopts_collection_bearer_when_strategy_unset(monkeypatch):
    # No auth argument → the env-load path. EV_AUTH_STRATEGY is absent from the env dict,
    # so the collection's declared scheme is the only thing that can send the token.
    calls: list = []
    _install_fake_client(monkeypatch, lambda m, u: 200, calls=calls)
    col = _col({"method": "GET", "path": "/users"})
    col.auth.type = "bearer"                          # the collection declares bearer
    out = probe.run_probe(col, _opts(), env={"EV_AUTH_TOKEN": "s3cr3t"})
    assert out is not None                            # reachable → the probe completed
    hdrs = calls[-1][2].get("headers") or {}
    assert hdrs.get("Authorization") == "Bearer s3cr3t"   # declared scheme authenticated it
