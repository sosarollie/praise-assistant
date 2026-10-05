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

"""Exploit-verification OFFLINE runnability gate.

No network. The gate parses + validates the collection and returns it, or raises
EVInputError with a checklist when EV was requested but the collection can't run.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vvaharness.config import Config
from vvaharness.exploit_verification import gate, options
from vvaharness.exploit_verification.errors import EVInputError
from vvaharness.orchestrator import entry
from test_ev_config import ev_config


def _collection(tmp_path, obj, name="pm.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def _opts(path, env=None):
    return options.load_options(ev_config(enabled="auto"),
                                {**(env or {}), "EV_API_COLLECTION": str(path)})


def _resumed_opts(env=None):
    """Options for a ``--resume`` run: EV_API_COLLECTION unset, EV enabled by the
    checkpoint."""
    return options.load_options(ev_config(enabled="auto"), env or {},
                                resumed_collection=True)


_BEARER_PM = {"info": {"name": "x"}, "auth": {"type": "bearer"},
              "item": [{"name": "g", "request": {"method": "GET", "url": "/api/users/1"}}]}


def test_gate_ok_returns_the_parsed_collection(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    res = gate.run_gate(_opts(p), env={"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t"})
    assert res.enabled and res.ok
    # The gate hands the normalized collection back in memory (no on-disk artifact);
    # the caller threads it to the scan, which persists it to the SQLite state store.
    assert res.collection is not None
    # the numeric id segment is parameterized during normalization
    assert [e.path for e in res.collection.endpoints] == ["/api/users/{usersId}"]
    assert not (tmp_path / "pm.evcol.json").exists()


def test_gate_missing_credential_raises(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(p), env={"EV_AUTH_STRATEGY": "bearer"})   # no token
    assert "EV_AUTH_TOKEN" in str(e.value)


def test_gate_warns_when_a_credential_is_too_generic_to_redact(tmp_path):
    """The known-value layer declines to mask a dictionary-word credential, because literal
    replacement would rewrite JSON keys and prose. Nothing in the redactor can close that, so
    the gate names the variable before the run — the operator can supply a distinctive value,
    and only they can. A warning, not a failure: it is their test credential."""
    p = _collection(tmp_path, _BEARER_PM)
    res = gate.run_gate(_opts(p), env={"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "admin"})
    assert res.enabled and res.ok                      # advisory, never fatal
    warn = [m for lvl, m in res.checks if lvl == gate.WARN and "EV_AUTH_TOKEN" in m]
    assert warn and "too generic" in warn[0]


def test_gate_stays_quiet_for_a_distinctive_credential(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    res = gate.run_gate(_opts(p), env={"EV_AUTH_STRATEGY": "bearer",
                                       "EV_AUTH_TOKEN": "sess-9f2b1c7d4e8a0b3f6c2d"})
    assert res.ok
    assert not [m for lvl, m in res.checks if lvl == gate.WARN and "too generic" in m]


def test_gate_ignores_a_generic_credential_the_strategy_never_sends(tmp_path):
    """The warning is about what a run will actually put on the wire.

    A leftover `EV_AUTH_PASSWORD` in the same `.env` under `EV_AUTH_STRATEGY=bearer` is never
    attached to a request, so there is nothing to redact and nothing for the operator to
    change. Warning about it anyway is a row with no action behind it — which is how a check
    teaches operators to skip it.
    """
    p = _collection(tmp_path, _BEARER_PM)
    res = gate.run_gate(_opts(p), env={"EV_AUTH_STRATEGY": "bearer",
                                       "EV_AUTH_TOKEN": "sess-9f2b1c7d4e8a0b3f6c2d",
                                       "EV_AUTH_PASSWORD": "admin"})
    assert res.ok
    assert not [m for lvl, m in res.checks if lvl == gate.WARN and "too generic" in m]


def test_gate_still_warns_about_a_generic_password_under_basic(tmp_path):
    """The control: under a strategy that does send the password, the warning must stand."""
    p = _collection(tmp_path, _BEARER_PM)
    res = gate.run_gate(_opts(p), env={"EV_AUTH_STRATEGY": "basic",
                                       "EV_AUTH_USERNAME": "svc",
                                       "EV_AUTH_PASSWORD": "admin"})
    warn = [m for lvl, m in res.checks if lvl == gate.WARN and "EV_AUTH_PASSWORD" in m]
    assert warn and "too generic" in warn[0]


def test_gate_rejects_an_unrecognised_api_key_location(tmp_path):
    """A location outside header/query/cookie attaches nothing: `build_headers` handles
    only header/cookie and `build_query` only query, so the key sits in the config and
    never reaches a request — while the gate used to report "credential present". The
    first authz test would then read that as "auth is not enforced"."""
    p = _collection(tmp_path, _BEARER_PM)
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(p), env={"EV_AUTH_STRATEGY": "api_key_header",
                                     "EV_AUTH_API_KEY": "k",
                                     "EV_AUTH_API_KEY_LOCATION": "headers"})
    assert "EV_AUTH_API_KEY_LOCATION" in str(e.value)


@pytest.mark.parametrize("location", ["header", "query", "cookie"])
def test_gate_accepts_every_valid_api_key_location(tmp_path, location):
    p = _collection(tmp_path, _BEARER_PM)
    res = gate.run_gate(_opts(p), env={"EV_AUTH_STRATEGY": "api_key_header",
                                       "EV_AUTH_API_KEY": "k",
                                       "EV_AUTH_API_KEY_LOCATION": location})
    assert res.enabled and res.ok


def test_gate_no_auth_needed_ok(tmp_path):
    pm = {"info": {"name": "x"}, "item": [
        {"name": "g", "request": {"method": "GET", "url": "/public"}}]}
    res = gate.run_gate(_opts(_collection(tmp_path, pm)), env={})
    assert res.ok


def test_gate_empty_collection_raises(tmp_path):
    pm = {"info": {"name": "x"}, "item": []}
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(_collection(tmp_path, pm)), env={})
    assert "0 endpoints" in str(e.value)


def test_gate_malformed_file_raises(tmp_path):
    p = _collection(tmp_path, {"neither": "postman nor openapi"})
    with pytest.raises(EVInputError):
        gate.run_gate(_opts(p), env={})


def test_gate_login_flow_endpoint_must_be_local(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    env = {"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_LOGIN_URL": "http://auth.example/login",
           "EV_AUTH_USERNAME": "u", "EV_AUTH_PASSWORD": "p"}
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(p, env), env=env)          # login host is not local
    assert "not local" in str(e.value)


def test_gate_login_flow_endpoint_local_ok(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    env = {"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_LOGIN_URL": "http://127.0.0.1:5000/login",
           "EV_AUTH_USERNAME": "u", "EV_AUTH_PASSWORD": "p"}
    assert gate.run_gate(_opts(p, env), env=env).ok


def _remapped_localhost(monkeypatch, addr="10.0.0.5"):
    """`localhost` no longer names this machine — the case the gate has to explain."""
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, port, *a, **kw: [(2, 1, 6, "", (addr, 0))])


# ── a FAIL row must carry the envelope's own reason, not a substitute ───────────
# The safety envelope distinguishes "this host is not local" from "this host is spelled
# `localhost` and resolves elsewhere". Only the gate knows WHICH input carried the URL, so
# it prefixes that and relays the rest: re-writing the message loses the diagnosis, and for
# a remapped name it produces the self-contradicting "host 'localhost' is not local".

def test_gate_says_why_a_localhost_auth_endpoint_is_refused(tmp_path, monkeypatch):
    _remapped_localhost(monkeypatch)
    p = _collection(tmp_path, _BEARER_PM)
    env = {"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_USERNAME": "u",
           "EV_AUTH_PASSWORD": "pw-Kx91",
           "EV_AUTH_LOGIN_URL": "http://localhost:8000/login"}
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(p, env), env=env)
    msg = str(e.value)
    assert "login endpoint" in msg                      # which input
    assert "resolves to 10.0.0.5" in msg                # the actual diagnosis
    assert "'localhost' is not local" not in msg        # not the contradiction


def test_gate_says_why_a_localhost_oob_base_is_refused(tmp_path, monkeypatch):
    _remapped_localhost(monkeypatch)
    p = _collection(tmp_path, _BEARER_PM)
    env = {"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t0k3n-Xq7",
           "EV_OOB_URL": "http://localhost:9090"}
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(p, env), env=env)
    msg = str(e.value)
    assert "EV_OOB_URL" in msg and "resolves to 10.0.0.5" in msg
    assert "'localhost' is not local" not in msg


def test_gate_oob_callback_base_must_be_local(tmp_path):
    """EV_OOB_URL is an address the target dials back on, so it is held to the same rule
    as the target. Refused rather than re-addressed: a callback that cannot arrive would
    downgrade a blind confirmation with nothing in the report saying why."""
    p = _collection(tmp_path, _BEARER_PM)
    env = {"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t0k3n-Xq7",
           "EV_OOB_URL": "http://192.168.1.50:9090"}
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(p, env), env=env)
    assert "EV_OOB_URL" in str(e.value) and "not local" in str(e.value)


def test_gate_oob_callback_base_local_ok(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    env = {"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t0k3n-Xq7",
           "EV_OOB_URL": "http://127.0.0.1:9090"}
    assert gate.run_gate(_opts(p, env), env=env).ok


def test_gate_ignores_a_non_local_oob_url_when_the_listener_is_off(tmp_path):
    """With `oob: off` the value is inert, so failing on it would block a run over a
    setting that is never read."""
    p = _collection(tmp_path, _BEARER_PM)
    env = {"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t0k3n-Xq7",
           "EV_OOB_URL": "http://192.168.1.50:9090"}
    opts = options.load_options(ev_config(enabled="auto", oob="off"),
                               {**env, "EV_API_COLLECTION": str(p)})
    assert gate.run_gate(opts, env=env).ok


def test_gate_oauth2_token_endpoint_must_be_local(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    env = {"EV_AUTH_STRATEGY": "oauth2_client_credentials",
           "EV_AUTH_TOKEN_URL": "http://idp.example/token", "EV_AUTH_CLIENT_ID": "c"}
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(p, env), env=env)
    assert "not local" in str(e.value)


def test_gate_over_a_handed_collection_skips_the_parse(tmp_path):
    # The --resume path: the collection is already normalized, so the source file is
    # never re-read (it is deleted to prove it).
    p = _collection(tmp_path, _BEARER_PM)
    env = {"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t"}
    col = gate.run_gate(_opts(p), env=env).collection
    p.unlink()

    res = gate.run_gate(_resumed_opts(), env=env, collection=col)
    assert res.enabled and res.ok
    # the checks still ran, and the first one says reused rather than parsed
    assert any(msg.startswith("reused checkpointed postman") for _lvl, msg in res.checks)
    assert any("credential present" in msg for _lvl, msg in res.checks)


def test_gate_over_a_handed_collection_still_needs_the_credential(tmp_path):
    # An .env that has drifted since the original run must fail here, not mid-scan.
    p = _collection(tmp_path, _BEARER_PM)
    col = gate.run_gate(_opts(p), env={"EV_AUTH_STRATEGY": "bearer",
                                       "EV_AUTH_TOKEN": "t"}).collection
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_resumed_opts(), env={"EV_AUTH_STRATEGY": "bearer"}, collection=col)
    assert "EV_AUTH_TOKEN" in str(e.value)


# ── transport-TLS material ───────────────────────────────────────────────────
# The gate loads any configured CA / mTLS client certificate, so unusable material
# fails here instead of on every request. Loading real (encrypted) cert material is
# exercised in test_ev_auth.py, which owns the throwaway-certificate fixture; these
# cover the wiring and need no crypto.

def test_gate_reports_an_unreadable_client_cert(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(p, {"EV_TARGET_CLIENT_CERT": str(tmp_path / "absent.pem")}),
                      env={"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t"})
    assert "EV_TARGET_CLIENT_CERT" in str(e.value)


def test_gate_reports_an_unreadable_ca_cert(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    with pytest.raises(EVInputError) as e:
        gate.run_gate(_opts(p, {"EV_TARGET_CA_CERT": str(tmp_path / "absent-ca.pem")}),
                      env={"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t"})
    assert "EV_TARGET_CA_CERT" in str(e.value)


def test_gate_has_no_tls_row_when_none_is_configured(tmp_path):
    res = gate.run_gate(_opts(_collection(tmp_path, _BEARER_PM)),
                        env={"EV_AUTH_STRATEGY": "bearer", "EV_AUTH_TOKEN": "t"})
    assert not any("target TLS" in msg for _, msg in res.checks)


def test_gate_disabled_is_noop(tmp_path):
    p = _collection(tmp_path, _BEARER_PM)
    o = options.load_options(ev_config(enabled="false"),
                             {"EV_API_COLLECTION": str(p)})
    res = gate.run_gate(o, env={})
    assert res.enabled is False
    assert res.collection is None


# ════ the CLI wrapper (entry._ev_gate) ════
#
# Decides whether main() may continue. With EV_API_COLLECTION unset there is nothing to
# parse here, but a --resume run may still have a checkpointed one — which
# scan._ev_prep loads and gates — so it must not be refused.

def _cli_args(resume=False, stop_after=None):
    """What argv still supplies; the collection comes from the environment."""
    return SimpleNamespace(resume=resume, stop_after=stop_after,
                           repo="/nonexistent", repo_file=None)


def test_cli_stop_after_ev_needs_a_path_on_a_fresh_run():
    assert entry._ev_gate(_cli_args(stop_after="ev"), Config({}))[0] == 2


def test_cli_stop_after_ev_is_allowed_on_a_resume_without_a_path():
    assert entry._ev_gate(_cli_args(resume=True, stop_after="ev"), Config({}))[0] is None


def test_cli_no_path_is_a_noop():
    assert entry._ev_gate(_cli_args(), Config({}))[0] is None


def test_cli_reads_the_collection_from_the_environment(tmp_path, monkeypatch):
    """The whole point of the move: no flag, and `scan` still finds its input. A parsed
    collection comes back, so the gate ran on the configured path."""
    monkeypatch.setenv("EV_API_COLLECTION", str(_collection(tmp_path, _BEARER_PM)))
    monkeypatch.setenv("EV_TARGET_URL", "http://127.0.0.1:5000")
    monkeypatch.setenv("EV_AUTH_TOKEN", "t")
    rc, col = entry._ev_gate(_cli_args(), ev_config(enabled="auto"))
    assert rc is None and col is not None


def test_cli_a_blank_variable_reads_as_no_collection(monkeypatch):
    """An empty line in `.env` must leave EV off rather than fail later on a path of ""."""
    monkeypatch.setenv("EV_API_COLLECTION", "   ")
    assert entry._ev_gate(_cli_args(), Config({})) == (None, None)
    assert entry._ev_gate(_cli_args(stop_after="ev"), Config({}))[0] == 2


def test_cli_refuses_a_network_collection_path(monkeypatch, capsys):
    """Reading a UNC path can leak the caller's credentials to the host serving it, so it
    is refused before any filesystem access — the check the flag used to guard."""
    monkeypatch.setenv("EV_API_COLLECTION", r"\\evil.example\share\c.json")
    assert entry._ev_gate(_cli_args(), Config({}))[0] == 2
    assert "must be a local path" in capsys.readouterr().err


def test_cli_batch_mode_ignores_the_collection(monkeypatch, tmp_path, capsys):
    """One EV_TARGET_URL cannot stand in for every repo in a batch, so a batch run
    verifies nothing rather than sending one target's payloads on behalf of all of them."""
    monkeypatch.setenv("EV_API_COLLECTION", str(_collection(tmp_path, _BEARER_PM)))
    args = _cli_args()
    args.repo_file = "repos.txt"
    assert entry._ev_gate(args, Config({})) == (None, None)
    assert "single-repo only" in capsys.readouterr().err


def test_the_removed_flag_is_rejected(capsys):
    """`--ev-api-collection` is gone. A stale invocation has to fail at argument parsing
    rather than run SAST-only and hand back a report the caller reads as verified."""
    with pytest.raises(SystemExit) as exc:
        entry.main(["--repo", "/nonexistent", "--ev-api-collection", "c.json"])
    assert exc.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
