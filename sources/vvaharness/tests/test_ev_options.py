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

"""Exploit-verification options — merge of CLI + .env + profile.

Pure function — no network.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.config import Config
from vvaharness.exploit_verification import options
from vvaharness.exploit_verification.errors import EVInputError
from vvaharness.exploit_verification.options import OnUnreachable
from test_ev_config import ev_config


def _env(path=None, extra=None):
    """The environment a scan would see — the collection path plus whatever else a test
    needs. `EV_API_COLLECTION` is the input now, so "no collection" is simply an env
    without it."""
    e = dict(extra or {})
    if path is not None:
        e["EV_API_COLLECTION"] = path
    return e


def test_enabled_when_path_present():
    o = options.load_options(
        ev_config(enabled="auto"),
        _env("/tmp/c.json", {"EV_TARGET_URL": "https://api.example.com"}))
    assert o.enabled is True
    assert o.api_collection_path == "/tmp/c.json"


def test_disabled_when_no_path():
    assert options.load_options(ev_config(), _env()).enabled is False


def test_a_blank_or_whitespace_variable_reads_as_absent():
    """An empty line in `.env` is the common shape of "not configured", so it must leave EV
    off rather than enable it with a path of "" that fails later."""
    for value in ("", "   ", "\t"):
        env = {"EV_API_COLLECTION": value}
        assert options.collection_path(env) is None
        assert options.load_options(ev_config(), env).enabled is False
        assert options.may_run(ev_config(enabled="auto"), env) is False


def test_the_path_is_stripped_of_surrounding_whitespace():
    """A trailing space in a `.env` line is a typo, not part of the filename."""
    assert options.collection_path({"EV_API_COLLECTION": "  /tmp/c.json  "}) == "/tmp/c.json"


def test_disabled_when_profile_forces_off():
    o = options.load_options(ev_config(enabled="false"),
                             _env("/tmp/c.json"))
    assert o.enabled is False


def test_enabled_by_a_resumed_collection_with_no_path():
    # A --resume run whose collection came from the checkpoint: the input IS present,
    # so EV is on even though EV_API_COLLECTION is unset.
    o = options.load_options(ev_config(), _env(), resumed_collection=True)
    assert o.enabled is True
    assert o.api_collection_path is None


def test_profile_off_still_beats_a_resumed_collection():
    o = options.load_options(ev_config(enabled="false"),
                             _env(), resumed_collection=True)
    assert o.enabled is False


def test_target_url_from_env():
    o = options.load_options(ev_config(),
                             _env("/c", {"EV_TARGET_URL": "http://127.0.0.1:8000"}))
    assert o.target_url == "http://127.0.0.1:8000"


def test_behavior_knobs_from_profile():
    o = options.load_options(
        ev_config(on_unreachable="warn", timeout_s=9, safe_mode=False),
        _env("/c"))
    assert o.on_unreachable == OnUnreachable.WARN
    assert o.timeout_s == 9.0
    assert o.safe_mode is False


def test_a_misspelled_policy_fails_instead_of_silently_defaulting():
    """A typo used to fall back to the DEFAULT, which for both policies is the more
    PERMISSIVE option: an operator who asked to `abort` on dead endpoints silently got
    "prune and continue", and one who asked to `abort` on a dead credential kept sending
    payloads. Validated at the gate instead, before any request or model spend."""
    with pytest.raises(EVInputError) as e:
        options.load_options(ev_config(on_unreachable="abrot"), _env("/c"))
    assert "on_unreachable" in str(e.value) and "abrot" in str(e.value)

    with pytest.raises(EVInputError) as e:
        options.load_options(ev_config(on_auth_failure="degrde"), _env("/c"))
    assert "on_auth_failure" in str(e.value)

    # every documented value still loads
    for v in ("drop", "warn", "abort"):
        assert options.load_options(ev_config(on_unreachable=v), _env("/c")).on_unreachable.value == v
    for v in ("degrade", "abort", "warn"):
        options.load_options(ev_config(on_auth_failure=v), _env("/c"))   # no raise


def test_the_concurrency_caps_default_to_the_safe_value():
    """The code default used to be 0 (unlimited) while every shipped profile chose 8/4 — so
    the only profile inheriting it ran uncapped at the target. The default is now the value
    the profiles already used; 0 still means "no cap" when asked for explicitly."""
    from vvaharness.config import _STEP_DEFAULTS
    ev = _STEP_DEFAULTS["step6_exploit_verification"]
    assert ev["max_concurrency_target"] == 8 and ev["max_concurrency_endpoint"] == 4


def test_tls_from_env():
    o = options.load_options(ev_config(),
                             _env("/c", {"EV_TARGET_VERIFY_SSL": "false",
                                         "EV_TARGET_CA_CERT": "/ca.pem"}))
    assert o.verify_ssl is False
    assert o.ca_cert == "/ca.pem"


def test_client_cert_from_env():
    o = options.load_options(ev_config(),
                             _env("/c", {"EV_TARGET_CLIENT_CERT": "/client.pem",
                                         "EV_TARGET_CLIENT_KEY": "/client.key"}))
    assert o.client_cert == "/client.pem" and o.client_key == "/client.key"
    assert o.client_key_passphrase is None          # absent → not set


def test_client_key_passphrase_from_env():
    # A combined PEM (no separate key) with an encrypted key — the passphrase is
    # taken verbatim: whitespace can be part of it, so it is never stripped.
    o = options.load_options(ev_config(),
                             _env("/c", {"EV_TARGET_CLIENT_CERT": "/client.pem",
                                         "EV_TARGET_CLIENT_KEY_PASSPHRASE":
                                             " pass phrase "}))
    assert o.client_key is None
    assert o.client_key_passphrase == " pass phrase "


def test_blank_client_key_passphrase_is_none():
    o = options.load_options(ev_config(),
                             _env("/c", {"EV_TARGET_CLIENT_KEY_PASSPHRASE": ""}))
    assert o.client_key_passphrase is None


# ── may_run: does this invocation need EV's model credentials at all? ─────────
#
# EV is off unless a collection is supplied, and its roles are detection-era — so a
# credential gap on one is FATAL, not a skip-this-stage WARN (unlike remediate/validate,
# which are in `llm.POST_SCAN_ROLES`). Without this gate a profile naming an EV model on
# some other backend would demand that credential from every scan, including the ones
# that never enable EV.

def _run_args(resume=False):
    """What argv still contributes: only `--resume`. The collection comes from the env."""
    return SimpleNamespace(resume=resume)


def _switch(value):
    return ev_config(enabled=value)


def test_may_run_is_false_for_a_plain_scan():
    assert options.may_run(_switch("auto"), _env()) is False


def test_may_run_is_true_once_a_collection_is_given():
    assert options.may_run(_switch("auto"), _env("/tmp/c.json")) is True


def test_a_bare_resume_does_not_demand_ev_credentials():
    """EV may still run on a resume from a checkpointed collection — but whether one was
    stored is not knowable at preflight, and answering "yes" would make an ordinary SAST
    resume fail for want of a credential its stages never use. Answering "no" only costs
    the early warning: EV degrades on an unavailable model anyway."""
    assert options.may_run(_switch("auto"), _env()) is False


def test_may_run_is_true_whenever_ev_is_required():
    """`enabled: true` means EV runs, so its models are always in scope — the collection
    is a separate requirement, enforced by `resolution_error`."""
    for env in (_env(), _env("/tmp/c.json")):
        assert options.may_run(_switch("true"), env) is True


def test_the_profile_veto_beats_everything():
    assert options.may_run(_switch("false"), _env("/tmp/c.json")) is False
    assert options.may_run(_switch("false"), _env()) is False


# ── `true` and `false` are hard: a contradiction aborts ──────────────────────
#
# One requires verification, the other forbids it, so either paired with the opposite
# input has no safe reading. Neither is a warning: what survives a run is the
# report, and it cannot say whether EV was skipped — a reader cannot tell "EV ran and
# confirmed nothing" from "EV never ran", so a line in stderr protects neither intent.
# `auto` is defined by whether the collection is set and can never conflict.

def test_required_without_a_collection_aborts():
    err = options.resolution_error(_switch("true"), _run_args(), _env())
    assert err and "requires a collection" in err
    assert "EV_API_COLLECTION" in err and "enabled: auto" in err     # names both fixes


def test_required_is_satisfied_by_a_collection_or_a_resume():
    """A resume may carry the collection in its checkpoint, so it is not a violation."""
    assert options.resolution_error(_switch("true"), _run_args(), _env("/tmp/c.json")) is None
    assert options.resolution_error(_switch("true"), _run_args(resume=True), _env()) is None


def test_a_vetoed_collection_aborts():
    err = options.resolution_error(_switch("false"), _run_args(), _env("/tmp/c.json"))
    assert err and "enabled: false" in err
    assert "Unset it" in err                                        # names the fix


def test_a_veto_with_no_flag_is_silent():
    for args in (_run_args(), _run_args(resume=True)):
        assert options.resolution_error(_switch("false"), args, _env()) is None
        assert options.load_options(_switch("false"), _env()).enabled is False


def test_auto_never_conflicts():
    for args in (_run_args(), _run_args(resume=True)):
        for env in (_env(), _env("/tmp/c.json")):
            assert options.resolution_error(_switch("auto"), args, env) is None


# ══ the whole decision tree, in one table ════════════════════════════════════
#
# Three inputs decide everything: the profile switch, whether EV_API_COLLECTION is set,
# and (on --resume) whether a collection was checkpointed. Kept as a table so the matrix
# is readable and a future change has to edit a row rather than reason about branches.
#
# `aborts`  — resolution_error fires: the run exits 2 at startup, before any model spend.
# `checks`  — may_run: EV's model roles are in the startup credential preflight.
# `runs`    — load_options: EV verifies this run.
#
# Two rows carry a footnote because startup is not the last word — it decides before the
# collection is known, so `_ev_prep` settles what it cannot (tested in
# test_ev_collection.py):
#   [1] enabled:true + resume + empty checkpoint — `runs` is False here, but the run does
#       not continue: `_ev_prep` raises rather than hand back an unverified report.
#   [2] auto + resume + checkpointed collection — `checks` is False here, so `_ev_prep`
#       runs the model checks itself before verifying.

_TREE = [
    # label                                 switch   env   resume ckpt  aborts checks runs
    ("true + collection set",              "true",  True,  False, False, False, True,  True),
    ("true + nothing",                       "true",  False, False, False, True,  None,  None),
    ("true + --resume, ckpt has one",        "true",  False, True,  True,  False, True,  True),
    ("true + --resume, ckpt empty [1]",      "true",  False, True,  False, False, True,  False),
    ("true + --resume + collection set", "true", True,  True,  False, False, True,  True),

    ("false + collection set",             "false", True,  False, False, True,  None,  None),
    ("false + nothing",                      "false", False, False, False, False, False, False),
    ("false + --resume, ckpt has one",       "false", False, True,  True,  False, False, False),
    ("false + --resume + collection set", "false", True, True,  False, True,  None,  None),

    ("auto + collection set",              "auto",  True,  False, False, False, True,  True),
    ("auto + nothing",                       "auto",  False, False, False, False, False, False),
    ("auto + --resume, ckpt has one [2]",    "auto",  False, True,  True,  False, False, True),
    ("auto + --resume, ckpt empty",          "auto",  False, True,  False, False, False, False),
    ("auto + --resume + collection set", "auto", True,  True,  False, False, True,  True),
]


@pytest.mark.parametrize(
    "switch,has_collection,resume,ckpt,aborts,checks,runs",
    [row[1:] for row in _TREE], ids=[row[0] for row in _TREE])
def test_the_decision_tree(switch, has_collection, resume, ckpt, aborts, checks, runs):
    cfg = _switch(switch)
    args = _run_args(resume=resume)
    env = _env("/tmp/c.json" if has_collection else None)

    err = options.resolution_error(cfg, args, env)
    assert (err is not None) is aborts, err or "expected an abort"
    if aborts:
        return                                  # nothing downstream runs

    assert options.may_run(cfg, env) is checks
    assert options.load_options(cfg, env, resumed_collection=ckpt).enabled is runs


def test_the_table_is_a_complete_specification():
    """The table stands in for the spec, so it has to stay complete and non-redundant:
    every row a distinct combination of the four inputs, and every switch exercised
    against each input shape."""
    inputs = [(r[1], r[2], r[3], r[4]) for r in _TREE]
    assert len(set(inputs)) == len(inputs)                      # no row repeats another
    for sw in ("true", "false", "auto"):
        shapes = {(has_col, resume) for s, has_col, resume, _ in inputs if s == sw}
        assert (False, False) in shapes and (True, False) in shapes   # set / unset
        assert (False, True) in shapes                                # resume


# ── model_preflight: EV's models must be usable on a run that will verify ────
#
# Closes the gap the startup preflight cannot: it accepts a --resume without knowing
# whether a collection was checkpointed, so a resumed run could reach S6 with models
# nobody had checked. Applied where the collection IS known, and it fails rather than
# degrades — the collection was supplied, so verification was asked for. Mirrors
# orchestrator.scan._remediate_preflight / _validate_preflight.

def _models(**purposes):
    return Config({"models": {"exploit_verification": purposes}})


def _cli(mid="claude-sonnet-4-6"):
    return {"id": mid, "via": "cli"}


def _usable_pair():
    return {"judge": _cli(), "classify": _cli()}


def test_model_preflight_passes_on_the_minimum(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    assert options.model_preflight(_models(**_usable_pair())) is None


@pytest.mark.parametrize("present,missing", [
    ({}, ["judge", "classify"]),
    ({"judge": _cli()}, ["classify"]),
    ({"classify": _cli()}, ["judge"]),
])
def test_the_indispensable_roles_must_be_declared(present, missing):
    """No judge means no confirmation authority; no classify means EV cannot tell what is
    testable. Either absence is a misconfiguration, not a preference."""
    err = options.model_preflight(_models(**present))
    assert err and all(m in err for m in missing)
    assert "cannot run without" in err


def test_the_optional_roles_may_simply_be_absent(monkeypatch):
    """`mapper` falls back to `classify`; `attacker` absent costs only the loop."""
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    assert options.model_preflight(_models(**_usable_pair())) is None


def test_a_declared_attacker_off_sdk_is_refused(monkeypatch):
    """Declared-and-unusable is a misconfiguration. The message says both ways out, so a
    reader is not left guessing which they wanted."""
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    err = options.model_preflight(_models(attacker=_cli(), **_usable_pair()))
    assert err and "must be via:sdk" in err
    assert "remove the role" in err


def test_a_missing_credential_is_reported_per_role(monkeypatch):
    for var in ("ANTHROPIC_SDK_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    err = options.model_preflight(_models(
        attacker={"id": "m", "via": "sdk"}, **_usable_pair()))
    assert err and "exploit_verification.attacker via:sdk" in err


def test_a_malformed_node_is_surfaced_not_swallowed():
    err = options.model_preflight(_models(judge={"via": "cli"},      # no `id`
                                          classify=_cli()))
    assert err and "not a usable model" in err


# ── `required`: the switch that makes verification mandatory ──────────────────

@pytest.mark.parametrize("switch,expected", [("true", True), ("auto", False),
                                             ("false", False)])
def test_required_reads_the_switch(switch, expected):
    assert options.required(_switch(switch)) is expected


# ── model_label: a progress line names the model, not the config block ────────

def test_model_label_names_the_model_for_a_node():
    """EV's stages receive the role NODE, so a log line that interpolates it directly
    printed `Config({'id': …, 'via': …})` — profile structure where a model name belongs.
    """
    assert options.model_label(Config({"id": "claude-sonnet-4-6", "via": "sdk"})) \
        == "claude-sonnet-4-6"


def test_model_label_passes_a_bare_id_through():
    assert options.model_label("claude-opus-4-8") == "claude-opus-4-8"


def test_model_label_never_raises_on_an_unusable_node():
    """A progress line must not be able to fail the stage it is describing."""
    assert options.model_label(SimpleNamespace(via="cli")) == "<unresolved model>"
    assert options.model_label(None) == "<unresolved model>"
