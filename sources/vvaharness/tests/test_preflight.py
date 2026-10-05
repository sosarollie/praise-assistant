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

"""Offline unit tests for the startup connectivity probe (check_backends).

A via:cli model that responds but whose reply exceeds the tiny preflight
max_tokens cap surfaces as an error, yet it is reachable — the probe must count
it as a pass. Genuine credential/connectivity failures must still fail. No real
network or subprocess: the probe call and model-role resolution are monkeypatched.
"""
import os
from types import SimpleNamespace

import pytest

from vvaharness.backends.llm.models import ResolvedModel
from vvaharness.backends.harness.models import TruncatedResponseError

import vvaharness.backends.llm.registry as llm
from vvaharness import orchestrator
from vvaharness.orchestrator import preflight as pf
from vvaharness.orchestrator.config_paths import _iter_model_roles

# _reachable_despite_token_cap — the decision helper

def test_reachable_despite_token_cap_matches_cli_message():
    msg = ("claude CLI failed: API Error: Claude's response exceeded the 4 "
           "output token maximum. To configure this behavior, set the "
           "CLAUDE_CODE_MAX_OUTPUT_TOKENS environment variable. (rc=1)")
    assert orchestrator._reachable_despite_token_cap(msg) is True


@pytest.mark.parametrize("msg", [
    "401 Invalid authentication credentials",
    "model_name 'x' is not a valid LLM model",
    "connection error: CERTIFICATE_VERIFY_FAILED",
    "",
    None,
])
def test_reachable_despite_token_cap_rejects_other_errors(msg):
    assert orchestrator._reachable_despite_token_cap(msg) is False


# check_backends — end-to-end probe classification

def _force_single_cli_role(monkeypatch):
    """Make check_backends see exactly one via:cli role, with `claude` on PATH,
    so the live probe is the only thing under test."""
    # check_backends/probe_backends live in the preflight submodule and resolve
    # these names through preflight's own bindings (confirmed via cartograph),
    # so patch them there.
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [("threatmodel", "model-node")])
    monkeypatch.setattr(orchestrator.preflight, "resolve_model",
                        lambda m: ResolvedModel("test-model", "cli", {}))
    monkeypatch.setattr(orchestrator.shutil, "which", lambda name: "/usr/bin/claude")
    # The live probe is what's under test here — present a gateway so the new
    # JWT-without-base_url fast-fail gate doesn't short-circuit before it.
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://test-gateway.example/")


def test_check_backends_token_cap_counts_as_reachable(monkeypatch):
    _force_single_cli_role(monkeypatch)

    def fake_probe(*a, **k):
        raise RuntimeError("claude CLI failed: API Error: Claude's response "
                           "exceeded the 4 output token maximum (rc=1)")

    monkeypatch.setattr(llm, "prompt", fake_probe)
    assert orchestrator.check_backends(cfg=object()) is True


def test_check_backends_sdk_truncation_counts_as_reachable(monkeypatch):
    _force_single_cli_role(monkeypatch)

    def fake_probe(*a, **k):
        raise TruncatedResponseError(
            "reply still hit the output-token budget after the doubled retry",
            stage="preflight", requested=4, retried=8,
        )

    monkeypatch.setattr(llm, "prompt", fake_probe)
    assert orchestrator.check_backends(cfg=object()) is True


# The probe's own output budget must not condemn a healthy model

def test_probe_requests_a_budget_a_normal_reply_cannot_exhaust(monkeypatch):
    # Assert on the value the backend actually receives, so the old inline
    # literal cannot creep back. 4 truncated every real reply.
    _force_single_cli_role(monkeypatch)
    seen: dict = {}

    def fake_probe(*a, **k):
        seen.update(k)
        return "pong"

    monkeypatch.setattr(llm, "prompt", fake_probe)
    assert orchestrator.check_backends(cfg=object()) is True
    assert seen["max_tokens"] == pf._PROBE_PING_MAX_TOKENS
    assert seen["max_tokens"] >= 64, (
        "a one-word reply plus a preamble must fit, and thinking tokens count "
        "against this budget on adaptive models")


def test_probe_makes_exactly_one_call_for_a_normal_reply(monkeypatch):
    # The doubled truncation retry billed a second call on every healthy sdk
    # probe. A reply that fits the budget must cost one round trip.
    _force_single_cli_role(monkeypatch)
    calls: list = []

    def fake_probe(*a, **k):
        calls.append(k.get("max_tokens"))
        return "pong"

    monkeypatch.setattr(llm, "prompt", fake_probe)
    assert orchestrator.check_backends(cfg=object()) is True
    assert calls == [pf._PROBE_PING_MAX_TOKENS]


def test_cache_probe_budget_matches_the_connectivity_probe(monkeypatch):
    # The cache-probe arm has no VVAH-E005 exemption, so a truncated reply
    # there is a hard FAILED from an HTTP 200. Same budget, same reason.
    assert pf._PROBE_MAX_TOKENS == pf._PROBE_PING_MAX_TOKENS


# _reachable_despite_truncated_reply — the named backstop

def test_reachable_despite_truncated_reply_matches_e005():
    e = TruncatedResponseError("cut off", stage="preflight", requested=4,
                               retried=8)
    assert orchestrator._reachable_despite_truncated_reply(e) is True


@pytest.mark.parametrize("exc", [
    RuntimeError("401 Invalid authentication credentials"),
    ValueError("model_name 'x' is not a valid LLM model"),
    OSError("connection error: CERTIFICATE_VERIFY_FAILED"),
])
def test_reachable_despite_truncated_reply_rejects_other_errors(exc):
    assert orchestrator._reachable_despite_truncated_reply(exc) is False


def test_agentic_probe_truncation_counts_as_reachable(monkeypatch):
    # The agentic handler carries the same exemption and had no coverage.
    _agentic_role(monkeypatch, "verify", "cli")

    def boom(*a, **k):
        raise TruncatedResponseError("cut off", stage="preflight-agentic",
                                     requested=4, retried=8)

    monkeypatch.setattr(llm, "agentic", boom)
    assert orchestrator.preflight.probe_backends(cfg=object()) is True


def test_check_backends_genuine_auth_error_still_fails(monkeypatch):
    _force_single_cli_role(monkeypatch)

    def fake_probe(*a, **k):
        raise RuntimeError("claude CLI failed: 401 Invalid authentication "
                           "credentials (rc=1)")

    monkeypatch.setattr(llm, "prompt", fake_probe)
    assert orchestrator.check_backends(cfg=object()) is False


# LangSmith tracing egress warning — surfaced at scan preflight too, because
# the scan is where the egress actually happens. Warning-only: it must never
# flip the preflight result or mutate os.environ (S10/S11 share this process
# environment).

_TRACING_ENVS = ("LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING_V2",
                 "LANGSMITH_TRACING", "LANGCHAIN_TRACING",
                 "LANGSMITH_API_KEY", "LANGCHAIN_API_KEY")


def _clear_tracing(monkeypatch):
    for v in _TRACING_ENVS:
        monkeypatch.delenv(v, raising=False)


def test_check_backends_warns_on_langsmith_tracing(monkeypatch, capsys):
    _force_single_cli_role(monkeypatch)
    _clear_tracing(monkeypatch)
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    monkeypatch.setenv("LANGSMITH_API_KEY", "lsv2_pt_supersecretvalue123")
    monkeypatch.setattr(llm, "prompt", lambda *a, **k: "ok")
    # Warning-only: preflight still passes, and os.environ is untouched.
    assert orchestrator.check_backends(cfg=object()) is True
    assert os.environ.get("LANGSMITH_TRACING") == "true"
    err = capsys.readouterr().err
    assert "WARN" in err
    assert "LANGSMITH_TRACING" in err
    assert "repository source" in err
    assert "supersecret" not in err        # presence only, never the key


def test_check_backends_quiet_without_langsmith_tracing(monkeypatch, capsys):
    _force_single_cli_role(monkeypatch)
    _clear_tracing(monkeypatch)
    monkeypatch.setattr(llm, "prompt", lambda *a, **k: "ok")
    assert orchestrator.check_backends(cfg=object()) is True
    assert "LangSmith" not in capsys.readouterr().err


def test_configure_backends_resolves_ca_cert(monkeypatch, tmp_path):
    """Regression: configure_backends resolves sdk/openai/cli ca_cert via
    _resolve_against (which moved to config_paths during the orchestrator
    split). A missing import previously raised NameError on the ca_cert branch
    when a profile set sdk.ca_cert (e.g. switching to an Opus SDK model behind
    a gateway). Exercises that exact path."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import preflight as pf
    captured = {}
    monkeypatch.setattr(pf.sdk, "configure", lambda **kw: captured.update(kw))
    monkeypatch.setattr(pf.oai, "configure", lambda **kw: None)
    monkeypatch.setattr(pf.cli, "configure", lambda **kw: None)
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("models:\n  deepdive: {id: x, via: sdk}\n"
                        "sdk:\n  ca_cert: certs/ca.pem\n", encoding="utf-8")
    cfg = config_mod.load(cfg_file)
    pf.configure_backends(cfg, tmp_path)              # must not raise NameError
    assert captured["ca_cert"] == str(tmp_path / "certs" / "ca.pem")

def test_prompt_probe_relaxes_the_degenerate_response_floors(monkeypatch, capsys):
    """A 4-token pong must not trip VVAH-E003, but an empty reply still must.

    The probe asks for ``max_tokens=4``, so its valid answer is ~5 chars — far
    under the global floors (150 chars / 30 tokens) that are sized for report
    prose. Those floors are keyed off the ``tag``, so every scan used to open
    with "degenerate response (1/3 consecutive)" warnings about a probe behaving
    exactly as designed, printed above the credential summary an operator is
    meant to read. The floors are checked inside the backend, which these tests
    stub out, so this asserts the behaviour through the same public entry point
    the backend uses rather than reaching into module state.
    """
    from vvaharness.util.response_quality import check_response_quality

    seen: list[str] = []

    def fake_prompt(*a, **k):
        tag = k.get("tag", "")
        # Exactly what the sdk/openai backends do with a successful reply.
        check_response_quality("pong", stage=tag, output_tokens=4)
        seen.append(tag)
        return "pong"

    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [("deepdive", "model-node")])
    monkeypatch.setattr(orchestrator.preflight, "resolve_model",
                        lambda m: ResolvedModel("test-model", "sdk", {}))
    monkeypatch.setattr(llm, "prompt", fake_prompt)

    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert seen == ["preflight"], "the probe must still tag itself 'preflight'"
    # The observable IS the warning. A failed floor only warns on the first two
    # calls, so probe_backends() returns True either way — asserting on its
    # return value alone would pass with the floors unrelaxed (it did).
    assert "VVAH-E003" not in capsys.readouterr().err, (
        "the connectivity probe warned about its own 4-token reply"
    )

    # Red-proof the relaxation: it must be a floor of 1, not a disabled check.
    # An earlier version of this block built its OWN
    # stage_floors("preflight", 1, 1) scope and drove check_response_quality
    # through that hand-built copy — which kept passing when the production
    # wrapper in preflight.py was mutated to min_chars=0/min_tokens=0 (a floor
    # of 0 makes `len(stripped) < 0` and `output_tokens < 0` unsatisfiable,
    # silently disabling the check for the probe entirely). So this drives
    # probe_backends() again with a backend whose reply is NOTHING: the only
    # floors in force are the ones the production `with stage_floors(...)`
    # actually installs, and under 1/1 the empty reply must warn where 0/0
    # would stay silent. The warning on stderr is the observable — the gate
    # only warns on the first failures, so probe_backends() still returns
    # True either way and its return value can never witness the floor.
    def empty_prompt(*a, **k):
        # Same call shape the sdk/openai backends use for a genuinely empty
        # 200-OK reply.
        check_response_quality("", stage=k.get("tag", ""), output_tokens=0)
        return ""

    monkeypatch.setattr(llm, "prompt", empty_prompt)
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert "VVAH-E003" in capsys.readouterr().err, (
        "an empty probe reply sailed through — the production floor is "
        "disabled, not relaxed"
    )


def test_agentic_probe_relaxes_the_degenerate_response_floors(monkeypatch, capsys):
    """The agentic smoke probe's valid reply ("ok") must not trip VVAH-E003,
    but an empty reply still must — through the production wrapper.

    Of the two dispatches in _probe_agentic_roles only the deepagents one
    reaches the quality gate (deepagents.agentic checks its final text;
    sdk/openai/cli agentic() never call the gate), so that is the branch this
    drives. Both assertions run through the real probe_backends(): the only
    floors in force are whatever the production `with stage_floors(...)`
    installs for the "preflight-agentic" tag, so a wrapper mutated to 0/0
    (check disabled) or deleted (150/30 defaults back, warning on "ok")
    each fail one half of this test. The stderr warning is the observable —
    the gate warns without raising on a first failure, so probe_backends()
    returns True either way.
    """
    from vvaharness.backends.llm import deepagents as deep_backend
    from vvaharness.util.response_quality import check_response_quality

    monkeypatch.setattr(
        orchestrator.preflight, "_iter_model_roles",
        lambda cfg: [("preprocess",
                      SimpleNamespace(id="claude-x", via="deepagents"))],
    )

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            return SimpleNamespace(is_error=False, subtype="success")

    # The prompt-connectivity probe for the same target rides the harness
    # one-shot; it is not under test here, so it just succeeds.
    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    seen: list[str] = []

    def ok_agentic(*a, **k):
        # Exactly what deepagents.agentic does with its final text — the one
        # agentic path that calls the gate at all.
        check_response_quality("ok", stage=k.get("tag", ""), output_tokens=1)
        seen.append(k.get("tag", ""))
        return "ok"

    monkeypatch.setattr(deep_backend, "agentic", ok_agentic)
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert seen == ["preflight-agentic"], (
        "the probe must still tag itself 'preflight-agentic' — the floor "
        "override is keyed on that exact tag")
    assert "VVAH-E003" not in capsys.readouterr().err, (
        "the agentic smoke probe warned about its own one-word reply")

    def empty_agentic(*a, **k):
        check_response_quality("", stage=k.get("tag", ""), output_tokens=0)
        return ""

    monkeypatch.setattr(deep_backend, "agentic", empty_agentic)
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert "VVAH-E003" in capsys.readouterr().err, (
        "an empty agentic probe reply sailed through — the production floor "
        "is disabled, not relaxed")


def test_cache_probe_relaxes_the_degenerate_response_floors(monkeypatch, capsys):
    """The cache probe's valid reply ("PONG", under a 16-token cap) must not
    trip VVAH-E003, but an empty reply still must — through the production
    wrapper in _call_and_diff, the one production frame every cache-probe
    call goes through. Same two-sided contract as the connectivity-probe
    test above: a wrapper mutated to 0/0 fails the empty half, a deleted
    wrapper (150/30 defaults back) fails the PONG half.
    """
    from vvaharness.util.response_quality import check_response_quality

    seen: list[str] = []

    def pong_prompt(*a, **k):
        # Exactly what the sdk/openai backends do with a successful reply.
        check_response_quality("PONG", stage=k.get("tag", ""), output_tokens=2)
        seen.append(k.get("tag", ""))
        return "PONG"

    monkeypatch.setattr(llm, "prompt", pong_prompt)
    pf._call_and_diff(model=SimpleNamespace(id="m", via="sdk"),
                      system_prompt="s", user_prompt="u",
                      thinking_budget=None, phase_label="cache-floor-test-a")
    assert seen == ["cache-probe"], (
        "the probe must still tag itself 'cache-probe' — the floor override "
        "is keyed on that exact tag")
    assert "VVAH-E003" not in capsys.readouterr().err, (
        "the cache probe warned about its own one-word reply")

    def empty_prompt(*a, **k):
        check_response_quality("", stage=k.get("tag", ""), output_tokens=0)
        return ""

    monkeypatch.setattr(llm, "prompt", empty_prompt)
    pf._call_and_diff(model=SimpleNamespace(id="m", via="sdk"),
                      system_prompt="s", user_prompt="u",
                      thinking_budget=None, phase_label="cache-floor-test-b")
    assert "VVAH-E003" in capsys.readouterr().err, (
        "an empty cache-probe reply sailed through — the production floor "
        "is disabled, not relaxed")


def _agentic_role(monkeypatch, role, via):
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [(role, "model-node")])
    monkeypatch.setattr(orchestrator.preflight, "resolve_model",
                        lambda m: ResolvedModel("test-model", via, {}))
    monkeypatch.setattr(llm, "prompt", lambda *a, **k: "ok")


def test_agentic_probe_raise_fails_preflight(monkeypatch):
    _agentic_role(monkeypatch, "preprocess", "sdk")

    def boom(*a, **k):
        raise NotImplementedError("Bash tool not supported by sdk backend")

    monkeypatch.setattr(llm, "agentic", boom)
    assert orchestrator.preflight.probe_backends(cfg=object()) is False


def test_agentic_probe_empty_reply_is_not_failure(monkeypatch):
    _agentic_role(monkeypatch, "verify", "cli")
    monkeypatch.setattr(llm, "agentic", lambda *a, **k: "")  # tool_use-only turn
    assert orchestrator.preflight.probe_backends(cfg=object()) is True


def test_agentic_probe_skips_prompt_only_roles(monkeypatch):
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [("threatmodel", "m"), ("decompose", "m")])
    monkeypatch.setattr(orchestrator.preflight, "resolve_model",
                        lambda m: ResolvedModel("test-model", "sdk", {}))
    monkeypatch.setattr(llm, "prompt", lambda *a, **k: "ok")
    calls = {"n": 0}

    def rec(*a, **k):
        calls["n"] += 1
        return "ok"

    monkeypatch.setattr(llm, "agentic", rec)
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert calls["n"] == 0  # agentic() never probed for prompt-only roles


# Every via:deepagents role — detection and post-scan alike — dispatches
# through the harness (the registry never routes deepagents), so the harness
# one-shot is the single seam the probe exercises for all of them.


def test_deepagents_post_scan_role_uses_hoisted_harness_probe(monkeypatch):
    from vvaharness.backends.llm import deepagents as deep_backend

    monkeypatch.setattr(
        orchestrator.preflight, "_iter_model_roles",
        lambda cfg: [("remediate", SimpleNamespace(id="gpt-5.5", via="deepagents"))],
    )
    monkeypatch.setattr(
        orchestrator.preflight, "resolve_model",
        lambda model: ResolvedModel("gpt-5.5", "deepagents", {}),
    )
    monkeypatch.setattr(
        llm, "prompt",
        lambda *args, **kwargs: pytest.fail("legacy dispatcher was called"),
    )
    captured = {}

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            captured["prompt"] = prompt
            captured["options"] = options
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert captured["options"].model == "gpt-5.5"
    assert captured["options"].allow_writes is False


def test_deepagents_harness_probe_forwards_provider(monkeypatch):
    """A role with an explicit provider must be probed against that vendor —
    the harness probe used to omit model_provider entirely."""
    from vvaharness.backends.llm import deepagents as deep_backend

    node = SimpleNamespace(id="gpt-5.5", via="deepagents", provider="openai")
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [("validate", node)])
    captured = {}

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            captured["options"] = options
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert captured["options"].model_provider == "openai"


def test_deepagents_harness_probe_env_carries_profile_tls(monkeypatch, tmp_path):
    """cfg.sdk TLS material reaches the harness probe's env, paths resolved.

    This is the DETECTION-seam env (include_tls defaults to True): detection
    deepagents roles run with build_harness_env's credentials + TLS carriers,
    so the probe would fail (or falsely pass) a private-CA/mTLS config
    relative to the real run without them. Relative cert paths must resolve
    against the config directory, exactly as configure_backends resolves them
    for via: sdk/openai.
    """
    from vvaharness.backends.llm import deepagents as deep_backend

    captured = {}

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            captured["options"] = options
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    cert = tmp_path / "client.pem"
    cert.write_text("placeholder", encoding="utf-8")
    cfg = SimpleNamespace(
        sdk=SimpleNamespace(
            ca_cert="certs/ca.pem", client_cert=str(cert), verify_ssl=True),
        openai=None,
        _data={"_config_dir": str(tmp_path)},
    )
    orchestrator.preflight._probe_deepagents_harness(cfg, "claude-x", "anthropic")
    env = captured["options"].env
    assert env["VVAHARNESS_TLS_CLIENT_CERT"] == str(cert)
    assert env["SSL_CERT_FILE"] == str(tmp_path / "certs" / "ca.pem")
    assert "VVAHARNESS_TLS_VERIFY" not in env  # verify_ssl: true is the default


def test_deepagents_harness_probe_env_unchanged_without_tls_config(monkeypatch):
    """No TLS keys on the block → the probe env gains no TLS carriers (S10/S11
    regression guard: the no-TLS path stays byte-identical)."""
    from vvaharness.backends.llm import deepagents as deep_backend

    captured = {}

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            captured["options"] = options
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    cfg = SimpleNamespace(sdk=SimpleNamespace(base_url="https://gw.example/"),
                          openai=None)
    orchestrator.preflight._probe_deepagents_harness(cfg, "claude-x", "anthropic")
    env = captured["options"].env
    assert "VVAHARNESS_TLS_CLIENT_CERT" not in env
    assert "VVAHARNESS_TLS_VERIFY" not in env


def test_deepagents_harness_probe_routes_through_llm_run_oneshot(monkeypatch):
    """The probe rides llm.deepagents.run_oneshot — the persistent-loop bridge —
    so the model cache it primes belongs to the loop the scan then uses, not a
    throwaway asyncio.run loop."""
    from vvaharness.backends.llm import deepagents as deep_backend

    captured = {}

    def fake_run_oneshot(prompt, options):
        captured["prompt"] = prompt
        captured["options"] = options
        return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "run_oneshot", fake_run_oneshot)
    cfg = SimpleNamespace(sdk=None, openai=None)
    orchestrator.preflight._probe_deepagents_harness(cfg, "claude-x", "anthropic")
    assert captured["options"].model == "claude-x"
    assert captured["options"].model_provider == "anthropic"


def test_deepagents_harness_probe_honors_cache_markers_kill_switch(monkeypatch):
    """`sdk: {cache_markers: off}` must reach the connectivity probe's options:
    on a marker-rejecting gateway the probe would otherwise block the very scan
    the kill switch exists to enable."""
    from vvaharness.backends.llm import deepagents as deep_backend  # noqa: PLC0415

    captured = {}

    def fake_run_oneshot(_prompt, options):
        captured["options"] = options
        return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "run_oneshot", fake_run_oneshot)
    cfg = SimpleNamespace(sdk=SimpleNamespace(cache_markers="off"), openai=None)
    orchestrator.preflight._probe_deepagents_harness(cfg, "claude-x", "anthropic")
    assert captured["options"].cache_markers is False

    cfg_default = SimpleNamespace(sdk=None, openai=None)
    orchestrator.preflight._probe_deepagents_harness(
        cfg_default, "claude-x", "anthropic")
    assert captured["options"].cache_markers is True


def _tls_probe_setup(monkeypatch, tmp_path, role):
    """One deepagents *role* on an mTLS profile (cfg.sdk.client_cert set),
    with the harness faked so probe_backends' env choice is what's under
    test. Returns the captured-options dict."""
    from vvaharness.backends.llm import deepagents as deep_backend

    captured = {}

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            captured["options"] = options
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)  # keep ambient env out
    cert = tmp_path / "client.pem"
    cert.write_text("placeholder", encoding="utf-8")
    node = SimpleNamespace(id="claude-x", via="deepagents", provider="anthropic")
    cfg = SimpleNamespace(
        sdk=SimpleNamespace(client_cert=str(cert), ca_cert=None, verify_ssl=True),
        openai=None,
        _data={"_config_dir": str(tmp_path)},
    )
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda _cfg: [(role, node)])
    return cfg, captured, str(cert)


def test_deepagents_post_scan_only_target_probes_credentials_only(
        monkeypatch, tmp_path):
    """The S10/S11 plugin_runner builds its env from credential_env_overrides
    alone — no TLS carriers — so a post-scan-only deepagents target must be
    probed the same way even when cfg.sdk.client_cert is set: probing with a
    client certificate the real run will not send would pass an mTLS profile
    that then fails at S10."""
    cfg, captured, _cert = _tls_probe_setup(monkeypatch, tmp_path, "remediate")
    assert orchestrator.preflight.probe_backends(cfg) is True
    env = captured["options"].env
    assert "VVAHARNESS_TLS_CLIENT_CERT" not in env
    assert "SSL_CERT_FILE" not in env


def test_deepagents_detection_target_probes_with_profile_tls(
        monkeypatch, tmp_path):
    """A detection deepagents role runs with build_harness_env (credentials +
    TLS carriers), so its probe env must carry the profile's TLS material."""
    cfg, captured, cert = _tls_probe_setup(monkeypatch, tmp_path, "threatmodel")
    assert orchestrator.preflight.probe_backends(cfg) is True
    assert captured["options"].env["VVAHARNESS_TLS_CLIENT_CERT"] == cert


def test_deepagents_detection_role_probes_via_harness(monkeypatch):
    """Detection roles on via:deepagents are probed through the harness
    one-shot — the seam a real scan uses — never through registry.prompt(),
    which no longer routes deepagents at all."""
    from vvaharness.backends.llm import deepagents as deep_backend

    node = SimpleNamespace(id="claude-x", via="deepagents")
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [("threatmodel", node)])
    monkeypatch.setattr(
        llm, "prompt",
        lambda *a, **k: pytest.fail("legacy dispatcher was called"))
    probed = []

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            probed.append(options.model)
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert probed == ["claude-x"]


def test_probe_covers_every_deepagents_role_via_harness(monkeypatch):
    """Every widened role passes the probe gate, and each one is probed
    through the harness one-shot — there is exactly ONE deepagents route now,
    so registry.prompt() must never see a deepagents model."""
    from vvaharness.backends.llm import deepagents as deep_backend

    roles = [(r, SimpleNamespace(id=f"m-{r}", via="deepagents"))
             for r in sorted(llm.DEEPAGENTS_ROLES)]
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: roles)
    harnessed = []

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            harnessed.append(options.model)
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    monkeypatch.setattr(
        llm, "prompt",
        lambda *a, **k: pytest.fail("legacy dispatcher was called"))
    # preprocess is agentic: its smoke probe goes through the wrapper, which
    # is not under test here (test_deepagents_preprocess_admitted_... is).
    monkeypatch.setattr(deep_backend, "agentic", lambda *a, **k: "ok")
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert set(harnessed) == {f"m-{r}" for r in llm.DEEPAGENTS_ROLES}


def test_probe_dedup_key_separates_providers(monkeypatch):
    """Two roles sharing a model id but naming different providers must be
    probed separately — the old (model_id, via) key collapsed them and let the
    untested provider pass silently."""
    from vvaharness.backends.llm import deepagents as deep_backend

    roles = [
        ("threatmodel",
         SimpleNamespace(id="m1", via="deepagents", provider="anthropic")),
        ("decompose",
         SimpleNamespace(id="m1", via="deepagents", provider="openai")),
    ]
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: roles)
    seen = []

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            seen.append(options.model_provider)
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert sorted(seen) == ["anthropic", "openai"]


@pytest.mark.parametrize("role", ["nonexistent-role"])
def test_deepagents_is_rejected_for_excluded_roles(role, monkeypatch, capsys):
    monkeypatch.setattr(
        orchestrator.preflight, "_iter_model_roles",
        lambda cfg: [(role, SimpleNamespace(id="gpt-5.5", via="deepagents"))],
    )
    assert orchestrator.preflight.probe_backends(cfg=object()) is False
    assert f"unsupported role(s): {role}" in capsys.readouterr().err


def test_deepagents_roles_is_wider_than_post_scan_roles():
    """A future change must never widen POST_SCAN_ROLES (fatal-vs-WARN) when
    it means to widen DEEPAGENTS_ROLES (the via gate) — they are not the same
    concept, and detection failures must stay fatal."""
    assert llm.DEEPAGENTS_ROLES != llm.POST_SCAN_ROLES
    assert llm.POST_SCAN_ROLES < llm.DEEPAGENTS_ROLES
    # Membership pin, not just a subset check: a widening to e.g.
    # {"remediate", "validate", "dedup"} satisfies the two asserts above while
    # silently downgrading a dedup probe failure from fatal to WARN — exactly
    # the silently-incomplete-scan outcome the constant exists to prevent.
    # Adding a role here is a deliberate act; update this set with it.
    assert llm.POST_SCAN_ROLES == frozenset({"remediate", "validate"})


def test_deepagents_preprocess_admitted_and_probed_via_wrapper(monkeypatch):
    """A deepagents preprocess role passes the gate, and its agentic smoke
    probe routes through the deepagents wrapper — the exact streaming path S1
    uses — never through the legacy dispatcher."""
    from vvaharness.backends.llm import deepagents as deep_backend

    monkeypatch.setattr(
        orchestrator.preflight, "_iter_model_roles",
        lambda cfg: [("preprocess", SimpleNamespace(id="claude-x", via="deepagents"))],
    )
    monkeypatch.setattr(
        orchestrator.preflight, "resolve_model",
        lambda model: ResolvedModel("claude-x", "deepagents", {}),
    )
    monkeypatch.setattr(
        llm, "agentic",
        lambda *a, **k: pytest.fail("legacy dispatcher was called"),
    )

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    captured = {}
    monkeypatch.setattr(
        deep_backend, "agentic", lambda *a, **k: captured.update(k) or "ok"
    )

    assert orchestrator.preflight.probe_backends(cfg=object()) is True
    assert captured["max_turns"] == 1
    assert captured["tag"] == "preflight-agentic"


def test_deepagents_autoexclude_admitted_without_agentic_probe(monkeypatch):
    from vvaharness.backends.llm import deepagents as deep_backend

    monkeypatch.setattr(
        orchestrator.preflight, "_iter_model_roles",
        lambda cfg: [("autoexclude", SimpleNamespace(id="claude-x", via="deepagents"))],
    )
    monkeypatch.setattr(
        orchestrator.preflight, "resolve_model",
        lambda model: ResolvedModel("claude-x", "deepagents", {}),
    )
    monkeypatch.setattr(
        deep_backend, "agentic",
        lambda *a, **k: pytest.fail("autoexclude is not an agentic role"),
    )

    class FakeHarness:
        async def run_oneshot(self, prompt, options):
            return SimpleNamespace(is_error=False, subtype="success")

    monkeypatch.setattr(deep_backend, "get_harness", lambda via: FakeHarness())
    assert orchestrator.preflight.probe_backends(cfg=object()) is True


# Credential-gap classification — post-scan roles degrade, detection roles abort
# S10/S11 are individually opt-in and run after detection finishes, so a missing
# credential for one of them must not stop S1-S9 from running: preflight WARNs and
# the scan's own [s10]/[s11] gates skip the stage. A credential shared with any
# detection role stays fatal — a scan that cannot detect must not start.


def _roles_on(monkeypatch, roles, via):
    """Present exactly *roles*, all resolving to *via*, and neutralize the probe so
    only the credential classification is under test."""
    monkeypatch.setattr(
        pf, "_iter_model_roles",
        lambda _cfg: [(r, SimpleNamespace(id="test-model", via=via)) for r in roles])
    monkeypatch.setattr(pf, "resolve_model",
                        lambda _m: ResolvedModel("test-model", via, {}))
    monkeypatch.setattr(pf, "probe_backends", lambda _cfg: True)
    # Present a gateway so the JWT-without-base_url fast-fail can't short-circuit.
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://test-gateway.example/")


def test_post_scan_only_cli_gap_warns_and_continues(monkeypatch, capsys):
    _roles_on(monkeypatch, ["validate"], "cli")
    monkeypatch.setattr(orchestrator.shutil, "which", lambda _name: None)

    assert orchestrator.check_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert "WARN" in err and "will be skipped" in err
    assert "ERROR" not in err


def test_detection_role_cli_gap_still_aborts(monkeypatch, capsys):
    _roles_on(monkeypatch, ["deepdive"], "cli")
    monkeypatch.setattr(orchestrator.shutil, "which", lambda _name: None)

    assert orchestrator.check_backends(cfg=object()) is False
    assert "ERROR: `claude` CLI not found" in capsys.readouterr().err


def test_gap_shared_with_detection_role_stays_fatal(monkeypatch, capsys):
    """One credential, two consumers: the detection role decides."""
    _roles_on(monkeypatch, ["deepdive", "validate"], "cli")
    monkeypatch.setattr(orchestrator.shutil, "which", lambda _name: None)

    assert orchestrator.check_backends(cfg=object()) is False
    assert "ERROR: `claude` CLI not found" in capsys.readouterr().err


def test_post_scan_deepagents_gap_warns_and_continues(monkeypatch, capsys):
    from vvaharness.util import environment

    _roles_on(monkeypatch, ["remediate", "validate"], "deepagents")
    monkeypatch.setattr(environment, "_backend_credential_ok",
                        lambda *_a, **_k: (False, "OPENAI_API_KEY not set"))

    assert orchestrator.check_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert "WARN: DeepAgents test-model: OPENAI_API_KEY not set" in err
    assert "remediate, validate" in err
    assert "ERROR" not in err


def test_detection_deepagents_credential_gap_is_fatal(monkeypatch, capsys):
    """The twin of the cli test above and the complement of the post-scan WARN:
    a credential gap on a DETECTION deepagents role must abort the run."""
    from vvaharness.util import environment

    _roles_on(monkeypatch, ["threatmodel"], "deepagents")
    monkeypatch.setattr(
        environment, "_backend_credential_ok",
        lambda *_a, **_k: (False, "ANTHROPIC_API_KEY or "
                                  "ANTHROPIC_AUTH_TOKEN not set"))

    assert orchestrator.check_backends(cfg=object()) is False
    err = capsys.readouterr().err
    assert "ERROR: DeepAgents test-model" in err
    assert "will be skipped" not in err


def test_all_deepagents_roles_pass_check_backends_gate(monkeypatch, capsys):
    """Every widened role is accepted by the check_backends via gate."""
    from vvaharness.util import environment

    _roles_on(monkeypatch, sorted(llm.DEEPAGENTS_ROLES), "deepagents")
    monkeypatch.setattr(environment, "_backend_credential_ok",
                        lambda *_a, **_k: (True, "credential present"))

    assert orchestrator.check_backends(cfg=object()) is True
    assert "ERROR" not in capsys.readouterr().err


@pytest.mark.parametrize("role", ["nonexistent-role"])
def test_excluded_role_rejected_by_check_backends_gate(role, monkeypatch, capsys):
    """A role outside DEEPAGENTS_ROLES (every shipped role is now admitted,
    so a synthetic one stands in) must stay fail-closed. The message literal
    is derived from DEEPAGENTS_ROLES, so assert its stable prefix plus the
    offending role rather than a frozen copy of the membership list."""
    from vvaharness.util import environment

    _roles_on(monkeypatch, [role], "deepagents")
    monkeypatch.setattr(environment, "_backend_credential_ok",
                        lambda *_a, **_k: (True, "credential present"))

    assert orchestrator.check_backends(cfg=object()) is False
    err = capsys.readouterr().err
    assert "ERROR: via:deepagents is supported only for" in err
    assert f"invalid role(s): {role}" in err


# sdk_sole — one Anthropic credential may serve sdk and deepagents; only cli
# (gateway JWT) forces distinct credentials. Tested at BOTH computation sites
# (configure_backends and check_backends) so scan and doctor cannot disagree.


def _mixed_roles(monkeypatch, roles):
    """Present *roles* as (name, id, via) triples through the real resolver."""
    nodes = [(r, SimpleNamespace(id=i, via=v)) for r, i, v in roles]
    monkeypatch.setattr(pf, "_iter_model_roles", lambda _cfg: nodes)
    monkeypatch.setattr(pf, "probe_backends", lambda _cfg: True)
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://test-gateway.example/")


def _one_anthropic_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_SDK_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-shared")


def test_sdk_key_fallback_kept_when_deepagents_shares_the_run(monkeypatch, capsys):
    """{sdk, deepagents} keeps the ANTHROPIC_API_KEY fallback: adding a
    deepagents role must not force a second env name for one credential."""
    _mixed_roles(monkeypatch, [("deepdive", "claude-a", "sdk"),
                               ("threatmodel", "claude-b", "deepagents")])
    _one_anthropic_key(monkeypatch)

    assert orchestrator.check_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert "fallback" in err
    assert "ERROR" not in err


def test_sdk_key_fallback_still_refused_with_cli(monkeypatch, capsys):
    """{sdk, cli} still refuses the fallback: the CLI's token is a gateway JWT
    and each backend must keep its own credential."""
    _mixed_roles(monkeypatch, [("deepdive", "claude-a", "sdk"),
                               ("verify", "claude-b", "cli")])
    _one_anthropic_key(monkeypatch)
    monkeypatch.setattr(orchestrator.shutil, "which",
                        lambda _name: "/usr/bin/claude")

    assert orchestrator.check_backends(cfg=object()) is False
    assert "ANTHROPIC_SDK_API_KEY not set" in capsys.readouterr().err


def _stub_backend_configures(monkeypatch):
    captured = {}
    monkeypatch.setattr(pf.sdk, "configure", lambda **kw: captured.update(kw))
    monkeypatch.setattr(pf.oai, "configure", lambda **kw: None)
    monkeypatch.setattr(pf.cli, "configure", lambda **kw: None)
    return captured


def _load_cfg(tmp_path, text):
    from vvaharness import config as config_mod
    p = tmp_path / "c.yaml"
    p.write_text(text, encoding="utf-8")
    return config_mod.load(p)


def test_configure_backends_fallback_flag_with_deepagents(monkeypatch, tmp_path):
    """Site 2 of the sdk_sole predicate: configure_backends must hand the sdk
    client allow_api_key_fallback=True for a {sdk, deepagents} profile."""
    captured = _stub_backend_configures(monkeypatch)
    cfg = _load_cfg(tmp_path,
                    "models:\n"
                    "  deepdive: {id: claude-a, via: sdk}\n"
                    "  threatmodel: {id: claude-b, via: deepagents}\n"
                    "sdk:\n  base_url: https://gw.example/\n")
    pf.configure_backends(cfg, tmp_path)
    assert captured["allow_api_key_fallback"] is True


def test_configure_backends_fallback_flag_refused_with_cli(monkeypatch, tmp_path):
    captured = _stub_backend_configures(monkeypatch)
    cfg = _load_cfg(tmp_path,
                    "models:\n"
                    "  deepdive: {id: claude-a, via: sdk}\n"
                    "  verify: {id: claude-b, via: cli}\n"
                    "sdk:\n  base_url: https://gw.example/\n")
    pf.configure_backends(cfg, tmp_path)
    assert captured["allow_api_key_fallback"] is False


# graph_annotate — visible to preflight only when step0.callgraph_detection
# selects the LLM annotator; in rules mode (taint.yaml's shipped shape) its
# model is never called at runtime, so probing it would fatally fail a config
# that scans fine today (§14.5 guard).

_TAINT_SHAPE = (
    "models:\n"
    "  graph_annotate: {id: annotate-model, via: sdk}\n"
    "  deepdive: {id: scan-model, via: sdk}\n"
    "step0:\n  callgraph_detection: rules\n"
)


def test_graph_annotate_not_probed_in_rules_mode(monkeypatch, tmp_path):
    """Regression built from taint.yaml's actual shape (graph_annotate via:sdk
    with callgraph_detection: rules): preflight must NOT probe — and therefore
    must not fail on — the dead annotator model."""
    cfg = _load_cfg(tmp_path, _TAINT_SHAPE)
    probed = []

    def fake_prompt(_p, *, model, **_k):
        probed.append(model.id)
        if model.id == "annotate-model":
            raise RuntimeError("unreachable")
        return "ok"

    monkeypatch.setattr(llm, "prompt", fake_prompt)
    assert pf.probe_backends(cfg) is True
    assert probed == ["scan-model"]


def test_graph_annotate_probed_and_fatal_in_llm_mode(monkeypatch, tmp_path):
    """With callgraph_detection: llm the annotator model IS probed, and being
    a detection role its unreachability is fatal."""
    cfg = _load_cfg(tmp_path, _TAINT_SHAPE.replace("rules", "llm"))
    probed = []

    def fake_prompt(_p, *, model, **_k):
        probed.append(model.id)
        if model.id == "annotate-model":
            raise RuntimeError("unreachable")
        return "ok"

    monkeypatch.setattr(llm, "prompt", fake_prompt)
    assert pf.probe_backends(cfg) is False
    assert "annotate-model" in probed


def test_probe_failure_on_post_scan_role_only_warns(monkeypatch, capsys):
    """An unreachable model that only S10/S11 use degrades that stage, not the scan."""
    monkeypatch.setattr(
        pf, "_iter_model_roles",
        lambda _cfg: [("validate", SimpleNamespace(id="test-model", via="sdk"))])
    monkeypatch.setattr(pf, "resolve_model",
                        lambda _m: ResolvedModel("test-model", "sdk", {}))

    def boom(*_a, **_k):
        raise RuntimeError("401 Invalid authentication credentials")

    monkeypatch.setattr(llm, "prompt", boom)
    assert pf.probe_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert "WARN" in err and "will be skipped" in err
    assert "FAILED" not in err
    # The closing summary must not contradict the WARN above it: an operator (or a
    # log scraper) reading only the summary would otherwise conclude every backend
    # was reachable when one was just reported unreachable.
    assert "all model backends reachable" not in err
    assert "detection backends reachable ✓" in err and "validate unreachable" in err


def test_probe_summary_says_all_reachable_when_nothing_skipped(monkeypatch, capsys):
    """The unqualified summary survives for a fully clean probe (guards the branch
    order in probe_backends: a skipped-stage summary must not swallow this one)."""
    monkeypatch.setattr(
        pf, "_iter_model_roles",
        lambda _cfg: [("deepdive", SimpleNamespace(id="test-model", via="sdk"))])
    monkeypatch.setattr(pf, "resolve_model",
                        lambda _m: ResolvedModel("test-model", "sdk", {}))
    monkeypatch.setattr(llm, "prompt", lambda *_a, **_k: "ok")

    assert pf.probe_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert "all model backends reachable ✓" in err
    assert "WARN" not in err


# ── Probe/stage tool-set identity ────────────────────────────────────────────
# The probe's contract is that it sends EXACTLY the tool set the stage will
# compute; both sides now call the shared validate_detection_tools derivation.
# These tests assert equality against the STAGE'S OWN computation — never a
# second hardcoded copy of the expected list, because a duplicated literal in
# the probe has already drifted once (it kept sending Bash for preprocess
# after S1 moved to the shared read-only derivation).


def _stage_tools(cfg, role):
    """What the corresponding STAGE would compute — replicated from the
    stage's own inline call (s1_preprocess.run, s6_verify.run, and
    s2_threatmodel._threatmodel_call all make exactly this call)."""
    from vvaharness.backends.llm.models import validate_detection_tools
    if role == "preprocess":
        return validate_detection_tools(
            getattr(cfg.step1, "allowed_tools", None),
            config_key="step1.allowed_tools",
            via=llm.resolve(cfg.models.preprocess).via)
    if role == "verify":
        return validate_detection_tools(
            getattr(cfg.step6_verify, "allowed_tools", None),
            config_key="step6_verify.allowed_tools",
            via=llm.resolve(cfg.models.verify).via)
    if role == "threatmodel":
        return validate_detection_tools(
            getattr(getattr(cfg, "step2", None), "allowed_tools", None),
            config_key="step2.allowed_tools",
            via=llm.resolve(cfg.models.threatmodel).via)
    raise AssertionError(f"not an agentic role: {role}")


_MINIMAL_AGENTIC_YAML = (
    "models:\n"
    "  preprocess: {id: m-pre, via: sdk}\n"
    "  verify: {id: m-ver, via: sdk}\n"
    "  threatmodel: {id: m-tm, via: sdk}\n"
    "step2:\n  agentic: true\n"
)


@pytest.mark.parametrize("role", ["preprocess", "verify", "threatmodel"])
def test_probe_tools_equal_stage_tools_without_allowed_tools(role, tmp_path):
    """A profile that omits allowed_tools: probe == stage. This is the drift
    case — the probe used to fall back to a Bash-bearing literal for
    preprocess that the real scan never sends."""
    cfg = _load_cfg(tmp_path, _MINIMAL_AGENTIC_YAML)
    via = llm.resolve(getattr(cfg.models, role)).via
    assert pf._agentic_role_tools(cfg, role, via) == _stage_tools(cfg, role)


def test_probe_tools_equal_stage_tools_with_cli_bash(tmp_path):
    """via:cli + Bash is a shipped capability; probe and stage agree on it."""
    cfg = _load_cfg(tmp_path,
                    "models:\n"
                    "  preprocess: {id: m-pre, via: cli}\n"
                    "  verify: {id: m-ver, via: cli}\n"
                    "  threatmodel: {id: m-tm, via: cli}\n"
                    "step1:\n  allowed_tools: [Read, Glob, Grep, Bash]\n"
                    "step2:\n"
                    "  agentic: true\n"
                    "  allowed_tools: [Read, Glob, Grep, Bash]\n"
                    "step6_verify:\n  allowed_tools: [Read, Glob, Grep, Bash]\n")
    for role in ("preprocess", "verify", "threatmodel"):
        via = llm.resolve(getattr(cfg.models, role)).via
        assert pf._agentic_role_tools(cfg, role, via) == _stage_tools(cfg, role)


@pytest.mark.parametrize("profile", ["default", "full", "sdk", "taint"])
def test_probe_tools_equal_stage_tools_for_shipped_profiles(profile):
    """Every shipped profile: the probe computes the stage's exact tool set
    for each role the agentic probe covers, and none of them raises — the
    shipped profiles' preflight outcome is unchanged by the shared
    derivation."""
    from pathlib import Path

    from vvaharness import config as config_mod
    profiles = Path(pf.__file__).resolve().parents[1] / "config" / "profiles"
    cfg = config_mod.load(profiles / f"{profile}.yaml")
    roles = pf._agentic_roles(cfg)
    assert roles  # the probe must cover something for every shipped profile
    for role in roles:
        via = llm.resolve(getattr(cfg.models, role)).via
        assert pf._agentic_role_tools(cfg, role, via) == _stage_tools(cfg, role)


# ── Fail-fast allowlist validation at preflight ──────────────────────────────
# A step6_verify.allowed_tools naming a non-read tool on via:sdk/openai used to
# pass preflight (the probe silently delegated) and then die at S6 start after
# S1-S5 spend. The probe now runs the stage's own validate_detection_tools, so
# the same config fails at preflight, fatally (detection role), naming the
# offending config key and tool.


def test_preflight_rejects_nonread_verify_tools_on_sdk(monkeypatch, tmp_path,
                                                       capsys):
    cfg = _load_cfg(tmp_path,
                    "models:\n  verify: {id: claude-a, via: sdk}\n"
                    "step6_verify:\n  allowed_tools: [Read, Bash]\n")
    monkeypatch.setattr(llm, "prompt", lambda *a, **k: "ok")
    monkeypatch.setattr(
        llm, "agentic",
        lambda *a, **k: pytest.fail("an invalid allowlist must never be probed"))
    assert pf.probe_backends(cfg) is False
    err = capsys.readouterr().err
    assert "ERROR" in err                      # detection role → fatal
    assert "step6_verify.allowed_tools" in err and "Bash" in err
    assert "will be skipped" not in err        # never the post-scan WARN path


def test_preflight_rejects_nonread_preprocess_tools_on_sdk(monkeypatch,
                                                           tmp_path, capsys):
    cfg = _load_cfg(tmp_path,
                    "models:\n  preprocess: {id: claude-a, via: sdk}\n"
                    "step1:\n  allowed_tools: [Read, Glob, Grep, Bash]\n")
    monkeypatch.setattr(llm, "prompt", lambda *a, **k: "ok")
    monkeypatch.setattr(
        llm, "agentic",
        lambda *a, **k: pytest.fail("an invalid allowlist must never be probed"))
    assert pf.probe_backends(cfg) is False
    err = capsys.readouterr().err
    assert "ERROR" in err
    assert "step1.allowed_tools" in err and "Bash" in err


def test_preflight_accepts_bash_verify_tools_on_cli(monkeypatch, tmp_path):
    """On via:cli a Bash allowlist is a shipped, documented capability —
    preflight must accept it and probe with exactly that tool set."""
    cfg = _load_cfg(tmp_path,
                    "models:\n  verify: {id: claude-a, via: cli}\n"
                    "step6_verify:\n  allowed_tools: [Read, Glob, Grep, Bash]\n")
    monkeypatch.setattr(llm, "prompt", lambda *a, **k: "ok")
    captured = {}
    monkeypatch.setattr(llm, "agentic",
                        lambda *a, **k: captured.update(k) or "ok")
    assert pf.probe_backends(cfg) is True
    assert captured["allowed_tools"] == ["Read", "Glob", "Grep", "Bash"]


# --- TLS path anchoring: verify_ssl is a tri-state, not a path ----------------
# Regression: `ca_cert`/`client_cert` were anchored at the profile dir via
# `_resolve_against` (which is ALSO where UNC/SMB inputs are refused, because
# reading such a path leaks an NTLM hash on Windows), but `verify_ssl` was
# forwarded raw — even though a non-boolean `verify_ssl` IS a CA-bundle path.

@pytest.mark.parametrize("value", [True, False, None, "true", "false", "FALSE"])
def test_resolve_verify_path_leaves_every_boolean_form_untouched(tmp_path, value):
    """Booleans and string boolean literals must never be treated as paths.

    This is the trap the fix had to avoid: running `"false"` through the path
    resolver would silently produce the filename `<cfg_dir>/false` and turn
    "TLS off" into "verify against a file that does not exist".
    """
    assert pf._resolve_verify_path(tmp_path, value) is value


def test_resolve_verify_path_anchors_a_relative_ca_bundle_at_the_profile_dir(tmp_path):
    """A CA-bundle PATH in verify_ssl resolves against the profile dir, not the cwd."""
    out = pf._resolve_verify_path(tmp_path, "corp-ca.pem")
    assert out == str(tmp_path / "corp-ca.pem")


def test_resolve_verify_path_refuses_a_unc_ca_bundle(tmp_path):
    """//host/share/ca.pem must be refused before any loader opens it."""
    with pytest.raises(ValueError, match="network/UNC"):
        pf._resolve_verify_path(tmp_path, "//host/share/ca.pem")


def test_resolve_cert_chain_anchors_both_shapes_and_passes_through_none(tmp_path):
    """A combined PEM and a (cert, key) pair — tuple OR list — both get anchored."""
    assert pf._resolve_cert_chain(tmp_path, None) is None
    assert pf._resolve_cert_chain(tmp_path, "c.pem") == str(tmp_path / "c.pem")
    for shape in (tuple, list):
        assert pf._resolve_cert_chain(tmp_path, shape(["c.pem", "c.key"])) == (
            str(tmp_path / "c.pem"), str(tmp_path / "c.key"),
        )


def test_resolve_cert_chain_refuses_a_unc_member_of_a_pair(tmp_path):
    """A UNC path hiding in the KEY half of a pair is refused too."""
    with pytest.raises(ValueError, match="network/UNC"):
        pf._resolve_cert_chain(tmp_path, ["c.pem", "//host/share/c.key"])


def test_configure_backends_anchors_verify_ssl_and_refuses_unc(monkeypatch, tmp_path):
    """WIRING: the anchoring must happen through `configure_backends`, not just the helper.

    The unit tests above exercise `_resolve_verify_path`/`_resolve_cert_chain`
    directly, so reverting the three call-site edits would leave them green while
    reopening the hole. This drives the real entry point: a relative CA path in
    `verify_ssl` must reach the backend profile-dir-anchored, and a UNC one must
    be refused before any loader opens it.
    """
    from vvaharness import config as config_mod
    captured: dict = {}
    monkeypatch.setattr(pf.sdk, "configure", lambda **kw: captured.update(kw))
    monkeypatch.setattr(pf.oai, "configure", lambda **kw: None)
    monkeypatch.setattr(pf.cli, "configure", lambda **kw: None)

    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("models:\n  deepdive: {id: x, via: sdk}\n"
                        "sdk:\n  verify_ssl: certs/corp-ca.pem\n", encoding="utf-8")
    pf.configure_backends(config_mod.load(cfg_file), tmp_path)
    assert captured["verify_ssl"] == str(tmp_path / "certs" / "corp-ca.pem")

    unc = tmp_path / "unc.yaml"
    unc.write_text("models:\n  deepdive: {id: x, via: sdk}\n"
                   "sdk:\n  verify_ssl: //host/share/ca.pem\n", encoding="utf-8")
    with pytest.raises(ValueError, match="network/UNC"):
        pf.configure_backends(config_mod.load(unc), tmp_path)


def test_configure_backends_anchors_every_member_of_a_client_cert_pair(monkeypatch, tmp_path):
    """WIRING: a YAML list pair reaches the sdk backend fully anchored."""
    from vvaharness import config as config_mod
    captured: dict = {}
    monkeypatch.setattr(pf.sdk, "configure", lambda **kw: captured.update(kw))
    monkeypatch.setattr(pf.oai, "configure", lambda **kw: None)
    monkeypatch.setattr(pf.cli, "configure", lambda **kw: None)
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("models:\n  deepdive: {id: x, via: sdk}\n"
                        "sdk:\n  client_cert: [certs/c.pem, certs/c.key]\n",
                        encoding="utf-8")
    pf.configure_backends(config_mod.load(cfg_file), tmp_path)
    assert captured["client_cert"] == (
        str(tmp_path / "certs" / "c.pem"), str(tmp_path / "certs" / "c.key"),
    )


def test_configure_backends_forwards_openai_client_cert_so_it_is_diagnosed(
    monkeypatch, tmp_path, capsys
):
    """WIRING: `openai.client_cert` must reach the backend to be warned about.

    Red before: preflight never read `oai_cfg.client_cert`, so the knob was
    silently ignored. Asserting only that `oai.configure` warns would still pass
    if the forwarding were deleted — so drive the real entry point and let the
    genuine `oai.configure` run.
    """
    from vvaharness import config as config_mod
    monkeypatch.setattr(pf.sdk, "configure", lambda **kw: None)
    monkeypatch.setattr(pf.cli, "configure", lambda **kw: None)
    # The genuine oai.configure mutates module globals and this file has no
    # reset fixture; monkeypatch copies so nothing leaks into later tests.
    monkeypatch.setattr(pf.oai, "_cfg", dict(pf.oai._cfg))
    monkeypatch.setattr(pf.oai, "_client", None)
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("models:\n  deepdive: {id: x, via: openai}\n"
                        "openai:\n  client_cert: /etc/pki/c.pem\n", encoding="utf-8")
    pf.configure_backends(config_mod.load(cfg_file), tmp_path)
    assert "cannot present a client certificate" in capsys.readouterr().err


def test_resolve_verify_path_treats_an_empty_string_as_not_a_path(tmp_path):
    """An empty/blank verify_ssl must NOT resolve to the profile directory.

    Red before: `coerce_verify("")` returns `""` (a string matching no boolean
    literal) and `Path("")` is `Path(".")`, so resolution yielded the profile dir
    and handed the TLS stack a DIRECTORY as its CA bundle — which on `via: cli`
    even passed an existence check and was exported as NODE_EXTRA_CA_CERTS.
    """
    for blank in ("", "   "):
        assert pf._resolve_verify_path(tmp_path, blank) is blank


def test_resolve_cert_chain_never_path_resolves_the_key_password(tmp_path):
    """A third chain member is the key PASSWORD, not a path — pass it through.

    Red before: every member was resolved, so an encrypted-key chain became
    (cert, key, '<cfg_dir>/<password>') and silently lost mTLS. A password
    beginning with `//` would additionally have been echoed by the UNC guard's
    exception message.
    """
    out = pf._resolve_cert_chain(tmp_path, ["c.pem", "c.key", "s3cret"])
    assert out == (str(tmp_path / "c.pem"), str(tmp_path / "c.key"), "s3cret")
    # A password that looks like a UNC path must not raise, and must not be echoed.
    assert pf._resolve_cert_chain(tmp_path, ("c.pem", "c.key", "//weird"))[2] == "//weird"


def test_resolve_cert_chain_keeps_an_empty_member_in_position(tmp_path):
    """An empty member must not be dropped — dropping it renumbers the chain.

    Red before: the `if p` filter turned ["cert.pem", ""] into a 1-tuple, so a
    pair was silently reinterpreted as a combined PEM with no key.
    """
    assert pf._resolve_cert_chain(tmp_path, ["c.pem", ""]) == (str(tmp_path / "c.pem"), "")



# ── nested model roles: `validate` and `exploit_verification` ─────────────────
#
# Both are MAPS of sub-roles rather than a single node, so `_iter_model_roles` descends
# one level. `validate` runs its whole panel on the orchestrator's backend, so only that
# is checked and it must keep reporting under the name "validate" — callers classify by
# it (`llm.POST_SCAN_ROLES` / `_post_scan_only` downgrade a post-scan gap to a WARN).
# Exploit verification genuinely mixes backends per purpose, so each sub-role is yielded
# and credential-checked on its own.

def _cfg_models(**roles):
    return SimpleNamespace(models=SimpleNamespace(**roles))


def test_validate_still_reports_under_its_own_role_name():
    orch = SimpleNamespace(id="m", via="deepagents")
    cfg = _cfg_models(validate=SimpleNamespace(orchestrator=orch,
                                               security_architect=SimpleNamespace(id="p")))
    rows = list(_iter_model_roles(cfg))
    assert rows == [("validate", orch)]                    # orchestrator only, parent name
    assert pf._post_scan_only([r for r, _ in rows]) is True  # so the WARN path still applies


def test_every_configured_ev_purpose_is_enumerated_separately():
    nodes = {p: SimpleNamespace(id=p, via="sdk")
             for p in ("attacker", "judge", "classify", "mapper")}
    cfg = _cfg_models(exploit_verification=SimpleNamespace(**nodes))
    rows = dict(_iter_model_roles(cfg))
    assert set(rows) == {f"exploit_verification.{p}" for p in nodes}
    assert rows["exploit_verification.judge"] is nodes["judge"]


def test_an_absent_ev_purpose_demands_no_credential():
    """An undeclared sub-role must not be reported. EV's optional purposes (`attacker`,
    `mapper`) are meant to be droppable — a profile that omits one is choosing to run
    without that capability, not asking for a credential to be demanded on its behalf."""
    cfg = _cfg_models(exploit_verification=SimpleNamespace(
        judge=SimpleNamespace(id="j", via="cli")))          # no attacker
    rows = dict(_iter_model_roles(cfg))
    assert set(rows) == {"exploit_verification.judge"}
    assert not any("attacker" in r for r in rows)


def test_no_ev_block_yields_nothing_extra():
    assert list(_iter_model_roles(_cfg_models(deepdive="m"))) == [("deepdive", "m")]


def _two_backend_roles(monkeypatch):
    """A cli detection role plus an EV role on a second backend."""
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [("deepdive", "cli-node"),
                                     ("exploit_verification.judge", "openai-node")])
    monkeypatch.setattr(orchestrator.preflight, "resolve_model",
                        lambda m: ResolvedModel("test-model",
                                                "cli" if m == "cli-node" else "openai", {}))
    monkeypatch.setattr(orchestrator.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(orchestrator.preflight, "probe_backends",
                        lambda *_a, **_kw: True)
    monkeypatch.setenv("OPENAI_API_KEY", "k")     # satisfied, so only the scope differs


def test_check_backends_drops_the_backend_of_a_skipped_role(monkeypatch, capsys):
    """`skip_roles` takes a role out of scope entirely, so its backend is not required.

    Without it, an EV role on a backend the rest of the pipeline does not use would
    demand that credential from every scan — EV roles are detection-era, so a gap on one
    is fatal rather than a skip-this-stage WARN (unlike remediate/validate).
    """
    _two_backend_roles(monkeypatch)

    pf.check_backends(cfg=SimpleNamespace())
    assert "active backends: cli, openai" in capsys.readouterr().err

    pf.check_backends(cfg=SimpleNamespace(), skip_roles=["exploit_verification.judge"])
    err = capsys.readouterr().err
    assert "active backends: cli" in err and "openai" not in err


def test_ev_model_roles_matches_what_iter_reports():
    """The skip list is derived from the same map `_iter_model_roles` descends, so the
    two cannot drift apart and silently stop skipping."""
    from vvaharness.orchestrator.config_paths import EV_MODEL_ROLES
    nodes = {p: SimpleNamespace(id=p, via="sdk")
             for p in ("attacker", "judge", "classify", "mapper")}
    cfg = SimpleNamespace(models=SimpleNamespace(
        exploit_verification=SimpleNamespace(**nodes)))
    assert {r for r, _ in _iter_model_roles(cfg)} == set(EV_MODEL_ROLES)

def test_api_backend_auth_diagnostics_are_presence_only(monkeypatch, capsys):
    monkeypatch.setattr(orchestrator.preflight, "_iter_model_roles",
                        lambda cfg: [("deepdive", "sdk-node"),
                                     ("chain", "openai-node")])
    monkeypatch.setattr(orchestrator.preflight, "resolve_model",
                        lambda m: ResolvedModel("test-model",
                                                "sdk" if m == "sdk-node" else "openai", {}))
    monkeypatch.setattr(orchestrator.preflight, "probe_backends",
                        lambda *_a, **_kw: True)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-secret-value")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-secret-value")
    cfg = SimpleNamespace(
        sdk=SimpleNamespace(
            api_key="cfg-sdk-secret",
            base_url="https://sdk-user:sdk-pass@sdk.example/v1?api_key=sdk-query",
        ),
        openai=SimpleNamespace(
            api_key="cfg-openai-secret",
            base_url="https://oai-user:oai-pass@oai.example/v1?api_key=oai-query",
        ),
    )

    assert pf.check_backends(cfg=cfg) is True
    err = capsys.readouterr().err
    assert "env  ANTHROPIC_SDK_API_KEY     = set ✓" in err
    assert "cfg  sdk.api_key               = set ✓" in err
    assert "cfg  sdk.base_url              = set ✓" in err
    assert "env  OPENAI_API_KEY            = set ✓" in err
    assert "cfg  openai.api_key            = set ✓" in err
    assert "cfg  openai.base_url           = set ✓" in err
    for secret in (
        "sk-ant-secret-value", "sk-openai-secret-value",
        "cfg-sdk-secret", "cfg-openai-secret",
        "sdk-user", "sdk-pass", "sdk.example", "sdk-query",
        "oai-user", "oai-pass", "oai.example", "oai-query",
    ):
        assert secret not in err



# Unrecognized model-node keys — advisory WARN, never a failure


def _sdk_config_nodes(monkeypatch, nodes):
    """Present *nodes* as via:sdk roles with a satisfied credential and no probe."""
    monkeypatch.setattr(pf, "_iter_model_roles", lambda _cfg: nodes)
    monkeypatch.setattr(pf, "probe_backends", lambda _cfg: True)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-test")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://test-gateway.example/")


def test_unknown_model_key_warns_once_and_stays_ok(monkeypatch, capsys):
    """A typo'd key is named per role in ONE aggregated WARN; preflight passes."""
    from vvaharness.config import Config as YamlNode

    _sdk_config_nodes(monkeypatch, [
        ("deepdive", YamlNode({"id": "m", "via": "sdk", "use_responses_apis": True})),
        ("chain", YamlNode({"id": "m", "via": "sdk", "temprature": 0.2})),
    ])

    assert orchestrator.check_backends(cfg=object()) is True
    err = capsys.readouterr().err
    assert err.count("unrecognized model key(s) ignored") == 1
    assert "models.deepdive.use_responses_apis" in err
    assert "models.chain.temprature" in err


def test_clean_model_nodes_warn_about_nothing(monkeypatch, capsys):
    """Every recognized key — use_responses_api included — passes silently."""
    from vvaharness.config import Config as YamlNode

    _sdk_config_nodes(monkeypatch, [
        ("deepdive", YamlNode({"id": "m", "via": "sdk", "provider": "openai",
                               "temperature": 0.2, "thinking_budget": 1024,
                               "betas": ["b1"], "use_responses_api": False})),
        ("chain", "bare-string-model"),
    ])
    monkeypatch.setattr(orchestrator.shutil, "which", lambda _name: "/usr/bin/claude")

    assert orchestrator.check_backends(cfg=object()) is True
    assert "unrecognized model key" not in capsys.readouterr().err
