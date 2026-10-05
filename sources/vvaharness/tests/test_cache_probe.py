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

"""Offline, deterministic tests for the cache diagnostic probe:
`vvaharness doctor --cache-probe` and its supporting helpers in
`vvaharness.orchestrator.preflight`.

This probe is meant to be run live, by an operator, against real model
routes — never automatically. Every test here is therefore offline — no
network, no real subprocess, no live LLM call. Where a live `prompt()` call
would occur, it is monkeypatched to inject a synthetic `usage` dict directly
into `TOKENS` (mirroring exactly what backends/llm/sdk.py and
backends/llm/openai.py do
internally), so the diff/classify/report pipeline is exercised end-to-end
without ever leaving the process.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness import cli
from vvaharness.backends.llm import registry as llm
from vvaharness.orchestrator import preflight as pf
from vvaharness.util.tokens import TOKENS, estimate_tokens


# ─────────────────────────────────────────────────────────────────────────────
# cache_probe_filler / estimate_tokens — deterministic, ≥8192 estimated tokens
# under the ONE shared estimator the backends' marker gates also use
# ─────────────────────────────────────────────────────────────────────────────

def test_filler_meets_the_8192_token_floor():
    # The zero-cost half of the sizing decision: the generator still sizes by
    # raw chars (`_FILLER_CHARS_PER_TOKEN`, cheaper filler), and THIS assertion
    # guarantees the result still clears the nominal floor under the shared
    # content-aware estimator — the same function the marker gate uses.
    filler = pf.cache_probe_filler()
    assert estimate_tokens(filler) >= 8192


def test_filler_has_margin_past_the_floor():
    # Landing exactly at the nominal floor is the failure mode this generator
    # exists to avoid: a real-tokenizer undercount could land below a
    # provider's actual minimum cacheable block size and get misdiagnosed as
    # "marker not honoured" rather than "filler too small". Assert real
    # margin, not just "at or above 8192". (The chars-based 1.25x build margin
    # compresses to ~1.14x under the shared estimator's prose ratio; 1.1x is
    # the floor this test holds it to.)
    filler = pf.cache_probe_filler()
    assert estimate_tokens(filler) >= int(8192 * 1.1)


def test_filler_is_deterministic_across_calls():
    assert pf.cache_probe_filler() == pf.cache_probe_filler()


def test_filler_respects_a_custom_floor():
    small = pf.cache_probe_filler(min_tokens=100)
    assert 100 <= estimate_tokens(small) < estimate_tokens(pf.cache_probe_filler())


def test_both_backends_share_one_estimator_with_the_probe_sizing_check():
    # The agreement that replaced the old chars/4 pin: the sizing check above
    # and both backends' minimum-size gates must be the SAME function object
    # (util/tokens.estimate_tokens), so the filler that audits the gate can
    # never be sized by a different arithmetic than the gate itself. Asserted
    # through the backends, not through preflight's namespace: preflight never
    # calls the name, so a ruff --fix that drops its import must not fail here.
    from vvaharness.util import tokens as util_tokens
    assert estimate_tokens is util_tokens.estimate_tokens
    assert pf.sdk.estimate_tokens is util_tokens.estimate_tokens
    assert pf.oai.estimate_tokens is util_tokens.estimate_tokens


def test_filler_clears_the_real_gate_for_every_minimum_table_row(monkeypatch):
    # The invariant the shared estimator exists to guarantee: the default
    # probe filler must clear `sdk._cache_prefix_meets_minimum` — the REAL
    # gate the probe audits — for a model id matching every row of the
    # per-model minimum table, and for the unknown-model fallback (the
    # largest published minimum). A filler on the wrong side of the gate
    # would probe a request the gate never marks.
    monkeypatch.setitem(pf.sdk._cfg, "cache_min_block_tokens", None)
    filler = pf.cache_probe_filler()
    candidates = [
        "claude-opus-5", "claude-fable-5",
        "claude-opus-4-6", "claude-haiku-4-5",
        "claude-opus-4-7", "claude-haiku-3-5",
        "claude-opus-4-1", "claude-sonnet-4-5", "claude-sonnet-5",
    ]
    covered: set[int] = set()
    for model in candidates:
        for i, (rx, _floor) in enumerate(pf.sdk._CACHE_MIN_TOKENS_TABLE):
            if rx.search(model):
                covered.add(i)
                break
        assert pf.sdk._cache_prefix_meets_minimum(filler, model) is True, model
    assert covered == set(range(len(pf.sdk._CACHE_MIN_TOKENS_TABLE))), (
        "every row of the minimum table must be exercised by a candidate id")
    # Unknown-model fallback: held to the strictest published floor.
    unknown = "some-future-model"
    assert pf.sdk._cache_min_tokens_for(unknown) == pf.sdk._CACHE_MIN_TOKENS_FALLBACK
    assert pf.sdk._cache_prefix_meets_minimum(filler, unknown) is True


# ─────────────────────────────────────────────────────────────────────────────
# classify_cache_verdict — the six-way classification, a pure function
# ─────────────────────────────────────────────────────────────────────────────

def test_row1_anthropic_works():
    usage_a = {"cache_creation_input_tokens": 9000}
    usage_b = {"cache_read_input_tokens": 9000}
    assert pf.classify_cache_verdict(usage_a, usage_b) == pf.V_ANTHROPIC_WORKS


def test_row2_anthropic_write_ok_read_fails():
    usage_a = {"cache_creation_input_tokens": 9000}
    usage_b = {"cache_read_input_tokens": 0}
    assert pf.classify_cache_verdict(usage_a, usage_b) == pf.V_ANTHROPIC_ROUTING_GAP


def test_row3_anthropic_marker_not_honoured():
    usage_a = {"cache_creation_input_tokens": 0}
    usage_b = {"cache_read_input_tokens": 0}
    assert pf.classify_cache_verdict(usage_a, usage_b) == pf.V_ANTHROPIC_NOT_HONOURED


def test_row4_openai_style_working_implicit():
    # The easy-to-miss case: creation field ABSENT entirely (not
    # present-and-zero), read > 0 — a working implicit-cache route.
    usage_a = {}
    usage_b = {"cache_read_input_tokens": 9000}
    assert pf.classify_cache_verdict(usage_a, usage_b) == pf.V_OPENAI_WORKING


def test_row5_openai_style_below_minimum():
    usage_a = {}
    usage_b = {"cache_read_input_tokens": 0}
    assert pf.classify_cache_verdict(usage_a, usage_b) == pf.V_OPENAI_BELOW_MIN


def test_row6_no_cache_fields_at_all():
    assert pf.classify_cache_verdict({}, {}) == pf.V_NO_CACHE_FIELDS


def test_creation_present_and_zero_is_not_confused_with_absent():
    # The distinguishing case between row 3 and row 6: a present-but-zero
    # creation field must NOT collapse to "no cache fields at all".
    present_zero = pf.classify_cache_verdict({"cache_creation_input_tokens": 0},
                                              {"cache_read_input_tokens": 0})
    absent = pf.classify_cache_verdict({}, {})
    assert present_zero == pf.V_ANTHROPIC_NOT_HONOURED
    assert absent == pf.V_NO_CACHE_FIELDS
    assert present_zero != absent


@pytest.mark.parametrize("code", [
    pf.V_ANTHROPIC_WORKS, pf.V_ANTHROPIC_ROUTING_GAP, pf.V_ANTHROPIC_NOT_HONOURED,
    pf.V_OPENAI_WORKING, pf.V_OPENAI_BELOW_MIN, pf.V_NO_CACHE_FIELDS,
    pf.V_MARKER_WITHHELD,
])
def test_every_verdict_code_has_report_text(code):
    assert code in pf._VERDICT_TEXT
    assert pf._VERDICT_TEXT[code]


# ─────────────────────────────────────────────────────────────────────────────
# usage_dict_for_classifier — field presence is OBSERVED (fed in from
# _call_and_diff's capture of what the backend recorded), never inferred from
# the `via` transport name. The old via-keyed reconstruction unconditionally
# dropped the write field for `via: openai`, which went wrong the moment
# openai.py::_normalise_usage started reporting cache writes from
# `prompt_tokens_details.cache_write_tokens`.
# ─────────────────────────────────────────────────────────────────────────────

def test_observed_presence_with_zero_values_keeps_the_keys():
    # Anthropic-shaped pair: both fields observed present, both zero — the
    # keys must survive (present-at-zero is row-selecting information).
    usage_a, usage_b = pf.usage_dict_for_classifier(
        cache_write=0, cache_read=0, write_present=True, read_present=True)
    assert "cache_creation_input_tokens" in usage_a
    assert "cache_read_input_tokens" in usage_b
    assert usage_a["cache_creation_input_tokens"] == 0


def test_unobserved_write_field_stays_absent():
    # Implicit-cache shape (vendor OpenAI endpoint): the write field was never
    # recorded, so it must not be fabricated — absence is the OpenAI-family
    # row selector.
    usage_a, usage_b = pf.usage_dict_for_classifier(
        cache_write=0, cache_read=500, write_present=False, read_present=True)
    assert "cache_creation_input_tokens" not in usage_a
    assert usage_b["cache_read_input_tokens"] == 500


def test_no_usage_recorded_at_all_reports_no_cache_fields():
    # A route that recorded no usage dicts yields False flags; the pair must
    # land on "no cache fields at all", never be guessed into either family —
    # even if the (necessarily zero) counters were somehow non-zero.
    usage_a, usage_b = pf.usage_dict_for_classifier(
        cache_write=999, cache_read=999, write_present=False, read_present=False)
    assert usage_a == {} and usage_b == {}
    assert pf.classify_cache_verdict(usage_a, usage_b) == pf.V_NO_CACHE_FIELDS


def test_anthropic_shaped_pair_end_to_end_through_the_real_pipeline():
    usage_a, usage_b = pf.usage_dict_for_classifier(
        cache_write=8000, cache_read=8000, write_present=True, read_present=True)
    assert pf.classify_cache_verdict(usage_a, usage_b) == pf.V_ANTHROPIC_WORKS


def test_implicit_cache_pair_end_to_end_through_the_real_pipeline():
    usage_a, usage_b = pf.usage_dict_for_classifier(
        cache_write=0, cache_read=7000, write_present=False, read_present=True)
    assert pf.classify_cache_verdict(usage_a, usage_b) == pf.V_OPENAI_WORKING


def test_observed_cache_write_on_openai_route_is_not_below_minimum():
    # THE defect this design exists to fix: a gateway on the openai route that
    # bills cache writes (write > 0 observed, read == 0). The old via-keyed
    # reconstruction discarded the write and produced "below minimum
    # cacheable size" — disproved by the very write it printed. With presence
    # observed, the pair classifies in the explicit-write family: writes
    # succeed, reads do not — the routing-gap diagnosis.
    usage_a, usage_b = pf.usage_dict_for_classifier(
        cache_write=8200, cache_read=0, write_present=True, read_present=True)
    verdict = pf.classify_cache_verdict(usage_a, usage_b)
    assert verdict == pf.V_ANTHROPIC_ROUTING_GAP
    assert verdict != pf.V_OPENAI_BELOW_MIN


def test_observed_cache_write_and_read_on_openai_route_is_working():
    # Same gateway, healthy: write observed on Call A, read observed on Call
    # B — a working cache, reported from the explicit-write family.
    usage_a, usage_b = pf.usage_dict_for_classifier(
        cache_write=8200, cache_read=8200, write_present=True, read_present=True)
    assert pf.classify_cache_verdict(usage_a, usage_b) == pf.V_ANTHROPIC_WORKS


# ─────────────────────────────────────────────────────────────────────────────
# Credential / base_url hygiene — never print a secret or an auth-bearing URL
# ─────────────────────────────────────────────────────────────────────────────

def test_scheme_host_strips_userinfo_path_and_query():
    out = pf._scheme_host("https://svc-account:sekret-token@gateway.example.com:8443"
                          "/v1/models?api_key=abcd1234")
    assert out == "https://gateway.example.com:8443"
    assert "sekret-token" not in out
    assert "svc-account" not in out
    assert "api_key" not in out
    assert "abcd1234" not in out


def test_scheme_host_none_and_empty():
    assert pf._scheme_host(None) == "(default)"
    assert pf._scheme_host("") == "(default)"


def test_scheme_host_malformed_url_does_not_raise():
    out = pf._scheme_host("not a url at all :::")
    assert isinstance(out, str)


def test_resolved_base_url_cli_has_no_base_url_concept():
    assert pf._resolved_base_url_scheme_host("cli") == "(cli subprocess — no base_url)"


def test_resolved_base_url_sdk_reads_the_configured_client(monkeypatch):
    fake_client = SimpleNamespace(base_url="https://user:pw@gw.internal/x?y=1")
    monkeypatch.setattr(pf.sdk, "_get_client", lambda: fake_client)
    out = pf._resolved_base_url_scheme_host("sdk")
    assert out == "https://gw.internal"
    assert "user" not in out and "pw" not in out


def test_resolved_base_url_handles_client_construction_failure(monkeypatch):
    def boom():
        raise RuntimeError("ANTHROPIC_SDK_API_KEY not set")
    monkeypatch.setattr(pf.sdk, "_get_client", boom)
    assert pf._resolved_base_url_scheme_host("sdk") == "(unresolved)"


# ─────────────────────────────────────────────────────────────────────────────
# _thinking_actually_sent — post-hoc ground truth, not "did I ask for it"
# ─────────────────────────────────────────────────────────────────────────────

def test_thinking_not_sent_when_not_requested():
    assert pf._thinking_actually_sent("some-model", None) is False
    assert pf._thinking_actually_sent("some-model", 0) is False


def test_thinking_sent_when_requested_and_model_not_downgraded(monkeypatch):
    monkeypatch.setattr(pf.sdk, "_NO_THINK_MODELS", set())
    assert pf._thinking_actually_sent("claude-test", 1024) is True


def test_thinking_not_sent_when_model_was_downgraded_mid_call(monkeypatch):
    # Mirrors the `thinking`-rejection handler in ``sdk.py::prompt``
    # (`~sdk.py:557-566`) — a 400 on `thinking` adds the model to
    # _NO_THINK_MODELS and retries without it, inside the same prompt() call.
    monkeypatch.setattr(pf.sdk, "_NO_THINK_MODELS", {"claude-test"})
    assert pf._thinking_actually_sent("claude-test", 1024) is False


# ─────────────────────────────────────────────────────────────────────────────
# _marker_would_be_placed — the sdk backend's own gate, asked, never re-derived
# ─────────────────────────────────────────────────────────────────────────────

def _sdk_gate_defaults(monkeypatch):
    """Pin the sdk gate's config knobs to shipped defaults and point the
    (fake) client at the vendor endpoint, so gate decisions depend only on
    the (model, prompt) pair under test."""
    monkeypatch.setitem(pf.sdk._cfg, "cache_markers", "on")
    monkeypatch.setitem(pf.sdk._cfg, "cache_route", "auto")
    monkeypatch.setitem(pf.sdk._cfg, "cache_min_block_tokens", None)
    monkeypatch.setattr(pf.sdk, "_get_client",
                        lambda: SimpleNamespace(base_url="https://api.anthropic.com/"))


def test_gate_helper_false_for_deepdive_prompt_on_a_4096_floor_model(monkeypatch):
    # The misdirection case: the deep-dive system prompt estimates well under
    # a 4096-token floor, so sdk._build_system_content sends a plain string
    # with no marker at all — the gate withheld it, provably.
    _sdk_gate_defaults(monkeypatch)
    assert pf._marker_would_be_placed(
        "sdk", pf._deepdive_system_prompt(), "claude-opus-4-6") is False


def test_gate_helper_true_when_the_prompt_clears_the_gate(monkeypatch):
    _sdk_gate_defaults(monkeypatch)
    assert pf._marker_would_be_placed(
        "sdk", pf.cache_probe_filler(), "claude-opus-4-6") is True


def test_gate_helper_false_when_the_kill_switch_is_off(monkeypatch):
    _sdk_gate_defaults(monkeypatch)
    monkeypatch.setitem(pf.sdk._cfg, "cache_markers", "off")
    assert pf._marker_would_be_placed(
        "sdk", pf.cache_probe_filler(), "claude-opus-4-6") is False


def test_gate_helper_false_for_an_unrecognised_route(monkeypatch):
    _sdk_gate_defaults(monkeypatch)
    monkeypatch.setattr(pf.sdk, "_get_client",
                        lambda: SimpleNamespace(base_url="https://gateway.example.com/v1"))
    assert pf._marker_would_be_placed(
        "sdk", pf.cache_probe_filler(), "claude-opus-4-6") is False


@pytest.mark.parametrize("via", ["cli", "openai"])
def test_gate_helper_unknowable_for_non_sdk_vias(via):
    # via:cli builds its own request inside the `claude` subprocess and
    # via:openai places no cache_control markers by design — for both, "our
    # gate withheld the marker" is not a statement this process can make.
    assert pf._marker_would_be_placed(via, "x" * 100_000, "claude-opus-4-6") is None


def test_gate_helper_failure_is_unknowable_not_false(monkeypatch):
    _sdk_gate_defaults(monkeypatch)

    def boom():
        raise RuntimeError("client construction failed")

    monkeypatch.setattr(pf.sdk, "_get_client", boom)
    assert pf._marker_would_be_placed(
        "sdk", pf.cache_probe_filler(), "claude-opus-4-6") is None


# ─────────────────────────────────────────────────────────────────────────────
# _cache_probe_targets — dedup, and deepagents stays out of scope. Not because
# the route skips prompt()/TOKENS — detection deepagents roles DO go through
# prompt() and DO record tokens — but because it is deliberately cache-neutral
# (Spec §12: it places no cache markers at all), so there is nothing for a
# cache probe to measure. _PROMPT_VIAS is deliberately not widened (Spec §9.7).
# ─────────────────────────────────────────────────────────────────────────────

def test_targets_dedupe_by_model_and_via(monkeypatch):
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="m1", via="sdk")),
        ("verify", SimpleNamespace(id="m1", via="sdk")),
        ("decompose", SimpleNamespace(id="m2", via="openai")),
    ])
    monkeypatch.setattr(pf, "resolve_model", lambda m: (m.id, m.via, {}))
    targets = pf._cache_probe_targets(cfg=object())
    assert set(targets.keys()) == {("m1", "sdk"), ("m2", "openai")}


def test_targets_exclude_deepagents_roles(monkeypatch):
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("remediate", SimpleNamespace(id="m3", via="deepagents")),
    ])
    monkeypatch.setattr(pf, "resolve_model", lambda m: (m.id, m.via, {}))
    assert pf._cache_probe_targets(cfg=object()) == {}


# ─────────────────────────────────────────────────────────────────────────────
# _call_and_diff — snapshot-diffing TOKENS around a (stubbed) prompt() call for
# VALUES, plus observing the recorded usage dicts for field PRESENCE
# ─────────────────────────────────────────────────────────────────────────────

def test_call_and_diff_isolates_its_own_phase(monkeypatch):
    def fake_prompt(user_prompt, *, model, **kw):
        TOKENS.add({"input_tokens": 10, "cache_creation_input_tokens": 4242,
                    "cache_read_input_tokens": 111, "output_tokens": 1})
        return "ok"
    monkeypatch.setattr(llm, "prompt", fake_prompt)
    result = pf._call_and_diff(model="m", system_prompt="sys", user_prompt="usr",
                               thinking_budget=None, phase_label="test-phase-xyz")
    assert result == {"cache_read": 111, "cache_write": 4242,
                      "cache_read_present": True, "cache_write_present": True}


def test_call_and_diff_does_not_leak_into_other_phases(monkeypatch):
    def fake_prompt(user_prompt, *, model, **kw):
        TOKENS.add({"cache_creation_input_tokens": 500, "cache_read_input_tokens": 0})
        return "ok"
    monkeypatch.setattr(llm, "prompt", fake_prompt)
    with TOKENS.phase("unrelated-phase"):
        TOKENS.add({"cache_creation_input_tokens": 999999, "cache_read_input_tokens": 999999})
    result = pf._call_and_diff(model="m", system_prompt="sys", user_prompt="usr",
                               thinking_budget=None, phase_label="isolated-phase")
    assert result == {"cache_read": 0, "cache_write": 500,
                      "cache_read_present": True, "cache_write_present": True}


def test_call_and_diff_observes_absence_the_counters_cannot_express(monkeypatch):
    # The counter diff for an absent write field and a present-at-zero write
    # field is identical (0). Only the observed usage dict tells them apart —
    # this is the observation the classifier's row selection depends on.
    def fake_prompt(user_prompt, *, model, **kw):
        TOKENS.add({"input_tokens": 8200, "cache_read_input_tokens": 0,
                    "output_tokens": 2})   # no creation key: implicit-cache shape
        return "ok"
    monkeypatch.setattr(llm, "prompt", fake_prompt)
    result = pf._call_and_diff(model="m", system_prompt="sys", user_prompt="usr",
                               thinking_budget=None, phase_label="absence-phase")
    assert result["cache_write"] == 0
    assert result["cache_write_present"] is False
    assert result["cache_read_present"] is True


def test_call_and_diff_observes_conditional_write_presence(monkeypatch):
    # Mirrors openai.py::_normalise_usage output on a gateway that reports
    # prompt_tokens_details.cache_write_tokens: creation key present.
    def fake_prompt(user_prompt, *, model, **kw):
        TOKENS.add({"input_tokens": 50, "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 8200, "output_tokens": 2})
        return "ok"
    monkeypatch.setattr(llm, "prompt", fake_prompt)
    result = pf._call_and_diff(model="m", system_prompt="sys", user_prompt="usr",
                               thinking_budget=None, phase_label="cond-write-phase")
    assert result["cache_write"] == 8200
    assert result["cache_write_present"] is True


def test_call_and_diff_no_usage_recorded_means_nothing_present(monkeypatch):
    # openai.py/sdk.py call TOKENS.add(None) when the response carried no
    # usage; deepagents skips the add entirely. Either way: no observation,
    # no presence — never a fabricated field.
    def fake_prompt(user_prompt, *, model, **kw):
        TOKENS.add(None)
        return "ok"
    monkeypatch.setattr(llm, "prompt", fake_prompt)
    result = pf._call_and_diff(model="m", system_prompt="sys", user_prompt="usr",
                               thinking_budget=None, phase_label="no-usage-phase")
    assert result == {"cache_read": 0, "cache_write": 0,
                      "cache_read_present": False, "cache_write_present": False}


def test_call_and_diff_restores_tokens_add_even_on_failure(monkeypatch):
    # The observation wrapper must never outlive the call: TOKENS.add goes
    # back to the class method whether prompt() returns or raises, so the
    # probe leaves global accounting exactly as it found it.
    def boom(user_prompt, *, model, **kw):
        raise RuntimeError("mid-call failure")
    monkeypatch.setattr(llm, "prompt", boom)
    assert "add" not in TOKENS.__dict__
    with pytest.raises(RuntimeError):
        pf._call_and_diff(model="m", system_prompt="sys", user_prompt="usr",
                          thinking_budget=None, phase_label="restore-phase")
    assert "add" not in TOKENS.__dict__
    assert TOKENS.add.__func__ is type(TOKENS).add


# ─────────────────────────────────────────────────────────────────────────────
# run_cache_probe — end-to-end, fully offline (prompt() stubbed)
# ─────────────────────────────────────────────────────────────────────────────

def _stub_prompt_writes_then_reads():
    """A fake backends.llm.registry.prompt() that behaves like a working Anthropic-style
    route: the A-shaped user message writes to cache, the B-shaped one reads."""
    def fake_prompt(user_prompt, *, model, **kw):
        if user_prompt == pf._USER_MSG_A:
            TOKENS.add({"input_tokens": 50, "cache_creation_input_tokens": 9000,
                        "cache_read_input_tokens": 0, "output_tokens": 2})
        else:
            TOKENS.add({"input_tokens": 50, "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 9000, "output_tokens": 2})
        return "PONG"
    return fake_prompt


def test_run_cache_probe_end_to_end_sdk_route(monkeypatch, capsys):
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="test-model", via="sdk")),
    ])
    monkeypatch.setattr(pf, "resolve_model", lambda m: ("test-model", "sdk", {}))
    monkeypatch.setattr(llm, "prompt", _stub_prompt_writes_then_reads())
    monkeypatch.setattr(pf.sdk, "_get_client",
                        lambda: SimpleNamespace(base_url="https://api.anthropic.com/"))
    monkeypatch.setattr(pf.sdk, "_NO_THINK_MODELS", set())

    ok = pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err

    assert ok is True
    assert "test-model" in out
    assert pf.V_ANTHROPIC_WORKS in out
    assert "tokens total" in out


def test_run_cache_probe_end_to_end_openai_route(monkeypatch, capsys):
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="gpt-test", via="openai")),
    ])
    monkeypatch.setattr(pf, "resolve_model", lambda m: ("gpt-test", "openai", {}))

    def fake_prompt(user_prompt, *, model, **kw):
        # OpenAI-style: no creation field ever, read > 0 on the second call.
        if user_prompt == pf._USER_MSG_A:
            TOKENS.add({"input_tokens": 50, "cache_read_input_tokens": 0, "output_tokens": 2})
        else:
            TOKENS.add({"input_tokens": 50, "cache_read_input_tokens": 7000, "output_tokens": 2})
        return "PONG"

    monkeypatch.setattr(llm, "prompt", fake_prompt)
    monkeypatch.setattr(pf.oai, "_get_client",
                        lambda: SimpleNamespace(base_url="https://api.openai.com/v1"))

    ok = pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err

    assert ok is True
    assert pf.V_OPENAI_WORKING in out


def _openai_route_fixture(monkeypatch):
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="gpt-test", via="openai")),
    ])
    monkeypatch.setattr(pf, "resolve_model", lambda m: ("gpt-test", "openai", {}))
    monkeypatch.setattr(pf.oai, "_get_client",
                        lambda: SimpleNamespace(base_url="https://gw.example.com/v1"))


def test_openai_route_with_billed_cache_write_and_no_read_is_a_routing_gap(
        monkeypatch, capsys):
    # THE regression this branch of tests pins: `via: openai` against a
    # gateway that bills cache writes. openai.py::_normalise_usage records
    # `cache_creation_input_tokens` whenever the endpoint reports
    # prompt_tokens_details.cache_write_tokens, so Call A shows a real write.
    # Call B reads nothing. The probe used to print that non-zero creation
    # column NEXT TO the "below this route's minimum cacheable size" verdict —
    # a diagnosis the observed write disproves. The correct family is the
    # routing gap: writes succeed, reads do not.
    _openai_route_fixture(monkeypatch)

    def fake_prompt(user_prompt, *, model, **kw):
        # Shapes exactly as _normalise_usage emits them on this gateway:
        # creation key present on every call (the endpoint reports
        # cache_write_tokens), non-zero only on the cold Call A.
        if user_prompt == pf._USER_MSG_A:
            TOKENS.add({"input_tokens": 50, "cache_creation_input_tokens": 8200,
                        "cache_read_input_tokens": 0, "output_tokens": 2})
        else:
            TOKENS.add({"input_tokens": 8250, "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0, "output_tokens": 2})
        return "PONG"

    monkeypatch.setattr(llm, "prompt", fake_prompt)

    ok = pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err

    assert ok is True
    assert pf.V_OPENAI_BELOW_MIN not in out
    rows = _result_rows(out)
    assert rows
    assert all(pf.V_ANTHROPIC_ROUTING_GAP in l for l in rows)
    # The row's own numbers agree with the verdict: the write it observed is
    # printed, and the below-minimum operator text never accompanies it.
    assert all("creation=8200" in l for l in rows)
    assert pf._VERDICT_TEXT[pf.V_OPENAI_BELOW_MIN] not in out
    assert pf._VERDICT_TEXT[pf.V_ANTHROPIC_ROUTING_GAP] in out


def test_openai_route_with_billed_cache_write_and_read_reports_working(
        monkeypatch, capsys):
    # Same gateway, healthy: write on Call A, read on Call B — classified in
    # the explicit-write family as a working cache, and never overridden into
    # the sdk-only marker-withheld verdict (the gate helper is None for
    # via: openai).
    _openai_route_fixture(monkeypatch)

    def fake_prompt(user_prompt, *, model, **kw):
        if user_prompt == pf._USER_MSG_A:
            TOKENS.add({"input_tokens": 50, "cache_creation_input_tokens": 8200,
                        "cache_read_input_tokens": 0, "output_tokens": 2})
        else:
            TOKENS.add({"input_tokens": 50, "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 8200, "output_tokens": 2})
        return "PONG"

    monkeypatch.setattr(llm, "prompt", fake_prompt)

    ok = pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err

    assert ok is True
    rows = _result_rows(out)
    assert rows
    assert all(pf.V_ANTHROPIC_WORKS in l for l in rows)
    assert pf.V_OPENAI_BELOW_MIN not in out
    assert pf.V_MARKER_WITHHELD not in out


def test_run_cache_probe_reports_failure_without_crashing(monkeypatch, capsys):
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="broken-model", via="sdk")),
    ])
    monkeypatch.setattr(pf, "resolve_model", lambda m: ("broken-model", "sdk", {}))

    def boom(*a, **kw):
        raise RuntimeError("401 Invalid authentication credentials")

    monkeypatch.setattr(llm, "prompt", boom)
    monkeypatch.setattr(pf.sdk, "_get_client",
                        lambda: SimpleNamespace(base_url="https://api.anthropic.com/"))

    ok = pf.run_cache_probe(cfg=object())
    err = capsys.readouterr().err
    assert ok is False
    assert "FAILED" in err
    assert "401 Invalid authentication credentials" in err  # not a secret; safe to see


def test_run_cache_probe_no_targets_is_a_noop(monkeypatch, capsys):
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [])
    ok = pf.run_cache_probe(cfg=object())
    assert ok is True
    assert "nothing to probe" in capsys.readouterr().err


def test_run_cache_probe_never_prints_a_credential(monkeypatch, capsys):
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="test-model", via="sdk")),
    ])
    monkeypatch.setattr(pf, "resolve_model", lambda m: ("test-model", "sdk", {}))
    monkeypatch.setattr(llm, "prompt", _stub_prompt_writes_then_reads())
    monkeypatch.setattr(
        pf.sdk, "_get_client",
        lambda: SimpleNamespace(
            base_url="https://svc:sk-ant-super-secret-token@gateway.example.com/v1"))

    pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err
    assert "sk-ant-super-secret-token" not in out
    assert "svc:" not in out


# ─────────────────────────────────────────────────────────────────────────────
# run_cache_probe — the marker-withheld override on 0-write/0-read rows
# ─────────────────────────────────────────────────────────────────────────────

def _stub_prompt_stone_cold():
    """A fake backends.llm.registry.prompt() for a route where nothing caches: every
    call reports the Anthropic-style cache fields present but zero."""
    def fake_prompt(user_prompt, *, model, **kw):
        TOKENS.add({"input_tokens": 8200, "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0, "output_tokens": 2})
        return "PONG"
    return fake_prompt


def _result_rows(err: str) -> list[str]:
    """The per-(model, filler, thinking-arm) result lines only — the closing
    verdicts section repeats the codes and would double-count matches."""
    return [line for line in err.splitlines()
            if "creation=" in line and "->" in line]


def test_probe_blames_the_gate_not_the_gateway_on_a_withheld_row(monkeypatch, capsys):
    # claude-opus-4-6 has a 4096-token floor the deep-dive shape does not
    # clear, so sdk's own gate sends no marker — its 0/0 rows must report
    # "withheld by gate", not "not honoured". The synthetic shape DOES clear
    # the gate, so its 0/0 rows must keep blaming the gateway: the override
    # cannot fire indiscriminately.
    _sdk_gate_defaults(monkeypatch)
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="claude-opus-4-6", via="sdk")),
    ])
    monkeypatch.setattr(pf, "resolve_model",
                        lambda m: ("claude-opus-4-6", "sdk", {}))
    monkeypatch.setattr(llm, "prompt", _stub_prompt_stone_cold())
    monkeypatch.setattr(pf.sdk, "_NO_THINK_MODELS", set())

    ok = pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err

    assert ok is True
    deepdive_rows = [l for l in _result_rows(out) if "deepdive-system" in l]
    synthetic_rows = [l for l in _result_rows(out) if "synthetic" in l]
    assert deepdive_rows and synthetic_rows
    assert all(pf.V_MARKER_WITHHELD in l for l in deepdive_rows)
    assert all(pf.V_ANTHROPIC_NOT_HONOURED not in l for l in deepdive_rows)
    assert all(pf.V_ANTHROPIC_NOT_HONOURED in l for l in synthetic_rows)
    assert all(pf.V_MARKER_WITHHELD not in l for l in synthetic_rows)


def test_probe_keeps_not_honoured_when_the_gate_placed_a_marker(monkeypatch, capsys):
    # claude-fable-5's floor is 512 estimated tokens; both prompt shapes clear
    # it, a marker went out on every call, and a 0/0 result stays a genuine
    # gateway question on every row.
    _sdk_gate_defaults(monkeypatch)
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="claude-fable-5", via="sdk")),
    ])
    monkeypatch.setattr(pf, "resolve_model",
                        lambda m: ("claude-fable-5", "sdk", {}))
    monkeypatch.setattr(llm, "prompt", _stub_prompt_stone_cold())
    monkeypatch.setattr(pf.sdk, "_NO_THINK_MODELS", set())

    ok = pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err

    assert ok is True
    rows = _result_rows(out)
    assert rows
    assert all(pf.V_ANTHROPIC_NOT_HONOURED in l for l in rows)
    assert pf.V_MARKER_WITHHELD not in out


def test_probe_never_overrides_a_cli_row(monkeypatch, capsys):
    # via:cli builds its request inside the `claude` subprocess — whether a
    # marker went out is unknowable here (helper returns None), so 0/0 keeps
    # the gateway verdict even for a model/prompt pair the sdk gate would
    # refuse.
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="claude-opus-4-6", via="cli")),
    ])
    monkeypatch.setattr(pf, "resolve_model",
                        lambda m: ("claude-opus-4-6", "cli", {}))
    monkeypatch.setattr(llm, "prompt", _stub_prompt_stone_cold())
    monkeypatch.setattr(pf.sdk, "_NO_THINK_MODELS", set())

    ok = pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err

    assert ok is True
    assert pf.V_MARKER_WITHHELD not in out
    assert pf.V_ANTHROPIC_NOT_HONOURED in out


def test_probe_never_overrides_an_openai_row(monkeypatch, capsys):
    # via:openai places no cache_control markers by design; its 0/0 shape
    # classifies as below-minimum/unstable and must never be rewritten into
    # the marker-withheld verdict (helper returns None).
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: [
        ("deepdive", SimpleNamespace(id="gpt-test", via="openai")),
    ])
    monkeypatch.setattr(pf, "resolve_model", lambda m: ("gpt-test", "openai", {}))

    def fake_prompt(user_prompt, *, model, **kw):
        TOKENS.add({"input_tokens": 8200, "cache_read_input_tokens": 0,
                    "output_tokens": 2})
        return "PONG"

    monkeypatch.setattr(llm, "prompt", fake_prompt)
    monkeypatch.setattr(pf.oai, "_get_client",
                        lambda: SimpleNamespace(base_url="https://api.openai.com/v1"))
    monkeypatch.setattr(pf.sdk, "_NO_THINK_MODELS", set())

    ok = pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err

    assert ok is True
    assert pf.V_MARKER_WITHHELD not in out
    assert pf.V_OPENAI_BELOW_MIN in out


# ─────────────────────────────────────────────────────────────────────────────
# CLI wiring — `doctor --cache-probe`, and `doctor` without it is unchanged
# ─────────────────────────────────────────────────────────────────────────────

def _stub_common_doctor_deps(monkeypatch, *, probe_ok=True):
    from vvaharness.util import environment as env

    fake_cfg = object()
    monkeypatch.setattr("vvaharness.config.load", lambda path: fake_cfg)
    monkeypatch.setattr("vvaharness.orchestrator.configure_backends", lambda cfg, d: None)
    monkeypatch.setattr("vvaharness.orchestrator.probe_backends", lambda cfg: probe_ok)
    monkeypatch.setattr(env, "run_checks", lambda cfg_path: [])
    monkeypatch.setattr(env, "summarize", lambda checks: (0, 0, 0))
    return fake_cfg


def test_doctor_without_flag_never_touches_the_cache_probe(monkeypatch, tmp_path):
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("models: {}\n", encoding="utf-8")
    _stub_common_doctor_deps(monkeypatch, probe_ok=True)

    def must_not_be_called(cfg):
        pytest.fail("run_cache_probe must not be called without --cache-probe")

    monkeypatch.setattr("vvaharness.orchestrator.preflight.run_cache_probe",
                        must_not_be_called)

    rc = cli._doctor(["--config", str(cfg_path)])
    assert rc == 0


def test_doctor_without_flag_return_code_matches_probe_result(monkeypatch, tmp_path):
    # Regression: `doctor` without the flag must behave exactly as it always has —
    # its return code is the ordinary probe's result, nothing more.
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("models: {}\n", encoding="utf-8")
    _stub_common_doctor_deps(monkeypatch, probe_ok=False)
    rc = cli._doctor(["--config", str(cfg_path)])
    assert rc == 1


def test_doctor_with_flag_invokes_the_cache_probe(monkeypatch, tmp_path):
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("models: {}\n", encoding="utf-8")
    _stub_common_doctor_deps(monkeypatch, probe_ok=True)

    calls = {"n": 0}

    def fake_cache_probe(cfg):
        calls["n"] += 1
        return True

    monkeypatch.setattr("vvaharness.orchestrator.preflight.run_cache_probe",
                        fake_cache_probe)

    rc = cli._doctor(["--config", str(cfg_path), "--cache-probe"])
    assert rc == 0
    assert calls["n"] == 1


def test_doctor_with_flag_reports_cache_probe_failure(monkeypatch, tmp_path):
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("models: {}\n", encoding="utf-8")
    _stub_common_doctor_deps(monkeypatch, probe_ok=True)
    monkeypatch.setattr("vvaharness.orchestrator.preflight.run_cache_probe",
                        lambda cfg: False)

    rc = cli._doctor(["--config", str(cfg_path), "--cache-probe"])
    assert rc == 1


def test_doctor_with_flag_skips_cache_probe_when_ordinary_probe_fails(monkeypatch, tmp_path):
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("models: {}\n", encoding="utf-8")
    _stub_common_doctor_deps(monkeypatch, probe_ok=False)

    def must_not_be_called(cfg):
        pytest.fail("cache probe must not run when the ordinary probe failed")

    monkeypatch.setattr("vvaharness.orchestrator.preflight.run_cache_probe",
                        must_not_be_called)

    rc = cli._doctor(["--config", str(cfg_path), "--cache-probe"])
    assert rc == 1


def test_help_documents_cache_probe(capsys):
    cli._print_help()
    out = capsys.readouterr().out
    assert "--cache-probe" in out
    assert "doctor" in out


# ─────────────────────────────────────────────────────────────────────────────
# deepagents arm — target selection, probe flow, withheld override, cost line
# ─────────────────────────────────────────────────────────────────────────────

def _deepagents_role(model_id="claude-da", provider=None):
    return SimpleNamespace(id=model_id, via="deepagents", provider=provider)


def _patch_roles(monkeypatch, roles):
    monkeypatch.setattr(pf, "_iter_model_roles", lambda cfg: roles)
    monkeypatch.setattr(
        pf, "resolve_model",
        lambda m: (m.id, m.via, {}),
    )


def _stub_dispatch_writes_then_reads(user_prompt, **kw):
    """A fake dispatch_prompt behaving like a working block-marker route:
    deepagents usage always carries BOTH cache fields."""
    if user_prompt == pf._USER_MSG_A:
        TOKENS.add({"input_tokens": 50, "cache_creation_input_tokens": 9000,
                    "cache_read_input_tokens": 0, "output_tokens": 2})
    else:
        TOKENS.add({"input_tokens": 50, "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 9000, "output_tokens": 2})
    return "PONG"


def _stub_dispatch_never_caches(user_prompt, **kw):
    """Fields present, values zero: the shape of a gateway stripping markers."""
    TOKENS.add({"input_tokens": 50, "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0, "output_tokens": 2})
    return "PONG"


def _patch_dispatch(monkeypatch, stub):
    import vvaharness.backends.llm.deepagents as deep
    monkeypatch.setattr(deep, "dispatch_prompt", stub)


def test_deepagents_targets_select_and_dedupe(monkeypatch):
    _patch_roles(monkeypatch, [
        ("remediate", _deepagents_role("m3")),
        ("validate", _deepagents_role("m3")),
        ("deepdive", SimpleNamespace(id="m1", via="sdk", provider=None)),
    ])
    targets = pf._deepagents_cache_probe_targets(cfg=object())
    assert set(targets.keys()) == {("m3", "deepagents")}


def test_deepagents_targets_empty_without_deepagents_roles(monkeypatch):
    _patch_roles(monkeypatch, [
        ("deepdive", SimpleNamespace(id="m1", via="sdk", provider=None)),
    ])
    assert pf._deepagents_cache_probe_targets(cfg=object()) == {}


def test_run_cache_probe_deepagents_route_end_to_end(monkeypatch, capsys):
    _patch_roles(monkeypatch, [("remediate", _deepagents_role())])
    _patch_dispatch(monkeypatch, _stub_dispatch_writes_then_reads)

    ok = pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err

    assert ok is True
    assert "claude-da" in out
    assert pf.V_ANTHROPIC_WORKS in out
    assert "1 deepagents pair(s) x 2 calls" in out


def test_deepagents_not_honoured_when_gate_placed_markers(monkeypatch, capsys):
    _patch_roles(monkeypatch, [("remediate", _deepagents_role())])
    _patch_dispatch(monkeypatch, _stub_dispatch_never_caches)

    pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err
    assert pf.V_ANTHROPIC_NOT_HONOURED in out
    assert pf.V_MARKER_WITHHELD not in out


def test_deepagents_withheld_when_kill_switch_off(monkeypatch, capsys):
    _patch_roles(monkeypatch, [("remediate", _deepagents_role())])
    _patch_dispatch(monkeypatch, _stub_dispatch_never_caches)
    cfg = SimpleNamespace(sdk=SimpleNamespace(cache_markers="off"))

    pf.run_cache_probe(cfg=cfg)
    out = capsys.readouterr().err
    assert pf.V_MARKER_WITHHELD in out
    assert pf.V_ANTHROPIC_NOT_HONOURED not in out


def test_deepagents_withheld_for_openai_provider(monkeypatch, capsys):
    # BlockMarkerPromptCaching marks only Anthropic-routed models, so a
    # 0/0 result on an openai-provider role implicates our gate, not the gateway.
    _patch_roles(monkeypatch, [("remediate", _deepagents_role("gpt-da", "openai"))])
    _patch_dispatch(monkeypatch, _stub_dispatch_never_caches)

    pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err
    assert pf.V_MARKER_WITHHELD in out


def test_deepagents_probe_failure_is_reported_not_fatal(monkeypatch, capsys):
    _patch_roles(monkeypatch, [("remediate", _deepagents_role())])

    def boom(*a, **kw):
        raise RuntimeError("connection refused")

    _patch_dispatch(monkeypatch, boom)
    ok = pf.run_cache_probe(cfg=object())
    err = capsys.readouterr().err
    assert ok is False
    assert "FAILED" in err


def test_cost_line_counts_both_arms(monkeypatch, capsys):
    _patch_roles(monkeypatch, [
        ("deepdive", SimpleNamespace(id="m1", via="sdk", provider=None)),
        ("remediate", _deepagents_role()),
    ])
    monkeypatch.setattr(llm, "prompt", _stub_prompt_writes_then_reads())
    monkeypatch.setattr(pf.sdk, "_get_client",
                        lambda: SimpleNamespace(base_url="https://api.anthropic.com/"))
    monkeypatch.setattr(pf.sdk, "_NO_THINK_MODELS", set())
    _patch_dispatch(monkeypatch, _stub_dispatch_writes_then_reads)

    pf.run_cache_probe(cfg=object())
    out = capsys.readouterr().err
    # 1 prompt-route pair x 2 shapes x 2 thinking arms x 2 + 1 deepagents pair x 2.
    assert "10 call(s)" in out
