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

"""s2 threat-model JSON recovery: the bounded repair retry.

Pins the behaviours introduced after a 12-run pygoat benchmark lost the
threat model in 3 of 6 Anthropic cells. The failing responses (recorded in
the runs' errors JSONL under reason=threat_model_parse_failed) showed two
distinct modes, and BOTH arms of the benchmark exhibited the dominant one:

  A. Schema-shape slip — syntactically valid JSON whose `assets` items are
     bare strings ("process integrity, …" / "n/a placeholder replaced
     below") instead of {name, description, sensitivity} objects. Passes
     `extract_json`, dies in `ThreatModel.model_validate`.
  B. Genuine JSON syntax error early in an abnormally short response
     (283 completion tokens against a 64,000 cap — NOT truncation).

A single such response used to discard the entire threat model while the
scan continued at exit 0, silently stripping s3/s4 of threat-derived
targeting. s2 now makes ONE repair retry (the s4 pattern), and a second
failure still raises — these tests pin that the retry is bounded, that a
valid response is untouched, that an unrepairable response fails rather
than producing a half-built model, and that every step of the degradation
is recorded (stderr, errlog reason, COUNTERS).

Deliberately in its own file: tests/test_s2_threatmodel.py is large and
shared, and this file covers exactly one mechanism.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vvaharness.pipeline.stages import s2_threatmodel
from vvaharness.util import errlog
from vvaharness.util.counters import COUNTERS


def _cfg(**step2_kwargs):
    # Same minimal shape test_s2_threatmodel.py uses: baseline off so the
    # prompt has no baseline block, stub model name.
    return SimpleNamespace(
        step2=SimpleNamespace(baseline="none", **step2_kwargs),
        models=SimpleNamespace(threatmodel="stub-model"),
    )


def _valid_response() -> str:
    return json.dumps({
        "system_context": "A small web app.",
        "assets": [{"name": "user-db", "description": "user rows",
                    "sensitivity": "high"}],
        "trust_boundaries": [{"entry_point": "http", "crossing": "unauth -> app",
                              "reachable_assets": ["user-db"]}],
        "threats": [{"id": "T1", "threat": "SQLi exfiltrates user rows",
                     "actor": "remote_unauth", "surface": "http",
                     "asset": "user-db", "impact": "high",
                     "likelihood": "possible"}],
        "open_questions": [],
    })


def _assets_as_strings_response() -> str:
    # Failure mode A verbatim from the benchmark: valid JSON, but `assets`
    # holds bare strings, so extract_json succeeds and model_validate fails
    # with "Input should be a valid dictionary or instance of Asset".
    return json.dumps({
        "system_context": "A small web app.",
        "assets": ["process integrity, learner progress, sensitive business data"],
        "trust_boundaries": [{"entry_point": "http", "crossing": "unauth -> app",
                              "reachable_assets": []}],
        "threats": [],
        "open_questions": [],
    })


# Failure mode B shape: a syntax error (missing comma) early in the body.
_BROKEN_SYNTAX_RESPONSE = '{\n  "system_context": "x"\n  "assets": []\n}'


def _sequence(*responses):
    """Zero-arg callable for PromptStub.set_response that returns each
    response in turn; the stub keys BOTH the original call and the repair
    call to stage "s2" (tag first word), so a per-call sequence is how a
    test distinguishes them. Repeats the last element if called again."""
    it = list(responses)

    def _next() -> str:
        return it.pop(0) if len(it) > 1 else it[0]
    return _next


def _errlog_records() -> list[dict]:
    p = errlog.current_path()
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# Recovery: the two observed malformations are repaired by one retry
# ─────────────────────────────────────────────────────────────────────────────

def test_assets_as_bare_strings_is_repaired_by_one_retry(stub_prompt):
    """The dominant benchmark failure: schema-shape error, not syntax."""
    stub_prompt.set_response(
        "s2", _sequence(_assets_as_strings_response(), _valid_response()))
    tm = s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])

    assert tm.assets[0].name == "user-db"
    assert len(stub_prompt.calls) == 2
    assert stub_prompt.calls[1]["kw"]["tag"] == "s2 threatmodel json-repair"
    assert COUNTERS.get("s2_parse_repair_attempted") == 1
    assert COUNTERS.get("s2_parse_repair_recovered") == 1


def test_json_syntax_error_is_repaired_by_one_retry(stub_prompt):
    """The minority benchmark failure: a real JSONDecodeError."""
    stub_prompt.set_response(
        "s2", _sequence(_BROKEN_SYNTAX_RESPONSE, _valid_response()))
    tm = s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])

    assert tm.threats[0].id == "T1"
    assert COUNTERS.get("s2_parse_repair_recovered") == 1


def test_repair_prompt_carries_error_and_original_response(stub_prompt):
    """The repair model must see WHAT failed and WHY, or it can only guess —
    and it must be told to restructure, not re-imagine."""
    stub_prompt.set_response(
        "s2", _sequence(_assets_as_strings_response(), _valid_response()))
    s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])

    repair_prompt = stub_prompt.calls[1]["prompt"]
    assert "ValidationError" in repair_prompt
    assert "process integrity, learner progress" in repair_prompt
    assert "never a bare string" in repair_prompt


def test_repair_call_reuses_operator_token_cap_not_a_clamp(stub_prompt):
    """s4's repair clamps to 12k because it re-emits per-chunk findings; s2's
    repair re-emits the FULL threat model, so clamping would convert a
    recoverable shape error into a genuine truncation. The retry must reuse
    the operator's configured step2.max_tokens exactly — neither raised nor
    lowered."""
    stub_prompt.set_response(
        "s2", _sequence(_BROKEN_SYNTAX_RESPONSE, _valid_response()))
    s2_threatmodel.run("/nonexistent-repo", "repo",
                       _cfg(max_tokens=64000, timeout=42), [], [])

    repair_kw = stub_prompt.calls[1]["kw"]
    assert repair_kw["max_tokens"] == 64000
    assert repair_kw["timeout"] == 42


# ─────────────────────────────────────────────────────────────────────────────
# No behaviour change on the happy path
# ─────────────────────────────────────────────────────────────────────────────

def test_valid_response_parses_unchanged_with_no_repair_call(stub_prompt):
    stub_prompt.set_response("s2", _valid_response())
    tm = s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])

    assert tm.threats[0].id == "T1"
    assert len(stub_prompt.calls) == 1          # no second model call
    assert COUNTERS.get("s2_parse_repair_attempted") == 0
    assert COUNTERS.get("s2_parse_repair_recovered") == 0


# ─────────────────────────────────────────────────────────────────────────────
# Bounded: a second failure gives up cleanly, loudly, with no half-built model
# ─────────────────────────────────────────────────────────────────────────────

def test_double_failure_raises_after_exactly_one_retry(stub_prompt):
    stub_prompt.set_response("s2", _BROKEN_SYNTAX_RESPONSE)  # broken both times
    with pytest.raises(Exception):
        s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])

    assert len(stub_prompt.calls) == 2          # original + ONE repair, no loop
    assert COUNTERS.get("s2_parse_repair_attempted") == 1
    assert COUNTERS.get("s2_parse_repair_recovered") == 0


def test_truncated_response_fails_rather_than_half_building(stub_prompt):
    """A response cut mid-array is not recoverable by parsing; if the repair
    attempt also returns it, the stage must raise — never hand downstream a
    partially populated ThreatModel."""
    truncated = _valid_response()[:120]         # cut inside the assets object
    stub_prompt.set_response("s2", truncated)
    with pytest.raises(Exception):
        s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])
    assert len(stub_prompt.calls) == 2


def test_repair_call_provider_failure_gives_up_cleanly(stub_prompt):
    """If the repair prompt() itself blows up (rate limit, timeout), that is
    a second failure: raise, don't loop and don't swallow."""
    def _broken_then_boom():
        if not _broken_then_boom.fired:
            _broken_then_boom.fired = True
            return _BROKEN_SYNTAX_RESPONSE
        raise TimeoutError("simulated provider timeout on repair")
    _broken_then_boom.fired = False

    stub_prompt.set_response("s2", _broken_then_boom)
    with pytest.raises(TimeoutError):
        s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])
    assert COUNTERS.get("s2_parse_repair_recovered") == 0


# ─────────────────────────────────────────────────────────────────────────────
# The degradation is reported, not silent
# ─────────────────────────────────────────────────────────────────────────────

def test_permanent_failure_writes_exactly_one_errlog_record(stub_prompt):
    """A run that cannot be recovered errlogs ONCE, not once per attempt.

    counts_by_stage() feeds errors_by_stage in both run_manifest.json and the
    report, so one real failure must not read as two.
    """
    stub_prompt.set_response("s2", _BROKEN_SYNTAX_RESPONSE)
    with pytest.raises(Exception):
        s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])

    reasons = [r.get("reason") for r in _errlog_records()]
    assert reasons.count("threat_model_parse_failed") == 1
    assert "threat_model_parse_retry" not in reasons
    final = next(r for r in _errlog_records()
                 if r.get("reason") == "threat_model_parse_failed")
    # The head of what came back is recorded for a human diagnosing the shape.
    assert final["raw_head"].startswith("{")
    # And the machine-readable consequence is spelled out.
    assert "no" in final["note"] and "threat context" in final["note"]


def test_recovered_repair_writes_no_errlog_record_but_is_still_counted(
        stub_prompt):
    """A recovered slip is a HEALTHY scan and must not be reported as an error.

    Recovery must still be observable — a rising retry rate is the early-warning
    signal for prompt drift — but the visible channel is the counters, which the
    manifest dumps in full. Writing an errlog record here would make any CI gate
    or dashboard keyed on a non-zero s2 error count false-alarm on a run whose
    threat model came out perfect, and would inject a fabricated error delta into
    every before/after comparison.
    """
    stub_prompt.set_response(
        "s2", _sequence(_assets_as_strings_response(), _valid_response()))
    before = COUNTERS.get("s2_parse_repair_recovered")

    s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])

    reasons = [r.get("reason") for r in _errlog_records()]
    assert "threat_model_parse_retry" not in reasons
    assert "threat_model_parse_failed" not in reasons
    assert COUNTERS.get("s2_parse_repair_recovered") == before + 1


def test_raw_head_in_errlog_is_redacted(stub_prompt):
    """raw_head is verbatim model output; errlog redacts string extras, and
    this pins that a credential-shaped value in a failing response never
    reaches the on-disk errors log. Uses an AWS-key shape because that
    redaction pattern is anchored and deterministic."""
    leaky = '{"system_context": "key AKIAABCDEFGHIJKLMNOP",'  # unparseable AND leaky
    stub_prompt.set_response("s2", leaky)
    with pytest.raises(Exception):
        s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])

    text = errlog.current_path().read_text()
    assert "AKIAABCDEFGHIJKLMNOP" not in text


# ─────────────────────────────────────────────────────────────────────────────
# Prompt mitigation for the observed malformation (mitigation, not guarantee)
# ─────────────────────────────────────────────────────────────────────────────

def test_system_prompt_forbids_bare_string_array_elements():
    assert "never a bare string" in s2_threatmodel.SYSTEM
