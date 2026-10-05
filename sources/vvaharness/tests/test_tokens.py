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

"""Unit tests for vvaharness.util.tokens process-wide token accounting."""
import pytest

from vvaharness.util import tokens as tokens_mod
from vvaharness.util.tokens import TOKENS, _TokenCounter, DEFAULT_PHASE


@pytest.fixture(autouse=True)
def _reset_global_tokens():
    """Isolate the process-wide TOKENS singleton across the full suite."""
    TOKENS.reset()
    # _phase is not cleared by reset(); restore it explicitly so test order
    # can never leak a non-default current phase into another test.
    TOKENS._phase = DEFAULT_PHASE
    yield
    TOKENS.reset()
    TOKENS._phase = DEFAULT_PHASE


def _usage(inp=0, out=0, cw=0, cr=0):
    return {
        "input_tokens": inp,
        "output_tokens": out,
        "cache_creation_input_tokens": cw,
        "cache_read_input_tokens": cr,
    }


def test_add_basic_accumulation():
    c = _TokenCounter()
    c.add(_usage(inp=100, out=50))
    assert c.prompt == 100
    assert c.completion == 50
    assert c.calls == 1
    assert c.calls_with_usage == 1


def test_add_accumulates_across_multiple_calls():
    c = _TokenCounter()
    c.add(_usage(inp=10, out=5))
    c.add(_usage(inp=20, out=7))
    assert c.prompt == 30
    assert c.completion == 12
    assert c.calls == 2
    assert c.calls_with_usage == 2


def test_prompt_includes_cache_write_but_not_cache_read():
    # Headline prompt = fresh input + cache-write. cache-read is tracked
    # separately and must NOT inflate the prompt total.
    c = _TokenCounter()
    c.add(_usage(inp=100, out=10, cw=40, cr=1000))
    assert c.prompt == 140  # 100 fresh + 40 cache-write
    assert c.completion == 10
    snap = c.snapshot()
    bucket = snap["by_phase"][DEFAULT_PHASE]
    assert bucket["prompt"] == 140
    assert bucket["cache_write"] == 40
    assert bucket["cache_read"] == 1000


def test_add_none_is_safe_counts_call_only():
    c = _TokenCounter()
    c.add(None)
    assert c.calls == 1
    assert c.calls_with_usage == 0
    assert c.prompt == 0
    assert c.completion == 0
    # The phase bucket records the call even without usage.
    assert c.by_phase[DEFAULT_PHASE]["calls"] == 1


def test_add_non_dict_is_safe():
    c = _TokenCounter()
    c.add("not-a-dict")  # type: ignore[arg-type]
    c.add(12345)  # type: ignore[arg-type]
    assert c.calls == 2
    assert c.calls_with_usage == 0
    assert c.prompt == 0


def test_add_missing_fields_treated_as_zero():
    c = _TokenCounter()
    c.add({})  # empty dict is a dict -> counts as usage but all zeros
    assert c.calls_with_usage == 1
    assert c.prompt == 0
    assert c.completion == 0


def test_add_none_valued_fields_are_none_safe():
    # Anthropic usage dicts often carry None for cache fields.
    c = _TokenCounter()
    c.add({
        "input_tokens": None,
        "output_tokens": 5,
        "cache_creation_input_tokens": None,
        "cache_read_input_tokens": None,
    })
    assert c.prompt == 0
    assert c.completion == 5
    assert c.calls_with_usage == 1


def test_add_record_carrying_calls_counts_requests_not_records():
    """A record that pre-sums a multi-turn session (deepagents SessionUsage)
    carries its model-API-request count under "calls"; both counters advance
    by it, so `calls` means requests on every route and the
    calls == calls_with_usage consistency check keeps holding."""
    c = _TokenCounter()
    c.add({"input_tokens": 100, "output_tokens": 10, "calls": 9})
    assert c.calls == 9
    assert c.calls_with_usage == 9
    assert c.by_phase[DEFAULT_PHASE]["calls"] == 9
    # Token totals are per-record sums, unaffected by the request count.
    assert c.prompt == 100 and c.completion == 10


def test_add_invalid_calls_key_defaults_to_one_request():
    c = _TokenCounter()
    c.add({"input_tokens": 1, "calls": 0})
    c.add({"input_tokens": 1, "calls": -3})
    c.add({"input_tokens": 1, "calls": True})   # bool is not a count
    c.add({"input_tokens": 1, "calls": "9"})    # nor is a string
    assert c.calls == 4
    assert c.calls_with_usage == 4


def test_add_null_completion_count_is_counted_not_smoothed(capsys):
    """An explicit null completion count (seen from some gateways on short
    calls) coerces to 0 for the totals, but the coercion is recorded so a
    run whose completion counts were absent is distinguishable from one that
    genuinely produced no output; the stderr note fires once, not per ping."""
    c = _TokenCounter()
    c.add({"input_tokens": 5, "output_tokens": None})
    c.add({"input_tokens": 5, "output_tokens": None})
    c.add({"input_tokens": 5, "output_tokens": 0})   # a real zero is not absence
    c.add({"input_tokens": 5})                       # absent key keeps the type's default-0 contract
    assert c.completion == 0
    assert c.completion_absent == 2
    assert c.snapshot()["completion_absent"] == 2
    assert capsys.readouterr().err.count("WARN") == 1


def test_reset_clears_completion_absent_and_its_note():
    c = _TokenCounter()
    c.add({"output_tokens": None})
    c.reset()
    assert c.completion_absent == 0
    assert c.snapshot()["completion_absent"] == 0
    assert c._completion_absent_noted == set()


def test_phase_context_routes_to_named_bucket():
    c = _TokenCounter()
    with c.phase("s4"):
        c.add(_usage(inp=10, out=2))
    snap = c.snapshot()
    assert snap["by_phase"]["s4"]["prompt"] == 10
    assert snap["by_phase"]["s4"]["completion"] == 2
    assert snap["by_phase"]["s4"]["calls"] == 1
    assert DEFAULT_PHASE not in snap["by_phase"]


def test_phase_restores_previous_phase():
    c = _TokenCounter()
    assert c._phase == DEFAULT_PHASE
    with c.phase("s6"):
        assert c._phase == "s6"
    assert c._phase == DEFAULT_PHASE


def test_phase_restores_on_exception():
    c = _TokenCounter()
    with pytest.raises(ValueError):
        with c.phase("s9"):
            raise ValueError("boom")
    assert c._phase == DEFAULT_PHASE


def test_phase_nesting_restores_intermediate():
    c = _TokenCounter()
    with c.phase("outer"):
        with c.phase("inner"):
            c.add(_usage(inp=3))
        assert c._phase == "outer"
        c.add(_usage(inp=4))
    snap = c.snapshot()
    assert snap["by_phase"]["inner"]["prompt"] == 3
    assert snap["by_phase"]["outer"]["prompt"] == 4


def test_global_totals_aggregate_across_phases():
    c = _TokenCounter()
    with c.phase("a"):
        c.add(_usage(inp=10, out=1))
    with c.phase("b"):
        c.add(_usage(inp=20, out=2))
    assert c.prompt == 30
    assert c.completion == 3
    assert c.calls == 2


def test_snapshot_shape_and_total():
    c = _TokenCounter()
    c.add(_usage(inp=100, out=50))
    c.add(None)
    snap = c.snapshot()
    assert snap["prompt"] == 100
    assert snap["completion"] == 50
    assert snap["total"] == 150
    assert snap["calls"] == 2
    assert snap["calls_with_usage"] == 1
    assert set(snap.keys()) == {
        "prompt", "completion", "total", "calls",
        "calls_with_usage", "completion_absent", "usd", "turns", "by_phase",
    }
    # No backend reported spend in this fixture, so both read as absent rather than zero.
    assert snap["usd"] is None
    assert snap["turns"] is None


def test_snapshot_by_phase_is_a_copy():
    c = _TokenCounter()
    c.add(_usage(inp=5))
    snap = c.snapshot()
    snap["by_phase"][DEFAULT_PHASE]["prompt"] = 99999
    # Mutating the snapshot must not corrupt the live counter.
    assert c.by_phase[DEFAULT_PHASE]["prompt"] == 5


def test_reset_clears_all_totals_and_phases():
    c = _TokenCounter()
    with c.phase("s4"):
        c.add(_usage(inp=10, out=2))
    c.add(None)
    c.reset()
    assert c.prompt == 0
    assert c.completion == 0
    assert c.calls == 0
    assert c.calls_with_usage == 0
    assert c.snapshot()["by_phase"] == {}


def test_module_singleton_is_token_counter():
    assert isinstance(TOKENS, _TokenCounter)
    assert tokens_mod.TOKENS is TOKENS


def test_singleton_add_and_snapshot():
    # Exercise the actual process-wide singleton (reset by autouse fixture).
    TOKENS.add(_usage(inp=42, out=8, cw=2, cr=500))
    snap = TOKENS.snapshot()
    assert snap["prompt"] == 44  # 42 + 2 cache-write
    assert snap["completion"] == 8
    assert snap["total"] == 52
    assert snap["by_phase"][DEFAULT_PHASE]["cache_read"] == 500


def test_spend_reading_separates_reported_zero_from_unreported():
    """A backend that reports $0 is not the same as one that cannot report at all."""
    from vvaharness.util.tokens import _TokenCounter, reported_between

    c = _TokenCounter()
    before = c.spend()
    c.add({"input_tokens": 10, "output_tokens": 5})            # deepagents: no cost channel
    assert reported_between(before, c.spend()) == (None, None)

    mid = c.spend()
    c.add({"input_tokens": 1}, usd=0.0, turns=0)               # a genuinely free call
    assert reported_between(mid, c.spend()) == (0.0, 0)


def test_spend_delta_is_per_window():
    """Two sequential calls each attribute only their own reported spend."""
    from vvaharness.util.tokens import _TokenCounter, reported_between

    c = _TokenCounter()
    a0 = c.spend()
    c.add({"input_tokens": 1}, usd=0.25, turns=3)
    a1 = c.spend()
    c.add({"input_tokens": 1}, usd=0.75, turns=4)
    a2 = c.spend()

    assert reported_between(a0, a1) == (0.25, 3)
    assert reported_between(a1, a2) == (0.75, 4)               # not the cumulative 1.00 / 7
