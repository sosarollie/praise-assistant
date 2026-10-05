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

"""Tests for DeepAgents token-usage recovery.

Nothing populates the graph-state ``usage`` key on the DeepAgents route, so
the terminal HarnessResult (and hence the session JSONL result record and
stage telemetry) previously reported ``usage: null``. These tests cover the
aggregator's key normalization, the streaming accumulator's de-duplication and
per-persona attribution, the terminal-result fallback chain, and that a
recovered usage dict survives serialization into the session log.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from anthropic._models import construct_type
from anthropic.types import Usage
from langchain_anthropic.chat_models import _create_usage_metadata
from langchain_core.messages import AIMessage, HumanMessage

from vvaharness.backends.harness.deepagents.translate import (
    make_terminal_result,
    translate_final_state,
)
from vvaharness.backends.harness.deepagents import usage as usage_mod
from vvaharness.backends.harness.deepagents.usage import (
    UsageAccumulator,
    aggregate_usage_metadata,
)
from vvaharness.backends.harness.models import (
    HarnessMessage,
    HarnessSessionInit,
)
from vvaharness.util.tokens import TOKENS
from vvaharness.validation.constants.artifacts import SESSION_LOG_FILENAME
from vvaharness.validation.io.message_logger import stream_and_log


def _usage(
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_read: int = 0,
    cache_creation: int = 0,
) -> dict:
    """LangChain usage_metadata shape: input_tokens is TOTAL input incl. cache."""
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "input_token_details": {
            "cache_read": cache_read,
            "cache_creation": cache_creation,
        },
    }


def _ephemeral_usage(
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_read: int = 0,
    ephemeral_5m: int = 0,
    ephemeral_1h: int = 0,
) -> dict:
    """The shape langchain-anthropic emits for a TTL'd cache write.

    ``_create_usage_metadata`` (langchain_anthropic/chat_models.py) copies the
    ephemeral_5m/1h keys into ``input_token_details`` and ZEROES the generic
    ``cache_creation`` when their sum is positive, so the write spend lives
    only under the ephemeral keys.
    """
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "input_token_details": {
            "cache_read": cache_read,
            "cache_creation": 0,  # zeroed upstream in favour of the TTL keys
            "ephemeral_5m_input_tokens": ephemeral_5m,
            "ephemeral_1h_input_tokens": ephemeral_1h,
        },
    }


def _ai(
    msg_id: str | None = "m1",
    usage: dict | None = None,
    name: str | None = None,
    raw_usage: dict | None = None,
) -> AIMessage:
    meta = {"usage": raw_usage} if raw_usage is not None else {}
    return AIMessage(content="ok", id=msg_id, name=name, usage_metadata=usage,
                     response_metadata=meta)


# aggregate_usage_metadata

def test_cache_write_recovered_from_raw_response_usage():
    """A gateway can fold the write into input_tokens yet omit the detail key."""
    usage = aggregate_usage_metadata([_ai(
        "a",
        _usage(input_tokens=5791, output_tokens=7, cache_read=0,
               cache_creation=0),
        raw_usage={"input_tokens": 41, "cache_creation_input_tokens": 5750},
    )])

    assert usage is not None
    assert usage.get("cache_creation_input_tokens") == 5750
    assert usage.get("input_tokens") == 41


def test_cache_write_recovered_from_raw_nested_ephemeral():
    usage = aggregate_usage_metadata([_ai(
        "a",
        _usage(input_tokens=1100, output_tokens=5),
        raw_usage={"cache_creation": {"ephemeral_5m_input_tokens": 1000}},
    )])

    assert usage is not None
    assert usage.get("cache_creation_input_tokens") == 1000
    assert usage.get("input_tokens") == 100


def test_usage_metadata_detail_beats_raw_fallback():
    """The raw dict is a fallback only; a populated detail key wins untouched."""
    usage = aggregate_usage_metadata([_ai(
        "a",
        _ephemeral_usage(input_tokens=1100, output_tokens=5, ephemeral_5m=900),
        raw_usage={"cache_creation_input_tokens": 555},
    )])

    assert usage is not None
    assert usage.get("cache_creation_input_tokens") == 900


def test_aggregate_normalizes_fresh_input_from_total():
    """LangChain input_tokens is total input; cache counts are split out."""
    usage = aggregate_usage_metadata(
        [_ai("a", _usage(input_tokens=100, output_tokens=20, cache_read=30, cache_creation=10))]
    )
    assert usage == {
        "input_tokens": 60,
        "output_tokens": 20,
        "cache_read_input_tokens": 30,
        "cache_creation_input_tokens": 10,
        "calls": 1,
    }


def test_aggregate_sums_across_messages_and_ignores_non_ai():
    usage = aggregate_usage_metadata(
        [
            HumanMessage(content="hi"),
            _ai("a", _usage(input_tokens=10, output_tokens=1)),
            _ai("b", _usage(input_tokens=20, output_tokens=2, cache_read=5)),
            _ai("c"),
        ]
    )
    assert usage == {
        "input_tokens": 25,
        "output_tokens": 3,
        "cache_read_input_tokens": 5,
        "cache_creation_input_tokens": 0,
        "calls": 2,
    }


def test_aggregate_returns_none_when_no_message_carries_usage():
    assert aggregate_usage_metadata([HumanMessage(content="hi"), _ai()]) is None
    assert aggregate_usage_metadata([]) is None


def test_aggregate_handles_missing_cache_details():
    message = AIMessage(
        content="ok",
        id="a",
        usage_metadata={"input_tokens": 7, "output_tokens": 3, "total_tokens": 10},
    )
    usage = aggregate_usage_metadata([message])
    assert usage == {
        "input_tokens": 7,
        "output_tokens": 3,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "calls": 1,
    }


def test_aggregate_counts_ephemeral_cache_writes():
    """A TTL'd cache write (generic cache_creation zeroed, spend under the
    ephemeral_5m/1h keys) must be counted as cache-creation — before the fix
    it reported 0 and S10/S11 cache-write spend was priced at 1.0x instead of
    the 1.25x write multiplier."""
    usage = aggregate_usage_metadata(
        [_ai("a", _ephemeral_usage(input_tokens=200, output_tokens=20,
                                   cache_read=30, ephemeral_5m=100,
                                   ephemeral_1h=50))]
    )
    assert usage == {
        "input_tokens": 20,  # 200 total - 30 read - 150 written
        "output_tokens": 20,
        "cache_read_input_tokens": 30,
        "cache_creation_input_tokens": 150,
        "calls": 1,
    }


def test_aggregate_never_double_counts_generic_and_ephemeral_writes():
    """Defensive: if a producer ever populates BOTH shapes, the ephemeral sum
    wins (mirroring upstream, which zeroes the generic key for that reason) —
    the write must not be billed twice."""
    meta = _ephemeral_usage(input_tokens=100, ephemeral_5m=40)
    meta["input_token_details"]["cache_creation"] = 40  # hostile double report
    usage = aggregate_usage_metadata([_ai("a", meta)])
    assert usage is not None
    assert usage["cache_creation_input_tokens"] == 40
    assert usage["input_tokens"] == 60


def test_aggregate_zero_ephemeral_keys_fall_back_to_generic():
    """Ephemeral keys present but zero (no TTL breakdown reported): the
    generic cache_creation still counts."""
    meta = _ephemeral_usage(input_tokens=50)
    meta["input_token_details"]["cache_creation"] = 10  # upstream kept generic
    usage = aggregate_usage_metadata([_ai("a", meta)])
    assert usage is not None
    assert usage["cache_creation_input_tokens"] == 10
    assert usage["input_tokens"] == 40


def test_aggregate_flags_record_violating_inclusive_contract(capsys, monkeypatch):
    """Cache counts exceeding total input violate the inclusive UsageMetadata
    contract (input_tokens = sum of ALL input token types): the record is an
    exclusive-convention gateway's, so input_tokens is already fresh. It must
    be kept as fresh input — not clamped to zero, which would silently
    under-count — and the violation must be visibly flagged."""
    monkeypatch.setattr(usage_mod, "_EXCLUSIVE_USAGE_WARNED", set())
    usage = aggregate_usage_metadata(
        [_ai("a", _usage(input_tokens=10, cache_read=20, cache_creation=5))]
    )
    assert usage is not None
    assert usage["input_tokens"] == 10  # treated as already fresh
    assert usage["cache_read_input_tokens"] == 20
    assert usage["cache_creation_input_tokens"] == 5
    err = capsys.readouterr().err
    assert "WARN" in err and "cached input" in err


def test_inclusive_contract_warning_fires_once_per_process(capsys, monkeypatch):
    """An exclusive gateway violates on every record; one WARN is the signal,
    per-record repeats would be log spam. The corrective treatment still
    applies to every violating record."""
    monkeypatch.setattr(usage_mod, "_EXCLUSIVE_USAGE_WARNED", set())
    usage = aggregate_usage_metadata(
        [
            _ai("a", _usage(input_tokens=1, cache_read=50)),
            _ai("b", _usage(input_tokens=2, cache_read=60)),
        ]
    )
    assert usage is not None
    assert usage["input_tokens"] == 3  # both records treated as fresh
    assert capsys.readouterr().err.count("WARN") == 1


# UsageAccumulator: streaming events, dedup, subagent attribution

def _event(namespace: tuple[str, ...], *messages: AIMessage) -> tuple:
    return (namespace, {"agent": {"messages": list(messages)}})


def test_accumulator_counts_message_seen_twice_only_once():
    acc = UsageAccumulator()
    message = _ai("dup", _usage(input_tokens=10, output_tokens=5))
    acc.add_event(_event((), message))
    acc.add_event(_event((), message))
    acc.add_message(message)
    usage = acc.snapshot()
    assert usage is not None
    assert usage["input_tokens"] == 10 and usage["output_tokens"] == 5


def test_accumulator_folds_subagent_turns_into_totals_and_breakdown():
    acc = UsageAccumulator()
    acc.add_event(_event((), _ai("p1", _usage(input_tokens=100, output_tokens=10))))
    acc.add_event(
        _event(
            ("task:abc123",),
            _ai("s1", _usage(input_tokens=40, output_tokens=4), name="penetration-tester"),
        )
    )
    acc.add_event(
        _event(
            ("task:abc123",),
            _ai("s2", _usage(input_tokens=60, output_tokens=6), name="penetration-tester"),
        )
    )
    usage = acc.snapshot()
    assert usage is not None
    assert usage["input_tokens"] == 200
    assert usage["output_tokens"] == 20
    assert usage["subagents"] == {
        "penetration-tester": {
            "input_tokens": 100,
            "output_tokens": 10,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        }
    }


def test_accumulator_learns_persona_name_for_unnamed_turns():
    """A named turn teaches the namespace; later unnamed turns inherit it."""
    acc = UsageAccumulator()
    acc.add_event(
        _event(("task:x",), _ai("s1", _usage(input_tokens=1), name="security-architect"))
    )
    acc.add_event(_event(("task:x",), _ai("s2", _usage(input_tokens=2))))
    usage = acc.snapshot()
    assert usage is not None
    subagents = usage["subagents"]
    assert isinstance(subagents, dict)
    assert list(subagents) == ["security-architect"]
    assert subagents["security-architect"]["input_tokens"] == 3


def test_accumulator_falls_back_to_namespace_node_label():
    acc = UsageAccumulator()
    acc.add_event(_event(("task:abc123",), _ai("s1", _usage(input_tokens=5))))
    usage = acc.snapshot()
    assert usage is not None
    assert usage["subagents"] == {
        "task": {
            "input_tokens": 5,
            "output_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        }
    }


def test_accumulator_snapshot_reports_per_request_call_count():
    """A multi-turn session reports the number of model API requests (one per
    usage-bearing turn, de-duplicated across stream/final-state sightings) —
    not one pre-summed record. This is what makes ``calls`` mean the same
    thing on the deepagents route as on the per-turn backends."""
    acc = UsageAccumulator()
    dup = _ai("dup", _usage(input_tokens=1, output_tokens=1))
    acc.add_event(_event((), _ai("t1", _usage(input_tokens=10, output_tokens=1))))
    acc.add_event(_event((), _ai("t2", _usage(input_tokens=20, output_tokens=2))))
    acc.add_event(_event((), dup))
    acc.add_event(_event((), dup))  # second sighting must not inflate the count
    acc.add_event(_event((), _ai("no-usage")))  # zero-usage turn is not a call
    usage = acc.snapshot()
    assert usage is not None
    assert usage["calls"] == 3


def test_session_record_advances_calls_and_calls_with_usage_together():
    """One pre-summed session record advances totals.calls AND
    totals.calls_with_usage by its per-request count, so the pair stays
    mutually consistent (calls == calls_with_usage) at request granularity
    and per-call metrics are comparable across routes."""
    make_terminal_result(
        {"messages": [
            _ai("a", _usage(input_tokens=10, output_tokens=1)),
            _ai("b", _usage(input_tokens=20, output_tokens=2)),
            _ai("c", _usage(input_tokens=30, output_tokens=3)),
        ]}
    )
    snap = TOKENS.snapshot()
    assert snap["calls"] == 3
    assert snap["calls_with_usage"] == 3
    assert snap["prompt"] == 60
    # The per-phase bucket the stage telemetry sums carries the same count.
    assert sum(b["calls"] for b in snap["by_phase"].values()) == 3


def test_accumulator_snapshot_none_when_empty():
    acc = UsageAccumulator()
    acc.add_event(_event((), _ai()))
    acc.add_event({"agent": {"messages": [HumanMessage(content="hi")]}})
    assert acc.snapshot() is None


def test_accumulator_tolerates_malformed_events():
    acc = UsageAccumulator()
    acc.add_event(("only-one-element",))
    acc.add_event((None, None))
    acc.add_event({"agent": "not-a-dict"})
    acc.add_event({"agent": {"messages": "not-a-list"}})
    assert acc.snapshot() is None


# make_terminal_result fallback chain

def test_terminal_result_prefers_explicit_state_usage():
    state_usage: dict[str, object] = {"input_tokens": 1, "output_tokens": 2}
    terminal = make_terminal_result(
        {"messages": [_ai("a", _usage(input_tokens=99))], "usage": state_usage},
        stream_usage={"input_tokens": 50},
    )
    assert terminal.usage == state_usage


def test_terminal_result_uses_stream_usage_when_state_usage_missing():
    stream_usage: dict[str, object] = {"input_tokens": 50, "output_tokens": 5}
    terminal = make_terminal_result(
        {"messages": [_ai("a", _usage(input_tokens=99))]}, stream_usage=stream_usage
    )
    assert terminal.usage == stream_usage
    assert TOKENS.snapshot()["prompt"] == 50


def test_terminal_result_aggregates_state_messages_without_stream():
    terminal = make_terminal_result(
        {"messages": [_ai("a", _usage(input_tokens=30, output_tokens=7, cache_creation=8))]}
    )
    assert terminal.usage == {
        "input_tokens": 22,
        "output_tokens": 7,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 8,
        "calls": 1,
    }
    snap = TOKENS.snapshot()
    assert snap["prompt"] == 30 and snap["completion"] == 7


def test_terminal_result_ephemeral_cache_write_reaches_billable_counters():
    """End to end: a TTL'd cache write lands in the recovered usage AND in the
    process token counter's billable side (prompt = fresh + cache-write, plus
    the per-phase cache_write bucket the pricing layer multiplies at 1.25x)."""
    terminal = make_terminal_result(
        {"messages": [_ai("a", _ephemeral_usage(input_tokens=100, output_tokens=5,
                                                ephemeral_5m=60, ephemeral_1h=15))]}
    )
    assert terminal.usage == {
        "input_tokens": 25,  # 100 total - 75 written
        "output_tokens": 5,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 75,
        "calls": 1,
    }
    snap = TOKENS.snapshot()
    assert snap["prompt"] == 100  # fresh 25 + cache-write 75, both billable
    assert sum(b["cache_write"] for b in snap["by_phase"].values()) == 75


def test_terminal_result_usage_none_when_nothing_available():
    terminal = make_terminal_result({"messages": [_ai()]})
    assert terminal.usage is None
    assert TOKENS.snapshot()["calls_with_usage"] == 0


# translate_final_state (one-shot path)

def test_oneshot_result_carries_aggregated_usage():
    result = translate_final_state(
        {"messages": [_ai("a", _usage(input_tokens=12, output_tokens=3))]}
    )
    assert result.result_text == "ok"
    assert result.usage == {
        "input_tokens": 12,
        "output_tokens": 3,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "calls": 1,
    }
    assert TOKENS.snapshot()["prompt"] == 12


def test_oneshot_structured_response_still_counts_usage():
    state = {
        "structured_response": {"verdict": "FIXED"},
        "messages": [_ai("a", _usage(input_tokens=9, output_tokens=1))],
    }
    result = translate_final_state(state)
    assert result.usage is not None
    assert result.usage["input_tokens"] == 9


# session log integration

def test_session_log_terminal_record_has_non_null_usage(tmp_path: Path):
    """The JSONL result record carries recovered usage end to end."""
    terminal = make_terminal_result(
        {"messages": [_ai("a", _usage(input_tokens=100, output_tokens=10, cache_read=40))]},
        session_id="sess1",
    )

    async def _messages() -> AsyncIterator[HarnessMessage]:
        yield HarnessSessionInit(session_id="sess1")
        yield terminal

    exit_code, session_id = asyncio.run(
        stream_and_log(_messages(), tmp_path, "sess1", live=False)
    )
    assert exit_code == 0 and session_id == "sess1"
    records = [
        json.loads(line)
        for line in (tmp_path / SESSION_LOG_FILENAME).read_text().splitlines()
    ]
    result_record = records[-1]
    assert result_record["kind"] == "result"
    assert result_record["usage"] == {
        "input_tokens": 60,
        "output_tokens": 10,
        "cache_read_input_tokens": 40,
        "cache_creation_input_tokens": 0,
        "calls": 1,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Gateway-shape pinning: exact wire usage shapes fed through the REAL
# anthropic lenient parse and langchain _create_usage_metadata, then _Counts.
# The builders above hand-shape usage_metadata; these pins guarantee the
# hand-shaped dicts match what the installed libraries actually produce.
# ─────────────────────────────────────────────────────────────────────────────


def _wire_usage(payload: dict):
    """Parse a wire-shaped usage dict exactly as the SDK response path does."""
    return construct_type(type_=Usage, value=payload)


def _meta_from_wire(payload: dict) -> dict:
    return dict(_create_usage_metadata(_wire_usage(payload)))


# The gateway's observed write-shape (live probe: turn-1 of an agentic
# session): flat creation AND the nested TTL breakdown, both ints.
_GATEWAY_WRITE_SHAPE = {
    "input_tokens": 3,
    "output_tokens": 59,
    "cache_read_input_tokens": 1980,
    "cache_creation_input_tokens": 1115,
    "cache_creation": {"ephemeral_5m_input_tokens": 1115, "ephemeral_1h_input_tokens": 0},
}

# The gateway's observed no-write shape: every cache count an explicit zero.
_GATEWAY_NOWRITE_SHAPE = {
    "input_tokens": 4556,
    "output_tokens": 111,
    "cache_read_input_tokens": 0,
    "cache_creation_input_tokens": 0,
    "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0},
}

# A defensively-null gateway shape: fields present, values null.
_NULL_TOPLEVEL_SHAPE = {
    "input_tokens": 3,
    "output_tokens": 59,
    "cache_read_input_tokens": None,
    "cache_creation_input_tokens": None,
    "cache_creation": None,
}


def test_gateway_write_shape_counts_creation_once():
    meta = _meta_from_wire(_GATEWAY_WRITE_SHAPE)
    # langchain moves the TTL'd write under the ephemeral key and zeroes the
    # generic one; input_tokens becomes the inclusive total.
    assert meta["input_tokens"] == 3 + 1980 + 1115
    assert meta["input_token_details"]["ephemeral_5m_input_tokens"] == 1115
    assert meta["input_token_details"]["cache_creation"] == 0

    counts = usage_mod._Counts()
    counts.add(meta, _GATEWAY_WRITE_SHAPE)
    assert counts.cache_creation == 1115  # once — not doubled by the raw fallback
    assert counts.cache_read == 1980
    assert counts.input_tokens == 3


def test_gateway_nowrite_shape_stays_zero():
    meta = _meta_from_wire(_GATEWAY_NOWRITE_SHAPE)
    counts = usage_mod._Counts()
    counts.add(meta, _GATEWAY_NOWRITE_SHAPE)
    assert counts.cache_creation == 0
    assert counts.cache_read == 0
    assert counts.input_tokens == 4556


def test_null_toplevel_shape_is_all_zero_not_a_crash():
    meta = _meta_from_wire(_NULL_TOPLEVEL_SHAPE)
    counts = usage_mod._Counts()
    counts.add(meta, _NULL_TOPLEVEL_SHAPE)
    assert counts.cache_creation == 0
    assert counts.cache_read == 0
    assert counts.input_tokens == 3


def test_folded_write_shape_recovers_creation_from_raw():
    # A gateway that omits the detail keys from usage_metadata but still
    # carries the flat creation count in the provider-raw dict.
    meta = {"input_tokens": 5115, "output_tokens": 10, "total_tokens": 5125,
            "input_token_details": {"cache_read": 4000}}
    raw = {"input_tokens": 5115, "cache_read_input_tokens": 4000,
           "cache_creation_input_tokens": 1115}
    counts = usage_mod._Counts()
    counts.add(meta, raw)
    assert counts.cache_creation == 1115
    assert counts.input_tokens == 5115 - 4000 - 1115


def test_null_nested_raw_never_masks_flat_creation():
    # _raw_cache_creation must read the flat key first; a null-shaped nested
    # breakdown cannot mask it.
    raw = {"cache_creation_input_tokens": 1115,
           "cache_creation": {"ephemeral_5m_input_tokens": None,
                              "ephemeral_1h_input_tokens": None}}
    assert usage_mod._raw_cache_creation(raw) == 1115


def test_null_valued_nested_raw_alone_is_zero():
    raw = {"cache_creation": {"ephemeral_5m_input_tokens": None,
                              "ephemeral_1h_input_tokens": None}}
    assert usage_mod._raw_cache_creation(raw) == 0


def test_streaming_dead_path_empty_response_metadata():
    # An AIMessage with usage_metadata but empty response_metadata: the raw
    # fallback has nothing to read and must contribute nothing.
    message = AIMessage(
        content="x",
        id="m-dead-path",
        usage_metadata=_ephemeral_usage(
            input_tokens=100, output_tokens=5, cache_read=40, ephemeral_5m=20
        ),
    )
    accumulator = UsageAccumulator()
    accumulator.add_message(message)
    snapshot = accumulator.snapshot()
    assert snapshot is not None
    assert snapshot["cache_creation_input_tokens"] == 20
    assert snapshot["cache_read_input_tokens"] == 40


def test_upstream_lenient_null_nested_values_typeerror_tripwire():
    # Upstream tripwire, not our contract: through the SDK's LENIENT response
    # parse a gateway may hand langchain a CacheCreation whose values are
    # None, and _create_usage_metadata (langchain-anthropic 1.7.x) raises
    # TypeError before any usage reaches this package. Our gateway sends
    # ints (live-verified), so this cannot fire in practice. If an upgrade
    # makes this test fail, the upstream bug was fixed — delete the pin.
    shape = {
        "input_tokens": 3,
        "output_tokens": 59,
        "cache_read_input_tokens": 1980,
        "cache_creation_input_tokens": 1115,
        "cache_creation": {"ephemeral_5m_input_tokens": None,
                           "ephemeral_1h_input_tokens": None},
    }
    with pytest.raises(TypeError):
        _meta_from_wire(shape)
