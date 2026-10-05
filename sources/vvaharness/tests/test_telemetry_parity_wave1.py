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

"""Wave-1 accounting parity and anomaly-persistence tests.

Three defects found by the via:deepagents live-test campaign, pinned here so
they cannot regress:

1. ``totals.unattributed`` recorded only prompt/completion/calls while the
   token totals summed EVERY phase bucket, so a manifest whose out-of-stage
   calls touched a prompt cache could not be reconciled against itself
   (opus48: stage cache_write summed to 3,838 against totals of 9,180; the
   5,342-token preflight-probe delta was reportable nowhere; live in 5 of 12
   campaign arms). The identity ``Σ stages + unattributed == totals`` must
   now hold for every token key.

2. ``completion_absent`` was defeated at source on the openai route:
   ``_normalise_usage`` coerced a null completion count with ``or 0`` BEFORE
   ``TOKENS.add``, so the counter documented as keeping absent counts
   distinguishable from genuine zeros could never fire there. (The
   null-completion test below fails against the pre-fix HEAD by design.)

3. ``completion_absent`` and the per-phase ``cache_unparsed`` counters never
   reached the manifest despite docstrings promising machine visibility —
   they died at the ``TOKENS.snapshot()`` boundary. Both must now appear in
   the composed ``totals``.

Plus a regression guard on the settled ``prompt_tokens`` semantics: headline
prompt is billable input (fresh + cache-write) and NEVER includes cache
reads — total input volume is ``prompt_tokens + cache_read_tokens``. An
earlier analysis wrongly called this double-counting; it is by design.

Everything here is synthetic snapshots and in-process counters — no scan, no
model call, no filesystem.
"""
from __future__ import annotations

from vvaharness.backends.llm.openai import _normalise_usage
from vvaharness.util import stage_telemetry as st
from vvaharness.util.tokens import TOKENS, DEFAULT_PHASE, _TokenCounter


def _bucket(prompt=0, completion=0, cache_read=0, cache_write=0, calls=1):
    return st.TokenBucket(prompt=prompt, completion=completion,
                          cache_read=cache_read, cache_write=cache_write,
                          calls=calls)


# The token keys shared by stage rows, the unattributed bucket and totals,
# mapped to their totals spelling. Parity means: for EVERY one of these,
# summing the stage rows and the unattributed bucket reproduces the total.
_KEY_TO_TOTAL = {
    "prompt": "prompt_tokens",
    "completion": "completion_tokens",
    "cache_read": "cache_read_tokens",
    "cache_write": "cache_write_tokens",
    "calls": "calls",
}


# ---------------------------------------------------------------------------
# 1. full-key reconciliation: Σ stages + unattributed == totals
# ---------------------------------------------------------------------------

def test_stage_rows_plus_unattributed_reconcile_to_totals_for_every_key():
    """A run whose unmapped phases carry cache traffic (the opus48 shape:
    preflight probe cache writes) must still reconcile per key from the
    manifest alone."""
    by_phase = {
        "s2-threatmodel": _bucket(prompt=1_000, completion=200,
                                  cache_read=300, cache_write=2_838, calls=3),
        "s4-deepdive": _bucket(prompt=4_000, completion=800,
                               cache_read=1_200, cache_write=1_000, calls=7),
        # Unmapped: the preflight cache probe — 916 fresh + 5,342 cache-write
        # billed as prompt, exactly the population the truncated bucket lost.
        DEFAULT_PHASE: _bucket(prompt=6_258, completion=16,
                               cache_read=128, cache_write=5_342, calls=2),
    }
    prompt = sum(b["prompt"] for b in by_phase.values())
    completion = sum(b["completion"] for b in by_phase.values())
    calls = sum(b["calls"] for b in by_phase.values())
    token_snap = st.TokenSnapshot(prompt=prompt, completion=completion,
                                  total=prompt + completion, calls=calls,
                                  calls_with_usage=calls, by_phase=by_phase)

    section = st.compose_stage_section({}, token_snap, {}, None)
    stages = section["stages"]
    totals = section["totals"]
    unattributed = totals["unattributed"]

    for key, total_key in _KEY_TO_TOTAL.items():
        stage_sum = sum(entry["tokens"].get(key, 0)
                        for entry in stages.values())
        assert stage_sum + unattributed[key] == totals[total_key], (
            f"Σ stages + unattributed != totals for {key!r}")

    # The concrete campaign gap: unattributed cache_write is the 5,342 delta.
    assert unattributed["cache_write"] == 5_342
    assert unattributed["cache_read"] == 128


# ponytail: the zero-case shape pin (unattributed carries the full five-key
# set even when every phase maps) lives in the module's home suite —
# tests/test_stage_telemetry.py::test_unattributed_is_zero_when_every_phase_maps
# — not here. It was duplicated verbatim in both files during the wave-1
# coordination pass; one copy in the suite a compose_stage_section maintainer
# actually opens is the one that earns its run time.


# ---------------------------------------------------------------------------
# 2. the openai route must let a null completion reach the counter
# ---------------------------------------------------------------------------
# NOTE: these fail against pre-fix HEAD by design — _normalise_usage coerced
# the null with `or 0` before TOKENS.add, so completion_absent stayed 0.

def test_null_completion_on_openai_path_increments_completion_absent():
    """The gemini36-oai preflight shape: usage arrives with an explicit null
    completion count. The counter — not a silent zero — must record it."""
    TOKENS.add(_normalise_usage({
        "prompt_tokens": 12, "completion_tokens": None, "total_tokens": 12,
        "prompt_tokens_details": {"cached_tokens": 0},
    }))
    assert TOKENS.completion_absent == 1
    # ...and the coercion to 0 still happens downstream, in TOKENS.add: the
    # totals must not crash and must bill nothing for the absent count.
    assert TOKENS.completion == 0
    assert TOKENS.prompt == 12
    assert TOKENS.calls_with_usage == 1


def test_omitted_completion_field_on_openai_path_counts_as_absent():
    """A gateway that omits the field entirely is also an absent count, not a
    genuine zero."""
    TOKENS.add(_normalise_usage({"prompt_tokens": 7}))
    assert TOKENS.completion_absent == 1
    assert TOKENS.completion == 0


def test_explicit_zero_completion_is_a_real_zero_not_an_absence():
    """An explicit 0 is data (the model produced no output); it must never
    inflate the anomaly counter."""
    TOKENS.add(_normalise_usage({"prompt_tokens": 9, "completion_tokens": 0}))
    assert TOKENS.completion_absent == 0
    assert TOKENS.completion == 0
    assert TOKENS.calls_with_usage == 1


# ---------------------------------------------------------------------------
# 3. the anomaly counters must survive into the composed manifest section
# ---------------------------------------------------------------------------

def test_completion_absent_and_cache_unparsed_reach_the_composed_totals():
    """Cross the documented gap end-to-end: counter -> snapshot ->
    compose_stage_section -> totals. Both counters' docstrings promise
    machine visibility; the manifest is the machine-readable artifact."""
    c = _TokenCounter()
    with c.phase("s4-deepdive"):
        c.add({"input_tokens": 10, "output_tokens": None})
        c.note_cache_unparsed(("cacheReadInputTokens",), via="bedrock")
        c.note_cache_unparsed(("cacheReadInputTokens",), via="bedrock")
    with c.phase("s6-verify"):
        c.note_cache_unparsed(("prompt_tokens_details.custom",), via="openai")

    totals = st.compose_stage_section({}, c.snapshot(), {}, None)["totals"]

    assert totals["completion_absent"] == 1
    # cache_unparsed counts CALLS, per phase; the total spans every phase.
    assert totals["cache_unparsed_calls"] == 3


def test_anomaly_totals_are_zero_on_a_clean_run():
    c = _TokenCounter()
    with c.phase("s4-deepdive"):
        c.add({"input_tokens": 10, "output_tokens": 5})
    totals = st.compose_stage_section({}, c.snapshot(), {}, None)["totals"]
    assert totals["completion_absent"] == 0
    assert totals["cache_unparsed_calls"] == 0


# ---------------------------------------------------------------------------
# 4. regression guard: prompt_tokens stays fresh(+cache-write) only
# ---------------------------------------------------------------------------

def test_prompt_tokens_is_billable_input_and_never_includes_cache_reads():
    """Settled semantics (do NOT 'fix' this as double-counting — that claim
    was made once and corrected): headline prompt = fresh + cache-write;
    cache reads are tracked separately; total input volume is
    prompt_tokens + cache_read_tokens."""
    c = _TokenCounter()
    with c.phase("s4-deepdive"):
        c.add({"input_tokens": 100, "output_tokens": 10,
               "cache_creation_input_tokens": 40,
               "cache_read_input_tokens": 1_000})

    totals = st.compose_stage_section({}, c.snapshot(), {}, None)["totals"]

    assert totals["prompt_tokens"] == 140          # fresh + cache-write
    assert totals["cache_read_tokens"] == 1_000    # separate, not conflated
    assert totals["cache_write_tokens"] == 40
    # total_tokens is prompt + completion by design (cache reads excluded);
    # a reader wanting input volume adds cache_read_tokens back explicitly.
    assert totals["total_tokens"] == 150
    assert totals["prompt_tokens"] + totals["cache_read_tokens"] == 1_140
