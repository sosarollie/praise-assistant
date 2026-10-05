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

"""Unit tests for vvaharness.util.stage_telemetry.

Two halves: the STAGES recorder lifecycle (a process-global singleton, reset by
the autouse conftest fixture), and compose_stage_section() — a pure composer
exercised with literal snapshots and an in-memory price table, so no scan, no
model call and no filesystem access is involved.
"""
from __future__ import annotations

import pytest

from vvaharness.util import stage_telemetry as st
from vvaharness.util.pricing import (CacheRateDefaults, ModelPricing,
                                     PricingTable)


def _bucket(prompt=0, completion=0, cache_read=0, cache_write=0, calls=1):
    return st.TokenBucket(prompt=prompt, completion=completion,
                          cache_read=cache_read, cache_write=cache_write,
                          calls=calls)


def _token_snap(by_phase, *, prompt=0, completion=0, calls=0,
                calls_with_usage=0):
    return st.TokenSnapshot(prompt=prompt, completion=completion,
                            total=prompt + completion, calls=calls,
                            calls_with_usage=calls_with_usage,
                            by_phase=by_phase)


def _table(models, *, source="config"):
    return PricingTable(models=models, path="/prices/gateway.yaml",
                        sha256="abc123", source=source)


# ---------------------------------------------------------------------------
# recorder lifecycle
# ---------------------------------------------------------------------------

def test_start_records_running_stage():
    st.STAGES.start("s3", "Step 3 — Decompose")
    snap = st.STAGES.snapshot()
    assert snap["s3"] == {"label": "Step 3 — Decompose", "outcome": "running",
                          "duration_sec": None}


def test_done_closes_stage_with_duration():
    st.STAGES.start("s3", "Step 3")
    st.STAGES.done("s3", duration_sec=41.2)
    assert st.STAGES.snapshot()["s3"] == {"label": "Step 3",
                                         "outcome": "completed",
                                         "duration_sec": 41.2}


def test_done_records_error_outcome():
    st.STAGES.start("s2", "Step 2")
    st.STAGES.done("s2", outcome="error", duration_sec=0.5)
    rec = st.STAGES.snapshot()["s2"]
    assert rec["outcome"] == "error" and rec["duration_sec"] == 0.5


def test_done_without_start_still_records():
    """A stage recorded only on its way out must not be dropped."""
    st.STAGES.done("s8", duration_sec=1.5)
    assert st.STAGES.snapshot()["s8"] == {"label": "", "outcome": "completed",
                                         "duration_sec": 1.5}


@pytest.mark.parametrize("outcome", ["cached", "skipped", "disabled"])
def test_mark_records_untimed_outcomes(outcome):
    st.STAGES.mark("s5", outcome, label="prefilter")
    assert st.STAGES.snapshot()["s5"] == {"label": "prefilter",
                                         "outcome": outcome,
                                         "duration_sec": None}


def test_reset_clears_all_records():
    st.STAGES.start("s1", "Step 1")
    st.STAGES.done("s1", duration_sec=2.0)
    st.STAGES.reset()
    assert st.STAGES.snapshot() == {}


def test_snapshot_is_a_copy_not_a_live_view():
    st.STAGES.start("s1", "Step 1")
    snap = st.STAGES.snapshot()
    st.STAGES.done("s1", duration_sec=9.0)
    assert snap["s1"]["outcome"] == "running"
    assert snap["s1"]["duration_sec"] is None


def test_snapshot_is_ordered_s0_first_regardless_of_record_order():
    for stage_id in ("s8", "s0", "s4", "s11", "s1"):
        st.STAGES.mark(stage_id, "cached")
    assert list(st.STAGES.snapshot()) == ["s0", "s1", "s4", "s8", "s11"]


def test_snapshot_appends_unknown_stage_ids_last():
    st.STAGES.mark("s4", "cached")
    st.STAGES.mark("s99", "cached")
    st.STAGES.mark("s0", "cached")
    assert list(st.STAGES.snapshot()) == ["s0", "s4", "s99"]


# ---------------------------------------------------------------------------
# phase mapping contract
# ---------------------------------------------------------------------------

def test_every_mapped_phase_targets_a_known_stage():
    for stage_id, _ in st.PHASE_MAP.values():
        assert stage_id in st.STAGE_IDS


def test_stage_roles_cover_every_stage_id():
    assert set(st.STAGE_ROLES) == set(st.STAGE_IDS)


def test_remediation_agent_phase_is_charged_to_s10():
    """s10's tokens arrive under the remediation agent's own nested phase."""
    assert st.PHASE_MAP["remediation-agent-remediate"] == ("s10", "remediate")


# ---------------------------------------------------------------------------
# compose_stage_section — structure
# ---------------------------------------------------------------------------

def test_compose_reports_recorded_stage_fields():
    stage_snap = {"s3": st.StageRecord(label="Step 3 — Decompose",
                                       outcome="completed", duration_sec=41.2)}
    token_snap = _token_snap({"s3-decompose": _bucket(prompt=1000,
                                                      completion=200)},
                             prompt=1000, completion=200, calls=1,
                             calls_with_usage=1)

    section = st.compose_stage_section(stage_snap, token_snap,
                                       {"decompose": "model-a"}, None)
    entry = section["stages"]["s3"]

    assert entry["label"] == "Step 3 — Decompose"
    assert entry["outcome"] == "completed"
    assert entry["duration_sec"] == 41.2
    assert entry["tokens"] == _bucket(prompt=1000, completion=200)
    assert entry["model"] == "model-a"
    assert entry["cost_usd"] is None          # no price table
    assert entry["cost_estimated"] is False
    assert section["pricing"] is None


def test_compose_sums_both_s1_phases_into_one_stage():
    token_snap = _token_snap({
        "s1-autoexclude": _bucket(prompt=100, completion=10),
        "s1-preprocess": _bucket(prompt=900, completion=90, cache_read=50),
    })
    stage_snap = {"s1": st.StageRecord(label="Step 1", outcome="completed",
                                       duration_sec=3.0)}

    entry = st.compose_stage_section(stage_snap, token_snap, {}, None)["stages"]["s1"]

    assert entry["tokens"]["prompt"] == 1000
    assert entry["tokens"]["completion"] == 100
    assert entry["tokens"]["cache_read"] == 50
    assert entry["tokens"]["calls"] == 2


def test_compose_reports_cached_stage_with_null_duration():
    stage_snap = {"s4": st.StageRecord(label="", outcome="cached",
                                       duration_sec=None)}
    entry = st.compose_stage_section(stage_snap, _token_snap({}), {},
                                    None)["stages"]["s4"]
    assert entry["outcome"] == "cached" and entry["duration_sec"] is None
    assert entry["tokens"]["prompt"] == 0


def test_compose_includes_token_bearing_stage_with_no_record():
    """A phase can charge tokens to a stage the recorder never saw."""
    token_snap = _token_snap({"s10-remediate": _bucket(prompt=500)})
    entry = st.compose_stage_section({}, token_snap, {}, None)["stages"]["s10"]
    assert entry["outcome"] == "not_run"
    assert entry["tokens"]["prompt"] == 500


def test_compose_orders_stages_s0_first():
    stage_snap = {s: st.StageRecord(label="", outcome="cached",
                                    duration_sec=None)
                  for s in ("s9", "s2", "s11")}
    section = st.compose_stage_section(stage_snap, _token_snap({}), {}, None)
    assert list(section["stages"]) == ["s2", "s9", "s11"]


def test_compose_omits_stages_with_neither_record_nor_tokens():
    section = st.compose_stage_section({}, _token_snap({}), {}, None)
    assert section["stages"] == {}


def test_compose_flags_s11_cost_as_estimated():
    """s11 mixes orchestrator and persona models inside one phase."""
    token_snap = _token_snap({"s11-validate": _bucket(prompt=10)})
    stages = st.compose_stage_section({}, token_snap, {}, None)["stages"]
    assert stages["s11"]["cost_estimated"] is True


def test_compose_does_not_flag_single_model_stages_as_estimated():
    token_snap = _token_snap({"s4-deepdive": _bucket(prompt=10)})
    stages = st.compose_stage_section({}, token_snap, {}, None)["stages"]
    assert stages["s4"]["cost_estimated"] is False


def test_compose_reports_no_model_for_sarif_rendering():
    """s9 is the only stage that can never reach a model."""
    stage_snap = {
        "s9": st.StageRecord(label="sarif", outcome="completed", duration_sec=2.0),
    }
    stages = st.compose_stage_section(stage_snap, _token_snap({}),
                                     {"decompose": "model-a"}, None)["stages"]
    assert stages["s9"]["model"] is None


# ---------------------------------------------------------------------------
# s0 costing — the static seed spends real tokens in llm detection mode
# ---------------------------------------------------------------------------

def test_s0_spend_is_priced_via_the_callgraph_annotation_role():
    """The shipped default profile runs step0.callgraph_detection: llm, so the
    s0-seed bucket carries the annotator's spend and MUST be priceable."""
    pricing = _table({"annotate-model": ModelPricing(input_per_mtok=3.0,
                                                     output_per_mtok=15.0)})
    token_snap = _token_snap({"s0-seed": _bucket(prompt=1_000_000,
                                                 completion=100_000)})

    section = st.compose_stage_section(
        {}, token_snap, {"graph_annotate": "annotate-model"},
        pricing)
    entry = section["stages"]["s0"]

    assert entry["model"] == "annotate-model"
    assert entry["cost_usd"] == pytest.approx(3.0 + 1.5)
    # One model per run, resolved by a fallback chain — not a mixed-model stage.
    assert entry["cost_estimated"] is False
    assert section["pricing_status"] == {"status": "available",
                                         "reason": "pricing table applied"}


def test_s0_spend_does_not_null_the_run_total():
    """Regression: mapping s0 to no role made every priced default-profile run
    report totals.cost_usd = null, because an unpriceable token-bearing stage
    nulls the total."""
    pricing = _table({"m": ModelPricing(input_per_mtok=3.0, output_per_mtok=15.0)})
    token_snap = _token_snap({
        "s0-seed": _bucket(prompt=1_000_000),
        "s4-deepdive": _bucket(prompt=1_000_000),
    })

    section = st.compose_stage_section(
        {}, token_snap, {"graph_annotate": "m", "deepdive": "m"}, pricing)

    assert section["stages"]["s0"]["cost_usd"] == pytest.approx(3.0)
    assert section["totals"]["cost_usd"] == pytest.approx(6.0)


@pytest.mark.parametrize("configured,expected", [
    ({"graph_annotate": "ga", "preprocess": "pp", "callgraph_creation": "cc",
      "deepdive": "dd"}, "ga"),
    ({"preprocess": "pp", "callgraph_creation": "cc", "deepdive": "dd"}, "pp"),
    ({"callgraph_creation": "cc", "deepdive": "dd"}, "cc"),
    ({"deepdive": "dd"}, "dd"),
    ({"verify": "vv"}, None),
])
def test_s0_role_fallback_chain_matches_the_annotator(configured, expected):
    """_annotator.py resolves graph_annotate -> preprocess ->
    callgraph_creation -> deepdive, first configured role wins."""
    token_snap = _token_snap({"s0-seed": _bucket(prompt=10)})
    entry = st.compose_stage_section({}, token_snap, configured,
                                     None)["stages"]["s0"]
    assert entry["model"] == expected


def test_s0_unpriced_annotation_model_still_nulls_the_total():
    """The null-cost rule must survive the fallback: an s0 model the table does
    not price is reported as unavailable, never as zero."""
    pricing = _table({"other": ModelPricing(input_per_mtok=1.0,
                                            output_per_mtok=1.0)})
    token_snap = _token_snap({"s0-seed": _bucket(prompt=1_000)})
    section = st.compose_stage_section({}, token_snap,
                                       {"graph_annotate": "unpriced"}, pricing)
    assert section["stages"]["s0"]["cost_usd"] is None
    assert section["totals"]["cost_usd"] is None
    assert section["pricing_status"]["status"] == "incomplete"
    assert "unpriced" in section["pricing_status"]["reason"]


def test_s0_reports_zero_spend_in_rules_mode():
    """Rules-mode s0 makes no model call: zero tokens, zero cost, no null."""
    pricing = _table({"m": ModelPricing(input_per_mtok=3.0, output_per_mtok=15.0)})
    stage_snap = {"s0": st.StageRecord(label="Step 0 — Static seed (callgraph)",
                                       outcome="completed", duration_sec=12.4)}
    section = st.compose_stage_section(stage_snap, _token_snap({}),
                                       {"graph_annotate": "m"}, pricing)
    assert section["stages"]["s0"]["tokens"]["prompt"] == 0
    assert section["stages"]["s0"]["cost_usd"] == 0.0
    assert section["totals"]["cost_usd"] == 0.0


def test_unpriced_manifest_status_explains_unknown_costs():
    section = st.compose_stage_section(
        {}, _token_snap({"s4-deepdive": _bucket(prompt=100)}),
        {"deepdive": "claude-test"}, None)
    assert section["pricing"] is None
    assert section["pricing_status"] == {
        "status": "unavailable",
        "reason": "no pricing table configured",
    }


# ---------------------------------------------------------------------------
# compose_stage_section — totals and unattributed rollup
# ---------------------------------------------------------------------------

def test_totals_come_from_the_token_snapshot_headline():
    token_snap = _token_snap(
        {"s4-deepdive": _bucket(prompt=800, completion=100, cache_read=70,
                                cache_write=30, calls=4)},
        prompt=800, completion=100, calls=5, calls_with_usage=4)

    totals = st.compose_stage_section({}, token_snap, {}, None)["totals"]

    assert totals["prompt_tokens"] == 800
    assert totals["completion_tokens"] == 100
    assert totals["total_tokens"] == 900
    assert totals["cache_read_tokens"] == 70
    assert totals["cache_write_tokens"] == 30
    assert totals["calls"] == 5
    assert totals["calls_with_usage"] == 4


def test_unmapped_phases_roll_into_unattributed():
    from vvaharness.util.tokens import DEFAULT_PHASE

    token_snap = _token_snap({
        "s3-decompose": _bucket(prompt=100, completion=10),
        DEFAULT_PHASE: _bucket(prompt=7, completion=3, calls=2),
        "some-future-phase": _bucket(prompt=1, completion=1, calls=1),
    })

    section = st.compose_stage_section({}, token_snap, {}, None)

    # Full key parity with the totals, including the cache keys. The old
    # assertion pinned only {prompt, completion, calls} — the recorder's
    # convenience subset — while totals.cache_read/cache_write summed ALL phase
    # buckets including unmapped ones. That made the stage rows unreconcilable
    # against the totals from the manifest alone: one campaign run's rows summed
    # to 3,838 cache-write against totals of 9,180, and the 5,342 difference
    # (preflight probe writes) was reportable nowhere.
    assert section["totals"]["unattributed"] == {"prompt": 8, "completion": 4,
                                                "calls": 3, "cache_read": 0,
                                                "cache_write": 0}
    assert list(section["stages"]) == ["s3"]


def test_unattributed_is_zero_when_every_phase_maps():
    """The full five-key set must exist (as zeros) on a fully-mapped run, so
    a consumer can rely on the shape without probing for optional keys.
    Canonical copy — test_telemetry_parity_wave1.py once carried a verbatim
    duplicate of this pin and now defers to this one."""
    token_snap = _token_snap({"s7-dedup": _bucket(prompt=5)})
    totals = st.compose_stage_section({}, token_snap, {}, None)["totals"]
    assert totals["unattributed"] == {"prompt": 0, "completion": 0, "calls": 0,
                                      "cache_read": 0, "cache_write": 0}


# ---------------------------------------------------------------------------
# compose_stage_section — costing
# ---------------------------------------------------------------------------

def test_costs_each_phase_with_its_own_role_model():
    """s1 spans two roles; each phase must be priced by its own model."""
    pricing = _table({
        "cheap-model": ModelPricing(input_per_mtok=1.0, output_per_mtok=2.0),
        "dear-model": ModelPricing(input_per_mtok=10.0, output_per_mtok=20.0),
    })
    token_snap = _token_snap({
        "s1-autoexclude": _bucket(prompt=1_000_000),
        "s1-preprocess": _bucket(completion=1_000_000),
    })

    entry = st.compose_stage_section(
        {}, token_snap,
        {"autoexclude": "cheap-model", "preprocess": "dear-model"},
        pricing)["stages"]["s1"]

    assert entry["cost_usd"] == pytest.approx(1.0 + 20.0)
    assert entry["model"] == "dear-model"


def test_stage_cost_honors_the_tables_cache_rate_defaults():
    """compose_stage_section must hand PricingTable.cache_defaults down.

    This is the ONLY test of that hand-off, and the hand-off is the only
    bridge between the `cache_rate_defaults` feature and the dollar figures
    that reach run_manifest.json. Without it an operator's declared
    multipliers — here OpenAI-shaped, free writes and half-price reads — are
    silently replaced by the module's Anthropic-shaped fallback, and the whole
    suite stays green while every cached token is mispriced.
    """
    pricing = PricingTable(
        models={"model-a": ModelPricing(input_per_mtok=3.0,
                                        output_per_mtok=15.0)},
        path="/prices/gateway.yaml", sha256="abc123", source="config",
        cache_defaults=CacheRateDefaults(read_fraction=0.5,
                                         write_multiplier=0.0,
                                         is_fallback=False))
    # `prompt` is billable input = fresh + cache_write, so this bucket is 1M
    # fresh, 1M cache-write and 1M cache-read.
    token_snap = _token_snap({"s4-deepdive": _bucket(prompt=2_000_000,
                                                     cache_read=1_000_000,
                                                     cache_write=1_000_000)})

    section = st.compose_stage_section({}, token_snap,
                                       {"deepdive": "model-a"}, pricing)

    # fresh 1M x $3 + writes 1M x $3 x 0.0 + reads 1M x $3 x 0.5 = $4.50.
    # The module fallback (reads x0.10, writes x1.25) would report $7.05.
    assert section["stages"]["s4"]["cost_usd"] == pytest.approx(4.5)
    assert section["totals"]["cost_usd"] == pytest.approx(4.5)


def test_stage_cost_is_zero_when_priced_but_token_free():
    pricing = _table({"model-a": ModelPricing(input_per_mtok=3.0,
                                              output_per_mtok=15.0)})
    stage_snap = {"s4": st.StageRecord(label="", outcome="cached",
                                       duration_sec=None)}
    entry = st.compose_stage_section(stage_snap, _token_snap({}),
                                     {"deepdive": "model-a"},
                                     pricing)["stages"]["s4"]
    assert entry["cost_usd"] == 0.0


def test_totals_cost_sums_stage_costs():
    pricing = _table({"model-a": ModelPricing(input_per_mtok=3.0,
                                              output_per_mtok=15.0)})
    token_snap = _token_snap({
        "s4-deepdive": _bucket(prompt=1_000_000),
        "s6-verify": _bucket(completion=1_000_000),
    })

    section = st.compose_stage_section(
        {}, token_snap, {"deepdive": "model-a", "verify": "model-a"}, pricing)

    assert section["stages"]["s4"]["cost_usd"] == pytest.approx(3.0)
    assert section["stages"]["s6"]["cost_usd"] == pytest.approx(15.0)
    assert section["totals"]["cost_usd"] == pytest.approx(18.0)


def test_unpriced_model_nulls_that_stage_and_the_totals():
    pricing = _table({"model-a": ModelPricing(input_per_mtok=3.0,
                                              output_per_mtok=15.0)})
    token_snap = _token_snap({
        "s4-deepdive": _bucket(prompt=1_000_000),
        "s6-verify": _bucket(prompt=1_000_000),
    })

    section = st.compose_stage_section(
        {}, token_snap, {"deepdive": "model-a", "verify": "absent-model"},
        pricing)

    assert section["stages"]["s4"]["cost_usd"] == pytest.approx(3.0)
    assert section["stages"]["s6"]["cost_usd"] is None
    assert section["totals"]["cost_usd"] is None


def test_unknown_role_model_with_no_tokens_does_not_null_the_cost():
    pricing = _table({"model-a": ModelPricing(input_per_mtok=3.0,
                                              output_per_mtok=15.0)})
    token_snap = _token_snap({"s6-verify": _bucket(calls=1)})
    section = st.compose_stage_section({}, token_snap, {}, pricing)
    assert section["stages"]["s6"]["cost_usd"] == 0.0
    assert section["totals"]["cost_usd"] == 0.0


def test_no_price_table_nulls_every_cost():
    token_snap = _token_snap({"s4-deepdive": _bucket(prompt=1_000_000)})
    section = st.compose_stage_section({}, token_snap, {"deepdive": "model-a"},
                                       None)
    assert section["stages"]["s4"]["cost_usd"] is None
    assert section["totals"]["cost_usd"] is None


def test_pricing_provenance_is_reported_when_costing():
    pricing = _table({"model-a": ModelPricing(input_per_mtok=1.0,
                                              output_per_mtok=1.0)},
                     source="env")
    section = st.compose_stage_section({}, _token_snap({}), {}, pricing)
    assert section["pricing"] == {"file": "/prices/gateway.yaml",
                                 "sha256": "abc123", "source": "env"}
