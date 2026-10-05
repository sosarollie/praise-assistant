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

"""
Prompt-layout and cache-prefix wiring tests for the deep-dive stage:

  - the scan-constant trust context is delivered ahead of the per-chunk
    lines (and never duplicated into the volatile remainder);
  - the per-chunk CVE block stays anchored to the chunk fields, not hoisted
    alongside the trust context;
  - an empty chunk never reaches the model;
  - a chunk sharing a shard with other lenses renders its SOURCE CODE ahead
    of the lens text and shares an identical cache prefix across lenses;
  - omitting/emptying the cache prefix reproduces the pre-existing prompt
    byte-for-byte;
  - same-shard chunks stay adjacent once s4 sorts the manifest by risk_rank
    for dispatch;
  - shard-group siblings hold their model call until their group leader has
    been released (so the leader cache-writes the shared prefix and the rest
    read it), non-shard chunks are never gated, and a leader that fails still
    releases its siblings instead of stalling or dropping them;
  - the max_findings_per_run clip counts every finding it discards instead of
    dropping them silently.
"""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

from vvaharness.models import (
    AppProfile,
    Chunk,
    ChunkSize,
    ContextPackage,
    CVE,
    TaskManifest,
    ThreatModel,
    TrustBoundary,
)
from vvaharness.backends.llm import registry
from vvaharness.orchestrator.preflight import estimate_tokens
from vvaharness.pipeline.stages import s3_decompose
from vvaharness.pipeline.stages import s4_deepdive as s4
from vvaharness.util.counters import COUNTERS


def _ctx(**overrides) -> ContextPackage:
    defaults = dict(repo_root="/nonexistent-repo", language="python",
                     all_files=[], entry_points=[], unsafe_sinks=[], call_graph={})
    defaults.update(overrides)
    return ContextPackage(**defaults)


def _ctx_with_trust() -> ContextPackage:
    return _ctx(
        app_profile=AppProfile(application_id="app-1", externally_facing=True,
                                pci_scoped=True),
        threat_model=ThreatModel(
            system_context="A payment service.",
            trust_boundaries=[TrustBoundary(entry_point="POST /pay",
                                             crossing="unauth network -> app")],
        ),
        known_cves=[CVE(id="CVE-2024-9999", summary="A known remote flaw")],
    )


def _cfg(taint_prompt_mode="discover"):
    return SimpleNamespace(
        step4=SimpleNamespace(
            taint_prompt_mode=taint_prompt_mode, taint_model=None,
            max_tokens=64000, timeout=1800,
        ),
        models=SimpleNamespace(deepdive=SimpleNamespace(id="claude-sonnet-4-6", via="cli")),
    )


def _capture(monkeypatch):
    seen: dict = {}

    def fake_prompt(user, *, model, **kw):
        seen["user"] = user
        seen["model"] = model
        seen["kw"] = kw
        return '{"findings": []}'

    monkeypatch.setattr(registry, "prompt", fake_prompt)
    return seen


def _old_build_prompt(chunk: Chunk, ctx: ContextPackage, code: str) -> str:
    """Byte-for-byte reproduction of the pre-reorder ``_build_prompt`` body,
    kept only so the reorder's token-neutrality can be measured against a
    known-old baseline without depending on version control history."""
    cve_block = ""
    if chunk.related_cves:
        relevant = [c for c in ctx.known_cves if c.id in chunk.related_cves]
        cve_block = "\nRELATED CVEs (hunt for variants/siblings):\n" + "\n".join(
            f"  - {c.id}: {c.summary}" for c in relevant
        ) + "\n"
    return f"""RESEARCH LENS:
{s4.build_research_lens(chunk, code)}

CHUNK: {chunk.id}  SIZE: {chunk.size.value}
HYPOTHESIS: {chunk.hypothesis}
FOCUS ENTRY POINTS: {", ".join(chunk.focus_entry_points) or "(none)"}
{s4._trust_context_block(ctx)}{cve_block}
SOURCE CODE:
{code}

Analyze this code and respond with ONLY the JSON findings object."""


# ─────────────────────────────────────────────────────────────────────────────
# Trust context hoisted to the front; the CVE block stays per-chunk
# ─────────────────────────────────────────────────────────────────────────────

def test_risk_chunk_header_sequence_trust_first_cve_after_focus(monkeypatch):
    ctx = _ctx_with_trust()
    chunk = Chunk(id="chunk-07", size=ChunkSize.MEDIUM, files=["a.py"],
                  hypothesis="possible injection",
                  focus_entry_points=["handle"],
                  related_cves=["CVE-2024-9999"])
    seen = _capture(monkeypatch)
    s4._single_run(chunk, ctx, "def handle(): pass", _cfg())

    cache_prefix = seen["kw"]["cache_prefix"]
    remainder = seen["user"]
    # The cacheable prefix now carries the full scan-scoped context block (CMDB
    # profile, compact threat model, entry-point inventory, trust rule) rather
    # than the narrower trust summary it used to. The ordering guarantee is
    # unchanged and is what this test exists to pin.
    assert cache_prefix is not None
    assert cache_prefix.startswith("CMDB APPLICATION PROFILE:")
    assert "TRUST RULE:" in cache_prefix

    combined = cache_prefix + remainder
    # Anchor on the prefix occupying the head of the request verbatim. That is
    # the property prompt caching actually depends on, and it is stronger than
    # any single marker's index — a reordering inside the prefix cannot slip
    # past it.
    assert combined.startswith(cache_prefix)
    # TRUST RULE is the LAST part of the shared block, so requiring it to
    # precede the lens pins EVERY cached byte ahead of the per-chunk framing.
    i_trust = combined.index("TRUST RULE:")
    i_lens = combined.index("RESEARCH LENS:")
    i_focus = combined.index("FOCUS ENTRY POINTS:")
    i_cve = combined.index("RELATED CVEs")
    i_source = combined.index("SOURCE CODE:")
    assert i_trust < i_lens < i_focus < i_cve < i_source

    # never duplicated into the volatile remainder
    assert "TRUST RULE:" not in remainder
    assert "CMDB APPLICATION PROFILE:" not in remainder


def test_cve_block_never_lands_in_cache_prefix(monkeypatch):
    ctx = _ctx_with_trust()
    chunk = Chunk(id="chunk-08", size=ChunkSize.MEDIUM, files=["a.py"],
                  hypothesis="x", related_cves=["CVE-2024-9999"])
    seen = _capture(monkeypatch)
    s4._single_run(chunk, ctx, "code", _cfg())
    assert "RELATED CVEs" not in seen["kw"]["cache_prefix"]
    assert "RELATED CVEs" in seen["user"]


def test_reorder_is_token_neutral():
    ctx = _ctx_with_trust()
    chunk = Chunk(id="chunk-09", size=ChunkSize.MEDIUM, files=["a.py"],
                  hypothesis="possible injection", focus_entry_points=["handle"],
                  related_cves=["CVE-2024-9999"])
    code = "def handle(req):\n    return db.query(req.args['q'])\n"

    old_text = _old_build_prompt(chunk, ctx, code)
    trust = s4._trust_context_block(ctx)
    new_remainder = s4._build_prompt(chunk, ctx, code)
    new_text = trust + new_remainder

    old_tokens = estimate_tokens(old_text)
    new_tokens = estimate_tokens(new_text)
    delta = abs(new_tokens - old_tokens) / old_tokens
    assert delta < 0.005, f"token delta {delta:.4%} (old={old_tokens} new={new_tokens})"


def test_cache_prefix_is_trust_rule_only_when_no_scan_context(monkeypatch):
    """With no app profile, threat model or entry points, the only scan-scoped
    content that exists is the trust rule, and the per-chunk body must still be
    byte-identical to the pre-reorder single-string prompt.

    This replaces an earlier expectation that the prefix would be ``None`` here.
    The shared context block emits the trust rule unconditionally, so a prefix
    always exists; what still has to hold — and is what this test now pins — is
    that NOTHING beyond that rule is invented out of an empty context, and that
    no scan-scoped text leaks into the volatile per-chunk body. Spending a cache
    breakpoint on so small a prefix is prevented separately, by the backend's
    minimum-size gate, which is asserted in tests/test_backend_cache.py rather
    than here.
    """
    ctx = _ctx()  # no app_profile, no threat_model, no entry_points
    chunk = Chunk(id="chunk-10", size=ChunkSize.MEDIUM, files=["a.py"], hypothesis="x")
    seen = _capture(monkeypatch)
    s4._single_run(chunk, ctx, "code-body", _cfg())

    cache_prefix = seen["kw"]["cache_prefix"]
    assert cache_prefix is not None
    assert cache_prefix.startswith("TRUST RULE:")
    # nothing fabricated from an empty ContextPackage
    assert "CMDB APPLICATION PROFILE:" not in cache_prefix
    assert "Trust boundaries" not in cache_prefix
    assert "ENTRY POINT INVENTORY" not in cache_prefix
    assert seen["user"] == _old_build_prompt(chunk, ctx, "code-body")


# ─────────────────────────────────────────────────────────────────────────────
# Specialist (shard-major) chunks: SOURCE CODE before the lens,
# shared verbatim via cache_prefix across every lens on the same shard
# ─────────────────────────────────────────────────────────────────────────────

def test_specialist_chunk_source_before_lens_via_cache_prefix(monkeypatch):
    ctx = _ctx_with_trust()
    chunk = Chunk(id="spec-crypto-01", size=ChunkSize.MEDIUM,
                  files=["crypto.py"], hypothesis="weak cipher",
                  specialist="crypto", shard_id="shard-01")
    seen = _capture(monkeypatch)
    s4._single_run(chunk, ctx, "def encrypt(): use(DES)", _cfg())

    cache_prefix = seen["kw"]["cache_prefix"]
    remainder = seen["user"]
    assert "SOURCE CODE:" in cache_prefix
    assert "use(DES)" in cache_prefix
    # the shard body must not be duplicated into the volatile remainder
    assert "SOURCE CODE:" not in remainder
    assert "use(DES)" not in remainder

    combined = cache_prefix + remainder
    # TRUST RULE is the final part of the shared scan context, so it marks the
    # boundary between the scan-scoped block and the shard body that follows it
    # inside the same cache prefix.
    i_trust = combined.index("TRUST RULE:")
    i_source = combined.index("SOURCE CODE:")
    i_lens = combined.index("RESEARCH LENS:")
    i_closing = combined.index("Analyze this code")
    assert i_trust < i_source < i_lens < i_closing


def test_risk_chunk_without_shard_id_keeps_source_last(monkeypatch):
    ctx = _ctx_with_trust()
    chunk = Chunk(id="chunk-11", size=ChunkSize.MEDIUM, files=["a.py"],
                  hypothesis="x")
    seen = _capture(monkeypatch)
    s4._single_run(chunk, ctx, "print('body')", _cfg())
    remainder = seen["user"]
    i_lens = remainder.index("RESEARCH LENS:")
    i_source = remainder.index("SOURCE CODE:")
    assert i_lens < i_source


def test_specialist_chunks_sharing_a_shard_get_identical_cache_prefix(monkeypatch):
    """The whole point of shard-major ordering: four lens chunks over the
    same shard must produce byte-identical cache_prefix text so three of
    four calls can cache-read it instead of re-paying for the shard body."""
    ctx = _ctx_with_trust()
    code = "def handle(): pass\n" * 50
    lenses = ["crypto", "logic-bug", "access-control", "batch-etl"]
    prefixes = []
    for lens in lenses:
        chunk = Chunk(id=f"spec-{lens}-03", size=ChunkSize.MEDIUM,
                      files=["shared.py"], hypothesis="x",
                      specialist=lens, shard_id="shard-03")
        seen = _capture(monkeypatch)
        s4._single_run(chunk, ctx, code, _cfg())
        prefixes.append(seen["kw"]["cache_prefix"])
    assert len(set(prefixes)) == 1, "cache_prefix must be identical across lenses on one shard"


def test_specialist_prompt_savings_measured_on_fixture():
    """Report the token delta the shard-before-lens reorder buys: four
    lenses re-sending the same ~500-line shard body inline (today) versus
    one shared cache_prefix plus four small remainders (after)."""
    ctx = _ctx_with_trust()
    code = "\n".join(f"line {i}" for i in range(500))
    lenses = ["crypto", "logic-bug", "access-control", "batch-etl"]

    before_total = 0
    after_prefix_tokens = None
    after_remainder_total = 0
    for lens in lenses:
        chunk = Chunk(id=f"spec-{lens}-09", size=ChunkSize.MEDIUM,
                      files=["shared.py"], hypothesis="x",
                      specialist=lens, shard_id="shard-09")
        # "today": specialist chunks had no shard_id concept and were built
        # like any other chunk — full SOURCE CODE inline, every lens.
        legacy_chunk = chunk.model_copy(update={"shard_id": ""})
        before_total += estimate_tokens(_old_build_prompt(legacy_chunk, ctx, code))

        trust = s4._trust_context_block(ctx)
        prefix = trust + s4._shard_source_block(code)
        remainder = s4._build_prompt(chunk, ctx, code)
        after_prefix_tokens = estimate_tokens(prefix)  # identical every lens
        after_remainder_total += estimate_tokens(remainder)

    after_total = after_prefix_tokens + after_remainder_total  # prefix paid once
    savings = 1 - (after_total / before_total)
    # Not a hard gate (real corpus behaviour depends on cache hit/miss and
    # the backend route) — just proves the shard-major reorder measurably
    # shrinks the bytes that must be freshly billed on this fixture.
    assert savings > 0.5, f"measured savings {savings:.2%} (before={before_total} after={after_total})"


# ─────────────────────────────────────────────────────────────────────────────
# Dispatch-order locality: s4 dispatches in risk_rank order (run() sorts the
# manifest before submitting), so shard-major emission only reaches the wire
# if s3 hands every shard group consecutive risk_ranks. test_s3_decompose
# guards emission ORDER; this guards the rank contract dispatch depends on.
# ─────────────────────────────────────────────────────────────────────────────

def test_same_shard_chunks_stay_adjacent_in_dispatch_order(tmp_path):
    """A shard group pulled apart at dispatch runs its members outside each
    other's cache-TTL window, silently forfeiting the shard-prefix cache
    reads that shard-major emission exists to enable."""
    for i in range(4):
        (tmp_path / f"m{i}.py").write_text(
            f"def fn{i}():\n    return {i}  # AES\n", encoding="utf-8")
    ctx = _ctx(repo_root=str(tmp_path),
               all_files=[f"m{i}.py" for i in range(4)])
    # a few risk-ranked chunks already in the manifest, as in a real run
    manifest = TaskManifest(chunks=[
        Chunk(id=f"chunk-{i:02d}", size=ChunkSize.SMALL, risk_rank=i,
              files=[f"m{i % 4}.py"], hypothesis="x") for i in range(1, 4)
    ], rationale="x")
    cfg = SimpleNamespace(step3=SimpleNamespace(
        specialists=["crypto", "logic-bug"],
        specialist_chunk_loc=1, max_files_per_chunk=1, pack_by="loc"))
    s3_decompose._add_specialist_chunks(manifest, ctx, cfg)

    shards = {c.shard_id for c in manifest.chunks if c.shard_id}
    assert len(shards) >= 2, "fixture must produce multiple shard groups"

    # exactly the order s4's run() derives before submitting to the pool
    dispatch = sorted(manifest.chunks, key=lambda c: c.risk_rank)
    seen: list[str] = []
    for c in dispatch:
        if not c.shard_id:
            continue
        if not seen or seen[-1] != c.shard_id:
            assert c.shard_id not in seen, (
                f"shard {c.shard_id!r} pulled apart in dispatch order")
            seen.append(c.shard_id)


# ─────────────────────────────────────────────────────────────────────────────
# Intra-shard-group dispatch gating: with parallel >= group size, all members
# of a shard group used to go out simultaneously and each re-WROTE the shared
# cache prefix instead of reading the leader's copy. These tests pin the fix:
# siblings hold until their leader is released, non-shard chunks never wait,
# and a failed leader still releases its group. _SHARD_LEADER_DONE_CAP is
# patched to a value no test can outlive, so a sibling can only start via the
# leader's done-event and never by that bound expiring — every assertion is on
# event ORDER, never on real durations.
# ─────────────────────────────────────────────────────────────────────────────

_LENSES = ["crypto", "logic-bug", "access-control", "batch-etl", "injection"]


def _shard_group(shard: str, rank0: int) -> list[Chunk]:
    return [Chunk(id=f"spec-{lens}-{shard}", size=ChunkSize.SMALL,
                  files=["shared.py"], hypothesis="x", specialist=lens,
                  shard_id=shard, risk_rank=rank0 + i)
            for i, lens in enumerate(_LENSES)]


def _run_cfg(parallel: int):
    # via: sdk — a route WITH a prefix cache, so run() still builds shard
    # gates (cli/deepagents routes are gateless since prefix_cache_class).
    return SimpleNamespace(
        step4=SimpleNamespace(parallel=parallel, line_bucket=10, runs=1,
                              vote_threshold=1, specialist_runs=1,
                              max_tokens=64000, timeout=1800,
                              taint_prompt_mode="discover", taint_runs=1,
                              taint_model=None),
        models=SimpleNamespace(deepdive=SimpleNamespace(id="claude-sonnet-4-6",
                                                        via="sdk")),
    )


def test_gate_plan_gates_shard_groups_only():
    """Structural contract of the gate plan: every shard member shares one
    gate whose leader is the group's first chunk in dispatch order, and
    prefix-less chunks (taint/catch-all/threat-fallback) get no gate at all."""
    non_shard = [
        Chunk(id="chunk-01", size=ChunkSize.SMALL, files=["a.py"],
              hypothesis="x", risk_rank=1),
        Chunk(id="taint-01", size=ChunkSize.SMALL, files=["b.py"],
              hypothesis="x", risk_rank=12),
    ]
    group_a = _shard_group("shard-a", rank0=2)
    group_b = _shard_group("shard-b", rank0=7)
    dispatch = sorted(non_shard + group_a + group_b, key=lambda c: c.risk_rank)

    gates = s4._shard_gates(dispatch)
    assert "chunk-01" not in gates and "taint-01" not in gates
    for group in (group_a, group_b):
        group_gates = [gates[c.id] for c in group]
        assert all(g is group_gates[0] for g in group_gates), \
            "one shared gate object per shard group"
        assert group_gates[0]["leader"] == group[0].id
    assert gates[group_a[0].id] is not gates[group_b[0].id]


def test_shard_siblings_hold_until_their_leader_is_released(monkeypatch):
    """With every chunk in flight at once (parallel == chunk count — the
    worst race), no sibling may start before its group leader has finished
    or been released. Leaders return instantly here, so end-before-start
    ordering in the recorded event log is fully deterministic."""
    monkeypatch.setattr(s4, "_SHARD_LEADER_DONE_CAP", 300.0)
    events: list[tuple[str, str]] = []
    lock = threading.Lock()

    def fake_deepdive(chunk, *a, **kw):
        with lock:
            events.append(("start", chunk.id))
        with lock:
            events.append(("end", chunk.id))
        return []

    monkeypatch.setattr(s4, "_deepdive_chunk", fake_deepdive)

    group_a = _shard_group("shard-a", rank0=2)
    group_b = _shard_group("shard-b", rank0=7)
    non_shard = [Chunk(id="chunk-01", size=ChunkSize.SMALL, files=["a.py"],
                       hypothesis="x", risk_rank=1)]
    chunks = non_shard + group_a + group_b

    _, outcomes = s4.run(chunks, _ctx(), _run_cfg(parallel=len(chunks)))
    assert all(v == "completed" for v in outcomes.values())

    pos = {ev: i for i, ev in enumerate(events)}
    for group in (group_a, group_b):
        leader, siblings = group[0], group[1:]
        for sib in siblings:
            assert pos[("end", leader.id)] < pos[("start", sib.id)], (
                f"sibling {sib.id} started before leader {leader.id} "
                f"was released")


def test_non_shard_chunk_runs_while_leader_still_in_flight(monkeypatch):
    """Gating must serialize only the intra-group race: while a leader is
    still in flight (its siblings parked), a prefix-less chunk dispatched
    AFTER the whole group must run to completion ungated."""
    monkeypatch.setattr(s4, "_SHARD_LEADER_DONE_CAP", 300.0)
    group = _shard_group("shard-a", rank0=1)
    leader, siblings = group[0], group[1:]
    non_shard = Chunk(id="taint-01", size=ChunkSize.SMALL, files=["b.py"],
                      hypothesis="x", risk_rank=10)
    chunks = group + [non_shard]

    leader_block = threading.Event()
    non_shard_done = threading.Event()
    started: set[str] = set()
    lock = threading.Lock()

    def fake_deepdive(chunk, *a, **kw):
        with lock:
            started.add(chunk.id)
        if chunk.id == leader.id:
            leader_block.wait(timeout=30)
        if chunk.id == non_shard.id:
            non_shard_done.set()
        return []

    monkeypatch.setattr(s4, "_deepdive_chunk", fake_deepdive)

    runner = threading.Thread(
        target=s4.run, args=(chunks, _ctx(), _run_cfg(parallel=len(chunks))),
        daemon=True)
    runner.start()
    try:
        assert non_shard_done.wait(timeout=30), \
            "non-shard chunk did not run while the leader was in flight"
        with lock:
            snapshot = set(started)
        assert leader.id in snapshot
        assert non_shard.id in snapshot
        assert not (snapshot & {s.id for s in siblings}), \
            "a sibling started while its leader was still in flight"
    finally:
        leader_block.set()   # always unblock, even on assertion failure
    runner.join(timeout=30)
    assert not runner.is_alive()


def test_sibling_waits_for_a_slow_leader_with_no_patched_bounds(monkeypatch):
    """Regression guard for the real-world defect, with the shipped bounds in
    place — deliberately NOT monkeypatched.

    The gate originally released siblings after a fixed 3 s "head start", on the
    assumption that a provider's cache entry becomes readable once the prefix is
    parsed. It becomes readable when the writing call COMPLETES, so with a mean
    s4 call of 18-27 s every member of a shard group re-wrote the prefix. The
    sibling assertions in the tests above cannot catch that: they patch the wait
    bound to 300 s, which forces the wait-for-done path regardless of what the
    production default does. This test observes past any plausible short head
    start with the real constants loaded, so reintroducing one fails here.
    """
    group = _shard_group("shard-a", rank0=1)
    leader, siblings = group[0], group[1:]

    leader_block = threading.Event()
    leader_started = threading.Event()
    started: set[str] = set()
    lock = threading.Lock()

    def fake_deepdive(chunk, *a, **kw):
        with lock:
            started.add(chunk.id)
        if chunk.id == leader.id:
            leader_started.set()
            leader_block.wait(timeout=60)
        return []

    monkeypatch.setattr(s4, "_deepdive_chunk", fake_deepdive)

    runner = threading.Thread(
        target=s4.run, args=(group, _ctx(), _run_cfg(parallel=len(group))),
        daemon=True)
    runner.start()
    try:
        assert leader_started.wait(timeout=30), "leader never started"
        # Comfortably longer than the 3 s window that shipped, and longer than
        # any head start someone would plausibly reintroduce.
        time.sleep(4.0)
        with lock:
            snapshot = set(started)
        assert not (snapshot & {s.id for s in siblings}), (
            "a sibling started while its leader's call was still in flight — "
            "the shared cache prefix will be written more than once")
    finally:
        leader_block.set()
    runner.join(timeout=30)
    assert not runner.is_alive()


def test_leader_failure_releases_siblings(monkeypatch):
    """Degradation contract: a leader that errors must release its siblings
    (they run ungated, as before the fix) — never park or drop them. The
    huge done-cap proves the release came from the failure path, not from
    that bound expiring."""
    monkeypatch.setattr(s4, "_SHARD_LEADER_DONE_CAP", 300.0)
    group = _shard_group("shard-a", rank0=1)
    leader, siblings = group[0], group[1:]
    ran: set[str] = set()
    lock = threading.Lock()

    def fake_deepdive(chunk, *a, **kw):
        with lock:
            ran.add(chunk.id)
        if chunk.id == leader.id:
            raise RuntimeError("leader call failed")
        return []

    monkeypatch.setattr(s4, "_deepdive_chunk", fake_deepdive)

    _, outcomes = s4.run(list(group), _ctx(), _run_cfg(parallel=len(group)))
    assert outcomes[leader.id] == "error"
    for sib in siblings:
        assert sib.id in ran
        assert outcomes[sib.id] == "completed"


def test_sibling_start_timeout_is_visible_and_proceeds_ungated(
        monkeypatch, capsys):
    group = _shard_group("shard-a", rank0=1)
    leader, sibling = group[:2]
    gate = s4._shard_gates(group)[sibling.id]
    calls: list[str] = []

    monkeypatch.setattr(s4, "_SHARD_LEADER_CAP", 0.0)
    monkeypatch.setattr(
        s4, "_deepdive_chunk",
        lambda chunk, *args, **kwargs: calls.append(chunk.id) or [])

    result = s4._gated_deepdive(
        sibling, gate, _ctx(), None, _run_cfg(parallel=2), 1, 1)

    assert result == []
    assert calls == [sibling.id], "timeout must preserve the ungated fallback"
    assert COUNTERS.get("s4_shard_leader_start_cap_expired") == 1
    err = capsys.readouterr().err
    assert sibling.id in err and leader.id in err
    assert "did not start" in err and "proceeding ungated" in err


# ─────────────────────────────────────────────────────────────────────────────
# Empty-chunk guard
# ─────────────────────────────────────────────────────────────────────────────

def test_empty_chunk_causes_zero_model_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(registry, "prompt",
                        lambda u, *, model, **kw: (calls.append(1) or '{"findings": []}'))
    ctx = _ctx()
    empty_chunk = Chunk(id="chunk-empty", size=ChunkSize.MEDIUM, files=[], hypothesis="x")
    cfg = SimpleNamespace(
        step4=SimpleNamespace(parallel=1, line_bucket=10, runs=1, vote_threshold=1,
                              specialist_runs=1, max_tokens=64000, timeout=1800,
                              taint_prompt_mode="discover", taint_runs=1, taint_model=None),
        models=SimpleNamespace(deepdive=SimpleNamespace(id="claude-sonnet-4-6", via="cli")),
    )
    findings, outcomes = s4.run([empty_chunk], ctx, cfg)
    assert calls == []
    assert findings == []
    assert outcomes["chunk-empty"] == "skipped"


def test_empty_chunk_guard_leaves_non_empty_chunks_processed(monkeypatch):
    calls = []
    monkeypatch.setattr(registry, "prompt",
                        lambda u, *, model, **kw: (calls.append(1) or '{"findings": []}'))
    ctx = _ctx()
    empty_chunk = Chunk(id="chunk-empty", size=ChunkSize.MEDIUM, files=[], hypothesis="x")
    real_chunk = Chunk(id="chunk-real", size=ChunkSize.MEDIUM, files=["a.py"], hypothesis="x")
    cfg = SimpleNamespace(
        step4=SimpleNamespace(parallel=1, line_bucket=10, runs=1, vote_threshold=1,
                              specialist_runs=1, max_tokens=64000, timeout=1800,
                              taint_prompt_mode="discover", taint_runs=1, taint_model=None),
        models=SimpleNamespace(deepdive=SimpleNamespace(id="claude-sonnet-4-6", via="cli")),
    )
    _, outcomes = s4.run([empty_chunk, real_chunk], ctx, cfg)
    assert len(calls) == 1
    assert outcomes["chunk-empty"] == "skipped"
    assert outcomes["chunk-real"] == "completed"


# ─────────────────────────────────────────────────────────────────────────────
# max_findings_per_run clip: the discard is counted, never silent
# ─────────────────────────────────────────────────────────────────────────────

def _finding_item(i: int, confidence: float) -> dict:
    return {
        "file": "a.py", "line_start": i * 20 + 1, "line_end": i * 20 + 2,
        "vuln_class": "injection", "title": f"finding {i}",
        "description": "d", "code_snippet": "c", "confidence": confidence,
    }


def _capped_cfg(cap: int):
    cfg = _cfg()
    cfg.step4.max_findings_per_run = cap
    return cfg


def test_over_cap_call_bumps_truncation_counter_by_number_discarded(monkeypatch):
    payload = json.dumps(
        {"findings": [_finding_item(i, 0.3 + i * 0.1) for i in range(5)]})
    monkeypatch.setattr(registry, "prompt", lambda u, *, model, **kw: payload)
    chunk = Chunk(id="chunk-01", size=ChunkSize.MEDIUM, files=["a.py"],
                  hypothesis="x")
    out = s4._single_run(chunk, _ctx(), "code", _capped_cfg(3))

    assert len(out) == 3
    # detection behaviour unchanged: the cap keeps the highest-confidence
    # findings, and only counts what it discards
    assert [round(f.confidence, 1) for f in out] == [0.7, 0.6, 0.5]
    assert COUNTERS.get("s4_findings_truncated") == 2


def test_under_cap_call_bumps_nothing(monkeypatch):
    payload = json.dumps(
        {"findings": [_finding_item(i, 0.5) for i in range(3)]})
    monkeypatch.setattr(registry, "prompt", lambda u, *, model, **kw: payload)
    chunk = Chunk(id="chunk-01", size=ChunkSize.MEDIUM, files=["a.py"],
                  hypothesis="x")
    out = s4._single_run(chunk, _ctx(), "code", _capped_cfg(3))

    assert len(out) == 3
    # at (not over) the cap nothing is discarded, so the key must be absent
    # entirely -- "never truncated" and "truncated zero" render the same, but
    # the counter sink still must not invent the event
    assert "s4_findings_truncated" not in COUNTERS.snapshot()
