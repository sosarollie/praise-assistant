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

"""Process-wide per-stage telemetry: what each pipeline stage did, and for how long.

Mirrors the ``TOKENS`` singleton in :mod:`vvaharness.util.tokens`: the
orchestrator records one entry per stage (``STAGES``), and the run manifest
composes those entries with the per-phase token buckets into the per-stage
duration/token/cost table.

Two mappings tie the two recorders together:

``PHASE_MAP``
    Every ``TOKENS.phase`` label the pipeline opens, mapped to the stage it
    belongs to and the config model role that phase's calls run on. It is the
    costing key: each phase is priced with its OWN role's model, so a stage that
    spans two roles (s1 = autoexclude + preprocess) still costs correctly. The
    remediation agent opens its own nested phase, so s10 tokens arrive under
    ``remediation-agent-remediate`` rather than ``s10-remediate``; both map to
    s10. Phases absent from this map (including ``tokens.DEFAULT_PHASE`` — model
    calls made outside any stage, e.g. the startup credential probe) roll into
    ``totals.unattributed`` instead of being charged to a stage.

``STAGE_ROLES``
    The one headline model role reported per stage. Only s9 (SARIF rendering)
    spends nothing and reports no model.

``ROLE_FALLBACKS``
    Where a stage resolves its model through a fallback chain rather than one
    fixed role, the chain is mirrored here so the cost is exact. s0 is the case:
    with ``step0.callgraph_detection: llm`` (what the shipped default profile
    uses) the annotator spends real tokens under ``s0-seed``, picking the FIRST
    configured role of ``graph_annotate`` -> ``preprocess`` ->
    ``callgraph_creation`` -> ``deepdive`` (see
    ``pipeline/stages/callgraph_engine/_annotator.py``). In rules mode s0 makes no
    call at all and simply reports zero tokens against the same role.

s11 runs an orchestrator plus persona subagents that may differ from the
orchestrator model, so its role-mapped cost is an estimate and is flagged with
``cost_estimated: true``. Every other stage bills one model per run.
"""
from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from typing import TypedDict

from vvaharness.util.pricing import ModelPricing, PricingTable, TokenBucket, bucket_cost_usd

STAGE_IDS: tuple[str, ...] = ("s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                              "s8", "s9", "s10", "s11")

PHASE_MAP: dict[str, tuple[str, str | None]] = {
    "s0-seed": ("s0", "graph_annotate"),
    "s1-autoexclude": ("s1", "autoexclude"),
    "s1-preprocess": ("s1", "preprocess"),
    "s2-threatmodel": ("s2", "threatmodel"),
    "s3-decompose": ("s3", "decompose"),
    "s4-deepdive": ("s4", "deepdive"),
    "s5-prefilter": ("s5", "dedup"),
    "s6-verify": ("s6", "verify"),
    "s7-dedup": ("s7", "dedup"),
    "s8-chain": ("s8", "chain"),
    "s10-remediate": ("s10", "remediate"),
    "remediation-agent-remediate": ("s10", "remediate"),
    "s11-validate": ("s11", "validate"),
}

STAGE_ROLES: dict[str, str | None] = {
    "s0": "graph_annotate",
    "s1": "preprocess",
    "s2": "threatmodel",
    "s3": "decompose",
    "s4": "deepdive",
    "s5": "dedup",
    "s6": "verify",
    "s7": "dedup",
    "s8": "chain",
    "s9": None,
    "s10": "remediate",
    "s11": "validate",
}

# Mirrors the resolution order in callgraph_engine/_annotator.py. A role absent
# from this map resolves to itself.
ROLE_FALLBACKS: dict[str, tuple[str, ...]] = {
    "graph_annotate": ("graph_annotate", "preprocess", "callgraph_creation",
                       "deepdive"),
}

ESTIMATED_COST_STAGES: frozenset[str] = frozenset({"s11"})

_NOT_RUN = "not_run"
_RUNNING = "running"


class StageRecord(TypedDict):
    """One stage's recorded label, terminal outcome and wall-clock duration."""

    label: str
    outcome: str
    duration_sec: float | None


class TokenSnapshot(TypedDict, total=False):
    """The shape of ``TOKENS.snapshot()``."""

    prompt: int
    completion: int
    total: int
    calls: int
    calls_with_usage: int
    # Usage records whose completion count arrived as an explicit null and was
    # coerced to 0 (see util/tokens.py). snapshot() has always emitted it; it
    # was missing from this TypedDict, which is how the composer came to drop
    # it on the floor instead of persisting it into ``totals``.
    completion_absent: int
    by_phase: dict[str, TokenBucket]


class UnattributedTokens(TypedDict):
    """Tokens from phases that map to no stage.

    Key parity with the per-stage token rows is deliberate and load-bearing:
    the manifest's reconciliation identity is ``Σ stages + unattributed =
    totals`` for EVERY token key. This bucket originally carried only
    prompt/completion/calls, so an unmapped phase with cache traffic (the
    preflight cache probe) left the manifest unreconcilable with itself — one
    campaign arm's stage rows summed to cache_write 3,838 against totals of
    9,180, and the 5,342-token gap was reportable nowhere.
    """

    prompt: int
    completion: int
    cache_read: int
    cache_write: int
    calls: int


class StageEntry(TypedDict):
    """One ``stages.<id>`` object in the run manifest."""

    label: str
    outcome: str
    duration_sec: float | None
    tokens: TokenBucket
    model: str | None
    cost_usd: float | None
    cost_estimated: bool


class Totals(TypedDict):
    """The manifest's ``totals`` object."""

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    calls: int
    calls_with_usage: int
    # Anomaly counters, persisted so the blind spots they count are visible in
    # the one artifact that reliably survives a run. Their docstrings in
    # util/tokens.py promise machine visibility; until these keys existed the
    # promise held only for a debugger attached to the live process (the
    # manifest carried neither, and stderr is routinely reclaimed).
    completion_absent: int
    cache_unparsed_calls: int
    cost_usd: float | None
    unattributed: UnattributedTokens


class PricingProvenance(TypedDict):
    """Which price table produced the costs, for reproducibility."""

    file: str
    sha256: str
    source: str


class PricingStatus(TypedDict):
    """Why manifest costs are available, estimated, or unknown."""

    status: str
    reason: str


class StageSection(TypedDict):
    """The manifest fields this module owns."""

    stages: dict[str, StageEntry]
    totals: Totals
    pricing: PricingProvenance | None
    pricing_status: PricingStatus


def _copy(record: StageRecord) -> StageRecord:
    return StageRecord(label=record["label"], outcome=record["outcome"],
                       duration_sec=record["duration_sec"])


class _StageRecorder:
    """Process-wide recorder of per-stage outcome and duration.

    Thread-safe like ``_TokenCounter``: stages never overlap, but the pipeline's
    worker pools mean a stage body can touch the recorder off the main thread.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stages: dict[str, StageRecord] = {}

    def start(self, stage_id: str, label: str = "") -> None:
        """Open *stage_id*; it stays ``running`` until ``done``/``mark``."""
        with self._lock:
            self._stages[stage_id] = StageRecord(label=label, outcome=_RUNNING,
                                                 duration_sec=None)

    def done(self, stage_id: str, *, outcome: str = "completed",
             duration_sec: float | None = None) -> None:
        """Close *stage_id* with its terminal outcome and measured duration."""
        with self._lock:
            record = self._stages.get(stage_id)
            if record is None:
                record = StageRecord(label="", outcome=outcome,
                                     duration_sec=None)
                self._stages[stage_id] = record
            record["outcome"] = outcome
            record["duration_sec"] = duration_sec

    def mark(self, stage_id: str, outcome: str, label: str = "") -> None:
        """Record a stage that ran no timed body (cached/skipped/disabled)."""
        with self._lock:
            self._stages[stage_id] = StageRecord(label=label, outcome=outcome,
                                                 duration_sec=None)

    def reset(self) -> None:
        """Drop every record — one scan's telemetry per manifest."""
        with self._lock:
            self._stages = {}

    def snapshot(self) -> dict[str, StageRecord]:
        """Copy the records, ordered s0-first with unknown ids appended."""
        with self._lock:
            known = [s for s in STAGE_IDS if s in self._stages]
            extra = [s for s in self._stages if s not in STAGE_IDS]
            return {s: _copy(self._stages[s]) for s in known + extra}


STAGES = _StageRecorder()


def _sum_buckets(buckets: Sequence[TokenBucket]) -> TokenBucket:
    return TokenBucket(
        prompt=sum(b.get("prompt", 0) for b in buckets),
        completion=sum(b.get("completion", 0) for b in buckets),
        cache_read=sum(b.get("cache_read", 0) for b in buckets),
        cache_write=sum(b.get("cache_write", 0) for b in buckets),
        calls=sum(b.get("calls", 0) for b in buckets),
    )


def _has_tokens(bucket: TokenBucket) -> bool:
    return (bucket.get("prompt", 0) + bucket.get("completion", 0)
            + bucket.get("cache_read", 0)) > 0


def _group_phases(
    token_snap: TokenSnapshot,
) -> tuple[dict[str, list[tuple[str | None, TokenBucket]]], UnattributedTokens]:
    by_stage: dict[str, list[tuple[str | None, TokenBucket]]] = {}
    unattributed = UnattributedTokens(prompt=0, completion=0, cache_read=0,
                                      cache_write=0, calls=0)
    for phase, bucket in token_snap.get("by_phase", {}).items():
        mapped = PHASE_MAP.get(phase)
        if mapped is None:
            # Copy EVERY key `_sum_buckets` reads, not a convenient subset.
            # This roll-up once dropped the cache fields, so `_totals` (which
            # sums ALL phase buckets) and the stage rows described different
            # populations by construction — see the UnattributedTokens
            # docstring for the measured consequence.
            unattributed["prompt"] += bucket.get("prompt", 0)
            unattributed["completion"] += bucket.get("completion", 0)
            unattributed["cache_read"] += bucket.get("cache_read", 0)
            unattributed["cache_write"] += bucket.get("cache_write", 0)
            unattributed["calls"] += bucket.get("calls", 0)
            continue
        stage_id, role = mapped
        by_stage.setdefault(stage_id, []).append((role, bucket))
    return by_stage, unattributed


def _resolve_model(role: str | None,
                   role_models: Mapping[str, str]) -> str | None:
    """The model id a stage's role resolves to, following any fallback chain."""
    if role is None:
        return None
    for candidate in ROLE_FALLBACKS.get(role, (role,)):
        model_id = role_models.get(candidate)
        if model_id:
            return model_id
    return None


def _rate_for(role: str | None, role_models: Mapping[str, str],
              pricing: PricingTable) -> ModelPricing | None:
    model_id = _resolve_model(role, role_models)
    if model_id is None:
        return None
    return pricing.models.get(model_id)


def _stage_cost(phases: Sequence[tuple[str | None, TokenBucket]],
                role_models: Mapping[str, str],
                pricing: PricingTable | None) -> float | None:
    """Sum a stage's per-phase costs, or ``None`` when it cannot be priced."""
    if pricing is None:
        return None
    total = 0.0
    for role, bucket in phases:
        rate = _rate_for(role, role_models, pricing)
        if rate is not None:
            # Pass the table's own derivation multipliers so an operator pricing
            # OpenAI models is not silently costed at Anthropic's ratios.
            total += bucket_cost_usd(bucket, rate, pricing.cache_defaults)
        elif _has_tokens(bucket):
            return None
    return total


def _stage_entry(stage_id: str, record: StageRecord | None,
                 phases: Sequence[tuple[str | None, TokenBucket]],
                 role_models: Mapping[str, str],
                 pricing: PricingTable | None) -> StageEntry:
    role = STAGE_ROLES.get(stage_id)
    return StageEntry(
        label=record["label"] if record else "",
        outcome=record["outcome"] if record else _NOT_RUN,
        duration_sec=record["duration_sec"] if record else None,
        tokens=_sum_buckets([bucket for _, bucket in phases]),
        model=_resolve_model(role, role_models),
        cost_usd=_stage_cost(phases, role_models, pricing),
        cost_estimated=stage_id in ESTIMATED_COST_STAGES,
    )


def _total_cost(stages: Mapping[str, StageEntry]) -> float | None:
    costs = [entry["cost_usd"] for entry in stages.values()]
    priced = [c for c in costs if c is not None]
    if len(priced) != len(costs):
        return None
    return sum(priced)


def _totals(token_snap: TokenSnapshot, stages: Mapping[str, StageEntry],
            unattributed: UnattributedTokens) -> Totals:
    by_phase = token_snap.get("by_phase", {})
    combined = _sum_buckets(list(by_phase.values()))
    # cache_unparsed is deliberately NOT part of ``TokenBucket``: it counts
    # calls whose cache accounting arrived under names nothing parses, and an
    # unparsed field's value can't be trusted enough to cost, so pricing must
    # never read it (see util/tokens.py). Summed here as a plain mapping key
    # rather than widened into the costing type.
    cache_unparsed_calls = sum(
        b.get("cache_unparsed", 0) for b in by_phase.values()
        if isinstance(b.get("cache_unparsed"), int))
    return Totals(
        prompt_tokens=token_snap.get("prompt", 0),
        completion_tokens=token_snap.get("completion", 0),
        total_tokens=token_snap.get("total", 0),
        cache_read_tokens=combined.get("cache_read", 0),
        cache_write_tokens=combined.get("cache_write", 0),
        calls=token_snap.get("calls", 0),
        calls_with_usage=token_snap.get("calls_with_usage", 0),
        completion_absent=token_snap.get("completion_absent", 0),
        cache_unparsed_calls=cache_unparsed_calls,
        cost_usd=_total_cost(stages),
        unattributed=unattributed,
    )


def _provenance(pricing: PricingTable | None) -> PricingProvenance | None:
    if pricing is None:
        return None
    return PricingProvenance(file=pricing.path, sha256=pricing.sha256,
                             source=pricing.source)


def _pricing_status(stages: Mapping[str, StageEntry],
                    pricing: PricingTable | None) -> PricingStatus:
    if pricing is None:
        return {"status": "unavailable", "reason": "no pricing table configured"}
    unpriced = sorted({entry["model"] for entry in stages.values()
                       if entry["cost_usd"] is None and entry["model"]})
    if unpriced:
        return {
            "status": "incomplete",
            "reason": "pricing missing for model(s): " + ", ".join(unpriced),
        }
    return {"status": "available", "reason": "pricing table applied"}


def _ordered_stage_ids(stage_snap: Mapping[str, StageRecord],
                       by_stage: Mapping[str, object]) -> list[str]:
    present = set(stage_snap) | set(by_stage)
    known = [s for s in STAGE_IDS if s in present]
    extra = [s for s in stage_snap if s not in STAGE_IDS]
    return known + extra


def compose_stage_section(stage_snap: Mapping[str, StageRecord],
                          token_snap: TokenSnapshot,
                          role_models: Mapping[str, str],
                          pricing: PricingTable | None) -> StageSection:
    """Build the manifest's ``stages``/``totals``/``pricing`` fields.

    Pure: every input is a snapshot, so the result never depends on live
    recorder state.

    Args:
        stage_snap: ``STAGES.snapshot()``.
        token_snap: ``TOKENS.snapshot()``.
        role_models: Config model role name to the resolved model id it runs on.
        pricing: The active price table, or ``None`` to report null costs.

    Returns:
        The three manifest fields. A stage appears when it was recorded or when
        any phase charged tokens to it; ``cost_usd`` is null for a stage whose
        token-bearing model has no price (and then for ``totals`` too).
    """
    by_stage, unattributed = _group_phases(token_snap)
    stages = {
        stage_id: _stage_entry(stage_id, stage_snap.get(stage_id),
                               by_stage.get(stage_id, []), role_models, pricing)
        for stage_id in _ordered_stage_ids(stage_snap, by_stage)
    }
    return StageSection(stages=stages,
                        totals=_totals(token_snap, stages, unattributed),
                        pricing=_provenance(pricing),
                        pricing_status=_pricing_status(stages, pricing))
