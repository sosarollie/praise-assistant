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
Process-wide token accounting shared by every model backend (cli + sdk).

Both backends call TOKENS.add(usage_dict) so ScanMetrics sees one unified
total regardless of how each step reached the model.

Per-phase buckets: the orchestrator wraps each step in `with TOKENS.phase("sN")`.
Phases never overlap (s4/s6 thread pools run inside one phase), so a single
global current-phase string is sufficient.
"""
from __future__ import annotations
import re
import threading
from collections import defaultdict
from contextlib import contextmanager
from typing import NamedTuple, TypedDict

from vvaharness.util.warn_once import warn_once


class TokenUsage(TypedDict, total=False):
    """The usage fields a backend reports, in Anthropic's field names; every reader defaults absent ones to 0."""

    input_tokens: int
    # None means the provider sent an explicit null (or omitted the count on a
    # route that can tell). add() coerces it to 0 for the totals AFTER counting
    # it under `completion_absent`, so backends must pass the null through
    # rather than pre-coercing with `or 0` — pre-coercion at the backend seam
    # is exactly what kept the counter permanently at zero on the openai route.
    output_tokens: int | None
    cache_creation_input_tokens: int
    cache_read_input_tokens: int


DEFAULT_PHASE = "unscoped"


class Spend(NamedTuple):
    """A cumulative reading of REPORTED cost/turns, with separate report counts since backends report each independently."""

    usd: float = 0.0
    turns: int = 0
    usd_reports: int = 0
    turn_reports: int = 0


def reported_between(before: Spend, after: Spend) -> tuple[float | None, int | None]:
    """The (usd, turns) reported in the window between two readings, None where nothing was; assumes non-overlapping calls."""
    usd = (after.usd - before.usd
           if after.usd_reports > before.usd_reports else None)
    turns = (after.turns - before.turns
             if after.turn_reports > before.turn_reports else None)
    return usd, turns


# Content-aware token estimation.
#
# The ONE offline estimator this codebase uses wherever a token count must be
# guessed from text: the backends' minimum-cacheable-size gates (backends/
# sdk.py, backends/oai.py) and the cache probe's filler sizing check
# (orchestrator/preflight.py). A single shared implementation, so the gate
# and the probe that audits it can never disagree about a text's size.
#
# chars/4 is a single ratio, but the real chars-per-token differs sharply by
# content class. Measured on this pipeline's prompts and reconciled to billed
# usage, dense numbered source runs ~2.45 chars/token (line-number digits,
# indentation and operators each fragment into their own tokens) while
# narrative prose and JSON schema run ~4.4. A flat divisor therefore
# UNDER-counts dense source — chars/4 gives ~1.63x too few tokens on it — and
# only happens to be right for prose. Estimate the divisor from the content's
# own character mix instead: the share of non-space, non-alphabetic
# characters (digits + punctuation + operators) is a cheap, dependency-free
# proxy for tokenization density.
#
# tiktoken was considered and rejected. It is OpenAI's BPE, not the tokenizer
# that meters this pipeline's Anthropic calls, and it does NOT reproduce the
# billed ratios for this workload — it splits the same dense source at ~3.4
# chars/token, not the billed ~2.45. Pinning this path to it would also add a
# hard runtime dependency on a package the backends only have transitively
# (it arrives as a langchain-openai transitive) and cannot assume is present.
# A char-mix estimate calibrated to OUR billed anchors is both cheaper and
# closer to the tokenizers that bill us.

_CPT_PROSE = 4.4       # chars/token for narrative + schema text
_CPT_DENSE = 2.45      # chars/token for dense numbered source
_DENSE_FRAC_LO = 0.08  # <= this fraction of digits/punctuation reads as prose
_DENSE_FRAC_HI = 0.34  # >= this reads as fully dense numbered source


def estimate_tokens(text: str) -> int:
    """Content-aware token estimate for `text` (see the notes above). One O(n)
    pass over the string; n is bounded by the caller's prompt size (~200 KB)
    and this runs once per call, so the pass is negligible next to network I/O."""
    n = len(text)
    if n <= 0:
        return 0
    dense = 0
    for ch in text:
        if not ch.isspace() and not ch.isalpha():
            dense += 1
    frac = dense / n
    if frac <= _DENSE_FRAC_LO:
        cpt = _CPT_PROSE
    elif frac >= _DENSE_FRAC_HI:
        cpt = _CPT_DENSE
    else:
        span = (frac - _DENSE_FRAC_LO) / (_DENSE_FRAC_HI - _DENSE_FRAC_LO)
        cpt = _CPT_PROSE + span * (_CPT_DENSE - _CPT_PROSE)
    return int(n / cpt)


def _bucket() -> dict:
    # `cache_unparsed` counts CALLS whose usage carried cache accounting
    # under key names no backend parses (see unparsed_cache_keys) — not
    # tokens, because an unparsed field's semantics can't be trusted enough
    # to add its value into any total.
    return {"prompt": 0, "completion": 0, "cache_read": 0,
            "cache_write": 0, "calls": 0, "cache_unparsed": 0,
            "usd": 0.0, "turns": 0}


# Unparsed cache accounting.
#
# add() coerces missing cache fields with `or 0`, so a provider that reports
# its cache accounting under names no backend parses (Bedrock's camelCase
# cacheReadInputTokens/cacheWriteInputTokens, a gateway's private
# prompt_tokens_details variants, ...) is indistinguishable from a provider
# reporting a real zero — in every artifact this process keeps. Backends
# therefore filter their RAW usage dict through unparsed_cache_keys() before
# normalising it and record any hit via TOKENS.note_cache_unparsed(), which
# counts the call in the current phase's `cache_unparsed` bucket entry so
# the blind spot is machine-visible rather than log-only.
#
# Security: KEY NAMES ONLY are ever returned — never values. A hostile
# gateway controls its own usage payload and could smuggle an arbitrary
# string as a key name, so a name is only reportable when it looks like an
# identifier (strict charset, max 64 chars) AND mentions "cache"
# (case-insensitive); the reported set is deduped, sorted and capped.

_UNPARSED_CACHE_KEY_RX = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_UNPARSED_CACHE_KEY_CAP = 8


def unparsed_cache_keys(usage, parsed) -> tuple[str, ...]:
    """The cache-ish key names in `usage` that `parsed` does not cover.

    `parsed` is the caller's set of key names it already parses or knowingly
    accounts for. A key is reported when it is a string passing the
    identifier filter above, mentions "cache", is outside `parsed`, and is
    present with a non-None value — present-as-zero still counts (a 0 under
    an unparsed name is information; an absent field is not), while the
    None a typed-model dump fabricates for a field the wire never sent does
    not. Returns a sorted, capped tuple of key names; never values.
    """
    if not isinstance(usage, dict):
        return ()
    hits = {
        k for k, v in usage.items()
        if isinstance(k, str) and k not in parsed and v is not None
        and "cache" in k.lower() and _UNPARSED_CACHE_KEY_RX.match(k)
    }
    return tuple(sorted(hits)[:_UNPARSED_CACHE_KEY_CAP])


class _TokenCounter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._phase = DEFAULT_PHASE
        self.prompt = 0
        self.completion = 0
        self.calls = 0
        self.calls_with_usage = 0
        # Usage records whose completion count arrived as an explicit null
        # (some gateways send one on very short calls). The total coerces it
        # to 0 — there is nothing else to bill — but the coercion is counted,
        # so a run whose completion counts were absent stays distinguishable
        # from one that genuinely produced no output.
        self.completion_absent = 0
        self.usd = 0.0
        self.turns = 0
        self.usd_reports = 0
        self.turn_reports = 0
        self.by_phase: dict[str, dict] = defaultdict(_bucket)
        # Distinct (via, key-set) pairs already noted on stderr, so each
        # backend logs one line per distinct unparsed key-set per process
        # instead of once per call.
        self._cache_unparsed_seen: set[tuple] = set()
        # warn-once registry for null completion counts: one stderr note per
        # counter lifetime; noting every short preflight ping would be noise.
        self._completion_absent_noted: set[str] = set()

    @contextmanager
    def phase(self, name: str):
        prev, self._phase = self._phase, name
        try:
            yield
        finally:
            self._phase = prev

    def current_phase(self) -> str:
        with self._lock:
            return self._phase

    def add(self, usage: TokenUsage | None, *,
            usd: float | None = None, turns: int | None = None) -> None:
        """Record one usage record; *usd*/*turns* of None means unreported, not zero (see :class:`Spend`).

        ``calls`` counts model API requests that returned a response, at the
        same granularity on every route. One record is normally one request;
        a record that pre-sums a whole multi-turn session (the deepagents
        route's ``SessionUsage``) carries its request count under a ``calls``
        key, and both ``calls`` and ``calls_with_usage`` advance by that
        count — every request folded into such a record carried usage by
        construction, so the two counters stay mutually consistent at
        request granularity.
        """
        with self._lock:
            n_requests = 1
            if isinstance(usage, dict):
                raw_calls = usage.get("calls")
                if (isinstance(raw_calls, int)
                        and not isinstance(raw_calls, bool) and raw_calls > 0):
                    n_requests = raw_calls
            self.calls += n_requests
            b = self.by_phase[self._phase]
            b["calls"] += n_requests
            if usd is not None:
                self.usd_reports += 1
                self.usd += usd
                b["usd"] += usd
            if turns is not None:
                self.turn_reports += 1
                self.turns += turns
                b["turns"] += turns
            if not isinstance(usage, dict):
                return
            self.calls_with_usage += n_requests
            fresh = int(usage.get("input_tokens", 0) or 0)
            cw = int(usage.get("cache_creation_input_tokens", 0) or 0)
            cr = int(usage.get("cache_read_input_tokens", 0) or 0)
            out_raw = usage.get("output_tokens", 0)
            if out_raw is None:
                # Explicit null completion count: coerce to 0 for the totals,
                # but count the coercion (see completion_absent) and note it
                # once so the absence is visible rather than incidental.
                self.completion_absent += 1
                warn_once(
                    self._completion_absent_noted,
                    "null-completion-count",
                    "  [tokens] WARN: a usage record carried a null "
                    "completion count; coerced to 0 (occurrences counted "
                    "under completion_absent)",
                )
            out = int(out_raw or 0)
            # Headline "prompt" = billable input (fresh + cache-write). cache-read
            # is ~10% cost and tracked separately so it doesn't inflate the total.
            self.prompt += fresh + cw
            self.completion += out
            b["prompt"] += fresh + cw
            b["completion"] += out
            b["cache_read"] += cr
            b["cache_write"] += cw

    def spend(self) -> Spend:
        """A point-in-time reading, for diffing across one engine call."""
        with self._lock:
            return Spend(usd=self.usd, turns=self.turns,
                         usd_reports=self.usd_reports, turn_reports=self.turn_reports)

    def note_cache_unparsed(self, keys: tuple[str, ...], *,
                            via: str = "") -> bool:
        """Count one call whose usage carried cache accounting under key
        names nothing parses (see unparsed_cache_keys). Bumps the current
        phase's `cache_unparsed` bucket entry for EVERY affected call;
        returns True only the first time this (`via`, key-set) is seen in
        the process, so the caller emits its single stderr note per distinct
        key-set rather than once per call."""
        if not keys:
            return False
        with self._lock:
            self.by_phase[self._phase]["cache_unparsed"] += 1
            marker = (via, keys)
            if marker in self._cache_unparsed_seen:
                return False
            self._cache_unparsed_seen.add(marker)
            return True

    def reset(self) -> None:
        with self._lock:
            self.prompt = self.completion = self.calls = self.calls_with_usage = 0
            self.completion_absent = 0
            self.usd = 0.0
            self.turns = self.usd_reports = self.turn_reports = 0
            self.by_phase = defaultdict(_bucket)
            self._cache_unparsed_seen = set()
            self._completion_absent_noted = set()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "prompt": self.prompt,
                "completion": self.completion,
                "total": self.prompt + self.completion,
                "calls": self.calls,
                "calls_with_usage": self.calls_with_usage,
                "completion_absent": self.completion_absent,
                "usd": self.usd if self.usd_reports else None,
                "turns": self.turns if self.turn_reports else None,
                "by_phase": {k: dict(v) for k, v in self.by_phase.items()},
            }


TOKENS = _TokenCounter()
