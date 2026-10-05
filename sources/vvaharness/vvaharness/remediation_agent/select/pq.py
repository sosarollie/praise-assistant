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

"""remediation_agent.select.pq — the priority-queue "top N by CVSS" selector.

The actual selection: a :mod:`heapq` priority queue keyed by CVSS score (with a
band→score fallback and a stable original-position tie-breaker), plus the logged
wrapper both remediation entry points share."""
from __future__ import annotations

import heapq
import sys
from typing import Callable, Sequence, TypeVar

T = TypeVar("T")


# Fallback score by qualitative severity band when no numeric CVSS base score
# is available — the midpoint-ish CVSS 3.1 band anchors, so a band-only
# CRITICAL still outranks a numeric 7.5 HIGH, etc.
_BAND_SCORE: dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "INFO": 0.0,
}


def band_score(severity: str | None) -> float:
    """Map a qualitative severity band ("CRITICAL"/"HIGH"/…) to a fallback
    numeric score; unknown/empty bands score 0.0."""
    return _BAND_SCORE.get((severity or "").strip().upper(), 0.0)


def select_top_by_cvss(
    items: Sequence[T],
    n: int | None,
    score_of: Callable[[T], float | None],
    *,
    severity_of: Callable[[T], str | None] | None = None,
) -> list[T]:
    """Return the *n* highest-CVSS items, ordered highest→lowest.

    Implemented with a priority queue: each item is pushed as
    ``(-score, original_index)`` so :mod:`heapq` (a min-heap) yields the highest
    score first; the original index is a stable tie-breaker and keeps heap
    comparisons total (items themselves are never compared). The queue is
    popped ``min(n, len(items))`` times to produce the selection.

    ``score_of`` extracts a numeric CVSS base score from an item; when it
    returns ``None`` the band fallback (via ``severity_of``, defaulting to a
    ``.severity`` attribute) is used.

    Behaviour is consistent for any positive *n*: the result is always reordered
    highest→lowest by score, even when *n* covers (or exceeds) every item — so
    ``--top 3`` of 3 and ``--top 2`` of 3 order their output the same way, with
    no seam where a larger *n* would silently fall back to report order. When
    ``n`` is ``None`` (flag absent) or non-positive (a stray ``--top 0`` /
    negative), the input is returned unchanged — no reorder, nothing dropped."""
    if n is None or n <= 0:
        return list(items)

    def _score(it: T) -> float:
        s = score_of(it)
        if s is not None:
            return float(s)
        sev = (severity_of(it) if severity_of is not None
               else getattr(it, "severity", None))
        return band_score(sev)

    heap: list[tuple[float, int]] = [(-_score(it), i) for i, it in enumerate(items)]
    heapq.heapify(heap)
    return [items[heapq.heappop(heap)[1]] for _ in range(min(n, len(heap)))]


def select_top_logged(
    items: Sequence[T],
    n: int | None,
    score_of: Callable[[T], float | None],
    *,
    severity_of: Callable[[T], str | None] | None = None,
    log_prefix: str,
) -> list[T]:
    """:func:`select_top_by_cvss` plus the shared "selecting top N of M" log line.

    Both remediation entry points apply the SAME ``--top N`` gate and emit the
    SAME message (only the bracketed prefix differs), so the gate + message live
    here once rather than being copy-pasted at each call site. The line is
    printed to stderr only when a selection actually narrows the set (a positive
    ``n`` strictly below the total); otherwise the input is returned untouched
    and nothing is logged."""
    total = len(items)
    selected = select_top_by_cvss(items, n, score_of, severity_of=severity_of)
    if n is not None and 0 < n < total:
        print(f"  {log_prefix} selecting top {n} of {total} finding(s) "
              f"by CVSS score", file=sys.stderr)
    return selected
