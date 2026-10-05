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
Degenerate-response detector for LLM backend return values (VVAH-E003).

A "degenerate" response is a 200 OK from the provider that nonetheless carries
content too thin to be useful: an empty body, a one-word acknowledgement, a
truncated mid-sentence fragment, or any text that doesn't contain the structural
markers the calling stage expects.

On the happy path this is a no-op. On repeated failure for the same stage it
raises DegenerateResponseError, which the stage's chunk handler catches and logs
without halting the whole scan.
"""
from __future__ import annotations

import sys
import threading
from contextlib import contextmanager
from collections.abc import Mapping
from typing import Iterator, Sequence

from vvaharness.backends.harness.models import DegenerateResponseError
# Module-scope is cycle-safe here even though this module sits under every
# llm backend AND imports backends.harness.models above: report.redact
# imports only stdlib, report/__init__.py is empty, and _errlog (already
# imported below) pulls in report.redact at module scope anyway — so this
# adds no edge the import graph doesn't already have.
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog

# ── Configuration ────────────────────────────────────────────────────────────

_DEFAULT_MIN_CHARS = 150
_DEFAULT_MIN_TOKENS = 30
_DEGENERATE_MAX_CONSECUTIVE = 3
# Head of the offending reply stored on the VVAH-E003 errlog record. A live
# run produced 55 E003 records that could not be root-caused from the
# artifact, because each carried only lengths ("response too short (15
# chars, ...)") — and 15 vs 16 chars is the difference between
# '{"findings":[]}' and '{"findings": []}', so even a mixed batch of trips
# could not be attributed to one reply shape. 300 chars is enough to tell
# every degenerate archetype apart (empty body, one-word acknowledgement,
# refusal sentence, short/misspelled JSON) while keeping the errors file —
# which ships to operators — small.
_RAW_HEAD_CHARS = 300

# ── State ────────────────────────────────────────────────────────────────────

_lock = threading.Lock()
_consecutive: dict[str, int] = {}
# Per-stage (min_chars, min_tokens) overrides of the two _DEFAULT_MIN_* floors,
# keyed by the same `stage` tag the backends pass to check_response_quality().
# None in either slot means "keep the default for that axis". See stage_floors().
_stage_floors: dict[str, tuple[int | None, int | None]] = {}


def reset_counters() -> None:
    """Reset all consecutive-failure counters (call between repos in batch runs)."""
    with _lock:
        _consecutive.clear()


@contextmanager
def stage_floors(
    stage: str,
    *,
    min_chars: int | None = None,
    min_tokens: int | None = None,
) -> Iterator[None]:
    """Scoped per-stage override of the VVAH-E003 minimum-response floors.

    The global floors — _DEFAULT_MIN_CHARS (150) and _DEFAULT_MIN_TOKENS (30)
    — are sized for prose/report stages and misfire on a stage whose entire
    valid output is short: an autoexclude YAML overlay is ~120-150 chars
    (live models tripped the char floor with correct answers) and ~31-46
    output tokens, right on the token floor, with fully-valid single-key
    overlays as low as ~11 tokens. Every shipped backend calls
    check_response_quality() without `min_chars`, keyed by the stage `tag`,
    so a stage can set floors that fit its real output by wrapping its
    dispatch in this context manager — no parameter plumbed through four
    backends. A floor left as None keeps that axis's default; an explicitly
    passed `min_chars` always wins over the override.
    """
    with _lock:
        prev = _stage_floors.get(stage)
        _stage_floors[stage] = (
            int(min_chars) if min_chars is not None else None,
            int(min_tokens) if min_tokens is not None else None,
        )
    try:
        yield
    finally:
        with _lock:
            if prev is None:
                _stage_floors.pop(stage, None)
            else:
                _stage_floors[stage] = prev


# ── Public API ───────────────────────────────────────────────────────────────

def output_tokens_for_gate(usage: Mapping[str, object] | None) -> int | None:
    """The ``output_tokens`` value to hand :func:`check_response_quality`.

    Distinguishes THREE states that the four backends previously collapsed in
    two incompatible directions, which made the token floor either inert or
    permanently tripped depending on the route:

    * no usage payload at all -> ``None``: nothing was measured, so the token
      axis must not judge. (All four routes already agreed here.)
    * usage present but no ``output_tokens`` key -> ``None``. This is the case
      that mattered: three backends coerced it to ``0`` with ``or 0``, so a
      gateway that reports usage without that field failed the token floor on
      EVERY reply. On a stage whose tag is a shared constant that reaches the
      3-consecutive limit and starts discarding good work.
    * usage present and ``output_tokens`` genuinely ``0`` -> ``0``. A real
      measurement of nothing IS degenerate and must trip. ``via: cli`` used to
      map this to ``None`` via ``or None``, hiding it.

    Absent-vs-zero is the whole point, so do not reintroduce ``or 0`` / ``or
    None`` at a call site: pass the payload here instead.
    """
    if usage is None:
        return None
    raw = usage.get("output_tokens")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        # A non-numeric field is not a measurement either; skip the axis rather
        # than letting a bad payload masquerade as zero output.
        return None


def check_response_quality(
    text: str,
    stage: str = "",
    *,
    min_chars: int | None = None,
    output_tokens: int | None = None,
    expected_markers: Sequence[str] | None = None,
) -> None:
    """Validate that *text* meets the minimum quality bar for *stage*.

    Raises DegenerateResponseError after _DEGENERATE_MAX_CONSECUTIVE consecutive
    failures for the same stage. Logs a warning to stderr and errlog on first
    and intermediate failures. When *min_chars* is not passed, each floor is
    the stage's active stage_floors() override, else the _DEFAULT_MIN_* value.
    """
    with _lock:
        ov_chars, ov_tokens = _stage_floors.get(stage, (None, None))
    if min_chars is None:
        min_chars = ov_chars if ov_chars is not None else _DEFAULT_MIN_CHARS
    min_tokens = ov_tokens if ov_tokens is not None else _DEFAULT_MIN_TOKENS
    stripped = (text or "").strip()
    reasons: list[str] = []

    if len(stripped) < min_chars:
        reasons.append(
            f"response too short ({len(stripped)} chars, threshold={min_chars})"
        )

    if output_tokens is not None and output_tokens < min_tokens:
        reasons.append(
            f"output token count too low ({output_tokens} tokens, "
            f"threshold={min_tokens})"
        )

    if expected_markers:
        missing = [m for m in expected_markers if m not in stripped]
        if missing:
            reasons.append(f"expected marker(s) absent: {missing!r}")

    if not reasons:
        with _lock:
            _consecutive.pop(stage, None)
        return

    # ── Degenerate response detected ─────────────────────────────────────────
    with _lock:
        count = _consecutive.get(stage, 0) + 1
        _consecutive[stage] = count

    summary = "; ".join(reasons)
    label = f"[{stage}]" if stage else ""

    if count < _DEGENERATE_MAX_CONSECUTIVE:
        print(
            f"    [quality] WARN VVAH-E003{label}: degenerate response "
            f"({count}/{_DEGENERATE_MAX_CONSECUTIVE} consecutive): {summary}",
            file=sys.stderr,
        )
        _errlog.log(
            stage or "quality",
            stage or "response_quality",
            f"VVAH-E003 warning ({count}/{_DEGENERATE_MAX_CONSECUTIVE}): {summary}",
            error_code=DegenerateResponseError.error_code,
            # The reply's head, so the record is diagnosable from the artifact
            # alone (see _RAW_HEAD_CHARS). redact() the FULL text BEFORE the
            # cap, never after: capping first can bisect a credential so the
            # surviving fragment no longer matches any redaction pattern and
            # egresses under a field that reads as already scrubbed. errlog
            # redacts its string fields too, but only after receiving them —
            # same redact-before-cap rule as s2's raw_head and errlog's own
            # traceback tail.
            raw_head=redact(stripped)[:_RAW_HEAD_CHARS],
            # recovered=True: an intermediate warning returns the response to
            # the caller; the terminal case raises DegenerateResponseError,
            # which the calling stage catches and logs unmarked — that record
            # carries no head, but it can only be reached after two warning
            # records above have stored theirs for the same tag.
            recovered=True,
        )
        return

    # Threshold reached — reset to 1 so warnings restart rather than every
    # subsequent call immediately re-raising.
    with _lock:
        _consecutive[stage] = 1

    # `threshold` must name the axis that actually failed. It was hard-wired to
    # min_chars, so a 400-char reply tripped only on tokens still reported
    # "len=400 (threshold=90)" — a record asserting a bar the reply cleared four
    # times over, which is exactly the misdirection the raw_head field was added
    # to end. Per-stage floors make token-only trips the common case, so report
    # the char floor only when the char axis is the one that failed.
    char_axis_failed = len(stripped) < min_chars
    raise DegenerateResponseError(
        summary,
        stage=stage,
        response_len=len(stripped),
        threshold=min_chars if char_axis_failed else 0,
        consecutive=count,
    )
