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

"""Per-stage status reporting for the scan pipeline.

A single context manager that prints a clear start / done(✓, timed) / failed(✗)
line for each stage so an operator (or an AI agent driving the tool) always
sees what the pipeline is doing and how long it took — and, on failure, a
one-line cause instead of a silent hang. Output goes to stderr (stdout stays
clean for piped reports). Plain timestamped lines, so it is safe under CI /
non-TTY / log capture; no cursor tricks.
"""
from __future__ import annotations

import itertools
import json
import os
import shutil
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.util.stage_telemetry import STAGES

# Braille spinner frames + a small ANSI palette for the live TTY loader.
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_CYAN, _GREEN, _RED, _YELLOW, _DIM, _RST = (
    "\033[36m", "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m")

# Un-underscored because they are meant to cross the module boundary: a
# stage-completion glyph is a product-wide vocabulary, and any module printing its own
# summary line should consume these rather than spell a second `✓` of its own. Several
# still do (cli.py, preflight.py, environment.py, remediation_agent/runner.py); converting
# them is a separate sweep.
# WARN_MARK is not "a failure" — it is "finished, with coverage lost", a distinction the
# process exit code does not currently carry either way.
OK_MARK, WARN_MARK, FAIL_MARK = "✓", "⚠", "✗"


@dataclass
class StageResult:
    """Optional non-error result annotation for a completed stage.

    Most callers ignore the value yielded by :func:`stage` and retain the
    usual success rendering.  Callers whose work can complete cleanly without
    achieving its objective may mark that result explicitly so it is not
    rendered with a success checkmark.
    """

    incomplete_detail: str = ""

    def mark_incomplete(self, detail: str) -> None:
        """Render this clean completion as incomplete, with *detail*."""
        self.incomplete_detail = detail


def _is_tty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:
        return False


class _Spinner:
    """Animate one stderr line in place — ``⠋ [n/total] label … 12s`` — until
    stopped, then clear it so the caller can print the final ✓/✗ line. TTY only;
    runs on a daemon thread so the stage body is never blocked."""

    def __init__(self, label, out, n=None, total=None):
        self._label, self._out, self._n, self._total = label, out, n, total
        self._stop = threading.Event()
        self._t0 = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def _run(self):
        tag = f"[{self._n}/{self._total}] " if self._n and self._total else ""
        for frame in itertools.cycle(_SPIN):
            if self._stop.is_set():
                break
            el = int(time.time() - self._t0)
            # Truncate the label to the terminal width so the whole status
            # stays on a single visual row. A line that wraps onto a second
            # row defeats the single-row ``\r\033[K`` rewrite and leaves every
            # frame behind — that is the spinner "spamming" the terminal.
            # Lengths are measured on the plain text (no ANSI), which is what
            # the terminal actually counts toward wrapping.
            cols = shutil.get_terminal_size((80, 24)).columns
            prefix = f"  {frame} {tag}"      # visible leading text
            suffix = f" … {el}s"             # visible trailing text
            budget = cols - len(prefix) - len(suffix) - 1
            label = self._label
            if budget > 1 and len(label) > budget:
                label = label[: budget - 1] + "…"
            self._out.write(f"\r\033[K  {_CYAN}{frame}{_RST} "
                            f"{tag}{label}{_DIM}{suffix}{_RST}")
            self._out.flush()
            self._stop.wait(0.12)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=1)
        self._out.write("\r\033[K")   # clear the spinner line
        self._out.flush()


def json_logs_enabled() -> bool:
    """Structured JSON event logging is on when VVAHARNESS_JSON_LOGS is set to
    a truthy value (1/true/yes). Lets dashboards/CI consume machine-readable
    per-stage events instead of the pretty ▶/✓ lines."""
    return os.environ.get("VVAHARNESS_JSON_LOGS", "").lower() in ("1", "true", "yes")


def emit_event(event: str, *, stream=None, **fields) -> None:
    """Emit one structured JSON log line (no-op unless JSON logs are enabled).
    Always machine-parseable: one compact JSON object per line on stderr."""
    if not json_logs_enabled():
        return
    out = stream if stream is not None else sys.stderr
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event}
    rec.update({k: v for k, v in fields.items() if v is not None})
    print(json.dumps(rec, separators=(",", ":")), file=out, flush=True)


@contextmanager
def stage(label: str, *, n: int | None = None, total: int | None = None,
          stream=None, animate: bool | None = None,
          stage_id: str | None = None):
    """Wrap a pipeline stage: emit a start line, time the body, and emit a ✓
    completion line (or a ✗ failure line) before propagating any exception.

    Emits pretty ▶/✓/✗ lines by default; when VVAHARNESS_JSON_LOGS is set it
    emits structured JSON events (stage_start / stage_ok / stage_fail) with
    timing instead, so the run is machine-observable.

    `stage_id` is the pipeline stage this call represents ("s0".."s11"). When
    given, the same timing already printed here is also recorded on the
    process-wide STAGES recorder (so the run manifest can report per-stage
    duration/cost) and tagged onto the JSON events. Non-pipeline callers omit
    it and are unaffected.

    `animate` controls the in-place spinner: by default it animates only on an
    interactive TTY. Pass ``animate=False`` to force the plain one-shot
    ``▶ … / ✓ …`` lines — use this when the stage body itself writes to the
    same stream (e.g. a long agentic subprocess), where a live spinner would
    otherwise interleave with that output and spam the terminal.

    Never swallows — the caller's own try/except decides whether a stage
    failure is fatal or degrades gracefully. This only guarantees the operator
    sees *which* stage and *why* it failed, rather than a bare traceback or a
    stall.

    A stage body that returns cleanly but recorded errlog entries while it ran
    (a tolerated fallback: a discarded model reply, a failed chunk) closes as
    ``completed_with_errors`` instead of plain ``completed``, and the ✓ line
    says how many records to look for in errors.jsonl. Records the log site
    stamped ``recovered=True`` (a repaired parse, a relocated path — nothing
    was lost) stay in errors.jsonl and its tallies but do not count toward
    the flip; an unmarked record always does. Purely observational:
    control flow, exceptions and exit codes are untouched, and a stage that
    logged nothing closes exactly as before."""
    out = stream if stream is not None else sys.stderr
    tag = f"[{n}/{total}] " if n is not None and total is not None else ""
    as_json = json_logs_enabled()
    # Live spinner only on an interactive terminal, unless the caller overrides.
    auto_animate = _is_tty(out)
    animate = (auto_animate if animate is None else animate) and not as_json
    t0 = time.time()
    spin = None
    err0 = (_errlog.count_for_stage(stage_id, include_recovered=False)
            if stage_id else 0)
    if stage_id:
        STAGES.start(stage_id, label)
    if as_json:
        emit_event("stage_start", stage=label, n=n, total=total,
                   stage_id=stage_id, stream=out)
    elif animate:
        spin = _Spinner(label, out, n, total).start()
    else:
        print(f"  ▶ {tag}{label} …", file=out, flush=True)
    result = StageResult()
    try:
        yield result
    except BaseException as e:  # noqa: BLE001 — report then re-raise
        dt = round(time.time() - t0, 2)
        if spin:
            spin.stop()
        if stage_id:
            STAGES.done(stage_id, outcome="error", duration_sec=dt)
        if as_json:
            emit_event("stage_fail", stage=label, n=n, total=total,
                       duration_sec=dt, stage_id=stage_id,
                       error=redact(f"{type(e).__name__}: {e}"), stream=out)
        else:
            x = f"{_RED}{FAIL_MARK}{_RST}" if animate else FAIL_MARK
            print(f"  {x} {tag}{label} — failed after {dt:.1f}s: "
                  f"{redact(f'{type(e).__name__}: {e}')}", file=out, flush=True)
        # Blank line so consecutive [n/total] stage blocks are visually
        # separated in the log (skipped in JSON mode — one object per line).
        if not as_json:
            print(file=out, flush=True)
        raise
    else:
        dt = round(time.time() - t0, 2)
        if spin:
            spin.stop()
        # A clean return with new errlog records for this stage is a tolerated
        # fallback, not a clean run: close it as completed_with_errors and say
        # so on the ✓ line. Only records NOT stamped recovered=True count:
        # every banked healthy run logs recovered transients (s4 parses whose
        # repair retry succeeded), and a marker that fires on healthy runs is
        # one operators learn to ignore — the exact failure mode this exists
        # to end. errors_by_stage still tallies the recovered records for
        # diagnosis; only the outcome ignores them. An unmarked record always
        # counts (fail-safe: a forgotten flag over-reports, never re-silences
        # a loss). Zero counting records keeps plain "completed" — a healthy
        # stage must look exactly as it always did.
        n_err = ((_errlog.count_for_stage(stage_id, include_recovered=False)
                  - err0) if stage_id else 0)
        if stage_id:
            outcome = "completed_with_errors" if n_err > 0 else "completed"
            STAGES.done(stage_id, outcome=outcome, duration_sec=dt)
        # "unrecovered", not "recoverable": n_err is computed with
        # include_recovered=False — precisely the records the pipeline did
        # NOT recover from. The old word applied errlog's "recovered"
        # vocabulary to its exact complement, telling an operator that a
        # permanent loss (a lost report ranking, a failed chunk) was
        # recoverable.
        note = (f", {n_err} unrecovered error(s) — see errors.jsonl"
                if n_err > 0 else "")
        # The glyph is derived from the SAME n_err the outcome and the note are,
        # never recomputed: a stage whose telemetry says completed_with_errors and
        # whose line says "N unrecovered error(s)" must not still be wearing ✓, and
        # three independent reads of the errlog would eventually disagree. Colour
        # alone would not do: the non-animate branch below is uncoloured, and a CI
        # log is exactly where a degraded stage was being read as a clean one.
        mark, colour = (WARN_MARK, _YELLOW) if n_err > 0 else (OK_MARK, _GREEN)
        if result.incomplete_detail and as_json:
            emit_event("stage_incomplete", stage=label, n=n, total=total,
                       duration_sec=dt, stage_id=stage_id,
                       detail=result.incomplete_detail, stream=out)
        elif as_json:
            emit_event("stage_ok", stage=label, n=n, total=total,
                       duration_sec=dt, stage_id=stage_id,
                       errors=n_err if n_err > 0 else None, stream=out)
        elif result.incomplete_detail:
            print(f"  ○ {tag}{label} — {result.incomplete_detail} ({dt:.1f}s{note})",
                  file=out, flush=True)
        elif animate:
            print(f"  {colour}{mark}{_RST} {tag}{label} {_DIM}({dt:.1f}s{note}){_RST}",
                  file=out, flush=True)
        else:
            print(f"  {mark} {tag}{label} ({dt:.1f}s{note})", file=out, flush=True)
        # Blank line so consecutive [n/total] stage blocks are visually
        # separated in the log (skipped in JSON mode — one object per line).
        if not as_json:
            print(file=out, flush=True)
