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
Structured error log shared across pipeline stages.

Each entry is one JSON line: {ts, stage, unit, error, ...extra}. Steps call
log() from their except-handlers so transient failures (DNS blips, SDK
timeouts, parse errors) are recorded next to the report instead of being
lost in stderr scrollback.

the orchestrator calls configure() once per scan to point the log at
  <repo>/security-scan/<module>_<ts>_errors.jsonl
"""
from __future__ import annotations

import json
import os
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path

from vvaharness.report.redact import redact

_path: Path = Path("pipeline-errors.jsonl")
_lock = threading.Lock()


def configure(path: str | Path) -> None:
    global _path
    _path = Path(path)
    _path.parent.mkdir(parents=True, exist_ok=True)


def current_path() -> Path:
    """The errors-log path currently configured (for a report-time pointer)."""
    return _path


def counts_by_stage(path: str | Path | None = None, *,
                    include_recovered: bool = True) -> dict[str, int]:
    """Re-read the errors JSONL and tally records per `stage`.

    Best-effort and read-only: a missing or partially-garbled file yields an
    empty/partial map rather than raising. Intentionally takes no lock — it is
    read at stage boundaries (``status.stage`` via :func:`count_for_stage`)
    and once at report time, all single-threaded points, so the latent
    reentrancy a lock would add is not worth it. This is a COARSE per-stage error-record
    count (a stage may log several records per failed unit, e.g. one per run
    retry); authoritative chunk-failure counts come from the s4 chunk outcomes,
    not from here.

    ``include_recovered=False`` skips records :func:`log` stamped
    ``recovered=True`` — transients the pipeline already recovered from. The
    check is strict (the JSON literal ``true`` only): a record with no
    ``recovered`` field, or any other value in it, always counts, so an
    unmarked loss can over-report but never slip back to silence.
    """
    p = Path(path) if path is not None else _path
    counts: dict[str, int] = {}
    try:
        with p.open("r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rec = json.loads(ln)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not include_recovered and rec.get("recovered") is True:
                    continue
                stage = rec.get("stage")
                if isinstance(stage, str):
                    counts[stage] = counts.get(stage, 0) + 1
    except OSError:
        return counts
    return counts


def count_for_stage(stage_id: str, path: str | Path | None = None, *,
                    include_recovered: bool = True) -> int:
    """Total error records attributed to pipeline stage *stage_id*.

    Stage labels in the log are heterogeneous ("s3", "s4 chunk-08",
    "s6-verify", "s1.autoexclude"), so attribution is boundary-aware prefix
    matching: "s1" claims "s1.autoexclude" but never "s10". Best-effort and
    read-only, like counts_by_stage(); ``include_recovered`` forwards there.
    """
    total = 0
    for label, n in counts_by_stage(
            path, include_recovered=include_recovered).items():
        if label == stage_id or (label.startswith(stage_id)
                                 and not label[len(stage_id)].isalnum()):
            total += n
    return total


def log(stage: str, unit: str, error: BaseException | str, *,
        recovered: bool = False, **extra) -> None:
    """Append one JSONL record. Never raises.

    When *error* is an exception that self-identifies with an ``error_code``
    attribute (the VVAH-Exxx taxonomy in ``backends/harness/models.py``), the
    code is stamped onto the record; an explicit ``error_code=`` in *extra*
    wins. Generic exceptions carry no code and record without one, as before.

    ``recovered=True`` marks a transient the pipeline is known to survive with
    NOTHING lost (a parse whose repair retry succeeds, a file path relocated
    to its real location) — or a purely informational diagnostic of designed
    behaviour (a validator rejecting hallucinated call-graph edges, a
    containment guard refusing an out-of-repo read, a designed empty-chunk
    skip) whose genuine loss-paths log their own unmarked records. The record
    keeps its full diagnostics in the log
    and in every tally that reads it, but is excluded from the delta that
    flips a stage to ``completed_with_errors`` (``status.stage``) — a marker
    that fires on healthy runs is one operators learn to ignore. Only mark a
    site whose failure path logs a second, unmarked record (or raises): the
    default counts, so a forgotten flag over-reports rather than restoring
    the silent-degradation defect. Every new ``log()`` call site must
    be classified degrading-vs-informational when it is added — the guard in
    tests/test_degradation_composition_wave1.py enforces exactly that.
    """
    if isinstance(error, BaseException):
        msg = f"{type(error).__name__}: {error}"
        code = getattr(error, "error_code", None)
        if isinstance(code, str) and "error_code" not in extra:
            extra["error_code"] = code
        # Redact BEFORE the tail slice. Slicing first can cut a credential at
        # the -4000 boundary, dropping its leading anchor (`AKIA…`, `eyJ…`);
        # the surviving suffix then matches no redaction pattern and would be
        # written to disk in the clear. The tail itself is deliberate — a
        # traceback's END is the informative part — so only the redaction
        # moved inside the slice, never the slice inside the redaction.
        tb = redact("".join(traceback.format_exception(
            type(error), error, error.__traceback__)))[-4000:]
    else:
        msg, tb = str(error), None

    msg = redact(msg)
    safe_extra = {k: (redact(v) if isinstance(v, str) else v)
                  for k, v in extra.items()}
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        # `stage` is a fixed pipeline label; `unit` is repo-derived (a file
        # path / chunk id) so it is redacted too — a credential-shaped substring
        # in a path must not bypass the scrub applied to the other fields.
        "stage": stage,
        "unit": redact(unit) if isinstance(unit, str) else unit,
        "error": msg,
        **safe_extra,
    }
    if recovered:
        # Stamped only when set, and normalized to the bool literal — the
        # counting side matches `is True` strictly, and an untouched call
        # site keeps writing byte-identical records.
        rec["recovered"] = True
    if tb:
        rec["traceback"] = tb
    try:
        with _lock:
            # Tighten perms on first create so an errors log (which carries
            # redacted-but-still-sensitive context) isn't world-readable under
            # the default umask on shared CI hosts. exists() must be inside the
            # lock to avoid a TOCTOU with a concurrent writer.
            newly_created = not _path.exists()
            with _path.open("a", encoding="utf-8") as f:
                if newly_created:
                    try:
                        os.chmod(_path, 0o600)
                    except OSError:
                        pass  # Windows / unsupported FS — best-effort
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001
        print(f"WARN [_errlog]: failed to write {rec.get('stage')}/{rec.get('unit')}: {e}",
              file=sys.stderr)
