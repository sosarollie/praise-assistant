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

"""Unit tests for vvaharness.util.errlog (structured JSONL error log)."""
from __future__ import annotations

import json
import traceback

from vvaharness.report.redact import redact
from vvaharness.util import errlog

# A planted secret that the redactor matches via a fixed pattern (no validator):
# a GitHub personal-access token. The literal token bytes must never survive
# into the written log line.
_PLANTED_SECRET = "ghp_" + "A" * 36
_REDACTED_MARK = "[REDACTED-GITHUB-TOKEN]"


# errlog._path is a process-wide singleton; the autouse _isolate_errlog_path
# fixture in tests/conftest.py pins it to a per-test temp file, so test order
# never matters. Every test below sets its own path via configure() or a
# monkeypatch before reading anything back.


def _read_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return [ln for ln in f.read().splitlines() if ln]


# configure()

def test_configure_sets_path(tmp_path):
    target = tmp_path / "scan" / "mod_errors.jsonl"
    errlog.configure(target)
    assert errlog._path == target


def test_configure_creates_parent_dir(tmp_path):
    target = tmp_path / "nested" / "deeper" / "errors.jsonl"
    assert not target.parent.exists()
    errlog.configure(target)
    assert target.parent.is_dir()


def test_configure_accepts_str_and_normalizes_to_path(tmp_path):
    target = tmp_path / "as_str.jsonl"
    errlog.configure(str(target))
    from pathlib import Path
    assert isinstance(errlog._path, Path)
    assert errlog._path == target


def test_configure_idempotent_when_parent_exists(tmp_path):
    target = tmp_path / "exists" / "errors.jsonl"
    target.parent.mkdir(parents=True)
    # Must not raise (exist_ok=True).
    errlog.configure(target)
    errlog.configure(target)
    assert target.parent.is_dir()


# log() — happy path / JSONL shape

def test_log_writes_one_json_line(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("verify", "unit-1", "boom happened")
    lines = _read_lines(target)
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["stage"] == "verify"
    assert rec["unit"] == "unit-1"
    assert rec["error"] == "boom happened"
    assert "ts" in rec and rec["ts"]


def test_log_appends_multiple_lines(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("a", "u1", "first")
    errlog.log("b", "u2", "second")
    lines = _read_lines(target)
    assert len(lines) == 2
    assert json.loads(lines[0])["error"] == "first"
    assert json.loads(lines[1])["error"] == "second"


def test_log_string_error_has_no_traceback_key(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "plain string error")
    rec = json.loads(_read_lines(target)[0])
    assert "traceback" not in rec


def test_log_exception_records_type_message_and_traceback(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    try:
        raise ValueError("something failed")
    except ValueError as e:
        errlog.log("stage", "unit", e)
    rec = json.loads(_read_lines(target)[0])
    assert rec["error"] == "ValueError: something failed"
    assert "traceback" in rec
    assert "ValueError" in rec["traceback"]


def test_log_ts_is_utc_isoformat_seconds(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg")
    rec = json.loads(_read_lines(target)[0])
    # timespec="seconds" → no fractional seconds; UTC → +00:00 offset.
    assert "." not in rec["ts"]
    assert rec["ts"].endswith("+00:00")


# log() — extras

def test_log_extra_string_is_included(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg", file="src/app.py")
    rec = json.loads(_read_lines(target)[0])
    assert rec["file"] == "src/app.py"


def test_log_non_string_extras_stay_typed(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg",
               attempt=3, ratio=0.5, ok=True, items=[1, 2], meta={"k": "v"},
               nothing=None)
    rec = json.loads(_read_lines(target)[0])
    # Non-string extras must not be coerced or run through redact().
    assert rec["attempt"] == 3 and isinstance(rec["attempt"], int)
    assert rec["ratio"] == 0.5 and isinstance(rec["ratio"], float)
    assert rec["ok"] is True
    assert rec["items"] == [1, 2]
    assert rec["meta"] == {"k": "v"}
    assert rec["nothing"] is None


# log() — error_code stamping

def test_log_stamps_error_code_from_coded_exception(tmp_path):
    """A VVAH-Exxx exception self-identifies; its code must reach the record
    instead of landing as null (the S3 fallback records carried no
    code because the call site passed none)."""
    from vvaharness.backends.harness.models import DegenerateResponseError
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    try:
        raise DegenerateResponseError("too thin", stage="s4")
    except DegenerateResponseError as e:
        errlog.log("s4 chunk-01", "chunk-01", e)
    rec = json.loads(_read_lines(target)[0])
    assert rec["error_code"] == "VVAH-E003"


def test_log_explicit_error_code_extra_wins_over_stamp(tmp_path):
    from vvaharness.backends.harness.models import DegenerateResponseError
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    try:
        raise DegenerateResponseError("too thin", stage="s4")
    except DegenerateResponseError as e:
        errlog.log("s4", "chunk-01", e, error_code="VVAH-E001")
    rec = json.loads(_read_lines(target)[0])
    assert rec["error_code"] == "VVAH-E001"


def test_log_uncoded_exception_still_records_without_code(tmp_path):
    """Generic exceptions (ValueError, pydantic ValidationError) carry no
    code; the record is written as before, just without the key."""
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    try:
        raise ValueError("no code on me")
    except ValueError as e:
        errlog.log("s3", "task-manifest", e)
    rec = json.loads(_read_lines(target)[0])
    assert rec["error"] == "ValueError: no code on me"
    assert "error_code" not in rec


# count_for_stage()

def test_count_for_stage_is_boundary_aware(tmp_path):
    """Labels are heterogeneous; "s1" claims "s1.autoexclude" and "s1 mapper"
    but never "s10" (the prefix trap), and "s6" claims "s6-verify"."""
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("s1", "mapper", "a")
    errlog.log("s1.autoexclude", "overlay", "b")
    errlog.log("s1 mapper", "mapper", "c")
    errlog.log("s10", "patch", "d")
    errlog.log("s6-verify", "finding-1", "e")
    assert errlog.count_for_stage("s1") == 3
    assert errlog.count_for_stage("s10") == 1
    assert errlog.count_for_stage("s6") == 1
    assert errlog.count_for_stage("s2") == 0


def test_count_for_stage_missing_file_is_zero(tmp_path):
    errlog.configure(tmp_path / "never-written.jsonl")
    assert errlog.count_for_stage("s3") == 0


# log() / count_for_stage() — recovered-transient marking

def test_recovered_record_keeps_full_diagnostics(tmp_path):
    """recovered=True changes what COUNTS toward the stage outcome, not what
    is RECORDED: the record stays in the log with its message, traceback and
    extras intact, plus the bool flag."""
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    try:
        raise ValueError("JSON parse failed")
    except ValueError as e:
        errlog.log("s4", "chunk-01", e, recovered=True, phase="repair")
    rec = json.loads(_read_lines(target)[0])
    assert rec["recovered"] is True
    assert rec["error"] == "ValueError: JSON parse failed"
    assert rec["phase"] == "repair"
    assert "traceback" in rec


def test_unmarked_record_carries_no_recovered_key(tmp_path):
    """An untouched call site keeps writing byte-identical records — the flag
    is stamped only when set."""
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("s4", "chunk-01", "chunk produced no analysis")
    assert "recovered" not in json.loads(_read_lines(target)[0])


def test_counts_default_still_include_recovered(tmp_path):
    """errors_by_stage (manifest / Scan Health) keeps tallying every record;
    only the explicit include_recovered=False view for the stage-outcome
    delta excludes the recovered transients."""
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("s4", "chunk-01", "parse failed, repair succeeded",
               recovered=True)
    errlog.log("s4", "chunk-02", "chunk analysis lost")
    assert errlog.counts_by_stage() == {"s4": 2}
    assert errlog.count_for_stage("s4") == 2
    assert errlog.count_for_stage("s4", include_recovered=False) == 1


def test_only_literal_true_recovered_is_excluded(tmp_path):
    """FAIL-SAFE: exclusion matches the JSON literal ``true`` only. A record
    with no ``recovered`` field — or a tampered/legacy one carrying a string,
    an int, or null — still counts toward the stage-outcome delta: a
    malformed mark must over-report, never restore the silent-failure
    defect."""
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    rows = [
        {"ts": "t", "stage": "s4", "unit": "u", "error": "unmarked"},
        {"ts": "t", "stage": "s4", "unit": "u", "error": "e", "recovered": "true"},
        {"ts": "t", "stage": "s4", "unit": "u", "error": "e", "recovered": 1},
        {"ts": "t", "stage": "s4", "unit": "u", "error": "e", "recovered": None},
        {"ts": "t", "stage": "s4", "unit": "u", "error": "e", "recovered": True},
    ]
    with open(target, "a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    assert errlog.count_for_stage("s4") == 5
    assert errlog.count_for_stage("s4", include_recovered=False) == 4


# log() — redaction (security-relevant)

def test_planted_secret_in_message_is_redacted(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", f"failed with token {_PLANTED_SECRET}")
    raw = target.read_text(encoding="utf-8")
    assert _PLANTED_SECRET not in raw
    rec = json.loads(raw.splitlines()[0])
    assert _REDACTED_MARK in rec["error"]


def test_planted_secret_in_traceback_is_redacted(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    try:
        raise RuntimeError(f"leaked {_PLANTED_SECRET}")
    except RuntimeError as e:
        errlog.log("stage", "unit", e)
    raw = target.read_text(encoding="utf-8")
    assert _PLANTED_SECRET not in raw
    rec = json.loads(raw.splitlines()[0])
    # Secret leaks into both the formatted message and the traceback text.
    assert _REDACTED_MARK in rec["error"]
    assert _REDACTED_MARK in rec["traceback"]


def test_planted_secret_in_string_extra_is_redacted(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg", context=f"env had {_PLANTED_SECRET}")
    raw = target.read_text(encoding="utf-8")
    assert _PLANTED_SECRET not in raw
    rec = json.loads(raw.splitlines()[0])
    assert _REDACTED_MARK in rec["context"]


def test_secret_in_non_string_extra_is_not_redacted(tmp_path):
    """Non-string extras are stored as-is; redact() only runs on str extras."""
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg", payload=[_PLANTED_SECRET])
    rec = json.loads(_read_lines(target)[0])
    # The value lives inside a list (non-string extra) so it is preserved.
    assert rec["payload"] == [_PLANTED_SECRET]


def test_planted_secret_in_unit_is_redacted(tmp_path):
    # `unit` is repo-derived (a file path / chunk id); a credential-shaped
    # substring in it must be scrubbed like the body fields, not written raw.
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("inject.cves", f"/repo/{_PLANTED_SECRET}/feed.json", "msg")
    raw = target.read_text(encoding="utf-8")
    assert _PLANTED_SECRET not in raw
    rec = json.loads(raw.splitlines()[0])
    assert _REDACTED_MARK in rec["unit"]
    # The fixed stage label is preserved verbatim.
    assert rec["stage"] == "inject.cves"


# log() — redaction ordering vs the traceback tail slice (security-relevant)

# Canonical AWS access-key id: "AKIA" anchor + 16 [0-9A-Z]. redact()'s AWS-KEY
# pattern matches on that leading anchor, which is exactly what a tail slice
# can drop.
_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def test_aws_key_straddling_traceback_tail_cut_is_still_redacted(tmp_path):
    """REGRESSION: log() sliced the traceback to its last 4000 chars BEFORE
    redacting (``redact(tb[-4000:])``). When a credential straddles that cut,
    the slice drops its leading anchor (``AKIA``), the surviving suffix
    matches no redaction pattern, and raw key bytes were written to
    errors.jsonl in the clear. Correct order is ``redact(tb)[-4000:]``.

    The geometry below is the ONLY shape that distinguishes the two
    orderings: the whole ``AKIA`` anchor must fall in the dropped region and
    at least 12 chars of the key must survive into the kept tail (so the
    12-char window sweep can see a partial leak). Both properties are
    asserted explicitly against the real formatted traceback — if they ever
    stop holding, the test fails loudly instead of silently testing nothing.
    """
    secret = _AWS_KEY
    # In-test sanity: redact() really does mask this key on its own; without
    # this the assertions below could pass vacuously against a pattern change.
    assert secret not in redact(secret)

    keep = 4000          # errlog's tail size
    drop_into_key = 5    # cut 5 chars in: "AKIAI" dropped, 15 chars survive
    # Chars after the key in the traceback text are exactly
    # " " + filler + "\n", so pick len(filler) to land the cut inside the key.
    filler_len = keep - len(secret) + drop_into_key - 2
    # Space-separated filler: glued padding (e.g. "xxx" + key) would defeat
    # the AWS-KEY pattern's \b word boundary, so the key would never redact
    # even in correct code and the test would be decorative.
    filler = ("x " * filler_len)[:filler_len]

    try:
        raise ValueError("boom " + secret + " " + filler)
    except ValueError as e:
        exc = e

    # Assert the straddle geometry against the REAL traceback text.
    tb_full = "".join(traceback.format_exception(type(exc), exc,
                                                 exc.__traceback__))
    assert tb_full.count(secret) == 1
    idx = tb_full.index(secret)
    cut = len(tb_full) - keep
    assert idx + len("AKIA") <= cut, (
        "geometry broke: the AKIA anchor must fall wholly in the dropped "
        "region for this test to distinguish the orderings")
    assert cut + 12 <= idx + len(secret), (
        "geometry broke: at least 12 key chars must survive past the cut "
        "so the window sweep below can detect a partial leak")

    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", exc)
    raw = target.read_text(encoding="utf-8")

    # Whole key must be gone, and — the part a plain `not in` check misses —
    # every 12-char window of it too: truncate-then-redact leaks a SUFFIX of
    # the key ("OSFODNN7EXAMPLE"), never the whole thing.
    assert secret not in raw
    for i in range(len(secret) - 11):
        window = secret[i:i + 12]
        assert window not in raw, (
            f"key fragment {window!r} leaked to the errlog — traceback was "
            "truncated before redaction")

    rec = json.loads(raw.splitlines()[0])
    # The unsliced message field masks the whole key with the marker.
    assert "[REDACTED-AWS-KEY]" in rec["error"]
    # Tail semantics are preserved: the stored traceback is still capped.
    assert "traceback" in rec and len(rec["traceback"]) <= keep


# log() — never raises

def test_log_never_raises_on_bad_path(tmp_path, monkeypatch, capsys):
    # Point the log at a path whose parent is a regular file → open("a") fails.
    blocker = tmp_path / "iamafile"
    blocker.write_text("x", encoding="utf-8")
    bad = blocker / "cannot" / "errors.jsonl"
    monkeypatch.setattr(errlog, "_path", bad)
    # Must swallow the error and not raise.
    errlog.log("stage", "unit", "msg")
    err = capsys.readouterr().err
    assert "WARN [_errlog]" in err
    assert "stage/unit" in err


def test_log_failure_warning_does_not_propagate_exception(tmp_path, monkeypatch):
    # Force the inner write to blow up; log() must still return None cleanly.
    class _Boom:
        def open(self, *a, **k):
            raise OSError("disk on fire")
    monkeypatch.setattr(errlog, "_path", _Boom())
    assert errlog.log("stage", "unit", "msg") is None
