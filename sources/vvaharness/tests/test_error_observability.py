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
Tests for named error observability: VVAH-E001, VVAH-E002, VVAH-E003, VVAH-E005.

Covers:
  - AuthenticationError and ProxyError classes (structure, error_code, attrs)
  - DegenerateResponseError class
  - TruncatedResponseError class + truncation_retry_max() retry policy
  - check_response_quality() soft/loud progression (warn → warn → raise)
  - reset_counters() isolation between repos
  - stage-level continuation: E005 from prompt() degrades the unit, never the scan
  - entry.py exception handlers: AuthenticationError → exit 1 + errlog,
    ProxyError → exit 1 + errlog
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from vvaharness.backends.harness.models import (
    AuthenticationError,
    DegenerateResponseError,
    ProxyError,
    TruncatedResponseError,
    is_halt_error,
)
from vvaharness.backends.llm.models import truncation_retry_max
from vvaharness.models import Chunk, ChunkSize, ContextPackage
from vvaharness.pipeline.stages import s4_deepdive as s4
from vvaharness.util import errlog as _errlog
from vvaharness.util.response_quality import check_response_quality, reset_counters


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def errlog_path(tmp_path, monkeypatch):
    """Redirect the module-global errlog path to a per-test temp file."""
    path = tmp_path / "test_errors.jsonl"
    monkeypatch.setattr(_errlog, "_path", path)
    return path


def _read_errlog(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# is_halt_error() — gate used by stage-level exception handlers
# ─────────────────────────────────────────────────────────────────────────────

class TestIsHaltError:
    def test_authentication_error_is_halt_error(self):
        assert is_halt_error(AuthenticationError("test")) is True

    def test_proxy_error_is_halt_error(self):
        assert is_halt_error(ProxyError("test")) is True

    def test_runtime_error_is_not_halt_error(self):
        assert is_halt_error(RuntimeError("test")) is False

    def test_value_error_is_not_halt_error(self):
        assert is_halt_error(ValueError("test")) is False


# ─────────────────────────────────────────────────────────────────────────────
# VVAH-E001 — AuthenticationError
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthenticationError:
    def test_error_code_class_attribute(self):
        assert AuthenticationError.error_code == "VVAH-E001"

    def test_str_contains_error_code(self):
        err = AuthenticationError("token expired", status_code=401, backend="cli")
        assert "VVAH-E001" in str(err)

    def test_str_contains_http_status(self):
        err = AuthenticationError("bad token", status_code=401, backend="sdk")
        assert "HTTP 401" in str(err)

    def test_str_contains_backend(self):
        err = AuthenticationError("bad token", backend="sdk")
        assert "[sdk]" in str(err)

    def test_str_contains_remediation_hint(self):
        err = AuthenticationError("bad token")
        assert "vvaharness doctor" in str(err)
        assert "--resume" in str(err)

    def test_attrs_stored(self):
        err = AuthenticationError("msg", status_code=401, backend="cli")
        assert err.status_code == 401
        assert err.backend == "cli"

    def test_no_status_code_omits_http_clause(self):
        err = AuthenticationError("msg")
        assert "HTTP" not in str(err)

    def test_is_exception(self):
        with pytest.raises(AuthenticationError, match="VVAH-E001"):
            raise AuthenticationError("test", status_code=401, backend="cli")


# ─────────────────────────────────────────────────────────────────────────────
# VVAH-E002 — ProxyError
# ─────────────────────────────────────────────────────────────────────────────

class TestProxyError:
    def test_error_code_class_attribute(self):
        assert ProxyError.error_code == "VVAH-E002"

    def test_str_contains_error_code(self):
        err = ProxyError("tunnel failed", status_code=407, backend="sdk")
        assert "VVAH-E002" in str(err)

    def test_str_contains_http_status(self):
        err = ProxyError("tunnel failed", status_code=407)
        assert "HTTP 407" in str(err)

    def test_str_contains_remediation_hint(self):
        err = ProxyError("SSL error")
        assert "ANTHROPIC_BASE_URL" in str(err)
        assert "vvaharness doctor" in str(err)

    def test_attrs_stored(self):
        err = ProxyError("msg", status_code=407, backend="oai")
        assert err.status_code == 407
        assert err.backend == "oai"

    def test_is_exception(self):
        with pytest.raises(ProxyError, match="VVAH-E002"):
            raise ProxyError("bad proxy", status_code=407)


# ─────────────────────────────────────────────────────────────────────────────
# VVAH-E003 — DegenerateResponseError (class only)
# ─────────────────────────────────────────────────────────────────────────────

class TestDegenerateResponseError:
    def test_error_code_class_attribute(self):
        assert DegenerateResponseError.error_code == "VVAH-E003"

    def test_str_contains_error_code(self):
        err = DegenerateResponseError("too short", stage="s4", response_len=10, threshold=150, consecutive=3)
        assert "VVAH-E003" in str(err)

    def test_str_contains_stage(self):
        err = DegenerateResponseError("too short", stage="s4")
        assert "s4" in str(err)

    def test_attrs_stored(self):
        err = DegenerateResponseError("msg", stage="s4", response_len=10, threshold=150, consecutive=3)
        assert err.stage == "s4"
        assert err.response_len == 10
        assert err.threshold == 150
        assert err.consecutive == 3


# ─────────────────────────────────────────────────────────────────────────────
# VVAH-E005 — TruncatedResponseError class + truncation_retry_max() policy
# ─────────────────────────────────────────────────────────────────────────────

class TestTruncatedResponseError:
    def test_error_code_class_attribute(self):
        assert TruncatedResponseError.error_code == "VVAH-E005"

    def test_str_contains_error_code(self):
        err = TruncatedResponseError("cut off", stage="s4", requested=16000, retried=32000)
        assert "VVAH-E005" in str(err)

    def test_str_contains_stage_and_budgets(self):
        err = TruncatedResponseError("cut off", stage="s4", requested=16000, retried=32000)
        s = str(err)
        assert "s4" in s
        assert "16000" in s
        assert "32000" in s

    def test_attrs_stored(self):
        err = TruncatedResponseError("msg", stage="s4", requested=16000, retried=32000)
        assert err.stage == "s4"
        assert err.requested == 16000
        assert err.retried == 32000

    def test_is_not_halt_error(self):
        # A truncated unit degrades; only E001/E002 abort the scan.
        assert is_halt_error(TruncatedResponseError("cut off")) is False


class TestTruncationRetryMax:
    def test_no_cap_doubles(self):
        assert truncation_retry_max(16000) == 32000

    def test_below_cap_doubles(self):
        assert truncation_retry_max(16000, cap=64000) == 32000

    def test_near_cap_is_bounded_by_cap(self):
        assert truncation_retry_max(48000, cap=64000) == 64000

    def test_at_cap_returns_none(self):
        assert truncation_retry_max(64000, cap=64000) is None

    def test_above_cap_returns_none(self):
        assert truncation_retry_max(70000, cap=64000) is None


# ─────────────────────────────────────────────────────────────────────────────
# VVAH-E005 — stage-level continuation (mirrors the E003 degradation path)
# ─────────────────────────────────────────────────────────────────────────────

class TestStageContinuationOnTruncation:
    def test_s4_run_failure_on_e005_degrades_and_continues(self, monkeypatch, errlog_path):
        """E005 degrades the run like any unit failure; the chunk completes on surviving runs."""
        chunk = Chunk(id="chunk-01", size=ChunkSize.MEDIUM,
                      file_ids=["a.py"], hypothesis="x")
        ctx = ContextPackage(repo_root="/nonexistent-repo", language="python",
                             all_files=[], entry_points=[], unsafe_sinks=[],
                             call_graph={})
        cfg = SimpleNamespace(step4=SimpleNamespace(
            line_bucket=10, specialist_runs=1, taint_runs=None))
        monkeypatch.setattr(s4, "_load_chunk_code", lambda *_a, **_k: "code")
        monkeypatch.setattr(s4, "_neighbor_context", lambda *_a, **_k: "")

        calls = {"n": 0}

        def flaky_run(_chunk, _ctx, _code, _cfg):
            calls["n"] += 1
            if calls["n"] == 1:
                raise TruncatedResponseError(
                    "cut off", stage="s4 chunk-01",
                    requested=16000, retried=32000)
            return []

        monkeypatch.setattr(s4, "_single_run", flaky_run)

        out = s4._deepdive_chunk(chunk, ctx, Path("/nonexistent-repo"), cfg,
                                 runs_n=2, threshold=1)

        assert out == []
        assert calls["n"] == 2, "the second run must still execute"
        recs = _read_errlog(errlog_path)
        assert any(r.get("error_code") == "VVAH-E005"
                   and "recovered" not in r for r in recs)


# ─────────────────────────────────────────────────────────────────────────────
# check_response_quality() — soft/loud progression
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckResponseQuality:
    _SHORT = "hi"  # < 150 chars

    def test_good_response_passes_silently(self):
        """A response meeting all thresholds must not raise or warn."""
        check_response_quality("x" * 200, stage="s4")  # no exception

    def test_first_failure_warns_not_raises(self, capsys, errlog_path):
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        captured = capsys.readouterr()
        assert "WARN VVAH-E003" in captured.err
        assert "1/3" in captured.err

    def test_second_failure_warns_not_raises(self, capsys, errlog_path):
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        captured = capsys.readouterr()
        assert "2/3" in captured.err

    def test_third_failure_raises(self, errlog_path):
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        with pytest.raises(DegenerateResponseError):
            check_response_quality(self._SHORT, stage="s4", min_chars=200)

    def test_fourth_failure_warns_again_after_reset(self, capsys, errlog_path):
        """After raising on the 3rd consecutive failure the counter resets to 1,
        so the 4th failure is a warning (1/3) rather than another raise."""
        for _ in range(2):
            check_response_quality(self._SHORT, stage="s4", min_chars=200)
        with pytest.raises(DegenerateResponseError):
            check_response_quality(self._SHORT, stage="s4", min_chars=200)
        # 4th call should warn, not raise
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        captured = capsys.readouterr()
        assert "1/3" in captured.err

    def test_good_response_resets_consecutive_count(self, capsys, errlog_path):
        check_response_quality(self._SHORT, stage="s4", min_chars=200)  # count=1
        check_response_quality("x" * 200, stage="s4")                   # resets
        check_response_quality(self._SHORT, stage="s4", min_chars=200)  # count=1 again
        captured = capsys.readouterr()
        # only "1/3" warnings should appear, never "2/3"
        assert "1/3" in captured.err
        assert "2/3" not in captured.err

    def test_failure_writes_to_errlog(self, errlog_path):
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        records = _read_errlog(errlog_path)
        assert len(records) == 1
        rec = records[0]
        assert rec["error_code"] == "VVAH-E003"
        assert rec["stage"] == "s4"

    def test_errlog_record_carries_raw_head_of_the_reply(self, errlog_path):
        """The record must store the reply's head, not just its lengths.

        A live run produced 55 VVAH-E003 records that could not be
        root-caused from the artifact: the record said "15 chars" and two
        independent analysts could only *guess* whether the reply was a
        valid-but-empty JSON or a refusal. The raw_head makes the next
        occurrence diagnosable without reproducing the run.
        """
        reply = '{"findings": []}'
        check_response_quality(reply, stage="s4", min_chars=200)
        rec = _read_errlog(errlog_path)[0]
        assert rec["raw_head"] == reply

    def test_raw_head_is_redacted_before_truncation_never_after(self, errlog_path):
        """A credential straddling the cap boundary must not egress.

        Capping first bisects the key: the surviving fragment ("sk-ant-AAA")
        is too short to match the ANTHROPIC-KEY pattern, so errlog's own
        after-the-fact redaction of extras would pass it through — into a
        field whose presence claims it was scrubbed. Redacting the full text
        first masks the key before the cap can split it.
        """
        from vvaharness.util.response_quality import _RAW_HEAD_CHARS

        key = "sk-ant-" + "A" * 40
        # Place the key so the cap falls a few chars into it. The trailing
        # space matters: the ANTHROPIC-KEY pattern is \b-anchored, so the key
        # must not abut the padding or it would never redact at all.
        padding = "x" * (_RAW_HEAD_CHARS - len("sk-ant-") - 3 - 1) + " "
        reply = padding + key
        check_response_quality(reply, stage="s4",
                               min_chars=len(reply) + 100)
        rec = _read_errlog(errlog_path)[0]
        assert "raw_head" in rec
        assert key not in rec["raw_head"]
        assert "sk-ant-" not in rec["raw_head"], (
            "a bisected credential fragment egressed — the cap ran before "
            "the redaction"
        )
        assert len(rec["raw_head"]) <= _RAW_HEAD_CHARS

    def test_raw_head_is_capped(self, errlog_path):
        """The errors file ships to operators; the head must stay short."""
        from vvaharness.util.response_quality import _RAW_HEAD_CHARS

        check_response_quality("y" * 10_000, stage="s4",
                               min_chars=20_000)
        rec = _read_errlog(errlog_path)[0]
        assert len(rec["raw_head"]) == _RAW_HEAD_CHARS

    def test_independent_counters_per_stage(self, errlog_path):
        """Failures in s4 must not advance the s5 counter."""
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        # s5 is fresh — this should warn (1/3), not raise
        check_response_quality(self._SHORT, stage="s5", min_chars=200)
        # s4 at 2/3 — this should raise
        with pytest.raises(DegenerateResponseError):
            check_response_quality(self._SHORT, stage="s4", min_chars=200)

    def test_token_count_check(self, errlog_path):
        """output_tokens below the threshold should be detected as degenerate."""
        long_text = "x" * 200  # passes char check
        check_response_quality(long_text, stage="s4", output_tokens=5)
        records = _read_errlog(errlog_path)
        assert any("token" in r["error"] for r in records)

    def test_expected_marker_check(self, errlog_path):
        """Missing expected_markers should be detected as degenerate."""
        text = "x" * 200  # passes char check
        check_response_quality(text, stage="s4", expected_markers=["VERDICT"])
        records = _read_errlog(errlog_path)
        assert any("VERDICT" in r["error"] for r in records)

    def test_raises_error_contains_stage(self, errlog_path):
        for _ in range(2):
            check_response_quality(self._SHORT, stage="s7", min_chars=200)
        with pytest.raises(DegenerateResponseError) as exc_info:
            check_response_quality(self._SHORT, stage="s7", min_chars=200)
        assert exc_info.value.stage == "s7"

    def test_intermediate_warning_is_marked_recovered(self, errlog_path):
        """An intermediate warning is a tolerated transient: its record keeps
        the full diagnostics but is excluded from the delta that flips a stage
        to completed_with_errors."""
        check_response_quality(self._SHORT, stage="s4", min_chars=200)
        records = _read_errlog(errlog_path)
        assert len(records) == 1
        assert records[0]["recovered"] is True
        assert _errlog.count_for_stage("s4") == 1                 # tally kept
        assert _errlog.count_for_stage("s4", include_recovered=False) == 0

    def test_intermediate_warnings_do_not_flip_stage_marker(self, errlog_path):
        from vvaharness.util.stage_telemetry import STAGES
        from vvaharness.util.status import stage
        with stage("Step 4 — Deep dive", stage_id="s4"):
            check_response_quality(self._SHORT, stage="s4", min_chars=200)
            check_response_quality(self._SHORT, stage="s4", min_chars=200)
        assert STAGES.snapshot()["s4"]["outcome"] == "completed"

    def test_terminal_degenerate_error_still_flips_stage_marker(self, errlog_path):
        """The terminal case raises DegenerateResponseError; the calling stage
        catches it and logs UNMARKED, so the stage closes
        completed_with_errors — real losses keep flipping the marker."""
        from vvaharness.util.stage_telemetry import STAGES
        from vvaharness.util.status import stage
        with stage("Step 4 — Deep dive", stage_id="s4"):
            for _ in range(2):
                check_response_quality(self._SHORT, stage="s4", min_chars=200)
            try:
                check_response_quality(self._SHORT, stage="s4", min_chars=200)
            except DegenerateResponseError as e:
                _errlog.log("s4", "chunk-01", e)  # what a stage handler does
            else:
                pytest.fail("third consecutive failure must raise")
        assert STAGES.snapshot()["s4"]["outcome"] == "completed_with_errors"


# ─────────────────────────────────────────────────────────────────────────────
# reset_counters()
# ─────────────────────────────────────────────────────────────────────────────

class TestResetCounters:
    def test_reset_clears_mid_sequence(self, errlog_path):
        """After reset_counters() the stage counter goes back to 0."""
        check_response_quality("hi", stage="s4", min_chars=200)
        check_response_quality("hi", stage="s4", min_chars=200)
        reset_counters()
        # Should warn at 1/3, not raise
        check_response_quality("hi", stage="s4", min_chars=200)

    def test_reset_on_fresh_state_is_noop(self):
        """reset_counters() on an empty counter dict must not raise."""
        reset_counters()  # should not raise


# ─────────────────────────────────────────────────────────────────────────────
# entry.py — main() exception handlers
# ─────────────────────────────────────────────────────────────────────────────

class TestEntryExceptionHandlers:
    """Drive main() through the AuthenticationError / ProxyError / generic
    exception branches.

    Strategy: patch scan_repo to raise the target exception; patch the
    config/backend setup chain so main() reaches the try/except block without
    real I/O or credentials.
    """

    def _run_main(self, monkeypatch, tmp_path, exc, errlog_path):
        """Run entry.main() with minimal argv, causing scan_repo to raise *exc*."""
        import vvaharness.config as _cfg_mod
        import vvaharness.orchestrator.entry as entry

        monkeypatch.setattr(_errlog, "_path", errlog_path)

        # Minimal mock config: attribute access is via MagicMock auto-spec
        cfg_mock = MagicMock()
        cfg_mock._data = {}

        monkeypatch.setattr(_cfg_mod, "load", MagicMock(return_value=cfg_mock))
        monkeypatch.setattr(entry, "configure_backends", MagicMock())
        monkeypatch.setattr(entry, "_set_cmdb_path", MagicMock())
        monkeypatch.setattr(entry, "_cmdb_path", MagicMock(return_value=None))
        monkeypatch.setattr(entry, "scan_repo", MagicMock(side_effect=exc))

        argv = [
            "--repo", str(tmp_path),
            "--application-id", "APP-TEST",
            "--skip-preflight",
        ]
        return entry.main(argv)

    # ── AuthenticationError (VVAH-E001) ──────────────────────────────────────

    def test_authentication_error_returns_exit_1(self, monkeypatch, tmp_path, errlog_path, capsys):
        exc = AuthenticationError("token expired", status_code=401, backend="cli")
        ret = self._run_main(monkeypatch, tmp_path, exc, errlog_path)
        assert ret == 1

    def test_authentication_error_prints_to_stderr(self, monkeypatch, tmp_path, errlog_path, capsys):
        exc = AuthenticationError("token expired", status_code=401, backend="cli")
        self._run_main(monkeypatch, tmp_path, exc, errlog_path)
        err = capsys.readouterr().err
        assert "VVAH-E001" in err
        assert "vvaharness doctor" in err

    def test_authentication_error_writes_errlog(self, monkeypatch, tmp_path, errlog_path):
        exc = AuthenticationError("token expired", status_code=401, backend="cli")
        self._run_main(monkeypatch, tmp_path, exc, errlog_path)
        records = _read_errlog(errlog_path)
        assert len(records) >= 1
        rec = records[0]
        assert rec["error_code"] == "VVAH-E001"
        assert rec["stage"] == "auth"
        assert rec["application_id"] == "APP-TEST"

    # ── ProxyError (VVAH-E002) ───────────────────────────────────────────────

    def test_proxy_error_returns_exit_1(self, monkeypatch, tmp_path, errlog_path, capsys):
        exc = ProxyError("SSL cert verify failed", backend="sdk")
        ret = self._run_main(monkeypatch, tmp_path, exc, errlog_path)
        assert ret == 1

    def test_proxy_error_prints_to_stderr(self, monkeypatch, tmp_path, errlog_path, capsys):
        exc = ProxyError("CONNECT tunnel failed", status_code=407, backend="cli")
        self._run_main(monkeypatch, tmp_path, exc, errlog_path)
        err = capsys.readouterr().err
        assert "VVAH-E002" in err
        assert "vvaharness doctor" in err

    def test_proxy_error_writes_errlog(self, monkeypatch, tmp_path, errlog_path):
        exc = ProxyError("CONNECT tunnel failed", status_code=407, backend="cli")
        self._run_main(monkeypatch, tmp_path, exc, errlog_path)
        records = _read_errlog(errlog_path)
        assert len(records) >= 1
        rec = records[0]
        assert rec["error_code"] == "VVAH-E002"
        assert rec["stage"] == "proxy"
        assert rec["application_id"] == "APP-TEST"

    # ── Generic exception (fallthrough) ──────────────────────────────────────

    def test_generic_exception_returns_exit_1(self, monkeypatch, tmp_path, errlog_path, capsys):
        exc = RuntimeError("unexpected crash")
        ret = self._run_main(monkeypatch, tmp_path, exc, errlog_path)
        assert ret == 1

    def test_generic_exception_prints_scan_failed(self, monkeypatch, tmp_path, errlog_path, capsys):
        exc = RuntimeError("unexpected crash")
        self._run_main(monkeypatch, tmp_path, exc, errlog_path)
        err = capsys.readouterr().err
        assert "scan failed" in err


# ─────────────────────────────────────────────────────────────────────────────
# Hierarchy identity — the defect this file's own import first exposed
# ─────────────────────────────────────────────────────────────────────────────

def test_the_harness_error_hierarchy_is_not_duplicated():
    """``contract.errors`` must re-export ``models``, never redefine it.

    A merge briefly landed a second copy of the hierarchy in
    ``backends/harness/contract/errors.py``. Python compares exception classes
    by identity, so the copies did not interoperate: ``is_halt_error`` was
    checking ``isinstance`` against classes no backend ever raises, and returned
    False for every real VVAH-E001/E002. The single caller
    (``callgraph_engine``, which re-raises those instead of degrading to rules
    mode) therefore had a halt guard that always fell through while still
    reading as protection — the failure mode is silent, which is why it needs a
    test rather than a review.
    """
    from vvaharness.backends.harness import models as m
    from vvaharness.backends.harness.contract import errors as e

    for name in (
        "AuthenticationError", "DegenerateResponseError", "HarnessCLINotFoundError",
        "HarnessConnectionError", "HarnessError", "HarnessJSONDecodeError",
        "HarnessMessageParseError", "HarnessProcessError", "ProxyError",
    ):
        assert getattr(e, name) is getattr(m, name), (
            f"contract.errors.{name} is a different class object from "
            f"models.{name} — isinstance() across the two silently fails"
        )


def test_halt_predicates_recognise_the_errors_the_backends_raise():
    """The predicates must fire on instances built from ``models``, not a copy."""
    from vvaharness.backends.harness.contract import errors as e
    from vvaharness.backends.harness.models import AuthenticationError, ProxyError

    assert e.is_halt_error(AuthenticationError("token rejected")) is True
    assert e.is_halt_error(ProxyError("tls handshake failed")) is True
    assert e.is_token_error(AuthenticationError("token rejected")) is True
    # ...and must NOT swallow the scan on an ordinary stage failure.
    assert e.is_halt_error(ValueError("bad chunk")) is False
    assert e.is_token_error(ProxyError("tls")) is False
