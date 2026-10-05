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

from __future__ import annotations

import inspect
from types import SimpleNamespace

from vvaharness.util.scan_progress import ScanProgress


def test_from_cfg_accepts_llm_debug_style():
    cfg = SimpleNamespace(scan_progress=SimpleNamespace(enabled=True, style="llm_debug"))
    tracker = ScanProgress.from_cfg(cfg, repo_name="demo")
    assert tracker.enabled is True
    assert tracker.style == "llm_debug"


def test_from_cfg_accepts_stage_only_style():
    cfg = SimpleNamespace(scan_progress=SimpleNamespace(enabled=True, style="stage_only"))
    tracker = ScanProgress.from_cfg(cfg, repo_name="demo")
    assert tracker.style == "stage_only"


def test_stage_only_emits_only_stage_lifecycle_lines(capsys):
    tracker = ScanProgress(enabled=True, style="stage_only", repo_name="demo")
    tracker.stage_started("s0", "Static seed")
    tracker.stage_note("s0", "ignored note")
    tracker.stage_done("s0")
    err = capsys.readouterr().err
    assert "[progress] ▶ [1/11] S0 Static seed" in err
    assert "[progress] ✓ [1/11] S0 Static seed" in err
    assert "ignored note" not in err
    tracker.print_summary()
    assert capsys.readouterr().err == ""


def test_from_cfg_rejects_unknown_style_to_compact():
    cfg = SimpleNamespace(scan_progress=SimpleNamespace(enabled=True, style="wat"))
    tracker = ScanProgress.from_cfg(cfg, repo_name="demo")
    assert tracker.style == "compact"


def test_llm_payload_emits_when_llm_debug(capsys):
    tracker = ScanProgress(enabled=True, style="llm_debug", repo_name="demo")
    tracker.llm_payload(
        phase="s4-deepdive",
        backend="sdk",
        model_id="claude-opus-4-6",
        tag="s4 deepdive",
        user_prompt="User body\n```python\nprint('x')\n```",
        system_prompt="System body",
    )
    err = capsys.readouterr().err
    assert "[progress] llm-call" in err
    assert "phase=s4-deepdive" in err
    assert "backend=sdk" in err
    assert "model=claude-opus-4-6" in err
    assert "[progress] llm-system-prompt" in err
    assert "[progress] llm-user-prompt" in err


def test_llm_payload_silent_for_other_styles(capsys):
    tracker = ScanProgress(enabled=True, style="compact", repo_name="demo")
    tracker.llm_payload(
        phase="s3-decompose",
        backend="cli",
        model_id="x",
        user_prompt="hello",
    )
    assert capsys.readouterr().err == ""


def test_stage_done_echoes_recorded_completed_with_errors(capsys):
    """The orchestrator resolves the outcome through the STAGES record, so a
    stage status.stage() closed as completed_with_errors is echoed as such
    rather than the call site's plain default."""
    from vvaharness.orchestrator.scan import _recorded_stage_outcome
    from vvaharness.util.stage_telemetry import STAGES

    STAGES.start("s4", "deep dive")
    STAGES.done("s4", outcome="completed_with_errors", duration_sec=1.0)

    resolved = _recorded_stage_outcome("s4", "completed")
    assert resolved == "completed_with_errors"

    tracker = ScanProgress(enabled=True, style="compact", repo_name="demo")
    tracker.stage_done("s4", outcome=resolved)
    assert "outcome=completed_with_errors" in capsys.readouterr().err


def test_recorded_outcome_falls_back_when_entry_missing():
    """A stage with no STAGES record must fall back, never raise."""
    from vvaharness.orchestrator.scan import _recorded_stage_outcome
    assert _recorded_stage_outcome("s7", "skipped") == "skipped"


def test_recorded_outcome_falls_back_while_still_running():
    """An open (non-terminal) record is not an outcome to echo."""
    from vvaharness.orchestrator.scan import _recorded_stage_outcome
    from vvaharness.util.stage_telemetry import STAGES
    STAGES.start("s5", "verify")
    assert _recorded_stage_outcome("s5", "completed") == "completed"


def test_post_scan_progress_details_are_stable_and_complete():
    from vvaharness.orchestrator.scan import _progress_detail

    assert _progress_detail(
        {"attempted": 5, "fixed": 4, "not_fixed": 1},
        "attempted", "fixed", "not_fixed",
    ) == "attempted=5 fixed=4 not_fixed=1"
    assert _progress_detail(
        {"validated": 5, "passed": 0, "failed": 5},
        "validated", "passed", "failed",
    ) == "validated=5 passed=0 failed=5"


def test_s10_and_s11_stage_done_records_include_counters(capsys):
    tracker = ScanProgress(enabled=True, style="compact", repo_name="demo")
    tracker.stage_started("s10", "remediate")
    tracker.stage_done(
        "s10", detail="attempted=5 fixed=4 not_fixed=1")
    tracker.stage_started("s11", "validate")
    tracker.stage_done(
        "s11", detail="validated=5 passed=0 failed=5")

    err = capsys.readouterr().err
    assert "[progress] stage-done  s10  outcome=completed" in err
    assert "attempted=5 fixed=4 not_fixed=1" in err
    assert "[progress] stage-done  s11  outcome=completed" in err
    assert "validated=5 passed=0 failed=5" in err


def test_scan_orchestrator_closes_s10_and_s11_progress_records():
    """Regression pin: post-scan stages must call the tracker, not only STAGES."""
    from vvaharness.orchestrator import scan

    src = inspect.getsource(scan.scan_repo)
    assert src.count('_sp_start("s10"') == 1
    assert src.count('_sp_done("s10"') == 3  # completed + two disabled paths
    assert src.count('_sp_start("s11"') == 1
    assert src.count('_sp_done("s11"') == 3  # completed + two disabled paths
