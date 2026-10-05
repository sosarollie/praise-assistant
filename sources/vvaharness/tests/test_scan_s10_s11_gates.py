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

"""Drives a full (stubbed) ``scan_repo`` through S0-S9 to prove the S10/S11
enablement gates behave as the default-off profile change intends:

  * the packaged default profile (both flags false) runs neither stage;
  * ``--remediate`` enables S10 only, never S11;
  * a profile/config with both flags true runs both;
  * ``--stop-after s9`` skips both regardless of what the config enables.

Complements the config-level assertions in test_validate_persist_redaction.py
(profiles resolve to the right flags) and the unit-level gate tests in
test_validate_only.py (preflight, progress recording) by exercising the actual
``if not (rem_on and report.findings):`` / ``if not (val_on and ...):`` branches
in ``orchestrator.scan.scan_repo`` end-to-end, offline and deterministic.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from vvaharness import config as config_mod
from vvaharness.models import (
    ContextPackage,
    Finding,
    RankedFinding,
    Severity,
    TaskManifest,
)
from vvaharness.models import FinalReport
from vvaharness.orchestrator import scan


def _finding() -> Finding:
    return Finding(
        chunk_id="chunk-01", file="app.py", line_start=1, line_end=1,
        vuln_class="other", title="finding", description="description",
        code_snippet="sink(value)", confidence=0.9,
    )


def _ranked() -> RankedFinding:
    return RankedFinding(finding=_finding(), severity=Severity.HIGH,
                         exploitability_notes="notes")


def _args(config_path: Path, *, remediate: bool = False,
         stop_after: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        resume=False, stop_after=stop_after, config=str(config_path),
        auto_step1=False, remediate=remediate, top=None, force=False,
    )


def _stub_through_s9(monkeypatch, repo: Path) -> FinalReport:
    """Stub S0-S9 so ``scan_repo`` reaches the S10/S11 gates deterministically,
    with exactly one verified finding so neither gate is skipped for having
    nothing to act on."""
    finding = _finding()
    report = FinalReport(
        repo_root=str(repo), findings=[_ranked()], chains=[],
        raw_findings_count=1, summary="test",
    )

    monkeypatch.setattr(scan, "load_cves", lambda *a, **k: [])
    monkeypatch.setattr(scan, "load_controls", lambda *a, **k: [])
    monkeypatch.setattr(scan, "_load_app_profile", lambda *a: (None, None))
    monkeypatch.setattr(scan, "_ev_prep", lambda *a, **k: None)
    monkeypatch.setattr(scan, "_enrich_findings", lambda *a, **k: None)
    monkeypatch.setattr(scan, "_prune_ev_replays", lambda *a, **k: None)
    monkeypatch.setattr(
        scan.s0_seed, "run", lambda *a, **k: scan.s0_seed.SeedPackage())
    monkeypatch.setattr(
        scan.s1_preprocess, "run",
        lambda *a, **k: ContextPackage(
            repo_root=str(repo), language="python", all_files=["app.py"]))
    monkeypatch.setattr(
        scan.s3_decompose, "run",
        lambda *a, **k: TaskManifest(chunks=[], rationale="test"))
    monkeypatch.setattr(
        scan.s4_deepdive, "run",
        lambda *a, **k: ([finding], {"chunk-01": "completed"}))
    monkeypatch.setattr(scan.s5_prefilter, "run", lambda *a, **k: ([finding], []))
    monkeypatch.setattr(scan.s6_verify, "run", lambda *a, **k: ([finding], []))
    monkeypatch.setattr(scan.s7_dedup, "run", lambda *a, **k: ([finding], []))
    monkeypatch.setattr(scan.s8_chain, "run", lambda *a, **k: report)
    monkeypatch.setattr(
        scan.vcs_enrich, "md_to_sarif",
        lambda md, app_id, app_info, sarif, **k: Path(sarif).write_text("{}"))
    monkeypatch.setattr(scan, "stamp_case_ids", lambda *a, **k: None)
    # Preflight credential probing is exercised elsewhere (test_validate_only.py);
    # here we isolate the enablement/OR-gate logic itself.
    monkeypatch.setattr(scan, "_remediate_preflight", lambda *a, **k: None)
    monkeypatch.setattr(scan, "_validate_preflight", lambda *a, **k: None)
    return report


def _load_cfg(config_path: Path, *, remediate_on: bool = False,
             validate_on: bool = False) -> config_mod.Config:
    cfg = config_mod.load(config_path)
    cfg._data["step2"]["enabled"] = False
    cfg._data["scan_progress"]["enabled"] = False
    cfg._data.setdefault("step_remediate", {})["enabled"] = remediate_on
    cfg._data.setdefault("step_validate", {})["enabled"] = validate_on
    return cfg


@pytest.fixture(autouse=True)
def _isolate_state(monkeypatch, tmp_path):
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("VVAHARNESS_NO_LOCAL_CONFIG", "1")


def _run_calls(monkeypatch):
    """Record S10/S11 invocations without running the real agent loops."""
    calls: list[str] = []
    monkeypatch.setattr(
        scan, "_run_remediation",
        lambda *a, **k: calls.append("s10") or 0)
    monkeypatch.setattr(
        scan, "_run_validation",
        lambda *a, **k: calls.append("s11") or 0)
    return calls


_DEFAULT_PROFILE = Path("vvaharness/config/profiles/default.yaml").resolve()


def test_default_profile_plain_scan_skips_s10_and_s11(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sink(value)\n", encoding="utf-8")
    _stub_through_s9(monkeypatch, repo)
    calls = _run_calls(monkeypatch)
    cfg = _load_cfg(_DEFAULT_PROFILE, remediate_on=False, validate_on=False)

    scan.scan_repo(repo, "repo", None, _args(_DEFAULT_PROFILE), cfg)

    assert calls == [], "packaged default must skip both S10 and S11"


def test_remediate_flag_enables_s10_only_even_on_default_profile(
        tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sink(value)\n", encoding="utf-8")
    _stub_through_s9(monkeypatch, repo)
    calls = _run_calls(monkeypatch)
    cfg = _load_cfg(_DEFAULT_PROFILE, remediate_on=False, validate_on=False)

    scan.scan_repo(repo, "repo", None,
                   _args(_DEFAULT_PROFILE, remediate=True), cfg)

    assert calls == ["s10"], "--remediate must enable S10 only, never S11"


def test_both_flags_enabled_in_config_run_both_stages(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sink(value)\n", encoding="utf-8")
    _stub_through_s9(monkeypatch, repo)
    calls = _run_calls(monkeypatch)
    cfg = _load_cfg(_DEFAULT_PROFILE, remediate_on=True, validate_on=True)

    scan.scan_repo(repo, "repo", None, _args(_DEFAULT_PROFILE), cfg)

    assert calls == ["s10", "s11"], "both flags true must run S10 then S11"


def test_stop_after_s9_skips_both_even_when_config_enables_them(
        tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sink(value)\n", encoding="utf-8")
    _stub_through_s9(monkeypatch, repo)
    calls = _run_calls(monkeypatch)
    cfg = _load_cfg(_DEFAULT_PROFILE, remediate_on=True, validate_on=True)

    scan.scan_repo(repo, "repo", None,
                   _args(_DEFAULT_PROFILE, stop_after="s9"), cfg)

    assert calls == [], "--stop-after s9 must skip S10/S11 with any profile"
