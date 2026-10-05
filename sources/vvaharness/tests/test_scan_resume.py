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

from pathlib import Path
from types import SimpleNamespace

from vvaharness import config as config_mod
from vvaharness.models import ContextPackage, Finding, TaskManifest
from vvaharness.orchestrator import entry, scan, store
from vvaharness.orchestrator.checkpoints import load_ckpt, run_id_for
from vvaharness.pipeline.stages.s0_seed import SeedPackage


def _finding() -> Finding:
    return Finding(
        chunk_id="chunk-01",
        file="app.py",
        line_start=1,
        line_end=1,
        vuln_class="other",
        title="finding",
        description="description",
        code_snippet="sink(value)",
        confidence=0.9,
    )


def _args(config_path: Path, *, resume: bool, stop_after: str) -> SimpleNamespace:
    return SimpleNamespace(
        resume=resume,
        stop_after=stop_after,
        config=str(config_path),
        auto_step1=False,
    )


def _stub_scan_stages(monkeypatch, repo: Path, calls: list[str]) -> None:
    finding = _finding()

    monkeypatch.setattr(scan, "load_cves", lambda *args, **kwargs: [])
    monkeypatch.setattr(scan, "load_controls", lambda *args, **kwargs: [])
    monkeypatch.setattr(scan, "_load_app_profile", lambda *args: (None, None))
    monkeypatch.setattr(scan, "_ev_prep", lambda *args, **kwargs: None)
    monkeypatch.setattr(scan, "_enrich_findings", lambda *args, **kwargs: None)
    monkeypatch.setattr(scan, "_prune_ev_replays", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scan.s0_seed, "run",
        lambda *args, **kwargs: calls.append("s0") or SeedPackage())
    monkeypatch.setattr(
        scan.s1_preprocess, "run",
        lambda *args, **kwargs: calls.append("s1") or ContextPackage(
            repo_root=str(repo), language="python", all_files=["app.py"]))
    monkeypatch.setattr(
        scan.s3_decompose, "run",
        lambda *args, **kwargs: calls.append("s3") or TaskManifest(
            chunks=[], rationale="test"))
    monkeypatch.setattr(
        scan.s4_deepdive, "run",
        lambda *args, **kwargs: calls.append("s4") or (
            [finding], {"chunk-01": "completed"}))
    monkeypatch.setattr(
        scan.s5_prefilter, "run",
        lambda *args, **kwargs: calls.append("s5") or ([finding], []))
    monkeypatch.setattr(
        scan.s6_verify, "run",
        lambda *args, **kwargs: calls.append("s6") or ([finding], []))
    monkeypatch.setattr(
        scan.s7_dedup, "run",
        lambda *args, **kwargs: calls.append("s7") or ([finding], []))


def test_repo_name_falls_back_to_resolved_directory_for_dot(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert entry._repo_name(Path("."), None) == tmp_path.name
    assert entry._repo_name(Path("."), "   ") == tmp_path.name
    assert entry._repo_name(Path("."), "explicit-name") == "explicit-name"


def test_artifact_module_name_never_empty():
    assert scan._artifact_module_name("") == "repo"
    assert scan._artifact_module_name("...") == "repo"
    assert scan._artifact_module_name("module name") == "module_name"


def test_resume_after_s6_continues_at_s7(tmp_path, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("VVAHARNESS_NO_LOCAL_CONFIG", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sink(value)\n", encoding="utf-8")
    config_path = Path("vvaharness/config/profiles/default.yaml").resolve()
    cfg = config_mod.load(config_path)
    cfg._data["step2"]["enabled"] = False
    cfg._data["scan_progress"]["enabled"] = False
    calls: list[str] = []
    _stub_scan_stages(monkeypatch, repo, calls)

    scan.scan_repo(
        repo, "repo", None,
        _args(config_path, resume=False, stop_after="s6"), cfg)

    run_id = run_id_for(repo)
    assert calls == ["s0", "s1", "s3", "s4", "s5", "s6"]
    assert load_ckpt(None, run_id, "s5") is not None
    assert load_ckpt(None, run_id, "s6") is not None
    assert load_ckpt(None, run_id, "s7") is None

    calls.clear()
    scan.scan_repo(
        repo, "repo", None,
        _args(config_path, resume=True, stop_after="s7"), cfg)

    assert calls == ["s7"]
    s7_checkpoint = load_ckpt(None, run_id, "s7")
    assert s7_checkpoint is not None
    assert len(s7_checkpoint) == 5

    calls.clear()
    scan.scan_repo(
        repo, "repo", None,
        _args(config_path, resume=True, stop_after="s7"), cfg)

    assert calls == [], "the existing S7 row remains the authoritative fast path"


def test_resume_after_s5_continues_at_s6(tmp_path, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("VVAHARNESS_NO_LOCAL_CONFIG", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sink(value)\n", encoding="utf-8")
    config_path = Path("vvaharness/config/profiles/default.yaml").resolve()
    cfg = config_mod.load(config_path)
    cfg._data["step2"]["enabled"] = False
    cfg._data["scan_progress"]["enabled"] = False
    calls: list[str] = []
    _stub_scan_stages(monkeypatch, repo, calls)

    scan.scan_repo(
        repo, "repo", None,
        _args(config_path, resume=False, stop_after="s5"), cfg)

    run_id = run_id_for(repo)
    assert calls == ["s0", "s1", "s3", "s4", "s5"]
    assert load_ckpt(None, run_id, "s5") is not None
    assert load_ckpt(None, run_id, "s6") is None

    calls.clear()
    scan.scan_repo(
        repo, "repo", None,
        _args(config_path, resume=True, stop_after="s6"), cfg)

    assert calls == ["s6"]
    assert load_ckpt(None, run_id, "s6") is not None


def test_resume_does_not_trust_s6_without_s5(tmp_path, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("VVAHARNESS_NO_LOCAL_CONFIG", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("sink(value)\n", encoding="utf-8")
    config_path = Path("vvaharness/config/profiles/default.yaml").resolve()
    cfg = config_mod.load(config_path)
    cfg._data["step2"]["enabled"] = False
    cfg._data["scan_progress"]["enabled"] = False
    calls: list[str] = []
    _stub_scan_stages(monkeypatch, repo, calls)

    scan.scan_repo(
        repo, "repo", None,
        _args(config_path, resume=False, stop_after="s6"), cfg)
    run_id = run_id_for(repo)
    con = store.connect()
    with con:
        con.execute(
            "DELETE FROM checkpoints WHERE run_id=? AND step='s5'", (run_id,))
    con.close()

    calls.clear()
    scan.scan_repo(
        repo, "repo", None,
        _args(config_path, resume=True, stop_after="s6"), cfg)

    assert calls == ["s5", "s6"]