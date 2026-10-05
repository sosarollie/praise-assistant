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

"""Tests for s11 validation SQLite checkpoint/resume (mirrors s10 remediation).

Fully offline: ``VVAHARNESS_STATE_DIR`` points at a tmp dir so the real SQLite
store is exercised, and ``_validate_one`` is monkeypatched so no agent/LLM runs.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from vvaharness.models import (
    Decision,
    Finding,
    FindingCase,
    Provenance,
    Remediation,
    RemediationKind,
    ScoringPolicy,
    Verdict,
)
from vvaharness.orchestrator import store
from vvaharness.orchestrator.case_rollup import EXIT_NOT_REMEDIATED
from vvaharness.orchestrator.checkpoints import load_ckpt, run_id_for, save_ckpt
from vvaharness.validation.cli import _resolve_selection, _run
from vvaharness.validation.cli._parser import _build_parser
from vvaharness.validation.cli._run import (
    Selection,
    ValidatedCase,
    ValidationRun,
    run_validation,
)
from vvaharness.validation.ingest.case_loader import LoadedCase
from vvaharness.validation.models import ValidationResult

_VERDICT = Verdict(decision=Decision.FIXED, rationale="fix verified", score=1.0)


@pytest.fixture(autouse=True)
def _state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the SQLite state store at an isolated per-test dir."""
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "state"))


def _result(fid: str) -> ValidationResult:
    """A successful validation-result stand-in (these tests exercise run/checkpoint/resume
    mechanics, not the agent). A non-INCONCLUSIVE verdict keeps the run exit code 0."""
    return ValidationResult(
        finding_number=0, tracking_id=fid, finding_title="t",
        finding_description="", affected_files="",
        fixed="Yes", partially_fixed="No", not_fixed="No",
        files_needing_fixes="", reason_for_decision="fixed",
        severity="HIGH", pr_merge_readiness="ready", recommendations="",
    )


def _validated(loaded: LoadedCase) -> ValidatedCase:
    """What a completed ``_validate_one`` returns: the case, its verdict and its render row."""
    return ValidatedCase(loaded, _VERDICT, _result(loaded.case_id), session_failed=False)


def _case(case_id: str, cvss: float = 5.0) -> FindingCase:
    """A remediated case: one applied-edits attempt, unjudged -> state REMEDIATED."""
    finding = Finding(
        title="t", file="app/x.py", line_start=3, vuln_class="injection",
        severity="high", case_id=case_id, cvss_score=cvss,
    )
    return FindingCase(case_id=case_id, finding=finding).with_attempt(
        Remediation(
            kind=RemediationKind.EDITS_APPLIED, summary="s",
            files_touched=("app/x.py",), diff="",
        )
    )


def _write_case(repo: Path, fid: str, *, dirname: str | None = None, cvss: float = 5.0) -> None:
    d = repo / "security-remediation" / (dirname or fid)
    d.mkdir(parents=True)
    _case(fid, cvss).write(d / "finding_case.json")


def _config() -> SimpleNamespace:
    """The slice of Config that ``_provenance_for`` and ``_engine_identity`` read."""
    return SimpleNamespace(
        agent=SimpleNamespace(model="test-model", effort="high", via="deepagents")
    )


def _step(case_id: str) -> str:
    """The step key ``run_validation`` will compute for *case_id*.

    Derived through the production functions rather than hand-built, so a change to what the
    key hashes moves these tests with it instead of silently decoupling them.
    """
    model, backend = _run._engine_identity(_config())
    return _run._step_key(case_id, model=model, backend=backend)


def _run_args(repo: Path, selection: Selection) -> int:
    return run_validation(
        repo=repo,
        selection=selection,
        workspace_root=repo / "ws",
        config=_config(),
    ).exit_code


# checkpoint schema round-trip (validate_ branch in checkpoints._schema_for)


def test_validate_checkpoint_roundtrip(tmp_path: Path) -> None:
    """A ValidationResult saved under a validate_ step reloads byte-equal."""
    rid = run_id_for(tmp_path)
    res = _result("F-1")
    save_ckpt(tmp_path, rid, "validate_F-1", res)
    assert load_ckpt(tmp_path, rid, "validate_F-1") == res


def test_validate_checkpoint_enum_fields_survive(tmp_path: Path) -> None:
    """unverifiable_row injects enum values into the row's str fields — round-trip is lossless."""
    rid = run_id_for(tmp_path)
    save_ckpt(tmp_path, rid, "validate_F-2", _result("F-2"))
    loaded = load_ckpt(tmp_path, rid, "validate_F-2")
    assert loaded is not None
    assert loaded.tracking_id == "F-2"
    assert str(loaded.fixed) in {"No", "Yes", "?"}


# run_validation registers the run (fixes the standalone ghost-row gap)


def test_run_validation_registers_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """run_validation creates a runs row keyed by run_id_for(repo) with a real repo_root."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_case(repo, "F-1")
    monkeypatch.setattr(_run, "_validate_one", lambda loaded, run: _validated(loaded))

    assert _run_args(repo, Selection()) == 0

    with store.connect() as cx:
        row = cx.execute("SELECT run_id, repo_root FROM runs").fetchone()
    assert row[0] == run_id_for(repo)
    assert row[1] == str(repo.resolve())  # non-empty → no ghost row


def test_run_validation_returns_the_verdicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The run result carries the verdict contracts, not just a rendered exit code."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_case(repo, "F-1")
    monkeypatch.setattr(_run, "_validate_one", lambda loaded, run: _validated(loaded))

    result = run_validation(
        repo=repo, selection=Selection(), workspace_root=repo / "ws", config=_config()
    )

    assert result.exit_code == 0
    assert [v.decision for v in result.verdicts] == [Decision.FIXED]
    assert result.metadata.total_findings == 1
    assert result.metadata.findings_processed == 1
    assert result.metadata.findings_failed == 0


def test_run_validation_saves_checkpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful validation writes a validate_<id> checkpoint."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_case(repo, "F-1")
    monkeypatch.setattr(_run, "_validate_one", lambda loaded, run: _validated(loaded))

    _run_args(repo, Selection())

    assert load_ckpt(repo / "ws", run_id_for(repo), _step("F-1")) is not None


# resume semantics


def _spy(seen: list[str]):
    """A ``_validate_one`` stand-in that records which case ids actually ran."""
    def _validate_one(loaded: LoadedCase, run: object) -> ValidatedCase:
        seen.append(loaded.case_id)
        return _validated(loaded)
    return _validate_one


def test_resume_skips_checkpointed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--resume skips findings with an existing checkpoint, validates the rest."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_case(repo, "F-done")
    _write_case(repo, "F-new")
    save_ckpt(repo / "ws", run_id_for(repo), _step("F-done"), _result("F-done"))

    seen: list[str] = []
    monkeypatch.setattr(_run, "_validate_one", _spy(seen))
    _run_args(repo, Selection(resume=True))

    assert "F-done" not in seen   # skipped via checkpoint
    assert "F-new" in seen        # freshly validated


def test_no_resume_revalidates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --resume, a checkpointed finding is re-validated (today's behavior)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_case(repo, "F-done")
    save_ckpt(repo / "ws", run_id_for(repo), _step("F-done"), _result("F-done"))

    seen: list[str] = []
    monkeypatch.setattr(_run, "_validate_one", _spy(seen))
    _run_args(repo, Selection(resume=False))

    assert seen == ["F-done"]


def test_resume_unsafe_case_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The step key hashes the full case id, so resume matches the persisted key."""
    repo = tmp_path / "repo"
    repo.mkdir()
    fid = "routers/exec.py:49"
    _write_case(repo, fid, dirname="routers_exec")
    save_ckpt(repo / "ws", run_id_for(repo), _step(fid), _result(fid))

    seen: list[str] = []
    monkeypatch.setattr(_run, "_validate_one", _spy(seen))
    _run_args(repo, Selection(resume=True))

    assert seen == []  # skipped — hashed key matched


def test_resumed_case_without_a_verdict_is_reported_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A checkpoint hit whose case file records no verdict cannot be resumed as validated.

    The case file is authoritative: the checkpoint only proves the work ran, so a case with no
    verdict on its latest attempt resumes as an unscored INCONCLUSIVE session failure (rc 1)
    rather than silently reporting a pass.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_case(repo, "F-1")  # remediated, unjudged
    save_ckpt(repo / "ws", run_id_for(repo), _step("F-1"), _result("F-1"))

    seen: list[str] = []
    monkeypatch.setattr(_run, "_validate_one", _spy(seen))
    result = run_validation(
        repo=repo, selection=Selection(resume=True), workspace_root=repo / "ws",
        config=_config(),
    )

    assert seen == []  # the checkpoint was reused, not re-validated
    assert result.exit_code == 1
    assert [v.decision for v in result.verdicts] == [Decision.INCONCLUSIVE]
    assert result.verdicts[0].score is None


def test_resumed_case_reuses_the_persisted_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the case file carries a verdict, the resume surfaces that verdict verbatim."""
    repo = tmp_path / "repo"
    repo.mkdir()
    d = repo / "security-remediation" / "F-1"
    d.mkdir(parents=True)
    _case("F-1").with_verdict(
        Verdict(decision=Decision.PARTIALLY_FIXED, rationale="partial", score=0.6)
    ).write(d / "finding_case.json")
    save_ckpt(repo / "ws", run_id_for(repo), _step("F-1"), _result("F-1"))

    seen: list[str] = []
    monkeypatch.setattr(_run, "_validate_one", _spy(seen))
    result = run_validation(
        repo=repo, selection=Selection(resume=True), workspace_root=repo / "ws",
        config=_config(),
    )

    assert seen == []
    assert [v.decision for v in result.verdicts] == [Decision.PARTIALLY_FIXED]
    assert result.verdicts[0].score == 0.6
    # PARTIALLY_FIXED derives FAILED, and nothing here validated, so the run reports
    # "completed, nothing remediated" rather than a clean 0. Note the score, 0.6, clears
    # the conditional merge threshold — under MergeReadiness this case is conditionally
    # mergeable, which is exactly why the code keys on CaseState and leaves readiness to
    # the operator.
    assert result.exit_code == EXIT_NOT_REMEDIATED


def test_step_key_distinguishes_ids_colliding_under_safe() -> None:
    """Two ids that sanitize+truncate to the same _safe name get distinct step keys."""
    long = "a" * 200
    a = long + "/X"
    b = long + "/Y"
    assert _run._safe(a) == _run._safe(b)        # collide once sanitized + 80-char truncated
    assert _step(a) != _step(b)                 # full-fidelity hash keeps them apart


def test_step_key_is_scoped_to_the_engine_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two versions of the validation engine must not share a checkpoint.

    The verdict gates a merge, so resuming one from another engine version would republish a
    judgement this engine never made."""
    key = _step("F-1")
    import vvaharness
    monkeypatch.setattr(vvaharness, "__version__", vvaharness.__version__ + "-next")
    assert _step("F-1") != key


def test_step_key_is_scoped_to_the_model_and_backend() -> None:
    """Swapping the orchestrator model must invalidate the row, not resume its verdict.

    A swap moves neither the engine id nor the version, so without the model in the key
    ``--resume`` republished the old verdict. It gates a merge -- stale beats re-spending."""
    key = _run._step_key("F-1", model="claude-opus-5", backend="harness:deepagents")
    assert _run._step_key("F-1", model="claude-sonnet-5", backend="harness:deepagents") != key
    assert _run._step_key("F-1", model="claude-opus-5", backend="harness:sdk") != key


def test_step_key_uses_the_one_shared_derivation() -> None:
    """Validation keys through ``checkpoints.step_key_for``, not a second local hash.

    Two implementations meant a key-scheme change could land on half the product."""
    from vvaharness import __version__
    from vvaharness.orchestrator.checkpoints import VALIDATE_PREFIX, step_key_for

    assert _run._step_key("F-1", model="m", backend="harness:deepagents") == step_key_for(
        VALIDATE_PREFIX, engine_id=_run.VALIDATION_ENGINE_ID, engine_version=__version__,
        case_id="F-1", model="m", backend="harness:deepagents")


def test_step_key_needs_no_provenance() -> None:
    """The key must be computable before any verdict exists.

    The stamp is per-case and carries timestamps, so deriving a key from it would produce a
    different key on every run."""
    import inspect
    params = inspect.signature(_run._step_key).parameters
    assert "provenance" not in params
    assert set(params) == {"case_id", "model", "backend"}


def test_provenance_stamps_the_engine_version() -> None:
    """An unstamped verdict is unattributable and would collapse the step key's scoping."""
    from vvaharness import __version__

    stamp = _run._provenance_for(_config())
    assert stamp.engine == _run.VALIDATION_ENGINE_ID
    assert stamp.engine_version == __version__
    assert stamp.engine_version != ""


def test_resume_after_engine_upgrade_revalidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A checkpoint written by an older engine version is not reused by --resume."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_case(repo, "F-1")
    stale = _run._step_key("F-1", model="a-previous-model", backend="harness:deepagents")
    save_ckpt(repo / "ws", run_id_for(repo), stale, _result("F-1"))

    seen: list[str] = []
    monkeypatch.setattr(_run, "_validate_one", _spy(seen))
    _run_args(repo, Selection(resume=True))

    assert seen == ["F-1"]   # re-validated, because the stale key does not match this engine


def test_resume_ignores_foreign_tracking_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A checkpoint whose verdict is for a different finding is re-validated, never reused."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_case(repo, "F-1")
    # Park a result for a *different* finding under F-1's step key.
    save_ckpt(repo / "ws", run_id_for(repo), _step("F-1"), _result("OTHER"))

    seen: list[str] = []
    monkeypatch.setattr(_run, "_validate_one", _spy(seen))
    _run_args(repo, Selection(resume=True))

    assert seen == ["F-1"]  # identity mismatch → re-validated, foreign verdict not substituted


# parser + selection wiring for --resume


def test_parser_resume_flag() -> None:
    """--resume parses to args.resume True; absent defaults False."""
    assert _build_parser().parse_args(["--repo", ".", "--all", "--resume"]).resume is True
    assert _build_parser().parse_args(["--repo", ".", "--all"]).resume is False


@pytest.mark.parametrize("kw", [{"every_validatable": True}, {"findings": ("F-1",)}, {}])
def test_resolve_selection_threads_resume(kw: dict) -> None:
    """resume rides through every _resolve_selection precedence branch (all / finding / default)."""
    from vvaharness.validation.cli.args import ValidateArgs
    base: dict = {"every_validatable": False, "findings": (), "max_findings": None, "resume": True}
    base.update(kw)
    cfg = SimpleNamespace(max_findings=20)
    assert _resolve_selection(ValidateArgs(repo=Path("/repo"), **base), cfg).resume is True


def test_validation_run_resume_default() -> None:
    """ValidationRun defaults resume to False."""
    run = ValidationRun(
        repo=Path("."), workspace_root=Path("ws"),
        config=SimpleNamespace(), run_id="abc",
        provenance=Provenance(), policy=ScoringPolicy(),
    )
    assert run.resume is False


def test_all_case_ids_fails_safe_on_an_unreadable_case(tmp_path: Path) -> None:
    """Pruning needs the FULL live set, so an incomplete enumeration prunes nothing.

    A corrupt case file is still on disk; dropping its row would discard live state."""
    from vvaharness.validation.ingest.case_loader import all_case_ids

    _write_case(tmp_path, "F-1")
    assert all_case_ids(tmp_path) == ["F-1"]

    bad = tmp_path / "security-remediation" / "02_corrupt"
    bad.mkdir(parents=True)
    (bad / "finding_case.json").write_text("{not json", encoding="utf-8")
    assert all_case_ids(tmp_path) is None


def test_no_verdict_is_stamped_as_unattributable() -> None:
    """The harness reporting a missing record must not look like an unstamped judgement."""
    from vvaharness import __version__

    stamp = _run._no_verdict().produced_by
    assert stamp.engine == _run.VALIDATION_ENGINE_ID
    assert stamp.engine_version == __version__
    assert stamp.model == ""      # no model reached this; it is a harness statement


def test_measured_stamp_is_per_case() -> None:
    """Two cases in one run get distinct windows off a shared identity base.

    A single run-level stamp misattributed every case after the first."""
    from datetime import datetime, timedelta, timezone

    from vvaharness.util.tokens import Spend

    base = _run._provenance_for(_config())
    assert base.started is None and base.ended is None

    t0 = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)
    a = _run._measured(base, t0, Spend())
    b = _run._measured(base, t0 + timedelta(seconds=30), Spend())
    assert a.started != b.started
    assert a.engine == b.engine and a.model == b.model
    assert a.ended is not None and a.ended >= a.started
