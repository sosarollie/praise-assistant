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

"""Core validation execution: run_validation() and _validate_one()."""

from __future__ import annotations

import asyncio
import shutil
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from vvaharness.models import HARNESS_REGISTRY, Provenance, ScoringPolicy, Verdict
from vvaharness.orchestrator.checkpoints import VALIDATE_PREFIX, step_key_for
from vvaharness.report.redact import redact
from vvaharness.util.tokens import TOKENS, Spend, reported_between
from vvaharness.validation.cli._patterns import _UNSAFE
from vvaharness.validation.config import Config
from vvaharness.validation.constants.artifacts import (
    CMD_PREVIEW_LEN,
    LOGGING_DIRNAME,
    ORCHESTRATOR_LOG_DIRNAME,
    SESSION_LOG_FILENAME,
    VALIDATABLE_STATES,
    VALIDATE_ALIAS_S11,
    VALIDATION_SESSION_LOG_PREFIX,
)
from vvaharness.validation.constants.scoring import FIX_POLICY
from vvaharness.validation.execution.pipeline import execute_plan
from vvaharness.validation.ingest.case_loader import (
    LoadedCase,
    all_case_ids,
    discover_cases,
    select_cases,
)
from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.ingest.manifest_builder import build_manifest
from vvaharness.validation.ingest.workspace import assert_remediation_applied, stage_workspace
from vvaharness.validation.io.case_writeback import build_verdict, write_back_verdict
from vvaharness.validation.io.result_collector import CollectedFinding
from vvaharness.validation.models import RunMetadata, ValidationResult
from vvaharness.validation.models.plans import FixValidationPlan
from vvaharness.validation.report import augment_reports
from vvaharness.validation.report.models import ValidatedFinding

__all__ = ["VALIDATION_ENGINE_ID", "Selection", "ValidationRunResult", "run_validation"]

#: Engine identity stamped on every verdict; mirrors plugin_runner.ENGINE_ID.
VALIDATION_ENGINE_ID = "vvaharness.validation"


class SessionLogPaths(NamedTuple):
    """Where to read a session log from, and where its redacted copy will be written."""

    source: Path
    destination: Path


class ValidatedCase(NamedTuple):
    """One case that was run to completion, with its verdict and render row."""

    loaded: LoadedCase
    verdict: Verdict
    row: ValidationResult
    session_failed: bool


class ValidationRunResult(NamedTuple):
    """What one validation run produced: verdicts, exit code, and run metadata."""

    exit_code: int
    verdicts: tuple[Verdict, ...]
    metadata: RunMetadata


def _safe(case_id: str) -> str:
    """Return a filesystem-safe version of a case id (max 80 chars)."""
    return _UNSAFE.sub("_", case_id)[:CMD_PREVIEW_LEN]


def _engine_identity(config: Config) -> tuple[str, str]:
    """Resolve (model id, registry-qualified backend) for the validate role."""
    return str(config.agent.model), f"{HARNESS_REGISTRY}:{config.agent.via}"


def _step_key(case_id: str, *, model: str, backend: str) -> str:
    """Resume-checkpoint step for a case, keyed on the full case id to avoid collisions."""
    from vvaharness import __version__
    return step_key_for(VALIDATE_PREFIX, engine_id=VALIDATION_ENGINE_ID,
                        engine_version=__version__, case_id=case_id,
                        model=model, backend=backend)


def _session_log_dest(workspace: Path, loaded: LoadedCase) -> SessionLogPaths | None:
    """Resolve the source and destination paths for the session log, or None if unavailable."""
    src = workspace / LOGGING_DIRNAME / ORCHESTRATOR_LOG_DIRNAME / SESSION_LOG_FILENAME
    if not src.exists():
        return None
    fname = f"{VALIDATION_SESSION_LOG_PREFIX}{_safe(loaded.case_id)}.jsonl"
    return SessionLogPaths(src, loaded.path.parent / fname)


def _persist_session_log(workspace: Path, loaded: LoadedCase) -> Path | None:
    """Persist the redacted session transcript next to the case file; best-effort."""
    resolved = _session_log_dest(workspace, loaded)
    if resolved is None:
        return None
    src, dest = resolved
    try:
        dest.write_text(
            redact(src.read_text(encoding="utf-8", errors="replace")), encoding="utf-8"
        )
    except (OSError, ValueError):
        dest.unlink(missing_ok=True)
        return None
    return dest


def _print_result(row: ValidationResult) -> None:
    """Print a one-line verdict summary for a completed validation."""
    print(f"[{row.tracking_id}] verdict={row.reason_for_decision} score={row.fix_confidence}")
    if row.justification:
        print(f"    justification: {row.justification}")


def _run_plan(loaded: LoadedCase, run: ValidationRun, workspace: Path) -> ValidatedCase:
    """Stage, validate and write back one case, returning its verdict and timed row."""
    started = datetime.now(timezone.utc)
    spend_before = TOKENS.spend()
    session_id = uuid.uuid4().hex
    latest = loaded.case.attempts[-1]
    stage_workspace(run.repo, workspace, latest.remediation.diff)
    plan = FixValidationPlan(
        case_id=loaded.case_id,
        session_id=session_id,
        manifest=build_manifest(loaded.case, session_id=session_id),
        workspace_dir=workspace,
        output_dir=workspace,
        provenance=run.provenance,
        policy=run.policy,
    )
    outcome = asyncio.run(
        execute_plan(
            plan, run.config, post_results=False, meta=RunMetadata(total_findings=1)
        )
    )
    collected: CollectedFinding = outcome.findings[0]
    verdict = build_verdict(
        loaded.case,
        workspace,
        provenance=_measured(run.provenance, started, spend_before),
        policy=run.policy,
        session_failed=outcome.session_failed,
    )
    _record(loaded, verdict, workspace)
    return ValidatedCase(loaded, verdict, collected.row, outcome.session_failed)


def _measured(base: Provenance, started: datetime, spend_before: Spend) -> Provenance:
    """*base* with this case's session window and spend closed on (safe: cases run sequentially)."""
    usd, turns = reported_between(spend_before, TOKENS.spend())
    return base.model_copy(update={"started": started, "ended": datetime.now(timezone.utc),
                                   "usd": usd, "turns": turns})


def _record(loaded: LoadedCase, verdict: Verdict, workspace: Path) -> None:
    """Persist the session log and the verdict, reporting both on stderr."""
    record = _persist_session_log(workspace, loaded)
    if record is not None:
        print(f"  [{VALIDATE_ALIAS_S11}] session log → {record}", file=sys.stderr)
    judged = write_back_verdict(loaded.case, verdict, loaded.path)
    if judged is not None:
        print(
            f"  [{VALIDATE_ALIAS_S11}] case updated → {loaded.case_id}: "
            f"state={judged.state.value}",
            file=sys.stderr,
        )


def _validate_one(loaded: LoadedCase, run: ValidationRun) -> ValidatedCase | None:
    """Validate one case, or None when the pre-flight gate refuses it."""
    if not loaded.case.attempts:
        print(
            f"refusing {loaded.case_id}: no remediation attempt to validate", file=sys.stderr
        )
        return None
    workspace = run.workspace_root / _safe(loaded.case_id)
    try:
        assert_remediation_applied(run.repo, loaded.case.attempts[-1].remediation.files_touched)
    except IngestError as exc:
        print(f"refusing {loaded.case_id}: {exc}", file=sys.stderr)
        return None
    try:
        return _run_plan(loaded, run, workspace)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _resume_hit(run: ValidationRun, step: str) -> ValidationResult | None:
    """Return the cached render row for a prior run of *step*, or None to re-run."""
    from vvaharness.orchestrator.checkpoints import load_ckpt
    return load_ckpt(run.workspace_root, run.run_id, step)


def _process_case(loaded: LoadedCase, run: ValidationRun) -> ValidatedCase | None:
    """Validate (or resume) one case; checkpoint a fresh row. None on gate failure."""
    model, backend = _engine_identity(run.config)
    step = _step_key(loaded.case_id, model=model, backend=backend)
    if run.resume:
        cached = _resume_hit(run, step)
        # Reuse only when the cached row matches THIS case; else re-validate.
        if cached is not None and cached.tracking_id == loaded.case_id:
            print(
                f"  [{VALIDATE_ALIAS_S11}] resume: {loaded.case_id} already validated",
                file=sys.stderr,
            )
            return _resumed(loaded, cached)
    validated = _validate_one(loaded, run)
    if validated is not None:
        from vvaharness.orchestrator.checkpoints import save_ckpt
        save_ckpt(run.workspace_root, run.run_id, step, validated.row)
    return validated


def _resumed(loaded: LoadedCase, cached: ValidationResult) -> ValidatedCase:
    """Rebuild a ValidatedCase from a checkpointed row and the case's persisted verdict."""
    latest = loaded.case.attempts[-1] if loaded.case.attempts else None
    verdict = latest.verdict if latest is not None else None
    if verdict is None:
        return ValidatedCase(loaded, _no_verdict(), cached, session_failed=True)
    return ValidatedCase(loaded, verdict, cached, session_failed=False)


def _no_verdict() -> Verdict:
    """Verdict for a resume whose case file records none: unscored, engine-stamped but no model."""
    from vvaharness import __version__
    from vvaharness.models import Decision
    return Verdict(
        decision=Decision.INCONCLUSIVE,
        rationale="resumed from a checkpoint, but the case file records no verdict",
        score=None,
        produced_by=Provenance(engine=VALIDATION_ENGINE_ID, engine_version=__version__),
    )


def _run_cases(cases: list[LoadedCase], run: ValidationRun) -> tuple[int, list[ValidatedCase]]:
    """Run (or resume) validation per case; return the failure count and validated cases."""
    failures = 0
    validated: list[ValidatedCase] = []
    for loaded in cases:
        result = _process_case(loaded, run)
        if result is None:
            failures += 1  # refused before validation; _validate_one already explained why
            continue
        if result.session_failed:
            # A session/agent error — surface as FAILED, not a normal verdict.
            print(
                f"FAILED: {loaded.case_id} — {result.row.reason_for_decision}", file=sys.stderr
            )
            failures += 1
        else:
            _print_result(result.row)
        validated.append(result)
    return failures, validated


@dataclass(frozen=True)
class Selection:
    """What to validate: explicit case ids, or the validatable set capped top-N by CVSS."""

    case_ids: list[str] | None = None
    max_findings: int | None = None
    resume: bool = False


@dataclass(frozen=True)
class ValidationRun:
    """Shared state of one validation run, threaded through the per-case loop."""

    repo: Path
    workspace_root: Path
    config: Config
    run_id: str
    provenance: Provenance
    policy: ScoringPolicy
    resume: bool = False


def _cleanup_workspace(workspace_root: Path) -> None:
    """Remove the ephemeral staging tree; surface a genuine failure (e.g. permissions) as a WARN."""
    try:
        shutil.rmtree(workspace_root)
    except FileNotFoundError:
        pass  # already removed: nothing to clean
    except OSError as exc:
        print(
            f"  [{VALIDATE_ALIAS_S11}] WARN: could not remove workspace {workspace_root}: {exc}",
            file=sys.stderr,
        )


def _empty_selection_rc(repo: Path) -> int:
    """Exit code when nothing was selected: 0 if all cases are closed already, 1 if none exist."""
    if discover_cases(repo):
        print(
            f"validation: nothing to validate — all findings under {repo} are already "
            "in a terminal state",
            file=sys.stderr,
        )
        return 0
    valid = " / ".join(sorted(state.value for state in VALIDATABLE_STATES))
    print(
        f"validation cannot run: no findings in a validatable state ({valid}) under {repo}",
        file=sys.stderr,
    )
    return 1


def _prune_orphans(repo: Path, run_id: str, *, model: str, backend: str) -> None:
    """Drop this repo's rows no case on disk claims (live set is every case, not ``--finding``)."""
    from vvaharness.orchestrator.checkpoints import prune_stale_steps
    case_ids = all_case_ids(repo)
    if case_ids is None:
        return
    prune_stale_steps(run_id, VALIDATE_PREFIX,
                      [_step_key(cid, model=model, backend=backend)
                       for cid in case_ids])


def _provenance_for(config: Config) -> Provenance:
    """Stamp every verdict with what produced it; engine_version scopes the resume key."""
    from vvaharness import __version__
    model, backend = _engine_identity(config)
    return Provenance(
        engine=VALIDATION_ENGINE_ID,
        engine_version=__version__,
        model=model,
        backend=backend,
    )


def run_validation(
    *,
    repo: Path,
    selection: Selection,
    workspace_root: Path,
    config: Config,
    report_md: Path | None = None,
) -> ValidationRunResult:
    """Validate each validatable case in sequence; exit code is 0 when all succeeded."""
    meta = RunMetadata()
    try:
        cases = select_cases(repo, selection.case_ids, selection.max_findings)
    except IngestError as exc:
        print(f"ingest error: {exc}", file=sys.stderr)
        meta.errors.append(str(exc))
        return ValidationRunResult(1, (), meta)
    if not cases:
        return ValidationRunResult(_empty_selection_rc(repo), (), meta)
    # SQLite resume layer (lazy import keeps the validation package standalone-runnable).
    from vvaharness.orchestrator.checkpoints import run_id_for
    from vvaharness.orchestrator.store import register_run
    run_id = run_id_for(repo)
    register_run(run_id, repo_root=str(repo.resolve()))
    model, backend = _engine_identity(config)
    _prune_orphans(repo, run_id, model=model, backend=backend)
    run = ValidationRun(
        repo=repo,
        workspace_root=workspace_root,
        config=config,
        run_id=run_id,
        provenance=_provenance_for(config),
        policy=FIX_POLICY,
        resume=selection.resume,
    )
    failures, validated = _run_cases(cases, run)
    meta.total_findings = len(cases)
    meta.findings_processed = len(validated)
    meta.findings_failed = failures
    # best-effort: write results into the combined report
    augment_reports(
        repo,
        [ValidatedFinding(item.loaded.case.finding, item.row) for item in validated],
        report_md,
    )
    # Remove the staging tree entirely; checkpoints live in SQLite, so this is safe for --resume.
    _cleanup_workspace(workspace_root)
    # Lazy, like the resume layer above, so the validation package stays
    # standalone-runnable. A session failure still outranks a verdict: `failures` keeps
    # first claim on the code, so a broken run is never reported as a clean run that
    # merely failed to fix anything.
    from vvaharness.orchestrator.case_rollup import rc_for_verdicts
    verdicts = tuple(item.verdict for item in validated)
    return ValidationRunResult(
        exit_code=1 if failures else rc_for_verdicts(verdicts),
        verdicts=verdicts,
        metadata=meta,
    )
