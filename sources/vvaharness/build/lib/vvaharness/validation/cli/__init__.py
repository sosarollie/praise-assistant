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

"""The validation CLI entry point for ``vvaharness validate``."""

from __future__ import annotations

import sys
from collections.abc import MutableMapping
from pathlib import Path

import yaml
from pydantic import ValidationError

from vvaharness.config import is_network_path
from vvaharness.orchestrator import _default_config
from vvaharness.validation.cli._model import _apply_model_env, _check_persona_vendors
from vvaharness.validation.cli._parser import _build_parser
from vvaharness.validation.cli._run import Selection, ValidationRunResult, run_validation
from vvaharness.validation.cli.args import ValidateArgs
from vvaharness.validation.config import Config, load_config
from vvaharness.validation.constants.artifacts import REMEDIATION_DIRNAME, WORKSPACE_DIRNAME
from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.session.errors import ValidationSessionError

# Failures we can describe cleanly to the operator (no raw traceback).
_KNOWN_ERRORS = (
    IngestError,
    ValidationSessionError,
    ValidationError,
    FileNotFoundError,
    OSError,
    yaml.YAMLError,
)


def _resolve_selection(args: ValidateArgs, config: Config) -> Selection:
    """Resolve what to validate: --finding ids win, then --all uncapped, else top-N by CVSS."""
    if args.findings:
        return Selection(case_ids=list(args.findings), resume=args.resume)
    if args.every_validatable:
        return Selection(resume=args.resume)
    cap = args.max_findings if args.max_findings is not None else config.max_findings
    return Selection(max_findings=cap, resume=args.resume)


def _resolve_config_path(args: ValidateArgs) -> str:
    """Return the config path: given --config, else the packaged default (printed, not silent)."""
    if args.config:
        return str(args.config)
    default = str(_default_config())
    print(f"validate: no --config given; using default profile {default}", file=sys.stderr)
    return default


def _is_nonempty_dir(path: Path) -> bool:
    """True when *path* is an existing directory that already contains entries."""
    return path.is_dir() and any(path.iterdir())


def _check_path_guards(args: ValidateArgs) -> str | None:
    """Return an operator error if a path arg is invalid (UNC/network, or a non-empty workspace)."""
    for flag, path in (("--workspace", args.workspace), ("--repo", args.repo)):
        if path is not None and is_network_path(path):
            return (
                f"validate: {flag} {path!r} is a network/UNC path; "
                f"refusing (reading it could leak credentials over SMB)"
            )
    if args.workspace is not None and _is_nonempty_dir(args.workspace):
        return (
            f"validate: --workspace {args.workspace} is not empty; it is treated as ephemeral "
            f"and removed on completion. Pass a new or empty path."
        )
    return None


def _dispatch(
    argv: list[str] | None,
    *,
    progress: MutableMapping[str, int] | None = None,
) -> int:
    """Parse args, resolve model, build config, and run validation; return exit code."""
    args = ValidateArgs.of(_build_parser().parse_args(argv))
    rc, overrides = _apply_model_env(_resolve_config_path(args))
    if rc != 0:
        return rc
    # Both refusals run before load_config, so nothing is staged and nothing spent.
    for code, err in ((2, _check_persona_vendors(overrides)), (1, _check_path_guards(args))):
        if err:
            print(err, file=sys.stderr)
            return code
    config = load_config(overrides=overrides)
    # Resolve to absolute so the Write gate and report reader agree on one path.
    repo: Path = args.repo.resolve()
    workspace_root: Path = (
        args.workspace or (repo / REMEDIATION_DIRNAME / WORKSPACE_DIRNAME)
    ).resolve()
    result = run_validation(
        repo=repo,
        selection=_resolve_selection(args, config),
        workspace_root=workspace_root,
        config=config,
        report_md=args.scan_report,
    )
    if progress is not None:
        _record_progress(result, progress)
    # Only the exit code crosses the ordinary CLI boundary; the optional progress
    # sink lets the in-process scan wrapper report aggregate counts without rereading
    # potentially stale case artifacts.
    return result.exit_code


def _record_progress(
    result: ValidationRunResult,
    progress: MutableMapping[str, int],
) -> None:
    """Copy exact validation-result counts into the scan's progress sink."""
    from vvaharness.models import CaseState
    from vvaharness.models.derive import verdict_state

    passed = sum(
        verdict_state(verdict) is CaseState.VALIDATED
        for verdict in result.verdicts
    )
    # A selected case that did not produce a validated state did not pass
    # validation, whether the cause was a negative verdict, a refusal, or a
    # session failure.  This makes validated == passed + failed.
    validated = result.metadata.total_findings
    progress.update(
        validated=validated,
        passed=passed,
        failed=validated - passed,
    )


def main(
    argv: list[str] | None = None,
    *,
    progress: MutableMapping[str, int] | None = None,
) -> int:
    """CLI boundary: dispatch, turning any failure into a clean message and non-zero exit."""
    try:
        return (_dispatch(argv, progress=progress)
                if progress is not None else _dispatch(argv))
    except _KNOWN_ERRORS as e:
        print(f"validate: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # CLI boundary must not surface a bare traceback
        print(f"validate: unexpected error ({type(e).__name__}): {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
