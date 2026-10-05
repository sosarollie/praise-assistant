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

"""Unit tests for the s11 pipeline stage (s11_validate) and the scan.py opt-in block.

Fully offline/deterministic: validation.cli.main is monkeypatched so no model
SDK, network, or LLM call is made.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vvaharness import config as config_mod
from vvaharness.pipeline.stages import s11_validate

# helpers


def _cfg(step_validate: dict | None = None) -> config_mod.Config:
    data: dict = {"models": {"validate": {"id": "x", "via": "cli"}}}
    if step_validate is not None:
        data["step_validate"] = step_validate
    return config_mod.Config(data)


# s11_validate.run — argv construction


def test_run_passes_repo_config_without_all(tmp_path: Path) -> None:
    """run() with no finding_ids sends --repo + --config and NO --all.

    Omitting --all is what lets step_validate.max_findings apply in-scan; passing it
    would uncap the selection and make the profile budget dead config.
    """
    seen: list[list[str]] = []

    with patch("vvaharness.validation.cli.main", side_effect=lambda a: seen.append(a) or 0):
        rc = s11_validate.run(tmp_path, cfg=_cfg(), config_path="prof.yaml")

    assert rc == 0
    assert seen[0][:2] == ["--repo", str(tmp_path)]
    # The scan's profile is forwarded so s11 reads the same config (F21).
    assert "--config" in seen[0]
    assert seen[0][seen[0].index("--config") + 1] == "prof.yaml"
    assert "--all" not in seen[0]
    assert "--finding" not in seen[0]


def test_profile_max_findings_reaches_selection(tmp_path: Path) -> None:
    """The in-scan argv (no --finding, no --all) resolves to a capped Selection.

    End-to-end over the real parser + _resolve_selection: the profile's
    step_validate.max_findings arrives as the config cap, so the top-N budget the
    scan configured is the one validation enforces.
    """
    from vvaharness.validation.cli import _resolve_selection
    from vvaharness.validation.cli._parser import _build_parser

    seen: list[list[str]] = []
    with patch("vvaharness.validation.cli.main", side_effect=lambda a: seen.append(a) or 0):
        s11_validate.run(tmp_path, cfg=_cfg({"max_findings": 20}), config_path="prof.yaml")

    from vvaharness.validation.cli.args import ValidateArgs
    args = ValidateArgs.of(_build_parser().parse_args(seen[0]))
    selection = _resolve_selection(args, SimpleNamespace(max_findings=20))

    assert selection.case_ids is None
    assert selection.max_findings == 20


def test_run_empty_config_path_falls_back_to_default(tmp_path: Path) -> None:
    """An empty config_path omits --config so the validator uses its packaged default (F21)."""
    seen: list[list[str]] = []

    with patch("vvaharness.validation.cli.main", side_effect=lambda a: seen.append(a) or 0):
        s11_validate.run(tmp_path, cfg=_cfg(), config_path="")

    assert "--config" not in seen[0]


def test_run_passes_finding_ids(tmp_path: Path) -> None:
    """run() with finding_ids sends --finding per id."""
    seen: list[list[str]] = []

    with patch("vvaharness.validation.cli.main", side_effect=lambda a: seen.append(a) or 0):
        rc = s11_validate.run(tmp_path, cfg=_cfg(), config_path="prof.yaml", finding_ids=["F-1", "F-2"])

    assert rc == 0
    argv = seen[0]
    assert "--finding" in argv
    assert argv[argv.index("--finding") + 1] == "F-1"
    # second --finding
    second = argv.index("--finding", argv.index("--finding") + 1)
    assert argv[second + 1] == "F-2"
    assert "--all" not in argv


def test_run_propagates_nonzero_exit(tmp_path: Path) -> None:
    """run() returns whatever exit code validation.cli.main returns."""
    with patch("vvaharness.validation.cli.main", return_value=3):
        rc = s11_validate.run(tmp_path, cfg=_cfg(), config_path="prof.yaml")
    assert rc == 3


# s11_validate.run — the case-rollup hook
# The scan tests below patch s11_validate.run wholesale, so they bypass this hook;
# these two exercise it directly.


def test_s11_stage_records_the_rollup_after_validation_ran(tmp_path: Path) -> None:
    """run() records the rollup for the repo it was handed, and does it AFTER validation.

    The ordering is the whole point and needs its own evidence: recorded before
    validate_main, every case would still be `remediated` with no decision at all — the
    tally would omit exactly the information the rollup exists to report — and an
    assertion on the repo path alone would stay green. So both calls append to one list
    and the order is asserted.
    """
    from vvaharness.orchestrator import case_rollup

    calls: list[object] = []

    with patch("vvaharness.validation.cli.main",
               side_effect=lambda argv: calls.append("validated") or 0), \
            patch.object(case_rollup, "record",
                         side_effect=lambda repo: calls.append(repo) or {}):
        rc = s11_validate.run(tmp_path, cfg=_cfg(), config_path="prof.yaml")

    assert rc == 0
    assert calls == ["validated", tmp_path]


def test_s11_stage_return_code_survives_a_rollup_failure(tmp_path: Path) -> None:
    """The rollup is reporting: a raising record() must never change the answer the
    stage gives — byte-for-byte the code validate_main returned."""
    from vvaharness.orchestrator import case_rollup

    def boom(repo: object) -> dict:
        raise RuntimeError("rollup exploded")

    with patch("vvaharness.validation.cli.main", return_value=2), \
            patch.object(case_rollup, "record", side_effect=boom):
        rc = s11_validate.run(tmp_path, cfg=_cfg(), config_path="prof.yaml")

    assert rc == 2


def test_s11_stage_forwards_progress_sink(tmp_path: Path) -> None:
    """The in-scan wrapper exposes validation's exact current-run counters."""
    progress: dict[str, int] = {}

    def fake_main(argv: list[str], *, progress: dict[str, int]) -> int:
        progress.update(validated=5, passed=4, failed=1)
        return 0

    with patch("vvaharness.validation.cli.main", side_effect=fake_main):
        rc = s11_validate.run(
            tmp_path, cfg=_cfg(), config_path="prof.yaml", progress=progress)

    assert rc == 0
    assert progress == {"validated": 5, "passed": 4, "failed": 1}


def test_validation_progress_counts_current_run_verdicts() -> None:
    """Only FIXED passes; negative and inconclusive verdicts remain failures."""
    from vvaharness.models import Decision, Verdict
    from vvaharness.validation.cli import _record_progress

    result = SimpleNamespace(
        verdicts=(
            Verdict(decision=Decision.FIXED, rationale="held"),
            Verdict(decision=Decision.NOT_FIXED, rationale="bypass"),
            Verdict(decision=Decision.INCONCLUSIVE, rationale="no evidence"),
        ),
        metadata=SimpleNamespace(total_findings=3),
    )
    progress: dict[str, int] = {}

    _record_progress(result, progress)

    assert progress == {"validated": 3, "passed": 1, "failed": 2}


# scan._run_validation — opt-in wiring


def test_scan_run_validation_calls_s11(tmp_path: Path) -> None:
    """_run_validation delegates to s11_validate.run with repo + cfg."""
    from vvaharness.orchestrator import scan

    called: dict[str, object] = {}

    def _fake_run(
        repo: Path, *, cfg: object, config_path: str,
        finding_ids: object = None, resume: bool = False, report_md: object = None,
    ) -> int:
        called["repo"] = repo
        called["cfg"] = cfg
        called["config_path"] = config_path
        called["resume"] = resume
        called["report_md"] = report_md
        return 0

    with patch.object(s11_validate, "run", side_effect=_fake_run):
        rc = scan._run_validation(tmp_path, _cfg(), config_path="prof.yaml",
                                  report_md=tmp_path / "r.md")

    assert rc == 0  # a clean s11 contributes nothing to the scan's exit code
    assert called["repo"] == tmp_path
    # _run_validation forwards the scan's --config so s11 reads the same profile (F21).
    assert called["config_path"] == "prof.yaml"
    assert called["report_md"] == tmp_path / "r.md"  # canonical report threaded through


def test_scan_run_validation_warns_on_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """_run_validation prints a WARN to stderr when s11 returns non-zero — AND returns
    the code, which is the half that used to be dropped on the floor.

    Asserting only the WARN is what let the swallow live here: the message was already
    correct, so the test passed while the code went nowhere.
    """
    from vvaharness.orchestrator import scan

    with patch.object(s11_validate, "run", return_value=2):
        rc = scan._run_validation(tmp_path, _cfg(), config_path="prof.yaml")

    captured = capsys.readouterr()
    assert rc == 2
    assert "[s11] WARN" in captured.err
    # Says so, like its s10 sibling, instead of leaving the operator to guess.
    assert "the scan's exit code reflects it" in captured.err


def test_the_s11_gate_requires_findings_like_the_s10_gate_does() -> None:
    """A scan that found nothing must not exit non-zero.

    s11 has no verdicts of its own to report when detection found nothing, and the
    frozen validation tree answers "no findings in a validatable state" with exit 1
    (validation/cli/_run.py:_empty_selection_rc). Before the rc was propagated that 1
    was harmless; now it would turn a clean scan of a clean repo into a reported
    failure. The s10 gate one screen above already requires findings, and the s11 gate
    has to match it.

    This is a source tripwire rather than a behavioural test because nothing in the
    suite drives scan_repo as far as s11 — building that harness is a bigger change
    than the guard it would protect. A tripwire that names the consequence beats no pin
    at all; replace it the day a scan_repo harness exists.
    """
    import inspect

    from vvaharness.orchestrator import scan

    src = inspect.getsource(scan.scan_repo)
    assert 'if not (rem_on and report.findings):' in src
    assert 'if not (val_on and report.findings):' in src, (
        "the s11 gate no longer requires report.findings: a scan with zero findings "
        "will run s11, get exit 1 back for having nothing to validate, and report a "
        "clean scan as a failure"
    )


def test_only_the_returns_after_s11_carry_validations_code() -> None:
    """s10's code outranks s11's, and the returns before s11 stay bare.

    Two invariants a later edit could break silently, in a function no test can drive
    that far. `rem_rc or val_rc` — not max(), not sum() — is what makes precedence
    structural: `or` yields the first truthy operand, so a broken pipeline can never be
    downgraded to a validation verdict. And the three --stop-after returns that precede
    s11 must keep bare rem_rc, because folding a validation code into a run that never
    validated would be a lie.
    """
    import inspect

    from vvaharness.orchestrator import scan

    src = inspect.getsource(scan.scan_repo)
    assert src.count("rem_rc or val_rc") == 2, (
        "expected exactly the two ScanOutcome returns after the s11 block to fold in "
        "val_rc"
    )
    assert src.count("len(report.findings), rem_rc)") == 3, (
        "the --stop-after s8/s9/s10 returns must keep bare rem_rc — none of them ran s11"
    )
    # val_rc is initialised on the straight-line path, not at the call site: the
    # disabled and preflight-refused branches skip the call and still reach both folds.
    assert src.index("val_rc = 0") < src.index("val_on = "), (
        "val_rc must be initialised before the s11 gate, or a disabled s11 raises "
        "UnboundLocalError at the end of a full scan"
    )


# scan._validate_preflight — the s11 gate
# Symmetrical with _remediate_preflight: startup preflight only WARNs when a
# post-scan role's credential is missing, so this gate is what turns that gap into
# `[s11] DISABLED` while the rest of the scan completes.


def _val_cfg(orchestrator: object) -> SimpleNamespace:
    return SimpleNamespace(
        models=SimpleNamespace(validate=SimpleNamespace(orchestrator=orchestrator)))


def _credential(monkeypatch: pytest.MonkeyPatch, *, ready: bool, detail: str) -> None:
    """Pin the backend-credential answer. Patched on the environment module because
    _validate_preflight imports the helper at call time (circular-import avoidance)."""
    from vvaharness.util import environment
    monkeypatch.setattr(environment, "_backend_credential_ok",
                        lambda *_a, **_k: (ready, detail))


def test_validate_preflight_blocks_when_role_missing() -> None:
    from vvaharness.orchestrator import scan

    err = scan._validate_preflight(_val_cfg(None))
    assert err and "models.validate.orchestrator" in err


def test_validate_preflight_routes_legacy_openai_to_deepagents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`via: openai` is no longer refused outright — it is checked as DeepAgents.

    The credential probe must see the backend s11 will actually run on, so a role
    spelled `via: openai` passes preflight once the DeepAgents/OpenAI credential is
    present, instead of aborting on the selector alone.
    """
    from vvaharness.orchestrator import scan

    _credential(monkeypatch, ready=True, detail="credential present")
    err = scan._validate_preflight(
        _val_cfg(SimpleNamespace(id="gpt-5.5", via="openai")))
    assert err is None


def test_validate_preflight_reports_routed_backend_on_credential_gap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The message names the routed backend, not the profile spelling, so the operator
    # is pointed at the credential that is actually missing.
    from vvaharness.orchestrator import scan

    _credential(monkeypatch, ready=False, detail="OPENAI_API_KEY not set")
    err = scan._validate_preflight(
        _val_cfg(SimpleNamespace(id="gpt-5.5", via="openai")))
    assert err and "via:deepagents" in err and "OPENAI_API_KEY" in err


def test_validate_preflight_blocks_when_credential_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vvaharness.orchestrator import scan

    _credential(monkeypatch, ready=False, detail="OPENAI_API_KEY not set")
    err = scan._validate_preflight(
        _val_cfg(SimpleNamespace(id="gpt-5.5", via="deepagents", provider="openai")))
    assert err and "via:deepagents" in err and "OPENAI_API_KEY not set" in err


def test_validate_preflight_passes_with_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vvaharness.orchestrator import scan

    _credential(monkeypatch, ready=True, detail="credential present")
    assert scan._validate_preflight(
        _val_cfg(SimpleNamespace(id="gpt-5.5", via="deepagents",
                                 provider="openai"))) is None
