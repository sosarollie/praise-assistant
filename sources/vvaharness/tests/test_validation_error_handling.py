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

"""Validation robustness: marker-gate removal, model-endpoint validation, hard-failure
classification, the CLI error boundary, and the inputs/ hints override."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from vvaharness.models import Provenance
from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.ingest.workspace import assert_remediation_applied

# Marker gate removed: a touched file that exists is enough; empty/missing refused


def test_touched_file_without_marker_is_accepted(tmp_path) -> None:
    (tmp_path / "fix.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    # No "# START GENAI" marker anywhere — must NOT raise anymore (no exception == accepted).
    assert_remediation_applied(tmp_path, ["fix.py"])


def test_no_touched_files_still_refused(tmp_path) -> None:
    with pytest.raises(IngestError, match="no touched files found"):
        assert_remediation_applied(tmp_path, [])


def test_missing_touched_path_refused(tmp_path) -> None:
    with pytest.raises(IngestError, match="no touched files found"):
        assert_remediation_applied(tmp_path, ["does/not/exist.py"])


# Persona/validate model must run on an Anthropic-compatible endpoint


def test_persona_openai_endpoint_accepted_for_deepagents(tmp_path, capsys) -> None:
    from vvaharness.validation.cli import _model

    def fake_resolve(spec):
        sid = spec if isinstance(spec, str) else spec.get("id", "")
        return (sid, "openai" if "gpt" in sid else "cli", {})

    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(
        "models:\n"
        "  validate:\n"
        "    orchestrator: {id: claude-sonnet-4-6, via: sdk}\n"
        "    security_architect: {id: gpt-5.5}\n"
        "    penetration_tester: {id: claude-sonnet-4-6}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )
    rc, overrides = _model._apply_model_env(str(cfg_path))
    out = capsys.readouterr().err
    assert rc == 0
    assert "security_architect_model" in overrides
    assert "not on an Anthropic-compatible endpoint" not in out


def test_persona_all_anthropic_ok(tmp_path) -> None:
    from vvaharness.validation.cli._model import _apply_model_env
    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(
        "models:\n"
        "  validate:\n"
        "    orchestrator: {id: claude-sonnet-4-6, via: sdk}\n"
        "    security_architect: {id: claude-opus-4-8}\n"
        "    penetration_tester: {id: claude-sonnet-4-6}\n"
        "    cross_repo_analyzer: {id: claude-sonnet-4-6}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )
    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    assert overrides.get("security_architect_model") == "claude-opus-4-8"
    assert overrides.get("penetration_tester_model") == "claude-sonnet-4-6"


# A session failure is reported FAILED and forces a non-zero exit


def _loaded_case(case_id: str = "F-1"):
    """A minimal validatable case, paired with the path its verdict would be written to."""
    from vvaharness.models import Finding, FindingCase, Remediation, RemediationKind
    from vvaharness.validation.ingest.case_loader import LoadedCase

    case = FindingCase(
        case_id=case_id,
        finding=Finding(title=case_id, file="app/x.py", line_start=1, vuln_class="injection"),
    ).with_attempt(
        Remediation(
            kind=RemediationKind.EDITS_APPLIED, summary="s", files_touched=("app/x.py",)
        )
    )
    return LoadedCase(case=case, path=Path("/tmp") / case_id / "finding_case.json")


def test_run_cases_marks_session_failure_as_failure(monkeypatch, capsys) -> None:
    from vvaharness.models import Decision, Verdict
    from vvaharness.validation.cli import _run
    from vvaharness.validation.models import unverifiable_row

    loaded = _loaded_case()
    # session_failed is carried explicitly, not sniffed out of the rationale prose.
    failed = _run.ValidatedCase(
        loaded=loaded,
        verdict=Verdict(
            decision=Decision.INCONCLUSIVE, rationale="agent crashed", score=None
        ),
        row=unverifiable_row(tracking_id="F-1", title="F-1", reason="agent crashed"),
        session_failed=True,
    )
    monkeypatch.setattr(_run, "_process_case", lambda case, run: failed)
    run = _run.ValidationRun(
        repo=Path("/tmp"), workspace_root=Path("/tmp"), config=None, run_id="x",
        provenance=Provenance(), policy=None,
    )

    failures, validated = _run._run_cases([loaded], run)

    out = capsys.readouterr().err
    assert failures == 1                 # non-zero so a failure isn't mistaken for success
    assert "FAILED: F-1" in out
    assert "agent crashed" in out
    assert len(validated) == 1           # still recorded in the combined report
    # An unrecorded score must stay absent, never collapse to zero confidence.
    assert validated[0].verdict.score is None


# CLI boundary turns any failure into a clean message + non-zero (no traceback)


def _raiser(exc):
    def _f(_argv):
        raise exc
    return _f


def test_cli_known_error_is_clean(monkeypatch, capsys) -> None:
    from vvaharness.validation import cli as vcli

    monkeypatch.setattr(vcli, "_dispatch", _raiser(IngestError("bad report 'X'")))
    rc = vcli.main([])
    assert rc == 1
    assert "validate: bad report 'X'" in capsys.readouterr().err


def test_cli_unexpected_error_is_clean(monkeypatch, capsys) -> None:
    from vvaharness.validation import cli as vcli

    monkeypatch.setattr(vcli, "_dispatch", _raiser(RuntimeError("boom")))
    rc = vcli.main([])
    assert rc == 1
    assert "validate: unexpected error (RuntimeError): boom" in capsys.readouterr().err


# Hints: sole source is ./inputs/validator_hints.yaml — no bundled fallback


def test_hints_loaded_from_inputs(monkeypatch, tmp_path) -> None:
    from vvaharness.validation.hints import loader

    inp = tmp_path / "inputs"
    inp.mkdir()
    (inp / "validator_hints.yaml").write_text("CWE-99:\n  - only-hint\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert loader._resolve_raw() == {"CWE-99": ["only-hint"]}


def test_hints_absent_is_empty(monkeypatch, tmp_path) -> None:
    from vvaharness.validation.hints import loader

    monkeypatch.chdir(tmp_path)  # no inputs/ → no hints, no crash
    assert loader._resolve_raw() == {}


def test_hints_malformed_is_empty_with_warning(monkeypatch, tmp_path, capsys) -> None:
    from vvaharness.validation.hints import loader

    inp = tmp_path / "inputs"
    inp.mkdir()
    (inp / "validator_hints.yaml").write_text("CWE-89: [unclosed\n: : :", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert loader._resolve_raw() == {}  # malformed → empty, no bundled fallback
    assert "ignoring malformed hints file" in capsys.readouterr().out
