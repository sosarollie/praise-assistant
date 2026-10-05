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

"""The acceptance criterion for the contracts: usable with no config, profile or prior scan.

If a caller cannot build a Finding by hand and carry it through a remediation and a verdict
without touching the harness's configuration, the types are not a contract -- they are
internal plumbing with public names.
"""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from vvaharness.models import (
    Decision,
    Disposition,
    FindingCase,
    GateAssessment,
    GateStatus,
    Provenance,
    Remediation,
    RemediationKind,
    Severity,
    Verdict,
    merge_readiness_for,
    state_of,
)
from vvaharness.models import Finding


def _finding(**over: object) -> Finding:
    """Build the minimal hand-constructed finding an external caller would have."""
    base = {
        "title": "SQLi in login",
        "file": "app/auth.py",
        "line_start": 42,
        "vuln_class": "injection",
    }
    return Finding(**{**base, **over})


def test_finding_needs_only_four_fields():
    """A caller holding a third-party scanner result has no chunk id, snippet or vote count."""
    f = _finding()
    assert f.severity is Severity.MEDIUM      # defaulted, not demanded
    assert f.confidence == 0.5                # this codebase's "no opinion" value
    assert f.chunk_id == "" and f.code_snippet == ""


def test_vuln_class_tolerates_a_foreign_label():
    """An unrecognised class must not reject an otherwise valid finding."""
    assert _finding(vuln_class="sql-injection").vuln_class.value == "other"
    assert _finding(vuln_class="Injection").vuln_class.value == "injection"


def test_severity_tolerates_title_case():
    """Models and older callers spell it "High"; the canonical value is lower-case."""
    assert _finding(severity="High").severity is Severity.HIGH


def test_case_lifecycle_is_derived_not_stored():
    """State follows the attempt sequence, so no engine can write the state machine."""
    case = FindingCase(case_id="c1", finding=_finding())
    assert case.state.value == "open"

    rem = Remediation(kind=RemediationKind.EDITS_APPLIED, summary="parameterised the query")
    case = case.with_attempt(rem)
    assert case.state.value == "remediated"

    case = case.with_verdict(Verdict(decision=Decision.FIXED, rationale="suite green"))
    assert case.state.value == "validated"


def test_a_later_attempt_reopens_a_fixed_case():
    """A pass that later regresses must not have permanently closed the finding."""
    case = FindingCase(case_id="c1", finding=_finding()).with_attempt(
        Remediation(kind=RemediationKind.EDITS_APPLIED, summary="fix")
    )
    case = case.with_verdict(Verdict(decision=Decision.FIXED, rationale="green"))
    assert case.state.value == "validated"

    regressed = case.with_attempt(
        Remediation(
            kind=RemediationKind.NO_ACTION,
            summary="regressed",
            disposition=Disposition.NOT_APPLICABLE,
        )
    )
    assert regressed.state.value != "validated"


def test_unscored_verdict_still_yields_a_merge_decision():
    """A pass/fail validator reports no number; absent must not be read as zero confidence."""
    v = Verdict(decision=Decision.FIXED, rationale="the project's own tests pass")
    assert v.score is None
    assert merge_readiness_for(v).value == "ready"


def test_no_action_requires_a_reason():
    """'No fix' without a disposition would be an unexplained non-result."""
    with pytest.raises(ValidationError):
        Remediation(kind=RemediationKind.NO_ACTION, summary="nothing done")


def test_gate_names_are_open_but_normalised():
    """Gates are the extension point, so a caller's own gate name is legal."""
    assert GateAssessment(name="Root Cause", status="pass").name == "root_cause"
    custom = GateAssessment(name="no-secrets-introduced", status=GateStatus.FAIL)
    assert custom.name == "no_secrets_introduced"


def test_garbled_status_and_decision_fail_closed():
    """Unreadable input must never improve an outcome."""
    assert GateAssessment(name="g", status="nonsense").status is GateStatus.INVALID
    assert Decision("nonsense") is Decision.INCONCLUSIVE


def test_case_round_trips_through_json():
    """The persisted document must re-validate, derived fields included."""
    case = FindingCase(case_id="c1", finding=_finding()).with_attempt(
        Remediation(
            kind=RemediationKind.DIFF_PROPOSED,
            summary="proposed",
            gates=(GateAssessment(name="source", status=GateStatus.PASS),),
            produced_by=Provenance(engine="e", engine_version="1"),
        )
    )
    payload = case.model_dump(mode="json")
    assert payload["state"] == "remediated"          # emitted for a JSON reader
    assert FindingCase.model_validate(payload) == case  # and accepted back


def test_state_of_covers_every_decision():
    """Totality: a new Decision member must not fall off the mapping."""
    for decision in Decision:
        case = FindingCase(case_id="c", finding=_finding()).with_attempt(
            Remediation(kind=RemediationKind.EDITS_APPLIED, summary="s")
        )
        case = case.with_verdict(Verdict(decision=decision, rationale="r"))
        assert state_of(case.attempts) is not None


def test_backend_is_registry_qualified():
    """The prefix says which registry resolved the transport.

    The llm registry's "cli" is a subprocess; the harness registry aliases "cli" and "sdk" onto
    one in-process SDK. Unqualified, one token meant both in the same file."""
    from vvaharness.models import HARNESS_REGISTRY, LLM_REGISTRY

    assert LLM_REGISTRY != HARNESS_REGISTRY
    assert f"{LLM_REGISTRY}:cli" != f"{HARNESS_REGISTRY}:cli"


def test_attempt_does_not_restate_the_engine_id():
    """The engine belongs to ``Provenance``, not beside it.

    ``Attempt.recorded_by`` duplicated ``produced_by.engine`` with no reader and nothing
    reconciling them."""
    from vvaharness.models import Attempt, Provenance

    assert "recorded_by" not in Attempt.model_fields
    rem = Remediation(kind=RemediationKind.EDITS_APPLIED, summary="fixed",
                      produced_by=Provenance(engine="acme.fixer"))
    case = FindingCase(case_id="c1", finding=_finding()).with_attempt(rem)
    assert case.attempts[-1].remediation.produced_by.engine == "acme.fixer"


def test_unmeasured_cost_and_turns_read_as_absent():
    """A zero could not be told from a genuine zero, so unreported must be None.

    Neither default backend reports cost; a policy-denied attempt really did spend nothing."""
    from vvaharness.models import Provenance

    stamp = Provenance(engine="acme.fixer")
    assert stamp.usd is None
    assert stamp.turns is None
    assert stamp.model_dump()["usd"] is None


def test_evidence_cannot_express_harness_owned_facts():
    """A replacement engine must not be able to claim a diff, a file list, or a kind.

    The first two are facts about the disk that only the harness's snapshot establishes; the
    third depends on the run's mode, which the engine is not told."""
    from vvaharness.models import RemediationEvidence

    forbidden = {"diff", "files_touched", "kind", "disposition"}
    assert not forbidden & set(RemediationEvidence.model_fields)


def test_finalize_is_where_mode_decides_kind():
    """The same claim becomes edits_applied or diff_proposed depending only on mode."""
    from vvaharness.models import RemediationEvidence, RemediationOutcome, finalize

    claim = RemediationEvidence(outcome=RemediationOutcome.FIXED, summary="parameterised")
    edited = {"diff": "@@ -1 +1 @@", "files_touched": ("a.py",)}
    assert finalize(claim, mode="fix", **edited).kind is RemediationKind.EDITS_APPLIED
    assert finalize(claim, mode="report-only").kind is RemediationKind.DIFF_PROPOSED
    # Both spellings circulate for the mode; neither may silently select the fix branch.
    assert finalize(claim, mode="report_only").kind is RemediationKind.DIFF_PROPOSED


def test_finalize_will_not_claim_edits_it_cannot_show():
    """An engine that says "fixed" while nothing changed on disk found it ALREADY fixed.

    Reporting edits_applied with an empty file list and an empty diff is a claim the artefact
    itself contradicts, and it sends a case to a validator with nothing to check."""
    from vvaharness.models import RemediationEvidence, RemediationOutcome, finalize

    claim = RemediationEvidence(outcome=RemediationOutcome.FIXED,
                                summary="already remediated; no new edits were required")
    assert finalize(claim, mode="fix").kind is RemediationKind.ALREADY_RESOLVED
    assert finalize(claim, mode="fix", files_touched=("a.py",)).kind is (
        RemediationKind.EDITS_APPLIED)


def test_finalize_takes_the_diff_from_the_harness_not_the_engine():
    """The engine has no diff field, so the only diff on a contract is the one we derived."""
    from vvaharness.models import RemediationEvidence, RemediationOutcome, finalize

    claim = RemediationEvidence(outcome=RemediationOutcome.FIXED, summary="s")
    assert finalize(claim, mode="fix").diff == ""
    assert finalize(claim, mode="fix", diff="@@ -1 +1 @@").diff == "@@ -1 +1 @@"


def test_remediate_is_callable_with_a_finding_and_a_repo(tmp_path, monkeypatch):
    """The embeddable path: a Finding in, a Remediation out, no CLI and no hand-written config."""
    from vvaharness import remediate
    from vvaharness.remediation_agent import plugin_runner

    monkeypatch.setattr(
        plugin_runner, "_invoke",
        lambda finding, cfg, repo, mode, verbose=False, *, pre=None, ctx=None: json.dumps({
            "verdict": "Fixed", "summary": "parameterised the query",
            "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
            "changes": [{"file": "app/db.py", "summary": "bound the parameter"}],
        }))

    # The stub claims an edit to app/db.py, so the file must exist for the harness to verify it.
    (tmp_path / "app").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "db.py").write_text("q = 'x'\n", encoding="utf-8")
    rem = remediate(_finding(), repo=tmp_path)
    assert isinstance(rem, Remediation)
    assert rem.kind is RemediationKind.EDITS_APPLIED
    assert rem.produced_by.engine == "vvaharness.remediation_agent"
    # The case file the validator reads is on disk, written by the harness not the engine.
    assert list(tmp_path.glob("security-remediation/*/finding_case.json"))


def test_remediate_report_only_proposes_instead_of_applying(tmp_path, monkeypatch):
    """mode is a call-site safety choice, not a profile setting."""
    from vvaharness import remediate
    from vvaharness.remediation_agent import plugin_runner

    monkeypatch.setattr(
        plugin_runner, "_invoke",
        lambda finding, cfg, repo, mode, verbose=False, *, pre=None, ctx=None: json.dumps(
            {"verdict": "Fixed", "summary": "would parameterise"}))

    rem = remediate(_finding(), repo=tmp_path, mode="report-only")
    assert rem.kind is RemediationKind.DIFF_PROPOSED


def test_input_models_that_never_got_a_caller_are_gone():
    """RunContext/Budget/Mode declared nine fields and acquired zero callers."""
    import vvaharness.models as m

    for name in ("RunContext", "Budget", "Mode"):
        assert not hasattr(m, name), f"{name} is still exported"
