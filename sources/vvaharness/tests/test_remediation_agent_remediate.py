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

"""Tests for the Remediation Agent remediation command.

The backend model call is monkeypatched everywhere so the suite is token-free
and deterministic — we patch the single seam ``plugin_runner._invoke`` (and,
for the wiring test, ``backends.llm.agentic``) to return a canned structured
verdict instead of spending API budget.
"""
from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

import pytest

from vvaharness import config as config_mod
from vvaharness.backends.harness import HarnessResult
from vvaharness.models import (
    CaseState,
    Disposition,
    FindingCase,
    GateStatus,
    RemediationKind,
)
from vvaharness.remediation_agent import interactive, plugin_runner, prompts, remediate
from vvaharness.remediation_agent.models import FixerResult, RemediationVerdict, Verdict
from vvaharness.remediation_agent.plugin_runner.handoff import FixerDispatchGuard
from vvaharness.remediation_agent.report_parser import (
    DONE_MARKER,
    find_scan_dir,
    latest_report,
    mark_done,
    parse_findings,
)

_SAMPLE_REPORT = """# Agentic SAST — app

## Findings (3)

### 1. [CRITICAL] Stored JQL injection via unescaped DB-sourced space_key
**Class:** CWE-943
**File:** `routers/jira.py:174-174`

#### Description
blah blah

### 2. [HIGH] JQL injection via unsanitized `spaces` and `label` query params
**Class:** CWE-943
**File:** `routers/jira.py:324-127`

### 3. [MEDIUM] 409 response discloses internal UUID and JIRA ID
**Class:** CWE-209
**File:** `routers/pr_status.py:64-71`
"""


def _canned_verdict_json(finding_index: int = 0) -> str:
    return json.dumps({
        "finding_index": finding_index,
        "verdict": "Fixed",
        "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
        "root_cause": "interpolated user input into JQL at routers/jira.py:174",
        "changes": [{"file": "routers/jira.py", "summary": "parameterized JQL"}],
        "remaining_risks": [],
        "recommendations": [],
        "summary": "Applied minimal parameterization fix.",
    })


@pytest.fixture
def cfg():
    # The packaged default profile carries a models.remediate role + step_remediate.
    # Force the policy gate OFF by default so the token-free happy-path tests are
    # deterministic regardless of whether the active profile ships
    # enforce_policy: true — the dedicated policy tests opt back in explicitly.
    from vvaharness.orchestrator import _default_config
    cfg = config_mod.load(str(_default_config()))
    cfg._data.setdefault("step_remediate", {})["enforce_policy"] = False
    cfg._data["models"]["remediate"]["via"] = "cli"  # token-free tests stub the cli agentic seam
    return cfg


@pytest.fixture(autouse=True)
def _no_model_calls(monkeypatch):
    """Patch the single model-call seam so no test spends tokens.

    The stub mirrors the REAL ``_invoke`` signature — including the keyword-only
    ``pre``/``ctx`` arguments the policy ALLOW path passes — so the suite is
    robust whether or not ``step_remediate.enforce_policy`` is on in the active
    profile (an enforced + allowed finding routes through ``_invoke(pre=, ctx=)``)."""
    monkeypatch.setattr(
        plugin_runner, "_invoke",
        lambda finding, cfg, repo, mode, verbose=False, *, pre=None, ctx=None:
        _canned_verdict_json())


def _make_scan(tmp_path, *, with_report=True):
    repo = tmp_path / "target"
    repo.mkdir()
    if with_report:
        scan = repo / "security-scan"
        scan.mkdir()
        (scan / "app_20260618T032453Z_report.md").write_text(
            _SAMPLE_REPORT, encoding="utf-8")
    return repo


def test_parse_findings_yields_typed_findings():
    """The markdown parse now ends at a typed ``Finding`` — prose is consumed once."""
    targets = parse_findings(_SAMPLE_REPORT)
    assert [t.index for t in targets] == [1, 2, 3]
    assert [t.severity for t in targets] == ["CRITICAL", "HIGH", "MEDIUM"]
    # The location suffix is split into typed fields, not carried as a string.
    assert targets[0].finding.file == "routers/jira.py"
    assert (targets[0].finding.line_start, targets[0].finding.line_end) == (174, 174)
    assert targets[2].finding.file == "routers/pr_status.py"
    assert (targets[2].finding.line_start, targets[2].finding.line_end) == (64, 71)
    # The narrative sections reach the contract rather than sitting in a prose blob.
    assert targets[0].finding.description == "blah blah"
    assert targets[0].finding.cwe == "CWE-943"
    assert "[CRITICAL]" in targets[0].label
    # A report with no Confidence line means "no opinion", not "distrusted".
    assert targets[0].finding.confidence == 0.5


def test_finding_slug_is_stable_and_safe():
    findings = parse_findings(_SAMPLE_REPORT)
    assert findings[0].slug.startswith("01_")
    assert "/" not in findings[0].slug and " " not in findings[0].slug


def test_find_scan_dir_and_latest_report(tmp_path):
    repo = _make_scan(tmp_path)
    scan_dir = find_scan_dir(repo)
    assert scan_dir is not None and scan_dir.name == "security-scan"
    assert latest_report(scan_dir).name.endswith("_report.md")


def test_build_user_renders_the_finding_from_typed_fields():
    t = parse_findings(_SAMPLE_REPORT)[0]
    user = prompts.build_user(t, "/repo", mode="fix")
    assert "routers/jira.py" in user
    assert "MODE: fix" in user
    # The block is rendered, not passed through: the heading, the typed metadata and the
    # narrative all appear.
    assert "### 1. [CRITICAL] Stored JQL injection" in user
    assert "**File:** `routers/jira.py:174-174`" in user
    assert "#### Description" in user
    assert "blah blah" in user


def test_build_user_carries_taint_refs_and_duplicate_sites():
    """The two things both previous prompt paths dropped on the floor.

    The orchestrator's adapter buried source/sink below the prose and never rendered
    duplicates at all; the report renderer omits source/sink entirely. A fix that misses
    the other collapsed call sites is not a fix, so the agent has to be told about them."""
    from vvaharness.models import DupLocation, Finding
    from vvaharness.remediation_agent.target import RemediationTarget

    finding = Finding(
        title="SQLi", file="app/db.py", line_start=10, vuln_class="injection",
        source_ref="app/api.py:4", sink_ref="app/db.py:10",
        duplicates=[DupLocation(file="app/reports.py", line_start=88, line_end=90,
                                vuln_class="injection", title="SQLi", chunk_id="c1")],
    )
    user = prompts.build_user(RemediationTarget(finding=finding, index=1), "/repo")
    assert "**Source:** `app/api.py:4`" in user
    assert "**Sink:** `app/db.py:10`" in user
    assert "**Also at:** `app/reports.py:88-90`" in user


_VERIFIED_REPORT = """### 1. [CRITICAL] Stored JQL injection
**Class:** CWE-89
**File:** `routers/jira.py:174-174`
**CVSS 3.1:** **9.1** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
**Confidence:** 0.90 (3 runs agreed)

#### Description
space_key flows from the DB into a JQL string.

#### How to fix
Parameterize the JQL.

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 9/10) — reachable from an unauth route

The sink is reachable from an unauthenticated route; no guard intervenes.
"""


def test_rendered_block_keeps_structured_verdict_not_raw_reasoning():
    """Legacy reports still parse raw reasoning, but re-rendering excludes it."""
    from vvaharness.remediation_agent.render import render_finding_md

    target = parse_findings(_VERIFIED_REPORT)[0]
    assert target.finding.verdict == "TRUE_POSITIVE"
    assert target.finding.verdict_confidence == 9
    assert target.finding.verdict_reason == "reachable from an unauth route"
    assert "no guard intervenes" in target.finding.verifier_reasoning

    rendered = render_finding_md(target.finding, 1)
    for fragment in ("### 1. [CRITICAL] Stored JQL injection",
                     "**File:** `routers/jira.py:174-174`",
                     "**CVSS 3.1:** **9.1** (Critical)",
                     "**Confidence:** 0.90 (3 runs agreed)",
                     "space_key flows from the DB into a JQL string.",
                     "#### How to fix",
                     "Parameterize the JQL.",
                     "**Verdict:** TRUE_POSITIVE (confidence: 9/10)",
                     "reachable from an unauth route"):
        assert fragment in rendered, fragment
    assert "no guard intervenes" not in rendered


def test_rendered_block_keeps_the_exploitability_commentary():
    """The last field the render was losing, because it lived only on the wrapper.

    ``exploitability_notes`` is s8's chain-pass commentary and may say a control already
    blocks the path -- i.e. that the fix is unnecessary or should be scoped differently. It
    sat on ``RankedFinding``, which an engine handed a bare ``Finding`` cannot see, so the
    standalone prompt silently dropped it. It is now on ``Finding``.
    """
    from vvaharness.models import Finding
    from vvaharness.remediation_agent.render import render_finding_md

    notes = "Blocked by the edge WAF in prod; still reachable from the internal network."
    finding = Finding(title="SQLi", file="app/db.py", line_start=10,
                      vuln_class="injection", description="d",
                      exploitability_notes=notes)
    assert f"**Exploitability:** {notes}" in render_finding_md(finding, 1)

    # Omitted, not rendered empty, when the chain pass had nothing to say.
    bare = Finding(title="SQLi", file="app/db.py", line_start=10,
                   vuln_class="injection", description="d")
    assert "Exploitability" not in render_finding_md(bare, 1)


def test_rendered_finding_round_trips_through_the_parser():
    """The renderer's output is still a report block the field extractor understands.

    Not a curiosity: it is what proves the rendered prompt block carries the same facts as
    the typed finding, in the same shape the scan report uses, so the agent sees one layout
    whichever entry point drove the run."""
    from vvaharness.models import Finding
    from vvaharness.remediation_agent.render import render_finding_md
    from vvaharness.remediation_agent.report_parser import (
        Finding as ParsedFinding,
    )
    from vvaharness.remediation_agent.report_parser import (
        parse_finding_fields,
    )

    finding = Finding(
        title="SQLi in query builder", file="app/db.py", line_start=10, line_end=12,
        vuln_class="injection", cwe="CWE-89", severity="high",
        description="user input reaches the query", impact="db read",
        recommendation="parameterize", code_snippet="q = f'...{x}'",
        source_ref="app/api.py:4", sink_ref="app/db.py:10",
        confidence=0.8, votes=3, cvss_score=9.8, cvss_rating="Critical",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    body = render_finding_md(finding, 1)
    recovered = parse_finding_fields(
        ParsedFinding(index=1, severity="HIGH", title=finding.title,
                      file="app/db.py:10-12", body=body))
    assert recovered["cwe"] == "CWE-89"
    assert recovered["file"] == "app/db.py"
    assert (recovered["line_start"], recovered["line_end"]) == (10, 12)
    assert recovered["source_ref"] == "app/api.py:4"
    assert recovered["sink_ref"] == "app/db.py:10"
    assert recovered["cvss_score"] == 9.8
    assert recovered["confidence"] == 0.8
    assert recovered["votes"] == 3
    assert recovered["description"] == "user input reaches the query"
    assert recovered["recommendation"] == "parameterize"


def test_system_prompt_embeds_schema():
    assert "JSON Schema" in prompts.SYSTEM
    assert "verdict" in prompts.SYSTEM  # schema field name present


def test_default_profile_keeps_safe_tools_for_opt_in_remediation(monkeypatch):
    monkeypatch.setenv("VVAHARNESS_NO_LOCAL_CONFIG", "1")
    profiles_dir = Path(config_mod.__file__).resolve().parent / "profiles"
    profile = config_mod.load(str(profiles_dir / "default.yaml"))
    assert profile.models.remediate.via == "deepagents"
    assert profile.models.remediate.provider == "anthropic"
    assert profile.step_remediate.enabled is False
    assert profile.step_remediate.enforce_policy is True
    assert profile.step_remediate.allowed_tools == [
        "Read", "Glob", "Grep", "Edit", "Write",
    ]
    assert "Bash" not in profile.step_remediate.allowed_tools


@pytest.mark.parametrize(
    "profile_name", ["default.yaml", "sdk.yaml", "full.yaml", "taint.yaml"])
def test_shipped_profiles_enable_remediation_policy(profile_name):
    profiles_dir = Path(config_mod.__file__).resolve().parent / "profiles"
    profile = config_mod.load(str(profiles_dir / profile_name))
    assert profile.step_remediate.enforce_policy is True


def test_remediation_verdict_validates_canned_json():
    v = RemediationVerdict.model_validate(json.loads(_canned_verdict_json(1)))
    assert v.verdict == "Fixed"
    assert v.gates.source == "pass"


def test_coerce_salvages_verdict_missing_summary():
    # Real failure mode: agent returned a complete verdict but omitted `summary`.
    data = {
        "finding_index": 33,
        "verdict": "Fixed",
        "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
        "root_cause": "TOCTOU between check and update at workflow_service.py:153",
        "changes": [{"file": "services/workflow_service.py",
                     "summary": "wrapped in SELECT ... FOR UPDATE"}],
    }
    v = RemediationVerdict.coerce(data, finding_index=33)
    # the real content is preserved — NOT discarded into Needs Review
    assert v.verdict == "Fixed"
    assert v.finding_index == 33
    assert v.gates.source == "pass"
    assert v.changes[0].file == "services/workflow_service.py"
    assert v.summary == ""  # missing field defaults, doesn't nuke the verdict


def test_coerce_normalises_unknown_verdict():
    v = RemediationVerdict.coerce(
        {"verdict": "TotallyFixed", "summary": "x"}, finding_index=1)
    assert v.verdict == "Needs Review"
    assert v.summary == "x"


def test_coerce_non_dict_degrades_safely():
    v = RemediationVerdict.coerce(["not", "a", "dict"], finding_index=2)
    assert v.verdict == "Needs Review"
    assert v.finding_index == 2


def test_coerce_accepts_native_structured_verdict():
    finding = parse_findings(_SAMPLE_REPORT)[0]
    verdict = RemediationVerdict(verdict="Fixed", summary="native")
    out = plugin_runner._coerce_verdict(verdict, finding)
    assert out is verdict
    assert out.finding_index == finding.index


def test_remediate_missing_repo_arg(cfg):
    assert remediate(None, cfg=cfg) == 2


def test_remediate_requires_cfg():
    assert remediate("/tmp", cfg=None) == 2


def test_remediate_nonexistent_path(tmp_path, cfg):
    assert remediate(str(tmp_path / "nope"), cfg=cfg) == 1


def test_remediate_no_scan_dir(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path, with_report=False)
    assert remediate(str(repo), cfg=cfg) == 1
    assert "security-scan" in capsys.readouterr().err


def test_remediate_no_report(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path, with_report=False)
    (repo / "security-scan").mkdir()
    assert remediate(str(repo), cfg=cfg) == 1
    assert "_report.md" in capsys.readouterr().err


def test_remediate_invalid_mode(tmp_path, cfg):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), ["--mode", "bogus"], cfg=cfg) == 2


def test_remediate_invalid_top(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), ["--top", "0"], cfg=cfg) == 2
    assert "--top" in capsys.readouterr().err


# Report where the band ordering and the CVSS-score ordering DIFFER, so a
# correct --top must select by score, not by report position. Finding 3
# (MEDIUM) carries the highest numeric CVSS, finding 1 (CRITICAL) the lowest.
_SCORED_REPORT = """# Agentic SAST — app

## Findings (3)

### 1. [CRITICAL] low-score critical
**Class:** CWE-89
**File:** `a.py:1-1`
**CVSS 3.1:** **4.0** (Medium) — `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N`

### 2. [HIGH] mid-score high
**Class:** CWE-89
**File:** `b.py:2-2`
**CVSS 3.1:** **6.5** (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`

### 3. [MEDIUM] top-score medium
**Class:** CWE-89
**File:** `c.py:3-3`
**CVSS 3.1:** **9.8** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
"""


def _make_scored_scan(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    scan = repo / "security-scan"
    scan.mkdir()
    (scan / "app_20260618T032453Z_report.md").write_text(
        _SCORED_REPORT, encoding="utf-8")
    return repo


def test_remediate_top_selects_highest_cvss_only(tmp_path, cfg, capsys):
    repo = _make_scored_scan(tmp_path)
    assert remediate(str(repo), ["--top", "2"], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "selecting top 2 of 3 finding(s) by CVSS score" in err
    assert "2/2 findings processed" in err

    rem = repo / "security-remediation"
    findings = parse_findings(_SCORED_REPORT)
    # findings[2] (9.8) and findings[1] (6.5) are the two highest → remediated;
    # findings[0] (4.0) is skipped (no artefact folder).
    assert (rem / findings[2].slug / "finding_case.json").is_file()
    assert (rem / findings[1].slug / "finding_case.json").is_file()
    assert not (rem / findings[0].slug).exists()


def test_remediate_top_larger_than_findings_is_noop(tmp_path, cfg, capsys):
    repo = _make_scored_scan(tmp_path)
    assert remediate(str(repo), ["--top", "10"], cfg=cfg) == 0
    err = capsys.readouterr().err
    # N >= count: no selection message, every finding processed.
    assert "selecting top" not in err
    assert "3/3 findings processed" in err


def _set_top_n_findings(cfg, value):
    """Mutate the loaded Config's step_remediate.top_n_findings in place so a
    test can exercise the profile-driven cap without a bespoke YAML file."""
    sr = cfg._data.setdefault("step_remediate", {})
    sr["top_n_findings"] = value
    return cfg


def test_remediate_honors_profile_top_n_findings_without_flag(tmp_path, cfg, capsys):
    # The standalone `remediate` command (run detached from a scan, no --top)
    # must still apply the profile's step_remediate.top_n_findings cap.
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, 2)
    assert remediate(str(repo), [], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "selecting top 2 of 3 finding(s) by CVSS score" in err
    assert "2/2 findings processed" in err

    rem = repo / "security-remediation"
    findings = parse_findings(_SCORED_REPORT)
    # Only the two highest-CVSS findings are remediated; the 4.0 is skipped.
    assert (rem / findings[2].slug / "finding_case.json").is_file()
    assert (rem / findings[1].slug / "finding_case.json").is_file()
    assert not (rem / findings[0].slug).exists()


def test_remediate_cli_top_overrides_profile_cap(tmp_path, cfg, capsys):
    # --top on the CLI overrides a numeric profile cap for that run.
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, 1)               # profile says 1 ...
    assert remediate(str(repo), ["--top", "2"], cfg=cfg) == 0  # ... CLI says 2
    err = capsys.readouterr().err
    assert "selecting top 2 of 3 finding(s) by CVSS score" in err
    assert "2/2 findings processed" in err


@pytest.mark.parametrize("wildcard", ["all", "*"])
def test_remediate_profile_wildcard_remediates_every_finding(tmp_path, cfg,
                                                             capsys, wildcard):
    # top_n_findings: all/* in the profile → no cap, every finding remediated.
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, wildcard)
    assert remediate(str(repo), [], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "selecting top" not in err          # no narrowing
    assert "3/3 findings processed" in err


def test_remediate_cli_top_all_overrides_numeric_profile(tmp_path, cfg, capsys):
    # --top all overrides a numeric profile cap → remediate every finding.
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, 1)
    assert remediate(str(repo), ["--top", "all"], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "selecting top" not in err
    assert "3/3 findings processed" in err


def test_remediate_happy_path(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "identified 3 SAST issue(s)" in err
    assert "3/3 findings processed" in err
    assert "model:" in err  # banner printed


def test_remediate_writes_artifacts(tmp_path, cfg):
    repo = _make_scan(tmp_path)
    # The canned verdict claims routers/jira.py; the harness records a touched path only when
    # it resolves to a real file, so the fixture must actually contain it.
    (repo / "routers").mkdir(parents=True, exist_ok=True)
    (repo / "routers" / "jira.py").write_text("jql = 'x'\n", encoding="utf-8")
    assert remediate(str(repo), cfg=cfg) == 0
    rem = repo / "security-remediation"
    for f in parse_findings(_SAMPLE_REPORT):
        d = rem / f.slug
        # Evidence artefacts live under evidence/ ...
        assert (d / "evidence" / "triage.json").is_file()
        assert (d / "evidence" / "summary.md").is_file()
        data = json.loads((d / "evidence" / "triage.json").read_text())
        assert data["finding_index"] == f.index
        assert data["verdict"] == "Fixed"
        # ... and the canonical case file sits at the finding root.
        case = FindingCase.read(d / "finding_case.json")
        assert case.finding.title == f.title
        attempt = case.attempts[-1]
        assert attempt.remediation.kind is RemediationKind.EDITS_APPLIED
        # Harness-verified, not the agent's word for it.
        assert attempt.remediation.files_touched == ("routers/jira.py",)
        # An applied, unvalidated fix is REMEDIATED — derived, never written.
        assert case.state is CaseState.REMEDIATED


def test_finding_case_shape(tmp_path, cfg):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    rem = repo / "security-remediation"
    f1 = parse_findings(_SAMPLE_REPORT)[0]
    path = rem / f1.slug / "finding_case.json"
    case = FindingCase.read(path)
    assert case.case_id.endswith("routers/jira.py-174")
    assert case.finding.cwe == "CWE-943"
    assert case.finding.line_start == 174
    assert case.finding.vuln_class_label == "CWE-943"   # folds to OTHER, wording kept
    assert len(case.attempts) == 1
    attempt = case.attempts[0]
    assert attempt.ordinal == 1
    assert attempt.verdict is None                      # nothing has judged it yet
    assert attempt.reverted_paths == ()
    assert attempt.remediation.summary
    assert attempt.remediation.disposition is None
    # The three evidence gates the prompt asks for are carried across verbatim.
    assert [g.name for g in attempt.remediation.gates] == [
        "source", "sink", "missing_control"]
    assert all(g.status is GateStatus.PASS for g in attempt.remediation.gates)
    # ``state`` is emitted for a JSON reader but is never an accepted input.
    assert json.loads(path.read_text())["state"] == "remediated"


def test_derive_diff_prefers_git(tmp_path):
    """In a git work tree the diff comes from git, scoped to the changed files."""
    import subprocess

    from vvaharness.remediation_agent.artifacts import derive_diff

    repo = tmp_path / "gitrepo"
    repo.mkdir()
    (repo / "routers").mkdir()
    target = repo / "routers" / "jira.py"
    target.write_text("jql = f'... {space} ...'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-qm", "init"],
                   check=True, capture_output=True)
    target.write_text("jql = 'parameterized'\n", encoding="utf-8")

    diff = derive_diff(repo, {}, ["routers/jira.py"])
    assert "routers/jira.py" in diff and "parameterized" in diff
    assert "not a git repository" not in diff       # git path, not the fallback


def test_no_diff_patch_when_nothing_changed(tmp_path):
    """A non-git target with no snapshot yields no diff, so no patch is written."""
    from vvaharness.remediation_agent import artifacts as _artifacts
    from vvaharness.remediation_agent.artifacts import derive_diff
    from vvaharness.remediation_agent.models import Gates, RemediationVerdict

    v = RemediationVerdict(finding_index=1, verdict="Needs Review",
                           gates=Gates(), summary="x",
                           changes=[{"file": "a.py", "summary": "y"}])
    assert derive_diff(tmp_path, None, ["a.py"]) == ""
    out = tmp_path / "out"
    _artifacts.write_case(out, v, _contract(v), meta={"mode": "fix"})
    assert not (out / "evidence" / "diff.patch").exists()
    assert json.loads(
        (out / "evidence" / "triage.json").read_text())["diff_captured"] is False


def test_synth_diff_used_for_non_git_target(tmp_path):
    """Non-git target: a pre-edit snapshot + on-disk edit yields a synthesized
    unified diff, which the writer stores in evidence/diff.patch."""
    from vvaharness.remediation_agent import artifacts as _artifacts
    from vvaharness.remediation_agent.models import Gates, RemediationVerdict

    repo = tmp_path / "plainrepo"  # NOT a git repo
    (repo / "routers").mkdir(parents=True)
    target = repo / "routers" / "jira.py"
    target.write_text("jql = f'... {space} ...'\n", encoding="utf-8")

    # Runner snapshots BEFORE the agent edits ...
    before = _artifacts.snapshot_files(repo, ["routers/jira.py:174-174"])
    # ... then the "agent" edits the file in place.
    target.write_text("jql = 'parameterized'\n", encoding="utf-8")

    v = RemediationVerdict(
        finding_index=1, verdict="Fixed", gates=Gates(),
        changes=[{"file": "routers/jira.py", "summary": "parameterized"}],
        summary="x")
    diff = _artifacts.derive_diff(repo, before, ["routers/jira.py"])
    remediation = _contract(v, diff=diff)
    out = tmp_path / "out"
    _artifacts.write_case(out, v, remediation, meta={"mode": "fix"})

    patch = out / "evidence" / "diff.patch"
    assert patch.is_file()
    body = patch.read_text()
    assert body == diff                            # unchanged when no secrets are present
    assert "not a git repository" in body          # synthesized-diff marker
    assert "routers/jira.py" in body
    assert "-jql = f'... {space} ...'" in body
    assert "+jql = 'parameterized'" in body
    assert json.loads(
        (out / "evidence" / "triage.json").read_text())["diff_captured"] is True


def test_synth_diff_renders_new_file(tmp_path):
    """A file the agent creates (absent in the snapshot) renders as an added
    file in the synthesized diff."""
    from vvaharness.remediation_agent.artifacts.diff import synth_unified_diff

    repo = tmp_path / "plainrepo"
    repo.mkdir()
    # snapshot taken when the file did not exist yet (value None = absent)
    snap = {"new.py": None}

    (repo / "new.py").write_text("print('hello')\n", encoding="utf-8")

    diff = synth_unified_diff(repo, snap)
    assert diff is not None
    assert "/dev/null" in diff
    assert "b/new.py" in diff
    assert "+print('hello')" in diff


def test_synth_diff_none_when_unchanged(tmp_path):
    from vvaharness.remediation_agent.artifacts.diff import (
        snapshot_files,
        synth_unified_diff,
    )
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    before = snapshot_files(repo, ["a.py"])
    # no edit happens
    assert synth_unified_diff(repo, before) is None


def test_remediate_reuses_scan_checkpoint_dir(tmp_path, cfg):
    """Checkpoints land in the shared scan-pipeline checkpoint store (the same
    SQLite state store + run_id the scan pipeline uses), NOT a private
    security-remediation/checkpoints folder."""
    from vvaharness.orchestrator.checkpoints import REMEDIATE_PREFIX, load_ckpt, run_id_for
    from vvaharness.orchestrator.store import steps_with_prefix
    from vvaharness.remediation_agent.runner import step_key_of
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    run_id = run_id_for(repo)
    # Two halves, both needed. Enumerating proves exactly three rows exist and no stray ones;
    # deriving through step_key_of proves the rows are the ones production would look up, so
    # the test cannot silently decouple from the key if that derivation changes.
    steps = steps_with_prefix(run_id, REMEDIATE_PREFIX)
    assert len(steps) == 3, steps
    assert sorted(step_key_of(t, cfg) for t in parse_findings(_SAMPLE_REPORT)) == steps
    assert all(load_ckpt(repo / "checkpoints", run_id, s) is not None for s in steps)
    assert not (repo / "security-remediation" / "checkpoints").exists()


def test_checkpoint_step_key_is_scoped_to_engine_and_case(tmp_path, cfg):
    """The step key must not be the report ordinal, and must move with the engine version.

    Two properties in one place because they fail the same way — a resume that loads a row
    belonging to something else. The ordinal named "the third finding of whatever list this
    run built", so inserting a finding re-pointed every later row; and without the version a
    re-run after an upgrade republished the previous build's fix as this one's."""
    from vvaharness.models import Finding
    from vvaharness.orchestrator.checkpoints import REMEDIATE_PREFIX
    from vvaharness.remediation_agent.runner import step_key_of
    from vvaharness.remediation_agent.target import RemediationTarget

    finding = Finding(title="SQLi", file="app/db.py", line_start=10,
                      vuln_class="injection", case_id="case-abc")
    key = step_key_of(RemediationTarget(finding=finding, index=1), cfg)
    assert key.startswith(REMEDIATE_PREFIX)

    # Same case at a different report position → the SAME key.
    assert step_key_of(RemediationTarget(finding=finding, index=7), cfg) == key
    # A different case → a different key.
    other = finding.model_copy(update={"case_id": "case-xyz"})
    assert step_key_of(RemediationTarget(finding=other, index=1), cfg) != key
    # A different engine version → a different key, so an upgrade cannot resume.
    import vvaharness
    real = vvaharness.__version__
    try:
        vvaharness.__version__ = f"{real}-next"
        assert step_key_of(RemediationTarget(finding=finding, index=1), cfg) != key
    finally:
        vvaharness.__version__ = real


def test_checkpoint_step_key_moves_with_the_model(tmp_path, cfg):
    """Editing the profile's remediate model must invalidate the row, not resume it.

    A swap moves neither ``ENGINE_ID`` nor the version, so without the model in the key
    ``--resume`` left the previous model's fix standing as this run's."""
    from vvaharness.models import Finding
    from vvaharness.remediation_agent.plugin_runner import engine_model
    from vvaharness.remediation_agent.runner import step_key_of
    from vvaharness.remediation_agent.target import RemediationTarget

    target = RemediationTarget(
        finding=Finding(title="SQLi", file="app/db.py", line_start=10,
                        vuln_class="injection", case_id="case-abc"),
        index=1)
    key = step_key_of(target, cfg)

    # Mutate through _data, as the cfg fixture does — the accessors are views.
    swapped = copy.deepcopy(cfg)
    swapped._data["models"]["remediate"]["id"] = "some-other-model"
    assert engine_model(swapped) != engine_model(cfg), "fixture swap did not change the model"
    assert step_key_of(target, swapped) != key

    # An unanswerable cfg degrades to the empty pair: the key must stay derivable, since it
    # is what decides whether to run at all.
    assert engine_model(object()) == ("", "")
    assert step_key_of(target, object()).startswith("remediate_")


def test_provenance_version_matches_the_key_it_scopes(tmp_path, cfg):
    """The stamp on the record and the value hashed into its key must be the same.

    If they drift, the key says one build produced the attempt while the record says
    another, and the resume guard starts trusting a row it should not."""
    import vvaharness

    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    case = FindingCase.read(
        repo / "security-remediation"
        / parse_findings(_SAMPLE_REPORT)[0].slug / "finding_case.json")
    produced_by = case.attempts[-1].remediation.produced_by
    assert produced_by.engine == plugin_runner.ENGINE_ID
    assert produced_by.engine_version == vvaharness.__version__


def test_remediate_prunes_rows_no_current_finding_claims(tmp_path, cfg, monkeypatch):
    """A detached ``remediate`` clears this repo's stale remediation checkpoint rows.

    Nothing else does: only a fresh scan calls ``reset_run``, so without this a row written
    by an earlier engine version or an earlier finding set survives for the life of the
    state DB, and a later ``--resume`` can load one whose key scheme no longer exists."""
    from vvaharness.orchestrator import checkpoints as ck

    repo = _make_scan(tmp_path)
    run_id = ck.run_id_for(repo)
    # A row from a vanished finding, under a well-formed but no-longer-claimed key.
    stale = ck.REMEDIATE_PREFIX + "0" * 24
    ck.save_ckpt(repo / "checkpoints", run_id, stale, {"finding_id": "gone"})
    assert ck.load_ckpt(repo / "checkpoints", run_id, stale) is not None

    # prune_stale_steps runs at most once per (run_id, prefix) per PROCESS, and other
    # tests in this file already remediated; clear that latch so this run really prunes.
    monkeypatch.setattr(ck, "_PRUNED", set())
    assert remediate(str(repo), cfg=cfg) == 0

    assert ck.load_ckpt(repo / "checkpoints", run_id, stale) is None
    # ... and every finding the report DID carry kept its row.
    from vvaharness.remediation_agent.runner import step_key_of
    for target in parse_findings(_SAMPLE_REPORT):
        assert ck.load_ckpt(repo / "checkpoints", run_id,
                            step_key_of(target, cfg)) is not None


def test_remediate_top_n_does_not_prune_the_findings_it_skipped(tmp_path, cfg, monkeypatch):
    """``--top N`` narrows what gets fixed, NOT what counts as live state.

    An unselected finding's checkpoint row is what the next run resumes from, so pruning on
    the selected subset would quietly turn incremental remediation into a full re-run."""
    from vvaharness.orchestrator import checkpoints as ck
    from vvaharness.remediation_agent.runner import step_key_of

    repo = _make_scored_scan(tmp_path)
    run_id = ck.run_id_for(repo)
    targets = parse_findings(_SCORED_REPORT)
    # Pre-seed a row for the LOWEST-scoring finding, which --top 2 will not select.
    unselected = targets[0]
    ck.save_ckpt(repo / "checkpoints", run_id, step_key_of(unselected, cfg),
                 {"finding_id": unselected.case_id})

    monkeypatch.setattr(ck, "_PRUNED", set())
    assert remediate(str(repo), ["--top", "2"], cfg=cfg) == 0

    # Survived: it is still in the report, so it is still live.
    assert ck.load_ckpt(repo / "checkpoints", run_id,
                        step_key_of(unselected, cfg)) is not None


def test_remediate_resume_skips_checkpointed(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), cfg=cfg) == 0
    capsys.readouterr()
    assert remediate(str(repo), ["--resume"], cfg=cfg) == 0
    err = capsys.readouterr().err
    assert "cached" in err
    assert "3/3 findings processed" in err


def test_apply_plugin_wires_backend_and_validates(tmp_path, cfg, monkeypatch):
    """Patch backends.llm.agentic itself to prove the runner calls the backend
    and validates its structured output into triage.json."""
    calls = {}

    def fake_agentic(user, *, model, **kw):
        calls["model"] = model
        calls["cwd"] = kw.get("cwd")
        return _canned_verdict_json()

    monkeypatch.setattr(plugin_runner, "agentic", fake_agentic)
    # Use the real _invoke (undo the autouse stub) for this one test.
    monkeypatch.undo()
    monkeypatch.setattr(plugin_runner, "agentic", fake_agentic)

    finding = parse_findings(_SAMPLE_REPORT)[0]
    # The canned verdict claims routers/jira.py; the harness records a touched file only when it
    # resolves, so the fixture has to contain it.
    (tmp_path / "routers").mkdir(parents=True, exist_ok=True)
    (tmp_path / "routers" / "jira.py").write_text("jql = 'x'\n", encoding="utf-8")
    out = tmp_path / "out"
    remediation = plugin_runner.apply_plugin(finding, out, cfg=cfg, repo=tmp_path,
                                             mode="fix")
    assert remediation.kind is RemediationKind.EDITS_APPLIED
    assert remediation.produced_by.engine == plugin_runner.ENGINE_ID
    assert calls["cwd"] == str(tmp_path)
    assert (out / "evidence" / "triage.json").is_file()
    assert (out / "finding_case.json").is_file()


def test_invoke_routes_deepagents_through_hoisted_harness(
        tmp_path, cfg, monkeypatch):
    calls = {}

    class FakeHarness:
        def run_streaming(self, prompt, options):
            calls["prompt"] = prompt
            calls["options"] = options

            async def messages():
                yield HarnessResult(
                    subtype="success",
                    structured=json.loads(_canned_verdict_json()),
                )
            return messages()

    monkeypatch.undo()
    cfg._data["models"]["remediate"] = {
        "id": "gpt-5.5", "via": "deepagents",
    }
    monkeypatch.setattr(plugin_runner, "get_harness", lambda via: FakeHarness())
    monkeypatch.setattr(
        plugin_runner, "agentic",
        lambda *args, **kwargs: pytest.fail("legacy dispatcher was called"),
    )

    finding = parse_findings(_SAMPLE_REPORT)[0]
    raw = plugin_runner._invoke(finding, cfg, tmp_path, "fix")
    options = calls["options"]
    assert raw["verdict"] == "Fixed"
    assert calls["prompt"].startswith(
        "REPOSITORY ROOT: / (DeepAgents virtual workspace root)"
    )
    assert str(tmp_path.resolve()) not in calls["prompt"]
    assert options.model == "gpt-5.5"
    assert options.cwd == tmp_path
    assert options.response_model is RemediationVerdict
    assert options.allow_writes is True
    assert options.writable_paths == (str(tmp_path.resolve()),)
    assert "Bash" in options.tool_policy.disallowed_tools
    assert options.agents["fixer"].response_model is FixerResult
    assert len(options.parent_middleware) == 1
    assert isinstance(options.parent_middleware[0], FixerDispatchGuard)


def test_virtualize_deepagents_prompt_preserves_finding_content(tmp_path):
    original = (
        f"REPOSITORY ROOT: {tmp_path}\n"
        "MODE: fix\nPRIMARY FILE: services/workflow_service.py\n"
    )
    virtual = plugin_runner._virtualize_deepagents_prompt(original)
    assert str(tmp_path) not in virtual
    assert "MODE: fix" in virtual
    assert "PRIMARY FILE: services/workflow_service.py" in virtual


def test_invoke_deepagents_report_only_is_read_only(tmp_path, cfg, monkeypatch):
    captured = {}

    class FakeHarness:
        def run_streaming(self, prompt, options):
            captured["options"] = options

            async def messages():
                yield HarnessResult(subtype="success", result_text=_canned_verdict_json())
            return messages()

    monkeypatch.undo()
    cfg._data["models"]["remediate"] = {
        "id": "gpt-5.5", "via": "deepagents",
    }
    monkeypatch.setattr(plugin_runner, "get_harness", lambda via: FakeHarness())
    finding = parse_findings(_SAMPLE_REPORT)[0]
    plugin_runner._invoke(finding, cfg, tmp_path, "report-only")
    assert captured["options"].allow_writes is False
    assert captured["options"].writable_paths == ()


def test_run_sync_bridges_an_active_event_loop():
    async def value():
        return 42

    async def caller():
        return plugin_runner._run_sync(value())

    assert asyncio.run(caller()) == 42


def test_run_sync_propagates_threaded_exception():
    error = RuntimeError("boom")

    async def fail():
        raise error

    async def caller():
        with pytest.raises(RuntimeError, match="boom") as caught:
            plugin_runner._run_sync(fail())
        assert caught.value is error

    asyncio.run(caller())


@pytest.mark.parametrize("via", ["cli", "sdk", "openai"])
def test_invoke_keeps_legacy_routes(tmp_path, cfg, monkeypatch, via):
    calls = []
    monkeypatch.undo()
    cfg._data["models"]["remediate"] = {"id": "model", "via": via}
    monkeypatch.setattr(
        plugin_runner, "agentic",
        lambda *args, **kwargs: calls.append(kwargs["model"]) or _canned_verdict_json(),
    )
    finding = parse_findings(_SAMPLE_REPORT)[0]
    plugin_runner._invoke(finding, cfg, tmp_path, "fix")
    assert len(calls) == 1
    assert calls[0].id == "model"
    assert calls[0].via == via


def test_verbose_dumps_prompt_and_response(tmp_path, cfg, monkeypatch, capsys):
    """--verbose echoes the prompt and the raw model response to stderr."""
    monkeypatch.setattr(plugin_runner, "agentic",
                        lambda user, *, model, **kw: _canned_verdict_json())
    monkeypatch.undo()
    monkeypatch.setattr(plugin_runner, "agentic",
                        lambda user, *, model, **kw: _canned_verdict_json())

    finding = parse_findings(_SAMPLE_REPORT)[0]
    plugin_runner.apply_plugin(finding, tmp_path / "out", cfg=cfg,
                               repo=tmp_path, mode="fix", verbose=True)
    err = capsys.readouterr().err
    assert "PROMPT →" in err
    assert "FINAL VERDICT ←" in err
    assert "verdict" in err  # the raw response block is present


def test_verbose_flag_announced(tmp_path, cfg, capsys):
    repo = _make_scan(tmp_path)
    assert remediate(str(repo), ["--verbose"], cfg=cfg) == 0
    assert "verbose:" in capsys.readouterr().err


def test_verbose_dumps_policy_and_playbook_when_enforced(
        tmp_path, cfg, capsys, monkeypatch):
    """With the policy gate enabled, --verbose must explicitly surface the
    per-finding policy DECISION and the resolved PLAYBOOK STRATEGY that were
    ingested for the finding (not just bury them inside the prompt dump)."""
    from vvaharness.remediation_agent import policy as _policy

    # The enforce path calls _invoke(..., pre=, ctx=); the autouse stub doesn't
    # accept those kwargs, so override it with a compatible canned seam.
    monkeypatch.setattr(
        plugin_runner, "_invoke",
        lambda finding, cfg, repo, mode, verbose=False, *, pre=None, ctx=None:
        _canned_verdict_json())


    # CWE-89 in a non-sensitive path is allow:auto with a playbook strategy.
    report = (
        "# Agentic SAST — app\n\n"
        "## Findings (1)\n\n"
        "### 1. [HIGH] SQL injection in query builder\n"
        "**Class:** CWE-89\n"
        "**File:** `app/db.py:10-10`\n\n"
        "#### Description\nblah\n")
    finding = parse_findings(report)[0]

    # Enable the policy gate and build a real context (gate + playbook).
    cfg._data.setdefault("step_remediate", {})["enforce_policy"] = True
    # The profile's policy/playbook paths are relative to the config dir; the
    # packaged profile has no inputs/ tree next to it, so clear them and let the
    # gate/playbook fall back to their shipped defaults (repo-root inputs/).
    cfg._data["step_remediate"]["policy_file"] = None
    cfg._data["step_remediate"]["playbook_file"] = None
    ctx = _policy.build_context(cfg, tmp_path)
    assert ctx.enabled

    plugin_runner.apply_plugin(finding, tmp_path / "out", cfg=cfg,
                               repo=tmp_path, mode="fix", verbose=True,
                               policy_ctx=ctx)
    err = capsys.readouterr().err
    assert "POLICY → finding 1" in err
    assert "CWE-89" in err
    assert "decision:" in err
    assert "PLAYBOOK STRATEGY → finding 1" in err


def test_verbose_states_policy_disabled_when_not_enforced(
        tmp_path, cfg, capsys):
    """When the policy gate is OFF (the default), --verbose must say so
    explicitly so the absence of POLICY/PLAYBOOK blocks is never ambiguous —
    pointing the user at the step_remediate.enforce_policy toggle."""
    finding = parse_findings(_SAMPLE_REPORT)[0]
    # No policy_ctx passed → enforcement disabled.
    plugin_runner.apply_plugin(finding, tmp_path / "out", cfg=cfg,
                               repo=tmp_path, mode="fix", verbose=True)
    err = capsys.readouterr().err
    assert "enforcement disabled" in err
    assert "enforce_policy" in err
    # ... and no policy/playbook blocks were printed.
    assert "POLICY → finding" not in err
    assert "PLAYBOOK STRATEGY" not in err


def test_stream_trace_renders_tool_calls_and_text(capsys):
    """The live-trace renderer turns stream-json events into concise lines:
    tool calls (🔧), assistant text (💬), and tool results (↩)."""
    import sys as _sys

    from vvaharness.backends.llm.cli import stream_trace

    # tool_use + text in one assistant event
    stream_trace(json.dumps({
        "type": "assistant",
        "message": {"content": [
            {"type": "text", "text": "Looking at routers/jira.py"},
            {"type": "tool_use", "name": "Read",
             "input": {"file_path": "routers/jira.py"}},
        ]},
    }), out=_sys.stderr)
    # tool_result coming back
    stream_trace(json.dumps({
        "type": "user",
        "message": {"content": [
            {"type": "tool_result", "content": [{"type": "text", "text": "x" * 50}]},
        ]},
    }), out=_sys.stderr)

    err = capsys.readouterr().err
    assert "🔧 Read(" in err
    assert "💬 Looking at routers/jira.py" in err
    assert "↩ tool result (50 chars)" in err


def test_stream_trace_ignores_junk(capsys):
    import sys as _sys

    from vvaharness.backends.llm.cli import stream_trace
    stream_trace("not json", out=_sys.stderr)
    stream_trace("", out=_sys.stderr)
    assert capsys.readouterr().err == ""


def test_mark_done_roundtrip_and_idempotent(tmp_path):
    report = tmp_path / "r.md"
    report.write_text(_SAMPLE_REPORT, encoding="utf-8")
    findings = parse_findings(_SAMPLE_REPORT)
    # mark finding 1 done
    assert mark_done(report, findings[0]) is True
    txt = report.read_text()
    assert DONE_MARKER in txt
    # re-parse: only finding 1 is done, title is clean (marker stripped)
    reparsed = parse_findings(txt)
    assert reparsed[0].done is True
    assert "remediation-agent:done" not in reparsed[0].title
    assert reparsed[1].done is False
    # idempotent: second mark is a no-op
    assert mark_done(report, findings[0]) is False
    assert report.read_text().count(DONE_MARKER) == 1


def test_parse_selection_variants():
    findings = parse_findings(_SAMPLE_REPORT)
    assert interactive.parse_selection("q", findings) is None
    assert interactive.parse_selection("", findings) is None
    assert interactive.parse_selection("all", findings) == [0, 1, 2]
    assert interactive.parse_selection("1,3", findings) == [0, 2]
    assert interactive.parse_selection("1-3", findings) == [0, 1, 2]
    assert interactive.parse_selection("2 bogus 9", findings) == [1]


def test_parse_selection_pending_excludes_done():
    findings = parse_findings(_SAMPLE_REPORT)
    findings[0].done = True
    assert interactive.parse_selection("pending", findings) == [1, 2]


def test_decode_key_tokens():
    assert interactive.decode_key("\x1b[A") == interactive.UP
    assert interactive.decode_key("\x1b[B") == interactive.DOWN
    assert interactive.decode_key("k") == interactive.UP
    assert interactive.decode_key("j") == interactive.DOWN
    assert interactive.decode_key("\r") == interactive.ENTER
    assert interactive.decode_key("q") == interactive.QUIT
    assert interactive.decode_key("\x1b") == interactive.QUIT
    assert interactive.decode_key("x") == interactive.OTHER


def test_render_rows_marks_done():
    findings = parse_findings(_SAMPLE_REPORT)
    findings[1].done = True
    rows = interactive.render_rows(findings)
    assert "✅" in rows[1]
    assert "✅" not in rows[0]


def test_interactive_fallback_select_then_quit(tmp_path, cfg, monkeypatch, capsys):
    """Non-TTY path: scripted input picks issue 1 then quits. Asserts the
    artifacts + checkpoint exist and the report header now carries the done
    marker."""
    repo = _make_scan(tmp_path)

    answers = iter(["1", "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))

    rc = remediate(str(repo), ["--interactive"], cfg=cfg)
    assert rc == 0

    rem = repo / "security-remediation"
    f1 = parse_findings(_SAMPLE_REPORT)[0]
    assert (rem / f1.slug / "evidence" / "triage.json").is_file()
    assert (rem / f1.slug / "finding_case.json").is_file()
    from vvaharness.orchestrator.checkpoints import load_ckpt, run_id_for
    from vvaharness.remediation_agent.runner import step_key_of
    run_id = run_id_for(repo)
    # Derived through the production helper, never a hand-written "remediate_1": the
    # interactive loop must key checkpoints exactly as the batch loop does, or --resume in one
    # mode cannot see work done in the other.
    parsed = parse_findings(_SAMPLE_REPORT)
    assert load_ckpt(repo / "checkpoints", run_id, step_key_of(parsed[0], cfg)) is not None
    # Only the picked finding was checkpointed; the unpicked one has no row.
    assert load_ckpt(repo / "checkpoints", run_id, step_key_of(parsed[1], cfg)) is None


    # report marked done for finding 1 only
    report = latest_report(repo / "security-scan")
    reparsed = parse_findings(report.read_text())
    assert reparsed[0].done is True
    assert reparsed[1].done is False

    err = capsys.readouterr().err
    assert "1 remediated this session" in err


def test_interactive_ignores_profile_top_n_and_shows_full_list(
        tmp_path, cfg, monkeypatch, capsys):
    """Interactive mode is a manual picker, so a profile-driven
    step_remediate.top_n_findings cap must NOT pre-truncate the list — the user
    must see (and be able to pick) EVERY finding. Here the profile caps at 1 but
    all 3 findings must be offered; selecting "all" remediates all 3."""
    repo = _make_scored_scan(tmp_path)
    _set_top_n_findings(cfg, 1)               # profile caps at 1 ...

    answers = iter(["all", "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))

    rc = remediate(str(repo), ["--interactive"], cfg=cfg)
    assert rc == 0

    err = capsys.readouterr().err
    # The cap is ignored: no narrowing message, full list identified.
    assert "selecting top" not in err
    assert "identified 3 SAST issue(s)" in err

    # ... and every finding was remediable (full list shown), all 3 picked.
    rem = repo / "security-remediation"
    findings = parse_findings(_SCORED_REPORT)
    for f in findings:
        assert (rem / f.slug / "finding_case.json").is_file()
    assert "3 remediated this session" in err


def test_interactive_still_honors_explicit_cli_top(
        tmp_path, cfg, monkeypatch, capsys):
    """An explicit ``--top N`` on the CLI is still honored in interactive mode
    (only the profile-driven cap is ignored). With --top 2, only the 2
    highest-CVSS findings are offered."""
    repo = _make_scored_scan(tmp_path)

    answers = iter(["all", "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))

    rc = remediate(str(repo), ["--interactive", "--top", "2"], cfg=cfg)
    assert rc == 0

    err = capsys.readouterr().err
    assert "selecting top 2 of 3 finding(s) by CVSS score" in err
    assert "identified 2 SAST issue(s)" in err

    rem = repo / "security-remediation"
    findings = parse_findings(_SCORED_REPORT)
    # the two highest-CVSS (9.8, 6.5) remediated; the 4.0 was never offered.
    assert (rem / findings[2].slug / "finding_case.json").is_file()
    assert (rem / findings[1].slug / "finding_case.json").is_file()
    assert not (rem / findings[0].slug).exists()


_SECRET_BODY = (
    "### 1. [HIGH] Git token embedded in subprocess argv\n"
    "**Class:** CWE-312\n"
    "**File:** `app/clone.py:10`\n\n"
    "#### Description\n"
    'url = "https://x-access-token:ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789@host/r.git"\n'
)
_SECRET = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"


def _secret_target():
    """A target whose scan body carried a real-shaped credential, as the report would.

    Parsed from markdown so the credential arrives the way it really does — quoted inside
    the finding's own description — rather than being planted on the typed object."""
    return parse_findings(_SECRET_BODY)[0]


def _contract(verdict, *, diff=""):
    """Map *verdict* onto the shared contract the way the harness does: evidence, then finalize."""
    from vvaharness.models import Provenance, finalize
    from vvaharness.remediation_agent.models import to_evidence
    evidence = to_evidence(verdict, provenance=Provenance())
    return finalize(evidence, mode="fix", diff=diff,
                    files_touched=tuple(c.file for c in evidence.changes))


def test_finding_case_json_stays_valid_with_secret_in_fields(tmp_path):
    """Regression: redaction must not corrupt the JSON case file.

    Earlier the writer redacted the already-serialised JSON string, so a secret
    pattern matching across JSON quotes/escapes mangled the escaping and the file no
    longer parsed (report augmentation logged "could not read remediation DTO"). The
    writer redacts the structure BEFORE serialising (redact_tree), so the encoder owns
    all escaping."""
    from vvaharness.remediation_agent import artifacts

    verdict = RemediationVerdict(
        finding_index=1, verdict="Fixed",
        root_cause="token in argv",
        summary="moved token to env",
    )
    out_dir = tmp_path / "01_git-token"
    artifacts.write_case(out_dir, verdict, _contract(verdict),
                         meta={"mode": "fix"}, target=_secret_target())

    path = out_dir / "finding_case.json"
    # Must parse — this is the exact failure mode the bug produced.
    case = FindingCase.read(path)
    # And the credential quoted out of the scan body must be masked, not echoed.
    assert _SECRET not in path.read_text(encoding="utf-8")
    assert case.attempts[-1].remediation.summary == "moved token to env"


def test_persisted_diffs_are_redacted_and_remain_useful_to_validation(tmp_path):
    """Persisted copies mask multiline secrets without degrading S11 evidence."""
    from vvaharness.remediation_agent import artifacts
    from vvaharness.validation.ingest.workspace import stage_workspace
    from vvaharness.validation.tools.diff_facts import parse_diff_patch

    diff = (
        "diff --git a/app/clone.py b/app/clone.py\n"
        "--- a/app/clone.py\n"
        "+++ b/app/clone.py\n"
        "@@ -1,1 +1,4 @@\n"
        f'-url = "https://x-access-token:{_SECRET}@host/r.git"\n'
        '+key = "-----BEGIN RSA PRIVATE KEY-----\n'
        "+MIIEowIBAAKCAQEArealsecretmaterial\n"
        '+-----END RSA PRIVATE KEY-----"\n'
        '+url = os.environ["GIT_URL"]\n'
    )
    verdict = RemediationVerdict(
        finding_index=1, verdict="Fixed",
        root_cause=f"the token {_SECRET} was interpolated into argv",
        summary="moved token to env",
    )
    out_dir = tmp_path / "01_git-token"
    remediation = _contract(verdict, diff=diff)
    artifacts.write_case(out_dir, verdict, remediation,
                         meta={"mode": "fix"}, target=_secret_target())

    patch = (out_dir / "evidence" / "diff.patch").read_text(encoding="utf-8")
    case_path = out_dir / "finding_case.json"
    case = FindingCase.read(case_path)
    persisted_diff = case.attempts[-1].remediation.diff
    assert remediation.diff == diff  # policy/post-gate callers retain the raw in-memory value
    assert _SECRET not in patch
    assert _SECRET not in case_path.read_text(encoding="utf-8")
    assert persisted_diff == patch
    assert "MIIEowIBAAKCAQEArealsecretmaterial" not in patch
    assert patch.count("[REDACTED-PRIVATE-KEY]") == 3
    assert len(patch.splitlines()) == len(diff.splitlines())
    assert [line[:1] for line in patch.splitlines()] == [
        line[:1] for line in diff.splitlines()
    ]
    assert patch.splitlines()[:4] == diff.splitlines()[:4]
    assert '+url = os.environ["GIT_URL"]' in patch

    # S11 consumes this persisted content as authoritative evidence while
    # reading the already-patched tree for broader code context.
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app").mkdir()
    (repo / "app" / "clone.py").write_text('url = os.environ["GIT_URL"]\n')
    workspace = tmp_path / "workspace"
    stage_workspace(repo, workspace, persisted_diff)
    changes = parse_diff_patch(workspace)
    assert (workspace / "diff.patch").read_text(encoding="utf-8") == persisted_diff
    assert [(change.path, change.added_ranges) for change in changes] == [
        ("app/clone.py", [(1, 4)])
    ]


def test_diff_redaction_preserves_crlf_metadata_hunks_and_final_newline_state():
    """Only hunk payloads change; diff grammar and physical framing stay exact."""
    from vvaharness.remediation_agent.artifacts.writer import _redact_diff

    fragment_old = "MIIEowIBAAKCAQEAlongRemovedPrivateKeyFragment"
    fragment_new = "nB4vqB7YUzE5RrT4vtQeqdQNBpVBwixPwcNyKquG"
    diff = (
        "diff --git a/app/key.pem b/app/key.pem\r\n"
        "index 1111111..2222222 100644\r\n"
        "--- a/app/key.pem\r\n"
        "+++ b/app/key.pem\r\n"
        "@@ -1,3 +1,3 @@ certificate\r\n"
        " context\r\n"
        f"-{fragment_old}\r\n"
        f"+{fragment_new}\r\n"
        " tail\r\n"
        "@@ -10 +10 @@ settings\r\n"
        '-password = "correct-horse-battery-staple"\r\n'
        '+password = os.environ["PASSWORD"]\r\n'
        "\\ No newline at end of file\r\n"
        "diff --git a/old-name b/new-name\r\n"
        "similarity index 100%\r\n"
        "rename from old-name\r\n"
        "rename to new-name\r\n"
        "diff --git a/image.bin b/image.bin\r\n"
        "index 3333333..4444444 100644\r\n"
        "Binary files a/image.bin and b/image.bin differ"
    )

    masked = _redact_diff(diff)

    assert fragment_old not in masked
    assert fragment_new not in masked
    assert "correct-horse-battery-staple" not in masked
    assert masked.endswith("Binary files a/image.bin and b/image.bin differ")
    assert not masked.endswith(("\r", "\n"))
    assert masked.count("\r\n") == diff.count("\r\n")

    structural_prefixes = (
        "diff --git ", "index ", "--- ", "+++ ", "@@ ",
        "\\ No newline", "similarity index ", "rename from ",
        "rename to ", "Binary files ",
    )
    original_structure = [
        line for line in diff.splitlines(keepends=True)
        if line.startswith(structural_prefixes)
    ]
    masked_structure = [
        line for line in masked.splitlines(keepends=True)
        if line.startswith(structural_prefixes)
    ]
    assert masked_structure == original_structure
    assert [line[:1] for line in masked.splitlines()] == [
        line[:1] for line in diff.splitlines()
    ]


def test_wrapped_and_short_pem_fragments_are_redacted_without_delimiters():
    """Source wrappers cannot hide a delimiter-free PEM payload from persistence."""
    from vvaharness.remediation_agent.artifacts.writer import _redact_diff

    fragments = (
        "MIIEowIBAAKCAQEAlongPrivateKeyFragment",
        "nB4vqB7YUzE5RrT4vtQeqdQNBpVBwixPwcNyKquG",
        "AQAB",
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC",
        "YQ==",
        "QUJD",
        "REVG",
    )
    diff = (
        "diff --git a/key.js b/key.js\n"
        "--- a/key.js\n"
        "+++ b/key.js\n"
        "@@ -1,3 +1 @@\n"
        f'-const pem = "{fragments[0]}\\n" +\n'
        f'-  "{fragments[1]}\\n" +\n'
        f'-  "{fragments[2]}\\n";\n'
        "+const pem = loadKey();\n"
        "diff --git a/key.xml b/key.xml\n"
        "--- a/key.xml\n"
        "+++ b/key.xml\n"
        "@@ -1,2 +1 @@\n"
        f'-<Tail value="{fragments[4]}"/>\n'
        f"-<PrivateKey>{fragments[3]}</PrivateKey>\n"
        "+<PrivateKey source=\"vault\"/>\n"
        "diff --git a/tail.js b/tail.js\n"
        "--- a/tail.js\n"
        "+++ b/tail.js\n"
        "@@ -1,2 +1 @@\n"
        f'-const finalChunk = "{fragments[5]}\\n";\n'
        f'-const privateKey = "{fragments[6]}";\n'
        "+const finalChunk = loadKeyTail();\n"
    )

    masked = _redact_diff(diff)

    for fragment in (*fragments[:4], fragments[6]):
        assert fragment not in masked
    assert f'-<Tail value="{fragments[4]}"/>\n' in masked
    assert f'-const finalChunk = "{fragments[5]}\\n";\n' in masked
    assert '-const pem = "[REDACTED-PRIVATE-KEY]\\n" +\n' in masked
    assert '-  "[REDACTED-PRIVATE-KEY]\\n" +\n' in masked
    assert '-  "[REDACTED-PRIVATE-KEY]\\n";\n' in masked
    assert "-<PrivateKey>[REDACTED-PRIVATE-KEY]</PrivateKey>\n" in masked
    assert '-const privateKey = "[REDACTED-PRIVATE-KEY]";\n' in masked
    assert "+const pem = loadKey();\n" in masked
    assert "+<PrivateKey source=\"vault\"/>\n" in masked
    assert "diff --git a/key.xml b/key.xml\n" in masked
    assert "@@ -1,2 +1 @@\n" in masked


def test_ordinary_escaped_newline_string_is_not_a_private_key_fragment():
    from vvaharness.remediation_agent.artifacts.writer import _redact_diff

    diff = (
        "diff --git a/message.js b/message.js\n"
        "--- a/message.js\n"
        "+++ b/message.js\n"
        "@@ -1 +1 @@\n"
        '-const message = "hello\\n";\n'
        '+const message = "goodbye\\n";\n'
    )

    assert _redact_diff(diff) == diff


def test_malformed_hunk_lines_never_restore_raw_passthrough():
    from vvaharness.remediation_agent.artifacts.writer import _redact_diff

    diff = (
        "diff --git a/settings.py b/settings.py\n"
        "--- a/settings.py\n"
        "+++ b/settings.py\n"
        "@@ -1 +1 @@\n"
        "\n"
        '?password = "malformed-secret-value"\n'
        "MIIEowIBAAKCAQEAMalformedPrivateKeyPayload\n"
        '-api_key = "later-plaintext-secret"\n'
        '+api_key = os.environ["API_KEY"]\n'
    )

    masked = _redact_diff(diff)

    assert "@@ -1 +1 @@\n\n" in masked
    assert "malformed-secret-value" not in masked
    assert "MIIEowIBAAKCAQEAMalformedPrivateKeyPayload" not in masked
    assert "later-plaintext-secret" not in masked
    assert '?password = "[REDACTED-SECRET]"\n' in masked
    assert '+api_key = os.environ["API_KEY"]\n' in masked


def test_localized_no_newline_marker_does_not_end_redaction_state():
    from vvaharness.remediation_agent.artifacts.writer import _redact_diff

    marker = "\\ Kein Zeilenumbruch am Dateiende\n"
    diff = (
        "diff --git a/settings.py b/settings.py\n"
        "--- a/settings.py\n"
        "+++ b/settings.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-first = False\n"
        "+first = True\n"
        f"{marker}"
        '-password = "later-plaintext-secret"\n'
        '+password = os.environ["PASSWORD"]\n'
    )

    masked = _redact_diff(diff)

    assert marker in masked
    assert "later-plaintext-secret" not in masked
    assert '+password = os.environ["PASSWORD"]\n' in masked


def test_hunk_header_context_is_redacted_without_changing_ranges():
    from vvaharness.remediation_agent.artifacts.writer import _redact_diff

    diff = (
        "diff --git a/settings.py b/settings.py\n"
        "--- a/settings.py\n"
        "+++ b/settings.py\n"
        '@@ -1 +1 @@ password = "header-plaintext-secret"\n'
        "-enabled = False\n"
        "+enabled = True\n"
    )

    masked = _redact_diff(diff)

    assert "header-plaintext-secret" not in masked
    assert '@@ -1 +1 @@ password = "[REDACTED-SECRET]"\n' in masked


def test_safe_config_reads_survive_generic_diff_redaction():
    from vvaharness.remediation_agent.artifacts.writer import _redact_diff

    safe_lines = (
        '+password = os.environ["P"]\n',
        '+api_key = os.getenv("API_KEY")\n',
        '+client_secret = config["CLIENT_SECRET"]\n',
        "+auth_token = process.env.AUTH_TOKEN\n",
    )
    diff = (
        "diff --git a/settings.py b/settings.py\n"
        "--- a/settings.py\n"
        "+++ b/settings.py\n"
        "@@ -1 +1,4 @@\n"
        '-password = "removed-plaintext-secret"\n'
        + "".join(safe_lines)
    )

    masked = _redact_diff(diff)

    assert "removed-plaintext-secret" not in masked
    for line in safe_lines:
        assert line in masked


@pytest.mark.parametrize(
    ("hunk", "prefix"),
    (
        (
            (
                "@@ -1,2 +1 @@\n"
                "-AQAB\n"
                "------END PRIVATE KEY-----\n"
                "+key = load_key()\n"
            ),
            "-",
        ),
        (
            (
                "@@ -1 +1,2 @@\r\n"
                "-key = old_value\r\n"
                "+AQAB\r\n"
                "+-----END PRIVATE KEY-----\r\n"
            ),
            "+",
        ),
        (
            (
                "@@ -1,3 +1,3 @@\n"
                " AQAB\n"
                " -----END PRIVATE KEY-----\n"
                "-enabled = False\n"
                "+enabled = True\n"
            ),
            " ",
        ),
        (
            (
                "@@ -1,2 +1,2 @@\n"
                "-AQAB\n"
                "+note\n"
                "------END PRIVATE KEY-----\n"
                "+key = load_key()\n"
            ),
            "-",
        ),
    ),
    ids=("old-side", "new-side", "context-line", "opposite-side-interleaving"),
)
def test_short_fragment_before_same_side_end_marker_is_redacted(hunk, prefix):
    from vvaharness.remediation_agent.artifacts.writer import _redact_diff

    ending = "\r\n" if "\r\n" in hunk else "\n"
    diff = (
        f"diff --git a/key.pem b/key.pem{ending}"
        f"--- a/key.pem{ending}"
        f"+++ b/key.pem{ending}"
        f"{hunk}"
    )
    expected = diff.replace(
        f"{prefix}AQAB{ending}",
        f"{prefix}[REDACTED-PRIVATE-KEY]{ending}",
    ).replace(
        f"{prefix}-----END PRIVATE KEY-----{ending}",
        f"{prefix}[REDACTED-PRIVATE-KEY]{ending}",
    )

    assert _redact_diff(diff) == expected


def test_unmatched_private_key_marker_is_bounded_to_its_hunk_and_file():
    """A truncated PEM block cannot consume later hunks or file metadata."""
    from vvaharness.remediation_agent.artifacts.writer import _redact_diff

    diff = (
        "diff --git a/key.pem b/key.pem\n"
        "--- a/key.pem\n"
        "+++ b/key.pem\n"
        "@@ -1 +1 @@\n"
        "------BEGIN PRIVATE KEY-----\n"
        "+replacement = load_key()\n"
        "@@ -8 +8 @@\n"
        "-old_value = 1\n"
        "+new_value = 1\n"
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -2 +2 @@\n"
        "-enabled = False\n"
        "+enabled = True\n"
    )

    masked = _redact_diff(diff)

    assert "-[REDACTED-PRIVATE-KEY]\n" in masked
    assert "+replacement = load_key()\n" in masked
    assert "@@ -8 +8 @@\n-old_value = 1\n+new_value = 1\n" in masked
    assert "diff --git a/app.py b/app.py\n" in masked
    assert "@@ -2 +2 @@\n-enabled = False\n+enabled = True\n" in masked


def test_to_evidence_is_total_over_the_verdict_literal():
    """Every ``Verdict`` member must map, in both modes, with NO_ACTION always explained.

    The Literal is prompt text and frozen, so the only way this drifts is a new member
    added without a mapping — which would raise a KeyError on a live run, not here."""
    for label in Verdict.__args__:
        for mode in ("fix", "report-only"):
            r = _finalized(label, mode)
            # A declined attempt must always say why; the contract enforces it, so
            # reaching here at all proves the mapping supplied a disposition.
            if r.kind is RemediationKind.NO_ACTION:
                assert r.disposition is not None
            else:
                assert r.disposition is None


def _finalized(label, mode):
    """The contract a prompt *label* becomes under *mode*, through the real two-step path."""
    from vvaharness.models import Provenance, finalize
    from vvaharness.remediation_agent.models import to_evidence
    evidence = to_evidence(RemediationVerdict(verdict=label, summary="s"),
                           provenance=Provenance())
    # A diff is supplied because this pins the outcome->kind mapping. Without proof of an edit
    # finalize reports already_resolved instead, which is a different property (tested separately).
    return finalize(evidence, mode=mode, diff="@@ -1 +1 @@", files_touched=("a.py",))


def _kinds(label):
    """The contract *label* maps to, in fix mode and in report-only mode."""
    return tuple(_finalized(label, mode) for mode in ("fix", "report-only"))


def test_finalize_maps_each_verdict_to_its_kind():
    """Pin the mapping itself: mode splits only the two fix verdicts."""
    for label in ("Fixed", "Partially Fixed"):
        fix, report_only = _kinds(label)
        assert fix.kind is RemediationKind.EDITS_APPLIED
        assert report_only.kind is RemediationKind.DIFF_PROPOSED

    expected = {
        "Not Fixed": Disposition.NOT_APPLICABLE,
        "Needs Review": Disposition.NOT_APPLICABLE,
        "False Positive": Disposition.FALSE_POSITIVE,
        "Denied": Disposition.POLICY_DENIED,
    }
    for label, disposition in expected.items():
        for r in _kinds(label):
            assert r.kind is RemediationKind.NO_ACTION
            assert r.disposition is disposition


def test_to_evidence_carries_gates_and_changes():
    """The three named gate fields widen into the open gate vocabulary, order preserved."""
    from vvaharness.remediation_agent.models import Gates

    verdict = RemediationVerdict(
        verdict="Fixed", summary="s",
        gates=Gates(source="pass", sink="partial", missing_control="fail"),
        changes=[{"file": "a.py", "summary": "why a"},
                 {"file": "", "summary": "dropped: no path"}],
    )
    r = _contract(verdict)
    assert [(g.name, g.status) for g in r.gates] == [
        ("source", GateStatus.PASS),
        ("sink", GateStatus.PARTIAL),
        ("missing_control", GateStatus.FAIL),
    ]
    # A change with no path is not a change: it can be neither reviewed nor reverted.
    assert [(c.file, c.summary) for c in r.changes] == [("a.py", "why a")]
    assert r.files_touched == ("a.py",)


def test_parse_finding_fields_carries_taint_refs():
    """Source/sink refs a report DOES render must reach the contract, not be nulled out."""
    from vvaharness.remediation_agent.report_parser import Finding, parse_finding_fields

    body = (
        "### 1. [HIGH] SQLi\n"
        "**Class:** CWE-89\n"
        "**File:** `app/db.py:10-10`\n"
        "**Source:** `app/api.py:4`\n"
        "**Sink:** `app/db.py:10`\n"
    )
    f = Finding(index=1, severity="HIGH", title="SQLi", file="app/db.py:10-10",
                body=body)
    fields = parse_finding_fields(f)
    assert fields["source_ref"] == "app/api.py:4"
    assert fields["sink_ref"] == "app/db.py:10"

    # A report that renders neither still yields None rather than a bogus value.
    bare = Finding(index=1, severity="HIGH", title="SQLi", file="app/db.py:10-10",
                   body="### 1. [HIGH] SQLi\n**Class:** CWE-89\n")
    assert parse_finding_fields(bare)["source_ref"] is None
    assert parse_finding_fields(bare)["sink_ref"] is None




def test_provenance_records_the_attempt_window(tmp_path, cfg):
    """started/ended bracket the engine call, and the start is the one already in meta."""
    import datetime as _dt

    repo = _make_scan(tmp_path)
    target = parse_findings(_SAMPLE_REPORT)[0]
    out = tmp_path / "out"
    rem = plugin_runner.apply_plugin(target, out, cfg=cfg, repo=repo, mode="fix")

    stamp = rem.produced_by
    assert stamp.started is not None and stamp.ended is not None
    assert stamp.ended >= stamp.started
    assert stamp.started.tzinfo is _dt.timezone.utc
    # The evidence sidecar's "generated" is that same instant, not a second clock read.
    triage = json.loads((out / "evidence" / "triage.json").read_text())
    assert triage["generated"] == stamp.started.isoformat()


def test_provenance_records_reported_spend(tmp_path, cfg, monkeypatch):
    """usd/turns come from what the backend reported for THIS attempt, not the run total."""
    from vvaharness.util.tokens import TOKENS

    def _spending(finding, cfg_, repo, mode, verbose=False, *, pre=None, ctx=None):
        TOKENS.add({"input_tokens": 100}, usd=0.12, turns=5)
        return _canned_verdict_json()

    monkeypatch.setattr(plugin_runner, "_invoke", _spending)
    repo = _make_scan(tmp_path)
    target = parse_findings(_SAMPLE_REPORT)[0]
    rem = plugin_runner.apply_plugin(target, tmp_path / "o1", cfg=cfg, repo=repo, mode="fix")
    assert (rem.produced_by.usd, rem.produced_by.turns) == (0.12, 5)

    # A second attempt reports its own spend, not the accumulated total.
    second = plugin_runner.apply_plugin(target, tmp_path / "o2", cfg=cfg, repo=repo, mode="fix")
    assert (second.produced_by.usd, second.produced_by.turns) == (0.12, 5)


def test_provenance_leaves_spend_absent_when_unreported(tmp_path, cfg):
    """The default backend has no cost channel, so the stamp must not invent one."""
    repo = _make_scan(tmp_path)
    target = parse_findings(_SAMPLE_REPORT)[0]
    rem = plugin_runner.apply_plugin(target, tmp_path / "out", cfg=cfg, repo=repo, mode="fix")
    assert rem.produced_by.usd is None
    assert rem.produced_by.turns is None
