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

"""Tests for the Remediation Agent policy gate + playbook + diff post-gate.

The gate is pure deterministic code (no model spend). The post-gate runs the
real diff/revert helpers against tmp git and non-git repos. All token-spending
paths are exercised via monkeypatched seams in test_remediation_agent_remediate.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from vvaharness.models import Disposition, FindingCase, RemediationKind
from vvaharness.remediation_agent import frameworks
from vvaharness.remediation_agent import policy as _policy
from vvaharness.remediation_agent.artifacts.diff import changed_files_whole_tree
from vvaharness.remediation_agent.models import Gates, RemediationVerdict
from vvaharness.remediation_agent.playbook import Playbook
from vvaharness.remediation_agent.policy_gate import (
    Action,
    RemediationGate,
    cap_verdict,
    inspect_diff,
)
from vvaharness.remediation_agent.report_parser import parse_findings

# The shipped policy allows all CWEs but protects repository-control and CI paths.
# These tests use the fully populated example when they need CWE allow/deny rules.
EXAMPLE_POLICY = str(
    Path(__file__).resolve().parent.parent / "inputs" / "remediation_policy.yaml.example")


def _reverted_paths(out_dir: Path) -> tuple[str, ...]:
    """The paths the harness rolled back, as recorded on the persisted attempt."""
    case = FindingCase.read(out_dir / "finding_case.json")
    return case.attempts[-1].reverted_paths


@pytest.fixture
def gate():
    return RemediationGate(EXAMPLE_POLICY)  # fully-populated deny/allow/path lists


def test_deny_root_cwe_is_guidance(gate):
    d = gate.decide("CWE-284", "app/x.py")
    assert d.action is Action.GUIDANCE_ONLY
    assert not d.may_generate_patch
    assert d.matched_rule == "deny:CWE-284"


def test_deny_descendant_cwe_is_guidance(gate):
    # CWE-862 is a descendant of CWE-284 in the policy file.
    d = gate.decide("CWE-862", "app/x.py")
    assert d.action is Action.GUIDANCE_ONLY
    assert "descendant_of:CWE-284" in d.reason


def test_allow_cwe_is_patch(gate):
    d = gate.decide("CWE-89", "app/db.py")
    assert d.action is Action.PATCH
    assert d.may_generate_patch


def test_allow_cwe_xss_is_patch(gate):
    d = gate.decide("CWE-79", "app/views.py")
    assert d.action is Action.PATCH


def test_deny_paths_block_allowed_cwe(gate):
    # CWE-89 is allowed, but an auth/ path is a sensitive subsystem.
    d = gate.decide("CWE-89", "src/auth/login.py")
    assert d.action is Action.GUIDANCE_ONLY
    assert d.reason.startswith("sensitive_path:")


def test_default_action_is_deny_for_unlisted_cwe(gate):
    d = gate.decide("CWE-99", "app/x.py")
    assert d.action is Action.GUIDANCE_ONLY
    assert d.reason == "default_action"


def test_unmapped_cwe_is_guidance(gate):
    assert gate.decide(None, "app/x.py").action is Action.GUIDANCE_ONLY
    assert gate.decide("not-a-cwe", "app/x.py").action is Action.GUIDANCE_ONLY


def test_kill_switch_env(gate, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_REMEDIATE_DISABLE", "1")
    d = gate.decide("CWE-89", "app/db.py")          # normally auto
    assert d.action is Action.GUIDANCE_ONLY
    assert d.reason == "kill_switch_env"


def test_kill_switch_file(tmp_path, monkeypatch):
    sentinel = tmp_path / ".off"
    sentinel.write_text("x")
    # Hand-write a tiny policy that points the kill-switch file at the sentinel.
    pol = tmp_path / "policy.yaml"
    pol.write_text(
        "schema_version: '1.0'\n"
        "default_action: deny\n"
        f"kill_switch: {{file: {sentinel}}}\n"
        "allow:\n  - {id: CWE-89}\n",
        encoding="utf-8")
    g = RemediationGate(pol)
    assert g.decide("CWE-89", "app/db.py").action is Action.GUIDANCE_ONLY


def test_fail_closed_on_bad_policy(tmp_path):
    bad = tmp_path / "missing.yaml"   # does not exist → load fails
    g = RemediationGate(bad)
    assert g.decide("CWE-89", "app/db.py").action is Action.GUIDANCE_ONLY


def test_policy_enforcement_defaults_on_when_key_is_omitted():
    class Config:
        step_remediate = object()

    assert _policy.policy_enabled(Config()) is True


def test_patch_touches_forbidden_root_setup_py(gate):
    assert gate.patch_touches_forbidden(["setup.py"]) == "**/setup.py"
    assert gate.patch_touches_forbidden(["pkg/Makefile"]) == "**/Makefile"
    assert gate.patch_touches_forbidden(["scripts/deploy.sh"]) == "**/*.sh"


def test_patch_touches_forbidden_clean(gate):
    assert gate.patch_touches_forbidden(["app/db.py", "app/views.py"]) is None


def test_shipped_policy_forbids_repository_control_paths():
    gate = RemediationGate()
    protected = [
        ".git/hooks/pre-commit",
        ".github/workflows/ci.yml",
        ".gitlab-ci.yml",
        ".circleci/config.yml",
        ".buildkite/pipeline.yml",
        "Jenkinsfile",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml",
        "cloudbuild.yaml",
        "buildspec.yml",
        ".githooks/pre-commit",
        ".husky/pre-commit",
    ]
    assert gate.forbidden_files(protected) == protected
    assert gate.patch_touches_forbidden(["src/app.py"]) is None


def test_forbidden_files_union(gate):
    bad = gate.forbidden_files(["app/db.py", "setup.py", "src/auth/x.py"])
    assert "setup.py" in bad and "src/auth/x.py" in bad
    assert "app/db.py" not in bad


def test_cap_verdict():
    assert cap_verdict(Action.PATCH, True) == "ACCEPT"
    assert cap_verdict(Action.PATCH, False) == "REJECT"
    assert cap_verdict(Action.GUIDANCE_ONLY, True) == "REJECT"


def test_inspect_diff_git_headers():
    diff = ("diff --git a/app/db.py b/app/db.py\n"
            "--- a/app/db.py\n+++ b/app/db.py\n@@ -1 +1 @@\n-x\n+y\n")
    assert inspect_diff(diff) == ["app/db.py"]


def test_inspect_diff_synth_and_new_file():
    diff = ("# (synthesized diff — target is not a git repository)\n"
            "diff --git a/new.py b/new.py\n--- /dev/null\n+++ b/new.py\n+print(1)\n")
    assert inspect_diff(diff) == ["new.py"]


def test_inspect_diff_empty():
    assert inspect_diff(None) == []
    assert inspect_diff("") == []


@pytest.fixture
def pb():
    return Playbook()


def test_playbook_resolves_python_default(pb):
    s = pb.resolve("CWE-89", "python", set())
    assert s is not None and s.name == "parameterized-query"
    assert s.confidence == "auto"
    assert "parameter" in s.instruction.lower()


def test_playbook_framework_beats_default(pb):
    s = pb.resolve("CWE-89", "python", {"django"})
    assert s.name == "orm-or-params"


def test_playbook_falls_back_to_cwe_fallback(pb):
    # An unknown language for CWE-89 → CWE-level fallback strategy.
    s = pb.resolve("CWE-89", "haskell", set())
    assert s is not None and s.name == "input-allowlist"


def test_playbook_unknown_cwe_returns_none(pb):
    assert pb.resolve("CWE-99999", "python", set()) is None


def test_playbook_guidance_for_denied(pb):
    g = pb.guidance_for("CWE-284")
    assert "Improper Access Control" in g


def test_strategy_prompt_block_is_authoritative(pb):
    block = pb.resolve("CWE-89", "python", set()).as_prompt_block()
    assert "Required fix strategy: parameterized-query" in block
    assert "do not invent an alternative approach" in block


def test_language_for():
    assert frameworks.language_for("a/b/c.py") == "python"
    assert frameworks.language_for("x.ts") == "javascript"
    assert frameworks.language_for("x.unknownext") == "default"


def _verdict(changes, *, gates=None):
    # Default to all-passing gates so the clean-path audit label is ACCEPT
    # (the post-gate derives ACCEPT/REJECT from verdict.gates; pass a failing
    # Gates() to exercise the REJECT path).
    g = gates if gates is not None else Gates(
        source="pass", sink="pass", missing_control="pass")
    return RemediationVerdict(
        finding_index=1, verdict="Fixed", gates=g,
        changes=[{"file": f, "summary": "x"} for f in changes], summary="ok")


def _git_init(repo):
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-qm", "init"],
                   check=True, capture_output=True)


_REPORT = """# Agentic SAST — app

## Findings (1)

### 1. [HIGH] SQLi in db helper
**Class:** CWE-89
**File:** `app/db.py:10-10`

#### Description
interpolated SQL
"""


def _ctx(repo):
    ctx = _policy.PolicyContext(
        gate=RemediationGate(EXAMPLE_POLICY), playbook=Playbook(),
        frameworks=set(), enabled=True)
    return ctx


def test_post_gate_reverts_forbidden_file_only(tmp_path):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("sql = f'... {x}'\n", encoding="utf-8")
    (repo / "setup.py").write_text("VERSION = '1.0'\n", encoding="utf-8")
    _git_init(repo)

    before = {"app/db.py": "sql = f'... {x}'\n", "setup.py": "VERSION = '1.0'\n"}
    # the "agent" edits BOTH an allowed file and a forbidden one
    (repo / "app" / "db.py").write_text("sql = '...'  # fixed\n", encoding="utf-8")
    (repo / "setup.py").write_text("VERSION = '9.9'  # tampered\n", encoding="utf-8")

    ctx = _ctx(repo)
    finding = parse_findings(_REPORT)[0]
    pre = _policy.pre_decision(ctx, finding)
    assert pre.allowed  # CWE-89 in app/db.py is allowed

    verdict = _verdict(["app/db.py", "setup.py"])
    post = _policy.enforce_post(ctx, finding, verdict, pre, repo=repo,
                                before_snapshot=before)

    # forbidden file reverted on disk; allowed edit kept
    assert "setup.py" in post.reverted
    assert (repo / "setup.py").read_text() == "VERSION = '1.0'\n"
    assert "# fixed" in (repo / "app" / "db.py").read_text()
    # forbidden change dropped from the verdict; verdict downgraded
    assert [c.file for c in verdict.changes] == ["app/db.py"]
    assert verdict.verdict == "Needs Review"
    assert post.final_verdict == "REJECT"
    assert post.matched_globs  # records the matched glob


def test_post_gate_noop_when_all_allowed(tmp_path):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("sql = f'... {x}'\n", encoding="utf-8")
    _git_init(repo)
    before = {"app/db.py": "sql = f'... {x}'\n"}
    (repo / "app" / "db.py").write_text("sql = '...'\n", encoding="utf-8")

    ctx = _ctx(repo)
    finding = parse_findings(_REPORT)[0]
    pre = _policy.pre_decision(ctx, finding)
    verdict = _verdict(["app/db.py"])
    post = _policy.enforce_post(ctx, finding, verdict, pre, repo=repo,
                                before_snapshot=before)
    assert post.reverted == []
    assert not post.downgraded
    assert post.final_verdict == "ACCEPT"   # patch allowed + gates passed
    assert [c.file for c in verdict.changes] == ["app/db.py"]


def test_post_gate_clean_path_rejects_when_gates_not_passed(tmp_path):
    """On the clean (nothing-reverted) path the audit label is derived from
    the agent's OWN verdict.gates — a 'fail'/'partial' gate yields REJECT, not a
    rubber-stamped ACCEPT."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("sql = f'... {x}'\n", encoding="utf-8")
    _git_init(repo)
    before = {"app/db.py": "sql = f'... {x}'\n"}
    (repo / "app" / "db.py").write_text("sql = '...'\n", encoding="utf-8")

    ctx = _ctx(repo)
    finding = parse_findings(_REPORT)[0]
    pre = _policy.pre_decision(ctx, finding)
    # gates not all 'pass' → clean path must REJECT even with no reverts.
    verdict = _verdict(["app/db.py"],
                       gates=Gates(source="pass", sink="fail", missing_control="pass"))
    post = _policy.enforce_post(ctx, finding, verdict, pre, repo=repo,
                                before_snapshot=before)
    assert post.reverted == []
    assert not post.downgraded
    assert post.final_verdict == "REJECT"   # derived from failing gate


def test_post_gate_rejects_not_fixed_attempt_without_diff(tmp_path):
    """Policy permission cannot turn an unapplied fix into ACCEPT."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("sql = f'... {x}'\n", encoding="utf-8")
    _git_init(repo)

    ctx = _ctx(repo)
    finding = parse_findings(_REPORT)[0]
    pre = _policy.pre_decision(ctx, finding)
    verdict = RemediationVerdict(
        finding_index=1, verdict="Not Fixed",
        gates=Gates(source="pass", sink="pass", missing_control="pass"),
        changes=[], summary="No safe patch could be applied.")

    post = _policy.enforce_post(
        ctx, finding, verdict, pre, repo=repo,
        before_snapshot={"app/db.py": "sql = f'... {x}'\n"})

    assert post.reverted == []
    assert post.final_verdict == "REJECT"


def test_persisted_verdict_rejects_no_diff_despite_prior_worktree_changes(
        tmp_path, monkeypatch):
    """An earlier finding's dirty patch cannot make this no-op look accepted."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config
    from vvaharness.remediation_agent import plugin_runner

    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    path = repo / "app" / "db.py"
    path.write_text("sql = unsafe\n", encoding="utf-8")
    _git_init(repo)
    # Simulate an edit left in the worktree by an earlier finding.  The current
    # attempt snapshots this state and makes no further change.
    path.write_text("sql = parameterized\n", encoding="utf-8")

    verdict = RemediationVerdict(
        finding_index=1, verdict="Not Fixed",
        gates=Gates(source="pass", sink="pass", missing_control="pass"),
        changes=[], summary="Could not apply this finding's fix.")
    monkeypatch.setattr(plugin_runner, "_invoke", lambda *a, **k: verdict)
    cfg = config_mod.load(str(_default_config()))
    cfg._data["models"]["remediate"]["via"] = "cli"

    out = tmp_path / "out"
    remediation = plugin_runner.apply_plugin(
        parse_findings(_REPORT)[0], out, cfg=cfg, repo=repo, mode="fix",
        policy_ctx=_ctx(repo))
    triage = json.loads((out / "evidence" / "triage.json").read_text())

    assert remediation.kind is RemediationKind.NO_ACTION
    assert remediation.diff == ""
    assert triage["diff_captured"] is False
    assert triage["final_verdict"] == "REJECT"
    assert triage["policy_reason"] == "no_diff_captured"
    assert triage["policy_pre_reason"] == "allow_list"


def test_post_gate_reverts_forbidden_file_omitted_from_changes(tmp_path):
    """A forbidden edit the agent made but OMITTED from verdict.changes
    must still be discovered (via the whole-tree git observation) and reverted.

    The agent reports only the allowed file; it silently also tampered with
    setup.py. The post-gate must catch and roll back setup.py regardless."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("sql = f'... {x}'\n", encoding="utf-8")
    (repo / "setup.py").write_text("VERSION = '1.0'\n", encoding="utf-8")
    _git_init(repo)

    # Snapshot only the finding's own file (this is what the runner snapshots
    # up-front from finding.file) — setup.py was NOT snapshotted, exactly as it
    # would not be when the agent edits it off-book.
    before = {"app/db.py": "sql = f'... {x}'\n"}
    (repo / "app" / "db.py").write_text("sql = '...'  # fixed\n", encoding="utf-8")
    (repo / "setup.py").write_text("VERSION = '9.9'  # tampered\n", encoding="utf-8")

    ctx = _ctx(repo)
    finding = parse_findings(_REPORT)[0]
    pre = _policy.pre_decision(ctx, finding)
    assert pre.allowed

    # The agent's self-reported changes OMIT setup.py.
    verdict = _verdict(["app/db.py"])
    post = _policy.enforce_post(ctx, finding, verdict, pre, repo=repo,
                                before_snapshot=before)

    # whole-tree observation caught the omitted forbidden edit and reverted it.
    assert "setup.py" in post.reverted
    assert (repo / "setup.py").read_text() == "VERSION = '1.0'\n"
    # the allowed edit is preserved
    assert "# fixed" in (repo / "app" / "db.py").read_text()
    assert post.final_verdict == "REJECT"
    assert post.matched_globs


# START GENAI
def test_whole_tree_lists_untracked_without_polluting_index(tmp_path):
    """changed_files_whole_tree must surface agent-created untracked files
    (the post-gate's whole-tree ground truth) WITHOUT intent-adding anything
    into the target's git index. The previous ``git add -N -- .`` intent-added
    every untracked path — harness artifacts, unrelated user files — once per
    finding."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("x = 1\n", encoding="utf-8")
    _git_init(repo)

    # Agent creates new untracked files: a real fix plus unrelated harness output.
    (repo / "app" / "new_helper.py").write_text("y = 2\n", encoding="utf-8")
    (repo / "security-scan").mkdir()
    (repo / "security-scan" / "report.json").write_text("{}\n", encoding="utf-8")

    changed = changed_files_whole_tree(repo)

    # Ground truth preserved: untracked files surface at file granularity.
    assert "app/new_helper.py" in changed
    assert "security-scan/report.json" in changed

    # Core guard: the index was NOT mutated. An intent-add (`git add -N`)
    # would make these paths appear in `git ls-files`; an untracked file does
    # not. This assertion FAILS on the old whole-tree `add -N -- .` and passes
    # once the intent-add is removed.
    tracked = subprocess.run(
        ["git", "-C", str(repo), "ls-files"],
        capture_output=True, text=True).stdout.splitlines()
    assert "app/new_helper.py" not in tracked, "untracked file was intent-added"
    assert "security-scan/report.json" not in tracked, "harness artifact intent-added"
    assert tracked == ["app/db.py"], f"index polluted: {tracked!r}"
# END GENAI


# START GENAI
def test_whole_tree_parses_rename_old_path_with_space_3rd_char(tmp_path):
    """A porcelain ``-z`` rename record carries the ORIGINAL path as a bare
    NUL token with no ``XY `` prefix. The parser must consume it verbatim — an
    original path whose 3rd char is a space (e.g. ``ab cde/x.py``) must NOT be
    mangled to ``cde/x.py``, which would slip past the forbid/deny glob and let
    the renamed-away forbidden path escape revert."""
    repo = tmp_path / "repo"
    # Directory name "ab cde" puts a space at index 2 of the old path.
    (repo / "ab cde").mkdir(parents=True)
    (repo / "ab cde" / "x.py").write_text("content\n", encoding="utf-8")
    _git_init(repo)

    # Staged rename → status emits `R  <new>\0<old>` with old as a bare token.
    subprocess.run(["git", "-C", str(repo), "mv", "ab cde/x.py", "ab cde/y.py"],
                   check=True, capture_output=True)

    changed = changed_files_whole_tree(repo)

    # Both the new path and the EXACT original path surface...
    assert "ab cde/y.py" in changed
    assert "ab cde/x.py" in changed
    # ...and the mangled (prefix-stripped) form must NOT appear.
    assert "cde/x.py" not in changed
# END GENAI


def test_worktree_forbidden_matches_scans_non_git_tree(tmp_path):
    """Unit: the non-git fallback scan finds working-tree files matching the
    gate's forbidden/sensitive globs (so the runner can snapshot them up-front
    and the post-gate can revert an agent-omitted edit)."""
    repo = tmp_path / "plain"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("x\n", encoding="utf-8")
    (repo / "Makefile").write_text("all:\n", encoding="utf-8")
    (repo / "deploy.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    hits = _policy.worktree_forbidden_matches(
        repo, ["**/Makefile", "**/*.sh"])
    assert "Makefile" in hits
    assert "deploy.sh" in hits
    assert "app/db.py" not in hits
    # empty patterns → empty result (no scan)
    assert _policy.worktree_forbidden_matches(repo, []) == []


# START GENAI
def test_worktree_forbidden_scan_counts_files_not_dirs(tmp_path, monkeypatch):
    """Directory entries from rglob must NOT consume the scan budget. A
    forbidden file nested below more directories than the budget must still be
    discovered — otherwise the dirs exhaust the cap first and the agent-omitted
    forbidden file (the exact vector this scan closes) is silently missed."""
    from vvaharness.remediation_agent.policy import postgate
    # Budget smaller than the number of directories above the file.
    monkeypatch.setattr(postgate, "_WORKTREE_SCAN_MAX", 3)

    repo = tmp_path / "plain"
    deep = repo / "a" / "b" / "c" / "d" / "e" / "f"  # 6 dirs, yielded before file
    deep.mkdir(parents=True)
    (deep / "secret.env").write_text("KEY=1\n", encoding="utf-8")

    hits = postgate.worktree_forbidden_matches(repo, ["**/*.env"])
    # Counting dirs (the old bug) breaks after 3 dir entries, missing the file.
    assert "a/b/c/d/e/f/secret.env" in hits
# END GENAI


def test_worktree_forbidden_matches_symlink_loop_terminates(tmp_path):
    """A symlink loop in the target must not hang this scan. rglob('*') has no
    cycle detection, so a directory containing a symlink back to an ancestor
    recurses effectively forever; the fix walks with os.walk(followlinks=False),
    which never descends into a symlinked directory at all."""
    from vvaharness.remediation_agent.policy import postgate
    repo = tmp_path / "plain"
    real = repo / "real"
    real.mkdir(parents=True)
    (real / "secret.env").write_text("KEY=1\n", encoding="utf-8")
    try:
        (real / "loop").symlink_to(real)  # real/loop -> real (self-cycle)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")

    hits = postgate.worktree_forbidden_matches(repo, ["**/*.env"])
    assert "real/secret.env" in hits


def test_apply_plugin_reverts_offbook_forbidden_edit_non_git(tmp_path, monkeypatch):
    """End-to-end: on a NON-git target, the runner snapshots forbidden-path
    files up-front (driven by the gate's patterns) so the post-gate can revert an
    off-book edit the agent omitted from verdict.changes — there is no git
    baseline to fall back on."""
    import json

    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config
    from vvaharness.remediation_agent import plugin_runner

    repo = tmp_path / "plain"            # NOT a git repo
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("sql = f'... {x}'\n", encoding="utf-8")
    (repo / "Makefile").write_text("all:\n\techo orig\n", encoding="utf-8")

    def fake_agentic(user, *, model, **kw):
        # fix the allowed file, tamper the forbidden one, omit it from changes
        (repo / "app" / "db.py").write_text("sql = '...'  # fixed\n", encoding="utf-8")
        (repo / "Makefile").write_text("all:\n\techo HACKED\n", encoding="utf-8")
        return json.dumps({"finding_index": 1, "verdict": "Fixed",
                           "changes": [{"file": "app/db.py", "summary": "param"}],
                           "summary": "ok"})

    monkeypatch.setattr(plugin_runner, "agentic", fake_agentic)
    cfg = config_mod.load(str(_default_config()))
    cfg._data["models"]["remediate"]["via"] = "cli"  # policy gate is backend-agnostic; stub the cli seam
    ctx = _policy.PolicyContext(gate=RemediationGate(EXAMPLE_POLICY),
                                playbook=Playbook(), frameworks=set(), enabled=True)
    finding = parse_findings(_REPORT)[0]      # CWE-89 in app/db.py → allowed

    out = tmp_path / "out"
    remediation = plugin_runner.apply_plugin(finding, out, cfg=cfg,
                                             repo=repo, mode="fix", policy_ctx=ctx)

    # off-book forbidden edit reverted from the pre-edit snapshot; allowed kept
    assert (repo / "Makefile").read_text() == "all:\n\techo orig\n"
    assert "# fixed" in (repo / "app" / "db.py").read_text()
    # The revert downgraded the engine's "Fixed" to a decline, and the rolled-back
    # path is recorded on the attempt rather than only narrated in prose.
    assert remediation.kind is RemediationKind.NO_ACTION
    assert _reverted_paths(out) == ("Makefile",)
    assert json.loads(
        (out / "evidence" / "triage.json").read_text())["final_verdict"] == "REJECT"


def test_revert_non_git_uses_snapshot(tmp_path):

    repo = tmp_path / "plain"            # NOT a git repo
    (repo).mkdir()
    (repo / "Makefile").write_text("all:\n\techo orig\n", encoding="utf-8")
    before = {"Makefile": "all:\n\techo orig\n"}
    (repo / "Makefile").write_text("all:\n\techo HACKED\n", encoding="utf-8")

    reverted = _policy.revert_files(repo, ["Makefile"], before)
    assert reverted == ["Makefile"]
    assert "orig" in (repo / "Makefile").read_text()
    assert "HACKED" not in (repo / "Makefile").read_text()


def test_revert_refuses_absolute_path_escape(tmp_path):
    """An absolute path in the (LLM-controlled) change set must NOT delete a
    file outside the repo. `repo / "/abs"` resolves to `/abs` under pathlib, so
    a snapshot keyed on an absolute path would otherwise unlink the host file."""
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("DO NOT DELETE\n", encoding="utf-8")

    abs_ref = str(outside)
    # snapshot says the file "did not exist before" → revert would unlink it.
    reverted = _policy.revert_files(repo, [abs_ref], {abs_ref: None})

    assert reverted == []                       # refused, nothing reverted
    assert outside.exists()                     # out-of-repo file untouched
    assert outside.read_text() == "DO NOT DELETE\n"


def test_revert_refuses_dotdot_traversal(tmp_path):
    """A `../` traversal must NOT overwrite/delete a file outside the repo."""
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("orig\n", encoding="utf-8")

    trav = "../outside.txt"
    # snapshot would have revert_files write "tampered" back over the file.
    reverted = _policy.revert_files(repo, [trav], {trav: "tampered\n"})

    assert reverted == []                       # refused
    assert outside.read_text() == "orig\n"      # out-of-repo file untouched


def test_revert_refuses_symlink_escape(tmp_path):
    """An in-repo symlink that points outside the tree must not be followed to
    corrupt the out-of-repo target."""
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "real_target.txt"
    outside.write_text("orig\n", encoding="utf-8")
    link = repo / "link.txt"
    link.symlink_to(outside)

    reverted = _policy.revert_files(repo, ["link.txt"], {"link.txt": "tampered\n"})

    assert reverted == []                       # refused (resolves outside repo)
    assert outside.read_text() == "orig\n"      # symlink target untouched


@pytest.mark.parametrize(
    "ref",
    [
        r"\\attacker\share\x",
        "//attacker/share/x",
        r"\\?\UNC\attacker\share\x",
        r"C:\Windows\System32\x",
        "C:/Windows/x",
        "D:relative",
    ],
)
def test_revert_reuses_shared_unc_and_drive_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ref: str,
) -> None:
    """Host-rooted Windows refs are refused before any git pathspec is built.

    ``Path.is_absolute()`` does not recognize these forms consistently across
    operating systems.  The reverter must therefore keep delegating to the diff
    subsystem's shared ``_safe_repo_path`` guard, which applies the explicit
    UNC/drive-letter pattern before its independent resolve-based containment check.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(
        "vvaharness.remediation_agent.policy.revert._is_git_worktree",
        lambda _repo: True,
    )

    def must_not_reach_git(_repo: Path, _rel: str) -> bool:
        pytest.fail(f"unsafe path reached git path handling: {ref!r}")

    monkeypatch.setattr(
        "vvaharness.remediation_agent.policy.revert._is_tracked",
        must_not_reach_git,
    )

    assert _policy.revert_files(repo, [ref]) == []


def test_resolve_input_falls_back_when_path_missing(tmp_path):
    """A configured policy/playbook path that resolves to a NON-existent file
    must fall back to the bundled default (return None) rather than handing the
    loader a bogus path — which would fail closed and deny every finding. This
    reproduces the packaged `default` profile, whose config dir is
    vvaharness/config/profiles/ so `./inputs/...` points at a dir with no input
    files."""
    import types

    cfg_dir = tmp_path / "profiles"
    cfg_dir.mkdir()
    cfg = types.SimpleNamespace(_data={"_config_dir": str(cfg_dir)})

    # ./inputs/... resolves under cfg_dir, which has no inputs/ → fall back.
    assert _policy._resolve_input(cfg, "./inputs/remediation_policy.yaml") is None

    # An existing file is returned as-is.
    real = cfg_dir / "policy.yaml"
    real.write_text("schema_version: '1.0'\ndefault_action: allow\n")
    assert _policy._resolve_input(cfg, "./policy.yaml") == str(real)


def test_build_context_with_default_profile_does_not_fail_closed(tmp_path):
    """End-to-end: building the policy context from the packaged default profile
    must load a usable (allow-all) gate, NOT a fail-closed one. Regression for
    the bug where every finding came back `policy_unavailable_fail_closed`."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config

    cfg = config_mod.load(str(_default_config()))
    ctx = _policy.build_context(cfg, tmp_path)
    # allow-all default → an arbitrary CWE is patch-eligible (not fail-closed).
    d = ctx.gate.decide("CWE-20", "app/x.py")
    assert d.action is Action.PATCH
    assert d.reason != "policy_unavailable_fail_closed"


def test_pregate_denied_cwe_skips_agent(tmp_path, monkeypatch):
    """A policy-denied CWE must short-circuit to a guidance verdict WITHOUT
    calling the model. We assert the backend seam is never invoked."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config
    from vvaharness.remediation_agent import plugin_runner

    called = {"n": 0}
    monkeypatch.setattr(plugin_runner, "agentic",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or "{}")

    cfg = config_mod.load(str(_default_config()))
    ctx = _policy.PolicyContext(gate=RemediationGate(EXAMPLE_POLICY),
                                playbook=Playbook(),
                                frameworks=set(), enabled=True)

    # CWE-284 (Improper Access Control) is on the deny-list.
    report = _REPORT.replace("CWE-89", "CWE-284")
    finding = parse_findings(report)[0]
    out = tmp_path / "out"
    remediation = plugin_runner.apply_plugin(finding, out, cfg=cfg, repo=tmp_path,
                                             mode="fix", policy_ctx=ctx)
    assert called["n"] == 0                       # agent NEVER called
    assert remediation.kind is RemediationKind.NO_ACTION
    assert remediation.disposition is Disposition.POLICY_DENIED
    # No model was contacted, so the stamp must not name one. Engine identity stays -- the
    # resume key is built from it.
    assert remediation.produced_by.model == ""
    assert remediation.produced_by.backend == ""
    assert remediation.produced_by.engine == plugin_runner.ENGINE_ID
    assert (out / "evidence" / "triage.json").is_file()
    triage = json.loads((out / "evidence" / "triage.json").read_text())
    assert triage["final_verdict"] == "REJECT"
    assert triage["policy_reason"]


def test_pregate_allowed_cwe_without_playbook_still_runs(tmp_path, monkeypatch):
    """An allowed CWE that has NO playbook entry must still run the agent on the
    main remediation prompt — the playbook is supplementary context, not a
    second gate. CWE-1333 (ReDoS) is on the example allow-list but has no
    playbook strategy."""
    import json

    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config
    from vvaharness.remediation_agent import plugin_runner

    called = {"n": 0}

    def fake_agentic(user, *, model, **kw):
        called["n"] += 1
        return json.dumps({"finding_index": 1, "verdict": "Fixed",
                           "changes": [], "summary": "ok"})

    monkeypatch.setattr(plugin_runner, "agentic", fake_agentic)
    cfg = config_mod.load(str(_default_config()))
    cfg._data["models"]["remediate"]["via"] = "cli"  # policy gate is backend-agnostic; stub the cli seam
    ctx = _policy.PolicyContext(gate=RemediationGate(EXAMPLE_POLICY),
                                playbook=Playbook(),
                                frameworks=set(), enabled=True)
    report = _REPORT.replace("CWE-89", "CWE-1333")
    finding = parse_findings(report)[0]

    # pre-gate: allowed by policy, but no playbook strategy resolved.
    pre = _policy.pre_decision(ctx, finding)
    assert pre.allowed                      # gate says PATCH
    assert pre.strategy is None             # playbook has no CWE-1333 entry

    remediation = plugin_runner.apply_plugin(finding, tmp_path / "out", cfg=cfg,
                                             repo=tmp_path, mode="fix", policy_ctx=ctx)
    assert called["n"] == 1                 # agent WAS called (not guidance)
    # The stub reports `changes: []` and the harness proves nothing changed, so the honest kind
    # is already_resolved -- claiming edits_applied here would be a claim with no evidence.
    assert remediation.kind is RemediationKind.ALREADY_RESOLVED


def test_pregate_allowed_cwe_injects_strategy(tmp_path, monkeypatch):

    """An allowed CWE runs the agent and the prompt carries the playbook
    strategy + do-not-edit globs."""
    import json

    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config
    from vvaharness.remediation_agent import plugin_runner

    seen = {}

    def fake_agentic(user, *, model, **kw):
        seen["user"] = user
        return json.dumps({"finding_index": 1, "verdict": "Fixed",
                           "changes": [], "summary": "ok"})

    monkeypatch.setattr(plugin_runner, "agentic", fake_agentic)
    cfg = config_mod.load(str(_default_config()))
    cfg._data["models"]["remediate"]["via"] = "cli"  # policy gate is backend-agnostic; stub the cli seam
    ctx = _policy.PolicyContext(gate=RemediationGate(EXAMPLE_POLICY),
                                playbook=Playbook(),
                                frameworks=set(), enabled=True)
    finding = parse_findings(_REPORT)[0]      # CWE-89 → allowed
    plugin_runner.apply_plugin(finding, tmp_path / "out", cfg=cfg,
                               repo=tmp_path, mode="fix", policy_ctx=ctx)
    assert "Required fix strategy: parameterized-query" in seen["user"]
    assert "Remediation policy (authoritative)" in seen["user"]
    assert "Do NOT edit files matching these globs" in seen["user"]  # path guards surfaced


_DENY_REPORT = """# Agentic SAST — app

## Findings (1)

### 1. [CRITICAL] Missing authorization on admin endpoint
**Class:** CWE-862
**File:** `app/admin.py:20-20`
**CVSS 3.1:** **9.1** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

#### Description
no authz check
"""


def _make_scan(tmp_path, report_text):
    repo = tmp_path / "target"
    (repo / "security-scan").mkdir(parents=True)
    (repo / "security-scan" / "app_20260618T032453Z_report.md").write_text(
        report_text, encoding="utf-8")
    return repo


def test_remediate_command_enforces_policy_when_enabled(tmp_path, monkeypatch):
    """`vvaharness remediate` (no -i) must honour enforce_policy: a deny-listed
    CWE (CWE-862) is short-circuited to guidance WITHOUT calling the agent."""
    import json

    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config
    from vvaharness.remediation_agent import plugin_runner, remediate

    called = {"n": 0}
    monkeypatch.setattr(plugin_runner, "agentic",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or "{}")

    cfg = config_mod.load(str(_default_config()))
    cfg._data.setdefault("step_remediate", {})["enforce_policy"] = True
    # Point at the fully-populated example policy (the shipped default is
    # allow-all with empty lists, so it would not deny CWE-862). The playbook
    # path is cleared so it falls back to its shipped default.
    from pathlib import Path as _Path
    cfg._data["step_remediate"]["policy_file"] = str(
        _Path(__file__).resolve().parent.parent / "inputs"
        / "remediation_policy.yaml.example")
    cfg._data["step_remediate"]["playbook_file"] = None

    repo = _make_scan(tmp_path, _DENY_REPORT)
    rc = remediate(str(repo), [], cfg=cfg)
    assert rc == 0
    assert called["n"] == 0          # deny-listed CWE → agent NEVER called

    from vvaharness.remediation_agent.report_parser import parse_findings
    slug = parse_findings(_DENY_REPORT)[0].slug
    triage = json.loads(
        (repo / "security-remediation" / slug / "evidence" / "triage.json").read_text())
    assert triage["final_verdict"] == "REJECT"
    assert "descendant_of:CWE-284" in triage["policy_reason"]


def test_fix_route_reverts_offbook_forbidden_edit_end_to_end(tmp_path, monkeypatch):
    """Pin the fix-mode policy contract end-to-end through apply_plugin.

    The fix route grants the agent edit/Bash tools, so it can write files beyond
    the finding. Here the (monkeypatched) agent fixes the allowed file AND makes
    an off-book edit to a forbidden build script (setup.py) that it OMITS from
    the reported ``changes``. The post-gate must observe the whole tree, revert
    the forbidden edit, keep the allowed one, and downgrade the verdict."""
    import json

    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config
    from vvaharness.remediation_agent import plugin_runner

    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text("sql = f'... {x}'\n", encoding="utf-8")
    (repo / "setup.py").write_text("VERSION = '1.0'\n", encoding="utf-8")
    _git_init(repo)

    def fake_agentic(user, *, model, **kw):
        # The agent edits the allowed file and ALSO tampers with the forbidden
        # build script, but only reports the allowed file in `changes`.
        (repo / "app" / "db.py").write_text("sql = '...'  # fixed\n", encoding="utf-8")
        (repo / "setup.py").write_text("VERSION = '9.9'  # tampered\n", encoding="utf-8")
        return json.dumps({"finding_index": 1, "verdict": "Fixed",
                           "changes": [{"file": "app/db.py", "summary": "param"}],
                           "summary": "ok"})

    monkeypatch.setattr(plugin_runner, "agentic", fake_agentic)
    cfg = config_mod.load(str(_default_config()))
    cfg._data["models"]["remediate"]["via"] = "cli"  # policy gate is backend-agnostic; stub the cli seam
    ctx = _policy.PolicyContext(gate=RemediationGate(EXAMPLE_POLICY),
                                playbook=Playbook(), frameworks=set(), enabled=True)
    finding = parse_findings(_REPORT)[0]      # CWE-89 in app/db.py → allowed

    out = tmp_path / "out"
    remediation = plugin_runner.apply_plugin(finding, out, cfg=cfg,
                                             repo=repo, mode="fix", policy_ctx=ctx)

    # Off-book forbidden edit was reverted; allowed edit preserved.
    assert (repo / "setup.py").read_text() == "VERSION = '1.0'\n"
    assert "# fixed" in (repo / "app" / "db.py").read_text()
    assert remediation.kind is RemediationKind.NO_ACTION
    assert _reverted_paths(out) == ("setup.py",)
    assert json.loads(
        (out / "evidence" / "triage.json").read_text())["final_verdict"] == "REJECT"


def test_remediate_command_allows_explicit_policy_opt_out(tmp_path, monkeypatch):

    """An explicit enforce_policy false keeps the trusted-target escape hatch."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config
    from vvaharness.remediation_agent import plugin_runner, remediate

    called = {"n": 0}

    def fake(user, *, model, **kw):
        called["n"] += 1
        return '{"finding_index": 1, "verdict": "Fixed", "changes": [], "summary": "ok"}'

    monkeypatch.setattr(plugin_runner, "agentic", fake)
    cfg = config_mod.load(str(_default_config()))
    cfg._data["models"]["remediate"]["via"] = "cli"  # policy gate is backend-agnostic; stub the cli seam
    cfg._data.setdefault("step_remediate", {})["enforce_policy"] = False
    repo = _make_scan(tmp_path, _DENY_REPORT)
    assert remediate(str(repo), [], cfg=cfg) == 0
    assert called["n"] == 1          # agent WAS called (policy off)
