# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Regression coverage for unsafe S10 reusable-workflow pinning."""
from __future__ import annotations

import json

from vvaharness import config as config_mod
from vvaharness.models import RemediationKind
from vvaharness.orchestrator import _default_config
from vvaharness.remediation_agent import plugin_runner
from vvaharness.remediation_agent.models import Change, Gates, RemediationVerdict
from vvaharness.remediation_agent.playbook import Playbook
from vvaharness.remediation_agent.policy import PolicyContext
from vvaharness.remediation_agent.policy.workflow_refs import (
    introduced_unsafe_workflow_refs,
    workflow_snapshot_paths,
)
from vvaharness.remediation_agent.policy_gate import RemediationGate
from vvaharness.remediation_agent.report_parser import parse_findings

_WORKFLOW = ".github/workflows/cicd_pipeline.yaml"
_CALLEE = "visa/reusable/.github/workflows/security.yml"
_REALISTIC_SHA = "0123456789abcdef0123456789abcdef01234567"
_ZERO_SHA = "0" * 40
_REPORT = f"""# Agentic SAST — app

## Findings (1)

### 1. [HIGH] Mutable reusable workflow reference
**Class:** CWE-829
**File:** `{_WORKFLOW}:12-12`

#### Description
The privileged workflow delegates to {_CALLEE}@develop with secrets inherited.
"""


def _workflow(ref: str, *, name: str = "CI") -> str:
    return f"""name: {name}
jobs:
  security:
    uses: {_CALLEE}@{ref}
    secrets: inherit
"""


def _write(repo, path: str, content: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def test_all_zero_workflow_pin_is_unsafe(tmp_path):
    before = {_WORKFLOW: _workflow("develop")}
    _write(tmp_path, _WORKFLOW, _workflow(_ZERO_SHA))

    issues = introduced_unsafe_workflow_refs(tmp_path, before)

    assert list(issues) == [_WORKFLOW]
    assert _ZERO_SHA in issues[_WORKFLOW][0]
    assert "placeholder commit SHA" in issues[_WORKFLOW][0]


def test_unverified_nonzero_sha_is_unsafe(tmp_path):
    before = {_WORKFLOW: _workflow("develop")}
    _write(tmp_path, _WORKFLOW, _workflow(_REALISTIC_SHA))

    issues = introduced_unsafe_workflow_refs(tmp_path, before)

    assert "not established by the pre-edit repository" in issues[_WORKFLOW][0]


def test_repository_established_sha_is_allowed(tmp_path):
    lock_workflow = ".github/workflows/locked.yaml"
    before = {
        _WORKFLOW: _workflow("develop"),
        lock_workflow: _workflow(_REALISTIC_SHA, name="Known good pin"),
    }
    _write(tmp_path, _WORKFLOW, _workflow(_REALISTIC_SHA))
    _write(tmp_path, lock_workflow, before[lock_workflow])

    assert introduced_unsafe_workflow_refs(tmp_path, before) == {}


def test_unchanged_mutable_ref_does_not_block_unrelated_edit(tmp_path):
    before = {_WORKFLOW: _workflow("develop")}
    _write(tmp_path, _WORKFLOW, _workflow("develop", name="Renamed CI"))

    assert introduced_unsafe_workflow_refs(tmp_path, before) == {}


def test_workflow_files_are_included_in_pre_edit_snapshot_scope(tmp_path):
    _write(tmp_path, _WORKFLOW, _workflow("develop"))
    _write(tmp_path, ".github/workflows/secondary.yml", _workflow("main"))
    _write(tmp_path, ".github/not-a-workflow.yml", "name: ignored\n")

    assert workflow_snapshot_paths(tmp_path) == [
        _WORKFLOW,
        ".github/workflows/secondary.yml",
    ]


def test_apply_plugin_reverts_placeholder_and_records_not_fixed(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    original = _workflow("develop")
    _write(repo, _WORKFLOW, original)
    target = parse_findings(_REPORT)[0]

    verdict = RemediationVerdict(
        finding_index=1,
        verdict="Fixed",
        gates=Gates(source="pass", sink="pass", missing_control="pass"),
        changes=[Change(file=_WORKFLOW, summary="Pinned reusable workflow.")],
        summary="Pinned the reusable workflow to an immutable commit.",
    )

    def fake_invoke(*args, **kwargs):
        _write(repo, _WORKFLOW, _workflow(_ZERO_SHA))
        return verdict

    monkeypatch.setattr(plugin_runner, "_invoke", fake_invoke)
    cfg = config_mod.load(str(_default_config()))
    ctx = PolicyContext(
        gate=RemediationGate(), playbook=Playbook(), frameworks=set(), enabled=True)
    out = tmp_path / "out"

    remediation = plugin_runner.apply_plugin(
        target, out, cfg=cfg, repo=repo, mode="fix", policy_ctx=ctx)
    triage = json.loads((out / "evidence" / "triage.json").read_text())

    assert (repo / _WORKFLOW).read_text(encoding="utf-8") == original
    assert remediation.kind is RemediationKind.NO_ACTION
    assert remediation.diff == ""
    assert remediation.files_touched == ()
    assert triage["verdict"] == "Not Fixed"
    assert triage["final_verdict"] == "REJECT"
    assert triage["policy_reason"] == "unsafe_workflow_reference"
    assert triage["policy_pre_reason"] == "default_action"
    assert _WORKFLOW in triage["policy_reverted"]
