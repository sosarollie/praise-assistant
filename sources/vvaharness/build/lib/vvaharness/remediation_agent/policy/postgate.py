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

"""Enforce path policy and workflow-reference integrity on generated edits."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff import (
    _norm_path,
    capture_git_diff,
    changed_files_whole_tree,
    synth_unified_diff,
)
from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.remediation_agent.policy.context import PolicyContext
from vvaharness.remediation_agent.policy.decide import PreResult
from vvaharness.remediation_agent.policy.revert import revert_files
from vvaharness.remediation_agent.policy.workflow_refs import (
    introduced_unsafe_workflow_refs,
)
from vvaharness.remediation_agent.policy_gate import cap_verdict, inspect_diff
from vvaharness.remediation_agent.policy_gate.matching import _glob_match
from vvaharness.remediation_agent.target import RemediationTarget

# Cap the worktree glob (non-git fallback) so a huge target can't pin the post-gate.
_WORKTREE_SCAN_MAX = 20000
# Cap directories visited too. os.walk(followlinks=False) never descends into a
# symlinked directory — closing off a symlink loop by construction — but this
# bounds a merely huge (non-cyclic) tree the same way _WORKTREE_SCAN_MAX bounds
# the file count.
_WORKTREE_DIR_MAX = 20000


def worktree_forbidden_matches(repo: Path, patterns: list[str]) -> list[str]:
    """Return repo-relative files in *repo*'s working tree that hit any of *patterns*; non-git fallback for the post-gate, best-effort and never raises."""
    if not patterns:
        return []
    repo = Path(repo)
    out: list[str] = []
    seen = 0
    dirs_seen = 0
    try:
        for dirpath, _dirnames, filenames in os.walk(repo, followlinks=False):
            dirs_seen += 1
            if dirs_seen > _WORKTREE_DIR_MAX:
                break
            for name in filenames:
                p = Path(dirpath) / name
                if not p.is_file():
                    continue
                # Count only FILES toward the budget — counting dirs too let vendored dirs (node_modules/.venv) consume the cap.
                seen += 1
                if seen > _WORKTREE_SCAN_MAX:
                    return out
                try:
                    rel = p.relative_to(repo).as_posix()
                except ValueError:
                    continue
                for pat in patterns:
                    if _glob_match(rel, pat):
                        out.append(rel)
                        break
    except Exception:  # noqa: BLE001 — a best-effort scan must never break a run
        return out
    return out



@dataclass
class PostResult:
    """Outcome of the post-gate after the agent edited files."""
    reverted: list[str]          # repo-relative files reverted on disk
    matched_globs: list[str]     # the policy globs that triggered the revert
    downgraded: bool             # True if the verdict was forced to REJECT
    final_verdict: str           # ACCEPT | REJECT
    reason: str | None = None    # deterministic post-gate rejection reason


def _gates_ok(verdict: RemediationVerdict) -> bool:
    """True iff ALL three evidence gates in the agent's own verdict read 'pass'."""
    g = getattr(verdict, "gates", None)
    if g is None:
        return False
    return (g.source == "pass" and g.sink == "pass"
            and g.missing_control == "pass")


def enforce_post(ctx: PolicyContext, target: RemediationTarget,
                 verdict: RemediationVerdict, pre: PreResult, *,
                 repo: Path,
                 before_snapshot: dict[str, str | None] | None = None,
                 all_gates_passed: bool = True) -> PostResult:
    """Validate actual on-disk changes and mutate *verdict* on rejection."""
    changed = [c.file for c in verdict.changes if c.file]

    # Observe the WHOLE working tree, not just what the agent reported, so an omitted forbidden-file edit is still caught.
    whole_tree = changed_files_whole_tree(repo)

    # Non-git fallback: walk the working tree for forbidden-glob matches, since changed_files_whole_tree returns [] off git.
    worktree_forbidden: list[str] = []
    if not whole_tree:
        worktree_forbidden = worktree_forbidden_matches(
            repo, [*ctx.gate.forbid_patch_paths, *ctx.gate.deny_paths])

    # Scope the diff to reported + whole-tree paths so omitted files still render into the synthesized (non-git) baseline.
    diff_scope = list(dict.fromkeys([*changed, *whole_tree]))
    diff = capture_git_diff(repo, diff_scope)
    if not diff and before_snapshot is not None:
        diff = synth_unified_diff(repo, before_snapshot, extra_files=diff_scope)
    diff_files = inspect_diff(diff)
    candidates = list(dict.fromkeys(
        [*diff_files, *changed, *whole_tree, *worktree_forbidden]))

    forbidden = ctx.gate.forbidden_files(candidates)
    matched: list[str] = []
    for f in forbidden:
        g = (ctx.gate.patch_touches_forbidden([f])
             or ctx.gate.changed_paths_hit_deny([f]))
        if g:
            matched.append(g)

    unsafe_refs = introduced_unsafe_workflow_refs(repo, before_snapshot)
    bad = list(dict.fromkeys([*forbidden, *unsafe_refs]))

    ceiling = pre.decision.action
    if not bad:
        # Derive the gate status from the agent's OWN verdict.gates rather than trusting the caller's default-True flag.
        # A policy allow-list is only permission to apply a patch, not evidence
        # that remediation happened.  A no-op (including an explicit Not Fixed
        # verdict) must never receive an ACCEPT audit label.
        patch_applied = bool(diff and diff.strip())
        gates_passed = (all_gates_passed and _gates_ok(verdict)
                        and patch_applied
                        and verdict.verdict in ("Fixed", "Partially Fixed"))
        return PostResult(reverted=[], matched_globs=[], downgraded=False,
                          final_verdict=cap_verdict(ceiling, gates_passed))

    reverted = revert_files(repo, bad, before_snapshot)
    bad_norm = {_norm_path(f) for f in bad}
    verdict.changes = [c for c in verdict.changes
                       if _norm_path(c.file) not in bad_norm]

    notes: list[str] = []
    if forbidden:
        notes.append(
            f"Policy post-gate reverted edits to forbidden/sensitive paths "
            f"({', '.join(sorted(set(matched)))}).")
    if unsafe_refs:
        detail = "; ".join(
            f"{path}: {', '.join(refs)}" for path, refs in unsafe_refs.items())
        notes.append(
            "Policy post-gate rejected unverified reusable-workflow refs "
            f"({detail}). S10 must use a commit already established by the "
            "repository or decline the fix; it must never invent a SHA.")
    note = (
        f"{' '.join(notes)} Reverted {len(reverted)} file(s): "
        f"{', '.join(reverted)}. Route to a human."
    )
    verdict.remaining_risks = list(verdict.remaining_risks) + [note]
    # Post-gate revert is a PARTIAL outcome, so route to a human rather than marking Denied (the pre-gate owns that terminal state).
    if unsafe_refs:
        verdict.verdict = "Not Fixed"
    elif verdict.verdict in ("Fixed", "Partially Fixed"):
        verdict.verdict = "Needs Review"
    verdict.summary = (verdict.summary + " " if verdict.summary else "") + note
    print(f"    [policy] post-gate rejected and reverted {len(reverted)} "
          f"unsafe edit(s): {', '.join(reverted)}", file=sys.stderr)
    return PostResult(reverted=reverted, matched_globs=sorted(set(matched)),
                      downgraded=True, final_verdict="REJECT",
                      reason="unsafe_workflow_reference" if unsafe_refs else None)
