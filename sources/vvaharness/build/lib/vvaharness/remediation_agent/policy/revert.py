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

"""remediation_agent.policy.revert — roll back forbidden-path edits on disk.

The post-gate reverts the files a patch touched that hit
``forbid_patch_paths``/``deny_paths``. References are LLM/plugin-controlled, so
:func:`revert_files` confines every target to the repo (CWE-22) and restores
from the pre-edit snapshot or git, best-effort and never raising."""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff import _norm_path, _safe_repo_path

log = logging.getLogger(__name__)


def _is_git_worktree(repo: Path) -> bool:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=15)
        return r.returncode == 0 and r.stdout.strip() == "true"
    except Exception:                                  # noqa: BLE001
        return False


def _is_tracked(repo: Path, rel: str) -> bool:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "--error-unmatch", "--", rel],
            capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:                                  # noqa: BLE001
        return False


def revert_files(repo: Path, files: list[str],
                 before_snapshot: dict[str, str | None] | None = None) -> list[str]:
    """Roll back *files* (repo-relative) to their pre-edit state. Best-effort and
    never raises.

    Preference order per file:
      1. Pre-edit snapshot (exact baseline the runner captured): restore the
         original contents, or delete the file if it did not exist before.
      2. git: ``git checkout -- <file>`` for a tracked file; delete an untracked
         (newly-created) file.
      3. Otherwise leave the file as-is (we have no baseline to restore)."""
    repo = Path(repo)
    snap = before_snapshot or {}
    is_git = _is_git_worktree(repo)
    reverted: list[str] = []
    for raw in files or []:
        rel = _norm_path(raw)
        if not rel:
            continue
        # Fail closed on path traversal / absolute / symlink escapes (CWE-22):
        # `rel` is LLM/plugin-controlled, so an absolute path, a `../` traversal,
        # or an in-repo symlink resolving outside the tree must NEVER reach
        # unlink/write_text/git below — that would corrupt host or CI-workspace
        # files under harness privileges. Shared with the diff artifacts' own
        # confinement check (mirrors `artifacts.diff.paths._safe_repo_path`).
        if _safe_repo_path(repo, raw) is None:
            log.warning("refusing to revert out-of-repo path %r (escapes %s)",
                        raw, repo)
            continue
        p = repo / rel
        try:
            if rel in snap:
                old = snap[rel]
                if old is None:
                    if p.exists():
                        p.unlink()
                else:
                    p.write_text(old, encoding="utf-8")
                reverted.append(rel)
                continue
            if is_git:
                if _is_tracked(repo, rel):
                    subprocess.run(
                        ["git", "-C", str(repo), "checkout", "--", rel],
                        capture_output=True, text=True, timeout=30)
                elif p.exists():
                    # untracked (agent-created) → remove
                    p.unlink()
                reverted.append(rel)
        except Exception as e:                         # noqa: BLE001
            log.warning("failed to revert %s: %s", rel, e)
    return reverted
