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

"""remediation_agent.artifacts.diff.gitcapture — real ``git diff`` capture.

The git work-tree strategies: a scoped ``git diff`` for a set of files
(:func:`capture_git_diff`) and the unscoped whole-tree changed-file set
(:func:`changed_files_whole_tree`) the policy post-gate needs as ground truth."""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff.paths import _safe_repo_path

log = logging.getLogger(__name__)


def changed_files_whole_tree(repo: Path) -> list[str]:
    """Return EVERY changed path in *repo*'s working tree (repo-relative).

    Unlike :func:`capture_git_diff`, this is NOT scoped to a caller-supplied file
    list: it asks git for the full set of modified/added/deleted/untracked paths
    via ``git status --porcelain --untracked-files=all``, which lists every
    untracked (agent-created) file individually WITHOUT mutating the index. This
    is the ground truth the policy post-gate needs so that a forbidden edit the
    agent made but OMITTED from ``verdict.changes`` is still discovered and
    reverted. Returns ``[]`` for a non-git target / when git is
    unavailable / on any error (the caller falls back to the snapshot).
    Never raises.

    NOTE: this used to run ``git add -N -- .`` first to make untracked files
    visible, but that intent-added EVERY untracked path (harness artifacts,
    unrelated user files) into the target's index once per finding.
    ``--untracked-files=all`` surfaces the same per-file set as plain ``??``
    records with zero index side effects, so the scan is read-only."""
    repo = Path(repo)
    try:
        chk = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=15)
        if chk.returncode != 0 or chk.stdout.strip() != "true":
            return []
        # List the full changed set — untracked files included at file
        # granularity (--untracked-files=all) — without touching the index.
        out = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain", "-z",
             "--untracked-files=all"],
            capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            return []
    except Exception:  # noqa: BLE001 — never break a run
        return []

    files: list[str] = []
    seen: set[str] = set()

    def _add(path: str) -> None:
        if path and path not in seen:
            seen.add(path)
            files.append(path)

    # Parse porcelain v1 `-z` STRUCTURALLY. Each status record is `XY <path>`
    # (2 status chars + a space + the exact, unquoted path — strip the 3-char
    # prefix). A rename/copy record (X or Y is 'R'/'C') is followed by a SECOND,
    # bare NUL token holding the ORIGINAL path with NO `XY ` prefix: it must be
    # consumed verbatim. Applying the 3-char strip to that bare token mangles an
    # original path whose 3rd char is a space (e.g. "ab cde/x.py" -> "cde/x.py"),
    # which would then slip past the forbid/deny glob and escape revert.
    records = out.stdout.split("\0")
    i, n = 0, len(records)
    while i < n:
        rec = records[i]
        i += 1
        if not rec:
            continue
        _add(rec[3:] if len(rec) > 3 else "")
        # Rename/copy: the next token is the bare original path — verbatim.
        if ("R" in rec[:2] or "C" in rec[:2]) and i < n:
            _add(records[i])
            i += 1
    return files


def capture_git_diff(repo: Path, files: list[str]) -> str | None:
    """Return a unified ``git diff`` for *files* (repo-relative) in *repo*, or

    None when no diff can be produced (not a git repo / git missing / no
    changes). Uses ``git add -N`` (intent-to-add) first so newly-created files
    appear in the diff, then diffs the working tree against HEAD scoped to just
    those paths so each finding's patch is isolated to its own files.

    Best-effort and side-effect-light: ``add -N`` only records intent (no
    staging of content) and never commits. Never raises."""
    repo = Path(repo)
    # Confine every caller-supplied ref to the repo BEFORE it reaches a git
    # pathspec. verdict.changes[].file (and the whole-tree union) is
    # LLM/plugin-controlled; an absolute or UNC ref (e.g. \\attacker\share\x)
    # handed to `git add -N`/`git diff` on a Windows runner opens an outbound
    # SMB connection that leaks the runner's NetNTLMv2 hash.
    # _safe_repo_path rejects absolute / UNC / drive-letter / ../ escapes; keep
    # the survivors repo-relative for the pathspec.
    root = repo.resolve()
    paths: list[str] = []
    for f in (files or []):
        safe = _safe_repo_path(repo, f)
        if safe is not None:
            paths.append(safe.relative_to(root).as_posix())
    if not paths:
        return None
    env = {**os.environ, "LC_ALL": "C"}
    git = ["git", "-C", str(repo), "-c", "color.ui=false"]
    try:
        # Is this a git work tree at all?
        chk = subprocess.run(
            [*git, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=15, env=env)
        if chk.returncode != 0 or chk.stdout.strip() != "true":
            return None
        # Record intent-to-add so untracked (newly-created) files show in diff.
        subprocess.run([*git, "add", "-N", "--", *paths],
                       capture_output=True, text=True, timeout=30, env=env)
        out = subprocess.run(
            [*git, "diff", "--no-ext-diff", "--", *paths],
            capture_output=True, text=True, timeout=60, env=env)
        diff = out.stdout
        return diff if diff.strip() else None
    except Exception:  # noqa: BLE001 — diff capture must never break a run
        return None
