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

"""remediation_agent.artifacts.diff.paths — repo-relative path normalisation + confinement.

The path helpers shared by the snapshot / synthesized-diff / git-diff modules.
Both ``_safe_repo_path`` and ``_norm_path`` defend the diff artifacts against
path traversal (CWE-22): finding/verdict file references are LLM/plugin-
controlled, so they are normalised and confined to the repo before any read."""
from __future__ import annotations

import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

# UNC (``\\host\share``, ``//host/share``) and Windows drive-letter (``C:\``,
# ``C:/``, ``C:rel``) prefixes are host-rooted regardless of the OS we parse the
# string on. ``Path.is_absolute()`` only recognises them when running ON Windows,
# so on a POSIX runner a Windows-style ``\\attacker\share`` ref would slip past
# the absolute check and reach a git pathspec — and on a Windows runner that git
# call opens an outbound SMB connection that leaks the runner's NetNTLMv2 hash.
# Reject them explicitly and host-independently.
_UNC_OR_DRIVE = re.compile(r"^(?:[\\/]{2}|[A-Za-z]:)")


def _norm_path(ref: str) -> str:
    """Normalise a finding/verdict file reference to a clean repo-relative path.

    Strips any ``:line`` / ``:start-end`` location suffix (e.g.
    ``routers/jira.py:174-174`` → ``routers/jira.py``) and trims whitespace."""
    ref = (ref or "").strip()
    if not ref:
        return ""
    # Only strip a trailing ``:<digits>`` or ``:<digits>-<digits>`` suffix;
    # leave Windows drive-letter colons and the rest of the path intact.
    return re.sub(r":\d+(?:-\d+)?$", "", ref)


def _safe_repo_path(repo: Path, ref: str) -> Path | None:
    """Resolve a finding/verdict file reference to a regular file confined to
    *repo*, or ``None`` when the reference escapes the repository.

    The references handled here originate from the scan ``Finding`` and from the
    LLM/plugin-controlled ``verdict.changes[].file`` / ``files_touched``. An
    absolute path, a ``../`` traversal, or an in-repo symlink resolving outside
    the tree would otherwise let :func:`snapshot_files` / :func:`synth_unified_diff`
    READ arbitrary host or CI-workspace files and copy their contents into the
    remediation diff artifacts (CWE-22). Resolving both sides and requiring
    containment fails closed on every such escape; :func:`revert_files` in
    ``remediation_agent.policy.revert`` reuses this helper for the same check
    before reverting a file on disk."""
    rel = _norm_path(ref)
    if not rel or Path(rel).is_absolute() or _UNC_OR_DRIVE.match(rel):
        return None
    try:
        target = (repo / rel).resolve()
        target.relative_to(repo.resolve())
    except (ValueError, OSError):
        return None
    return target
