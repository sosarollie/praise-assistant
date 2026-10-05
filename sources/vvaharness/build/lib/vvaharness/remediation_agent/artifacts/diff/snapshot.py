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

"""Captures a finding's file contents before the agent edits them, for later diff synthesis and post-gate restoration."""
from __future__ import annotations

import logging
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff.paths import (
    _norm_path,
    _safe_repo_path,
)

log = logging.getLogger(__name__)


def changed_since_snapshot(repo: Path, before: dict[str, str | None] | None) -> list[str]:
    """Repo-relative paths whose contents differ from the pre-edit *before* snapshot; the non-git counterpart to :func:`changed_files_whole_tree`."""
    repo = Path(repo)
    changed: list[str] = []
    for rel, old in (before or {}).items():
        p = _safe_repo_path(repo, rel)
        if p is None:
            continue
        try:
            now = p.read_text(encoding="utf-8") if p.is_file() else None
        except Exception:  # noqa: BLE001 — binary/unreadable → treat as absent, as snapshot does
            now = None
        if now != old:
            changed.append(rel)
    return changed


def snapshot_files(repo: Path, files: list[str]) -> dict[str, str | None]:
    """Capture the current contents of *files* (repo-relative) under *repo*, mapping a not-yet-existing path to ``None``."""
    repo = Path(repo)
    snap: dict[str, str | None] = {}
    for f in files or []:
        rel = _norm_path(f)
        if not rel or rel in snap:
            continue
        # Fail closed on an out-of-repo reference so it can't leak host/CI files into the diff artifact (CWE-22).
        p = _safe_repo_path(repo, f)
        if p is None:
            log.warning("snapshot: refusing out-of-repo file reference %r "
                        "(escapes %s)", f, repo)
            continue
        try:
            snap[rel] = p.read_text(encoding="utf-8") if p.is_file() else None
        except Exception:  # noqa: BLE001 — binary/unreadable → treat as absent
            snap[rel] = None
    return snap
