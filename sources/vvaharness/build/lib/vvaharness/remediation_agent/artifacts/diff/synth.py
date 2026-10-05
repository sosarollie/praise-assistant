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

"""remediation_agent.artifacts.diff.synth — synthesized unified diff for non-git targets.

Builds a git-style unified diff with stdlib :mod:`difflib` from a pre-edit
snapshot of the files (captured by :func:`snapshot_files`) so a patch can always
be produced even when the target is not under version control."""
from __future__ import annotations

import difflib
import logging
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff.paths import (
    _norm_path,
    _safe_repo_path,
)

log = logging.getLogger(__name__)


# Marker placed at the top of a synthesized (non-git) patch so reviewers can
# tell it is not a true VCS diff.
SYNTH_HEADER = "# (synthesized diff — target is not a git repository)\n"


def synth_unified_diff(repo: Path, before: dict[str, str | None],
                       extra_files: list[str] | None = None) -> str | None:
    """Synthesize a git-style unified diff for a **non-git** target.

    Compares the pre-edit *before* snapshot (path → contents, ``None`` = the
    file did not exist) against the current on-disk contents, scoped to the
    union of the snapshot's paths and *extra_files* (e.g. files the agent
    reported editing that were not snapshotted up-front — these have no baseline
    and render as newly-added files).

    Returns the concatenated unified diff (prefixed with :data:`SYNTH_HEADER`),
    or ``None`` when nothing changed. Best-effort and never raises."""
    repo = Path(repo)
    before = before or {}
    # Map each kept repo-relative path to a repo-confined absolute path. Refs
    # from *extra_files* are LLM/plugin-controlled (``verdict.changes[].file``),
    # so an absolute/`../`/symlink-escape ref must NOT be read into the diff
    # (CWE-22). Confine every ref and drop escapes (mirrors snapshot_files).
    paths: list[str] = []
    safe: dict[str, Path] = {}
    for ref in list(before.keys()) + list(extra_files or []):
        rel = _norm_path(ref)
        if not rel or rel in safe:
            continue
        p = _safe_repo_path(repo, ref)
        if p is None:
            log.warning("synth diff: refusing out-of-repo file reference %r "
                        "(escapes %s)", ref, repo)
            continue
        safe[rel] = p
        paths.append(rel)
    if not paths:
        return None

    chunks: list[str] = []
    for rel in paths:
        old = before.get(rel)
        old_text = "" if old is None else old
        p = safe[rel]
        try:
            new_text = p.read_text(encoding="utf-8") if p.is_file() else ""
        except Exception:  # noqa: BLE001 — binary/unreadable → skip this file
            continue

        if old_text == new_text:
            continue
        from_label = "/dev/null" if old is None else f"a/{rel}"
        to_label = f"b/{rel}" if new_text != "" else "/dev/null"
        diff = difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=from_label, tofile=to_label)
        body = "".join(diff)
        if not body:
            continue
        # difflib omits a trailing newline on the last hunk line when the source
        # lacked one; normalise so concatenated chunks stay line-delimited.
        if not body.endswith("\n"):
            body += "\n"
        chunks.append(f"diff --git a/{rel} b/{rel}\n{body}")

    if not chunks:
        return None
    return SYNTH_HEADER + "".join(chunks)
