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

"""Fail-closed validation for S10 edits to reusable GitHub workflow refs."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff import _norm_path, _safe_repo_path

_WORKFLOW_PREFIX = ".github/workflows/"
_FULL_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_USES = re.compile(
    r"(?im)^\s*(?:-\s*)?uses\s*:\s*['\"]?"
    r"(?P<workflow>[^@\s'\"#]+/\.github/workflows/[^@\s'\"#]+\.ya?ml)"
    r"@(?P<ref>[^\s'\"#]+)"
)


def workflow_snapshot_paths(repo: Path) -> list[str]:
    """Return existing workflow files that must be snapshotted before S10."""
    root = Path(repo) / _WORKFLOW_PREFIX
    if not root.is_dir():
        return []
    try:
        return sorted(
            p.relative_to(repo).as_posix()
            for pattern in ("*.yml", "*.yaml")
            for p in root.glob(pattern)
            if p.is_file()
        )
    except OSError:
        return []


def introduced_unsafe_workflow_refs(
    repo: Path, before: Mapping[str, str | None] | None
) -> dict[str, list[str]]:
    """Find unsafe reusable-workflow refs introduced by the current attempt.

    A new remote reusable-workflow reference is accepted only when it uses a
    non-placeholder 40-hex commit already established for that exact workflow
    elsewhere in the pre-edit repository snapshot. S10 has no network resolver,
    so an otherwise plausible new hash is not evidence that the commit exists;
    it must decline instead of guessing.

    Pre-existing unsafe refs are ignored: this guard prevents S10 from making a
    bad edit, but does not reinterpret unrelated edits as having introduced the
    repository's existing debt.
    """
    snapshot = before or {}
    trusted: dict[str, set[str]] = defaultdict(set)
    prior: dict[str, Counter[tuple[str, str]]] = {}
    for raw_path, text in snapshot.items():
        path = _norm_path(raw_path)
        if not _is_workflow_path(path) or text is None:
            continue
        refs = _references(text)
        prior[path] = Counter(refs)
        for workflow, ref in refs:
            if _is_nonplaceholder_sha(ref):
                trusted[workflow.casefold()].add(ref.casefold())

    current_paths = set(workflow_snapshot_paths(repo))
    current_paths.update(path for path in snapshot if _is_workflow_path(path))
    issues: dict[str, list[str]] = {}
    for path in sorted(current_paths):
        target = _safe_repo_path(Path(repo), path)
        if target is None:
            continue
        try:
            current = target.read_text(encoding="utf-8") if target.is_file() else ""
        except OSError:
            continue
        previous = prior.get(path, Counter())
        seen: Counter[tuple[str, str]] = Counter()
        for workflow, ref in _references(current):
            key = (workflow, ref)
            seen[key] += 1
            if seen[key] <= previous[key]:
                continue
            reason = _unsafe_reason(workflow, ref, trusted)
            if reason:
                issues.setdefault(path, []).append(
                    f"{workflow}@{ref} ({reason})")
    return issues


def _references(text: str) -> list[tuple[str, str]]:
    return [
        (match.group("workflow"), match.group("ref"))
        for match in _USES.finditer(text)
    ]


def _is_workflow_path(path: str) -> bool:
    folded = path.casefold()
    return folded.startswith(_WORKFLOW_PREFIX) and folded.endswith((".yml", ".yaml"))


def _is_nonplaceholder_sha(ref: str) -> bool:
    return bool(_FULL_SHA.fullmatch(ref)) and len(set(ref.casefold())) > 1


def _unsafe_reason(
    workflow: str, ref: str, trusted: dict[str, set[str]]
) -> str:
    if not _FULL_SHA.fullmatch(ref):
        return "not an immutable 40-character commit SHA"
    if not _is_nonplaceholder_sha(ref):
        return "placeholder commit SHA"
    if ref.casefold() not in trusted.get(workflow.casefold(), set()):
        return "commit SHA is not established by the pre-edit repository"
    return ""


__all__ = ["introduced_unsafe_workflow_refs", "workflow_snapshot_paths"]
