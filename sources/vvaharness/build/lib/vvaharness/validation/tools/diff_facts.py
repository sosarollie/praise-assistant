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

"""Deterministic, read-only diff fact tools for validation subagents."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vvaharness.validation.constants.diff import (
    ADDED_LINE,
    DEV_NULL_PATH,
    DIFF_PATCH_FILENAME,
    GIT_HEADER_MIN_TOKENS,
    GIT_HEADER_PREFIX,
    GIT_PATH_PREFIXES,
    HUNK_HEADER_RE,
    HUNK_NEW_START_GROUP,
    MARKER_PATH_START,
    NEW_FILE_MARKER,
    NO_NEWLINE_NOTE,
    OLD_FILE_MARKER,
    REMOVED_LINE,
    TRUST_BOUNDARY_RE,
)


def _without_git_prefix(path: str) -> str:
    return path[2:] if path[:2] in GIT_PATH_PREFIXES else path


def _marker_path(marker_line: str) -> str:
    return marker_line[MARKER_PATH_START:].split("\t")[0]


@dataclass
class FileChange:
    """One file's added line ranges, as parsed out of a unified diff."""

    path: str
    added_ranges: list[tuple[int, int]] = field(default_factory=list)


class _DiffParser:
    """Feed unified-diff lines in order, then call ``finish()`` for per-file changes."""

    def __init__(self) -> None:
        self.changes: list[FileChange] = []
        self.current_path: str | None = None
        self.old_path: str | None = None
        self.added_ranges: list[tuple[int, int]] = []
        self.new_line_number = 0
        self.added_run_start: int | None = None
        self.added_run_length = 0

    def _close_added_run(self) -> None:
        if self.added_run_start is not None and self.added_run_length:
            self.added_ranges.append((self.added_run_start, self.added_run_length))
        self.added_run_start, self.added_run_length = None, 0

    def _close_file(self) -> None:
        self._close_added_run()
        if self.current_path is not None:
            self.changes.append(FileChange(self.current_path, self.added_ranges))
        self.current_path, self.old_path, self.added_ranges = None, None, []

    def _consume_hunk_line(self, line: str) -> None:
        prefix = line[:1]
        if prefix == ADDED_LINE:
            if self.added_run_start is None:
                self.added_run_start = self.new_line_number
            self.added_run_length += 1
            self.new_line_number += 1
        elif prefix == REMOVED_LINE:
            self._close_added_run()
        elif prefix == NO_NEWLINE_NOTE:
            return
        else:
            self._close_added_run()
            self.new_line_number += 1

    def feed(self, line: str) -> None:
        if line.startswith(GIT_HEADER_PREFIX):
            self._close_file()
            tokens = line.split(" ")
            # Keep the new-side path as a rename/binary fallback.
            if len(tokens) >= GIT_HEADER_MIN_TOKENS:
                self.current_path = _without_git_prefix(tokens[-1])
        elif line.startswith(OLD_FILE_MARKER):
            self._close_added_run()
            self.old_path = _without_git_prefix(_marker_path(line))
        elif line.startswith(NEW_FILE_MARKER):
            self._close_added_run()
            new_path = _without_git_prefix(_marker_path(line))
            # "+++ /dev/null" is a deletion; keep the real old path so it stays tracked.
            self.current_path = self.old_path if new_path == DEV_NULL_PATH else new_path
            self.new_line_number = 0
        elif hunk := HUNK_HEADER_RE.match(line):
            self._close_added_run()
            self.new_line_number = int(hunk.group(HUNK_NEW_START_GROUP))
        elif self.new_line_number:
            self._consume_hunk_line(line)

    def finish(self) -> list[FileChange]:
        self._close_file()
        return self.changes


def parse_diff_patch(workspace: Path) -> list[FileChange]:
    """Parse ``diff.patch`` into per-file changes (added line ranges + deletion flag)."""
    diff_file = workspace / DIFF_PATCH_FILENAME
    if not diff_file.exists():
        return []
    parser = _DiffParser()
    for line in diff_file.read_text().splitlines():
        parser.feed(line)
    return parser.finish()


def diff_touched(workspace: Path, file_path: str) -> dict:
    """Return whether *file_path* is in ``diff.patch`` and which lines were added."""
    for change in parse_diff_patch(workspace):
        if change.path == file_path:
            return {"touched": True, "added_ranges": change.added_ranges}
    return {"touched": False, "added_ranges": []}


def changed_lines(workspace: Path, file_path: str) -> list[tuple[int, int]]:
    """Return added line ranges for *file_path* from ``diff.patch``."""
    return diff_touched(workspace, file_path)["added_ranges"]


@dataclass
class DiffImpactMap:
    """Which files a diff changed, and whether any of them is a trust boundary."""

    files_changed: list[str]
    trust_boundary_touched: bool


def build_diff_impact_map(workspace: Path) -> DiffImpactMap:
    """List changed files and whether any is a trust-boundary path (auth/session/crypto/...)."""
    files = [change.path for change in parse_diff_patch(workspace)]
    return DiffImpactMap(
        files_changed=sorted(set(files)),
        trust_boundary_touched=any(TRUST_BOUNDARY_RE.search(path) for path in files),
    )
