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

"""Deterministic pattern scanner for validation subagents."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from vvaharness.validation.constants.pattern_sets import (
    BUILTIN_RULE,
    DEFAULT_PATTERN_SETS,
    NUL_BYTE,
    SKIP_IN_SCAN,
)
from vvaharness.validation.tools._scope import iter_in_scope_files

_MAX_FILE_BYTES = 512 * 1024
_MAX_TOTAL_BYTES = 32 * 1024 * 1024
_MAX_FILES = 10_000
_MAX_MATCHES_PER_FILE = 50
_MAX_MATCHES = 200

@dataclass(frozen=True)
class _ReadResult:
    data: bytes = b""
    unreadable: bool = False
    too_large: bool = False
    binary: bool = False
    has_more: bool = False


@dataclass(frozen=True)
class _ScanPattern:
    name: str
    description: str
    regex: re.Pattern[str]


@dataclass
class _ScanState:
    matches: list[dict] = field(default_factory=list)
    matches_seen: int = 0
    files_considered: int = 0
    files_scanned: int = 0
    files_too_large: int = 0
    files_unreadable: int = 0
    binary_files: int = 0
    bytes_scanned: int = 0
    file_count_truncated: bool = False
    byte_limit_truncated: bool = False
    per_file_truncated: bool = False
    overall_truncated: bool = False


def _read_bounded(path: Path, max_bytes: int) -> _ReadResult:
    try:
        with path.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            raw_bytes = handle.read(max_bytes)
    except OSError:
        return _ReadResult(unreadable=True)
    observed_size = max(size, len(raw_bytes))
    return _ReadResult(
        data=raw_bytes,
        too_large=observed_size > _MAX_FILE_BYTES,
        binary=NUL_BYTE in raw_bytes,
        has_more=observed_size > max_bytes,
    )


def _scan_text(
    state: _ScanState,
    *,
    text: str,
    relative_path: str,
    pattern: _ScanPattern,
) -> None:
    file_matches = 0
    for match in pattern.regex.finditer(text):
        state.matches_seen += 1
        file_matches += 1
        if file_matches > _MAX_MATCHES_PER_FILE:
            state.per_file_truncated = True
            continue
        if len(state.matches) >= _MAX_MATCHES:
            state.overall_truncated = True
            continue
        state.matches.append({
            "kind": "match",
            "file": relative_path,
            "line": text.count("\n", 0, match.start()) + 1,
            "pattern_set": pattern.name,
            "rule": BUILTIN_RULE,
            "description": pattern.description,
        })


def _result(state: _ScanState, pattern_set: str) -> list[dict]:
    state.matches.sort(key=lambda match: (match["file"], match["line"]))
    reasons = [
        reason
        for limited, reason in (
            (state.files_too_large, "file_size_limit"),
            (state.files_unreadable, "unreadable_files"),
            (state.binary_files, "binary_files"),
            (state.file_count_truncated, "overall_file_limit"),
            (state.byte_limit_truncated, "overall_byte_limit"),
            (state.per_file_truncated, "per_file_match_limit"),
            (state.overall_truncated, "overall_match_limit"),
        )
        if limited
    ]
    state.matches.append({
        "kind": "summary",
        "pattern_set": pattern_set,
        "matches_seen": state.matches_seen,
        "matches_returned": len(state.matches),
        "files_considered": state.files_considered,
        "files_scanned": state.files_scanned,
        "files_too_large": state.files_too_large,
        "files_unreadable": state.files_unreadable,
        "binary_files": state.binary_files,
        "bytes_scanned": state.bytes_scanned,
        "truncated": bool(reasons),
        "truncation_reasons": reasons,
        "limits": {
            "max_file_bytes": _MAX_FILE_BYTES,
            "max_total_bytes": _MAX_TOTAL_BYTES,
            "max_files": _MAX_FILES,
            "max_matches_per_file": _MAX_MATCHES_PER_FILE,
            "max_matches": _MAX_MATCHES,
        },
    })
    return state.matches


def _consume_file(
    state: _ScanState, file_path: Path, workspace: Path, pattern: _ScanPattern
) -> None:
    state.files_considered += 1
    remaining_bytes = _MAX_TOTAL_BYTES - state.bytes_scanned
    read_limit = min(_MAX_FILE_BYTES, remaining_bytes)
    result = _read_bounded(file_path, read_limit)
    state.bytes_scanned += len(result.data)
    state.files_unreadable += int(result.unreadable)
    state.files_too_large += int(result.too_large)
    state.binary_files += int(result.binary)
    budget_exhausted = read_limit == remaining_bytes and result.has_more
    state.byte_limit_truncated |= budget_exhausted
    if not (result.unreadable or result.too_large or result.binary
            or budget_exhausted):
        state.files_scanned += 1
        _scan_text(
            state,
            text=result.data.decode("utf-8", errors="replace"),
            relative_path=str(file_path.relative_to(workspace)),
            pattern=pattern,
        )


def _scan_workspace(
    state: _ScanState, workspace: Path, pattern: _ScanPattern
) -> None:
    for file_path in iter_in_scope_files(workspace, include_tests=False):
        if file_path.name in SKIP_IN_SCAN:
            continue
        if state.files_considered >= _MAX_FILES:
            state.file_count_truncated = True
            break
        _consume_file(state, file_path, workspace, pattern)
        if state.byte_limit_truncated:
            break


def pattern_scan(workspace: Path, pattern_set: str) -> list[dict]:
    """Return bounded, secret-free match metadata followed by one scan summary.

    Builtin sets: ``secret_exposure``, ``insecure_value``. An unknown set raises
    ValueError so the caller gets a signal rather than a clean-looking empty list.
    Candidate text is deliberately omitted because tool results can enter transcripts.
    """
    if pattern_set not in DEFAULT_PATTERN_SETS:
        raise ValueError(
            f"unknown pattern_set {pattern_set!r}; available: {sorted(DEFAULT_PATTERN_SETS)}"
        )

    description, regex = DEFAULT_PATTERN_SETS[pattern_set]
    pattern = _ScanPattern(pattern_set, description, regex)
    state = _ScanState()
    _scan_workspace(state, workspace, pattern)
    return _result(state, pattern_set)
