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

"""Deterministic test-inventory fact tool for validation subagents."""

from __future__ import annotations

import re
from pathlib import Path

from vvaharness.validation.constants.test_inventory import (
    JS_TEST_SUFFIXES,
    NEGATIVE_TEST_MARKERS,
    PY_TEST_EXACT_NAMES,
    PY_TEST_NAME_PREFIX,
    PY_TEST_NAME_SUFFIX,
)
from vvaharness.validation.tools._scope import iter_in_scope_files

_MARKER_PATTERNS = tuple(
    (marker, re.compile(rf"(?<!\w){re.escape(marker)}(?!\w)", re.IGNORECASE))
    for marker in NEGATIVE_TEST_MARKERS
)


def _is_test_file(name: str) -> bool:
    if name in PY_TEST_EXACT_NAMES:
        return True
    if name.endswith(".py") and (
        name.startswith(PY_TEST_NAME_PREFIX) or name.endswith(PY_TEST_NAME_SUFFIX)
    ):
        return True
    return any(name.endswith(suffix) for suffix in JS_TEST_SUFFIXES)


def _negative_markers(text: str) -> list[str]:
    return sorted({marker for marker, pattern in _MARKER_PATTERNS if pattern.search(text)})


def test_inventory(workspace: Path) -> dict:
    """Inventory test files and flag negative/adversarial test markers."""
    test_files: list[dict] = []
    for file_path in iter_in_scope_files(workspace, include_tests=True):
        if not _is_test_file(file_path.name):
            continue
        try:
            text = file_path.read_text(errors="replace")
        except OSError:
            continue
        markers = _negative_markers(text)
        test_files.append(
            {
                "file": str(file_path.relative_to(workspace)),
                "lines": len(text.splitlines()),
                "negative_test_markers": markers,
                "has_negative_tests": bool(markers),
            }
        )
    test_files.sort(key=lambda item: item["file"])
    return {
        "test_files": test_files,
        "total_test_files": len(test_files),
        "files_with_negative_tests": sum(1 for item in test_files if item["has_negative_tests"]),
    }
