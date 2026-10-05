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

"""Shared in-scope file iteration for validation fact tools.

Applies the production ``s1_preprocess`` exclusions and refuses symlinks whose target
escapes the workspace (host-file-disclosure guard); one walk feeds scanner and inventory.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from vvaharness.pipeline.stages.s1_preprocess import (
    _DEFAULT_EXCLUDE_DIRS,
    _DEFAULT_EXCLUDE_EXTS,
    _DEFAULT_EXCLUDE_GLOBS,
    glob_hit,
)

# The production exclude set mixes infra/vendor dirs with test dirs; partition since tests differ.
_TEST_DIRS: frozenset[str] = frozenset({
    "test", "tests", "__tests__", "__test__", "e2e", "testdata",
    "fixtures", "__fixtures__", "mocks", "__mocks__", "stubs",
})
_PRODUCTION_EXCLUDE_DIRS: frozenset[str] = frozenset(d.lower() for d in _DEFAULT_EXCLUDE_DIRS)
_INFRA_DIRS: frozenset[str] = _PRODUCTION_EXCLUDE_DIRS - _TEST_DIRS
_EXCLUDE_EXTS: frozenset[str] = frozenset(e.lower() for e in _DEFAULT_EXCLUDE_EXTS)

# _TEST_DIRS must stay a subset of production; raises (asserts strip under -O) not silently.
if not _TEST_DIRS <= _PRODUCTION_EXCLUDE_DIRS:
    raise RuntimeError(
        "validation _TEST_DIRS drifted from s1_preprocess._DEFAULT_EXCLUDE_DIRS: "
        f"{sorted(_TEST_DIRS - _PRODUCTION_EXCLUDE_DIRS)} missing from the production set"
    )


def _has_excluded_ext(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(ext) for ext in _EXCLUDE_EXTS)


def _excluded_file(rel_path: Path, *, include_tests: bool) -> bool:
    if _has_excluded_ext(rel_path.name):
        return True
    return not include_tests and bool(
        glob_hit(rel_path.as_posix(), _DEFAULT_EXCLUDE_GLOBS)
    )


def _escapes_workspace(path: Path, root: Path) -> bool:
    """True when *path* is a symlink whose target resolves outside *root*."""
    if not path.is_symlink():  # only symlinks can escape; skip resolve() for the common case
        return False
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return True
    return False


def iter_in_scope_files(workspace: Path, *, include_tests: bool) -> Iterator[Path]:
    """Yield workspace files within the production scan scope.

    Always skips infra/vendor dirs, binary/media extensions, and symlinks that
    escape *workspace*. When tests are excluded, the authoritative S1 test-file
    and repository-metadata globs are applied as well as its test directories.
    """
    root = workspace.resolve()
    excluded_dirs = _INFRA_DIRS if include_tests else (_INFRA_DIRS | _TEST_DIRS)
    for current, dir_names, file_names in os.walk(workspace, followlinks=False):
        dir_names[:] = sorted(
            name for name in dir_names if name.lower() not in excluded_dirs
        )
        current_path = Path(current)
        for name in sorted(file_names):
            path = current_path / name
            rel_path = path.relative_to(workspace)
            if (
                _excluded_file(rel_path, include_tests=include_tests)
                or _escapes_workspace(path, root)
                or not path.is_file()
            ):
                continue
            yield path
