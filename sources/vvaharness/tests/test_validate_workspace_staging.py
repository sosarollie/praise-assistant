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

"""The staged workspace must be a COPY, so a write inside it cannot reach the target repo.

``stage_workspace`` used to pass ``copy_function=os.link``, hardlinking the tree it staged. A
validator is permitted to execute the target's test suite, and an in-place write through a
hardlink lands in the operator's real source file -- the staged copy and the repo file are the
same inode. The validation path takes no snapshot and has no rollback, so that damage would be
silent and permanent. These tests are the regression guard.
"""

from __future__ import annotations

import os
from pathlib import Path

from vvaharness.validation.constants.artifacts import DIFF_FILENAME
from vvaharness.validation.ingest.workspace import stage_workspace


def _repo(tmp_path: Path) -> Path:
    """A target repo with a source file, a nested package, and dirs staging must exclude."""
    repo = tmp_path / "repo"
    (repo / "app" / "pkg").mkdir(parents=True)
    (repo / "app" / "main.py").write_text("original\n", encoding="utf-8")
    (repo / "app" / "pkg" / "util.py").write_text("util-original\n", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (repo / "security-scan").mkdir()
    (repo / "security-scan" / "report.sarif").write_text("{}", encoding="utf-8")
    return repo


def test_overwrite_in_workspace_does_not_reach_the_repo(tmp_path: Path) -> None:
    """Rewriting a staged file must leave the repo's copy untouched."""
    repo = _repo(tmp_path)
    workspace = tmp_path / "ws"

    stage_workspace(repo, workspace, "diff-body")
    (workspace / "app" / "main.py").write_text("VALIDATOR WROTE THIS\n", encoding="utf-8")

    assert (repo / "app" / "main.py").read_text(encoding="utf-8") == "original\n"


def test_append_in_workspace_does_not_reach_the_repo(tmp_path: Path) -> None:
    """An in-place append -- the mode a hardlink actually leaks through -- must not escape."""
    repo = _repo(tmp_path)
    workspace = tmp_path / "ws"

    stage_workspace(repo, workspace, "diff-body")
    with (workspace / "app" / "pkg" / "util.py").open("a", encoding="utf-8") as handle:
        handle.write("appended-by-validator\n")

    assert (repo / "app" / "pkg" / "util.py").read_text(encoding="utf-8") == "util-original\n"


def test_staged_files_are_distinct_inodes(tmp_path: Path) -> None:
    """The staged tree must not share inodes with the repo -- the hardlink guard itself."""
    repo = _repo(tmp_path)
    workspace = tmp_path / "ws"

    stage_workspace(repo, workspace, "diff-body")

    for relative in (Path("app/main.py"), Path("app/pkg/util.py")):
        source = (repo / relative).stat()
        staged = (workspace / relative).stat()
        assert (source.st_dev, source.st_ino) != (staged.st_dev, staged.st_ino), (
            f"{relative} is the same inode in the repo and the workspace; a write inside the "
            "staging area would land in the operator's source tree"
        )
        assert (repo / relative).stat().st_nlink == 1


def test_deleting_a_staged_file_leaves_the_repo_intact(tmp_path: Path) -> None:
    """A validator that removes a staged file must not remove the operator's."""
    repo = _repo(tmp_path)
    workspace = tmp_path / "ws"

    stage_workspace(repo, workspace, "diff-body")
    os.unlink(workspace / "app" / "main.py")

    assert (repo / "app" / "main.py").is_file()


def test_new_file_in_workspace_does_not_appear_in_the_repo(tmp_path: Path) -> None:
    """A build artefact or test fixture created during validation stays in the workspace."""
    repo = _repo(tmp_path)
    workspace = tmp_path / "ws"

    stage_workspace(repo, workspace, "diff-body")
    (workspace / "app" / "generated.py").write_text("x\n", encoding="utf-8")

    assert not (repo / "app" / "generated.py").exists()


def test_staging_copies_content_and_writes_the_diff(tmp_path: Path) -> None:
    """Isolation must not come at the cost of actually staging the tree."""
    repo = _repo(tmp_path)
    workspace = tmp_path / "ws"

    stage_workspace(repo, workspace, "diff-body")

    assert (workspace / "app" / "main.py").read_text(encoding="utf-8") == "original\n"
    assert (workspace / "app" / "pkg" / "util.py").read_text(encoding="utf-8") == "util-original\n"
    assert (workspace / DIFF_FILENAME).read_text(encoding="utf-8") == "diff-body"


def test_staging_excludes_git_and_scan_dirs(tmp_path: Path) -> None:
    """The ignore list still applies: no .git, no prior scan output in the staged tree."""
    repo = _repo(tmp_path)
    workspace = tmp_path / "ws"

    stage_workspace(repo, workspace, "diff-body")

    assert not (workspace / ".git").exists()
    assert not (workspace / "security-scan").exists()


def test_restaging_replaces_a_previous_workspace(tmp_path: Path) -> None:
    """Staging twice must not merge a stale tree into the new one."""
    repo = _repo(tmp_path)
    workspace = tmp_path / "ws"

    stage_workspace(repo, workspace, "first")
    (workspace / "stale.txt").write_text("stale", encoding="utf-8")
    stage_workspace(repo, workspace, "second")

    assert not (workspace / "stale.txt").exists()
    assert (workspace / DIFF_FILENAME).read_text(encoding="utf-8") == "second"
