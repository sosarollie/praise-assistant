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

"""CWE-22: the remediation-applied marker must constrain touched-file paths under the
repo root. A crafted ``files_touched`` entry using ``..`` or an absolute path resolves
to a host file that exists — it must NOT satisfy the marker."""
from __future__ import annotations

from pathlib import Path

import pytest

from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.ingest.workspace import (
    _resolve_touched,
    assert_remediation_applied,
)


def test_in_repo_file_resolves(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("x = 1\n")
    assert _resolve_touched(tmp_path, "app/db.py") is not None
    # app/ prefix fallback also works
    assert _resolve_touched(tmp_path, "db.py") is not None


@pytest.mark.parametrize("touched", [
    "../secret.txt",
    "../../etc/hostname",
    "app/../../secret.txt",
    "/etc/passwd",
    "/etc/hostname",
])
def test_traversal_and_absolute_paths_rejected(tmp_path: Path, touched: str) -> None:
    # Plant a real file outside the repo that the traversal would resolve to.
    outside = tmp_path.parent / "secret.txt"
    outside.write_text("top secret\n")
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    assert _resolve_touched(repo, touched) is None


def test_symlink_escape_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "outside.txt").write_text("secret\n")
    (repo / "link.txt").symlink_to(tmp_path / "outside.txt")  # in-repo symlink → out of repo
    assert _resolve_touched(repo, "link.txt") is None


def test_assert_remediation_applied_rejects_traversal_only(tmp_path: Path) -> None:
    (tmp_path.parent / "secret.txt").write_text("x\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    # The ONLY "touched" file is an out-of-repo traversal → must fail closed.
    with pytest.raises(IngestError):
        assert_remediation_applied(repo, ["../secret.txt"])
