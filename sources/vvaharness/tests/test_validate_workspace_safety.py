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

"""N28: the ephemeral workspace is never allowed to delete operator data.

``_dispatch`` refuses a ``--workspace`` that points at a non-empty existing directory,
and ``_cleanup_workspace`` removes the staging tree without swallowing real failures.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vvaharness.validation.cli import _dispatch, _is_nonempty_dir
from vvaharness.validation.cli._run import ValidationRunResult, _cleanup_workspace
from vvaharness.validation.models import RunMetadata

_CLI = "vvaharness.validation.cli"

# _dispatch reads .exit_code off the run result, so a stub must be the real NamedTuple.
_CLEAN_RUN = ValidationRunResult(exit_code=0, verdicts=(), metadata=RunMetadata())


def test_is_nonempty_dir(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    nonempty = tmp_path / "data"
    nonempty.mkdir()
    (nonempty / "f.txt").write_text("x", encoding="utf-8")

    assert _is_nonempty_dir(empty) is False
    assert _is_nonempty_dir(nonempty) is True
    assert _is_nonempty_dir(tmp_path / "missing") is False  # absent path is not a dir


def test_dispatch_refuses_nonempty_workspace(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "operator_data.txt").write_text("important", encoding="utf-8")
    called: list[object] = []

    with (
        patch(f"{_CLI}._apply_model_env", return_value=(0, {})),
        patch(f"{_CLI}.load_config", return_value=SimpleNamespace(max_findings=None)),
        patch(f"{_CLI}.run_validation", side_effect=lambda **k: called.append(k) or 0),
    ):
        rc = _dispatch(["--repo", str(repo), "--workspace", str(ws)])

    assert rc == 1
    assert called == []  # validation never ran, so the workspace was never deleted
    assert (ws / "operator_data.txt").exists()
    assert "not empty" in capsys.readouterr().err


def test_dispatch_allows_empty_workspace(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()  # exists but empty → allowed
    called: list[object] = []

    with (
        patch(f"{_CLI}._apply_model_env", return_value=(0, {})),
        patch(f"{_CLI}.load_config", return_value=SimpleNamespace(max_findings=None)),
        patch(f"{_CLI}.run_validation", side_effect=lambda **k: called.append(k) or _CLEAN_RUN),
    ):
        rc = _dispatch(["--repo", str(repo), "--workspace", str(ws)])

    assert rc == 0
    assert len(called) == 1  # proceeded into validation


def test_cleanup_workspace_removes_tree(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / "sub").mkdir(parents=True)
    (ws / "sub" / "f").write_text("x", encoding="utf-8")

    _cleanup_workspace(ws)

    assert not ws.exists()


def test_cleanup_workspace_missing_is_noop(tmp_path: Path) -> None:
    # An already-absent tree is clean; the helper must not raise.
    _cleanup_workspace(tmp_path / "never_existed")
