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

"""Regression guard: validate CLI rejects UNC/network paths before any filesystem probe.

A Windows UNC path supplied via --workspace or --repo would, the moment the loader
calls is_dir()/iterdir(), open an SMB connection and leak the user's NTLMv2 hash to
the host. The guard fires before _is_nonempty_dir() touches the path. These tests are
OS-independent: rejection is pure string classification via PureWindowsPath."""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vvaharness.validation.cli import _dispatch
from vvaharness.validation.cli._run import ValidationRunResult
from vvaharness.validation.models import RunMetadata

# _dispatch reads .exit_code off the run result, so a stub must be the real NamedTuple.
_CLEAN_RUN = ValidationRunResult(exit_code=0, verdicts=(), metadata=RunMetadata())


def test_unc_workspace_rejected_before_dir_probe(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    # --workspace \\evil\share must be rejected with rc=1 before _is_nonempty_dir() fires.
    with (
        patch("vvaharness.validation.cli._apply_model_env", return_value=(0, {})),
        patch("vvaharness.validation.cli.load_config", return_value=MagicMock()),
        patch("vvaharness.validation.cli._is_nonempty_dir",
              side_effect=AssertionError("guard must fire before dir probe")),
    ):
        rc = _dispatch(["--repo", str(tmp_path), "--workspace", r"\\evil\share", "--all"])
    assert rc == 1
    assert "network/UNC" in capsys.readouterr().err


def test_unc_repo_rejected(capsys: pytest.CaptureFixture) -> None:
    # --repo \\evil\share (no --workspace) must be rejected because workspace_root
    # would be derived from it, reaching _is_nonempty_dir() with a UNC path.
    with (
        patch("vvaharness.validation.cli._apply_model_env", return_value=(0, {})),
        patch("vvaharness.validation.cli.load_config", return_value=MagicMock()),
        patch("vvaharness.validation.cli._is_nonempty_dir",
              side_effect=AssertionError("guard must fire before dir probe")),
    ):
        rc = _dispatch(["--repo", r"\\evil\share", "--all"])
    assert rc == 1
    assert "network/UNC" in capsys.readouterr().err


def test_slash_slash_unc_rejected(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    # Forward-slash UNC form (//evil/share) is equally rejected.
    with (
        patch("vvaharness.validation.cli._apply_model_env", return_value=(0, {})),
        patch("vvaharness.validation.cli.load_config", return_value=MagicMock()),
        patch("vvaharness.validation.cli._is_nonempty_dir",
              side_effect=AssertionError("guard must fire before dir probe")),
    ):
        rc = _dispatch(["--repo", str(tmp_path), "--workspace", "//evil/share", "--all"])
    assert rc == 1
    assert "network/UNC" in capsys.readouterr().err


def test_local_workspace_passes_guard(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    # A normal local path must pass the guard without triggering a UNC rejection.
    with (
        patch("vvaharness.validation.cli._apply_model_env", return_value=(0, {})),
        patch("vvaharness.validation.cli.load_config", return_value=MagicMock()),
        patch("vvaharness.validation.cli.run_validation", return_value=_CLEAN_RUN),
    ):
        rc = _dispatch(["--repo", str(tmp_path), "--all"])
    assert rc == 0
    assert "network/UNC" not in capsys.readouterr().err
