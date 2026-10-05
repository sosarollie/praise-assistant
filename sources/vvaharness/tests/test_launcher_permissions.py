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

"""The deny-by-default permission gate is ALWAYS wired into a validation session.

`build_validation_options` must unconditionally attach a PermissionsPolicy bound to the
staged workspace, and `build_streaming_sdk_options` must turn that into the SDK
`can_use_tool` callback. A regression that dropped `permissions` would silently run the
agent ungated against an untrusted repo, so this invariant is locked down here."""
from __future__ import annotations

from pathlib import Path

from vvaharness.backends.harness import PermissionsPolicy
from vvaharness.backends.harness.claude.options import build_streaming_sdk_options
from vvaharness.validation.config import load_config
from vvaharness.validation.models import Manifest
from vvaharness.validation.session.launcher import build_validation_options


def _options(workspace: Path):
    return build_validation_options(
        config=load_config(),
        manifest=Manifest(jira_key="TEST-1", session_id="s1"),
        workspace=workspace,
        output_dir=workspace / "out",
        system_prompt=None,
    )


def test_build_validation_options_always_sets_permissions(tmp_path: Path) -> None:
    options = _options(tmp_path)
    assert isinstance(options.permissions, PermissionsPolicy)
    # The gate confines writes/reads to the staged workspace, not some other dir.
    assert options.permissions.target_dir == tmp_path


def test_permissions_become_the_sdk_can_use_tool_gate(tmp_path: Path) -> None:
    sdk_opts = build_streaming_sdk_options(_options(tmp_path))
    assert sdk_opts.can_use_tool is not None
