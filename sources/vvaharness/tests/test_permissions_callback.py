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

"""The SDK CanUseTool adapter (`_permissions_callback`) faithfully maps a
PermissionsPolicy decision onto the SDK result types (PermissionResultAllow /
PermissionResultDeny), preserving the deny `message` and `interrupt` flag. The
`context` arg is ignored (ARG001) and must not be required."""
from __future__ import annotations

import asyncio
from pathlib import Path

from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny

from vvaharness.backends.harness import PermissionsPolicy
from vvaharness.backends.harness.claude.options import _permissions_callback


def _decide(policy: PermissionsPolicy, tool: str, inp: dict):
    """Drive the async gate synchronously and return the SDK result."""
    return asyncio.run(_permissions_callback(policy)(tool, inp, None))  # type: ignore[arg-type]


def test_allowed_tool_returns_allow_with_unchanged_input(tmp_path: Path) -> None:
    policy = PermissionsPolicy(target_dir=tmp_path)
    result = _decide(policy, "Read", {"file_path": "x.py"})
    assert isinstance(result, PermissionResultAllow)
    assert result.updated_input == {"file_path": "x.py"}


def test_edit_returns_deny_with_interrupt_and_message(tmp_path: Path) -> None:
    policy = PermissionsPolicy(target_dir=tmp_path)
    result = _decide(policy, "Edit", {"file_path": "x.py"})
    assert isinstance(result, PermissionResultDeny)
    assert result.interrupt is True          # Edit is a hard deny → interrupt the session
    assert result.message                    # non-empty reason carried through


def test_write_outside_target_denied(tmp_path: Path) -> None:
    policy = PermissionsPolicy(target_dir=tmp_path)
    result = _decide(policy, "Write", {"file_path": "/etc/passwd"})
    assert isinstance(result, PermissionResultDeny)


def test_context_argument_is_ignored(tmp_path: Path) -> None:
    # ToolPermissionContext is ARG001-suppressed; passing None must not raise.
    policy = PermissionsPolicy(target_dir=tmp_path)
    result = _decide(policy, "Grep", {})
    assert isinstance(result, PermissionResultAllow)
