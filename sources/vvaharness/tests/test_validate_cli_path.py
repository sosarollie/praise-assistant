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

"""Validation backend pins the claude executable (CWE-426/427).

VVAHARNESS_CLAUDE_BINARY was previously read into config and then DROPPED — the
SDK resolved a bare 'claude' against PATH. These tests lock in that (a) the
configured binary is resolved to an absolute path and (b) it reaches the SDK as
ClaudeAgentOptions.cli_path, so the override is actually effective."""
from pathlib import Path

from vvaharness.backends.harness import OneShotOptions, StreamingOptions
from vvaharness.backends.harness.claude.options import (
    build_oneshot_sdk_options,
    build_streaming_sdk_options,
)
from vvaharness.validation.session import launcher


def test_resolve_binary_explicit_existing_path(tmp_path):
    p = tmp_path / "claude"
    p.write_text("#!/bin/sh\n", encoding="utf-8")
    assert launcher._resolve_binary(str(p)) == str(p)


def test_resolve_binary_bare_name_resolved_to_abs(monkeypatch):
    monkeypatch.setattr(launcher.shutil, "which", lambda n: "/opt/bin/claude")
    assert launcher._resolve_binary("claude") == "/opt/bin/claude"


def test_resolve_binary_unresolvable_passthrough(monkeypatch):
    monkeypatch.setattr(launcher.shutil, "which", lambda n: None)
    # SDK resolves as before — never break a working setup.
    assert launcher._resolve_binary("claude-nope") == "claude-nope"


def test_oneshot_options_sets_cli_path():
    o = OneShotOptions(model="m", cwd=Path("."), cli_path="/abs/claude")
    opts = build_oneshot_sdk_options(o)
    assert opts.cli_path == "/abs/claude"


def test_oneshot_options_cli_path_defaults_none():
    o = OneShotOptions(model="m", cwd=Path("."))
    opts = build_oneshot_sdk_options(o)
    assert opts.cli_path is None      # untouched -> SDK default resolution


def test_streaming_options_sets_cli_path():
    o = StreamingOptions(model="m", cwd=Path("."), cli_path="/abs/claude")
    opts = build_streaming_sdk_options(o)
    assert opts.cli_path == "/abs/claude"
