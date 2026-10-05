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

"""EV adaptive-loop extra tools — sandboxed code tools + call-graph attack path."""
from __future__ import annotations

import json
from types import SimpleNamespace

from vvaharness.exploit_verification.verify.tools import build_loop_tools


def _finding():
    return SimpleNamespace(file="app.py", line_start=5, title="t",
                           code_snippet="db.query(user_input)", sink_ref="app.py:5")


def _ctx():
    return SimpleNamespace(entry_points=[], call_graph={}, call_graph_files={}, unsafe_sinks=[])


def test_code_tools_read_from_repo(tmp_path):
    (tmp_path / "a.txt").write_text("hello world", encoding="utf-8")
    schemas, dispatch = build_loop_tools(str(tmp_path), None, _finding())
    assert {"Read", "Glob", "Grep"} <= {s["name"] for s in schemas}
    out = dispatch("Read", {"path": "a.txt"})
    assert "hello world" in out


def test_attack_path_tool_with_ctx():
    schemas, dispatch = build_loop_tools(None, _ctx(), _finding())
    assert "attack_path" in {s["name"] for s in schemas}
    d = json.loads(dispatch("attack_path", {}))
    assert d["sink"] == "app.py:5" and "db.query" in d["sink_code"]


def test_no_capabilities_no_tools():
    schemas, dispatch = build_loop_tools(None, None, _finding())
    assert schemas == []
    assert dispatch("Read", {"path": "x"}) is None      # unknown → None (caller falls through)
    assert dispatch("http_request", {}) is None
