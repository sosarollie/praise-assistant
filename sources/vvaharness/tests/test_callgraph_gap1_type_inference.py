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


from pathlib import Path

import pytest

from vvaharness.pipeline.stages.callgraph_engine._rules import MatchSpec
from vvaharness.pipeline.stages.callgraph_engine._scan import (
    _match_call,
    get_parser,
    scan_file,
)


def _java_sink_spec() -> MatchSpec:
    return MatchSpec(
        rule_id="java.sql.exec",
        role="sink",
        origin="codeql",
        cwe="CWE-89",
        kind="sql",
        languages=frozenset({"java"}),
        package="java.sql",
        class_name="Statement",
        top_class="Statement",
        methods=frozenset({"executeQuery"}),
    )


def test_match_call_accepts_class_tail_resolution_for_java():
    spec = _java_sink_spec()
    # Simulate variable resolution where receiver type is narrowed to concrete
    # class tail only (or a non-package-qualified symbol).
    imports = {"stmt": "com.acme.Statement"}

    hit = _match_call("stmt", "executeQuery", imports, [spec], "java")
    assert hit is not None
    assert hit.rule_id == "java.sql.exec"


def test_scan_file_java_narrows_iface_to_concrete_initializer(tmp_path):
    if get_parser is None:
        pytest.skip("tree-sitter backend unavailable in this environment")

    java_src = """
        package demo;
        import java.sql.Statement;

        interface BaseStmt { String executeQuery(String q); }
        class ImplStmt implements BaseStmt {
            public String executeQuery(String q) { return q; }
        }

        class Demo {
            void run() {
                BaseStmt stmt = new ImplStmt();
                stmt.executeQuery("SELECT 1");
            }
        }
    """
    f = tmp_path / "Demo.java"
    f.write_text(java_src, encoding="utf-8")

    spec = MatchSpec(
        rule_id="demo.impl.exec",
        role="sink",
        origin="codeql",
        cwe="CWE-89",
        kind="sql",
        languages=frozenset({"java"}),
        package="demo",
        class_name="ImplStmt",
        top_class="ImplStmt",
        methods=frozenset({"executeQuery"}),
    )

    idx = scan_file(
        abs_path=Path(f),
        rel="Demo.java",
        language="java",
        source_specs=[],
        sink_specs=[spec],
    )

    assert idx is not None
    assert any(cs.method == "executeQuery" for cs in idx.sink_hits)
