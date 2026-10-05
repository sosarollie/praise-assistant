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

from vvaharness.pipeline.stages.callgraph_engine._scan import get_parser, scan_file


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_scan_file_python_collects_nested_arg_identifiers(tmp_path):
    src = (
        "def sink(a, b, c):\n"
        "    return a\n"
        "\n"
        "def handle(req, y):\n"
        "    return sink(req.user.id, clean(req), c=y.value)\n"
    )
    f = tmp_path / "mod.py"
    f.write_text(src, encoding="utf-8")

    idx = scan_file(
        abs_path=Path(f),
        rel="mod.py",
        language="python",
        source_specs=[],
        sink_specs=[],
    )

    assert idx is not None
    sink_call = next(c for c in idx.call_args if c.callee_name == "sink")
    assert "req" in sink_call.arg_symbols
    assert "y" in sink_call.arg_symbols


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_scan_file_js_captures_class_field_arrow_and_computed_call(tmp_path):
    src = (
        "class Demo {\n"
        "  handler = (req) => this.routes[\"process\"](req.user.id);\n"
        "  process(input) { return input; }\n"
        "}\n"
    )
    f = tmp_path / "demo.js"
    f.write_text(src, encoding="utf-8")

    idx = scan_file(
        abs_path=Path(f),
        rel="demo.js",
        language="javascript",
        source_specs=[],
        sink_specs=[],
    )

    assert idx is not None
    assert any(fn.name == "handler" for fn in idx.functions)
    assert any(edge[2] == "process" for edge in idx.call_edges)
    process_call = next(c for c in idx.call_args if c.callee_name == "process")
    assert "req" in process_call.arg_symbols


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_scan_file_java_captures_catch_and_varargs_receiver_types(tmp_path):
    src = (
        "class Demo {\n"
        "  void log(Object... args) {\n"
        "    try { throw new RuntimeException(); } catch (Exception e) {\n"
        "      e.getMessage();\n"
        "      args[0].toString();\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    f = tmp_path / "Demo.java"
    f.write_text(src, encoding="utf-8")

    idx = scan_file(
        abs_path=Path(f),
        rel="Demo.java",
        language="java",
        source_specs=[],
        sink_specs=[],
    )

    assert idx is not None
    assert idx.imports.get("e", "").endswith("Exception")
    assert idx.imports.get("args", "").endswith("Object")
    assert any(edge[1] == "e" and edge[2] == "getMessage" for edge in idx.call_edges)
    assert any(edge[1] == "args" and edge[2] == "toString" for edge in idx.call_edges)


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_scan_file_java_captures_enhanced_for_receiver_types(tmp_path):
    src = (
        "import java.util.List;\n"
        "class Details { String getPolicyName() { return \"x\"; } }\n"
        "class Demo {\n"
        "  void run(List<Details> items) {\n"
        "    for (Details item : items) {\n"
        "      item.getPolicyName();\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    f = tmp_path / "Demo.java"
    f.write_text(src, encoding="utf-8")

    idx = scan_file(
        abs_path=Path(f),
        rel="Demo.java",
        language="java",
        source_specs=[],
        sink_specs=[],
    )

    assert idx is not None
    assert idx.imports.get("item", "").endswith("Details")
    assert any(edge[1] == "item" and edge[2] == "getPolicyName" for edge in idx.call_edges)


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_scan_file_csharp_captures_receiver_types_for_catch_foreach_and_locals(tmp_path):
    src = (
        "using System;\n"
        "using System.Collections.Generic;\n"
        "class Item { public string GetName() => \"x\"; }\n"
        "class Demo {\n"
        "  void Run(List<Item> items) {\n"
        "    try { throw new Exception(); } catch (Exception e) { e.Message.ToString(); }\n"
        "    Item local = new Item();\n"
        "    Item alias = local;\n"
        "    foreach (Item item in items) { item.GetName(); }\n"
        "    local.GetName();\n"
        "    alias.GetName();\n"
        "  }\n"
        "}\n"
    )
    f = tmp_path / "Demo.cs"
    f.write_text(src, encoding="utf-8")

    idx = scan_file(
        abs_path=Path(f),
        rel="Demo.cs",
        language="csharp",
        source_specs=[],
        sink_specs=[],
    )

    assert idx is not None
    assert idx.imports.get("e", "").endswith("Exception")
    assert idx.imports.get("local", "").endswith("Item")
    assert idx.imports.get("alias", "").endswith("Item")
    assert idx.imports.get("item", "").endswith("Item")
    assert any(edge[1] == "e" and edge[2] == "ToString" for edge in idx.call_edges)
    assert any(edge[1] == "item" and edge[2] == "GetName" for edge in idx.call_edges)
    assert any(edge[1] == "local" and edge[2] == "GetName" for edge in idx.call_edges)


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_scan_file_typescript_captures_typed_receivers_and_for_of_items(tmp_path):
    src = (
        "class Client { save(): void {} }\n"
        "class Demo {\n"
        "  run(client: Client, items: Client[]) {\n"
        "    const local: Client = client;\n"
        "    let alias = local;\n"
        "    const made = new Client();\n"
        "    for (const item of items) { item.save(); }\n"
        "    local.save();\n"
        "    alias.save();\n"
        "    made.save();\n"
        "  }\n"
        "}\n"
    )
    f = tmp_path / "demo.ts"
    f.write_text(src, encoding="utf-8")

    idx = scan_file(
        abs_path=Path(f),
        rel="demo.ts",
        language="typescript",
        source_specs=[],
        sink_specs=[],
    )

    assert idx is not None
    assert idx.imports.get("client", "").endswith("Client")
    assert idx.imports.get("items.__generic0__", "").endswith("Client")
    assert idx.imports.get("local", "").endswith("Client")
    assert idx.imports.get("alias", "").endswith("Client")
    assert idx.imports.get("made", "").endswith("Client")
    assert idx.imports.get("item", "").endswith("Client")
    assert any(edge[1] == "item" and edge[2] == "save" for edge in idx.call_edges)
    assert any(edge[1] == "local" and edge[2] == "save" for edge in idx.call_edges)
