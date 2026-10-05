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

"""
Tests for the tree-sitter call-graph backend.

Two layers:
  • fallback path — always runs; asserts that with tree-sitter unavailable
    ``build()`` returns False and the s1 dispatcher drops through to the
    legacy regex supplement (so taint.yaml never breaks on a base install).
  • AST path — only when ``tree-sitter-language-pack`` is importable; parses
    a tiny multi-file Python fixture and asserts qualified edges + def_spans.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.lang import ts_graph
from vvaharness.pipeline.stages.s1_preprocess import q_join


def _cfg():
    return SimpleNamespace(step1=SimpleNamespace(
        call_graph_max_targets=3, call_graph="tree_sitter",
        call_graph_validate=True, call_graph_supplement=True,
        call_graph_rounds=2,
    ))


def test_parse_file_regex_fallback_for_unmapped_language():
    """A language with no _QUERIES entry must still yield defs/calls via the
    regex scanner so the graph isn't empty for COBOL/JCL/etc."""
    src = "def foo():\n    bar()\n\ndef bar():\n    pass\n"
    defs, calls = ts_graph._parse_file("x.cob", src, "cobol")
    names = {n for n, *_ in defs}
    assert {"foo", "bar"} <= names
    assert any(c == "bar" for c, _ in calls)
    # regex path has no end-of-def → start == end
    for _n, _qn, sl, el, sb, eb in defs:
        assert sl == el and sb == -1 and eb == -1


def test_normalize_lang_for_queries_maps_c_family_by_suffix():
    assert ts_graph._normalize_lang_for_queries("a.c", "c-cpp") == "c"
    assert ts_graph._normalize_lang_for_queries("a.h", "c-cpp") == "c"
    assert ts_graph._normalize_lang_for_queries("a.cpp", "c-cpp") == "cpp"
    assert ts_graph._normalize_lang_for_queries("a.cc", "c-cpp") == "cpp"
    assert ts_graph._normalize_lang_for_queries("a.hpp", "c-cpp") == "cpp"


def test_normalize_lang_for_queries_leaves_other_langs_unchanged():
    assert ts_graph._normalize_lang_for_queries("x.py", "python") == "python"
    assert ts_graph._normalize_lang_for_queries("x.java", "java") == "java"


def test_normalize_lang_for_queries_routes_tsx_to_the_tsx_grammar():
    # EXT_TO_LANG folds .tsx into "typescript", but the typescript grammar does
    # not accept JSX. Same broad-id-to-concrete-grammar resolution as c-cpp.
    assert ts_graph._normalize_lang_for_queries("src/Page.tsx",
                                                "typescript") == "tsx"
    assert ts_graph._normalize_lang_for_queries("src/svc.ts",
                                                "typescript") == "typescript"


def test_tsx_queries_are_derived_from_typescript():
    # Same node names, different grammar. Derived, not copied, so they cannot
    # drift apart.
    tsx, ts = ts_graph._QUERIES["tsx"], ts_graph._QUERIES["typescript"]
    assert tsx["grammar"] == "tsx"
    assert ts["grammar"] == "typescript"
    assert tsx["defs"] == ts["defs"]
    assert tsx["calls"] == ts["calls"]


@pytest.mark.skipif(ts_graph.get_parser is None,
                    reason="tree-sitter backend unavailable")
def test_tsx_grammar_recovers_functions_the_typescript_grammar_loses():
    """JSX under the typescript grammar triggers error recovery that swallows
    most of the file. Measured here: the default-exported component and a
    sibling helper are both lost, leaving only the inner arrow.

    S1's graph backend is a second, independent tree-sitter implementation from
    the S0 callgraph engine, so the same .tsx defect had to be fixed in both.
    """
    src = ("export default function Page() {\n"
           "  const onClick = (e) => { helper(e.target.value); };\n"
           "  return <div onClick={onClick}>{helper(1)}</div>;\n"
           "}\n"
           "function helper(x){ return fetch('/api?x=' + x); }\n")

    ts_defs, ts_calls = ts_graph._parse_file("src/Page.tsx", src, "typescript")
    tsx_defs, tsx_calls = ts_graph._parse_file("src/Page.tsx", src, "tsx")

    assert {d[0] for d in tsx_defs} == {"Page", "onClick", "helper"}
    assert {d[0] for d in ts_defs} == {"onClick"}
    assert len(tsx_calls) > len(ts_calls)


def test_build_returns_false_when_backend_missing(monkeypatch, tmp_path):
    """Force-unavailable backend → build() must refuse cleanly so the s1
    dispatcher falls back to _supplement_call_graph."""
    monkeypatch.setattr(ts_graph, "get_parser", None)
    monkeypatch.setattr(ts_graph, "get_language", None)
    data: dict = {"call_graph": {}}
    ok = ts_graph.build(data, [], tmp_path, _cfg())
    assert ok is False
    assert data == {"call_graph": {}}   # untouched


def test_captures_shim_handles_both_api_shapes():
    class _N:  # minimal Node stand-in
        pass
    n1, n2 = _N(), _N()
    # 0.22+ dict shape
    q = SimpleNamespace(captures=lambda _root: {"name": [n1], "def": [n2]})
    out = ts_graph._captures(q, None)
    assert set(out) == {(n1, "name"), (n2, "def")}
    # 0.20/0.21 list shape
    q = SimpleNamespace(captures=lambda _root: [(n1, "name"), (n2, "def")])
    assert ts_graph._captures(q, None) == [(n1, "name"), (n2, "def")]


def test_parse_file_skips_unmatched_name_capture(monkeypatch):
    class _Node:
        def __init__(self, text: str, sb: int, eb: int, sl: int, el: int):
            self.start_byte = sb
            self.end_byte = eb
            self.start_point = (sl, 0)
            self.end_point = (el, 0)
            self._text = text

    class _Query:
        def __init__(self, caps):
            self._caps = caps

        def captures(self, _root):
            return list(self._caps)

    class _Parser:
        def parse(self, _src):
            return SimpleNamespace(root_node=object())

    src = "def foo():\n    return 1\n"
    name_node = _Node("foo", 4, 7, 0, 0)
    # This @def range does not contain the name node => unmatched capture case.
    def_node = _Node("junk", 12, 16, 1, 1)

    monkeypatch.setattr(ts_graph, "_compile",
                        lambda _lang: (_Parser(), _Query([(name_node, "name"), (def_node, "def")]), _Query([])))

    defs, calls = ts_graph._parse_file("x.py", src, "python")
    assert defs == []
    assert calls == []


needs_ts = pytest.mark.skipif(
    not ts_graph.available(),
    reason="tree-sitter-language-pack not installed; "
           "pip install . (or pipx install .), then run "
           "'vvaharness doctor' to verify, to enable",
)


@needs_ts
def test_build_python_fixture_edges_and_spans(tmp_path):
    (tmp_path / "ctrl.py").write_text(
        "def handle(req):\n"
        "    q = req.args.get('q')\n"
        "    return process(q)\n",
        encoding="utf-8")
    (tmp_path / "svc.py").write_text(
        "from dao import raw_query\n"
        "\n"
        "def process(q):\n"
        "    s = 'SELECT * FROM t WHERE x = ' + q\n"
        "    return raw_query(s)\n"
        "\n"
        "def unused():\n"
        "    pass\n",
        encoding="utf-8")
    (tmp_path / "dao.py").write_text(
        "import db\n"
        "\n"
        "def raw_query(sql):\n"
        "    return db.execute(sql)\n",
        encoding="utf-8")

    data: dict = {"call_graph": {}, "entry_points": [], "unsafe_sinks": []}
    ok = ts_graph.build(data, ["ctrl.py", "svc.py", "dao.py"],
                        tmp_path, _cfg())
    assert ok is True

    cg = data["call_graph"]
    assert q_join("svc.py", "process") in cg[q_join("ctrl.py", "handle")]
    assert q_join("dao.py", "raw_query") in cg[q_join("svc.py", "process")]

    spans = data["def_spans"]
    # process() spans lines 3..5 in svc.py — AST-exact end line, which the
    # regex backend cannot produce.
    assert spans[q_join("svc.py", "process")] == [3, 5]
    assert spans[q_join("ctrl.py", "handle")][0] == 1
    assert spans[q_join("dao.py", "raw_query")][0] == 3

    # call_graph_files only lists names that participate in an edge
    assert "process" in data["call_graph_files"]
    assert "raw_query" in data["call_graph_files"]


@needs_ts
def test_enclosing_picks_innermost_def(tmp_path):
    (tmp_path / "a.py").write_text(
        "def outer():\n"
        "    def inner():\n"
        "        target()\n"
        "    inner()\n"
        "\n"
        "def target():\n"
        "    pass\n",
        encoding="utf-8")
    data: dict = {"call_graph": {}}
    ts_graph.build(data, ["a.py"], tmp_path, _cfg())
    # target() call on line 3 is inside inner(), not outer()
    assert q_join("a.py", "target") in data["call_graph"].get(
        q_join("a.py", "inner"), [])


def test_build_does_not_regraft_stale_edges_by_name_only(tmp_path):
    (tmp_path / "new.py").write_text(
        "def caller():\n"
        "    helper()\n"
        "\n"
        "def helper():\n"
        "    pass\n",
        encoding="utf-8")

    stale = {
        "call_graph": {
            # Old caller file no longer exists; same bare names do exist in new.py.
            q_join("old.py", "caller"): [q_join("new.py", "helper")]
        }
    }
    ok = ts_graph.build(stale, ["new.py"], tmp_path, _cfg())
    assert ok is True
    # Ensure stale old.py caller was not re-grafted onto new.py::caller.
    assert q_join("new.py", "caller") in stale["call_graph"]
    assert q_join("new.py", "helper") in stale["call_graph"][q_join("new.py", "caller")]
    assert q_join("old.py", "caller") not in stale["call_graph"]


def test_build_unions_overloaded_same_name_spans(tmp_path):
    (tmp_path / "Svc.java").write_text(
        "class Svc {\n"
        "  void process(String q) {\n"
        "    callA();\n"
        "  }\n"
        "\n"
        "  void process(String q, int x) {\n"
        "    callB();\n"
        "    callC();\n"
        "  }\n"
        "}\n",
        encoding="utf-8")

    data: dict = {"call_graph": {}, "entry_points": [], "unsafe_sinks": []}
    ok = ts_graph.build(data, ["Svc.java"], tmp_path, _cfg())
    assert ok is True

    keys = [k for k in data["def_spans"] if k.startswith(q_join("Svc.java", "Svc.process("))]
    assert len(keys) == 2
    spans = [data["def_spans"][k] for k in keys]
    # Per-overload spans should remain distinct.
    assert all(s[0] <= s[1] for s in spans)


@needs_ts
def test_build_java_qnodes_include_class_and_signature(tmp_path):
    (tmp_path / "Demo.java").write_text(
        "class Demo {\n"
        "  void process(String q) { sink(q); }\n"
        "  void process(String q, int n) { sink(q); }\n"
        "  void sink(String x) {}\n"
        "}\n",
        encoding="utf-8",
    )

    data: dict = {"call_graph": {}, "entry_points": [], "unsafe_sinks": []}
    ok = ts_graph.build(data, ["Demo.java"], tmp_path, _cfg())
    assert ok is True

    keys = sorted(k for k in data["def_spans"] if k.startswith("Demo.java::Demo.process"))
    assert len(keys) == 2
    assert any("string" in k.lower() for k in keys)
    assert any("int" in k.lower() for k in keys)


@needs_ts
def test_build_java_captures_ctor_and_method_reference_calls(tmp_path):
    (tmp_path / "Demo.java").write_text(
        "import java.util.function.Function;\n"
        "class Ctor {}\n"
        "class Mapper { static String mapOne(String v) { return v; } }\n"
        "class Demo {\n"
        "  void run() {\n"
        "    Ctor c = new Ctor();\n"
        "    Function<String,String> f = Mapper::mapOne;\n"
        "    f.apply(\"x\");\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    data: dict = {"call_graph": {}, "entry_points": [], "unsafe_sinks": []}
    ok = ts_graph.build(data, ["Demo.java"], tmp_path, _cfg())
    assert ok is True

    edge_txt = "\n".join(
        f"{k} -> {v}"
        for k, vs in data["call_graph"].items()
        for v in vs
    )
    assert "::Ctor" in edge_txt
    assert "Mapper.mapOne" in edge_txt


@needs_ts
def test_build_csharp_qnodes_include_class_and_signature(tmp_path):
    (tmp_path / "Demo.cs").write_text(
        "class Demo {\n"
        "  void Process(string q) { Sink(q); }\n"
        "  void Process(string q, int n) { Sink(q); }\n"
        "  void Sink(string x) {}\n"
        "}\n",
        encoding="utf-8",
    )

    data: dict = {"call_graph": {}, "entry_points": [], "unsafe_sinks": []}
    ok = ts_graph.build(data, ["Demo.cs"], tmp_path, _cfg())
    assert ok is True

    keys = sorted(k for k in data["def_spans"] if k.startswith("Demo.cs::Demo.Process"))
    assert len(keys) == 2
    assert any("string" in k for k in keys)
    assert any("int" in k for k in keys)


@needs_ts
def test_build_csharp_captures_ctor_and_linq_query_calls(tmp_path):
    (tmp_path / "Demo.cs").write_text(
        "using System.Linq;\n"
        "class Ctor {}\n"
        "class Demo {\n"
        "  int Where(int x) { return x; }\n"
        "  int Select(int x) { return x; }\n"
        "  int[] Run(int[] xs) {\n"
        "    var c = new Ctor();\n"
        "    var q = from x in xs where x > 1 select x;\n"
        "    return q.ToArray();\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    data: dict = {"call_graph": {}, "entry_points": [], "unsafe_sinks": []}
    ok = ts_graph.build(data, ["Demo.cs"], tmp_path, _cfg())
    assert ok is True

    edge_txt = "\n".join(
        f"{k} -> {v}"
        for k, vs in data["call_graph"].items()
        for v in vs
    )
    assert "::Ctor" in edge_txt
    assert "Demo.Where" in edge_txt
    assert "Demo.Select" in edge_txt


@needs_ts
def test_build_python_async_function_def_span(tmp_path):
    (tmp_path / "async_mod.py").write_text(
        "async def do_async(v):\n"
        "    return sink(v)\n"
        "\n"
        "def sink(x):\n"
        "    return x\n",
        encoding="utf-8",
    )

    data: dict = {"call_graph": {}, "entry_points": [], "unsafe_sinks": []}
    ok = ts_graph.build(data, ["async_mod.py"], tmp_path, _cfg())
    assert ok is True

    assert q_join("async_mod.py", "do_async") in data["def_spans"]
    assert q_join("async_mod.py", "sink") in data["call_graph"].get(
        q_join("async_mod.py", "do_async"), []
    )


@needs_ts
def test_build_javascript_class_field_arrow_and_computed_call(tmp_path):
    (tmp_path / "svc.js").write_text(
        "class Demo {\n"
        "  handler = (req) => this.routes[\"process\"](req.user.id);\n"
        "  process(input) { return input; }\n"
        "}\n",
        encoding="utf-8",
    )

    data: dict = {"call_graph": {}, "entry_points": [], "unsafe_sinks": []}
    ok = ts_graph.build(data, ["svc.js"], tmp_path, _cfg())
    assert ok is True

    spans = data["def_spans"]
    assert q_join("svc.js", "handler") in spans
    edge_txt = "\n".join(
        f"{k} -> {v}"
        for k, vs in data["call_graph"].items()
        for v in vs
    )
    assert "svc.js::process" in edge_txt
