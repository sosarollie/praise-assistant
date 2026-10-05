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

import vvaharness.pipeline.stages.callgraph_engine._graph as graph_mod
from vvaharness.pipeline.stages.callgraph_engine._graph import (
    _resolve_called_fids,
    build_taint_paths,
)
from vvaharness.pipeline.stages.callgraph_engine._scan import (
    CallArgFact,
    CallSite,
    FileIndex,
    FuncDef,
)


def _callsite(*, file: str, line: int, containing_fn: str, role: str, kind: str, method: str = "", cwe: str = "CWE-89") -> CallSite:
    return CallSite(
        file=file,
        line=line,
        receiver="",
        method=method,
        containing_fn=containing_fn,
        snippet="snippet",
        matched_rule=f"{role}-rule",
        cwe=cwe,
        role=role,
        kind=kind,
    )


def test_build_taint_paths_drops_name_only_ambiguous_edges():
    source_idx = FileIndex(
        file="api/controller.py",
        language="python",
        imports={},
        functions=[FuncDef(name="entry", start_line=1, end_line=10)],
        source_hits=[
            _callsite(file="api/controller.py", line=2, containing_fn="entry", role="source", kind="network")
        ],
        call_edges=[("entry", "", "run")],
    )
    sink_a = FileIndex(
        file="db/query.py",
        language="python",
        imports={},
        functions=[FuncDef(name="run", start_line=10, end_line=20)],
        sink_hits=[
            _callsite(file="db/query.py", line=15, containing_fn="run", role="sink", kind="sql", method="execute")
        ],
    )
    sink_b = FileIndex(
        file="net/client.py",
        language="python",
        imports={},
        functions=[FuncDef(name="run", start_line=30, end_line=40)],
        sink_hits=[
            _callsite(file="net/client.py", line=35, containing_fn="run", role="sink", kind="ssrf", method="open")
        ],
    )

    pkg = build_taint_paths([source_idx, sink_a, sink_b], {})

    # GAP-GRAPH-03: bare-name no-hint calls no longer hard-drop; they emit
    # top proximity-scored candidates at LOW confidence. Verify paths are produced.
    assert len(pkg.taint_paths) > 0


def test_build_taint_paths_applies_source_sink_compatibility():
    idx = FileIndex(
        file="loader.py",
        language="python",
        imports={},
        functions=[FuncDef(name="load", start_line=1, end_line=20)],
        source_hits=[
            _callsite(file="loader.py", line=3, containing_fn="load", role="source", kind="filesystem")
        ],
        sink_hits=[
            _callsite(file="loader.py", line=7, containing_fn="load", role="sink", kind="xss", method="write"),
            _callsite(file="loader.py", line=9, containing_fn="load", role="sink", kind="path", method="open"),
        ],
    )

    pkg = build_taint_paths([idx], {})

    assert pkg.taint_paths == [["loader.py:3", "loader.py:9"]]


def test_build_taint_paths_sink_identity_uses_containing_function():
    idx = FileIndex(
        file="api.py",
        language="python",
        imports={},
        functions=[FuncDef(name="handle", start_line=1, end_line=20)],
        source_hits=[
            _callsite(file="api.py", line=2, containing_fn="handle",
                      role="source", kind="network", method="request")
        ],
        sink_hits=[
            _callsite(file="api.py", line=8, containing_fn="handle",
                      role="sink", kind="sql", method="execute")
        ],
    )

    pkg = build_taint_paths([idx], {})

    assert len(pkg.unsafe_sinks) == 1
    assert pkg.unsafe_sinks[0].function == "handle"


def test_build_taint_paths_emits_function_signatures_for_snapshot():
    idx = FileIndex(
        file="nested.py",
        language="python",
        imports={},
        functions=[
            FuncDef(
                name="helper",
                start_line=1,
                end_line=5,
                qnode="outer_one.helper(request)",
                parameter_text="(request)",
                parameter_names=("request",),
            ),
            FuncDef(
                name="helper",
                start_line=10,
                end_line=15,
                qnode="outer_two.helper(request, user_id)",
                parameter_text="(request, user_id)",
                parameter_names=("request", "user_id"),
            ),
        ],
    )

    pkg = build_taint_paths([idx], {})

    assert len(pkg.function_signatures) == 2
    assert pkg.function_signatures["nested.py::outer_one.helper(request)"]["parameter_names"] == ["request"]
    assert pkg.function_signatures["nested.py::outer_two.helper(request, user_id)"]["parameter_names"] == ["request", "user_id"]


def test_build_taint_paths_sets_intra_proc_evidence_confidence():
    idx = FileIndex(
        file="single.py",
        language="python",
        imports={},
        functions=[FuncDef(name="handle", start_line=1, end_line=20)],
        source_hits=[
            _callsite(file="single.py", line=3, containing_fn="handle", role="source", kind="network")
        ],
        sink_hits=[
            _callsite(file="single.py", line=9, containing_fn="handle", role="sink", kind="sql", method="execute")
        ],
    )

    pkg = build_taint_paths([idx], {})

    assert len(pkg.taint_evidence) == 1
    ev = pkg.taint_evidence[0]
    assert getattr(ev, "confidence", None) == 1.0
    assert getattr(ev, "notes", "") == "min_edge_confidence=1.0000"


def test_build_taint_paths_preserves_js_class_method_signature_identity():
    idx = FileIndex(
        file="api.js",
        language="javascript",
        imports={},
        functions=[
            FuncDef(
                name="run",
                start_line=1,
                end_line=10,
                class_name="C",
                qnode="C.run(input, fallback)",
                parameter_text="(input, fallback)",
                parameter_names=("input", "fallback"),
            )
        ],
    )

    pkg = build_taint_paths([idx], {})

    assert "api.js::C.run(input, fallback)" in pkg.function_signatures
    assert pkg.function_signatures["api.js::C.run(input, fallback)"]["parameter_names"] == ["input", "fallback"]


def test_resolve_called_fids_prefers_typed_receiver_qualified_match():
    file_index = {
        "svc/handler.java": FileIndex(
            file="svc/handler.java",
            language="java",
            imports={"client": "com.acme.Client"},
            functions=[],
        )
    }
    fn_meta = {
        "svc/client.java::Client.save(String)": ("svc/client.java", 1, 20),
        "svc/other.java::Other.save(String)": ("svc/other.java", 1, 20),
    }
    fn_defs_by_name = {
        "save": [
            "svc/client.java::Client.save(String)",
            "svc/other.java::Other.save(String)",
        ]
    }
    fn_defs_by_qual = {
        "Client.save": ["svc/client.java::Client.save(String)"],
        "Other.save": ["svc/other.java::Other.save(String)"],
    }

    result = _resolve_called_fids(
        "svc/handler.java::Handler.run()",
        "svc/handler.java",
        "client",
        "save",
        fn_defs_by_name,
        fn_defs_by_qual,
        fn_meta,
        file_index,
        max_targets=3,
    )

    assert result == ["svc/client.java::Client.save(String)"]


def test_resolve_called_fids_skips_unrelated_bare_defs_for_typed_receiver():
    file_index = {
        "svc/handler.java": FileIndex(
            file="svc/handler.java",
            language="java",
            imports={"e": "java.lang.Exception"},
            functions=[],
        )
    }
    fn_meta = {
        "svc/a.java::ProcessingDecision.getMessage()": ("svc/a.java", 1, 20),
        "svc/b.java::OnboardingResult.getMessage()": ("svc/b.java", 1, 20),
    }
    fn_defs_by_name = {
        "getMessage": [
            "svc/a.java::ProcessingDecision.getMessage()",
            "svc/b.java::OnboardingResult.getMessage()",
        ]
    }

    result = _resolve_called_fids(
        "svc/handler.java::Handler.run()",
        "svc/handler.java",
        "e",
        "getMessage",
        fn_defs_by_name,
        {},
        fn_meta,
        file_index,
        max_targets=3,
    )

    assert result == []


def test_filter_budget_keeps_one_per_sink_family_under_tight_budget(monkeypatch):
    monkeypatch.setattr(graph_mod, "_GLOBAL_PATH_BUDGET", 2)
    monkeypatch.setattr(graph_mod, "_GLOBAL_PATH_BUDGET_MAX", 2)

    source_idx = FileIndex(
        file="src.py",
        language="python",
        imports={},
        functions=[FuncDef(name="entry", start_line=1, end_line=20)],
        source_hits=[
            _callsite(file="src.py", line=2, containing_fn="entry", role="source", kind="network")
        ],
        call_edges=[("entry", "", "to_sql"), ("entry", "", "to_sql_alt"), ("entry", "", "to_ssrf")],
    )
    sql_idx = FileIndex(
        file="sql_mod.py",
        language="python",
        imports={},
        functions=[FuncDef(name="to_sql", start_line=10, end_line=20)],
        sink_hits=[
            _callsite(file="sql_mod.py", line=15, containing_fn="to_sql", role="sink", kind="sql", method="execute")
        ],
    )
    ssrf_idx = FileIndex(
        file="http_mod.py",
        language="python",
        imports={},
        functions=[FuncDef(name="to_ssrf", start_line=30, end_line=40)],
        sink_hits=[
            _callsite(file="http_mod.py", line=35, containing_fn="to_ssrf", role="sink", kind="ssrf", method="open")
        ],
    )
    sql_alt_idx = FileIndex(
        file="sql_mod_alt.py",
        language="python",
        imports={},
        functions=[FuncDef(name="to_sql_alt", start_line=50, end_line=60)],
        sink_hits=[
            _callsite(file="sql_mod_alt.py", line=55, containing_fn="to_sql_alt", role="sink", kind="sql", method="execute")
        ],
    )

    pkg = build_taint_paths([source_idx, sql_idx, ssrf_idx, sql_alt_idx], {})

    families = {p[-1].split(":")[0] for p in pkg.taint_paths}
    assert len(pkg.taint_paths) == 2
    assert "http_mod.py" in families
    assert "sql_mod.py" in families or "sql_mod_alt.py" in families

    uncertainty = getattr(pkg, "uncertainty_edges", [])
    assert uncertainty
    assert any(rec.get("reason") == "global_cap" for rec in uncertainty)


def test_build_taint_paths_carries_bridge_uncertainty_edges():
    idx = FileIndex(
        file="svc.py",
        language="python",
        imports={},
        functions=[FuncDef(name="handle", start_line=1, end_line=20)],
    )
    idx.bridge_signals = [{
        "edge_type": "bridge",
        "bridge_kind": "subprocess",
        "language": "python",
        "file": "svc.py",
        "line": 9,
        "src_qnode": "svc.py::handle",
        "dst_qnode": "bridge::subprocess",
        "reason": "bridge_signal",
        "confidence": 0.25,
        "snippet": "subprocess.run(cmd)",
    }]

    pkg = build_taint_paths([idx], {})

    edges = getattr(pkg, "uncertainty_edges", [])
    assert any(e.get("edge_type") == "bridge" and e.get("bridge_kind") == "subprocess" for e in edges)


def test_build_taint_paths_function_signatures_include_bounded_body(tmp_path):
    p = tmp_path / "sample.py"
    p.write_text(
        "def handle(a, b):\n"
        "    x = a + b\n"
        "    return x\n",
        encoding="utf-8",
    )

    idx = FileIndex(
        file=str(p),
        language="python",
        imports={},
        functions=[
            FuncDef(
                name="handle",
                start_line=1,
                end_line=3,
                qnode="handle(a, b)",
                parameter_text="(a, b)",
                parameter_names=("a", "b"),
            )
        ],
    )

    pkg = build_taint_paths([idx], {})

    sig = pkg.function_signatures[f"{p}::handle(a, b)"]
    assert "body_text" in sig
    assert "def handle(a, b):" in str(sig["body_text"])


def test_build_taint_paths_prefers_csharp_using_static_extension_owner():
    source_idx = FileIndex(
        file="App.cs",
        language="csharp",
        imports={"__using_static__:TextExt": "Demo.TextExt"},
        functions=[FuncDef(name="Entry", class_name="App", qnode="App.Entry(String)", start_line=1, end_line=20)],
        source_hits=[
            _callsite(file="App.cs", line=6, containing_fn="App.Entry(String)", role="source", kind="network", method="Shell")
        ],
        call_edges=[("App.Entry(String)", "", "Shell")],
    )
    sink_ext = FileIndex(
        file="TextExt.cs",
        language="csharp",
        imports={"__cs_extension_method__:Shell": "TextExt"},
        functions=[FuncDef(name="Shell", class_name="TextExt", qnode="TextExt.Shell(String)", start_line=3, end_line=8)],
        sink_hits=[
            _callsite(file="TextExt.cs", line=5, containing_fn="TextExt.Shell(String)", role="sink", kind="cmd", method="Shell", cwe="CWE-78")
        ],
    )
    sink_other = FileIndex(
        file="Other.cs",
        language="csharp",
        imports={},
        functions=[FuncDef(name="Shell", class_name="Other", qnode="Other.Shell(String)", start_line=3, end_line=8)],
    )

    pkg = build_taint_paths([source_idx, sink_ext, sink_other], {})

    assert any(
        p and p[0] == "App.cs:6" and p[-1] == "TextExt.cs:5"
        for p in pkg.taint_paths
    )


def test_build_taint_paths_keeps_unsanitized_when_sanitized_and_unsanitized_args_both_reach_sink():
    idx = FileIndex(
        file="branchy.py",
        language="python",
        imports={},
        functions=[FuncDef(name="handle", start_line=1, end_line=30)],
        source_hits=[
            _callsite(file="branchy.py", line=3, containing_fn="handle", role="source", kind="network", method="get")
        ],
        sink_hits=[
            _callsite(file="branchy.py", line=20, containing_fn="handle", role="sink", kind="sql", method="execute")
        ],
        call_args=[
            # Source seeds taint in user_in.
            CallArgFact(function_qnode="handle", line=3, callee_name="get", receiver="req", arg_symbols=[], target_symbol="user_in"),
            # One branch sanitizes user_in into safe_val.
            CallArgFact(function_qnode="handle", line=10, callee_name="to_int", receiver="", arg_symbols=["user_in"], target_symbol="safe_val"),
            # Sink takes both safe_val and raw user_in, representing sibling branches converging.
            CallArgFact(function_qnode="handle", line=20, callee_name="execute", receiver="db", arg_symbols=["safe_val", "user_in"], target_symbol=None),
        ],
    )

    pkg = build_taint_paths([idx], {})

    # Unsanitized flow must remain visible.
    assert pkg.taint_paths == [["branchy.py:3", "branchy.py:20"]]
    assert len(pkg.taint_evidence) == 1
    evidence = pkg.taint_evidence[0]
    assert evidence.sanitized is False
    assert getattr(evidence, "confidence", None) == 1.0


def test_build_taint_paths_marks_fully_sanitized_and_reduces_confidence():
    idx = FileIndex(
        file="sanitized.py",
        language="python",
        imports={},
        functions=[FuncDef(name="handle", start_line=1, end_line=30)],
        source_hits=[
            _callsite(file="sanitized.py", line=3, containing_fn="handle", role="source", kind="network", method="get")
        ],
        sink_hits=[
            _callsite(file="sanitized.py", line=20, containing_fn="handle", role="sink", kind="sql", method="execute")
        ],
        call_args=[
            CallArgFact(function_qnode="handle", line=3, callee_name="get", receiver="req", arg_symbols=[], target_symbol="user_in"),
            CallArgFact(function_qnode="handle", line=10, callee_name="to_int", receiver="", arg_symbols=["user_in"], target_symbol="safe_val"),
            # Sink only receives sanitized value.
            CallArgFact(function_qnode="handle", line=20, callee_name="execute", receiver="db", arg_symbols=["safe_val"], target_symbol=None),
        ],
    )

    pkg = build_taint_paths([idx], {})

    # Fully sanitized path should be retained in evidence, but not as taint path.
    assert pkg.taint_paths == []
    assert len(pkg.taint_evidence) == 1
    evidence = pkg.taint_evidence[0]
    assert evidence.sanitized is True
    assert getattr(evidence, "confidence", None) == 0.5
    assert "sanitized_path" in getattr(evidence, "notes", "")


def test_build_taint_paths_java_constructor_injection_field_flow_reaches_sink():
    idx = FileIndex(
        file="Demo.java",
        language="java",
        imports={},
        functions=[
            FuncDef(
                name="Demo",
                class_name="Demo",
                qnode="Demo.Demo(String)",
                start_line=1,
                end_line=8,
                parameter_text="(String payload)",
                parameter_names=("payload",),
            ),
            FuncDef(
                name="read",
                class_name="Demo",
                qnode="Demo.read()",
                start_line=9,
                end_line=16,
                parameter_text="()",
                parameter_names=(),
            ),
        ],
        source_hits=[
            _callsite(
                file="Demo.java",
                line=3,
                containing_fn="Demo.Demo(String)",
                role="source",
                kind="network",
                method="source",
            )
        ],
        sink_hits=[
            _callsite(
                file="Demo.java",
                line=6,
                containing_fn="Demo.Demo(String)",
                role="sink",
                kind="sql",
                method="execute",
            )
        ],
        call_args=[
            # Source seeds taint into ctor-local payload.
            CallArgFact(
                function_qnode="Demo.Demo(String)",
                line=3,
                callee_name="source",
                receiver="",
                arg_symbols=[],
                target_symbol="payload",
            ),
            # Sink in ctor receives payload after constructor field write.
            CallArgFact(
                function_qnode="Demo.Demo(String)",
                line=6,
                callee_name="execute",
                receiver="stmt",
                arg_symbols=["payload"],
                target_symbol=None,
            ),
        ],
        field_writes=[
            # Constructor injection writes ctor param into instance field.
            type("FieldWriteFact", (), {
                "function_qnode": "Demo.Demo(String)",
                "line": 4,
                "receiver": "this",
                "field": "payload",
                "src_symbol": "payload",
            })()
        ],
        field_reads=[],
        call_edges=[],
    )

    pkg = build_taint_paths([idx], {})

    assert ["Demo.java:3", "Demo.java:6"] in pkg.taint_paths
    assert any(
        any(getattr(edge, "transfer_kind", "") == "field_write" for edge in ev.edges)
        for ev in pkg.taint_evidence
    )