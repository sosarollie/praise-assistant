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

"""Regression tests for silent S0 coverage loss via ReflectionFact.

The defect: ReflectionFact.language was Literal["python", "java", "csharp"]
while the JS/TS extractor emitted language="javascript". The resulting
ValidationError unwound scan_file, and the blanket per-file guard in
callgraph_engine._scan_repo then evicted the ENTIRE file — functions, calls,
def-spans — from the S0 seed index. On one JS/TS target this silently dropped
the two files holding the app's eval() sinks. These tests pin down:

  1. the widened language schema (every language the extractors can emit),
  2. loud (not coerced) failure on unknown languages,
  3. per-fact / per-extractor containment: a reflection failure never costs
     the file's other results,
  4. the drop being counted (COUNTERS) and logged rather than silent.
"""

import ast
import logging
import pathlib
import typing
from pathlib import Path

import pytest
import pydantic

from vvaharness.models import ReflectionFact
from vvaharness.util.counters import COUNTERS
from vvaharness.pipeline.stages import callgraph_engine
from vvaharness.pipeline.stages.callgraph_engine import _scan as scan_mod
from vvaharness.pipeline.stages.callgraph_engine._scan import get_parser, scan_file


# Exactly the language labels a reflection extractor can emit. Derived from
# _REFLECTION_FACT_EXTRACTORS, NOT from the parser registry LANG_PLUGINS: the
# latter also carries "go" (which has no reflection extractor at all) and
# "typescript" (whose key reuses the JS extractor, so .ts facts are labelled
# "javascript"). Listing either would widen the schema for a value nothing can
# produce — and, for "typescript", would advertise a label that is never used.
# test_extractor_registry_emits_only_schema_languages below keeps this list
# honest if an extractor is added or relabelled.
EXTRACTOR_LANGUAGES = ["python", "java", "javascript", "csharp"]

# A TypeScript file shaped like the routes/captcha.ts that the original
# defect silently dropped: it holds both a normal function definition and an
# eval() sink, so losing the file loses both the def-span and the sink.
_TS_EVAL_SOURCE = (
    "export function verifyCaptcha(userInput: string): boolean {\n"
    "  const check = \"return \" + userInput;\n"
    "  return eval(check);\n"
    "}\n"
)


def _write_ts_repo(tmp_path: Path) -> Path:
    routes = tmp_path / "routes"
    routes.mkdir()
    (routes / "captcha.ts").write_text(_TS_EVAL_SOURCE, encoding="utf-8")
    return tmp_path


# ── 1. schema accepts every emitted language ────────────────────────────────

@pytest.mark.parametrize("lang", EXTRACTOR_LANGUAGES)
def test_reflection_fact_constructs_for_every_extractor_language(lang):
    fact = ReflectionFact(function_qnode="mod.fn", line=3, language=lang)
    assert fact.language == lang


def test_schema_literal_matches_the_emitted_language_set_exactly():
    """The Literal must be neither too narrow nor too wide.

    Too narrow was the original defect: language="javascript" failed validation
    and the per-file guard evicted whole files, eval() sinks included. Too wide
    is the opposite error — advertising a label nothing produces. Both
    directions are pinned here so the schema tracks the extractors.
    """
    allowed = set(typing.get_args(
        ReflectionFact.model_fields["language"].annotation))
    assert allowed == set(EXTRACTOR_LANGUAGES)


def test_extractor_registry_emits_only_schema_languages():
    """Every `language=` literal handed to _append_reflection_fact must be in
    the schema, and every schema value must actually be emitted.

    Reads the literals straight out of the module's AST, so adding a new
    extractor (say for Go) without widening the Literal fails here rather than
    in production, where the failure costs whole files from the seed index.

    The AST is walked rather than the raw text: a regex over the source also
    matches `language="..."` inside comments and docstrings, and the parser
    registry's neighbouring `ts_language=` values, none of which are facts.
    """
    tree = ast.parse(
        pathlib.Path(scan_mod.__file__).read_text(encoding="utf-8"))
    emitted = {
        kw.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_append_reflection_fact"
        for kw in node.keywords
        if kw.arg == "language" and isinstance(kw.value, ast.Constant)
    }
    assert emitted, "found no _append_reflection_fact call sites to check"
    allowed = set(typing.get_args(
        ReflectionFact.model_fields["language"].annotation))
    assert emitted <= allowed, (
        f"extractors emit {sorted(emitted - allowed)} which the Literal "
        f"rejects — these facts will fail validation and be dropped")
    assert allowed <= emitted, (
        f"the Literal allows {sorted(allowed - emitted)} which no extractor "
        f"emits — remove them rather than advertising an unused label")


def test_go_has_a_parser_but_no_reflection_extractor():
    """Pins the asymmetry that made the wide Literal wrong: Go is parsed, so it
    contributes functions and call edges, but nothing extracts reflection facts
    for it — hence language="go" is unreachable and must not be in the schema.
    """
    assert "go" in scan_mod.LANG_PLUGINS
    assert "go" not in scan_mod._REFLECTION_FACT_EXTRACTORS
    assert "go" not in EXTRACTOR_LANGUAGES


def test_typescript_facts_are_labelled_javascript():
    """The typescript key reuses the JS extractor, so .ts reflection facts carry
    language="javascript". That is why "typescript" is absent from the schema.
    """
    assert (scan_mod._REFLECTION_FACT_EXTRACTORS["typescript"]
            is scan_mod._REFLECTION_FACT_EXTRACTORS["javascript"])
    assert "typescript" not in EXTRACTOR_LANGUAGES


# ── 2. unknown language fails loudly, not coerced to a wrong label ──────────

def test_reflection_fact_unknown_language_raises_instead_of_silent_coercion():
    # Deliberate design: unlike call_type (coerced to "invoke"), an unknown
    # language must NOT be silently relabeled — it raises, and the scanner
    # contains that failure to the single fact (tested below).
    with pytest.raises(pydantic.ValidationError):
        ReflectionFact(function_qnode="mod.fn", line=3, language="klingon")


# ── 3a. the original defect, end to end: TS eval() file survives the scan ───

@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_ts_eval_file_is_scanned_with_javascript_reflection_fact(tmp_path):
    # Before the fix this raised ValidationError inside scan_file (the JS/TS
    # extractor emits language="javascript"), which dropped the whole file.
    f = tmp_path / "captcha.ts"
    f.write_text(_TS_EVAL_SOURCE, encoding="utf-8")

    idx = scan_file(
        abs_path=f,
        rel="routes/captcha.ts",
        language="typescript",
        source_specs=[],
        sink_specs=[],
    )

    assert idx is not None
    assert any(fn.name == "verifyCaptcha" for fn in idx.functions)
    assert any(edge[2] == "eval" for edge in idx.call_edges)
    assert idx.reflection_facts, "eval() should yield a reflection fact"
    assert all(rf.language == "javascript" for rf in idx.reflection_facts)


# ── 3b. per-fact containment: one bad fact never costs the file ─────────────

@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_bad_reflection_fact_drops_only_the_fact_not_the_file(
        tmp_path, monkeypatch, caplog):
    # Force every fact construction to fail (stands in for any future schema
    # mismatch) and prove the file still contributes functions/calls.
    class _Boom:
        def __init__(self, **kw):
            raise pydantic.ValidationError.from_exception_data(
                "ReflectionFact",
                [{"type": "literal_error",
                  "loc": ("language",),
                  "input": kw.get("language"),
                  "ctx": {"expected": "'python'"}}],
            )

    monkeypatch.setattr(scan_mod, "ReflectionFact", _Boom)

    f = tmp_path / "captcha.ts"
    f.write_text(_TS_EVAL_SOURCE, encoding="utf-8")

    dropped_before = COUNTERS.get("s0_reflection_facts_dropped")
    with caplog.at_level(logging.WARNING, logger=scan_mod.__name__):
        idx = scan_file(
            abs_path=f,
            rel="routes/captcha.ts",
            language="typescript",
            source_specs=[],
            sink_specs=[],
        )

    # The file's other results survive; only the facts are gone.
    assert idx is not None
    assert any(fn.name == "verifyCaptcha" for fn in idx.functions)
    assert any(edge[2] == "eval" for edge in idx.call_edges)
    assert idx.reflection_facts == []

    # 4. the drop is counted and logged, never silent.
    assert COUNTERS.get("s0_reflection_facts_dropped") > dropped_before
    assert any("dropped 1 reflection fact" in rec.getMessage()
               for rec in caplog.records)


# ── 3c. engine level: extractor crash must not evict the file from the index ─

@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_reflection_extractor_crash_keeps_file_in_scan_repo_index(
        tmp_path, monkeypatch):
    # THE regression that matters: a file whose reflection-fact extraction
    # raises must still contribute its functions/calls/def-spans to the scan
    # result, i.e. must NOT be absent from the per-file index _scan_repo
    # returns (the old blanket per-file handler dropped it entirely).
    def _explode(src, tree):
        raise RuntimeError("synthetic reflection extractor failure")

    monkeypatch.setitem(
        scan_mod._REFLECTION_FACT_EXTRACTORS, "typescript", _explode)

    repo = _write_ts_repo(tmp_path)
    failed_before = COUNTERS.get("s0_reflection_extract_failed_files")

    indices = callgraph_engine._scan_repo(
        repo_root=str(repo),
        in_scope={"routes/captcha.ts"},
        source_specs=[],
        sink_specs=[],
        keep_predicate=lambda idx: bool(idx.functions),
    )

    by_file = {fi.file: fi for fi in indices}
    assert "routes/captcha.ts" in by_file, (
        "file with a failing reflection extractor was evicted from the "
        "seed index — the whole-file blast radius is back")
    kept = by_file["routes/captcha.ts"]
    assert any(fn.name == "verifyCaptcha" for fn in kept.functions)
    assert any(edge[2] == "eval" for edge in kept.call_edges)
    assert kept.reflection_facts == []
    # Counted, not silent.
    assert COUNTERS.get("s0_reflection_extract_failed_files") > failed_before


# ── sibling enrichment extractors get the same containment ──────────────────

@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
@pytest.mark.parametrize("registry_name,counter", [
    ("_FRAMEWORK_MARKER_EXTRACTORS", "s0_framework_extract_failed_files"),
    ("_RESPONSE_DATAFLOW_EXTRACTORS", "s0_response_extract_failed_files"),
    ("_FIELD_FACT_EXTRACTORS", "s0_field_fact_extract_failed_files"),
])
def test_enrichment_extractor_crash_keeps_file_in_index(
        tmp_path, monkeypatch, registry_name, counter):
    # Every registry-driven enrichment pass is enrichment like reflection
    # facts; a crash in any of them must degrade to "file kept", never reach
    # the whole-file handler in _scan_repo.
    def _explode(src, tree):
        raise RuntimeError("synthetic enrichment extractor failure")

    registry = getattr(scan_mod, registry_name)
    monkeypatch.setitem(registry, "typescript", _explode)

    repo = _write_ts_repo(tmp_path)
    failed_before = COUNTERS.get(counter)

    indices = callgraph_engine._scan_repo(
        repo_root=str(repo),
        in_scope={"routes/captcha.ts"},
        source_specs=[],
        sink_specs=[],
        keep_predicate=lambda idx: bool(idx.functions),
    )

    by_file = {fi.file: fi for fi in indices}
    assert "routes/captcha.ts" in by_file
    assert any(fn.name == "verifyCaptcha"
               for fn in by_file["routes/captcha.ts"].functions)
    assert COUNTERS.get(counter) > failed_before


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_bridge_signal_crash_keeps_file_in_index(tmp_path, monkeypatch):
    # Bridge-signal extraction is not registry-driven, so it needs its own
    # case: it is the first enrichment pass to run after the index is built,
    # and before containment it evicted the whole file on any failure.
    def _explode(language, rel, calls):
        raise RuntimeError("synthetic bridge-signal failure")

    monkeypatch.setattr(scan_mod, "_extract_bridge_signals", _explode)

    repo = _write_ts_repo(tmp_path)
    failed_before = COUNTERS.get("s0_bridge_extract_failed_files")

    indices = callgraph_engine._scan_repo(
        repo_root=str(repo),
        in_scope={"routes/captcha.ts"},
        source_specs=[],
        sink_specs=[],
        keep_predicate=lambda idx: bool(idx.functions),
    )

    by_file = {fi.file: fi for fi in indices}
    assert "routes/captcha.ts" in by_file
    assert any(fn.name == "verifyCaptcha"
               for fn in by_file["routes/captcha.ts"].functions)
    assert COUNTERS.get("s0_bridge_extract_failed_files") > failed_before


# ── whole-file failures stay caught, but are now counted and labeled ────────

@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_whole_file_scan_failure_is_counted_and_scan_continues(
        tmp_path, monkeypatch, capsys):
    # The outer safety net must survive: a scan_file crash skips the file
    # without killing the scan — and the loss is tallied and the log line
    # names the whole-file case explicitly.
    def _explode(*a, **kw):
        raise RuntimeError("synthetic whole-file scan failure")

    monkeypatch.setattr(callgraph_engine, "scan_file", _explode)

    repo = _write_ts_repo(tmp_path)
    dropped_before = COUNTERS.get("s0_files_dropped_scan_error")

    indices = callgraph_engine._scan_repo(
        repo_root=str(repo),
        in_scope={"routes/captcha.ts"},
        source_specs=[],
        sink_specs=[],
        keep_predicate=lambda idx: True,
    )

    assert indices == []
    assert COUNTERS.get("s0_files_dropped_scan_error") > dropped_before
    err = capsys.readouterr().err
    assert "whole file dropped from seed index" in err


# ── JS/TS reflection dispatch: three unreachable branches ───────────────────
# _js_extract_reflection_facts detected only eval()/Function(). Two of its three
# detectors were dead code:
#   * require(variable) sat behind `elif fn_node.type == "identifier"` chained
#     after an `if` on the identical condition, so every identifier call took
#     the first branch;
#   * obj[method]() sat behind `elif node.type == "call_expression"` chained
#     after an `if` on the same node type — never true.
# A third defect returned early from the whole subtree when a call_expression
# had no `function` field, abandoning recursion into nested calls.
# This matters for real JS apps: dynamic require and subscript dispatch are the
# two idiomatic ways JS reaches code by name, i.e. exactly what reflection
# facts exist to record.

_JS_REFLECTION_SOURCE = (
    "function a(x){ return eval(x); }\n"
    "function b(name){ const m = require(name); return m; }\n"
    "function c(obj, key){ return obj[key](); }\n"
)


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
@pytest.mark.parametrize("grammar", ["javascript", "typescript"])
def test_js_reflection_detects_eval_require_and_subscript(grammar):
    # Both grammars must behave identically: LANG_PLUGINS points the typescript
    # entry at the same extractor, so a node-name divergence would silently cost
    # every .ts file its reflection facts.
    src = _JS_REFLECTION_SOURCE.encode("utf-8")
    tree = get_parser(grammar).parse(src)

    facts = scan_mod._js_extract_reflection_facts(src, tree)

    assert len(facts) == 3, (
        f"expected eval + require + subscript, got "
        f"{[(f.line, f.call_type, f.target_symbols) for f in facts]}")
    by_line = {f.line: f for f in facts}
    assert by_line[1].call_type == "invoke"          # eval(x)
    assert by_line[2].call_type == "construct"       # require(name)
    assert by_line[2].target_symbols == ["name"]
    assert by_line[3].call_type == "invoke"          # obj[key]()
    assert by_line[3].target_symbols == ["key"]
    assert by_line[3].receiver == "obj"
    # Every fact carries the schema's javascript label, .ts included.
    assert {f.language for f in facts} == {"javascript"}


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_js_reflection_recurses_into_nested_calls():
    # Guards the early-`return` defect: a reflection sink nested inside another
    # call must still be found.
    src = b"function d(cb){ setTimeout(function(){ return eval(cb); }, 10); }\n"
    tree = get_parser("javascript").parse(src)

    facts = scan_mod._js_extract_reflection_facts(src, tree)

    assert len(facts) == 1, "nested eval() inside a callback was not visited"
    assert facts[0].call_type == "invoke"


# ── JS/TS extraction gaps that silently shrank the analysed surface ─────────

@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
@pytest.mark.parametrize("expr,label", [
    ("eval(req.query.expr)", "member_expression"),
    ("eval(a + b)", "binary_expression"),
    ("eval(x)", "identifier"),
    ("eval('1+1')", "string literal"),
])
def test_eval_reflection_fact_records_every_argument_shape(expr, label):
    """The argument allow-list was inverted with respect to risk.

    It accepted identifier/string/template_string and skipped everything else,
    so eval("1+1") — a constant that cannot be attacker-controlled — produced a
    fact while eval(req.query.expr) and eval(a + b) produced none. Those two are
    the shapes real tainted eval takes in JS, so the filter suppressed exactly
    the sinks worth reporting. Deciding whether the argument is truly tainted is
    the taint engine's job; this pass only records that the site exists.
    """
    src = f"function h(req, a, b, x) {{ return {expr}; }}\n".encode("utf-8")
    tree = get_parser("javascript").parse(src)

    facts = scan_mod._js_extract_reflection_facts(src, tree)

    assert len(facts) == 1, f"{label} argument produced no reflection fact"


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_eval_with_no_arguments_is_not_a_reflection_fact():
    src = b"function h(){ return eval(); }\n"
    facts = scan_mod._js_extract_reflection_facts(
        src, get_parser("javascript").parse(src))
    assert facts == []


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
@pytest.mark.parametrize("grammar", ["javascript", "typescript"])
def test_function_expression_assigned_to_a_variable_is_extracted(grammar):
    # tree-sitter names this node "function_expression"; the variable_declarator
    # branch listed only ("arrow_function", "function"), so `const f = function
    # () {}` yielded no FuncDef even though the class-field branch handled it.
    src = (b"const f = function(){ return 1; };\n"
           b"const g = function named(){ return 2; };\n"
           b"const h = () => 3;\n")
    _, functions, _, _, _, _ = scan_mod._js_extract(
        src, get_parser(grammar).parse(src))

    assert {fn.name for fn in functions} == {"f", "g", "h"}


_TSX_COMPONENT = (
    "export default function Page() {\n"
    "  const onClick = (e) => { helper(e.target.value); };\n"
    "  return <div onClick={onClick}>{helper(1)}</div>;\n"
    "}\n"
    "function helper(x){ return fetch(\"/api?x=\" + x); }\n"
)


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_tsx_file_is_parsed_with_the_tsx_grammar(tmp_path):
    """EXT_TO_LANG folds .tsx into "typescript", but the typescript grammar
    rejects JSX: the component parses with has_error and error recovery
    swallows most of the file (measured: 1 of 3 functions, the default-exported
    component among the losses). scan_file must select the tsx grammar for .tsx
    while keeping language="typescript" so downstream language keying is
    unchanged.
    """
    f = tmp_path / "Page.tsx"
    f.write_text(_TSX_COMPONENT, encoding="utf-8")

    idx = scan_file(abs_path=f, rel="src/Page.tsx", language="typescript",
                    source_specs=[], sink_specs=[])

    assert idx is not None
    assert {fn.name for fn in idx.functions} == {"Page", "onClick", "helper"}
    # The language label must NOT become "tsx" — only the grammar changed.
    assert idx.language == "typescript"


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_plain_ts_file_still_uses_the_typescript_grammar(tmp_path):
    # Guard the narrowness of the .tsx branch: a .ts file with TS-only syntax
    # (which the tsx grammar also accepts, but which must not change behaviour)
    # keeps working.
    f = tmp_path / "svc.ts"
    f.write_text("export function add(a: number, b: number): number "
                 "{ return a + b; }\n", encoding="utf-8")

    idx = scan_file(abs_path=f, rel="src/svc.ts", language="typescript",
                    source_specs=[], sink_specs=[])

    assert idx is not None
    assert {fn.name for fn in idx.functions} == {"add"}
    assert idx.language == "typescript"


# ── anonymous handlers: the dominant Express/Koa/Fastify shape ───────────────
# _js_extract created a FuncDef only for declarations, methods, and functions
# assigned to a `const`. Handlers passed inline as call arguments, returned from
# a factory, or assigned to `module.exports` owned NO function, so a sink inside
# a route handler could not be attributed to a reviewable unit and the entry
# point degraded to a synthetic "<line-N>" name. Measured on a ~900-file Express
# target: 0 framework entry points and 0 taint evidence, while function
# extraction otherwise looked healthy — the real attack surface was invisible.

_EXPRESS_ROUTES = (
    "const express = require('express');\n"
    "const router = express.Router();\n"
    "router.get('/products', (req, res) => { db.query('S ' + req.query.q); });\n"
    "router.post('/feedback', authMw, function (req, res) "
    "{ eval(req.body.expr); });\n"
    "module.exports = function searchProducts() {\n"
    "  return (req, res) => { child_process.exec('ls ' + req.query.dir); };\n"
    "};\n"
    "function named(x){ return x; }\n"
)


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
@pytest.mark.parametrize("grammar", ["javascript", "typescript"])
def test_inline_returned_and_assigned_handlers_all_get_functions(grammar):
    src = _EXPRESS_ROUTES.encode("utf-8")
    _, functions, _, _, _, _ = scan_mod._js_extract(
        src, get_parser(grammar).parse(src))

    names = {f.name for f in functions}
    # Inline argument handlers, named after callee + route so they stay greppable
    # rather than becoming an opaque <anon>.
    assert "get(/products)" in names
    assert "post(/feedback)" in names
    # Assigned-not-declared function, and the handler it returns.
    assert "searchProducts" in names
    assert "searchProducts>handler" in names
    # The ordinary declaration still works.
    assert "named" in names
    # Pre-fix this file yielded exactly one function.
    assert len(functions) >= 5


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_handler_spans_cover_their_body_so_sinks_can_be_attributed():
    """The point of the FuncDef is attribution: a sink inside the handler must
    fall inside that handler's line span, otherwise it is credited to no
    function and the reflection/taint guards mis-handle it."""
    src = _EXPRESS_ROUTES.encode("utf-8")
    _, functions, calls, _, _, _ = scan_mod._js_extract(
        src, get_parser("javascript").parse(src))

    by_name = {f.name: f for f in functions}
    h = by_name["get(/products)"]
    # db.query on line 3 sits inside the handler declared on line 3.
    q = [c for c in calls if c[2] == "query"]
    assert q, "db.query call not extracted"
    assert h.start_line <= q[0][0] <= h.end_line

    ex = by_name["searchProducts>handler"]
    e = [c for c in calls if c[2] == "exec"]
    assert e, "child_process.exec call not extracted"
    assert ex.start_line <= e[0][0] <= ex.end_line


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_multiple_inline_handlers_on_one_call_are_disambiguated():
    # `app.use(a, b)` with two inline handlers must not collide on one name.
    src = b"app.use((req,res,next)=>{next();}, (err,req,res,next)=>{log(err);});\n"
    _, functions, _, _, _, _ = scan_mod._js_extract(
        src, get_parser("javascript").parse(src))
    names = [f.name for f in functions]
    assert len(names) == len(set(names)), f"duplicate handler names: {names}"
    assert len(names) == 2


# ── Express framework markers on TypeScript ─────────────────────────────────
# Measured on a ~900-file Express/TypeScript app: 0 framework markers and 4
# framework entry points, against 126 for a comparable Django app. Three causes,
# all in _js_extract_framework_markers:
#   * middleware detection matched only bare `identifier` parameters, but
#     TypeScript wraps each parameter in required_parameter/optional_parameter,
#     so NO parameter was ever found in a .ts file;
#   * the route branch accepted only a named identifier as the handler, ignoring
#     the inline-arrow form that dominates Express;
#   * unnamed handlers became "<anonymous>", an entry point that matches no
#     function and therefore cannot be bound, analysed or reported.

@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
@pytest.mark.parametrize("grammar", ["javascript", "typescript"])
def test_inline_route_handler_produces_a_marker_and_route_fact(grammar):
    src = b"app.get('/x', (req, res) => { res.send(req.query.q); });\n"
    markers, routes = scan_mod._js_extract_framework_markers(
        src, get_parser(grammar).parse(src))

    assert markers, "inline arrow handler produced no framework marker"
    assert routes, "inline arrow handler produced no route fact"
    # Both branches must agree on one name, and it must be the same label
    # _js_extract gives the FuncDef for that node, or the marker binds to nothing.
    assert {m.function_qnode for m in markers} == {"get(/x)"}
    assert routes[0].route_pattern == "/x"


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_typescript_typed_parameters_are_recognised_as_middleware():
    # required_parameter, not identifier — the defect that silenced every .ts file.
    src = (b"function mw(req: Request, res: Response, next: NextFunction)"
           b"{ next(); }\n")
    markers, _ = scan_mod._js_extract_framework_markers(
        src, get_parser("typescript").parse(src))

    assert [m.function_qnode for m in markers] == ["mw"]
    assert "req" in markers[0].parameter_names


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_unnameable_handler_is_skipped_not_recorded_as_anonymous():
    """An entry point that matches no function is worse than none: it inflates
    the count with something no later stage can bind or analyse."""
    src = b"const t = [(req, res) => { res.end(); }];\n"
    markers, _ = scan_mod._js_extract_framework_markers(
        src, get_parser("typescript").parse(src))

    assert markers == []
    assert not any(m.function_qnode == "<anonymous>" for m in markers)


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_marker_name_matches_the_funcdef_name_for_the_same_node():
    """The marker and the FuncDef must agree, since _emit_framework_entry_points
    keys entry points on the marker's qnode and downstream binds by function."""
    src = b"router.post('/feedback', (req, res) => { save(req.body); });\n"
    tree = get_parser("typescript").parse(src)
    markers, _ = scan_mod._js_extract_framework_markers(src, tree)
    _, functions, _, _, _, _ = scan_mod._js_extract(src, tree)

    assert {m.function_qnode for m in markers} <= {f.name for f in functions}


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_factory_registered_route_binds_across_files():
    """`app.get('/x', search())` — the handler is what search() RETURNS, defined
    in another module. All three producers must agree on one name or the route,
    the marker and the function never join up:

      server.ts        route fact + marker  -> search>handler
      routes/search.ts marker               -> search>handler
      routes/search.ts FuncDef              -> search>handler

    Measured before this: 2 route facts across 61 route files, on an app whose
    handlers are registered this way throughout.
    """
    p = get_parser("typescript")
    server = b"app.get('/rest/products/search', search());\n"
    factory = (b"export function search() {\n"
               b"  return (req: Request, res: Response) => {\n"
               b"    db.query('SELECT * FROM p WHERE n LIKE ' + req.query.q);\n"
               b"  };\n"
               b"}\n")

    s_markers, s_routes = scan_mod._js_extract_framework_markers(
        server, p.parse(server))
    assert [r.function_qnode for r in s_routes] == ["search>handler"]
    assert [r.route_pattern for r in s_routes] == ["/rest/products/search"]
    assert "search>handler" in {m.function_qnode for m in s_markers}

    f_markers, _ = scan_mod._js_extract_framework_markers(
        factory, p.parse(factory))
    _, functions, _, _, _, _ = scan_mod._js_extract(factory, p.parse(factory))

    assert "search>handler" in {m.function_qnode for m in f_markers}
    assert {"search", "search>handler"} <= {f.name for f in functions}
    # The tainted request parameter must be on the RETURNED function, since that
    # is where the sink lives.
    inner = next(m for m in f_markers if m.function_qnode == "search>handler")
    assert "req" in inner.parameter_names


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_returned_handler_marker_is_not_dropped_as_unnameable():
    """Regression guard: skipping unnameable handlers must not also skip the
    returned-factory handler, which IS nameable via its enclosing function."""
    src = (b"function makeHandler() { return (req, res) => { res.end(); }; }\n")
    markers, _ = scan_mod._js_extract_framework_markers(
        src, get_parser("typescript").parse(src))
    assert [m.function_qnode for m in markers] == ["makeHandler>handler"]


# ── request-property reads as source hits: the taint-evidence blocker ────────
# Every other source in the engine is a CALL: scan_file's call loop matches
# receiver.method against source specs and appends to source_hits, and
# build_taint_paths seeds taint EXCLUSIVELY from those hits. A JS request input is
# a member READ, so it could never enter that path — it never appears in `calls`,
# never becomes an annotator candidate (measured: 0 of 74 candidates on 20 Express
# route files had receiver `req`), and would not match _match_call even given a
# spec. Taint evidence on an Express app was therefore NECESSARILY zero, whatever
# the specs, thresholds or handler extraction did.

@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_request_property_read_becomes_a_source_hit(tmp_path):
    f = tmp_path / "search.ts"
    f.write_text("export function search() {\n"
                 "  return (req: Request, res: Response) => {\n"
                 "    db.query('S ' + req.query.q);\n"
                 "  };\n"
                 "}\n", encoding="utf-8")

    idx = scan_file(abs_path=f, rel="routes/search.ts", language="typescript",
                    source_specs=[], sink_specs=[])

    srcs = [h for h in idx.source_hits if h.role == "source"]
    assert [(h.receiver, h.method) for h in srcs] == [("req", "query")]
    assert srcs[0].matched_rule == "js-request-property"


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_source_and_sink_in_one_handler_share_a_containing_fn(tmp_path):
    """The scope label must be the QNODE form, matching _js_extract.

    _graph._fn_id keys taint on containing_fn, so a bare name on the source and a
    qnode on the sink would file two hits from the SAME function under different
    ids — the source would be recorded and then silently connect to nothing. That
    is exactly the bug this pins.
    """
    f = tmp_path / "inline.ts"
    f.write_text("router.get('/x', (req: Request, res: Response) => {\n"
                 "  db.query('S ' + req.params.id);\n"
                 "});\n", encoding="utf-8")

    idx = scan_file(abs_path=f, rel="routes/inline.ts", language="typescript",
                    source_specs=[], sink_specs=[])

    src = next(h for h in idx.source_hits if h.receiver == "req")
    assert src.containing_fn == "get(/x)(req, res)"
    assert src.containing_fn in {fn.qnode for fn in idx.functions}


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_only_known_request_properties_count(tmp_path):
    # A narrow receiver/property set keeps an unrelated local named `req` from
    # producing a wave of false sources.
    f = tmp_path / "x.ts"
    f.write_text("function h(req, res){ log(req.id); log(req.query.q); }\n",
                 encoding="utf-8")
    idx = scan_file(abs_path=f, rel="x.ts", language="typescript",
                    source_specs=[], sink_specs=[])
    assert [(h.receiver, h.method) for h in idx.source_hits] == [("req", "query")]


@pytest.mark.skipif(get_parser is None, reason="tree-sitter backend unavailable")
def test_two_anonymous_callbacks_on_one_callee_get_distinct_qnodes(tmp_path):
    """Anonymous inline callbacks must not share a qnode within a file.

    `idx` disambiguates only within ONE argument list, so two separate calls to
    the same callee both produced `query(err, rows)`. A shared qnode is a shared
    `_fn_id`, and `_graph.build_taint_paths` pairs a source with a sink whenever
    they agree on one — so a `req.*` read in one callback was reported as
    flowing into an unrelated callback's sink. That is a FABRICATED taint path
    reaching the report as a phantom injection finding, which is worse than a
    missed one. A string-literal first argument (a route path) normally keeps
    these apart, so only the literal-free shape collides.
    """
    f = tmp_path / "collide.js"
    f.write_text("function handlerA(req, res) {\n"
                 "  const sql = 'SELECT 1';\n"
                 "  db.query(sql, (err, rows) => { res.send(req.query.q); });\n"
                 "}\n"
                 "function handlerB(reqB, resB) {\n"
                 "  const sql2 = 'SELECT 2';\n"
                 "  db.query(sql2, (err, rows) => { db.run('D ' + rows.id); });\n"
                 "}\n", encoding="utf-8")

    idx = scan_file(abs_path=f, rel="collide.js", language="javascript",
                    source_specs=[], sink_specs=[])

    qnodes = [fn.qnode for fn in idx.functions]
    assert len(qnodes) == len(set(qnodes)), f"colliding qnodes: {qnodes}"

    # The source and the sink sit in DIFFERENT callbacks, so their scope labels
    # must differ — that inequality is what stops the fabricated pairing.
    src = next(h for h in idx.source_hits if h.receiver == "req")
    run_hits = [h for h in idx.sink_hits or [] if h.method == "run"]
    if run_hits:
        assert src.containing_fn != run_hits[0].containing_fn

    # The route-literal labels other consumers grep for must stay untouched.
    g = tmp_path / "route.js"
    g.write_text("app.get('/products', (req, res) => { res.send(1); });\n",
                 encoding="utf-8")
    idx2 = scan_file(abs_path=g, rel="route.js", language="javascript",
                     source_specs=[], sink_specs=[])
    assert "get(/products)(req, res)" in {fn.qnode for fn in idx2.functions}
