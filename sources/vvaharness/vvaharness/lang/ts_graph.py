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
tree-sitter call-graph backend for ``step1.call_graph: tree_sitter``.

Drop-in alternative to ``s1_preprocess._supplement_call_graph`` with the same
output contract on ``data``::

    data["call_graph"]       = {qnode: [qnode, …]}      # qnode = "rel/path::name"
    data["call_graph_files"] = {bare_name: ["rel/path:line", …]}
    data["def_spans"]        = {qnode: [start_line, end_line]}   # NEW (Phase-4 slicing)

Design notes
------------
* **Per-language queries** live in ``_QUERIES`` below — one ``defs`` query
  capturing ``@name`` (the identifier) and ``@def`` (the whole function node,
  for span/byte-range), and one ``calls`` query capturing ``@callee``.
* **Enclosing-def resolution** is byte-range based: each call site is mapped to
  the *innermost* def whose ``[start_byte, end_byte)`` contains it. That's
  exact for AST-derived ranges (regex couldn't do this — it had no end-of-def).
* **Cross-file callee resolution** reuses ``_resolve_callee_files`` from
  ``s1_preprocess`` so polymorphic-name handling stays identical to the regex
  path (same-file > unique > longest-common-dir-prefix, capped at
  ``call_graph_max_targets``).
* **Graceful degrade** at three levels: (1) if ``tree-sitter-language-pack`` is
  not installed the whole backend returns ``False`` and the caller falls back
  to regex; (2) if a language has no query entry, that file falls back to
  regex ``_scan_defs``/``_CALL_TOKEN_RX``; (3) if a query fails to compile
  against the installed grammar version, that language is disabled for the run
  with a single warning.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

from vvaharness.lang.hints import EXT_TO_LANG
from vvaharness.pipeline.stages.s1_preprocess import (
    _CALL_TOKEN_RX,
    _NOT_A_DEF,
    MODULE_SCOPE,
    _resolve_callee_files,
    _scan_defs,
    q_join,
    q_name,
    q_split,
)

_TS_ERR: str | None = None
try:  # pragma: no cover - import guarded
    from tree_sitter_language_pack import get_language, get_parser
except Exception as _e:  # noqa: BLE001
    get_parser = get_language = None  # type: ignore[assignment]
    _TS_ERR = repr(_e)
try:  # pragma: no cover - only present on tree-sitter >=0.23
    from tree_sitter import Query as _TSQuery
    from tree_sitter import QueryCursor as _TSQueryCursor
except Exception:  # noqa: BLE001
    _TSQuery = _TSQueryCursor = None  # type: ignore[assignment]


# Keys are vvaharness language ids (EXT_TO_LANG values). ``grammar`` is the
# name passed to tree-sitter-language-pack. Queries are intentionally
# permissive — false-positive callees are pruned by the def-site lookup, same
# as the regex path.
_QUERIES: dict[str, dict] = {
    "python": {
        "grammar": "python",
        "defs": "(function_definition name: (identifier) @name) @def",
        "calls": """
            (call function: [
              (identifier) @callee
              (attribute attribute: (identifier) @callee)
            ])""",
    },
    "java": {
        "grammar": "java",
        "defs": """
            (class_declaration name: (identifier) @name) @def
            (method_declaration name: (identifier) @name) @def
            (constructor_declaration name: (identifier) @name) @def""",
        "calls": """
            (method_invocation name: (identifier) @callee)
            (object_creation_expression type: (type_identifier) @ctor_type)
            (object_creation_expression type: (scoped_type_identifier) @ctor_type)
            (object_creation_expression type: (generic_type (type_identifier) @ctor_type))
            (method_reference) @method_ref""",
    },
    "kotlin": {
        "grammar": "kotlin",
        "defs": "(function_declaration (simple_identifier) @name) @def",
        "calls": """
            (call_expression [
              (simple_identifier) @callee
              (navigation_expression (navigation_suffix
                  (simple_identifier) @callee))
            ])""",
    },
    "javascript": {
        "grammar": "javascript",
        "defs": """
            (function_declaration name: (identifier) @name) @def
            (method_definition name: (property_identifier) @name) @def
            (variable_declarator name: (identifier) @name
                value: [(arrow_function) (function_expression)]) @def""",
        "calls": """
            (call_expression function: [
              (identifier) @callee
              (member_expression property: (property_identifier) @callee)
            ])""",
    },
    "typescript": {
        "grammar": "typescript",
        "defs": """
            (function_declaration name: (identifier) @name) @def
            (method_definition name: (property_identifier) @name) @def
            (variable_declarator name: (identifier) @name
                value: [(arrow_function) (function_expression)]) @def""",
        "calls": """
            (call_expression function: [
              (identifier) @callee
              (member_expression property: (property_identifier) @callee)
            ])""",
    },
    "go": {
        "grammar": "go",
        "defs": """
            (function_declaration name: (identifier) @name) @def
            (method_declaration name: (field_identifier) @name) @def""",
        "calls": """
            (call_expression function: [
              (identifier) @callee
              (selector_expression field: (field_identifier) @callee)
            ])""",
    },
    "c": {
        "grammar": "c",
        "defs": """
            (function_definition declarator:
              (function_declarator declarator: (identifier) @name)) @def""",
        "calls": "(call_expression function: (identifier) @callee)",
    },
    "cpp": {
        "grammar": "cpp",
        "defs": """
            (function_definition declarator:
              (function_declarator declarator:
                [(identifier) @name
                 (qualified_identifier name: (identifier) @name)
                 (field_identifier) @name])) @def""",
        "calls": """
            (call_expression function: [
              (identifier) @callee
              (field_expression field: (field_identifier) @callee)
              (qualified_identifier name: (identifier) @callee)
            ])""",
    },
    "csharp": {
        "grammar": "c_sharp",
        "defs": """
            (class_declaration name: (identifier) @name) @def
            (struct_declaration name: (identifier) @name) @def
            (interface_declaration name: (identifier) @name) @def
            (method_declaration name: (identifier) @name) @def
            (constructor_declaration name: (identifier) @name) @def
            (local_function_statement name: (identifier) @name) @def""",
        "calls": """
            (invocation_expression function: [
              (identifier) @callee
              (member_access_expression name: (identifier) @callee)
            ])
            (object_creation_expression type: (identifier) @ctor_type)
            (object_creation_expression type: (qualified_name) @ctor_type)
            (object_creation_expression type: (generic_name (identifier) @ctor_type))
            (query_expression) @linq_query""",
    },
    "ruby": {
        "grammar": "ruby",
        "defs": """
            (method name: (identifier) @name) @def
            (singleton_method name: (identifier) @name) @def""",
        "calls": "(call method: (identifier) @callee)",
    },
    "php": {
        "grammar": "php",
        "defs": """
            (function_definition name: (name) @name) @def
            (method_declaration name: (name) @name) @def""",
        "calls": """
            (function_call_expression function: (name) @callee)
            (member_call_expression name: (name) @callee)
            (scoped_call_expression name: (name) @callee)""",
    },
    "rust": {
        "grammar": "rust",
        "defs": "(function_item name: (identifier) @name) @def",
        "calls": """
            (call_expression function: [
              (identifier) @callee
              (field_expression field: (field_identifier) @callee)
              (scoped_identifier name: (identifier) @callee)
            ])""",
    },
    "swift": {
        "grammar": "swift",
        "defs": "(function_declaration name: (simple_identifier) @name) @def",
        "calls": """
            (call_expression [
              (simple_identifier) @callee
              (navigation_expression suffix:
                (navigation_suffix suffix: (simple_identifier) @callee))
            ])""",
    },
    "scala": {
        "grammar": "scala",
        "defs": """
            (function_definition name: (identifier) @name) @def
            (val_definition pattern: (identifier) @name
                value: [(lambda_expression) (block)]) @def""",
        "calls": """
            (call_expression function: [
              (identifier) @callee
              (field_expression field: (identifier) @callee)
            ])""",
    },
}

# TSX shares TypeScript's node names, so it needs the same queries against a
# different grammar. Derived rather than copied so the two cannot drift.
_QUERIES["tsx"] = {**_QUERIES["typescript"], "grammar": "tsx"}


def available() -> bool:
    return get_parser is not None


_cache: dict[str, tuple | None] = {}
_warned: set[str] = set()


def _normalize_lang_for_queries(rel: str, lang: str) -> str:
    """Map broad EXT_TO_LANG ids to concrete _QUERIES keys.

    ``EXT_TO_LANG`` intentionally groups C and C++ under ``c-cpp`` for
    family-level behavior, and folds ``.tsx`` into ``typescript``. The AST query
    table is keyed by concrete grammars (``c``/``cpp``, ``typescript``/``tsx``),
    so resolve by file suffix before query lookup.

    The ``.tsx`` case is not cosmetic: the ``typescript`` grammar does not accept
    JSX, so a React/Next component parses with errors and recovery swallows most
    of the file. The return value is used only to pick the parser and query set;
    the caller keeps its own language label.
    """
    if lang == "typescript" and Path(rel).suffix.lower() == ".tsx":
        return "tsx"
    if lang != "c-cpp":
        return lang
    suf = Path(rel).suffix.lower()
    if suf in {".cc", ".cpp", ".cxx", ".hpp"}:
        return "cpp"
    return "c"


def _text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _normalize_type(raw: str) -> str:
    txt = str(raw or "").strip()
    txt = re.sub(r"<[^>]*>", "", txt)
    txt = txt.replace("[]", "").strip()
    if not txt:
        return ""
    return txt.split(".")[-1].split()[-1]


def _simple_name(sym: str) -> str:
    base = str(sym or "").strip()
    if not base:
        return ""
    base = base.split("(", 1)[0]
    base = base.split("::", 1)[-1]
    base = base.rsplit(".", 1)[-1]
    return base


def _enclosing_class_path(node) -> str:
    names: list[str] = []
    cur = node.parent
    while cur is not None:
        if cur.type in {"class_declaration", "struct_declaration", "interface_declaration"}:
            n = cur.child_by_field_name("name")
            if n is not None:
                names.append(n.text.decode("utf-8", "replace"))
        cur = cur.parent
    names.reverse()
    return ".".join(names)


def _java_param_sig(def_node, src: bytes) -> str:
    params = def_node.child_by_field_name("parameters")
    if params is None:
        return "()"
    out: list[str] = []
    for p in params.named_children:
        if p.type not in {"formal_parameter", "spread_parameter"}:
            continue
        tn = p.child_by_field_name("type")
        out.append(_normalize_type(_text(src, tn)) if tn is not None else "")
    return "(" + ", ".join(out) + ")"


def _cs_param_sig(def_node, src: bytes) -> str:
    params = def_node.child_by_field_name("parameters")
    if params is None:
        return "()"
    out: list[str] = []
    for p in params.named_children:
        if p.type != "parameter":
            continue
        tn = p.child_by_field_name("type")
        out.append(_normalize_type(_text(src, tn)) if tn is not None else "")
    return "(" + ", ".join(out) + ")"


def _qnode_for_def(lang: str, name: str, def_node, src: bytes) -> str:
    if lang == "java":
        cls = _enclosing_class_path(def_node)
        prefix = f"{cls}." if cls else ""
        return f"{prefix}{name}{_java_param_sig(def_node, src)}"
    if lang == "csharp":
        cls = _enclosing_class_path(def_node)
        prefix = f"{cls}." if cls else ""
        return f"{prefix}{name}{_cs_param_sig(def_node, src)}"
    return name


def _normalize_ctor_type(raw: str) -> str:
    txt = _normalize_type(raw)
    if txt:
        return txt
    return ""


def _captures(query, node):
    """tree-sitter API shim across three generations, normalised to
    list[(Node, name)]:
      • 0.20/0.21 — ``Query.captures(node) -> list[(Node, name)]``
      • 0.22      — ``Query.captures(node) -> dict[name, list[Node]]``
      • ≥0.23     — ``Query.captures`` removed; use ``QueryCursor(query)
                     .captures(node) -> dict[name, list[Node]]``.
    """
    cap = getattr(query, "captures", None)
    if cap is not None:
        out = cap(node)
    elif _TSQueryCursor is not None:
        out = _TSQueryCursor(query).captures(node)
    else:  # pragma: no cover — unreachable if any supported tree-sitter is present
        raise RuntimeError("tree-sitter Query API unsupported")
    if isinstance(out, dict):
        return [(n, name) for name, nodes in out.items() for n in nodes]
    return list(out)


def _compile(lang: str):
    """Return (parser, defs_query, calls_query) or None if unavailable."""
    if lang in _cache:
        return _cache[lang]
    spec = _QUERIES.get(lang)
    if not spec or get_parser is None:
        _cache[lang] = None
        return None
    try:
        parser = get_parser(spec["grammar"])
        L = get_language(spec["grammar"])
        # tree-sitter ≥0.23 deprecates Language.query() in favour of the
        # Query(language, source) constructor; fall back for older wheels.
        if _TSQuery is not None:
            qd = _TSQuery(L, spec["defs"])
            qc = _TSQuery(L, spec["calls"])
        else:
            qd = L.query(spec["defs"])
            qc = L.query(spec["calls"])
    except Exception as e:  # noqa: BLE001 - grammar/node-name drift across versions
        if lang not in _warned:
            _warned.add(lang)
            print(f"  [s1] tree-sitter: disabling {lang!r} "
                  f"(query compile failed: {e}); regex fallback for those files",
                  file=sys.stderr)
        _cache[lang] = None
        return None
    _cache[lang] = (parser, qd, qc)
    return _cache[lang]


def _parse_file(rel: str, text: str, lang: str):
    """Return (defs, calls) for one file.

    defs  : list[(simple_name, qnode, start_line, end_line, start_byte, end_byte)]
    calls : list[(callee_name, byte_offset)]

    Falls back to regex when no tree-sitter query is available for ``lang``.
    Regex defs have no end-of-function span — end_line is set to start_line so
    Phase-4 slicing degrades to a single-line anchor (s4's existing
    neighbor_context still pads it).
    """
    bundle = _compile(lang)
    if bundle is None:
        lines = text.splitlines()
        rdefs = _scan_defs(lines)
        defs = [(name, name, ln, ln, -1, -1) for ln, name in rdefs]
        calls = [(m.group(1), m.start()) for m in _CALL_TOKEN_RX.finditer(text)]
        return defs, calls
    parser, qd, qc = bundle
    src = text.encode("utf-8", errors="replace")
    tree = parser.parse(src)
    root = tree.root_node

    # defs: pair each @name with its enclosing @def via match index. The
    # captures list interleaves them per-match in query order; collect by
    # capture name then zip — robust across both API shapes.
    name_nodes: list = []
    def_nodes: list = []
    for node, cap in _captures(qd, root):
        if cap == "name":
            name_nodes.append(node)
        elif cap == "def":
            def_nodes.append(node)

    # When counts mismatch (e.g. an alternative pattern matched @def but the
    # @name branch didn't), associate each @name to the smallest @def that
    # contains it — exact under AST ranges.
    def_ranges = sorted(((d.start_byte, d.end_byte, d) for d in def_nodes),
                        key=lambda t: t[1] - t[0])
    defs: list[tuple[str, str, int, int, int, int]] = []
    for nn in name_nodes:
        name = src[nn.start_byte:nn.end_byte].decode("utf-8", "replace")
        if not name or name in _NOT_A_DEF:
            continue
        host = None
        for sb, eb, d in def_ranges:
            if sb <= nn.start_byte < eb:
                host = d
                break
        if host is None:
            # Skip unmatched names instead of emitting identifier-only spans.
            continue
        qnode = _qnode_for_def(lang, name, host, src)
        defs.append((name, qnode,
                     host.start_point[0] + 1, host.end_point[0] + 1,
                     host.start_byte, host.end_byte))

    calls: list[tuple[str, int]] = []
    for node, cap in _captures(qc, root):
        if cap == "callee":
            name = src[node.start_byte:node.end_byte].decode("utf-8", "replace")
            if name and name not in _NOT_A_DEF and len(name) >= 2:
                calls.append((name, node.start_byte))
        elif cap == "ctor_type":
            name = _normalize_ctor_type(src[node.start_byte:node.end_byte].decode("utf-8", "replace"))
            if name and len(name) >= 1:
                calls.append((name, node.start_byte))
        elif cap == "method_ref":
            raw = src[node.start_byte:node.end_byte].decode("utf-8", "replace")
            name = _simple_name(raw)
            if name and name not in _NOT_A_DEF:
                calls.append((name, node.start_byte))
        elif cap == "linq_query":
            txt = src[node.start_byte:node.end_byte].decode("utf-8", "replace").lower()
            wrapped = f" {txt} "
            if " from " in wrapped:
                calls.append(("From", node.start_byte))
            if " where " in wrapped:
                calls.append(("Where", node.start_byte))
            if " select " in wrapped:
                calls.append(("Select", node.start_byte))
            if " join " in wrapped:
                calls.append(("Join", node.start_byte))
            if " group " in wrapped:
                calls.append(("GroupBy", node.start_byte))
            if " orderby " in wrapped:
                calls.append(("OrderBy", node.start_byte))

    if lang in {"javascript", "typescript"}:
        extra_defs, extra_calls = _js_ts_extra_defs_calls(root, src)
        if extra_defs:
            seen_defs = {(n, qn, sb, eb) for n, qn, _sl, _el, sb, eb in defs}
            for d in extra_defs:
                key = (d[0], d[1], d[4], d[5])
                if key not in seen_defs:
                    defs.append(d)
                    seen_defs.add(key)
        if extra_calls:
            seen_calls = set(calls)
            for c in extra_calls:
                if c not in seen_calls:
                    calls.append(c)
                    seen_calls.add(c)

    return defs, calls


def _first_named_child(node):
    if node is None:
        return None
    for c in getattr(node, "named_children", ()):
        return c
    return None


def _strip_js_string(text: str) -> str:
    return str(text or "").strip().strip('"\'`')


def _js_ts_callee_name(fn_node, src: bytes) -> tuple[str, str]:
    cur = fn_node
    while cur is not None and cur.type == "parenthesized_expression":
        cur = _first_named_child(cur)

    while cur is not None:
        t = cur.type
        if t == "identifier":
            return "", _text(src, cur)
        if t == "member_expression":
            obj = cur.child_by_field_name("object")
            prop = cur.child_by_field_name("property")
            method = _text(src, prop) if prop is not None else ""
            receiver = _text(src, obj) if obj is not None else ""
            return receiver, _strip_js_string(method)
        if t == "subscript_expression":
            obj = cur.child_by_field_name("object")
            idx = cur.child_by_field_name("index")
            receiver = _text(src, obj) if obj is not None else ""
            if idx is None:
                return receiver, ""
            if idx.type in {"identifier", "property_identifier"}:
                return receiver, _text(src, idx)
            return receiver, _strip_js_string(_text(src, idx))
        if t == "call_expression":
            cur = cur.child_by_field_name("function")
            continue
        break
    return "", ""


def _js_ts_extra_defs_calls(root, src: bytes):
    defs: list[tuple[str, str, int, int, int, int]] = []
    calls: list[tuple[str, int]] = []

    def _visit(node):
        t = node.type

        if t in {"public_field_definition", "field_definition", "property_definition"}:
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is None or value_node is None:
                for c in node.named_children:
                    if name_node is None and c.type in {"property_identifier", "identifier"}:
                        name_node = c
                        continue
                    if value_node is None and c.type in {"arrow_function", "function_expression", "function"}:
                        value_node = c
            if (name_node is not None and value_node is not None
                    and value_node.type in {"arrow_function", "function_expression", "function"}):
                name = _text(src, name_node)
                if name and name not in _NOT_A_DEF:
                    defs.append((
                        name,
                        name,
                        value_node.start_point[0] + 1,
                        value_node.end_point[0] + 1,
                        value_node.start_byte,
                        value_node.end_byte,
                    ))

        if t == "call_expression":
            fn = node.child_by_field_name("function")
            _recv, method = _js_ts_callee_name(fn, src)
            if method and method not in _NOT_A_DEF:
                calls.append((method, node.start_byte))

        for c in node.children:
            _visit(c)

    _visit(root)
    return defs, calls


def _enclosing(defs_sorted, byte_off: int) -> str | None:
    """Innermost def name containing byte_off (defs sorted by span width asc)."""
    for _name, qnode, _sl, _el, sb, eb in defs_sorted:
        if sb >= 0 and sb <= byte_off < eb:
            return qnode
    return None


def build(data: dict, all_files: list[str], repo_root: Path, cfg) -> bool:
    """Populate ``data["call_graph"|"call_graph_files"|"def_spans"]`` via
    tree-sitter. Returns ``False`` (and leaves ``data`` untouched) when the
    backend is unavailable so the caller can fall back to the regex
    supplement."""
    if get_parser is None:
        print(f"  [s1] call_graph=tree_sitter requested but "
              f"tree-sitter-language-pack is not installed ({_TS_ERR}); "
              f"falling back to regex. This package is a standard dependency; "
              f"re-run 'pip install .' (or 'pipx install .') to restore it, "
              f"then run 'vvaharness doctor' to verify.", file=sys.stderr)
        return False

    s1 = getattr(cfg, "step1", None)
    max_targets = int(getattr(s1, "call_graph_max_targets", 3)) if s1 else 3

    # First pass: parse every source file once; collect defs (for the global
    # name→files index) and per-file (defs, calls) for the second pass.
    parsed: list[tuple[str, list, list]] = []
    fn_locs: dict[str, set[str]] = defaultdict(set)
    def_files: dict[str, set[str]] = defaultdict(set)
    def_qnodes_by_file_name: dict[tuple[str, str], set[str]] = defaultdict(set)
    def_spans: dict[str, list[int]] = {}
    n_ts = n_rx = 0
    for rel in all_files:
        lang = EXT_TO_LANG.get(Path(rel).suffix.lower())
        if not lang:
            continue
        lang = _normalize_lang_for_queries(rel, lang)
        p = repo_root / rel
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        defs, calls = _parse_file(rel, text, lang)
        if _compile(lang) is not None:
            n_ts += 1
        else:
            n_rx += 1
        for name, qnode, sl, el, _sb, _eb in defs:
            fn_locs[name].add(f"{rel}:{sl}")
            def_files[name].add(rel)
            def_qnodes_by_file_name[(rel, name)].add(qnode)
            qn = q_join(rel, qnode)
            # Union span for overloads in the same file: merge only when the
            # two definitions are adjacent (gap ≤ 50 lines) so far-apart
            # overloads don't engulf unrelated code between them. A far-apart
            # overload wins if its individual span is larger than the existing
            # union (replaces with the larger body as the canonical slice anchor).
            prev = def_spans.get(qn)
            if prev is None:
                def_spans[qn] = [sl, el]
            else:
                gap = sl - prev[1] if sl > prev[1] else prev[0] - el
                if gap <= 50:
                    def_spans[qn] = [min(prev[0], sl), max(prev[1], el)]
                elif (el - sl) > (prev[1] - prev[0]):
                    def_spans[qn] = [sl, el]  # keep larger overload body
        # sort defs by span width asc so _enclosing() returns the innermost
        defs_sorted = sorted(defs, key=lambda d: (d[5] - d[4]) if d[4] >= 0
                             else 1 << 30)
        parsed.append((rel, defs_sorted, calls))

    # Second pass: emit qualified edges.
    cg: dict[str, set[str]] = defaultdict(set)
    n_edges = 0
    for rel, defs_sorted, calls in parsed:
        for callee, off in calls:
            if callee not in def_files:
                continue   # not defined anywhere we scanned → external/builtin
            caller = _enclosing(defs_sorted, off) or MODULE_SCOPE
            if _simple_name(caller) == callee:
                continue
            qcaller = q_join(rel, caller)
            for tf in _resolve_callee_files(callee, rel, def_files, max_targets):
                callee_qnodes = def_qnodes_by_file_name.get((tf, callee)) or {callee}
                for callee_qn in callee_qnodes:
                    qcallee = q_join(tf, callee_qn)
                    if qcallee not in cg[qcaller]:
                        cg[qcaller].add(qcallee)
                        n_edges += 1

    # Preserve existing edges only when both qnode endpoints still resolve to
    # real defs in their original files. This avoids name-only re-grafting on
    # --resume after code movement/renames.
    n_agent = 0
    for k, vs in (data.get("call_graph") or {}).items():
        kf, kn = q_split(k)
        kn_simple = _simple_name(kn)
        if not kf or kn_simple not in def_files or kf not in def_files.get(kn_simple, set()):
            continue
        for v in vs or ():
            vf, vn = q_split(v)
            vn_simple = _simple_name(vn)
            if not vf or vn_simple not in def_files or vf not in def_files.get(vn_simple, set()):
                continue
            qcaller = q_join(kf, kn)
            qcallee = q_join(vf, vn)
            if qcallee not in cg[qcaller]:
                cg[qcaller].add(qcallee)
                n_agent += 1

    data["call_graph"] = {k: sorted(v) for k, v in cg.items() if v}
    relevant = set()
    for k, vs in data["call_graph"].items():
        relevant.add(q_name(k))
        relevant.update(q_name(v) for v in vs)
    # Keep full def-site metadata for all scanned defs. Specialist chunks in S4
    # may focus files/functions that are not on the retained call-graph edge
    # frontier, and aggressive name filtering here starves graph slicing.
    data["call_graph_files"] = {k: sorted(v) for k, v in fn_locs.items()}
    data["def_spans"] = dict(def_spans)

    print(f"  [s1] call-graph (tree-sitter): {n_edges} AST edges "
          f"+ {n_agent} agent-validated = "
          f"{sum(len(v) for v in data['call_graph'].values())} qualified edges "
          f"over {len(data['call_graph'])} nodes; "
          f"{len(data['def_spans'])} def-spans; "
          f"{n_ts} files via AST, {n_rx} via regex fallback",
          file=sys.stderr)
    return True
