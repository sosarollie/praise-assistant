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

"""Per-file tree-sitter scanner. Emits a :class:`FileIndex` containing:

    * imports        — local-name → fully-qualified-name
    * functions      — (name, start_line, end_line, parameters) for scope
                       resolution and later SAST signature use
    * source_hits    — CallSite records matching a source rule
    * sink_hits      — CallSite records matching a sink rule

Language support is pluggable via ``LANG_PLUGINS`` — a dict keyed by
vvaharness language keys (see vvaharness.lang.hints.EXT_TO_LANG). Each plugin
provides tree-sitter queries + a per-node extractor.
"""
from __future__ import annotations

import logging
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

_log = logging.getLogger(__name__)

try:
    from tree_sitter_language_pack import get_parser
except Exception as _e:  # noqa: BLE001
    get_parser = None  # type: ignore[assignment]
    _TS_ERR = repr(_e)
else:
    _TS_ERR = ""

from vvaharness.models import (
    CFG,
    CFGNode,
    FrameworkMarkerFact,
    ReflectionFact,
    ResponseDataflowFact,
    RouteTaintFact,
)
from vvaharness.pipeline.stages.callgraph_engine._rules import MatchSpec
from vvaharness.util.counters import COUNTERS


def _append_reflection_fact(facts: list[ReflectionFact], **kw) -> None:
    """Validate-and-append one reflection fact, containing failures.

    Reflection facts are enrichment on top of the file's functions, calls and
    def-spans. The extractors used to construct ReflectionFact inline, so one
    fact failing validation unwound the whole extractor and — via the per-file
    guard in ``_scan_repo`` — evicted the entire file from the seed index. That
    cost real coverage: ``language="javascript"`` against a then-narrower
    Literal dropped exactly the files holding an app's eval() sinks. A bad fact
    now costs only itself, counted and logged so the loss is never silent.
    """
    try:
        facts.append(ReflectionFact(**kw))
    except Exception as e:  # noqa: BLE001 — any bad fact, never the file
        COUNTERS.bump("s0_reflection_facts_dropped")
        _log.warning(
            "callgraph: dropped 1 reflection fact (scope=%s line=%s): %s",
            kw.get("function_qnode"), kw.get("line"), e)


def _enrich(rel: str, pass_name: str, counter: str, fn):
    """Run one enrichment pass over an already-built FileIndex, containing
    failures. Returns the pass's result, or None if it raised.

    Every caller runs after the index already holds the file's functions, calls
    and def-spans. Letting a tree-walk crash propagate hands the file to
    ``_scan_repo``'s per-file handler, which evicts it from the seed entirely —
    so a bug in a peripheral pass costs the file's real analysis surface.
    Per-pass counters and the pass name in the log keep this distinguishable
    from a whole-file failure and from a sibling pass failing.

    BaseException is deliberately not caught: KeyboardInterrupt and SystemExit
    must still abort the scan rather than look like a missing enrichment.
    """
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 — degrade the pass, never drop the file
        COUNTERS.bump(counter)
        _log.warning(
            "callgraph: %s extraction failed for file=%s: %s "
            "— file kept without %s", pass_name, rel, e, pass_name)
        print(f"  [s0/callgraph] {pass_name} extraction failed for {rel}: {e}"
              f" — file kept, {pass_name} skipped", file=sys.stderr)
        return None


# Cache tree-sitter parser instances per language to avoid redundant O(n)
# re-instantiation when scanning n files of the same language.
_PARSERS: dict[str, object] = {}


def _get_cached_parser(ts_language: str):
    """Return cached parser for the given tree-sitter language.
    
    First call instantiates via get_parser(); subsequent calls return the cached
    instance. This eliminates per-file parser allocation overhead and enforces
    the "one parser per language" invariant.
    """
    if ts_language not in _PARSERS:
        _PARSERS[ts_language] = get_parser(ts_language)
    return _PARSERS[ts_language]


@dataclass
class CallSite:
    file: str                    # repo-relative path
    line: int                    # 1-based
    receiver: str                # leftmost identifier of the call expression
    method: str                  # attribute name (or bare function name)
    containing_fn: str           # nearest enclosing function name ("" = module)
    snippet: str                 # ~120 chars
    matched_rule: str            # MatchSpec.rule_id
    cwe: str                     # from MatchSpec.cwe
    role: str                    # "source" | "sink"
    kind: str                    # ep_kind / sink_kind
    semantic_family: str = ""
    owasp_top10_2025: tuple[str, ...] = ()


@dataclass
class FuncDef:
    name: str                    # bare function name (no class scope for MVP)
    start_line: int              # 1-based
    end_line: int
    class_name: str = ""         # enclosing class name for methods
    qnode: str = ""             # collision-resistant function identity
    parameter_text: str = ""     # raw parameter clause, including defaults
    parameter_names: tuple[str, ...] = ()
    parameter_types: tuple[str, ...] = ()
    return_type: str = ""


@dataclass
class ObservedCall:
    """A call site observed by tree-sitter, regardless of rule matches.

    Used by LLM annotator mode to derive source/sink specs from actual
    repository call fingerprints.
    """
    file: str
    language: str
    line: int
    receiver: str
    resolved_receiver: str
    method: str
    containing_fn: str
    snippet: str


@dataclass
class VarAssignFact:
    function_qnode: str
    line: int
    dst_symbol: str
    src_symbol: str | None = None
    src_call: str | None = None


@dataclass
class ReturnFact:
    function_qnode: str
    line: int
    symbol: str | None = None


@dataclass
class CallArgFact:
    function_qnode: str
    line: int
    callee_name: str
    receiver: str
    arg_symbols: list[str] = field(default_factory=list)
    target_symbol: str | None = None


@dataclass
class FieldWriteFact:
    function_qnode: str
    line: int
    receiver: str        # "self", "this", or variable name
    field: str           # attribute/property/field name
    src_symbol: str | None = None  # RHS identifier if simple assignment


@dataclass
class FieldReadFact:
    function_qnode: str
    line: int
    receiver: str
    field: str
    dst_symbol: str | None = None  # LHS identifier if assigned


@dataclass
class ContainerWriteFact:
    function_qnode: str
    line: int
    container_symbol: str    # the list/dict/array variable
    element_symbol: str | None = None  # the value being written


@dataclass
class FileIndex:
    file: str
    language: str
    imports: dict[str, str]      # local-name → fully-qualified module/class name
    functions: list[FuncDef]
    source_hits: list[CallSite] = field(default_factory=list)
    sink_hits:   list[CallSite] = field(default_factory=list)
    # All call edges in the file, whether or not they matched a rule. Used
    # by the graph module to build true reachability.
    # (containing_fn_name, receiver_name, called_method_name)
    call_edges: list[tuple[str, str, str]] = field(default_factory=list)
    # All observed calls with snippets, for LLM-based spec derivation.
    observed_calls: list[ObservedCall] = field(default_factory=list)
    # Lightweight intra-procedural facts for interprocedural taint.
    assigns: list[VarAssignFact] = field(default_factory=list)
    returns: list[ReturnFact] = field(default_factory=list)
    call_args: list[CallArgFact] = field(default_factory=list)
    # Field and container extractor facts.
    field_writes: list[FieldWriteFact] = field(default_factory=list)
    field_reads: list[FieldReadFact] = field(default_factory=list)
    container_writes: list[ContainerWriteFact] = field(default_factory=list)
    # Control-flow graphs and reflection facts.
    cfgs: dict[str, CFG] = field(default_factory=dict)  # function_qnode → CFG
    reflection_facts: list[ReflectionFact] = field(default_factory=list)
    # Framework detection facts.
    framework_markers: list[FrameworkMarkerFact] = field(default_factory=list)
    route_facts: list[RouteTaintFact] = field(default_factory=list)
    response_dataflow: list[ResponseDataflowFact] = field(default_factory=list)
    # Low-confidence bridge signals for potential cross-language handoff.
    bridge_signals: list[dict[str, object]] = field(default_factory=list)


def _bridge_kind_for_call(language: str, receiver: str, method: str, snippet: str) -> str | None:
    m = (method or "").strip().lower()
    r = (receiver or "").strip().lower()
    low = (snippet or "").lower()

    # Shell/process handoff signals.
    if m in {"system", "popen", "spawn", "exec", "execl", "execle", "execvp", "execvpe", "runtimeexec"}:
        return "shell"
    if m in {"run", "call", "check_call", "check_output", "create_subprocess_exec", "create_subprocess_shell", "start"}:
        if r in {"subprocess", "processbuilder", "runtime", "os"} or "subprocess" in low:
            return "subprocess"

    # SQL string-builder / concatenation patterns.
    if m in {"execute", "executemany", "raw", "query", "preparestatement", "createquery"}:
        if any(tok in low for tok in ("select ", "insert ", "update ", "delete ", " where ", ".format(", "f\"", "f'", "+")):
            return "sql_builder"

    # Template/render handoff.
    if m in {"render", "render_template", "templateresponse", "renderhtml", "renderstring", "execute_template", "compiletemplate"}:
        return "template"

    # Conservative fallback for JS template construction with eval-like routing.
    if language in {"javascript", "typescript"} and m in {"send", "end"}:
        if "template" in low or "<" in low:
            return "template"

    return None


def _extract_bridge_signals(language: str,
                            rel: str,
                            calls: list[tuple[int, str, str, str, str]]) -> list[dict[str, object]]:
    signals: list[dict[str, object]] = []
    for line, receiver, method, scope, snippet in calls:
        kind = _bridge_kind_for_call(language, receiver, method, snippet)
        if not kind:
            continue
        src_qnode = f"{rel}::{normalize_function_qnode(scope)}" if scope else f"{rel}::<module>"
        signals.append({
            "edge_type": "bridge",
            "bridge_kind": kind,
            "language": language,
            "file": rel,
            "line": int(line),
            "src_qnode": src_qnode,
            "dst_qnode": f"bridge::{kind}",
            "reason": "bridge_signal",
            "confidence": 0.25,
            "snippet": (snippet or "")[:160],
        })
    return signals


@dataclass
class LangPlugin:
    """Per-language extraction rules. `extract` walks the parsed tree and
    populates a fresh FileIndex + returns (call_list) for matching."""
    ts_language: str
    extract: Callable[[bytes, "object"], tuple[
        dict[str, str],           # imports
        list[FuncDef],            # function defs
        list[tuple[int, str, str, str, str]],  # calls: (line, receiver, method, containing_fn, snippet)
        list[VarAssignFact],      # local alias/call assignment facts
        list[ReturnFact],         # return identifier facts
        list[CallArgFact],        # call argument identifier facts
    ]]


def _build_cfg_for_function(func_node, func_name: str, src: bytes) -> CFG | None:
    """Build a one-block CFG scaffold when given a function AST node.

    The current scanner does not call this helper with a node and therefore
    leaves ``FileIndex.cfgs`` empty. The schema/helper are reserved for future
    control-flow refinement; no branch- or path-sensitive analysis is claimed.
    
    Args:
        func_node: tree-sitter function_definition/method_declaration node
        func_name: function name for reference
        src: source code bytes
        
    Returns:
        CFG with blocks and successors, or None if parsing fails
    """
    if func_node is None:
        return None
    try:
        cfg = CFG(
            blocks={},
            entry="B0",
            exit="",
            function_name=func_name,
        )
        cfg.blocks["B0"] = CFGNode(
            block_id="B0",
            stmts=[func_node],
            successors=[],
            condition=None,
        )
        cfg.exit = "B0"
        return cfg
    except Exception:
        return None


def _extract_control_flow_nodes(node) -> list[tuple[int, str, str]]:
    """Recursively extract all control-flow statement nodes.

    Finds if/while/for/switch/try nodes and returns their start line,
    condition text, and node type.

    Returns:
        list of (start_line, condition_text, node_type) tuples
    """
    cf_nodes: list[tuple[int, str, str]] = []

    def _walk(n):
        if n is None:
            return
        t = n.type
        if t in ("if_statement", "if_expression"):
            # Try to extract condition text
            cond_text = ""
            for c in n.children:
                if c.type in ("comparison_operator", "binary_operator", "condition", "parenthesized_expression"):
                    cond_text = n.type
                    break
            cf_nodes.append((n.start_point[0] + 1, cond_text, t))
        elif t in ("while_statement", "for_statement", "for_in_statement"):
            cf_nodes.append((n.start_point[0] + 1, "", t))
        elif t in ("switch_statement", "switch_expression"):
            cf_nodes.append((n.start_point[0] + 1, "", t))
        elif t in ("try_statement", "try_catch_statement", "try_expression"):
            cf_nodes.append((n.start_point[0] + 1, "", t))
        # Recurse into children
        for child in n.children:
            _walk(child)

    _walk(node)
    return cf_nodes


def _py_extract_reflection_facts(src: bytes, tree) -> list[ReflectionFact]:
    """Extract Python reflection facts (getattr, setattr, __import__).
    
    Detects patterns like:
    - getattr(obj, name)
    - setattr(obj, name, val)
    - __import__(module)
    - importlib.import_module(...)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ReflectionFact records
    """
    root = tree.root_node
    facts: list[ReflectionFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type == "function_definition":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _py_text(n, src)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "call":
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                return
            # Check for bare function calls: getattr, setattr, __import__
            if fn_node.type == "identifier":
                fname = _py_text(fn_node, src)
                if fname in ("getattr", "setattr", "__import__",
                              "vars", "type", "eval", "exec", "compile"):
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        # Extract 2nd arg (name) for getattr/setattr, 1st arg for __import__
                        # and 1st arg for vars/type/eval/exec/compile
                        target_symbols: list[str] = []
                        for i, arg in enumerate(args_node.named_children):
                            if fname == "__import__" and i == 0:
                                if arg.type == "string":
                                    target_symbols.append(
                                        _py_text(arg, src).strip("\"'"))
                                elif arg.type == "identifier":
                                    target_symbols.append(_py_text(arg, src))
                                break
                            elif fname in ("getattr", "setattr") and i == 1:
                                if arg.type == "string":
                                    target_symbols.append(
                                        _py_text(arg, src).strip("\"'"))
                                elif arg.type == "identifier":
                                    target_symbols.append(_py_text(arg, src))
                                break
                            elif fname in ("vars", "type", "eval", "exec", "compile") and i == 0:
                                if arg.type == "string":
                                    target_symbols.append(
                                        _py_text(arg, src).strip("\"'"))
                                elif arg.type == "identifier":
                                    target_symbols.append(_py_text(arg, src))
                                break
                        if target_symbols:
                            _call_type = (
                                "getattr" if fname in ("getattr", "vars")
                                else "invoke" if fname in ("eval", "exec")
                                else "construct"
                            )
                            _append_reflection_fact(facts,
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                call_type=_call_type,
                                target_symbols=target_symbols,
                                receiver="",
                                language="python",
                            )
            # Check for importlib.import_module
            elif fn_node.type == "attribute":
                attr_node = fn_node.child_by_field_name("attribute")
                if attr_node is not None:
                    method = _py_text(attr_node, src)
                    if method == "import_module":
                        receiver = _py_leftmost_identifier(fn_node, src)
                        if receiver == "importlib":
                            args_node = node.child_by_field_name("arguments")
                            if args_node is not None:
                                for arg in args_node.named_children:
                                    if arg.type == "string":
                                        target_symbols = [
                                            _py_text(arg, src).strip("\"'")]
                                        _append_reflection_fact(facts,
                                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                                            line=node.start_point[0] + 1,
                                            call_type="construct",
                                            target_symbols=target_symbols,
                                            receiver="importlib",
                                            language="python",
                                        )
                                        break
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


def _java_extract_reflection_facts(src: bytes, tree) -> list[ReflectionFact]:
    """Extract Java reflection facts (getMethod, forName, invoke, newInstance).
    
    Detects patterns like:
    - Class.getMethod(name)
    - Class.forName(name)
    - method.invoke(...)
    - Class.newInstance()
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ReflectionFact records
    """
    root = tree.root_node
    facts: list[ReflectionFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type in ("method_declaration", "constructor_declaration"):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "method_invocation":
            name_node = node.child_by_field_name("name")
            obj_node = node.child_by_field_name("object")
            if name_node is None:
                return
            method = _text_of(src, name_node)
            receiver = _java_leftmost(obj_node, src) if obj_node is not None else ""
            
            # getMethod(name), forName(name), getDeclaredMethod(name),
            # getDeclaredField(name), getField(name)
            if method in ("getMethod", "forName", "getDeclaredMethod",
                          "getDeclaredField", "getField"):
                args_node = node.child_by_field_name("arguments")
                if args_node is not None:
                    target_symbols: list[str] = []
                    for arg in args_node.named_children:
                        if arg.type == "string_literal":
                            target_symbols.append(_text_of(src, arg).strip("\""))
                        elif arg.type == "identifier":
                            target_symbols.append(_text_of(src, arg))
                    if target_symbols:
                        _append_reflection_fact(facts,
                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                            line=node.start_point[0] + 1,
                            call_type="getmethod",
                            target_symbols=target_symbols,
                            receiver=receiver,
                            language="java",
                        )
            # invoke(...) 
            elif method == "invoke":
                _append_reflection_fact(facts,
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    call_type="invoke",
                    target_symbols=[],
                    receiver=receiver,
                    language="java",
                )
            # newInstance(), getDeclaredConstructor(...), getConstructor(...)
            elif method in ("newInstance", "getDeclaredConstructor", "getConstructor"):
                _append_reflection_fact(facts,
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    call_type="construct",
                    target_symbols=[],
                    receiver=receiver,
                    language="java",
                )
            # MethodHandles.lookup() — method handle lookup
            elif method == "lookup" and "MethodHandles" in receiver:
                _append_reflection_fact(facts,
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    call_type="getmethod",
                    target_symbols=[],
                    receiver=receiver,
                    language="java",
                )
            # Activator receiver — dynamic instantiation pattern
            elif receiver == "Activator":
                _append_reflection_fact(facts,
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    call_type="construct",
                    target_symbols=[],
                    receiver=receiver,
                    language="java",
                )
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


def _cs_extract_reflection_facts(src: bytes, tree) -> list[ReflectionFact]:
    """Extract C# reflection facts (GetMethod, GetType, CreateDelegate, etc.).
    
    Detects patterns like:
    - type.GetMethod(name)
    - Type.GetType(name)
    - Delegate.CreateDelegate(...)
    - Assembly.LoadFrom(...)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ReflectionFact records
    """
    root = tree.root_node
    facts: list[ReflectionFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type in ("method_declaration", "constructor_declaration"):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "invocation_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                return
            if fn_node.type == "member_access_expression":
                name_node = fn_node.child_by_field_name("name")
                expr_node = fn_node.child_by_field_name("expression")
                if name_node is None:
                    return
                method = _text_of(src, name_node)
                receiver = _cs_leftmost(expr_node, src) if expr_node is not None else ""

                # GetMethod(name), GetType(name), GetMethods(), GetConstructor(...),
                # GetConstructors()
                if method in ("GetMethod", "GetType", "GetMethods",
                              "GetConstructor", "GetConstructors"):
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        target_symbols: list[str] = []
                        for arg in args_node.named_children:
                            if arg.type in ("string", "string_literal"):
                                target_symbols.append(
                                    _text_of(src, arg).strip("\""))
                            elif arg.type == "identifier":
                                target_symbols.append(_text_of(src, arg))
                            elif arg.type == "argument":
                                e = arg.child_by_field_name("expression")
                                if e is not None:
                                    if e.type in ("string", "string_literal"):
                                        target_symbols.append(
                                            _text_of(src, e).strip("\""))
                                    elif e.type == "identifier":
                                        target_symbols.append(_text_of(src, e))
                        if target_symbols:
                            _append_reflection_fact(facts,
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                call_type="getmethod",
                                target_symbols=target_symbols,
                                receiver=receiver,
                                language="csharp",
                            )
                        elif method in ("GetMethods", "GetConstructor", "GetConstructors"):
                            # No string arg required — emit fact on the call itself
                            _append_reflection_fact(facts,
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                call_type="getmethod",
                                target_symbols=[],
                                receiver=receiver,
                                language="csharp",
                            )
                # CreateDelegate(...) or Invoke() on a delegate
                elif method in ("CreateDelegate", "Invoke"):
                    _append_reflection_fact(facts,
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        call_type="delegate" if method == "CreateDelegate" else "invoke",
                        target_symbols=[],
                        receiver=receiver,
                        language="csharp",
                    )
                # LoadFrom(...), Load(...), LoadFile(...) for Assembly
                elif method in ("LoadFrom", "Load", "LoadFile"):
                    _append_reflection_fact(facts,
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        call_type="construct",
                        target_symbols=[],
                        receiver=receiver,
                        language="csharp",
                    )
                # Activator.CreateInstance(type) — dynamic instantiation
                elif method == "CreateInstance":
                    _append_reflection_fact(facts,
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        call_type="construct",
                        target_symbols=[],
                        receiver=receiver,
                        language="csharp",
                    )
                # Type.InvokeMember(name, ...) — reflective invocation
                elif method == "InvokeMember":
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        target_symbols = []
                        for arg in args_node.named_children:
                            if arg.type in ("string", "string_literal"):
                                target_symbols.append(
                                    _text_of(src, arg).strip("\""))
                            elif arg.type == "argument":
                                e = arg.child_by_field_name("expression")
                                if e is not None and e.type in ("string", "string_literal"):
                                    target_symbols.append(
                                        _text_of(src, e).strip("\""))
                            break  # only first arg (member name)
                    _append_reflection_fact(facts,
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        call_type="invoke",
                        target_symbols=target_symbols if args_node is not None else [],
                        receiver=receiver,
                        language="csharp",
                    )
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


def _py_extract_framework_markers(src: bytes, tree) -> tuple[list[FrameworkMarkerFact], list[RouteTaintFact]]:
    """Extract Python framework markers (Django views, request patterns).
    
    Detects:
    - Django view functions with 'request' parameter
    - request.GET/POST/META/FILES access patterns
    - View function naming patterns (*_view, handle*, process*)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        tuple of (marker_facts, route_facts)
    """
    root = tree.root_node
    markers: list[FrameworkMarkerFact] = []
    routes: list[RouteTaintFact] = []
    fn_ranges: list[tuple[int, int, str]] = []
    class_stack: list[str] = []

    def _collect_fn_ranges(node):
        if node.type == "function_definition":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_name = _py_text(n, src)
                if class_stack:
                    fn_name = f"{'.'.join(class_stack)}.{fn_name}"
                fn_ranges.append((node.start_byte, node.end_byte, fn_name))
        elif node.type == "class_definition":
            n = node.child_by_field_name("name")
            cls = _py_text(n, src) if n is not None else ""
            if cls:
                class_stack.append(cls)
                for c in node.children:
                    _collect_fn_ranges(c)
                class_stack.pop()
                return
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        # Detect function definitions with 'request' parameter
        if node.type == "function_definition":
            fn_name_node = node.child_by_field_name("name")
            if fn_name_node is None:
                return
            fn_name = _py_text(fn_name_node, src)
            params_node = node.child_by_field_name("parameters")
            if params_node is None:
                return
            
            # Extract parameter names
            param_names = []
            for param in params_node.named_children:
                if param.type in ("identifier", "parameter"):
                    pname = _py_text(param, src) if param.type == "identifier" else (
                        _py_text(param.child_by_field_name("name"), src) if param.child_by_field_name("name") else "")
                    if pname:
                        param_names.append(pname)
            
            # Treat any function that takes `request` as a Django view marker.
            # Naming heuristics miss common handlers (e.g., `profile(request)`).
            if "request" in param_names:
                markers.append(FrameworkMarkerFact(
                    function_qnode=fn_name,
                    line=node.start_point[0] + 1,
                    marker_type="django_view",
                    marker_name="request",
                    parameter_names=["request"],
                    framework="django",
                    confidence="high",
                ))

            # Callable class entry marker: `__call__(self, ...)` often backs
            # framework handler objects. Keep marker_type aligned with existing
            # framework model by using django_view.
            if fn_name == "__call__":
                callable_params = [p for p in param_names if p != "self"]
                if callable_params:
                    markers.append(FrameworkMarkerFact(
                        function_qnode=fn_name,
                        line=node.start_point[0] + 1,
                        marker_type="django_view",
                        marker_name="__call__",
                        parameter_names=[callable_params[0]],
                        framework="django",
                        confidence="medium",
                    ))
            
            # Detect request.GET/POST/META access patterns
            for child in node.children:
                _check_request_access(child, fn_name, src, markers, fn_ranges)
        
        for c in node.children:
            _visit(c)

    def _check_request_access(node, fn_name: str, src: bytes, markers: list, fn_ranges):
        """Recursively check for request.GET/POST/META patterns."""
        if node.type == "attribute":
            obj_node = node.child_by_field_name("object")
            # Python grammar uses "attribute"; keep legacy "attr" fallback
            # for compatibility with older/alternate grammars.
            attr_node = (node.child_by_field_name("attribute")
                         or node.child_by_field_name("attr"))
            if obj_node and attr_node:
                obj_text = _py_text(obj_node, src)
                attr_text = _py_text(attr_node, src)
                if obj_text == "request" and attr_text in ("GET", "POST", "META", "FILES"):
                    markers.append(FrameworkMarkerFact(
                        function_qnode=fn_name,
                        line=node.start_point[0] + 1,
                        marker_type="django_dict_access",
                        marker_name=f"request.{attr_text}",
                        parameter_names=["result"],
                        framework="django",
                        confidence="high",
                    ))
        
        for c in node.children:
            _check_request_access(c, fn_name, src, markers, fn_ranges)

    _visit(root)
    return markers, routes


def _java_extract_framework_markers(src: bytes, tree) -> tuple[list[FrameworkMarkerFact], list[RouteTaintFact]]:
    """Extract Java framework markers (Spring annotations, servlet types).
    
    Detects:
    - @RequestParam, @PathVariable, @RequestBody, @RequestHeader annotations
    - @GetMapping, @PostMapping with path patterns
    - ServletRequest, HttpServletRequest parameter types
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        tuple of (marker_facts, route_facts)
    """
    root = tree.root_node
    markers: list[FrameworkMarkerFact] = []
    routes: list[RouteTaintFact] = []
    
    def _visit(node):
        # Detect method with Spring annotations
        if node.type == "method_declaration":
            method_name_node = node.child_by_field_name("name")
            if method_name_node is None:
                return
            method_name = _text_of(src, method_name_node)
            
            # Collect annotations on the method (check direct children for modifiers)
            for child in node.children:
                if child.type == "modifiers":
                    for mod_child in child.children:
                        if mod_child.type in ("annotation", "marker_annotation"):
                            _process_spring_annotation(mod_child, method_name, node, src, markers, routes)
            
            # Check method parameters for annotations
            params_node = node.child_by_field_name("parameters")
            if params_node is not None:
                for param in params_node.named_children:
                    if param.type == "formal_parameter":
                        _process_parameter_annotations(param, method_name, src, markers)
        
        for c in node.children:
            _visit(c)

    def _process_spring_annotation(annotation_node, method_name: str, method_node, src: bytes, 
                                   markers: list, routes: list):
        """Process Spring annotations on a method."""
        name_node = annotation_node.child_by_field_name("name")
        if name_node is None:
            return
        
        annotation_name = _text_of(src, name_node)
        
        # @GetMapping("/path/{id}"), @PostMapping, etc.
        if annotation_name in ("GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "RequestMapping"):
            # Extract route pattern
            args = annotation_node.child_by_field_name("arguments")
            if args is not None:
                for arg in args.named_children:
                    if arg.type == "string_literal":
                        route_path = _text_of(src, arg).strip("\"")
                        # Extract path parameters
                        import re as re_module
                        params = re_module.findall(r'\{(\w+)\}', route_path)
                        for param in params:
                            routes.append(RouteTaintFact(
                                function_qnode=method_name,
                                line=method_node.start_point[0] + 1,
                                route_pattern=route_path,
                                parameter_name=param,
                                is_tainted=True,
                                framework="spring",
                            ))

    def _process_parameter_annotations(param_node, method_name: str, src: bytes, markers: list):
        """Process annotations on a parameter."""
        param_name_node = param_node.child_by_field_name("name")
        if param_name_node is None:
            return
        param_name = _text_of(src, param_name_node)
        
        # Check for annotations (inside modifiers node on parameter, iterate direct children)
        for child in param_node.children:
            if child.type == "modifiers":
                for mod_child in child.children:
                    if mod_child.type in ("annotation", "marker_annotation"):
                        ann_name_node = mod_child.child_by_field_name("name")
                        if ann_name_node is not None:
                            ann_name = _text_of(src, ann_name_node)
                            if ann_name in ("RequestParam", "PathVariable", "RequestBody", "RequestHeader"):
                                markers.append(FrameworkMarkerFact(
                                    function_qnode=method_name,
                                    line=param_node.start_point[0] + 1,
                                    marker_type="spring_annotation",
                                    marker_name=f"@{ann_name}",
                                    parameter_names=[param_name],
                                    framework="spring",
                                    confidence="high",
                                ))
        
        # Check for ServletRequest/HttpServletRequest types
        type_node = param_node.child_by_field_name("type")
        if type_node is not None:
            type_text = _text_of(src, type_node)
            if "ServletRequest" in type_text or "HttpServletRequest" in type_text:
                markers.append(FrameworkMarkerFact(
                    function_qnode=method_name,
                    line=param_node.start_point[0] + 1,
                    marker_type="spring_implicit",
                    marker_name=type_text,
                    parameter_names=[param_name],
                    framework="spring",
                    confidence="medium",
                ))

    _visit(root)
    return markers, routes


def _cs_extract_framework_markers(src: bytes, tree) -> tuple[list[FrameworkMarkerFact], list[RouteTaintFact]]:
    """Extract C# framework markers (ASP.NET annotations, binding parameters).
    
    Detects:
    - [FromQuery], [FromRoute], [FromBody], [FromHeader] annotations
    - [HttpGet], [HttpPost] with route patterns
    - ControllerBase inheritance + [ApiController]
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        tuple of (marker_facts, route_facts)
    """
    root = tree.root_node
    markers: list[FrameworkMarkerFact] = []
    routes: list[RouteTaintFact] = []
    
    def _visit(node):
        # Detect method with ASP.NET attributes
        if node.type == "method_declaration":
            method_name_node = node.child_by_field_name("name")
            if method_name_node is None:
                return
            method_name = _text_of(src, method_name_node)
            
            # Check method attributes (inside attribute_list)
            for child in node.children:
                if child.type == "attribute_list":
                    for attr_node in child.children:
                        if attr_node.type == "attribute":
                            _process_aspnet_attribute(attr_node, method_name, node, src, markers, routes)
            
            # Check parameters for attributes
            params_node = node.child_by_field_name("parameters")
            if params_node is not None:
                for param in params_node.named_children:
                    if param.type == "parameter":
                        _process_parameter_attributes(param, method_name, src, markers)
        
        for c in node.children:
            _visit(c)

    def _process_aspnet_attribute(attr_node, method_name: str, method_node, src: bytes,
                                 markers: list, routes: list):
        """Process ASP.NET attributes on a method."""
        attr_name_node = attr_node.child_by_field_name("name")
        if attr_name_node is None:
            return
        
        attr_name = _text_of(src, attr_name_node)
        
        # [HttpGet("/path/{id}")] etc.
        if attr_name in ("HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch"):
            args = attr_node.child_by_field_name("arguments")
            if args is not None:
                for arg in args.named_children:
                    if arg.type in ("string", "string_literal"):
                        route_path = _text_of(src, arg).strip("\"")
                        # Extract path parameters {id}
                        import re as re_module
                        params = re_module.findall(r'\{(\w+)\}', route_path)
                        for param in params:
                            routes.append(RouteTaintFact(
                                function_qnode=method_name,
                                line=method_node.start_point[0] + 1,
                                route_pattern=route_path,
                                parameter_name=param,
                                is_tainted=True,
                                framework="aspnet",
                            ))

    def _process_parameter_attributes(param_node, method_name: str, src: bytes, markers: list):
        """Process attributes on a parameter."""
        param_name_node = param_node.child_by_field_name("name")
        if param_name_node is None:
            return
        param_name = _text_of(src, param_name_node)
        
        # Check for parameter attributes [FromQuery], [FromRoute], etc. (inside attribute_list)
        for child in param_node.children:
            if child.type == "attribute_list":
                for attr_node in child.children:
                    if attr_node.type == "attribute":
                        attr_name_node = attr_node.child_by_field_name("name")
                        if attr_name_node is not None:
                            attr_name = _text_of(src, attr_name_node)
                            if attr_name in ("FromQuery", "FromRoute", "FromBody", "FromHeader"):
                                markers.append(FrameworkMarkerFact(
                                    function_qnode=method_name,
                                    line=param_node.start_point[0] + 1,
                                    marker_type="aspnet_annotation",
                                    marker_name=f"[{attr_name}]",
                                    parameter_names=[param_name],
                                    framework="aspnet",
                                    confidence="high",
                                ))

    _visit(root)
    return markers, routes


def _py_extract_response_dataflow(src: bytes, tree) -> list[ResponseDataflowFact]:
    """Extract Python response dataflow (JsonResponse, HttpResponse, render).
    
    Detects patterns like:
    - JsonResponse(data)
    - HttpResponse(content)
    - render(request, template, context=)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ResponseDataflowFact records
    """
    root = tree.root_node
    facts: list[ResponseDataflowFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type == "function_definition":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _py_text(n, src)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "call":
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                return
            
            # Detect bare function calls: JsonResponse, HttpResponse, render
            if fn_node.type == "identifier":
                fname = _py_text(fn_node, src)
                if fname in ("JsonResponse", "HttpResponse", "render"):
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        # Extract first argument as the data flowing into response
                        for i, arg in enumerate(args_node.named_children):
                            if fname == "render" and i == 2:  # context= parameter
                                if arg.type == "keyword_argument":
                                    val_node = arg.child_by_field_name("value")
                                    if val_node is not None:
                                        from_sym = _py_text(val_node, src)
                                        facts.append(ResponseDataflowFact(
                                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                                            line=node.start_point[0] + 1,
                                            from_symbol=from_sym,
                                            to_sink="render",
                                            framework="django",
                                            response_type="html",
                                        ))
                            elif fname in ("JsonResponse", "HttpResponse") and i == 0:
                                from_sym = _py_text(arg, src)
                                response_type = "json" if fname == "JsonResponse" else "html"
                                facts.append(ResponseDataflowFact(
                                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                                    line=node.start_point[0] + 1,
                                    from_symbol=from_sym,
                                    to_sink=fname,
                                    framework="django",
                                    response_type=response_type,
                                ))
                                break
        
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


def _java_extract_response_dataflow(src: bytes, tree) -> list[ResponseDataflowFact]:
    """Extract Java response dataflow (ResponseEntity, model.addAttribute).
    
    Detects patterns like:
    - ResponseEntity<...> return values
    - model.addAttribute(name, value)
    - new ResponseEntity<>(body, status)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ResponseDataflowFact records
    """
    root = tree.root_node
    facts: list[ResponseDataflowFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type == "method_declaration":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        # Detect ResponseEntity<...> constructor calls
        if node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                type_text = _text_of(src, type_node)
                if "ResponseEntity" in type_text:
                    args = node.child_by_field_name("arguments")
                    if args is not None:
                        for i, arg in enumerate(args.named_children):
                            if i == 0:  # First argument is body
                                from_sym = _text_of(src, arg)
                                facts.append(ResponseDataflowFact(
                                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                                    line=node.start_point[0] + 1,
                                    from_symbol=from_sym,
                                    to_sink="ResponseEntity",
                                    framework="spring",
                                    response_type="json",
                                ))
                                break
        
        # Detect model.addAttribute(...) calls
        if node.type == "method_invocation":
            fn_node = node.child_by_field_name("name")
            if fn_node is not None:
                method_name = _text_of(src, fn_node)
                if method_name == "addAttribute":
                    args = node.child_by_field_name("arguments")
                    if args is not None:
                        # Second argument is the value being added
                        children = list(args.named_children)
                        if len(children) >= 2:
                            from_sym = _text_of(src, children[1])
                            facts.append(ResponseDataflowFact(
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                from_symbol=from_sym,
                                to_sink="addAttribute",
                                framework="spring",
                                response_type="html",
                            ))
        
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


def _cs_extract_response_dataflow(src: bytes, tree) -> list[ResponseDataflowFact]:
    """Extract C# response dataflow (Ok, BadRequest, Created, JSON serialization).
    
    Detects patterns like:
    - Ok(model)
    - BadRequest(error)
    - Created(location, resource)
    - Json(data)
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ResponseDataflowFact records
    """
    root = tree.root_node
    facts: list[ResponseDataflowFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_fn_ranges(node):
        if node.type == "method_declaration":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    def _visit(node):
        if node.type == "invocation_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node is None:
                return
            
            # Detect bare method calls: Ok, BadRequest, Created, Json
            if fn_node.type == "identifier":
                method_name = _text_of(src, fn_node)
                if method_name in ("Ok", "BadRequest", "Created", "Json"):
                    args = node.child_by_field_name("arguments")
                    if args is not None:
                        for i, arg in enumerate(args.named_children):
                            # Map method name to response type
                            response_type_map = {
                                "Ok": "json",
                                "BadRequest": "json",
                                "Created": "json",
                                "Json": "json",
                            }
                            response_type = response_type_map.get(method_name, "json")
                            
                            # Skip location argument in Created()
                            if method_name == "Created" and i == 0:
                                continue
                            
                            from_sym = _text_of(src, arg)
                            facts.append(ResponseDataflowFact(
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                from_symbol=from_sym,
                                to_sink=method_name,
                                framework="aspnet",
                                response_type=response_type,
                            ))
                            break  # Only process first data argument
        
        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


# Uses tree-sitter-python's node types (call, attribute, identifier,
# import_statement, import_from_statement, function_definition, class_definition).


def _py_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _py_leftmost_identifier(node, src: bytes) -> str:
    """Walk a call/attribute expression to its leftmost identifier — that's
    what we treat as the receiver root for import resolution."""
    cur = node
    while cur is not None:
        if cur.type == "identifier":
            return _py_text(cur, src)
        # attribute has children [object, ".", attribute]; recurse into object
        if cur.type == "attribute":
            cur = cur.child_by_field_name("object") or cur.children[0]
            continue
        if cur.type == "call":
            cur = cur.child_by_field_name("function")
            continue
        # subscript, parenthesized, etc. — take first child and keep walking
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _py_snippet(src: bytes, node) -> str:
    """Grab a compact single-line snippet at the call site."""
    line_start = src.rfind(b"\n", 0, node.start_byte) + 1
    line_end = src.find(b"\n", node.end_byte)
    if line_end == -1:
        line_end = len(src)
    return src[line_start:line_end].decode("utf-8", errors="ignore").strip()[:120]


def normalize_function_qnode(name: str) -> str:
    return str(name or "").strip()


def _py_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    # Precompute function ranges so we can attribute each call to a scope.
    fn_ranges: list[tuple[int, int, str]] = []  # (start, end, name)
    calls: list[tuple[int, str, str, str, str]] = []
    assigns: list[VarAssignFact] = []
    returns: list[ReturnFact] = []
    call_args: list[CallArgFact] = []
    # Stack of enclosing class names so methods get class_name populated,
    # enabling ClassName.method qualified lookup in _graph.py (mirrors Java).
    class_stack: list[str] = []
    # Stack of enclosing function names so nested defs do not collapse into
    # a single bare-name qnode.
    function_stack: list[str] = []

    def _normalize_py_type_text(raw: str) -> str:
        txt = str(raw or "").strip().strip("\"'")
        return txt

    def _py_parameter_type_hints(params_node) -> tuple[tuple[str, ...], dict[str, str]]:
        if params_node is None:
            return (), {}
        out_types: list[str] = []
        hint_map: dict[str, str] = {}

        for child in params_node.named_children:
            p_name = ""
            p_type = ""
            if child.type == "identifier":
                out_types.append("")
                continue
            if child.type in (
                "typed_parameter",
                "typed_default_parameter",
                "default_parameter",
                "parameter",
                "list_splat_pattern",
                "dictionary_splat_pattern",
            ):
                name_node = child.child_by_field_name("name")
                type_node = child.child_by_field_name("type")
                if name_node is None:
                    for gc in child.named_children:
                        if gc.type == "identifier":
                            name_node = gc
                            break
                if name_node is not None and name_node.type == "identifier":
                    p_name = _py_text(name_node, src)
                if type_node is not None:
                    p_type = _normalize_py_type_text(_py_text(type_node, src))
                # Fallback: try to recover a trailing annotation expression.
                if not p_type:
                    for gc in child.named_children:
                        if gc is not name_node and gc.type not in (
                            "identifier",
                            "default_value",
                            "expression",
                        ):
                            maybe = _normalize_py_type_text(_py_text(gc, src))
                            if maybe and maybe != p_name:
                                p_type = maybe
                                break
                out_types.append(p_type)
                if p_name and p_type:
                    hint_map[p_name] = p_type

        return tuple(out_types), hint_map

    def _py_return_type_hint(fn_node) -> str:
        rt = fn_node.child_by_field_name("return_type")
        if rt is not None:
            return _normalize_py_type_text(_py_text(rt, src))
        return ""

    def _py_call_parts(call_node) -> tuple[str, str]:
        fn_node = call_node.child_by_field_name("function")
        if fn_node is None:
            return "", ""
        if fn_node.type == "attribute":
            method_node = fn_node.child_by_field_name("attribute")
            method = _py_text(method_node, src) if method_node else ""
            receiver = _py_leftmost_identifier(fn_node, src)
            return receiver, method
        if fn_node.type == "identifier":
            return "", _py_text(fn_node, src)
        return "", ""

    def _py_assignment_target_for_call(call_node) -> str | None:
        parent = call_node.parent
        if parent is None or parent.type != "assignment":
            return None
        right = parent.child_by_field_name("right")
        left = parent.child_by_field_name("left")
        if right is call_node and left is not None and left.type == "identifier":
            return _py_text(left, src)
        return None

    def _py_function_parameters(params_node) -> tuple[str, ...]:
        if params_node is None:
            return ()

        names: list[str] = []
        seen: set[str] = set()

        def _append_name(name_node) -> None:
            if name_node is None or name_node.type != "identifier":
                return
            name = _py_text(name_node, src)
            if name and name not in seen:
                seen.add(name)
                names.append(name)

        for child in params_node.named_children:
            if child.type == "identifier":
                _append_name(child)
                continue
            if child.type in (
                "typed_parameter",
                "default_parameter",
                "list_splat_pattern",
                "dictionary_splat_pattern",
                "parameter",
            ):
                name_node = child.child_by_field_name("name")
                if name_node is None:
                    for grandchild in child.named_children:
                        if grandchild.type == "identifier":
                            name_node = grandchild
                            break
                _append_name(name_node)

        return tuple(names)

    def _py_function_qnode(fname: str, params_node) -> str:
        scope_parts: list[str] = []
        if class_stack:
            scope_parts.extend(class_stack)
        if function_stack:
            scope_parts.extend(function_stack)
        scope_parts.append(fname)
        params_text = _py_text(params_node, src) if params_node is not None else ""
        return "".join((".".join(scope_parts), params_text))

    def _py_identifier_args(call_node) -> list[str]:
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            return []
        out: list[str] = []
        for arg in args_node.named_children:
            if arg.type == "keyword_argument":
                val = arg.child_by_field_name("value")
                out.extend(_collect_identifier_symbols(val, src))
            else:
                out.extend(_collect_identifier_symbols(arg, src))
        return out

    def _py_return_identifier(ret_node) -> str | None:
        val = ret_node.child_by_field_name("value")
        if val is None:
            for c in ret_node.named_children:
                if c.type != "return":
                    val = c
                    break
        if val is not None and val.type == "identifier":
            return _py_text(val, src)
        return None

    def _visit(node):
        t = node.type
        if t == "import_statement":
            # import foo   |   import foo.bar   |   import foo as f, baz
            for name_node in node.children:
                if name_node.type != "dotted_name" and name_node.type != "aliased_import":
                    continue
                if name_node.type == "aliased_import":
                    mod_node = name_node.child_by_field_name("name")
                    alias_node = name_node.child_by_field_name("alias")
                    if mod_node and alias_node:
                        imports[_py_text(alias_node, src)] = _py_text(mod_node, src)
                else:
                    mod = _py_text(name_node, src)
                    imports[mod.split(".")[0]] = mod
        elif t == "import_from_statement":
            mod_node = node.child_by_field_name("module_name")
            mod = _py_text(mod_node, src) if mod_node else ""
            saw_wildcard = False
            # Children after module_name are the imported symbols
            for c in node.children:
                if c.type in ("dotted_name", "aliased_import") and c is not mod_node:
                    if c.type == "aliased_import":
                        name_node = c.child_by_field_name("name")
                        alias_node = c.child_by_field_name("alias")
                        if name_node and alias_node:
                            imports[_py_text(alias_node, src)] = (
                                f"{mod}.{_py_text(name_node, src)}"
                                if mod else _py_text(name_node, src)
                            )
                    else:
                        sym = _py_text(c, src)
                        imports[sym] = f"{mod}.{sym}" if mod else sym
                elif c.type in ("wildcard_import", "asterisk"):
                    saw_wildcard = True
            if saw_wildcard and mod:
                # Minimal deterministic signal for `from X import *`.
                imports[f"__wildcard__:{mod}"] = f"{mod}.*"
        elif t == "class_definition":
            # Push the class name so nested function_definition nodes see it.
            # We handle the children ourselves and return to avoid double-visit.
            name_node = node.child_by_field_name("name")
            cls = _py_text(name_node, src) if name_node is not None else ""
            if cls:
                supers = node.child_by_field_name("superclasses")
                base_names: list[str] = []
                if supers is not None:
                    for base_node in supers.named_children:
                        btxt = _py_text(base_node, src).strip()
                        if btxt:
                            base_names.append(btxt)
                if base_names:
                    imports[f"__bases__:{cls}"] = ",".join(base_names)
                    # Also emit __supertype__ keys so iface_method_to_fids in
                    # _graph.py can resolve Python base-class dispatch.
                    for base in base_names:
                        simple = base.split(".")[-1]
                        resolved = imports.get(base, imports.get(simple, base))
                        imports[f"__supertype__:{cls}:{simple}"] = resolved
                class_stack.append(cls)
                for child in node.children:
                    _visit(child)
                class_stack.pop()
            else:
                for child in node.children:
                    _visit(child)
            return
        elif t == "decorated_definition":
            # The inner function/class definition is a direct child; visit all
            # children so the inner node is processed in the current class scope.
            for child in node.children:
                _visit(child)
            return
        elif t in ("function_definition", "async_function_definition"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _py_text(name_node, src)
                params_node = node.child_by_field_name("parameters")
                parameter_types, param_hint_map = _py_parameter_type_hints(params_node)
                qnode = normalize_function_qnode(_py_function_qnode(fname, params_node))
                functions.append(FuncDef(
                    name=fname,
                    class_name=class_stack[-1] if class_stack else "",
                    qnode=qnode,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    parameter_text=_py_text(params_node, src) if params_node is not None else "",
                    parameter_names=_py_function_parameters(params_node),
                    parameter_types=parameter_types,
                    return_type=_py_return_type_hint(node),
                ))
                for pname, ptype in param_hint_map.items():
                    # Annotation-based receiver resolution hint, e.g. `x: Client`.
                    imports[pname] = ptype
                fn_ranges.append((node.start_byte, node.end_byte, qnode))
                function_stack.append(fname)
                for child in node.children:
                    _visit(child)
                function_stack.pop()
                return
        elif t in (
            "lambda",
            "generator_expression",
            "list_comprehension",
            "set_comprehension",
            "dictionary_comprehension",
        ):
            kind_map = {
                "lambda": "lambda",
                "generator_expression": "genexpr",
                "list_comprehension": "listcomp",
                "set_comprehension": "setcomp",
                "dictionary_comprehension": "dictcomp",
            }
            scope_parts: list[str] = []
            if class_stack:
                scope_parts.extend(class_stack)
            if function_stack:
                scope_parts.extend(function_stack)
            scope_parts.append(f"<{kind_map.get(t, 'scope')}@{node.start_point[0] + 1}>")
            qnode = normalize_function_qnode(".".join(scope_parts))
            fn_ranges.append((node.start_byte, node.end_byte, qnode))
            for child in node.children:
                _visit(child)
            return
        elif t == "call":
            fn_node = node.child_by_field_name("function")
            if fn_node is not None:
                receiver, method = _py_call_parts(node)
                if method:
                    line = node.start_point[0] + 1
                    scope = normalize_function_qnode(_scope_for(node.start_byte, fn_ranges))
                    snippet = _py_snippet(src, node)
                    calls.append((line, receiver, method, scope, snippet))
                    call_args.append(CallArgFact(
                        function_qnode=scope,
                        line=line,
                        callee_name=method,
                        receiver=receiver,
                        arg_symbols=_py_identifier_args(node),
                        target_symbol=_py_assignment_target_for_call(node),
                    ))
        elif t == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "identifier" and right is not None:
                dst = _py_text(left, src)
                src_symbol: str | None = None
                src_call: str | None = None
                if right.type == "identifier":
                    src_symbol = _py_text(right, src)
                elif right.type == "call":
                    _r, m = _py_call_parts(right)
                    src_call = m or None
                if src_symbol is not None or src_call is not None:
                    scope = normalize_function_qnode(_scope_for(node.start_byte, fn_ranges))
                    assigns.append(VarAssignFact(
                        function_qnode=scope,
                        line=node.start_point[0] + 1,
                        dst_symbol=dst,
                        src_symbol=src_symbol,
                        src_call=src_call,
                    ))
        elif t == "return_statement":
            scope = normalize_function_qnode(_scope_for(node.start_byte, fn_ranges))
            returns.append(ReturnFact(
                function_qnode=scope,
                line=node.start_point[0] + 1,
                symbol=_py_return_identifier(node),
            ))
        # Recurse into children (function_definition scopes contain calls too).
        for child in node.children:
            _visit(child)

    def _scope_for(offset: int, ranges: list[tuple[int, int, str]]) -> str:
        # Innermost enclosing function wins — walk in reverse so nested
        # defs override outer ones.
        for s, e, name in reversed(ranges):
            if s <= offset < e:
                return normalize_function_qnode(name)
        return normalize_function_qnode("")

    _visit(root)
    return imports, functions, calls, assigns, returns, call_args


def _text_of(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _snippet_at(src: bytes, node) -> str:
    line_start = src.rfind(b"\n", 0, node.start_byte) + 1
    line_end = src.find(b"\n", node.end_byte)
    if line_end == -1:
        line_end = len(src)
    return src[line_start:line_end].decode("utf-8", errors="ignore").strip()[:120]


def _scope_at(offset: int, ranges: list[tuple[int, int, str]]) -> str:
    """Innermost enclosing function name for a byte offset, "" if module-level."""
    for s, e, name in reversed(ranges):
        if s <= offset < e:
            return name
    return ""


def _collect_identifier_symbols(node, src: bytes) -> list[str]:
    """Collect identifier symbols from an expression subtree in source order."""
    out: list[str] = []

    def _walk(cur):
        if cur is None:
            return
        if cur.type == "identifier":
            out.append(_text_of(src, cur))
            return
        for child in getattr(cur, "named_children", ()):
            _walk(child)

    _walk(node)
    seen: set[str] = set()
    deduped: list[str] = []
    for sym in out:
        if sym and sym not in seen:
            seen.add(sym)
            deduped.append(sym)
    return deduped


# tree-sitter-java node types: import_declaration, scoped_identifier,
# method_declaration, constructor_declaration, class_declaration,
# method_invocation (fields: object?, name), object_creation_expression
# (field: type), field_access (field: object, field).

def _java_leftmost(node, src: bytes) -> str:
    cur = node
    while cur is not None:
        if cur.type == "identifier":
            return _text_of(src, cur)
        if cur.type == "field_access":
            cur = cur.child_by_field_name("object") or (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.type == "method_invocation":
            obj = cur.child_by_field_name("object")
            if obj is None:
                return ""
            cur = obj
            continue
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _java_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    fn_ranges: list[tuple[int, int, str]] = []
    calls: list[tuple[int, str, str, str, str]] = []
    assigns: list[VarAssignFact] = []
    returns: list[ReturnFact] = []
    call_args: list[CallArgFact] = []
    class_stack: list[str] = []
    package_name = ""
    local_types: dict[str, str] = {}
    generic_hints: dict[str, str] = {}

    def _normalize_type_name(raw: str) -> str:
        # Strip generics/arrays/annotations so lookups stay stable.
        t = re.sub(r"<[^>]*>", "", raw)
        t = t.replace("[]", "").strip()
        t = t.split()[-1] if t else ""
        return t

    def _resolve_type(raw: str) -> str:
        t = _normalize_type_name(raw)
        if not t:
            return ""
        if "." in t:
            return t
        if t in imports:
            return imports[t]
        if package_name:
            return f"{package_name}.{t}"
        return t

    def _first_generic_type_arg(raw: str) -> str:
        m = re.search(r"<\s*([^,>]+)", str(raw or ""))
        if not m:
            return ""
        hint = m.group(1).strip()
        hint = hint.replace("? extends", "").replace("? super", "").strip()
        return _normalize_type_name(hint)

    def _ctor_type_from_node(node) -> str:
        """Best-effort concrete type extraction from Java expressions.

        Supports:
        - `new Foo(...)`
        - cast expressions like `(Foo) value`
        """
        if node is None:
            return ""
        if node.type == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                return _resolve_type(_text_of(src, type_node))
            return ""
        if node.type == "cast_expression":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                return _resolve_type(_text_of(src, type_node))
            return ""
        return ""

    def _java_call_target(node) -> str | None:
        parent = node.parent
        if parent is None:
            return None
        if parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            right = parent.child_by_field_name("right")
            if right is node and left is not None and left.type == "identifier":
                return _text_of(src, left)
        if parent.type == "variable_declarator":
            val = parent.child_by_field_name("value")
            name = parent.child_by_field_name("name")
            if val is node and name is not None and name.type == "identifier":
                return _text_of(src, name)
        return None

    def _java_identifier_args(call_node) -> list[str]:
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            return []
        out: list[str] = []
        for c in args_node.named_children:
            out.extend(_collect_identifier_symbols(c, src))
        return out

    def _java_param_name_and_type(node) -> tuple[str, str]:
        name_node = node.child_by_field_name("name")
        type_node = node.child_by_field_name("type")

        if name_node is None or type_node is None:
            for child in node.named_children:
                if name_node is None and child.type == "identifier":
                    name_node = child
                elif name_node is None and child.type == "variable_declarator":
                    inner = child.child_by_field_name("name")
                    if inner is not None:
                        name_node = inner
                if type_node is None and child.type in {
                    "type_identifier",
                    "integral_type",
                    "floating_point_type",
                    "boolean_type",
                    "void_type",
                    "generic_type",
                    "array_type",
                    "catch_type",
                    "scoped_type_identifier",
                }:
                    type_node = child

        name = _text_of(src, name_node) if name_node is not None else ""
        raw_type = _text_of(src, type_node) if type_node is not None else ""
        return name, raw_type

    def _java_invocation_parts(node) -> tuple[str, str]:
        name_node = node.child_by_field_name("name")
        method = _text_of(src, name_node) if name_node else ""
        obj_node = node.child_by_field_name("object")
        receiver = _java_leftmost(obj_node, src) if obj_node is not None else ""
        return receiver, method

    def _java_return_identifier(ret_node) -> str | None:
        val = ret_node.child_by_field_name("value")
        if val is None:
            for c in ret_node.named_children:
                if c.type == "identifier":
                    val = c
                    break
        if val is not None and val.type == "identifier":
            return _text_of(src, val)
        return None

    def _visit(node):
        nonlocal package_name
        t = node.type
        if t == "package_declaration":
            for c in node.children:
                if c.type == "scoped_identifier":
                    package_name = _text_of(src, c)
                    break
        elif t == "import_declaration":
            qname = ""
            is_wildcard = False
            is_static = False
            for c in node.children:
                if c.type == "scoped_identifier":
                    qname = _text_of(src, c)
                elif c.type == "asterisk":
                    is_wildcard = True
                elif c.type == "static":
                    is_static = True
            if qname and not is_wildcard:
                imports[qname.split(".")[-1]] = qname
            elif qname and is_wildcard and is_static:
                # Minimal deterministic signal for `import static X.*`.
                imports[f"__static_wildcard__:{qname}"] = f"{qname}.*"
        elif t == "class_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                cls = _text_of(src, name_node)
                if cls:
                    imports[cls] = f"{package_name}.{cls}" if package_name else cls
                    class_stack.append(cls)
                    # Record implements/extends relationships so that
                    # iface_method_to_fids in _graph.py can resolve interface
                    # dispatch correctly. We emit one __supertype__:<cls> key
                    # per direct supertype, using the short name so the graph
                    # builder can look up interface → implementation mappings.
                    for c in node.children:
                        if c.type == "super_interfaces":
                            # implements clause: children are type_list items
                            for tc in c.named_children:
                                raw = _text_of(src, tc).strip()
                                # Strip generic params: List<T> → List
                                base = re.sub(r"<[^>]*>", "", raw).strip()
                                if base:
                                    simple = base.split(".")[-1]
                                    imports[f"__supertype__:{cls}:{simple}"] = (
                                        _resolve_type(base) if "." not in base else base
                                    )
                        elif c.type == "superclass":
                            # extends clause: single type
                            for tc in c.named_children:
                                raw = _text_of(src, tc).strip()
                                base = re.sub(r"<[^>]*>", "", raw).strip()
                                if base:
                                    simple = base.split(".")[-1]
                                    imports[f"__supertype__:{cls}:{simple}"] = (
                                        _resolve_type(base) if "." not in base else base
                                    )
                    for c in node.children:
                        _visit(c)
                    class_stack.pop()
                    return
        elif t in ("method_declaration", "constructor_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                params_node = node.child_by_field_name("parameters")
                param_type_names: list[str] = []
                param_names_j: list[str] = []
                if params_node is not None:
                    for param in params_node.named_children:
                        if param.type in ("formal_parameter", "spread_parameter"):
                            type_node = param.child_by_field_name("type")
                            pname_node = param.child_by_field_name("name")
                            if type_node is not None:
                                raw_t = _text_of(src, type_node)
                                t_stripped = re.sub(r"<[^>]*>", "", raw_t).replace("[]", "").strip().split()[-1] if raw_t else ""
                                param_type_names.append(t_stripped)
                            if pname_node is not None:
                                param_names_j.append(_text_of(src, pname_node))
                class_prefix = ".".join(class_stack) + "." if class_stack else ""
                param_sig = "(" + ", ".join(param_type_names) + ")"
                qnode_j = f"{class_prefix}{fname}{param_sig}"
                param_text_j = _text_of(src, params_node) if params_node is not None else ""
                functions.append(FuncDef(
                    name=fname,
                    class_name=".".join(class_stack),
                    qnode=qnode_j,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    parameter_text=param_text_j,
                    parameter_names=tuple(param_names_j),
                ))
                fn_ranges.append((node.start_byte, node.end_byte, qnode_j))
        elif t in ("formal_parameter", "catch_formal_parameter", "spread_parameter"):
            p_name, raw_type = _java_param_name_and_type(node)
            if p_name and raw_type:
                local_types[p_name] = _resolve_type(raw_type)
                g0 = _first_generic_type_arg(raw_type)
                if g0:
                    generic_hints[f"{p_name}.__generic0__"] = _resolve_type(g0)
        elif t == "local_variable_declaration":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                raw_decl_type = _text_of(src, type_node)
                resolved_type = _resolve_type(raw_decl_type)
                generic0 = _first_generic_type_arg(raw_decl_type)
                if resolved_type:
                    for c in node.children:
                        if c.type == "variable_declarator":
                            n = c.child_by_field_name("name")
                            if n is not None:
                                name = _text_of(src, n)
                                # Prefer concrete initializer types when available:
                                # `Iface x = new Impl()` should resolve `x` to `Impl`
                                # for call matching, not only `Iface`.
                                init = c.child_by_field_name("value")
                                narrowed = _ctor_type_from_node(init)
                                local_types[name] = narrowed or resolved_type
                                if generic0:
                                    generic_hints[f"{name}.__generic0__"] = _resolve_type(generic0)
                                # Emit assign fact from the same declarator.
                                val_node = init
                                if val_node is not None:
                                    src_sym_lv: str | None = None
                                    src_call_lv: str | None = None
                                    if val_node.type == "identifier":
                                        src_sym_lv = _text_of(src, val_node)
                                    elif val_node.type == "method_invocation":
                                        _recv_lv, method_lv = _java_invocation_parts(val_node)
                                        src_call_lv = method_lv or None
                                    elif val_node.type == "object_creation_expression":
                                        tn_lv = val_node.child_by_field_name("type")
                                        if tn_lv is not None:
                                            src_call_lv = _text_of(src, tn_lv).split(".")[-1].strip() or None
                                    if src_sym_lv is not None or src_call_lv is not None:
                                        assigns.append(VarAssignFact(
                                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                                            line=node.start_point[0] + 1,
                                            dst_symbol=name,
                                            src_symbol=src_sym_lv,
                                            src_call=src_call_lv,
                                        ))
        elif t == "enhanced_for_statement":
            loop_name = ""
            raw_loop_type = ""
            for child in node.named_children:
                if not raw_loop_type and child.type in {
                    "type_identifier",
                    "integral_type",
                    "floating_point_type",
                    "boolean_type",
                    "generic_type",
                    "array_type",
                    "scoped_type_identifier",
                }:
                    raw_loop_type = _text_of(src, child)
                    continue
                if raw_loop_type and not loop_name and child.type == "identifier":
                    loop_name = _text_of(src, child)
                    break
            if loop_name and raw_loop_type:
                local_types[loop_name] = _resolve_type(raw_loop_type)
                g0 = _first_generic_type_arg(raw_loop_type)
                if g0:
                    generic_hints[f"{loop_name}.__generic0__"] = _resolve_type(g0)
        elif t == "assignment_expression":
            # Track reassignments that narrow variable types, e.g.:
            # `conn = new HttpURLConnection(...)` or `x = (Foo) y`.
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "identifier" and right is not None:
                narrowed = _ctor_type_from_node(right)
                if narrowed:
                    local_types[_text_of(src, left)] = narrowed
                src_symbol: str | None = None
                src_call: str | None = None
                if right.type == "identifier":
                    src_symbol = _text_of(src, right)
                elif right.type == "method_invocation":
                    _recv, method = _java_invocation_parts(right)
                    src_call = method or None
                elif right.type == "object_creation_expression":
                    type_node = right.child_by_field_name("type")
                    if type_node is not None:
                        src_call = _text_of(src, type_node).split(".")[-1].strip() or None
                if src_symbol is not None or src_call is not None:
                    assigns.append(VarAssignFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        dst_symbol=_text_of(src, left),
                        src_symbol=src_symbol,
                        src_call=src_call,
                    ))
        elif t == "method_invocation":
            receiver, method = _java_invocation_parts(node)
            if method:
                line = node.start_point[0] + 1
                scope = _scope_at(node.start_byte, fn_ranges)
                calls.append((
                    line, receiver, method,
                    scope,
                    _snippet_at(src, node)))
                call_args.append(CallArgFact(
                    function_qnode=scope,
                    line=line,
                    callee_name=method,
                    receiver=receiver,
                    arg_symbols=_java_identifier_args(node),
                    target_symbol=_java_call_target(node),
                ))
        elif t == "lambda_expression":
            parent_scope = _scope_at(node.start_byte, fn_ranges)
            synthetic = f"<lambda@{node.start_point[0] + 1}>"
            qnode = f"{parent_scope}.{synthetic}" if parent_scope else synthetic
            fn_ranges.append((node.start_byte, node.end_byte, qnode))
            for c in node.children:
                _visit(c)
            return
        elif t == "method_reference":
            txt = _text_of(src, node)
            left, right = (txt.split("::", 1) + [""])[:2]
            recv_raw = left.strip()
            meth_raw = right.strip()
            method = ""
            if meth_raw == "new":
                method = recv_raw.split(".")[-1] if recv_raw else "new"
            elif meth_raw:
                method = meth_raw.split("(")[0].strip()
            receiver = recv_raw.split(".")[0] if recv_raw else ""
            if method:
                line = node.start_point[0] + 1
                scope = _scope_at(node.start_byte, fn_ranges)
                calls.append((line, receiver, method, scope, _snippet_at(src, node)))
                call_args.append(CallArgFact(
                    function_qnode=scope,
                    line=line,
                    callee_name=method,
                    receiver=receiver,
                    arg_symbols=[],
                    target_symbol=None,
                ))
        elif t == "object_creation_expression":
            # `new Foo(...)` — receiver empty, method = short class name.
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                cls = _text_of(src, type_node).split(".")[-1].strip()
                if cls:
                    line = node.start_point[0] + 1
                    scope = _scope_at(node.start_byte, fn_ranges)
                    calls.append((
                        line, "", cls,
                        scope,
                        _snippet_at(src, node)))
                    call_args.append(CallArgFact(
                        function_qnode=scope,
                        line=line,
                        callee_name=cls,
                        receiver="",
                        arg_symbols=_java_identifier_args(node),
                        target_symbol=_java_call_target(node),
                    ))
        elif t == "return_statement":
            returns.append(ReturnFact(
                function_qnode=_scope_at(node.start_byte, fn_ranges),
                line=node.start_point[0] + 1,
                symbol=_java_return_identifier(node),
            ))
        for c in node.children:
            _visit(c)

    _visit(root)
    # Lightweight type hints for variable receivers: let matcher resolve
    # receiver variables through inferred declaration/parameter types.
    imports.update({k: v for k, v in local_types.items() if v})
    imports.update({k: v for k, v in generic_hints.items() if v})
    return imports, functions, calls, assigns, returns, call_args


# tree-sitter-javascript / tree-sitter-typescript node types:
# import_statement (import_clause, source), variable_declarator,
# function_declaration, method_definition, arrow_function,
# call_expression (fields: function, arguments),
# member_expression (fields: object, property).

def _js_leftmost(node, src: bytes) -> str:
    cur = node
    while cur is not None:
        if cur.type in ("identifier", "property_identifier"):
            return _text_of(src, cur)
        if cur.type == "subscript_expression":
            cur = cur.child_by_field_name("object") or (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.type == "parenthesized_expression":
            cur = cur.named_children[0] if cur.named_children else None
            continue
        if cur.type == "member_expression":
            cur = cur.child_by_field_name("object") or (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.type == "call_expression":
            cur = cur.child_by_field_name("function")
            continue
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _js_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    fn_ranges: list[tuple[int, int, str]] = []
    calls: list[tuple[int, str, str, str, str]] = []
    assigns: list[VarAssignFact] = []
    returns: list[ReturnFact] = []
    call_args: list[CallArgFact] = []
    class_stack: list[str] = []
    local_types: dict[str, str] = {}
    generic_hints: dict[str, str] = {}
    
    # GAP-TS-05: Load TypeScript path aliases from tsconfig.json
    path_aliases: dict[str, str] = {}
    base_url = ""
    try:
        # Try to find and load tsconfig.json from the workspace
        # This is a simple heuristic: check parent directories
        import json
        import os
        cwd = os.getcwd()
        for _ in range(5):  # Check up to 5 levels up
            tsconfig_path = os.path.join(cwd, "tsconfig.json")
            if os.path.exists(tsconfig_path):
                with open(tsconfig_path, 'r') as f:
                    tsconfig = json.load(f)
                    compiler_opts = tsconfig.get("compilerOptions", {})
                    base_url = compiler_opts.get("baseUrl", "")
                    paths = compiler_opts.get("paths", {})
                    # Convert path patterns: "@/*" -> "src/*" becomes "@/*" -> "src/"
                    for pattern, mappings in (paths or {}).items():
                        if mappings and len(mappings) > 0:
                            # Take first mapping, strip trailing /*
                            first_mapping = mappings[0].rstrip("/*").strip()
                            # Remove trailing /* from pattern
                            clean_pattern = pattern.rstrip("/*").strip()
                            path_aliases[clean_pattern] = first_mapping
                    break
            cwd = os.path.dirname(cwd)
            if cwd == os.path.dirname(cwd):  # root directory
                break
    except Exception:
        pass  # If tsconfig parsing fails, continue without path aliases

    def _resolve_import_path(path: str) -> str:
        """Resolve TypeScript path aliases (e.g., @/utils -> src/utils)."""
        if not path or not path_aliases:
            return path
        # Check for matching alias patterns
        for alias, target in path_aliases.items():
            if path.startswith(alias):
                # Replace alias prefix with target
                return target + path[len(alias):]
        return path

    def _js_normalize_type(raw: str) -> str:
        txt = str(raw or "").strip()
        if txt.startswith(":"):
            txt = txt[1:].strip()
        txt = txt.replace("readonly ", "").replace("?", "").strip()
        if txt.endswith("[]"):
            txt = txt[:-2].strip()
        txt = re.sub(r"<[^>]*>", "", txt).strip()
        return txt.split(".")[-1] if txt else ""

    def _js_first_generic_type(raw: str) -> str:
        txt = str(raw or "").strip()
        if txt.startswith(":"):
            txt = txt[1:].strip()
        if txt.endswith("[]"):
            return _js_normalize_type(txt[:-2])
        m = re.search(r"<\s*([^,>]+)", txt)
        if not m:
            return ""
        return _js_normalize_type(m.group(1).strip())

    def _js_annotation_text(node) -> str:
        if node is None:
            return ""
        return str(_text_of(src, node)).lstrip(":").strip()

    def _js_record_param_hints(params_node) -> None:
        if params_node is None:
            return
        for param in params_node.named_children:
            pname = ""
            raw_type = ""
            if param.type in ("required_parameter", "optional_parameter"):
                pname_node = param.child_by_field_name("pattern") or param.child_by_field_name("name")
                if pname_node is None:
                    for gc in param.named_children:
                        if gc.type == "identifier":
                            pname_node = gc
                            break
                type_node = param.child_by_field_name("type")
                pname = _text_of(src, pname_node) if pname_node is not None and pname_node.type == "identifier" else ""
                raw_type = _js_annotation_text(type_node)
            elif param.type == "identifier":
                pname = _text_of(src, param)
            elif param.type in ("assignment_pattern", "rest_pattern"):
                for gc in param.named_children:
                    if gc.type == "identifier":
                        pname = _text_of(src, gc)
                        break
            if pname and raw_type:
                normalized = _js_normalize_type(raw_type)
                if normalized:
                    local_types[pname] = normalized
                g0 = _js_first_generic_type(raw_type)
                if g0:
                    generic_hints[f"{pname}.__generic0__"] = g0

    def _js_param_info(params_node, fn_node) -> tuple[str, tuple[str, ...]]:
        if params_node is None:
            # single-param arrow shorthand: x => ...
            for c in fn_node.children:
                if c.type == "identifier":
                    return "", (_text_of(src, c),)
            return "", ()
        names: list[str] = []
        for param in params_node.named_children:
            if param.type == "identifier":
                names.append(_text_of(src, param))
            elif param.type in ("required_parameter", "optional_parameter"):
                pname_node = param.child_by_field_name("pattern") or (
                    param.children[0] if param.child_count else None
                )
                if pname_node is not None and pname_node.type == "identifier":
                    names.append(_text_of(src, pname_node))
            elif param.type in ("assignment_pattern", "rest_pattern"):
                for gc in param.named_children:
                    if gc.type == "identifier":
                        names.append(_text_of(src, gc))
                        break
        return _text_of(src, params_node), tuple(names)

    def _js_collect_identifiers(node, out: list[str]) -> None:
        if node is None:
            return
        if node.type == "identifier":
            out.append(_text_of(src, node))
            return
        for c in node.named_children:
            _js_collect_identifiers(c, out)

    def _js_rhs_taint_symbols(node) -> list[str]:
        if node is None:
            return []
        if node.type in ("conditional_expression", "ternary_expression", "template_string", "template_literal"):
            syms: list[str] = []
            _js_collect_identifiers(node, syms)
            # Preserve order but dedupe.
            seen: set[str] = set()
            out: list[str] = []
            for s in syms:
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
            return out
        return []

    def _js_call_parts(call_node) -> tuple[str, str]:
        fn = call_node.child_by_field_name("function")
        cur = fn
        while cur is not None and cur.type == "parenthesized_expression":
            cur = cur.named_children[0] if cur.named_children else None

        while cur is not None:
            if cur.type == "member_expression":
                prop = cur.child_by_field_name("property")
                method = _text_of(src, prop) if prop else ""
                return _js_leftmost(cur, src), method
            if cur.type == "identifier":
                return "", _text_of(src, cur)
            if cur.type == "subscript_expression":
                obj = cur.child_by_field_name("object")
                idx = cur.child_by_field_name("index")
                method = ""
                if idx is not None:
                    method = _text_of(src, idx).strip().strip('"\'`')
                return _js_leftmost(obj, src) if obj is not None else "", method
            if cur.type == "call_expression":
                cur = cur.child_by_field_name("function")
                continue
            break

        return "", ""

    def _js_identifier_args(call_node) -> list[str]:
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            return []
        out: list[str] = []
        for arg in args_node.named_children:
            out.extend(_collect_identifier_symbols(arg, src))
        return out

    def _visit(node):
        t = node.type
        if t == "import_statement":
            src_node = node.child_by_field_name("source")
            src_txt = _text_of(src, src_node).strip("\"'") if src_node else ""
            # Resolve path aliases for TypeScript
            src_txt = _resolve_import_path(src_txt)
            for c in node.children:
                if c.type != "import_clause":
                    continue
                for gc in c.children:
                    if gc.type == "identifier":
                        imports[_text_of(src, gc)] = src_txt
                    elif gc.type == "namespace_import":
                        for ggc in gc.children:
                            if ggc.type == "identifier":
                                imports[_text_of(src, ggc)] = src_txt
                    elif gc.type == "named_imports":
                        for spec in gc.children:
                            if spec.type != "import_specifier":
                                continue
                            n = spec.child_by_field_name("name")
                            a = spec.child_by_field_name("alias")
                            if n is None:
                                continue
                            local = _text_of(src, a) if a else _text_of(src, n)
                            imports[local] = (
                                f"{src_txt}.{_text_of(src, n)}"
                                if src_txt else _text_of(src, n))
        elif t == "variable_declarator":
            # const x = require('y')  — CommonJS shape
            n = node.child_by_field_name("name")
            v = node.child_by_field_name("value")
            if n is not None and v is not None:
                if v.type == "call_expression":
                    fn = v.child_by_field_name("function")
                    if (fn is not None and fn.type == "identifier"
                            and _text_of(src, fn) == "require"):
                        args = v.child_by_field_name("arguments")
                        saw_static = False
                        if args is not None:
                            for arg in args.children:
                                if arg.type == "string":
                                    saw_static = True
                                    req_path = _text_of(src, arg).strip("\"'")
                                    # Resolve path aliases for require() as well
                                    req_path = _resolve_import_path(req_path)
                                    imports[_text_of(src, n)] = req_path
                            if not saw_static and n.type == "identifier":
                                imports[_text_of(src, n)] = "__dynamic_require__"
                elif v.type in ("arrow_function", "function", "function_expression"):
                    # Arrow functions and function expressions assigned to a
                    # variable get a FuncDef. "function_expression" is the node
                    # type tree-sitter actually produces for
                    # `const f = function () {}` — without it that whole form
                    # was skipped here, even though the class-field branch below
                    # already listed it. "function" is kept for grammar
                    # versions that use the shorter name.
                    var_name = _text_of(src, n) if n.type == "identifier" else ""
                    if var_name:
                        params_node = v.child_by_field_name("parameters") or v.child_by_field_name("parameter")
                        _js_record_param_hints(params_node)
                        pnames: list[str] = []
                        ptypes: list[str] = []
                        if params_node is not None:
                            for param in params_node.named_children:
                                if param.type == "identifier":
                                    pnames.append(_text_of(src, param))
                                elif param.type in ("required_parameter", "optional_parameter"):
                                    pname_node = param.child_by_field_name("pattern") or (param.children[0] if param.child_count else None)
                                    if pname_node is not None and pname_node.type == "identifier":
                                        pnames.append(_text_of(src, pname_node))
                                    type_node = param.child_by_field_name("type")
                                    if type_node is not None:
                                        ptypes.append(_text_of(src, type_node))
                        elif params_node is None:
                            # single-param arrow: param => body
                            for c in v.children:
                                if c.type == "identifier":
                                    pnames.append(_text_of(src, c))
                                    break
                        class_ctx = class_stack[-1] if class_stack else ""
                        scope_qnode = f"{class_ctx}.{var_name}" if class_ctx else var_name
                        param_sig_js = "(" + ", ".join(pnames) + ")"
                        full_qnode_js = f"{scope_qnode}{param_sig_js}"
                        param_text_js = _text_of(src, params_node) if params_node is not None else ""
                        functions.append(FuncDef(
                            name=var_name,
                            class_name=class_ctx,
                            qnode=full_qnode_js,
                            start_line=v.start_point[0] + 1,
                            end_line=v.end_point[0] + 1,
                            parameter_text=param_text_js,
                            parameter_names=tuple(pnames),
                        ))
                        fn_ranges.append((v.start_byte, v.end_byte, full_qnode_js))
                elif n.type == "identifier":
                    dst = _text_of(src, n)
                    ann_node = node.child_by_field_name("type")
                    raw_ann = _js_annotation_text(ann_node)
                    if raw_ann:
                        normalized = _js_normalize_type(raw_ann)
                        if normalized:
                            local_types[dst] = normalized
                        g0 = _js_first_generic_type(raw_ann)
                        if g0:
                            generic_hints[f"{dst}.__generic0__"] = g0
                    if v.type == "identifier":
                        src_name = _text_of(src, v)
                        if dst and src_name:
                            if dst not in local_types and src_name in local_types:
                                local_types[dst] = local_types[src_name]
                            hinted_g0 = generic_hints.get(f"{src_name}.__generic0__", "")
                            if hinted_g0:
                                generic_hints[f"{dst}.__generic0__"] = hinted_g0
                    elif v.type == "new_expression":
                        ctor = v.child_by_field_name("constructor") or (v.named_children[0] if v.named_children else None)
                        ctor_txt = _text_of(src, ctor) if ctor is not None else ""
                        normalized = _js_normalize_type(ctor_txt)
                        if dst and normalized:
                            local_types[dst] = normalized
                    for sym in _js_rhs_taint_symbols(v):
                        assigns.append(VarAssignFact(
                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                            line=node.start_point[0] + 1,
                            dst_symbol=dst,
                            src_symbol=sym,
                        ))
                elif v.type == "identifier" and n.type == "identifier":
                    # simple alias: const y = x
                    assigns.append(VarAssignFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        dst_symbol=_text_of(src, n),
                        src_symbol=_text_of(src, v),
                    ))
        elif t in ("public_field_definition", "field_definition", "property_definition"):
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is None or value_node is None:
                for c in node.named_children:
                    if name_node is None and c.type in ("property_identifier", "identifier"):
                        name_node = c
                        continue
                    if value_node is None and c.type in ("arrow_function", "function", "function_expression"):
                        value_node = c
            if (
                name_node is not None
                and value_node is not None
                and value_node.type in ("arrow_function", "function", "function_expression")
            ):
                fname = _text_of(src, name_node)
                params_node = value_node.child_by_field_name("parameters") or value_node.child_by_field_name("parameter")
                _js_record_param_hints(params_node)
                param_text, param_names = _js_param_info(params_node, value_node)
                class_ctx = class_stack[-1] if class_stack else ""
                scope_qnode = f"{class_ctx}.{fname}" if class_ctx else fname
                qnode_js = f"{scope_qnode}({', '.join(param_names)})"
                functions.append(FuncDef(
                    name=fname,
                    class_name=class_ctx,
                    qnode=qnode_js,
                    start_line=value_node.start_point[0] + 1,
                    end_line=value_node.end_point[0] + 1,
                    parameter_text=param_text,
                    parameter_names=param_names,
                ))
                fn_ranges.append((value_node.start_byte, value_node.end_byte, qnode_js))
        elif t == "class_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                cls = _text_of(src, name_node)
                if cls:
                    class_stack.append(cls)
                    # Record extends/implements from class_heritage children
                    # (tree-sitter-javascript: class_heritage → extends_clause or
                    # implements_clause; TypeScript also has implements_clause).
                    for c in node.children:
                        if c.type in ("class_heritage", "extends_clause", "implements_clause"):
                            for hc in c.named_children:
                                raw = _text_of(src, hc).strip()
                                # Strip generic params
                                base = re.sub(r"<[^>]*>", "", raw).strip()
                                if base and not base.startswith("{"):
                                    simple = base.split(".")[-1]
                                    imports[f"__supertype__:{cls}:{simple}"] = base
                    for c in node.children:
                        _visit(c)
                    class_stack.pop()
                    return
        elif t in ("function_declaration", "method_definition",
                   "generator_function_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                params_node = node.child_by_field_name("parameters")
                _js_record_param_hints(params_node)
                param_text, param_names = _js_param_info(params_node, node)
                class_ctx = class_stack[-1] if class_stack else ""
                scope_qnode = f"{class_ctx}.{fname}" if class_ctx else fname
                qnode_js = f"{scope_qnode}({', '.join(param_names)})"
                functions.append(FuncDef(
                    name=fname,
                    class_name=class_stack[-1] if class_stack else "",
                    qnode=qnode_js,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    parameter_text=param_text,
                    parameter_names=param_names,
                ))
                fn_ranges.append((node.start_byte, node.end_byte, qnode_js))
        elif t == "call_expression":
            receiver, method = _js_call_parts(node)
            if method:
                line = node.start_point[0] + 1
                scope = _scope_at(node.start_byte, fn_ranges)
                calls.append((line, receiver, method, scope, _snippet_at(src, node)))
                # GAP-JS-01: emit CallArgFact for intra-procedural taint
                arg_syms = _js_identifier_args(node)
                # target symbol: what variable receives the return value
                target_sym: str | None = None
                parent = node.parent
                if parent is not None:
                    if parent.type == "variable_declarator":
                        tgt = parent.child_by_field_name("name")
                        if tgt is not None and tgt.type == "identifier":
                            target_sym = _text_of(src, tgt)
                    elif parent.type == "assignment_expression":
                        left = parent.child_by_field_name("left")
                        right = parent.child_by_field_name("right")
                        if right is node and left is not None and left.type == "identifier":
                            target_sym = _text_of(src, left)
                call_args.append(CallArgFact(
                    function_qnode=scope,
                    line=line,
                    callee_name=method,
                    receiver=receiver,
                    arg_symbols=arg_syms,
                    target_symbol=target_sym,
                ))
                # Callback handlers passed inline as arguments —
                # `app.get('/x', (req, res) => ...)`, `router.post(p, mw, h)`.
                # This is the dominant server-side shape in Express/Koa/Fastify,
                # and without it those bodies belong to NO function: they get no
                # FuncDef, no def-span and no qnode, so a sink inside a route
                # handler cannot be attributed to a reviewable unit and the
                # entry point falls back to a synthetic "<line-N>" name. On a
                # ~900-file Express app this left 0 framework entry points and 0
                # taint evidence while function extraction otherwise looked
                # healthy, i.e. the real attack surface was invisible.
                #
                # Named after the callee and, when the call carries a string
                # literal first argument, that route path — so the handler reads
                # as `get('/products')` rather than an opaque `<anon>`. That
                # keeps it greppable, stable across runs, and matchable against
                # the route the framework registers.
                args_node = node.child_by_field_name("arguments")
                if args_node is not None:
                    route_lit = ""
                    for a in args_node.named_children:
                        if a.type in ("string", "template_string"):
                            route_lit = _text_of(src, a).strip("\"'`")
                            break
                    idx = 0
                    for a in args_node.named_children:
                        if a.type not in ("arrow_function", "function",
                                          "function_expression"):
                            continue
                        idx += 1
                        base = method or "callback"
                        label = f"{base}({route_lit})" if route_lit else base
                        if idx > 1:
                            label = f"{label}#{idx}"
                        params_node = (a.child_by_field_name("parameters")
                                       or a.child_by_field_name("parameter"))
                        _js_record_param_hints(params_node)
                        p_text, p_names = _js_param_info(params_node, a)
                        # `idx` disambiguates only WITHIN one argument list, so
                        # two separate calls to the same callee still collided:
                        # `db.query(sqlA, cb)` and `db.query(sqlB, cb)` both
                        # became `query(err, rows)`. Sharing a qnode shares an
                        # `_fn_id`, and build_taint_paths pairs a source to a
                        # sink whenever they agree on one — so a `req.*` read in
                        # one callback was reported as flowing into an unrelated
                        # callback's sink. That is a FABRICATED taint path, not
                        # a missed one, and it reaches the report as a phantom
                        # injection finding. A route literal usually keeps these
                        # apart (`get(/products)`), which is why only the
                        # literal-free shape collides.
                        #
                        # Disambiguated by start line, and only on an actual
                        # collision, so the greppable route-named labels every
                        # other consumer already matches on stay byte-identical.
                        # The walk is deterministic, so the suffix is stable
                        # across runs of the same file.
                        qnode = f"{label}({', '.join(p_names)})"
                        if qnode in {f.qnode for f in functions}:
                            qnode = f"{label}@L{a.start_point[0] + 1}" \
                                    f"({', '.join(p_names)})"
                        functions.append(FuncDef(
                            name=label,
                            class_name=class_stack[-1] if class_stack else "",
                            qnode=qnode,
                            start_line=a.start_point[0] + 1,
                            end_line=a.end_point[0] + 1,
                            parameter_text=p_text,
                            parameter_names=p_names,
                        ))
                        fn_ranges.append((a.start_byte, a.end_byte, qnode))
        elif t == "return_statement":
            ret_sym: str | None = None
            for c in node.named_children:
                if c.type == "identifier":
                    ret_sym = _text_of(src, c)
                    break
            returns.append(ReturnFact(
                function_qnode=_scope_at(node.start_byte, fn_ranges),
                line=node.start_point[0] + 1,
                symbol=ret_sym,
            ))
            # A RETURNED handler — `module.exports = function () { return (req,
            # res) => { ... } }`. This is the canonical route shape in the
            # benchmark's Express target, and like the inline-argument case above
            # the returned body otherwise belongs to no function at all. Named
            # after the enclosing function so the pair reads as
            # `searchProducts>handler`, which keeps the owning module visible.
            for c in node.named_children:
                if c.type not in ("arrow_function", "function",
                                  "function_expression"):
                    continue
                outer = _scope_at(node.start_byte, fn_ranges)
                outer_name = outer.split("(")[0] if outer else ""
                label = f"{outer_name}>handler" if outer_name else "handler"
                params_node = (c.child_by_field_name("parameters")
                               or c.child_by_field_name("parameter"))
                _js_record_param_hints(params_node)
                p_text, p_names = _js_param_info(params_node, c)
                functions.append(FuncDef(
                    name=label,
                    class_name=class_stack[-1] if class_stack else "",
                    qnode=f"{label}({', '.join(p_names)})",
                    start_line=c.start_point[0] + 1,
                    end_line=c.end_point[0] + 1,
                    parameter_text=p_text,
                    parameter_names=p_names,
                ))
                fn_ranges.append((c.start_byte, c.end_byte,
                                  f"{label}({', '.join(p_names)})"))
        elif t == "assignment_expression":
            # track variable assignments for taint propagation
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            # A function assigned rather than declared — `module.exports =
            # function search() {...}`, `exports.handler = async (e) => {...}`,
            # `app.locals.fn = function () {...}`. Same class of miss as the
            # inline-argument and returned-handler cases: the body owns no
            # FuncDef, so nothing inside it can be attributed. Only the
            # variable_declarator form (`const f = function(){}`) was covered.
            if (right is not None and left is not None
                    and right.type in ("arrow_function", "function",
                                       "function_expression")):
                nm = right.child_by_field_name("name")
                if nm is not None:
                    fname_as = _text_of(src, nm)
                else:
                    # Name after the assignment target, keeping only the last
                    # dotted segment so `exports.handler` reads as `handler`.
                    fname_as = _text_of(src, left).split(".")[-1].strip()
                if fname_as:
                    params_node = (right.child_by_field_name("parameters")
                                   or right.child_by_field_name("parameter"))
                    _js_record_param_hints(params_node)
                    p_text, p_names = _js_param_info(params_node, right)
                    cls_as = class_stack[-1] if class_stack else ""
                    scope_as = f"{cls_as}.{fname_as}" if cls_as else fname_as
                    qn_as = f"{scope_as}({', '.join(p_names)})"
                    functions.append(FuncDef(
                        name=fname_as,
                        class_name=cls_as,
                        qnode=qn_as,
                        start_line=right.start_point[0] + 1,
                        end_line=right.end_point[0] + 1,
                        parameter_text=p_text,
                        parameter_names=p_names,
                    ))
                    fn_ranges.append((right.start_byte, right.end_byte, qn_as))
            if left is not None and left.type == "member_expression":
                obj_n = left.child_by_field_name("object")
                prop_n = left.child_by_field_name("property")
                obj_txt = _text_of(src, obj_n) if obj_n is not None else ""
                prop_txt = _text_of(src, prop_n) if prop_n is not None else ""
                left_txt = _text_of(src, left)
                if left_txt == "module.exports":
                    imports["__cjs_export__:default"] = "module.exports"
                elif obj_txt == "exports" and prop_txt:
                    imports[f"__cjs_export__:{prop_txt}"] = "exports"
            if left is not None and left.type == "identifier" and right is not None:
                dst = _text_of(src, left)
                src_sym_js: str | None = None
                src_call_js: str | None = None
                if right.type == "identifier":
                    src_sym_js = _text_of(src, right)
                elif right.type == "call_expression":
                    fn2 = right.child_by_field_name("function")
                    if fn2 is not None:
                        if fn2.type == "member_expression":
                            prop2 = fn2.child_by_field_name("property")
                            src_call_js = _text_of(src, prop2) if prop2 else None
                        elif fn2.type == "identifier":
                            src_call_js = _text_of(src, fn2)
                            if src_call_js == "require":
                                args2 = right.child_by_field_name("arguments")
                                static_req = False
                                if args2 is not None:
                                    for a2 in args2.children:
                                        if a2.type == "string":
                                            static_req = True
                                            imports[dst] = _text_of(src, a2).strip("\"'")
                                            break
                                if not static_req:
                                    imports[dst] = "__dynamic_require__"
                if src_sym_js is not None or src_call_js is not None:
                    assigns.append(VarAssignFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        dst_symbol=dst,
                        src_symbol=src_sym_js,
                        src_call=src_call_js,
                    ))
                for sym in _js_rhs_taint_symbols(right):
                    assigns.append(VarAssignFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        dst_symbol=dst,
                        src_symbol=sym,
                    ))
        elif t == "for_in_statement":
            loop_name = ""
            iterable = ""
            for child in node.named_children:
                if not loop_name and child.type == "identifier":
                    loop_name = _text_of(src, child)
                    continue
                if loop_name and not iterable and child.type == "identifier":
                    iterable = _text_of(src, child)
                    break
            if loop_name and iterable:
                hinted = generic_hints.get(f"{iterable}.__generic0__", "")
                if hinted:
                    local_types[loop_name] = hinted
        for c in node.children:
            _visit(c)

    _visit(root)
    imports.update({k: v for k, v in local_types.items() if v})
    imports.update({k: v for k, v in generic_hints.items() if v})
    return imports, functions, calls, assigns, returns, call_args


# tree-sitter-go node types: import_declaration, import_spec_list, import_spec
# (fields: name?, path), function_declaration, method_declaration,
# call_expression (fields: function, arguments),
# selector_expression (fields: operand, field).

def _go_leftmost(node, src: bytes) -> str:
    cur = node
    while cur is not None:
        if cur.type == "identifier":
            return _text_of(src, cur)
        if cur.type == "selector_expression":
            cur = cur.child_by_field_name("operand") or (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.type == "call_expression":
            cur = cur.child_by_field_name("function")
            continue
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _go_import_spec(spec, src: bytes, imports: dict[str, str]) -> None:
    path_node = spec.child_by_field_name("path")
    name_node = spec.child_by_field_name("name")
    if path_node is None:
        return
    path = _text_of(src, path_node).strip("\"`")
    alias = _text_of(src, name_node) if name_node else path.rsplit("/", 1)[-1]
    if alias and alias not in (".", "_"):
        imports[alias] = path


def _go_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    fn_ranges: list[tuple[int, int, str]] = []
    calls: list[tuple[int, str, str, str, str]] = []

    def _visit(node):
        t = node.type
        if t == "import_declaration":
            for c in node.children:
                if c.type == "import_spec":
                    _go_import_spec(c, src, imports)
                elif c.type == "import_spec_list":
                    for gc in c.children:
                        if gc.type == "import_spec":
                            _go_import_spec(gc, src, imports)
        elif t in ("function_declaration", "method_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                functions.append(FuncDef(
                    name=fname,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1))
                fn_ranges.append((node.start_byte, node.end_byte, fname))
        elif t == "call_expression":
            fn = node.child_by_field_name("function")
            method = ""
            receiver = ""
            if fn is not None:
                if fn.type == "selector_expression":
                    field = fn.child_by_field_name("field")
                    method = _text_of(src, field) if field else ""
                    receiver = _go_leftmost(fn, src)
                elif fn.type == "identifier":
                    method = _text_of(src, fn)
            if method:
                calls.append((
                    node.start_point[0] + 1, receiver, method,
                    _scope_at(node.start_byte, fn_ranges),
                    _snippet_at(src, node)))
        for c in node.children:
            _visit(c)

    _visit(root)
    return imports, functions, calls, [], [], []


# tree-sitter-c-sharp node types: using_directive (field: name),
# method_declaration, constructor_declaration, local_function_statement,
# invocation_expression (fields: function, arguments),
# member_access_expression (fields: expression, name),
# object_creation_expression (field: type).

def _cs_leftmost(node, src: bytes) -> str:
    cur = node
    while cur is not None:
        if cur.type == "identifier":
            return _text_of(src, cur)
        if cur.type == "member_access_expression":
            cur = cur.child_by_field_name("expression") or (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.type in ("invocation_expression", "element_access_expression"):
            fn = cur.child_by_field_name("function")
            cur = fn if fn is not None else (
                cur.children[0] if cur.child_count else None)
            continue
        if cur.child_count > 0:
            cur = cur.children[0]
            continue
        return ""
    return ""


def _cs_extract(src: bytes, tree):
    root = tree.root_node
    imports: dict[str, str] = {}
    functions: list[FuncDef] = []
    fn_ranges: list[tuple[int, int, str]] = []
    calls: list[tuple[int, str, str, str, str]] = []
    assigns: list[VarAssignFact] = []
    returns: list[ReturnFact] = []
    call_args: list[CallArgFact] = []
    class_stack: list[str] = []
    local_types: dict[str, str] = {}
    generic_hints: dict[str, str] = {}

    def _cs_normalize_type(raw: str) -> str:
        txt = re.sub(r"<[^>]*>", "", str(raw or ""))
        txt = txt.replace("[]", "").replace("?", "").strip()
        return txt.split()[-1] if txt else ""

    def _cs_first_generic_type_arg(raw: str) -> str:
        m = re.search(r"<\s*([^,>]+)", str(raw or ""))
        if not m:
            return ""
        return _cs_normalize_type(m.group(1).strip())

    def _cs_local_decl_type(node) -> str:
        parent = node.parent
        if parent is None or parent.type != "variable_declaration":
            return ""
        for child in parent.named_children:
            if child is node:
                continue
            return _text_of(src, child)
        return ""

    def _cs_catch_name_and_type(node) -> tuple[str, str]:
        names = [_text_of(src, child) for child in node.named_children if child.type == "identifier"]
        if len(names) >= 2:
            return names[1], names[0]
        return "", ""

    def _cs_using_static_owner(node) -> str:
        """Extract fully-qualified owner for 'using static X.Y.Z;' directives."""
        text = _text_of(src, node)
        if not text:
            return ""
        # Keep this conservative and deterministic: only accept explicit
        # 'using static <qname>;' directives.
        m = re.search(r"\busing\s+static\s+([A-Za-z_][A-Za-z0-9_\.]*)", text)
        return m.group(1).strip() if m else ""

    def _cs_is_extension_method(method_node) -> bool:
        """Return True when first parameter is a C# extension receiver (this T x)."""
        params_node = method_node.child_by_field_name("parameters")
        if params_node is None:
            return False
        for p in params_node.named_children:
            if p.type != "parameter":
                continue
            ptxt = _text_of(src, p).strip()
            return ptxt.startswith("this ")
        return False

    def _cs_query_clauses(node) -> list[tuple[str, str]]:
        """Emit conservative synthetic LINQ method signals from query syntax.

        This bridges query-expression syntax (from/where/select/...) to
        method-like call edges without attempting full query desugaring.
        """
        mapping = {
            "from_clause": "From",
            "where_clause": "Where",
            "select_clause": "Select",
            "join_clause": "Join",
            "group_clause": "GroupBy",
            "orderby_clause": "OrderBy",
        }
        out: list[tuple[str, str]] = []
        for c in node.named_children:
            method = mapping.get(c.type)
            if not method:
                continue
            recv = ""
            if c.type == "from_clause":
                expr = c.child_by_field_name("expression")
                if expr is not None:
                    recv = _cs_leftmost(expr, src)
            out.append((recv, method))
        return out

    def _cs_invocation_parts(node) -> tuple[str, str]:
        fn = node.child_by_field_name("function")
        if fn is None and node.child_count:
            fn = node.children[0]
        method = ""
        receiver = ""
        if fn is not None:
            if fn.type == "member_access_expression":
                n = fn.child_by_field_name("name")
                method = _text_of(src, n) if n else ""
                receiver = _cs_leftmost(fn, src)
            elif fn.type == "identifier":
                method = _text_of(src, fn)
        return receiver, method

    def _cs_identifier_args(call_node) -> list[str]:
        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            return []
        out: list[str] = []
        for c in args_node.named_children:
            if c.type == "argument":
                expr = c.child_by_field_name("expression")
                out.extend(_collect_identifier_symbols(expr, src))
            else:
                out.extend(_collect_identifier_symbols(c, src))
        return out

    def _cs_call_target(node) -> str | None:
        parent = node.parent
        if parent is None:
            return None
        if parent.type in ("assignment_expression", "simple_assignment_expression"):
            left = parent.child_by_field_name("left")
            right = parent.child_by_field_name("right")
            if right is node and left is not None and left.type == "identifier":
                return _text_of(src, left)
        if parent.type == "equals_value_clause":
            gp = parent.parent
            if gp is not None and gp.type == "variable_declarator":
                name = gp.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    return _text_of(src, name)
        if parent.type == "variable_declarator":
            name = parent.child_by_field_name("name")
            value = parent.child_by_field_name("value")
            if value is node and name is not None and name.type == "identifier":
                return _text_of(src, name)
        return None

    def _cs_return_identifier(ret_node) -> str | None:
        expr = ret_node.child_by_field_name("expression")
        if expr is None:
            for c in ret_node.named_children:
                if c.type == "identifier":
                    expr = c
                    break
        if expr is not None and expr.type == "identifier":
            return _text_of(src, expr)
        return None

    def _cs_assignment_parts(node) -> tuple[str | None, str | None, str | None]:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or left.type != "identifier" or right is None:
            return None, None, None
        
        # Check for += or -= operators (event handler registration/unregistration)
        operator = node.child_by_field_name("operator")
        op_text = _text_of(src, operator) if operator is not None else "="
        is_event_op = op_text in ("+=", "-=")
        
        src_symbol: str | None = None
        src_call: str | None = None
        if right.type == "identifier":
            src_symbol = _text_of(src, right)
        elif right.type == "invocation_expression":
            _recv, method = _cs_invocation_parts(right)
            src_call = method or None
        elif right.type == "object_creation_expression":
            type_node = right.child_by_field_name("type")
            if type_node is not None:
                src_call = _text_of(src, type_node).split(".")[-1].strip() or None
        
        # Mark event handler patterns with __event__ prefix for later processing
        if is_event_op:
            if src_symbol:
                src_symbol = f"__event__:{src_symbol}"
            if src_call:
                src_call = f"__event__:{src_call}"
        
        return _text_of(src, left), src_symbol, src_call

    def _visit(node):
        t = node.type
        if t == "using_directive":
            name_node = node.child_by_field_name("name")
            if name_node is None:
                for c in node.children:
                    if c.type in ("qualified_name", "identifier"):
                        name_node = c
                        break
            if name_node is not None:
                qname = _text_of(src, name_node)
                imports[qname.split(".")[-1]] = qname
            static_owner = _cs_using_static_owner(node)
            if static_owner:
                imports[f"__using_static__:{static_owner.split('.')[-1]}"] = static_owner
        elif t in ("class_declaration", "struct_declaration", "interface_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                cls = _text_of(src, name_node)
                if cls:
                    class_stack.append(cls)
                    # Record C# base types / interfaces from the `bases` list
                    # (tree-sitter-c-sharp: base_list → type_identifier or
                    # qualified_name children) so _graph.py can resolve
                    # interface dispatch via __supertype__ keys.
                    for c in node.children:
                        if c.type == "base_list":
                            for bc in c.named_children:
                                raw = _text_of(src, bc).strip()
                                base = re.sub(r"<[^>]*>", "", raw).strip()
                                if base:
                                    simple = base.split(".")[-1]
                                    imports[f"__supertype__:{cls}:{simple}"] = base
                    for c in node.children:
                        _visit(c)
                    class_stack.pop()
                    return
        elif t in ("method_declaration", "constructor_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                params_node = node.child_by_field_name("parameters")
                param_type_names_cs: list[str] = []
                param_names_cs: list[str] = []
                if params_node is not None:
                    for param in params_node.named_children:
                        if param.type == "parameter":
                            type_node = param.child_by_field_name("type")
                            pname_node = param.child_by_field_name("name")
                            if type_node is not None:
                                raw_t = _text_of(src, type_node)
                                param_type_names_cs.append(raw_t.strip().split("<")[0].split("[")[0].strip())
                            if pname_node is not None:
                                pname = _text_of(src, pname_node)
                                param_names_cs.append(pname)
                                if type_node is not None:
                                    resolved = _cs_normalize_type(_text_of(src, type_node))
                                    if resolved:
                                        local_types[pname] = resolved
                                    g0 = _cs_first_generic_type_arg(_text_of(src, type_node))
                                    if g0:
                                        generic_hints[f"{pname}.__generic0__"] = g0
                class_prefix_cs = ".".join(class_stack) + "." if class_stack else ""
                param_sig_cs = "(" + ", ".join(param_type_names_cs) + ")"
                qnode_cs = f"{class_prefix_cs}{fname}{param_sig_cs}"
                param_text_cs = _text_of(src, params_node) if params_node is not None else ""
                functions.append(FuncDef(
                    name=fname,
                    class_name=".".join(class_stack),
                    qnode=qnode_cs,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    parameter_text=param_text_cs,
                    parameter_names=tuple(param_names_cs),
                ))
                if _cs_is_extension_method(node):
                    owner = ".".join(class_stack)
                    imports[f"__cs_extension_owner__:{qnode_cs}"] = owner
                    imports[f"__cs_extension_method__:{fname}"] = owner
                fn_ranges.append((node.start_byte, node.end_byte, qnode_cs))
        elif t == "local_function_statement":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = _text_of(src, name_node)
                params_node = node.child_by_field_name("parameters")
                param_type_names_lf: list[str] = []
                param_names_lf: list[str] = []
                if params_node is not None:
                    for param in params_node.named_children:
                        if param.type == "parameter":
                            type_node = param.child_by_field_name("type")
                            pname_node = param.child_by_field_name("name")
                            if type_node is not None:
                                param_type_names_lf.append(_text_of(src, type_node).strip().split("<")[0].strip())
                            if pname_node is not None:
                                pname = _text_of(src, pname_node)
                                param_names_lf.append(pname)
                                if type_node is not None:
                                    resolved = _cs_normalize_type(_text_of(src, type_node))
                                    if resolved:
                                        local_types[pname] = resolved
                                    g0 = _cs_first_generic_type_arg(_text_of(src, type_node))
                                    if g0:
                                        generic_hints[f"{pname}.__generic0__"] = g0
                class_prefix_lf = ".".join(class_stack) + "." if class_stack else ""
                param_sig_lf = "(" + ", ".join(param_type_names_lf) + ")"
                qnode_lf = f"{class_prefix_lf}{fname}{param_sig_lf}"
                param_text_lf = _text_of(src, params_node) if params_node is not None else ""
                functions.append(FuncDef(
                    name=fname,
                    class_name=".".join(class_stack),
                    qnode=qnode_lf,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    parameter_text=param_text_lf,
                    parameter_names=tuple(param_names_lf),
                ))
                fn_ranges.append((node.start_byte, node.end_byte, qnode_lf))
        elif t == "invocation_expression":
            receiver, method = _cs_invocation_parts(node)
            if method:
                line = node.start_point[0] + 1
                scope = _scope_at(node.start_byte, fn_ranges)
                calls.append((
                    line, receiver, method,
                    scope,
                    _snippet_at(src, node)))
                call_args.append(CallArgFact(
                    function_qnode=scope,
                    line=line,
                    callee_name=method,
                    receiver=receiver,
                    arg_symbols=_cs_identifier_args(node),
                    target_symbol=_cs_call_target(node),
                ))
                fn_node = node.child_by_field_name("function")
                if fn_node is None and node.child_count:
                    fn_node = node.children[0]
                if method == "Invoke":
                    imports[f"__uncertain_delegate_event__:{line}:{scope}:{receiver or 'unknown'}"] = "delegate_or_event"
                elif fn_node is not None and fn_node.type == "identifier" and receiver == "":
                    imports[f"__uncertain_delegate_event__:{line}:{scope}:{method}"] = "possible_delegate_or_event"
        elif t == "query_expression":
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)
            for receiver, method in _cs_query_clauses(node):
                calls.append((line, receiver, method, scope, _snippet_at(src, node)))
                call_args.append(CallArgFact(
                    function_qnode=scope,
                    line=line,
                    callee_name=method,
                    receiver=receiver,
                    arg_symbols=[],
                    target_symbol=None,
                ))
        elif t == "await_expression":
            # Minimal async signal: preserve await boundaries as explicit call edges.
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)
            calls.append((line, "", "await", scope, _snippet_at(src, node)))
            call_args.append(CallArgFact(
                function_qnode=scope,
                line=line,
                callee_name="await",
                receiver="",
                arg_symbols=[],
                target_symbol=None,
            ))
        elif t == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node is not None:
                cls = _text_of(src, type_node).split(".")[-1].strip()
                if cls:
                    line = node.start_point[0] + 1
                    scope = _scope_at(node.start_byte, fn_ranges)
                    calls.append((
                        line, "", cls,
                        scope,
                        _snippet_at(src, node)))
                    call_args.append(CallArgFact(
                        function_qnode=scope,
                        line=line,
                        callee_name=cls,
                        receiver="",
                        arg_symbols=_cs_identifier_args(node),
                        target_symbol=_cs_call_target(node),
                    ))
        elif t == "catch_declaration":
            catch_name, catch_type = _cs_catch_name_and_type(node)
            if catch_name and catch_type:
                local_types[catch_name] = _cs_normalize_type(catch_type)
        elif t == "foreach_statement":
            loop_type = ""
            loop_name = ""
            iterable = ""
            for child in node.named_children:
                if not loop_type and child.type == "identifier":
                    loop_type = _text_of(src, child)
                    continue
                if loop_type and not loop_name and child.type == "identifier":
                    loop_name = _text_of(src, child)
                    continue
                if loop_type and loop_name and child.type == "identifier":
                    iterable = _text_of(src, child)
                    break
            if loop_name:
                normalized = _cs_normalize_type(loop_type)
                if normalized and normalized != "var":
                    local_types[loop_name] = normalized
                elif iterable:
                    hinted = generic_hints.get(f"{iterable}.__generic0__", "")
                    if hinted:
                        local_types[loop_name] = hinted
        elif t in ("assignment_expression", "simple_assignment_expression"):
            dst, src_symbol, src_call = _cs_assignment_parts(node)
            if dst is not None and (src_symbol is not None or src_call is not None):
                assigns.append(VarAssignFact(
                    function_qnode=_scope_at(node.start_byte, fn_ranges),
                    line=node.start_point[0] + 1,
                    dst_symbol=dst,
                    src_symbol=src_symbol,
                    src_call=src_call,
                ))
        elif t == "variable_declarator":
            name_node = node.child_by_field_name("name")
            # C# grammar: variable_declarator has a 'name' field but no 'value'
            # field — the initialiser is an unnamed child after '='.  Walk
            # named_children to find the first child that is not the name.
            value_node = node.child_by_field_name("value")
            if value_node is None and name_node is not None:
                for _vc in node.named_children:
                    if _vc is not name_node:
                        value_node = _vc
                        break
            if name_node is not None and name_node.type == "identifier" and value_node is not None:
                dst_name = _text_of(src, name_node)
                raw_decl_type = _cs_local_decl_type(node)
                resolved_decl_type = _cs_normalize_type(raw_decl_type)
                if resolved_decl_type:
                    local_types[dst_name] = resolved_decl_type
                generic0 = _cs_first_generic_type_arg(raw_decl_type)
                if generic0:
                    generic_hints[f"{dst_name}.__generic0__"] = generic0
                src_symbol: str | None = None
                src_call: str | None = None
                if value_node.type == "identifier":
                    src_symbol = _text_of(src, value_node)
                    if not resolved_decl_type:
                        hinted = local_types.get(src_symbol, "")
                        if hinted:
                            local_types[dst_name] = hinted
                        hinted_g0 = generic_hints.get(f"{src_symbol}.__generic0__", "")
                        if hinted_g0:
                            generic_hints[f"{dst_name}.__generic0__"] = hinted_g0
                elif value_node.type == "invocation_expression":
                    _recv, method = _cs_invocation_parts(value_node)
                    src_call = method or None
                elif value_node.type == "object_creation_expression":
                    type_node = value_node.child_by_field_name("type")
                    if type_node is not None:
                        src_call = _text_of(src, type_node).split(".")[-1].strip() or None
                        local_types[dst_name] = _cs_normalize_type(_text_of(src, type_node)) or local_types.get(dst_name, "")
                if src_symbol is not None or src_call is not None:
                    assigns.append(VarAssignFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        dst_symbol=dst_name,
                        src_symbol=src_symbol,
                        src_call=src_call,
                    ))
        elif t == "return_statement":
            returns.append(ReturnFact(
                function_qnode=_scope_at(node.start_byte, fn_ranges),
                line=node.start_point[0] + 1,
                symbol=_cs_return_identifier(node),
            ))
        for c in node.children:
            _visit(c)

    _visit(root)
    imports.update({k: v for k, v in local_types.items() if v})
    imports.update({k: v for k, v in generic_hints.items() if v})
    return imports, functions, calls, assigns, returns, call_args


LANG_PLUGINS: dict[str, LangPlugin] = {
    "python":     LangPlugin(ts_language="python",     extract=_py_extract),
    "java":       LangPlugin(ts_language="java",       extract=_java_extract),
    "javascript": LangPlugin(ts_language="javascript", extract=_js_extract),
    "typescript": LangPlugin(ts_language="typescript", extract=_js_extract),
    "go":         LangPlugin(ts_language="go",         extract=_go_extract),
    "csharp":     LangPlugin(ts_language="csharp",     extract=_cs_extract),
}


def _js_extract_reflection_facts(src: bytes, tree) -> list[ReflectionFact]:
    """Extract JavaScript reflection facts (eval, Function, require(var), obj[name]()).
    
    Detects patterns like:
    - eval(code)
    - Function(arg)(...)
    - require(variable)
    - obj[methodName]()
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        list of ReflectionFact records
    """
    root = tree.root_node
    facts: list[ReflectionFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    # Must cover every node type that can ENCLOSE a reflection call, not just the
    # two that name one. A fact whose scope cannot be resolved gets
    # function_qnode="" from _scope_at, and _apply_reflection_to_taint's skip
    # guard reads `if rf.function_qnode and not fid.endswith(...)` — an empty
    # qnode makes that False, so instead of belonging to one function the fact
    # applies to EVERY tainted function in the file and emits spurious taint
    # edges. Kept in step with the def-collecting walk in _js_extract, which
    # recognises the same set.
    def _collect_fn_ranges(node):
        if node.type in ("function_declaration", "arrow_function",
                         "function_expression", "method_definition",
                         "generator_function_declaration"):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
            else:
                fn_ranges.append((node.start_byte, node.end_byte, "<lambda>"))
        for c in node.children:
            _collect_fn_ranges(c)

    _collect_fn_ranges(root)

    # Three defects fixed here, all of which silently narrowed JS/TS reflection
    # coverage to the eval()/Function() case alone:
    #   1. the dynamic-require branch was `elif fn_node.type == "identifier"`
    #      chained after an `if` on the SAME condition, so every identifier call
    #      took the first branch and require(variable) was unreachable;
    #   2. the obj[method]() branch was `elif node.type == "call_expression"`
    #      chained after an `if` on the same node type — a condition that can
    #      never be true, so subscript-dispatch detection was unreachable;
    #   3. a `call_expression` with no `function` field did `return`, which
    #      abandoned recursion into that whole subtree rather than skipping the
    #      one node, so any nested call inside it was never visited.
    # Dispatch is now on the function node's type, with the identifier callees
    # distinguished by name, and recursion always runs.
    def _visit(node):
        if node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node is not None and fn_node.type == "identifier":
                fname = _text_of(src, fn_node)
                # eval(code) / Function(arg)
                if fname in ("eval", "Function"):
                    args_node = node.child_by_field_name("arguments")
                    # Any argument at all is recorded. The previous allow-list
                    # of identifier/string/template_string was inverted with
                    # respect to risk: it accepted eval("1+1"), a constant that
                    # cannot be attacker-controlled, and rejected the two forms
                    # that actually carry taint — eval(req.query.expr), a
                    # member_expression, and eval(a + b), a binary_expression.
                    # Those are the realistic shapes in JS web code, so the
                    # filter suppressed exactly the sinks worth reporting.
                    # Whether the argument is really tainted is the taint
                    # engine's call downstream; this pass only records that a
                    # dynamic-eval site exists.
                    if args_node is not None and args_node.named_children:
                        _append_reflection_fact(facts,
                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                            line=node.start_point[0] + 1,
                            call_type="invoke",
                            target_symbols=[],
                            receiver="",
                            language="javascript",
                        )
                # require(variable) dynamic requires
                elif fname == "require":
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        target_symbols = []
                        for arg in args_node.named_children:
                            if arg.type == "identifier":
                                target_symbols.append(_text_of(src, arg))
                            elif arg.type == "template_string":
                                target_symbols.append(_text_of(src, arg).strip("`"))
                        if target_symbols:
                            _append_reflection_fact(facts,
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                call_type="construct",
                                target_symbols=target_symbols,
                                receiver="",
                                language="javascript",
                            )
            # obj[methodName]() subscript dispatch
            elif fn_node is not None and fn_node.type == "subscript_expression":
                obj = fn_node.child_by_field_name("object")
                index = fn_node.child_by_field_name("index")
                # Any non-literal index counts, for the same reason the eval
                # branch above takes any argument: restricting this to a bare
                # identifier keeps the benign local-variable case and discards
                # `controllers[req.params.action]()` (member_expression) and
                # `handlers[prefix + name]()` (binary_expression) — the canonical
                # unsafe dynamic-dispatch sinks in Express and middleware code.
                # A string literal index is ordinary property access, not
                # reflection, so it stays excluded.
                if obj is not None and index is not None \
                        and index.type not in ("string", "number",
                                               "template_string"):
                    _append_reflection_fact(facts,
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        call_type="invoke",
                        target_symbols=[_text_of(src, index)],
                        receiver=_js_leftmost(obj, src),
                        language="javascript",
                    )

        for c in node.children:
            _visit(c)

    _visit(root)
    return facts


_REFLECTION_FACT_EXTRACTORS: dict[str, Callable[[bytes, "object"], list[ReflectionFact]]] = {
    "python": _py_extract_reflection_facts,
    "java": _java_extract_reflection_facts,
    "javascript": _js_extract_reflection_facts,
    "typescript": _js_extract_reflection_facts,
    "csharp": _cs_extract_reflection_facts,
}


def _js_route_label(src: bytes, fn_node) -> str:
    """Route-style label for an inline handler, or "" if it is not one.

    `router.get('/x', (req, res) => ...)` yields ``get(/x)``. Kept in one place so
    the route branch, the middleware branch and the FuncDef created by
    ``_js_extract`` all name the same node identically — otherwise a marker
    references a function that does not exist under that name and nothing binds.
    """
    args = getattr(fn_node, "parent", None)
    if args is None or args.type != "arguments":
        return ""
    call = args.parent
    if call is None or call.type != "call_expression":
        return ""
    callee = call.child_by_field_name("function")
    if callee is None:
        return ""
    if callee.type == "member_expression":
        prop = callee.child_by_field_name("property")
        method = _text_of(src, prop) if prop is not None else ""
    elif callee.type == "identifier":
        method = _text_of(src, callee)
    else:
        return ""
    if not method:
        return ""
    for a in args.named_children:
        if a.type in ("string", "template_string"):
            return f"{method}({_text_of(src, a).strip(chr(34) + chr(39) + chr(96))})"
    return method


def _js_param_name_list(src: bytes, fn_node) -> tuple[str, ...]:
    """Parameter names of a JS/TS function, module-level so scope labels agree.

    `_js_extract` has an equivalent nested helper that closes over its own `src`.
    This mirrors its logic rather than restructuring a working function, and both
    must stay in step: the qnode `name(p1, p2)` they build is what
    `_graph._fn_id` keys taint on, so a divergence would file a source hit and a
    sink hit from the SAME function under different ids and silently break the
    path between them.
    """
    params_node = (fn_node.child_by_field_name("parameters")
                   or fn_node.child_by_field_name("parameter"))
    if params_node is None:
        # single-param arrow shorthand: x => ...
        for c in fn_node.children:
            if c.type == "identifier":
                return (_text_of(src, c),)
        return ()
    names: list[str] = []
    for param in params_node.named_children:
        if param.type == "identifier":
            names.append(_text_of(src, param))
        elif param.type in ("required_parameter", "optional_parameter"):
            pat = (param.child_by_field_name("pattern")
                   or (param.children[0] if param.child_count else None))
            if pat is not None and pat.type == "identifier":
                names.append(_text_of(src, pat))
        elif param.type in ("assignment_pattern", "rest_pattern"):
            for gc in param.named_children:
                if gc.type == "identifier":
                    names.append(_text_of(src, gc))
                    break
    return tuple(names)


# Request properties that carry attacker-controlled data in Express/Koa/Fastify.
# `query`, `body`, `params` are the request inputs proper; `headers`/`cookies` are
# equally attacker-set. `files` covers multipart uploads.
_JS_REQUEST_TAINT_PROPS = frozenset({
    "query", "body", "params", "headers", "cookies", "files", "rawBody",
})
# Parameter names conventionally bound to the request object.
_JS_REQUEST_RECEIVERS = frozenset({"req", "request", "ctx"})


def _js_extract_request_source_hits(src: bytes, tree, rel: str) -> list[CallSite]:
    """Source hits for request-property READS — `req.query.q`, `req.body.email`.

    Why this exists at all: every other source in the engine is a CALL. The
    call-site loop in ``scan_file`` matches ``receiver.method`` against source
    specs and appends to ``source_hits``, and ``build_taint_paths`` seeds taint
    exclusively from those hits. A JS request input is not a call — it is a member
    read — so it could never enter that path: it never appears in ``calls``, never
    becomes an annotator candidate (measured: 0 of 74 candidates on 20 Express
    route files had receiver ``req``), and would not match ``_match_call`` even
    given a spec. The consequence was structural, not incidental: taint evidence
    on an Express application was **necessarily zero**, whatever the specs,
    thresholds or handler extraction did.

    Recognising these reads directly is framework knowledge rather than a
    spec match, which is the same trade the framework-marker extractors already
    make for Spring/Django/ASP.NET annotations. The receiver set is deliberately
    narrow, and only a read whose property is a known request input counts, so
    an unrelated local named `req` contributes at most a low-value candidate
    rather than a wave of false sources.
    """
    hits: list[CallSite] = []
    fn_ranges: list[tuple[int, int, str]] = []

    # Scope labels must be the QNODE form `name(p1, p2)`, exactly as _js_extract
    # builds them. `containing_fn` is what _graph._fn_id keys taint on, so a bare
    # name here would put the source hit and the sink hit of the SAME function
    # under two different ids and no path would ever form — the source would be
    # recorded and then silently fail to connect to anything.
    def _collect(node):
        if node.type in ("function_declaration", "arrow_function", "function",
                         "function_expression", "method_definition",
                         "generator_function_declaration"):
            n = node.child_by_field_name("name")
            label = (_text_of(src, n) if n is not None
                     else (_js_route_label(src, node)
                           or _js_returned_handler_label(src, node)
                           or "<lambda>"))
            fn_ranges.append((node.start_byte, node.end_byte,
                              f"{label}({', '.join(_js_param_name_list(src, node))})"))
        for c in node.children:
            _collect(c)

    _collect(tree.root_node)

    def _visit(node):
        if node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if obj is not None and prop is not None \
                    and obj.type == "identifier" \
                    and _text_of(src, obj) in _JS_REQUEST_RECEIVERS \
                    and _text_of(src, prop) in _JS_REQUEST_TAINT_PROPS:
                hits.append(CallSite(
                    file=rel,
                    line=node.start_point[0] + 1,
                    receiver=_text_of(src, obj),
                    method=_text_of(src, prop),
                    containing_fn=_scope_at(node.start_byte, fn_ranges),
                    snippet=_snippet_at(src, node),
                    matched_rule="js-request-property",
                    cwe="CWE-20",
                    role="source",
                    kind="network",
                    semantic_family="network",
                    owasp_top10_2025=("A03:2025-Injection",),
                ))
        for c in node.children:
            _visit(c)

    _visit(tree.root_node)
    return hits


def _js_returned_handler_label(src: bytes, fn_node) -> str:
    """``<enclosing>>handler`` when this function is RETURNED by another, else "".

    The factory shape: ``export function search() { return (req, res) => ... }``,
    registered elsewhere as ``app.get('/x', search())``. The route call names only
    the factory, so the tainted request parameters live one level in, on the
    returned function — which is the node this labels. The name mirrors the
    FuncDef ``_js_extract`` creates for the same node, so the marker binds.
    """
    p = getattr(fn_node, "parent", None)
    if p is None or p.type != "return_statement":
        return ""
    cur = p
    while cur is not None:
        if cur.type in ("function_declaration", "function_expression",
                        "function", "method_definition", "arrow_function"):
            if cur is fn_node:
                cur = cur.parent
                continue
            nm = cur.child_by_field_name("name")
            if nm is not None:
                return f"{_text_of(src, nm)}>handler"
            # An unnamed factory assigned to a variable still has a usable name.
            gp = cur.parent
            if gp is not None and gp.type in ("variable_declarator",
                                              "assignment_expression"):
                tgt = (gp.child_by_field_name("name")
                       or gp.child_by_field_name("left"))
                if tgt is not None:
                    base = _text_of(src, tgt).split(".")[-1].strip()
                    if base:
                        return f"{base}>handler"
            return ""
        cur = cur.parent
    return ""


def _js_extract_framework_markers(src: bytes, tree) -> tuple[list[FrameworkMarkerFact], list[RouteTaintFact]]:
    """Extract JavaScript/TypeScript framework markers (Express, Next.js, React, middleware).
    
    Detects:
    - Express.js route handlers (app.get('/path', handler))
    - Next.js API routes
    - Middleware patterns (req, res, next)
    - React component definitions
    
    Args:
        src: source code bytes
        tree: parsed tree-sitter AST
        
    Returns:
        tuple of (marker_facts, route_facts)
    """
    root = tree.root_node
    markers: list[FrameworkMarkerFact] = []
    routes: list[RouteTaintFact] = []

    def _visit(node):
        # Detect Express route handlers: app.get('/path', handler)
        if node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            if fn_node is not None and fn_node.type == "member_expression":
                member_name = fn_node.child_by_field_name("property")
                if member_name is not None:
                    method = _text_of(src, member_name)
                    if method in ("get", "post", "put", "delete", "patch", "use"):
                        args = node.child_by_field_name("arguments")
                        if args is not None:
                            args_list = list(args.named_children)
                            if len(args_list) >= 2:
                                # First arg is path, second is handler
                                path_arg = args_list[0]
                                handler_arg = args_list[1]
                                if path_arg.type in ("string", "string_fragment"):
                                    route_path = _text_of(src, path_arg).strip("\"'`")
                                    if handler_arg.type == "identifier":
                                        handler_name = _text_of(src, handler_arg)
                                    elif handler_arg.type in (
                                            "arrow_function", "function",
                                            "function_expression"):
                                        # An INLINE handler — the dominant Express
                                        # shape, and previously ignored entirely,
                                        # which is why a TypeScript route file
                                        # produced zero framework markers and
                                        # zero framework entry points. Named to
                                        # match the FuncDef that _js_extract now
                                        # creates for the same node, so the marker
                                        # binds to a real function instead of
                                        # dangling.
                                        handler_name = f"{method}({route_path})"
                                    elif handler_arg.type == "call_expression":
                                        # The FACTORY shape:
                                        # `app.get('/x', search())`. The handler
                                        # is whatever `search()` returns, which
                                        # lives in another module — so name it
                                        # `search>handler`, matching both the
                                        # FuncDef and the marker that the
                                        # factory's own file produces for its
                                        # returned function. Without this the
                                        # route is not recorded at all: measured
                                        # as 2 route facts across 61 route files
                                        # on an app whose handlers are all
                                        # registered this way.
                                        f_callee = handler_arg.child_by_field_name(
                                            "function")
                                        f_name = ""
                                        if f_callee is not None:
                                            if f_callee.type == "identifier":
                                                f_name = _text_of(src, f_callee)
                                            elif f_callee.type == "member_expression":
                                                pr = f_callee.child_by_field_name(
                                                    "property")
                                                f_name = (_text_of(src, pr)
                                                          if pr is not None else "")
                                        handler_name = (f"{f_name}>handler"
                                                        if f_name else "")
                                    else:
                                        handler_name = ""
                                    if handler_name:
                                        routes.append(RouteTaintFact(
                                            function_qnode=handler_name,
                                            line=node.start_point[0] + 1,
                                            route_pattern=route_path,
                                            parameter_name="",
                                            is_tainted=True,
                                            framework="express",
                                        ))
                                        markers.append(FrameworkMarkerFact(
                                            function_qnode=handler_name,
                                            line=node.start_point[0] + 1,
                                            marker_type="express_handler",
                                            marker_name=f"@{method}",
                                            parameter_names=["req", "res"],
                                            framework="express",
                                            confidence="medium",
                                        ))
        
        # Detect middleware patterns (req, res, next)
        elif node.type in ("arrow_function", "function_declaration", "function",
                           "function_expression", "method_definition"):
            params_node = node.child_by_field_name("parameters")
            if params_node is not None:
                param_names = []
                for param in params_node.named_children:
                    # TypeScript wraps each parameter in required_parameter /
                    # optional_parameter, whose name lives in the `pattern`
                    # field. Matching only bare `identifier` therefore found NO
                    # parameters in any .ts file, so Express middleware detection
                    # silently never fired on a TypeScript codebase — measured as
                    # 0 framework markers on a ~900-file Express app whose route
                    # handlers all take (req, res).
                    if param.type in ("identifier", "parameter"):
                        pname = _text_of(src, param)
                    elif param.type in ("required_parameter",
                                        "optional_parameter"):
                        pat = (param.child_by_field_name("pattern")
                               or (param.named_children[0]
                                   if param.named_child_count else None))
                        pname = _text_of(src, pat) if pat is not None else ""
                    else:
                        pname = ""
                    if pname:
                        param_names.append(pname)

                # Express/Connect middleware: (req, res, next)
                if len(param_names) >= 2 and "req" in param_names and "res" in param_names:
                    fn_name_node = node.child_by_field_name("name")
                    fn_name = _text_of(src, fn_name_node) if fn_name_node else ""
                    if not fn_name:
                        # An unnamed handler: derive the SAME route-based label
                        # the route branch above uses, so the two do not emit two
                        # markers for one function. A literal "<anonymous>" also
                        # becomes an entry point that matches no function, which
                        # is worse than no marker: it inflates the entry-point
                        # count with something nothing can bind to.
                        fn_name = (_js_route_label(src, node)
                                   or _js_returned_handler_label(src, node))
                    if not fn_name:
                        # Genuinely unnameable — a bare (req, res) function that
                        # is not an argument to a route call. Emitting it as
                        # "<anonymous>" would create an entry point that matches
                        # no function: it inflates the entry-point count with
                        # something no later stage can bind, analyse or report,
                        # which is worse than not recording it. Skip instead.
                        COUNTERS.bump("s0_framework_marker_unnameable")
                        for c in node.children:
                            _visit(c)
                        return
                    markers.append(FrameworkMarkerFact(
                        function_qnode=fn_name,
                        line=node.start_point[0] + 1,
                        marker_type="middleware",
                        marker_name="middleware",
                        parameter_names=param_names[:3],
                        framework="express",
                        confidence="high",
                    ))
        
        for c in node.children:
            _visit(c)

    _visit(root)
    return markers, routes


_FRAMEWORK_MARKER_EXTRACTORS: dict[
    str,
    "Callable[[bytes, object], tuple[list[FrameworkMarkerFact], list[RouteTaintFact]]]",
] = {
    "python": _py_extract_framework_markers,
    "java": _java_extract_framework_markers,
    "javascript": _js_extract_framework_markers,
    "typescript": _js_extract_framework_markers,
    "csharp": _cs_extract_framework_markers,
}


_RESPONSE_DATAFLOW_EXTRACTORS: dict[
    str,
    "Callable[[bytes, object], list[ResponseDataflowFact]]",
] = {
    "python": _py_extract_response_dataflow,
    "java": _java_extract_response_dataflow,
    "csharp": _cs_extract_response_dataflow,
}


def _semantic_sink_override(language: str,
                            receiver: str,
                            method: str,
                            snippet: str) -> tuple[str, str, str, tuple[str, ...]] | None:
    """Repo-agnostic semantic sink detection (Iteration B).

    This covers framework response-render paths that are not always captured by
    API-call signature rules.
    """
    low = (snippet or "").lower()
    m = (method or "").lower()
    r = (receiver or "").lower()

    if language == "python":
        if m in {"response", "htmlresponse", "httpresponse", "render_template", "templateresponse"}:
            if "html" in low and ("{" in snippet or ".format(" in low or "+" in snippet):
                return (
                    "xss",
                    "CWE-79",
                    "html-response",
                    ("A03:2025-Injection",),
                )
            if m in {"render_template", "templateresponse"}:
                return (
                    "xss",
                    "CWE-79",
                    "html-response",
                    ("A03:2025-Injection",),
                )

    if language == "java":
        if m in {"print", "println", "write"} and (
                r in {"response", "writer", "out"}
                or "httpservletresponse" in low):
            if "<" in snippet or "format(" in low or "+" in snippet:
                return (
                    "xss",
                    "CWE-79",
                    "html-response",
                    ("A03:2025-Injection",),
                )

    return None


def _match_call(receiver: str, method: str, imports: dict[str, str],
                specs: list[MatchSpec], language: str) -> MatchSpec | None:
    """Return the first spec whose fingerprint matches this call. `receiver`
    is "" for bare-name calls."""
    resolved = imports.get(receiver, "") if receiver else ""
    # Bare-name call (receiver=""): also resolve via the method's own import
    # entry so `from flask import render_template; render_template(...)` matches
    # the flask.render_template module_attr spec.
    bare_resolved = imports.get(method, "") if not receiver else ""
    for spec in specs:
        if language not in spec.languages:
            continue
        if spec.has_qualified():
            if spec.is_constructor:
                # Constructor call: in Python, `Foo(...)` is the ctor.
                if receiver == "" and method in spec.methods:
                    if imports.get(method, "").startswith(spec.package):
                        return spec
                continue
            if method not in spec.methods:
                continue
            # Receiver's resolved import must live under the modeled package.
            if not resolved:
                continue
            if resolved.startswith(spec.package + ".") or resolved == spec.package:
                return spec
            # Gap 1 recall guard: when we only have a narrowed class tail,
            # accept `...<ClassName>` for JVM-style qualified rules.
            if language in {"java", "csharp", "kotlin", "scala"}:
                cls_tail = spec.class_name.split(".")[-1] if spec.class_name else ""
                if cls_tail and (resolved == cls_tail or resolved.endswith("." + cls_tail)):
                    return spec
            # Handle `from java.sql import Statement; s = Statement(); s.executeQuery(...)`
            # — the receiver is a variable, not an import. For MVP skip this
            # case (requires type inference).
            continue
        if spec.has_module_attr():
            if method not in spec.module_attr_names:
                continue
            if receiver == spec.module_attr_module:
                return spec
            if (resolved == spec.module_attr_module
                    or resolved.startswith(spec.module_attr_module + ".")
                    or resolved.endswith("." + spec.module_attr_module)):
                return spec
            # Bare-name call: check if the method was imported from this module.
            if (bare_resolved == spec.module_attr_module
                    or bare_resolved.startswith(spec.module_attr_module + ".")):
                return spec
    return None


def _build_spec_index(specs: list[MatchSpec]) -> dict[str, dict[str, list[MatchSpec]]]:
    """Build language -> method -> specs index once per scan.

    Includes fallback buckets:
    - language "*" for specs that do not declare languages
    - method "*" for specs that do not declare methods
    """
    idx: dict[str, dict[str, list[MatchSpec]]] = defaultdict(lambda: defaultdict(list))
    for spec in specs:
        langs = list(spec.languages) if spec.languages else ["*"]
        if spec.methods:
            methods = list(spec.methods)
        elif spec.module_attr_names:
            methods = list(spec.module_attr_names)
        else:
            methods = ["*"]
        for lang in langs:
            for method in methods:
                idx[lang][method].append(spec)
    return idx


# Each function takes (src, tree) and returns
# (field_writes, field_reads, container_writes).  They do a separate tree
# walk so the LangPlugin 6-tuple return signature stays unchanged.


def _py_extract_field_facts(
    src: bytes, tree
) -> tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]:
    """Python-specific extraction of FieldWriteFact, FieldReadFact, ContainerWriteFact."""
    root = tree.root_node
    field_writes: list[FieldWriteFact] = []
    field_reads: list[FieldReadFact] = []
    container_writes: list[ContainerWriteFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_ranges(node):
        if node.type == "function_definition":
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _py_text(n, src)))
        for c in node.children:
            _collect_ranges(c)

    _collect_ranges(root)

    def _visit(node):
        t = node.type
        if t == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)

            # FieldWriteFact: self.x = val  (LHS is attribute node)
            if left is not None and left.type == "attribute":
                obj = left.child_by_field_name("object")
                attr = left.child_by_field_name("attribute")
                recv = _py_text(obj, src) if obj is not None else ""
                fname = _py_text(attr, src) if attr is not None else ""
                if recv and fname:
                    src_sym = (
                        _py_text(right, src)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    field_writes.append(FieldWriteFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

            # ContainerWriteFact: d[k] = x  (LHS is subscript node)
            elif left is not None and left.type == "subscript":
                val_node = left.child_by_field_name("value")
                container = (
                    _py_text(val_node, src)
                    if val_node is not None and val_node.type == "identifier"
                    else ""
                )
                if container:
                    elem = (
                        _py_text(right, src)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    container_writes.append(ContainerWriteFact(
                        function_qnode=scope, line=line,
                        container_symbol=container, element_symbol=elem,
                    ))

            # FieldReadFact: x = self.y  (RHS is attribute node)
            if right is not None and right.type == "attribute":
                obj = right.child_by_field_name("object")
                attr = right.child_by_field_name("attribute")
                recv = _py_text(obj, src) if obj is not None else ""
                fname = _py_text(attr, src) if attr is not None else ""
                if recv and fname:
                    dst = (
                        _py_text(left, src)
                        if left is not None and left.type == "identifier"
                        else None
                    )
                    field_reads.append(FieldReadFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, dst_symbol=dst,
                    ))

        elif t == "augmented_assignment":
            # self.x += tainted  →  FieldWriteFact
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "attribute":
                obj = left.child_by_field_name("object")
                attr = left.child_by_field_name("attribute")
                recv = _py_text(obj, src) if obj is not None else ""
                fname = _py_text(attr, src) if attr is not None else ""
                if recv and fname:
                    src_sym = (
                        _py_text(right, src)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    field_writes.append(FieldWriteFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

        elif t == "call":
            # ContainerWriteFact: container.append(x) / container.add(x)
            fn_node = node.child_by_field_name("function")
            if fn_node is not None and fn_node.type == "attribute":
                method_node = fn_node.child_by_field_name("attribute")
                obj_node = fn_node.child_by_field_name("object")
                method = _py_text(method_node, src) if method_node is not None else ""
                if (
                    method in ("append", "add")
                    and obj_node is not None
                    and obj_node.type == "identifier"
                ):
                    container = _py_text(obj_node, src)
                    args_node = node.child_by_field_name("arguments")
                    elem: str | None = None
                    if args_node is not None:
                        for _a in args_node.named_children:
                            if _a.type == "identifier":
                                elem = _py_text(_a, src)
                            break
                    container_writes.append(ContainerWriteFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        container_symbol=container,
                        element_symbol=elem,
                    ))

        for c in node.children:
            _visit(c)

    _visit(root)
    return field_writes, field_reads, container_writes


def _java_extract_field_facts(
    src: bytes, tree
) -> tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]:
    """Java-specific extraction of FieldWriteFact, FieldReadFact, ContainerWriteFact."""
    root = tree.root_node
    field_writes: list[FieldWriteFact] = []
    field_reads: list[FieldReadFact] = []
    container_writes: list[ContainerWriteFact] = []
    fn_ranges: list[tuple[int, int, str]] = []
    class_stack: list[str] = []
    class_fields: dict[str, set[str]] = defaultdict(set)

    def _normalized_param_types(params_node) -> list[str]:
        out: list[str] = []
        if params_node is None:
            return out
        for param in params_node.named_children:
            if param.type not in ("formal_parameter", "spread_parameter"):
                continue
            type_node = param.child_by_field_name("type")
            if type_node is None:
                continue
            raw_t = _text_of(src, type_node)
            stripped = re.sub(r"<[^>]*>", "", raw_t).replace("[]", "").strip()
            out.append(stripped.split()[-1] if stripped else "")
        return out

    def _collect_ranges(node):
        if node.type == "class_declaration":
            n = node.child_by_field_name("name")
            cls = _text_of(src, n) if n is not None else ""
            if cls:
                class_stack.append(cls)
                for c in node.children:
                    _collect_ranges(c)
                class_stack.pop()
                return

        if node.type == "field_declaration" and class_stack:
            cls_key = ".".join(class_stack)
            for c in node.children:
                if c.type == "variable_declarator":
                    n = c.child_by_field_name("name")
                    if n is not None and n.type == "identifier":
                        class_fields[cls_key].add(_text_of(src, n))

        if node.type in ("method_declaration", "constructor_declaration"):
            n = node.child_by_field_name("name")
            if n is not None:
                fname = _text_of(src, n)
                params_node = node.child_by_field_name("parameters")
                class_prefix = ".".join(class_stack) + "." if class_stack else ""
                sig = "(" + ", ".join(_normalized_param_types(params_node)) + ")"
                fn_ranges.append((node.start_byte, node.end_byte, f"{class_prefix}{fname}{sig}"))

        for c in node.children:
            _collect_ranges(c)

    _collect_ranges(root)

    def _enclosing_constructor(node):
        cur = node
        while cur is not None:
            if cur.type == "constructor_declaration":
                return cur
            cur = cur.parent
        return None

    def _enclosing_class_key(node) -> str:
        names: list[str] = []
        cur = node
        while cur is not None:
            if cur.type == "class_declaration":
                n = cur.child_by_field_name("name")
                if n is not None:
                    names.append(_text_of(src, n))
            cur = cur.parent
        names.reverse()
        return ".".join(names)

    def _constructor_param_names(ctor_node) -> set[str]:
        params_node = ctor_node.child_by_field_name("parameters") if ctor_node is not None else None
        names: set[str] = set()
        if params_node is None:
            return names
        for p in params_node.named_children:
            if p.type not in ("formal_parameter", "spread_parameter"):
                continue
            n = p.child_by_field_name("name")
            if n is not None and n.type == "identifier":
                names.add(_text_of(src, n))
        return names

    def _assign_target_of(node) -> str | None:
        """LHS identifier name if node is directly assigned."""
        parent = node.parent
        if parent is None:
            return None
        if parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            right = parent.child_by_field_name("right")
            if right is node and left is not None and left.type == "identifier":
                return _text_of(src, left)
        if parent.type == "variable_declarator":
            val = parent.child_by_field_name("value")
            name = parent.child_by_field_name("name")
            if val is node and name is not None and name.type == "identifier":
                return _text_of(src, name)
        return None

    def _visit(node):
        t = node.type
        if t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)

            # FieldWriteFact: obj.field = val  (LHS is field_access)
            if left is not None and left.type == "field_access":
                obj = left.child_by_field_name("object")
                fld = left.child_by_field_name("field")
                recv = _text_of(src, obj) if obj is not None else ""
                fname = _text_of(src, fld) if fld is not None else ""
                if recv and fname:
                    src_sym = (
                        _text_of(src, right)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    field_writes.append(FieldWriteFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

            # Constructor injection fallback: `field = ctorParam` where the
            # field assignment is unqualified (no explicit `this.`).
            if (
                left is not None and left.type == "identifier"
                and right is not None and right.type == "identifier"
            ):
                ctor = _enclosing_constructor(node)
                if ctor is not None:
                    dst = _text_of(src, left)
                    src_sym = _text_of(src, right)
                    ctor_params = _constructor_param_names(ctor)
                    cls_key = _enclosing_class_key(node)
                    if (
                        src_sym in ctor_params
                        and dst not in ctor_params
                        and dst in class_fields.get(cls_key, set())
                    ):
                        field_writes.append(FieldWriteFact(
                            function_qnode=scope,
                            line=line,
                            receiver="this",
                            field=dst,
                            src_symbol=src_sym,
                        ))

            # FieldReadFact: x = obj.field  (RHS is field_access)
            if right is not None and right.type == "field_access":
                obj = right.child_by_field_name("object")
                fld = right.child_by_field_name("field")
                recv = _text_of(src, obj) if obj is not None else ""
                fname = _text_of(src, fld) if fld is not None else ""
                if recv and fname:
                    dst = (
                        _text_of(src, left)
                        if left is not None and left.type == "identifier"
                        else None
                    )
                    field_reads.append(FieldReadFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, dst_symbol=dst,
                    ))

        elif t == "local_variable_declaration":
            # FieldReadFact: Type x = obj.field
            scope = _scope_at(node.start_byte, fn_ranges)
            line = node.start_point[0] + 1
            for c in node.children:
                if c.type == "variable_declarator":
                    name_n = c.child_by_field_name("name")
                    val_n = c.child_by_field_name("value")
                    if name_n is not None and val_n is not None and val_n.type == "field_access":
                        obj = val_n.child_by_field_name("object")
                        fld = val_n.child_by_field_name("field")
                        recv = _text_of(src, obj) if obj is not None else ""
                        fname = _text_of(src, fld) if fld is not None else ""
                        if recv and fname:
                            field_reads.append(FieldReadFact(
                                function_qnode=scope, line=line,
                                receiver=recv, field=fname,
                                dst_symbol=_text_of(src, name_n),
                            ))

        elif t == "method_invocation":
            name_n = node.child_by_field_name("name")
            obj_n = node.child_by_field_name("object")
            method = _text_of(src, name_n) if name_n is not None else ""
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)

            # ContainerWriteFact: list.add(x) / map.put(k, v)
            if method in ("add", "put") and obj_n is not None:
                recv = _java_leftmost(obj_n, src)
                if recv:
                    args_n = node.child_by_field_name("arguments")
                    elem: str | None = None
                    if args_n is not None:
                        for _a in args_n.named_children:
                            if _a.type == "identifier":
                                elem = _text_of(src, _a)
                                break
                    container_writes.append(ContainerWriteFact(
                        function_qnode=scope, line=line,
                        container_symbol=recv, element_symbol=elem,
                    ))

            # Setter convention: obj.setField(val)  →  FieldWriteFact
            elif re.match(r"^set[A-Z]", method) and obj_n is not None:
                recv = _java_leftmost(obj_n, src)
                fname = method[3].lower() + method[4:] if len(method) > 3 else ""
                if recv and fname:
                    args_n = node.child_by_field_name("arguments")
                    src_sym: str | None = None
                    if args_n is not None:
                        for _a in args_n.named_children:
                            if _a.type == "identifier":
                                src_sym = _text_of(src, _a)
                                break
                    field_writes.append(FieldWriteFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

            # Getter convention: obj.getField()  →  FieldReadFact
            elif re.match(r"^get[A-Z]", method) and obj_n is not None:
                recv = _java_leftmost(obj_n, src)
                fname = method[3].lower() + method[4:] if len(method) > 3 else ""
                args_n = node.child_by_field_name("arguments")
                zero_args = args_n is None or len(args_n.named_children) == 0
                if recv and fname and zero_args:
                    field_reads.append(FieldReadFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname,
                        dst_symbol=_assign_target_of(node),
                    ))

        for c in node.children:
            _visit(c)

    _visit(root)
    return field_writes, field_reads, container_writes


def _cs_extract_field_facts(
    src: bytes, tree
) -> tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]:
    """C#-specific extraction of FieldWriteFact, FieldReadFact, ContainerWriteFact."""
    root = tree.root_node
    field_writes: list[FieldWriteFact] = []
    field_reads: list[FieldReadFact] = []
    container_writes: list[ContainerWriteFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_ranges(node):
        if node.type in (
            "method_declaration",
            "constructor_declaration",
            "local_function_statement",
        ):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte, _text_of(src, n)))
        for c in node.children:
            _collect_ranges(c)

    _collect_ranges(root)

    def _mae_parts(node) -> tuple[str, str]:
        """(receiver, field_name) from a member_access_expression."""
        expr = node.child_by_field_name("expression")
        name = node.child_by_field_name("name")
        recv = _cs_leftmost(expr, src) if expr is not None else ""
        fname = _text_of(src, name) if name is not None else ""
        return recv, fname

    def _visit(node):
        t = node.type
        if t in ("assignment_expression", "simple_assignment_expression"):
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)

            # FieldWriteFact: obj.Field = val  (LHS is member_access_expression)
            if left is not None and left.type == "member_access_expression":
                recv, fname = _mae_parts(left)
                if recv and fname:
                    src_sym = (
                        _text_of(src, right)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    field_writes.append(FieldWriteFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))

            # ContainerWriteFact: container[key] = val  (LHS is element_access_expression)
            elif left is not None and left.type == "element_access_expression":
                expr = left.child_by_field_name("expression")
                container = (
                    _text_of(src, expr)
                    if expr is not None and expr.type == "identifier"
                    else ""
                )
                if container:
                    elem = (
                        _text_of(src, right)
                        if right is not None and right.type == "identifier"
                        else None
                    )
                    container_writes.append(ContainerWriteFact(
                        function_qnode=scope, line=line,
                        container_symbol=container, element_symbol=elem,
                    ))

            # FieldReadFact: x = obj.Field  (RHS is member_access_expression)
            if right is not None and right.type == "member_access_expression":
                recv, fname = _mae_parts(right)
                if recv and fname:
                    dst = (
                        _text_of(src, left)
                        if left is not None and left.type == "identifier"
                        else None
                    )
                    field_reads.append(FieldReadFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, dst_symbol=dst,
                    ))

        elif t == "variable_declarator":
            # Type x = obj.Field;  (initialiser may be inside equals_value_clause)
            name_n = node.child_by_field_name("name")
            val_n: object = None
            for _vc in node.named_children:
                if _vc is not name_n:
                    if _vc.type == "equals_value_clause":
                        for _gvc in _vc.named_children:
                            val_n = _gvc
                            break
                    else:
                        val_n = _vc
                    break
            if (
                name_n is not None
                and val_n is not None
                and val_n.type == "member_access_expression"
            ):
                recv, fname = _mae_parts(val_n)
                if recv and fname:
                    field_reads.append(FieldReadFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        receiver=recv, field=fname,
                        dst_symbol=(
                            _text_of(src, name_n)
                            if name_n.type == "identifier"
                            else None
                        ),
                    ))

        elif t == "invocation_expression":
            fn_n = node.child_by_field_name("function")
            if fn_n is not None and fn_n.type == "member_access_expression":
                name_n = fn_n.child_by_field_name("name")
                method = _text_of(src, name_n) if name_n is not None else ""
                # ContainerWriteFact: container.Add(x)
                if method == "Add":
                    expr = fn_n.child_by_field_name("expression")
                    container = _cs_leftmost(expr, src) if expr is not None else ""
                    if container:
                        args_n = node.child_by_field_name("arguments")
                        elem: str | None = None
                        if args_n is not None:
                            for _a in args_n.named_children:
                                if _a.type == "identifier":
                                    elem = _text_of(src, _a)
                                    break
                                if _a.type == "argument":
                                    e = _a.child_by_field_name("expression")
                                    if e is not None and e.type == "identifier":
                                        elem = _text_of(src, e)
                                    break
                        container_writes.append(ContainerWriteFact(
                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                            line=node.start_point[0] + 1,
                            container_symbol=container,
                            element_symbol=elem,
                        ))

        for c in node.children:
            _visit(c)

    _visit(root)
    return field_writes, field_reads, container_writes


def _go_extract_field_facts(
    src: bytes, tree
) -> tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]:
    """Go-specific extraction of field/container facts.

    Covers:
    - FieldWriteFact:  ``x.Field = val``  (assignment_statement LHS selector_expression)
    - FieldReadFact:   ``v := x.Field``   (short_var_declaration / assignment RHS selector)
    - ContainerWriteFact: ``s = append(s, elem)`` and ``m[k] = v``
    """
    root = tree.root_node
    field_writes: list[FieldWriteFact] = []
    field_reads: list[FieldReadFact] = []
    container_writes: list[ContainerWriteFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_ranges(node):
        if node.type in ("function_declaration", "method_declaration",
                         "func_literal"):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte,
                                  _text_of(src, n)))
        for c in node.children:
            _collect_ranges(c)

    _collect_ranges(root)

    def _visit(node):
        t = node.type
        if t == "assignment_statement":
            lefts = node.child_by_field_name("left")
            rights = node.child_by_field_name("right")
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)
            # FieldWriteFact: x.Field = val
            if lefts is not None:
                for lchild in (lefts.named_children if hasattr(lefts, "named_children") else [lefts]):
                    if lchild.type == "selector_expression":
                        obj = lchild.child_by_field_name("operand")
                        fld = lchild.child_by_field_name("field")
                        recv = _text_of(src, obj) if obj else ""
                        fname = _text_of(src, fld) if fld else ""
                        if recv and fname:
                            rchild = (rights.named_children[0]
                                      if rights and rights.named_children else rights)
                            src_sym = (
                                _text_of(src, rchild)
                                if rchild and rchild.type == "identifier" else None
                            )
                            field_writes.append(FieldWriteFact(
                                function_qnode=scope, line=line,
                                receiver=recv, field=fname, src_symbol=src_sym,
                            ))
                    # ContainerWriteFact: m[k] = v  (index_expression on LHS)
                    elif lchild.type == "index_expression":
                        container_node = lchild.child_by_field_name("operand")
                        container = (_text_of(src, container_node)
                                     if container_node and container_node.type == "identifier"
                                     else "")
                        if container:
                            rchild = (rights.named_children[0]
                                      if rights and rights.named_children else rights)
                            elem = (_text_of(src, rchild)
                                    if rchild and rchild.type == "identifier" else None)
                            container_writes.append(ContainerWriteFact(
                                function_qnode=scope, line=line,
                                container_symbol=container, element_symbol=elem,
                            ))
            # FieldReadFact: v = x.Field (RHS selector_expression, LHS identifier)
            if rights is not None:
                for rchild in (rights.named_children if hasattr(rights, "named_children") else [rights]):
                    if rchild.type == "selector_expression":
                        obj = rchild.child_by_field_name("operand")
                        fld = rchild.child_by_field_name("field")
                        recv = _text_of(src, obj) if obj else ""
                        fname = _text_of(src, fld) if fld else ""
                        if recv and fname:
                            lchild = (lefts.named_children[0]
                                      if lefts and lefts.named_children else lefts)
                            dst = (_text_of(src, lchild)
                                   if lchild and lchild.type == "identifier" else None)
                            field_reads.append(FieldReadFact(
                                function_qnode=scope, line=line,
                                receiver=recv, field=fname, dst_symbol=dst,
                            ))

        elif t == "short_var_declaration":
            # v := x.Field
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)
            if right is not None:
                for rchild in (right.named_children if hasattr(right, "named_children") else [right]):
                    if rchild.type == "selector_expression":
                        obj = rchild.child_by_field_name("operand")
                        fld = rchild.child_by_field_name("field")
                        recv = _text_of(src, obj) if obj else ""
                        fname = _text_of(src, fld) if fld else ""
                        if recv and fname:
                            lchild = (left.named_children[0]
                                      if left and left.named_children else left)
                            dst = (_text_of(src, lchild)
                                   if lchild and lchild.type == "identifier" else None)
                            field_reads.append(FieldReadFact(
                                function_qnode=scope, line=line,
                                receiver=recv, field=fname, dst_symbol=dst,
                            ))

        elif t == "call_expression":
            # ContainerWriteFact: append(s, elem)
            fn_node = node.child_by_field_name("function")
            if fn_node is not None and _text_of(src, fn_node) == "append":
                args = node.child_by_field_name("arguments")
                if args is not None and len(args.named_children) >= 2:
                    container_arg = args.named_children[0]
                    elem_arg = args.named_children[1]
                    container = (_text_of(src, container_arg)
                                 if container_arg.type == "identifier" else "")
                    if container:
                        elem = (_text_of(src, elem_arg)
                                if elem_arg.type == "identifier" else None)
                        container_writes.append(ContainerWriteFact(
                            function_qnode=_scope_at(node.start_byte, fn_ranges),
                            line=node.start_point[0] + 1,
                            container_symbol=container, element_symbol=elem,
                        ))

        for c in node.children:
            _visit(c)

    _visit(root)
    return field_writes, field_reads, container_writes


def _js_extract_field_facts(
    src: bytes, tree
) -> tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]:
    """JavaScript/TypeScript field and container fact extraction.

    Covers:
    - FieldWriteFact:  ``x.prop = val``   (assignment_expression LHS member_expression)
    - FieldReadFact:   ``v = x.prop``     (assignment RHS member_expression)
    - ContainerWriteFact: ``arr.push(elem)`` / ``arr[k] = v``
    """
    root = tree.root_node
    field_writes: list[FieldWriteFact] = []
    field_reads: list[FieldReadFact] = []
    container_writes: list[ContainerWriteFact] = []
    fn_ranges: list[tuple[int, int, str]] = []

    def _collect_ranges(node):
        if node.type in ("function_declaration", "method_definition",
                         "arrow_function", "function_expression"):
            n = node.child_by_field_name("name")
            if n is not None:
                fn_ranges.append((node.start_byte, node.end_byte,
                                  _text_of(src, n)))
        for c in node.children:
            _collect_ranges(c)

    _collect_ranges(root)

    def _visit(node):
        t = node.type
        if t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            line = node.start_point[0] + 1
            scope = _scope_at(node.start_byte, fn_ranges)

            # FieldWriteFact: x.prop = val
            if left is not None and left.type == "member_expression":
                obj = left.child_by_field_name("object")
                prop = left.child_by_field_name("property")
                recv = _text_of(src, obj) if obj else ""
                fname = _text_of(src, prop) if prop else ""
                if recv and fname:
                    src_sym = (
                        _text_of(src, right)
                        if right and right.type == "identifier" else None
                    )
                    field_writes.append(FieldWriteFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, src_symbol=src_sym,
                    ))
            # ContainerWriteFact: arr[k] = v
            elif left is not None and left.type == "subscript_expression":
                obj = left.child_by_field_name("object")
                container = (_text_of(src, obj)
                             if obj and obj.type == "identifier" else "")
                if container:
                    elem = (
                        _text_of(src, right)
                        if right and right.type == "identifier" else None
                    )
                    container_writes.append(ContainerWriteFact(
                        function_qnode=scope, line=line,
                        container_symbol=container, element_symbol=elem,
                    ))

            # FieldReadFact: v = x.prop
            if right is not None and right.type == "member_expression":
                obj = right.child_by_field_name("object")
                prop = right.child_by_field_name("property")
                recv = _text_of(src, obj) if obj else ""
                fname = _text_of(src, prop) if prop else ""
                if recv and fname:
                    dst = (
                        _text_of(src, left)
                        if left and left.type == "identifier" else None
                    )
                    field_reads.append(FieldReadFact(
                        function_qnode=scope, line=line,
                        receiver=recv, field=fname, dst_symbol=dst,
                    ))

        elif t in ("variable_declaration", "lexical_declaration"):
            # const/let/var v = x.prop
            for child in node.named_children:
                if child.type == "variable_declarator":
                    name_n = child.child_by_field_name("name")
                    val_n = child.child_by_field_name("value")
                    if val_n is not None and val_n.type == "member_expression":
                        obj = val_n.child_by_field_name("object")
                        prop = val_n.child_by_field_name("property")
                        recv = _text_of(src, obj) if obj else ""
                        fname = _text_of(src, prop) if prop else ""
                        if recv and fname:
                            dst = (_text_of(src, name_n)
                                   if name_n and name_n.type == "identifier" else None)
                            field_reads.append(FieldReadFact(
                                function_qnode=_scope_at(node.start_byte, fn_ranges),
                                line=node.start_point[0] + 1,
                                receiver=recv, field=fname, dst_symbol=dst,
                            ))

        elif t == "call_expression":
            # ContainerWriteFact: arr.push(elem) / arr.add(elem)
            fn_node = node.child_by_field_name("function")
            if fn_node is not None and fn_node.type == "member_expression":
                prop = fn_node.child_by_field_name("property")
                obj = fn_node.child_by_field_name("object")
                method = _text_of(src, prop) if prop else ""
                if method in ("push", "add", "append") and obj and obj.type == "identifier":
                    container = _text_of(src, obj)
                    args = node.child_by_field_name("arguments")
                    elem: str | None = None
                    if args is not None:
                        for _a in args.named_children:
                            if _a.type == "identifier":
                                elem = _text_of(src, _a)
                            break
                    container_writes.append(ContainerWriteFact(
                        function_qnode=_scope_at(node.start_byte, fn_ranges),
                        line=node.start_point[0] + 1,
                        container_symbol=container, element_symbol=elem,
                    ))

        for c in node.children:
            _visit(c)

    _visit(root)
    return field_writes, field_reads, container_writes


_FIELD_FACT_EXTRACTORS: dict[
    str,
    "Callable[[bytes, object], tuple[list[FieldWriteFact], list[FieldReadFact], list[ContainerWriteFact]]]",
] = {
    "python":     _py_extract_field_facts,
    "java":       _java_extract_field_facts,
    "csharp":     _cs_extract_field_facts,
    "go":         _go_extract_field_facts,
    "javascript": _js_extract_field_facts,
    "typescript": _js_extract_field_facts,  # identical grammar for field access
}


def scan_file(abs_path: Path, rel: str, language: str,
              source_specs: list[MatchSpec],
              sink_specs:   list[MatchSpec],
              collect_observed: bool = False,
              source_index: dict[str, dict[str, list[MatchSpec]]] | None = None,
              sink_index: dict[str, dict[str, list[MatchSpec]]] | None = None) -> FileIndex | None:
    plugin = LANG_PLUGINS.get(language)
    if not plugin:
        return None
    if get_parser is None:
        print(
            f"  [s0/callgraph] tree-sitter backend unavailable ({_TS_ERR}); "
            "re-run 'pip install .' (or 'pipx install .') and then "
            "'vvaharness doctor' to verify dependencies",
            file=sys.stderr,
        )
        return None
    try:
        src = abs_path.read_bytes()
    except OSError:
        return None
    if not src:
        return None
    # TSX needs its own grammar. EXT_TO_LANG folds .tsx into "typescript", and
    # the typescript grammar does not accept JSX syntax: a React/Next component
    # parses with has_error=True and error recovery swallows most of the file —
    # measured at 1 of 3 functions and 2 of 3 call edges on a small component,
    # with the default-exported component itself among the losses. The tsx
    # grammar parses the same file cleanly. Only the GRAMMAR is switched here;
    # the FileIndex keeps language="typescript" so downstream language keying
    # (detect_languages, specialist gating, sink/source indexes) is unchanged.
    # .jsx needs no equivalent: tree-sitter-javascript already handles JSX.
    # Suffix compared case-INsensitively, matching hints.detect_languages
    # (PurePosixPath(f).suffix.lower()) and ts_graph's twin of this branch. A
    # case-sensitive test left `Page.TSX` classified as typescript but routed to
    # the JSX-rejecting grammar, so S0 and S1 would disagree on the same file.
    ts_language = plugin.ts_language
    if ts_language == "typescript" and Path(rel).suffix.lower() == ".tsx":
        ts_language = "tsx"
    parser = _get_cached_parser(ts_language)
    tree = parser.parse(src)
    imports, functions, calls, assigns, returns, call_args = plugin.extract(src, tree)
    idx = FileIndex(file=rel, language=language,
                    imports=imports, functions=functions,
                    assigns=assigns, returns=returns, call_args=call_args)
    _bridge = _enrich(rel, "bridge-signal", "s0_bridge_extract_failed_files",
                      lambda: _extract_bridge_signals(language, rel, calls))
    if _bridge is not None:
        idx.bridge_signals = _bridge
    # Populate field/container facts from a separate tree walk.
    _ff_extractor = _FIELD_FACT_EXTRACTORS.get(language)
    if _ff_extractor is not None:
        # The UNPACK runs inside _enrich, not on its result. An extractor that
        # returns the wrong arity returns *normally*, so _enrich's except never
        # fires and a ValueError raised outside it would reach _scan_repo's
        # per-file handler and drop the whole file — the exact outcome this
        # containment exists to prevent, and misattributed to a scan error.
        def _do_field_facts():
            idx.field_writes, idx.field_reads, idx.container_writes = \
                _ff_extractor(src, tree)
        _enrich(rel, "field-fact", "s0_field_fact_extract_failed_files",
                _do_field_facts)
    # idx.cfgs is intentionally left empty. CFG population requires passing real
    # AST function nodes to _build_cfg_for_function; that work is deferred until
    # the path-sensitive analysis pass is implemented. When that pass lands it
    # must also fix _condition_edge_confidence and _apply_condition_taint in
    # _graph.py (both safe now that they will be reachable).
    # Extract reflection facts (getattr, getMethod, invoke, etc.)
    # Per-fact validation failures are already absorbed inside
    # _append_reflection_fact; _enrich catches the extractor's own tree walk
    # blowing up. A ReflectionFact schema mismatch once evicted exactly the
    # files holding an app's eval() sinks, which is why this pass in particular
    # must never cost the file.
    _refl_extractor = _REFLECTION_FACT_EXTRACTORS.get(language)
    if _refl_extractor is not None:
        _refl = _enrich(rel, "reflection-fact",
                        "s0_reflection_extract_failed_files",
                        lambda: _refl_extractor(src, tree))
        if _refl is not None:
            idx.reflection_facts = _refl
    # Extract framework markers, route facts, and response dataflow.
    _fm_extractor = _FRAMEWORK_MARKER_EXTRACTORS.get(language)
    if _fm_extractor is not None:
        # Unpack inside the containment, as for field facts above.
        def _do_framework_markers():
            idx.framework_markers, idx.route_facts = _fm_extractor(src, tree)
        _enrich(rel, "framework-marker", "s0_framework_extract_failed_files",
                _do_framework_markers)
    _resp_extractor = _RESPONSE_DATAFLOW_EXTRACTORS.get(language)
    if _resp_extractor is not None:
        _resp = _enrich(rel, "response-dataflow",
                        "s0_response_extract_failed_files",
                        lambda: _resp_extractor(src, tree))
        if _resp is not None:
            idx.response_dataflow = _resp
    # Request-property reads as source hits. Contained like the passes above, but
    # note this one is NOT mere enrichment: it is the only path by which a JS
    # request input can reach build_taint_paths, which seeds taint exclusively
    # from source_hits and matches only CALL sites otherwise.
    if language in ("javascript", "typescript"):
        def _do_request_sources():
            idx.source_hits.extend(
                _js_extract_request_source_hits(src, tree, rel))
        _enrich(rel, "request-source", "s0_request_source_extract_failed_files",
                _do_request_sources)
    for line, receiver, method, scope, snippet in calls:
        if source_index:
            src_lang = source_index.get(language, {})
            src_any = source_index.get("*", {})
            src_specs_lang = (
                src_lang.get(method, []) + src_lang.get("*", [])
                + src_any.get(method, []) + src_any.get("*", [])
            )
        else:
            src_specs_lang = source_specs
        if sink_index:
            snk_lang = sink_index.get(language, {})
            snk_any = sink_index.get("*", {})
            snk_specs_lang = (
                snk_lang.get(method, []) + snk_lang.get("*", [])
                + snk_any.get(method, []) + snk_any.get("*", [])
            )
        else:
            snk_specs_lang = sink_specs

        # Record the edge for BFS regardless of match status.
        idx.call_edges.append((scope, receiver, method))
        # Record full call fingerprint for annotator-style LLM mode.
        if collect_observed:
            idx.observed_calls.append(ObservedCall(
                file=rel,
                language=language,
                line=line,
                receiver=receiver,
                resolved_receiver=imports.get(receiver, ""),
                method=method,
                containing_fn=scope,
                snippet=snippet,
            ))
        src_spec = _match_call(receiver, method, imports, src_specs_lang, language)
        if src_spec:
            idx.source_hits.append(CallSite(
                file=rel, line=line, receiver=receiver, method=method,
                containing_fn=scope, snippet=snippet,
                matched_rule=src_spec.rule_id, cwe=src_spec.cwe,
                role="source", kind=src_spec.kind,
                semantic_family=src_spec.semantic_family,
                owasp_top10_2025=tuple(src_spec.owasp_top10_2025),
            ))
            # A call can be BOTH a source and a sink (rare but valid).
        snk_spec = _match_call(receiver, method, imports, snk_specs_lang, language)
        if snk_spec:
            idx.sink_hits.append(CallSite(
                file=rel, line=line, receiver=receiver, method=method,
                containing_fn=scope, snippet=snippet,
                matched_rule=snk_spec.rule_id, cwe=snk_spec.cwe,
                role="sink", kind=snk_spec.kind,
                semantic_family=snk_spec.semantic_family,
                owasp_top10_2025=tuple(snk_spec.owasp_top10_2025),
            ))
            continue

        # Iteration B semantic fallback: keep framework response sinks even if
        # the rule is not representable as module.attr signature.
        semantic = _semantic_sink_override(language, receiver, method, snippet)
        if semantic:
            sem_kind, sem_cwe, sem_family, sem_owasp = semantic
            idx.sink_hits.append(CallSite(
                file=rel, line=line, receiver=receiver, method=method,
                containing_fn=scope, snippet=snippet,
                matched_rule="vvah.semantic.sink",
                cwe=sem_cwe,
                role="sink",
                kind=sem_kind,
                semantic_family=sem_family,
                owasp_top10_2025=sem_owasp,
            ))
    return idx
