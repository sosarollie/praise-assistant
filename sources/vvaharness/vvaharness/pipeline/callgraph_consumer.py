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

"""Shared post-S2 callgraph consumers.

These helpers are intentionally read-only and deterministic: they consume the
SQLite-hydrated callgraph context already attached to ContextPackage and avoid
stage-local re-derivation logic in s3/s4/s5/s6/s7/s8.

Graph resolution is **call-graph first**: the call graph is authoritative for
reachability and function membership, and ``def_spans`` (an AST-derived
artifact) is treated only as corroborating evidence that pins a tighter
location. When no span overlaps the target line, :func:`qnodes_at` returns the
qnodes the call graph places in that file. The indices are built once per run
and memoized per ContextPackage.
"""
from __future__ import annotations

import weakref
from collections import defaultdict

from vvaharness.models import (
    CFG,  # noqa: F401 – re-exported for callers
    ConditionTaintEdge,
    ContextPackage,
    FrameworkMarkerFact,
    ReflectionFact,
    ReflectionTaintEdge,
    ResponseDataflowFact,
    RouteTaintFact,
    TaintEvidencePath,
)
from vvaharness.pipeline.stages.callgraph_engine._scan import FileIndex


def _q_file(qn: str) -> str:
    return qn.rpartition("::")[0]


def _q_name(qn: str) -> str:
    return qn.rpartition("::")[2]


def parse_hop(hop: str) -> tuple[str, int | None]:
    """Parse a seed/codeflow hop formatted as "file:line"."""
    file_part, sep, line_part = hop.rpartition(":")
    if sep and file_part and line_part.isdigit():
        return file_part, max(1, int(line_part))
    return hop, None


def _norm_file(path: str | None) -> str:
    """Normalize file paths for stable cross-platform matching."""
    norm = (path or "").strip().replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def _file_from_ref(ref: str | None) -> str | None:
    """Extract a file path from "file::symbol", "file:line", or bare file."""
    raw = (ref or "").strip()
    if not raw:
        return None
    file_part, sep, _tail = raw.partition("::")
    if sep:
        norm = _norm_file(file_part)
        return norm or None
    file_part, sep, line_part = raw.rpartition(":")
    if sep and file_part and line_part.isdigit():
        norm = _norm_file(file_part)
        return norm or None
    norm = _norm_file(raw)
    return norm or None


def _evidence_touched_files(evidence: TaintEvidencePath) -> set[str]:
    touched: set[str] = set()

    src_file = _file_from_ref(getattr(evidence, "source_ref", None))
    if src_file:
        touched.add(src_file)

    sink_file = _file_from_ref(getattr(evidence, "sink_ref", None))
    if sink_file:
        touched.add(sink_file)

    for edge in getattr(evidence, "edges", ()) or ():
        edge_file = _norm_file(getattr(edge, "file", None))
        if edge_file:
            touched.add(edge_file)

    return touched


def seed_reachable_files(seed_taint_paths: list[list[str]] | None) -> set[str]:
    """Return files proven by seed taint paths (widen-only reachability)."""
    out: set[str] = set()
    for path in seed_taint_paths or ():
        for hop in path:
            if not hop:
                continue
            f, _ln = parse_hop(hop)
            if f:
                out.add(f)
    return out


def seed_paths_by_file(seed_taint_paths: list[list[str]] | None) -> dict[str, list[list[str]]]:
    """Index seed taint paths by every file they touch."""
    out: dict[str, list[list[str]]] = defaultdict(list)
    for path in seed_taint_paths or ():
        touched: set[str] = set()
        for hop in path:
            f, _ln = parse_hop(hop)
            if f:
                touched.add(f)
        for f in touched:
            out[f].append(path)
    return out


def best_source_from_seed(paths: list[list[str]]) -> str | None:
    """Return the first source hop from a set of seed paths touching a file."""
    for path in paths:
        if not path:
            continue
        src = path[0]
        sf, sl = parse_hop(src)
        if sf and sl is not None:
            return f"{sf}:{sl}"
        if src:
            return src
    return None


def seed_evidence_reachable_files(seed_taint_evidence: list[TaintEvidencePath] | None) -> set[str]:
    """Return files proven by structured seed taint evidence."""
    out: set[str] = set()
    for evidence in seed_taint_evidence or ():
        out.update(_evidence_touched_files(evidence))
    return out


def seed_evidence_by_file(seed_taint_evidence: list[TaintEvidencePath] | None) -> dict[str, list[TaintEvidencePath]]:
    """Index structured seed taint evidence by every file it touches."""
    out: dict[str, list[TaintEvidencePath]] = defaultdict(list)
    for evidence in seed_taint_evidence or ():
        for file in _evidence_touched_files(evidence):
            out[file].append(evidence)
    return out


def best_source_from_evidence(evidence_paths: list[TaintEvidencePath]) -> str | None:
    """Return the best available source reference from evidence paths."""
    for evidence in evidence_paths or ():
        source_ref = (getattr(evidence, "source_ref", "") or "").strip()
        if source_ref:
            return source_ref
        for edge in getattr(evidence, "edges", ()) or ():
            edge_file = _norm_file(getattr(edge, "file", None))
            if not edge_file:
                continue
            try:
                edge_line = max(1, int(getattr(edge, "line", 0)))
            except Exception:  # noqa: BLE001
                edge_line = 0
            if edge_line:
                return f"{edge_file}:{edge_line}"
            return edge_file
    return None


def entry_anchor_lines(ctx: ContextPackage) -> dict[str, list[int]]:
    """Best-effort entry-point def-site anchors by file.

    Sources, in order:
      1) call_graph_files[entry.function] entries matching entry.file
      2) def_spans qnodes matching entry.file::entry.function
      3) fallback line 1 in entry.file
    """
    by_file: dict[str, set[int]] = defaultdict(set)

    def _base_name(qnode: str) -> str:
        tail = qnode.rpartition("::")[-1]
        tail = tail.split("(", 1)[0]
        return tail.rsplit(".", 1)[-1]

    for ep in ctx.entry_points:
        matched = False
        for site in (ctx.call_graph_files or {}).get(ep.function, ()):
            sf, sep, sl = site.rpartition(":")
            if sep and sf == ep.file and sl.isdigit():
                by_file[ep.file].add(max(1, int(sl)))
                matched = True
        if not matched:
            for qn, span in (ctx.def_spans or {}).items():
                qf, _, qname = qn.rpartition("::")
                if qf == ep.file and (_base_name(qname) == ep.function) and span:
                    by_file[ep.file].add(max(1, int(span[0])))
                    matched = True
        if not matched and ep.file:
            by_file[ep.file].add(1)
    return {f: sorted(lines) for f, lines in by_file.items()}


def build_span_index(ctx: ContextPackage) -> dict[str, list[tuple[int, int, str]]]:
    """``file -> [(lo, hi, qnode)]`` sorted by ``lo``. Built once per run.

    Only well-formed spans are indexed; malformed entries are skipped rather
    than raising.
    """
    index: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    for qn, sp in (ctx.def_spans or {}).items():
        if not isinstance(sp, (list, tuple)) or not sp:
            continue
        f = _q_file(qn)
        if not f:
            continue
        try:
            lo = int(sp[0])
            hi = int(sp[1]) if len(sp) > 1 else lo
        except Exception:  # noqa: BLE001
            continue
        index[f].append((lo, max(lo, hi), qn))
    for f in index:
        index[f].sort(key=lambda t: (t[0], t[1], t[2]))
    return dict(index)


def graph_qnodes_by_file(ctx: ContextPackage) -> dict[str, list[str]]:
    """``file -> ordered unique list of every qnode the call graph places in it``.

    This is the authoritative set of functions in a file for reachability
    purposes; :func:`qnodes_at` uses spans only to corroborate which of these
    covers a specific line.
    """
    out: dict[str, list[str]] = defaultdict(list)
    seen: dict[str, set[str]] = defaultdict(set)
    for caller, callees in (ctx.call_graph or {}).items():
        for qn in (caller, *(callees or ())):
            f = _q_file(qn)
            if f and qn not in seen[f]:
                out[f].append(qn)
                seen[f].add(qn)
    return dict(out)


def reverse_edges(ctx: ContextPackage) -> dict[str, list[str]]:
    """``callee -> [callers]`` (insertion-ordered, deduped). Built once per run."""
    rev: dict[str, list[str]] = defaultdict(list)
    seen: dict[str, set[str]] = defaultdict(set)
    for caller, callees in (ctx.call_graph or {}).items():
        for callee in (callees or ()):
            if caller not in seen[callee]:
                rev[callee].append(caller)
                seen[callee].add(caller)
    return dict(rev)


def qnodes_at(view: "GraphView", file: str, line_start: int, line_end: int,
              *, limit: int = 6, nearest_if_empty: bool = False) -> list[str]:
    """Qnodes covering ``[line_start, line_end]`` in ``file``.

    Resolution order (call-graph-first, spans as corroborating evidence):

    1. spans that overlap the line window (tightest, code-corroborated match);
    2. otherwise the call graph's file membership (the authoritative
       reachability set for the file);
    3. otherwise, only when ``nearest_if_empty`` is set, the nearest span in
       the file (single-anchor lookup for s3).
    """
    file = (file or "").replace("\\", "/")
    start = max(1, int(line_start or 1))
    end = max(start, int(line_end or start))

    exact: list[str] = []
    nearby: list[tuple[int, str]] = []
    for lo, hi, qn in view.span_index.get(file, ()):  # sorted by lo
        if lo <= end and hi >= start:
            exact.append(qn)
        else:
            nearby.append((min(abs(start - hi), abs(end - lo)), qn))
    if exact:
        return list(dict.fromkeys(exact))[:limit]

    cg = view.file_qnodes.get(file)
    if cg:
        return list(dict.fromkeys(cg))[:limit]

    if nearest_if_empty and nearby:
        nearby.sort(key=lambda t: (t[0], t[1]))
        return [nearby[0][1]]
    return []


def neighborhood(view: "GraphView", qnodes, *, max_edges: int = 8) -> dict:
    """Shared callers/callees view for s6/s7/s8."""
    graph = view.forward
    around: dict[str, dict[str, list[str]]] = {}
    for qn in qnodes:
        around[qn] = {
            "callers": (view.rev.get(qn) or [])[:max_edges],
            "callees": (graph.get(qn) or [])[:max_edges],
        }
    return around


class GraphView:
    """Memoized per-run bundle of the shared graph indices.

    Holds the span index, call-graph file membership, forward edges and reverse
    edges so a stage builds each exactly once per run rather than per finding /
    per sink / per chunk. Obtain via :func:`graph_view`.
    """

    __slots__ = ("forward", "span_index", "file_qnodes", "rev")

    def __init__(self, ctx: ContextPackage) -> None:
        self.forward = ctx.call_graph or {}
        self.span_index = build_span_index(ctx)
        self.file_qnodes = graph_qnodes_by_file(ctx)
        self.rev = reverse_edges(ctx)


# id()-keyed cache validated by a weakref, so a ContextPackage that is GC'd and
# whose id is later reused cannot return a stale view. ContextPackage is a
# pydantic model (unhashable, no attribute injection), so neither a
# WeakKeyDictionary nor an instance attribute is usable here.
_VIEW_CACHE: dict[int, tuple] = {}


def graph_view(ctx: ContextPackage) -> GraphView:
    """Return the memoized :class:`GraphView` for ``ctx`` (built once)."""
    key = id(ctx)
    entry = _VIEW_CACHE.get(key)
    if entry is not None:
        ref, view = entry
        if ref() is ctx:
            return view
    view = GraphView(ctx)
    try:
        ref = weakref.ref(ctx)
    except TypeError:  # pragma: no cover - pydantic models are weakref-able
        def ref(_c=ctx):
            return _c
    _VIEW_CACHE[key] = (ref, view)
    return view


def cfgs_for_function(
    function_qnode: str,
    file_indices: list[FileIndex],
) -> CFG | None:
    """Return the CFG for *function_qnode* from *file_indices*, or ``None``.

    Searches each :class:`~vvaharness.pipeline.stages.callgraph_engine._scan.FileIndex`
    for the one whose ``cfgs`` mapping contains *function_qnode* and returns
    the associated :class:`~vvaharness.models.CFG`.  Returns ``None`` when the
    function is external, was not scanned, or simply has no CFG recorded.

    Parameters
    ----------
    function_qnode:
        Fully-qualified node identifier, e.g. ``"src/app.py::process_input"``.
    file_indices:
        The list of per-file index objects produced by the callgraph scanner.
    """
    for fi in file_indices or ():
        cfg = (fi.cfgs or {}).get(function_qnode)
        if cfg is not None:
            return cfg
    return None


def reflection_facts_for_function(
    function_qnode: str,
    file_indices: list[FileIndex],
) -> list[ReflectionFact]:
    """Return all :class:`~vvaharness.models.ReflectionFact` objects for *function_qnode*.

    Searches every :class:`FileIndex` in *file_indices* and filters its
    ``reflection_facts`` list by ``fact.function_qnode == function_qnode``.
    Returns an empty list when no matching facts are found.

    Parameters
    ----------
    function_qnode:
        Fully-qualified node identifier.
    file_indices:
        The list of per-file index objects produced by the callgraph scanner.
    """
    out: list[ReflectionFact] = []
    for fi in file_indices or ():
        for fact in fi.reflection_facts or ():
            if getattr(fact, "function_qnode", None) == function_qnode:
                out.append(fact)
    return out


def reflection_facts_by_file(
    file_path: str,
    file_indices: list[FileIndex],
) -> list[ReflectionFact]:
    """Return all reflection facts from the :class:`FileIndex` for *file_path*.

    Finds the first :class:`FileIndex` whose ``file`` attribute matches
    *file_path* (after normalisation) and returns its complete
    ``reflection_facts`` list.  Returns an empty list when the file is not
    found in *file_indices*.

    Parameters
    ----------
    file_path:
        The source-relative file path to look up.
    file_indices:
        The list of per-file index objects produced by the callgraph scanner.
    """
    norm_target = _norm_file(file_path)
    for fi in file_indices or ():
        if _norm_file(fi.file) == norm_target:
            return list(fi.reflection_facts or ())
    return []


def condition_edges_in_evidence(
    evidence: TaintEvidencePath,
) -> list[ConditionTaintEdge]:
    """Return the :class:`~vvaharness.models.ConditionTaintEdge` objects in *evidence*.

    Filters ``evidence.edges`` by ``isinstance(edge, ConditionTaintEdge)``.
    Useful for downstream checkers that need to know whether a taint path is
    condition-gated.  Returns an empty list when the evidence carries no
    condition edges.

    Parameters
    ----------
    evidence:
        A structured taint evidence path from the scan pipeline.
    """
    out: list[ConditionTaintEdge] = []
    for edge in getattr(evidence, "edges", ()) or ():
        if isinstance(edge, ConditionTaintEdge):
            out.append(edge)
    return out


def reflection_edges_in_evidence(
    evidence: TaintEvidencePath,
) -> list[ReflectionTaintEdge]:
    """Return the :class:`~vvaharness.models.ReflectionTaintEdge` objects in *evidence*.

    Filters ``evidence.edges`` by ``isinstance(edge, ReflectionTaintEdge)``.
    Returns an empty list when the evidence carries no reflection edges.

    Parameters
    ----------
    evidence:
        A structured taint evidence path from the scan pipeline.
    """
    out: list[ReflectionTaintEdge] = []
    for edge in getattr(evidence, "edges", ()) or ():
        if isinstance(edge, ReflectionTaintEdge):
            out.append(edge)
    return out


def framework_markers_for_function(
    function_qnode: str,
    file_indices: list[FileIndex],
) -> list[FrameworkMarkerFact]:
    """Return all :class:`~vvaharness.models.FrameworkMarkerFact` objects for *function_qnode*.

    Searches every :class:`FileIndex` in *file_indices* and filters its
    ``framework_markers`` list by ``fact.function_qnode == function_qnode``.
    Returns an empty list when no matching facts are found.

    Parameters
    ----------
    function_qnode:
        Fully-qualified node identifier, e.g. ``"src/app.py::process_input"``.
    file_indices:
        The list of per-file index objects produced by the callgraph scanner.
    """
    out: list[FrameworkMarkerFact] = []
    for fi in file_indices or ():
        for fact in fi.framework_markers or ():
            if getattr(fact, "function_qnode", None) == function_qnode:
                out.append(fact)
    return out


def route_facts_for_file(
    file_path: str,
    file_indices: list[FileIndex],
) -> list[RouteTaintFact]:
    """Return all :class:`~vvaharness.models.RouteTaintFact` from the :class:`FileIndex` for *file_path*.

    Finds the first :class:`FileIndex` whose ``file`` attribute matches
    *file_path* (after normalisation) and returns its complete
    ``route_facts`` list. Returns an empty list when the file is not
    found in *file_indices*.

    Parameters
    ----------
    file_path:
        The source-relative file path to look up.
    file_indices:
        The list of per-file index objects produced by the callgraph scanner.
    """
    norm_target = _norm_file(file_path)
    for fi in file_indices or ():
        if _norm_file(fi.file) == norm_target:
            return list(fi.route_facts or ())
    return []


def response_dataflows_for_function(
    function_qnode: str,
    file_indices: list[FileIndex],
) -> list[ResponseDataflowFact]:
    """Return all :class:`~vvaharness.models.ResponseDataflowFact` objects for *function_qnode*.

    Searches every :class:`FileIndex` in *file_indices* and filters its
    ``response_dataflow`` list by ``fact.function_qnode == function_qnode``.
    Returns an empty list when no matching facts are found.

    Parameters
    ----------
    function_qnode:
        Fully-qualified node identifier.
    file_indices:
        The list of per-file index objects produced by the callgraph scanner.
    """
    out: list[ResponseDataflowFact] = []
    for fi in file_indices or ():
        for fact in fi.response_dataflow or ():
            if getattr(fact, "function_qnode", None) == function_qnode:
                out.append(fact)
    return out
