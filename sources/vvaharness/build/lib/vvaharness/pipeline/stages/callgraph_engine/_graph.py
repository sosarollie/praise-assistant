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

"""Naive call graph + source→sink reachability.

Given a list of :class:`FileIndex` records (each pre-labeled with source/sink
call sites and containing-function scopes), this module builds:

    * a global call graph keyed by function name — a call to ``foo(...)``
      links the caller to *every* ``def foo`` in the codebase (no type
      resolution, no import resolution beyond what the scanner already did)
    * intra-procedural pairs — source and sink in the same function
    * one-hop inter-procedural pairs — source in F, F calls G, G contains a
      sink (limited to depth-3 chains to bound runtime on large repos)

Emits a :class:`SeedPackage` with:
    * entry_points (one per unique source-containing function)
    * unsafe_sinks (every sink hit, deduped by (file, line, method))
    * taint_paths (each a list of "file:line" hops from source-line to
      sink-line, with the function boundaries in between)
    * rule_cwe (pass-through map for downstream stages)
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict, deque
from pathlib import Path

from vvaharness.models import (
    BridgeUncertaintyEdge,
    ConditionTaintEdge,
    EntryPoint,
    ReflectionFact,
    ReflectionTaintEdge,
    Sink,
    TaintEvidencePath,
    TaintSymbolRef,
    TaintTransferEdge,
)
from vvaharness.pipeline.stages.callgraph_engine._scan import CallSite, FileIndex

_log = logging.getLogger(__name__)
from vvaharness.rules.families import (
    PROTECTED_SEMANTIC_FAMILIES as _PROTECTED_SEMANTIC_FAMILIES,
)

_BASE_INTER_HOPS = 3
_HIGH_RISK_INTER_HOPS = 5
# Default fanout cap when a bare callee resolves to several def-sites. The
# effective value is read from step1.call_graph_max_targets so the s0 seed
# graph agrees with the s1 / ts_graph builders; this constant is only the
# fallback when no config is threaded (e.g. direct unit-test calls).
_DEFAULT_MAX_TARGETS_PER_CALL = 3
_HIGH_RISK_CWE = {
    "22", "78", "79", "89", "90", "94", "95", "434", "502", "601", "611", "918",
}
_FUNCTION_BODY_MAX_CHARS = 1200
_SOURCE_KIND_COMPAT: dict[str, set[str]] = {
    "network": {
        "cmd", "credentials", "deserialize", "dyn-eval", "el-injection",
        "header", "intent-redirection", "jndi", "ldap", "log-injection",
        "path", "pending-intent", "redirect", "regex", "sql", "ssrf",
        "template", "xpath", "xss", "xxe",
    },
    "ipc": {
        "cmd", "credentials", "deserialize", "dyn-eval", "el-injection",
        "header", "intent-redirection", "jndi", "ldap", "log-injection",
        "path", "pending-intent", "redirect", "regex", "sql", "ssrf",
        "template", "xpath", "xss", "xxe",
    },
    "cli": {
        "cmd", "credentials", "deserialize", "dyn-eval", "el-injection",
        "jndi", "ldap", "log-injection", "path", "regex", "sql",
        "ssrf", "template", "xpath", "xxe",
    },
    "filesystem": {
        "cmd", "credentials", "deserialize", "dyn-eval", "jndi", "ldap",
        "path", "regex", "sql", "template", "xpath", "xxe",
    },
    "env": {
        "cmd", "credentials", "deserialize", "dyn-eval", "el-injection",
        "jndi", "ldap", "log-injection", "path", "redirect", "regex",
        "sql", "ssrf", "template", "xpath", "xxe",
    },
}

# Iteration A: Confidence-weighted path budget per source/sink.
# Iteration G: Global path budget cap to fix quadratic path explosion.

_GLOBAL_PATH_BUDGET = 200  # Max paths to emit; tunable per profile
_GLOBAL_PATH_BUDGET_MAX = 500  # Iteration C/G extension for large repos
_CWE_SEVERITY: dict[str, float] = {
    "22": 1.0, "78": 1.0, "79": 0.9, "89": 1.0, "94": 1.0,
    "95": 0.8, "434": 0.7, "502": 1.0, "601": 0.8, "611": 0.6,
    "918": 1.0, "80": 0.9, "90": 0.8, "269": 0.7,
}
# _PROTECTED_SEMANTIC_FAMILIES is imported from vvaharness.rules.families.


def _score_path(path: list[str], src_callsite: CallSite, sink_callsite: CallSite,
                fn_meta: dict[str, tuple[str, int, int]]) -> float:
    """Score a taint path for ranking.
    
    Score = confidence × CWE_severity × (1 / hop_tightness)
    
    where:
    - confidence: edge confidence score (0.1 name-only ... 1.0 same-file)
    - CWE_severity: risk weighting for the sink CWE (high=1.0, low=0.6)
    - hop_tightness: penalty for long chains (shorter = tighter = better)
    """
    # Extract minimum edge confidence across hops.
    # For intra-proc paths, confidence is high (same file).
    # For inter-proc, confidence depends on resolved edge quality.
    hops = len(path) - 1
    if hops == 1:
        conf_score = 1.0  # Intra-proc: high confidence
    else:
        # Inter-proc: assume moderate confidence (type hints + proximity).
        # This is a conservative estimate; could be refined with actual edge data.
        conf_score = 0.8 if hops <= 3 else 0.5
    
    # CWE severity: high-risk CWEs are prioritized.
    cwe_num = _cwe_num(sink_callsite.cwe)
    sev = _CWE_SEVERITY.get(cwe_num, 0.5)
    
    # Hop tightness: shorter paths are more reliable.
    hop_penalty = 1.0 / max(hops, 1)
    
    return conf_score * sev * hop_penalty


def _extract_sink_family(sink: CallSite) -> str:
    """Extract sink family for deduplication (CWE + sink kind)."""
    cwe_num = _cwe_num(sink.cwe)
    semantic = (sink.semantic_family or "").strip().lower()
    if semantic:
        return f"{cwe_num}:{semantic}"
    return f"{cwe_num}:{sink.kind}"


def _effective_global_budget(taint_paths: list[list[str]],
                             sources: dict[str, list[CallSite]],
                             sinks: dict[str, list[CallSite]]) -> int:
    """Iteration C/G extension: expand cap for large repos when needed.

    Keeps default cap for small repos, but scales to a bounded higher cap when
    source/sink fanout is large so semantic-family coverage is preserved.
    """
    src_count = sum(len(v) for v in sources.values())
    sink_count = sum(len(v) for v in sinks.values())
    fanout = src_count * sink_count
    if fanout < 600 and len(taint_paths) <= _GLOBAL_PATH_BUDGET:
        return _GLOBAL_PATH_BUDGET
    if fanout >= 600:
        return min(_GLOBAL_PATH_BUDGET_MAX, _GLOBAL_PATH_BUDGET + 150)
    return min(_GLOBAL_PATH_BUDGET_MAX, _GLOBAL_PATH_BUDGET + 100)


def _filter_paths_by_budget(taint_paths: list[list[str]],
                           sources: dict[str, list[CallSite]],
                           sinks: dict[str, list[CallSite]],
                           fn_meta: dict[str, tuple[str, int, int]],
                           rule_cwe: dict[str, list[str]]) -> tuple[list[list[str]], list[dict[str, object]]]:
    """Apply Iterations A & G: confidence-weighted ranking and global budget cap.

    1. Score each path by confidence × severity × hop_tightness (Iteration A).
    2. Keep top-N paths per source (local budget).
    3. Keep top-M global paths (Iteration G global cap).
    4. Always keep at least one path per (source, sink_family) pair.
    """
    if not taint_paths:
        return taint_paths, []

    # Map path to (score, source_fn, sink_family, src_qnode, dst_qnode, path, sort_idx).
    scored_paths: list[tuple[float, str, str, str, str, list[str], int]] = []

    def _uncertainty_record(src_qnode: str,
                            dst_qnode: str,
                            reason: str,
                            confidence: float) -> dict[str, object]:
        return {
            "src_qnode": src_qnode,
            "dst_qnode": dst_qnode,
            "reason": reason,
            "confidence": round(max(0.0, min(1.0, confidence)), 4),
        }

    for sort_idx, path in enumerate(taint_paths):
        if len(path) < 2:
            continue
        # Hops are encoded as "file:line". A target-repo filename may itself
        # contain ':' , so parse from the right: only the trailing line number
        # is generated by vvaharness (see build_taint_paths). rpartition keeps
        # any colons in the file portion intact.
        src_file, _, src_line_str = path[0].rpartition(":")
        snk_file, _, snk_line_str = path[-1].rpartition(":")
        try:
            src_line = int(src_line_str)
            snk_line = int(snk_line_str)
        except ValueError:
            # Malformed hop (no trailing line number) -> degrade gracefully via
            # the existing neutral-scoring fallback instead of raising.
            scored_paths.append((
                0.5,
                src_file or path[0],
                "unknown",
                src_file or path[0],
                snk_file or path[-1],
                path,
                sort_idx,
            ))
            continue

        # Find source and sink CallSites by matching file:line.
        src_cs = None
        snk_cs = None
        for src_list in sources.values():
            for cs in src_list:
                if cs.file == src_file and cs.line == src_line:
                    src_cs = cs
                    break
        for snk_list in sinks.values():
            for cs in snk_list:
                if cs.file == snk_file and cs.line == snk_line:
                    snk_cs = cs
                    break

        if not src_cs or not snk_cs:
            # Fallback: keep path if we can't resolve sources.
            scored_paths.append((
                0.5,
                src_file,
                "unknown",
                src_file or path[0],
                snk_file or path[-1],
                path,
                sort_idx,
            ))
            continue

        score = _score_path(path, src_cs, snk_cs, fn_meta)
        sink_family = _extract_sink_family(snk_cs)
        src_fn = src_cs.containing_fn or f"<{src_cs.file}:{src_cs.line}>"
        src_qnode = src_cs.containing_fn or f"{src_cs.file}:{src_cs.line}"
        dst_qnode = snk_cs.containing_fn or f"{snk_cs.file}:{snk_cs.line}"
        scored_paths.append((score, src_fn, sink_family, src_qnode, dst_qnode, path, sort_idx))

    if not scored_paths:
        return [], []

    # Sort by score descending with a stable tie-breaker.
    scored_paths.sort(key=lambda x: (-x[0], x[6]))

    # Iteration A: Keep top paths per source (local budget).
    # Keep top 5 paths per source function.
    kept_by_source: dict[str, int] = {}
    per_source_limit = 5

    # Iteration G/C: Apply global budget cap (adaptive bounded extension).
    global_budget = _effective_global_budget(taint_paths, sources, sinks)
    if global_budget <= 0:
        return [], [
            _uncertainty_record(sp[3], sp[4], "global_cap", sp[0])
            for sp in scored_paths
        ]

    # Family floor before final cap: keep top path per sink family first.
    family_best: dict[str, tuple[float, str, str, str, str, list[str], int]] = {}
    for sp in scored_paths:
        if sp[2] not in family_best:
            family_best[sp[2]] = sp

    floor_candidates = sorted(family_best.values(), key=lambda x: (-x[0], x[6]))
    if len(floor_candidates) > global_budget:
        # Preserve the protected-family guard when the family floor itself
        # exceeds budget.
        floor_candidates = sorted(
            floor_candidates,
            key=lambda x: (
                0 if ((x[2].split(":", 1)[1] if ":" in x[2] else x[2]) in _PROTECTED_SEMANTIC_FAMILIES) else 1,
                -x[0],
                x[6],
            ),
        )

    kept_paths: list[list[str]] = []
    kept_indices: set[int] = set()
    kept_pairs: set[tuple[str, str]] = set()
    dropped_uncertainty: list[dict[str, object]] = []

    for sp in floor_candidates:
        if len(kept_paths) >= global_budget:
            dropped_uncertainty.append(_uncertainty_record(sp[3], sp[4], "global_cap", sp[0]))
            continue
        kept_paths.append(sp[5])
        kept_indices.add(sp[6])
        kept_by_source[sp[1]] = kept_by_source.get(sp[1], 0) + 1
        kept_pairs.add((sp[1], sp[2]))

    for score, src_fn, sink_family, src_qnode, dst_qnode, path, sort_idx in scored_paths:
        if sort_idx in kept_indices:
            continue

        pair = (src_fn, sink_family)
        pair_is_new = pair not in kept_pairs

        if len(kept_paths) >= global_budget:
            if not pair_is_new:
                dropped_uncertainty.append(_uncertainty_record(src_qnode, dst_qnode, "global_cap", score))
                continue

        # Check per-source limit (Iteration A).
        if kept_by_source.get(src_fn, 0) >= per_source_limit:
            if not pair_is_new:
                dropped_uncertainty.append(
                    _uncertainty_record(src_qnode, dst_qnode, "per_source_budget", score)
                )
                continue

        # Keep this path.
        kept_paths.append(path)
        kept_by_source[src_fn] = kept_by_source.get(src_fn, 0) + 1
        kept_pairs.add(pair)

    return kept_paths, dropped_uncertainty


def _cwe_num(cwe: str) -> str:
    if not cwe:
        return ""
    s = cwe.upper()
    i = s.find("CWE-")
    if i < 0:
        return ""
    tail = s[i + 4:]
    digits = []
    for ch in tail:
        if ch.isdigit():
            digits.append(ch)
        else:
            break
    return "".join(digits)


def _is_high_risk(cs: CallSite) -> bool:
    c = _cwe_num(cs.cwe)
    if c in _HIGH_RISK_CWE:
        return True
    k = (cs.kind or "").lower()
    return any(tok in k for tok in ("auth", "deserial", "command", "inject", "exec", "path", "sql", "ssrf"))


def _prefix_score(a: str, b: str) -> int:
    ap = Path(a).parent.parts
    bp = Path(b).parent.parts
    n = 0
    for x, y in zip(ap, bp):
        if x != y:
            break
        n += 1
    return n


def _compatible_taint_pair(source: CallSite, sink: CallSite) -> bool:
    # Iteration E recall floor: always keep protected semantic families.
    if (sink.semantic_family or "").strip().lower() in _PROTECTED_SEMANTIC_FAMILIES:
        return True

    src_kind = (source.kind or "").strip().lower()
    sink_kind = (sink.kind or "").strip().lower()
    if not src_kind or src_kind == "other" or not sink_kind or sink_kind == "other":
        return True
    allowed = _SOURCE_KIND_COMPAT.get(src_kind)
    if not allowed:
        return True
    return sink_kind in allowed


def _resolve_called_fids(caller_fid: str,
                         caller_file: str,
                         receiver: str,
                         called_name: str,
                         fn_defs_by_name: dict[str, list[str]],
                         fn_defs_by_qual: dict[str, list[str]],
                         fn_meta: dict[str, tuple[str, int, int]],
                         file_index: dict[str, FileIndex],
                         max_targets: int = _DEFAULT_MAX_TARGETS_PER_CALL,
                         receiver_class: str = "",
                         iface_method_index: dict[str, list[str]] | None = None) -> list[str]:
    """Resolve called_name to function definition(s).

    GAP-JAVA-02: when receiver resolves to an interface type, also check
    iface_method_index for implementing class methods.
    """
    idx = file_index.get(caller_file)
    hinted_type = ""
    hinted_simple = ""
    if idx and receiver:
        hinted_type = idx.imports.get(receiver, "")
        hinted_simple = hinted_type.split(".")[-1] if hinted_type else ""

    # Try qualified match first if receiver_class is available
    cands = []
    if receiver_class:
        qual_name = f"{receiver_class}.{called_name}"
        cands = list(dict.fromkeys(fn_defs_by_qual.get(qual_name, [])))

    # If the caller has a typed receiver variable, prefer owner-qualified
    # resolution before falling back to bare-name matching across the repo.
    if not cands and hinted_simple:
        qual_name = f"{hinted_simple}.{called_name}"
        cands = list(dict.fromkeys(fn_defs_by_qual.get(qual_name, [])))
    
    # Fall back to bare-name resolution if no qualified match
    # GAP-JAVA-02: interface dispatch — if receiver resolves to an interface type,
    # look up known implementations.
    if not cands and receiver and iface_method_index:
        if hinted_simple:
            iface_key = f"{hinted_simple}.{called_name}"
            impl_cands = iface_method_index.get(iface_key, [])
            if impl_cands:
                cands = list(dict.fromkeys(impl_cands))
    # Typed receiver but no owner-qualified or interface match: do not fan out
    # to unrelated bare-name methods such as logger.error() or e.getMessage().
    if not cands and (receiver_class or hinted_simple):
        return []
    
    # GAP-PYTHON-03: expand from X import * (wildcard) symbols
    # If bare-name call is not matched and caller has wildcard imports,
    # check those modules for the called_name definition.
    if not cands and idx:
        for wildcard_key, wildcard_val in (idx.imports or {}).items():
            if wildcard_key.startswith("__wildcard__:"):
                module_name = wildcard_key.split(":", 1)[1]  # Extract module from __wildcard__:module
                # Build qualified name: if module is 'foo.bar', try 'foo.bar.called_name'
                qual_name = f"{module_name}.{called_name}"
                wildcard_cands = fn_defs_by_qual.get(qual_name, [])
                if wildcard_cands:
                    cands = list(dict.fromkeys(wildcard_cands))
                    break  # Use first matching wildcard
    
    if not cands:
        cands = list(dict.fromkeys(fn_defs_by_name.get(called_name, [])))
    if not cands:
        return []
    if len(cands) == 1:
        return [cands[0]]

    # Same-file calls are usually most precise.
    same_file = [fid for fid in cands if fn_meta.get(fid, ("", 0, 0))[0] == caller_file]
    if same_file:
        return same_file[:max_targets]

    # Receiver/type hint from file-level import/type map, if available.
    hinted = hinted_type
    hint_parts = [p.lower() for p in hinted.split(".") if p]

    # C# extension-resolution hints:
    # - '__using_static__:*' carries static owner imports in caller file.
    # - '__cs_extension_method__:<name>' carries known extension owner classes
    #   seen during scanning.
    using_static_owners: list[str] = []
    extension_owner_hints: list[str] = []
    if idx:
        for k, v in (idx.imports or {}).items():
            if k.startswith("__using_static__:") and v:
                using_static_owners.append(v)
            if k == f"__cs_extension_method__:{called_name}" and v:
                extension_owner_hints.append(v)

    # GAP-GRAPH-03: bare-name no-receiver calls previously returned [] (silent drop).
    # Now emit the top-scored candidates as LOW confidence rather than hard-dropping.
    # Downstream stages see these as weaker edges; the WARNING is diagnostic.
    if not receiver_class and not receiver and not hint_parts:
        if len(cands) == 1:
            return cands  # unambiguous bare-name: safe to return
        # Multiple bare-name candidates: return proximity-scored subset at LOW confidence.
        # We use the same scoring path below; just don't gate on hint_parts.
        _log.debug(
            "[graph] bare-name no-hint call to '%s' from '%s' — %d candidate(s); "
            "returning top %d at LOW confidence",
            called_name, caller_fid, len(cands), min(max_targets, len(cands)),
        )
        cp2 = caller_file.split("/")
        def _score2(f: str) -> int:
            n = 0
            for a, b in zip(cp2, f.split("/")):
                if a == b:
                    n += 1
                else:
                    break
            return n
        ranked2 = sorted(cands, key=lambda fid: _score2(fn_meta.get(fid, ("", 0, 0))[0]), reverse=True)
        return ranked2[:max_targets]

    scored: list[tuple[int, str]] = []
    for fid in cands:
        f = fn_meta.get(fid, ("", 0, 0))[0]
        score = _prefix_score(caller_file, f)
        if hint_parts:
            low = f.lower()
            score += sum(1 for p in hint_parts if p in low)
        # Prefer extension owners imported via 'using static Owner;'.
        callee_name = _fid_name(fid)
        callee_owner = callee_name.split(".")[0] if "." in callee_name else ""
        if using_static_owners:
            low_owner = callee_owner.lower()
            for owner in using_static_owners:
                owner_tail = owner.split(".")[-1].lower()
                if owner_tail and owner_tail == low_owner:
                    score += 3
                    break
        if extension_owner_hints:
            low_owner = callee_owner.lower()
            if any(low_owner == h.split(".")[-1].lower() for h in extension_owner_hints):
                score += 2
        scored.append((score, fid))
    scored.sort(key=lambda t: (-t[0], t[1]))

    # Keep only the top-ranked definitions to avoid implausible cross-file fanout.
    if not scored:
        return []
    top = scored[0][0]
    narrowed = [fid for score, fid in scored if score == top][: max_targets]
    result = narrowed if narrowed else [fid for _score, fid in scored[:max_targets]]
    # GAP-GRAPH-02: emit WARNING when legitimate candidates are hard-dropped.
    total_cands = len(scored)
    if total_cands > max_targets:
        dropped = [fid for _score, fid in scored[max_targets:]]
        _log.warning(
            "[graph] max_targets cap (%d): call to '%s' from '%s' dropped %d "
            "candidate(s): %s — increase step1.call_graph_max_targets if these "
            "are known sinks",
            max_targets, called_name, caller_fid, len(dropped),
            ", ".join(dropped[:3]) + (f" +{len(dropped)-3} more" if len(dropped) > 3 else ""),
        )
    return result


def _edge_confidence(caller_fid: str,
                     callee_fid: str,
                     caller_file: str,
                     callee_file: str,
                     receiver: str,
                     called_name: str,
                     file_index: dict[str, FileIndex],
                     fn_meta: dict[str, tuple[str, int, int]]) -> float:
    """Determine confidence score for a resolved call edge.

    Returns:
    - 1.0: same-file call (most precise)
    - 0.9: receiver resolved via import hints
    - 0.7–0.8: proximity match (shared directory prefix)
    - 0.5: name-only fallback (bare function match)
    """
    # SAME_FILE: most precise (intra-file call).
    if caller_file == callee_file:
        return 1.0

    # IMPORT_HINT: receiver type resolved from file-level import map.
    idx = file_index.get(caller_file)
    if idx and receiver:
        hinted = idx.imports.get(receiver, "")
        if hinted and hinted in callee_file:
            return 0.9
        hint_parts = [p.lower() for p in hinted.split(".") if p]
        if hint_parts:
            callee_lower = callee_file.lower()
            hint_matches = sum(1 for p in hint_parts if p in callee_lower)
            if hint_matches >= len(hint_parts) // 2:  # At least half the hint matches
                return 0.9

    # PROXIMITY: directory prefix matching.
    prefix_match = _prefix_score(caller_file, callee_file)
    if prefix_match >= 2:  # Shared at least 2 directory levels
        return 0.8
    elif prefix_match == 1:  # Shared at least 1 directory level
        return 0.7

    # NAME_ONLY: fallback when no other heuristic applies.
    return 0.5


def _fn_id(file: str, fn_name: str) -> str:
    return f"{file}::{fn_name or '<module>'}"


def _fid_name(fid: str) -> str:
    return fid.split("::", 1)[1] if "::" in fid else fid


def _bounded_function_body(file_path: str,
                           start_line: int,
                           end_line: int,
                           file_index: dict[str, FileIndex]) -> str:
    """Return a bounded function body snapshot for prompt context.

    Reads the source file from disk once per signature emission path and clips
    by both line count and char count to remain safe for prompt serialization.
    """
    if start_line <= 0 or end_line < start_line:
        return ""
    abs_path: str | None = None
    idx = file_index.get(file_path)
    if idx is not None:
        # FileIndex only stores repo-relative path; keep this fallback resilient.
        abs_path = None
    try:
        p = Path(file_path)
        if p.is_file():
            abs_path = str(p)
    except Exception:
        abs_path = None
    if not abs_path:
        # When we only have repo-relative paths, best-effort open directly.
        abs_path = file_path
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return ""
    lo = max(0, start_line - 1)
    hi = min(len(lines), end_line)
    if lo >= hi:
        return ""
    body = "\n".join(lines[lo:hi])
    if len(body) > _FUNCTION_BODY_MAX_CHARS:
        return body[:_FUNCTION_BODY_MAX_CHARS].rstrip() + "\n[truncated body snapshot]"
    return body


def _param_symbol(slot: int) -> str:
    return f"__p{slot}"


def _fact_fid(file: str, fn_name: str) -> str:
    return _fn_id(file, fn_name or "")


def _call_targets_for_fact(
    caller_fid: str,
    caller_file: str,
    call_fact,
    fn_defs_by_name: dict[str, list[str]],
    fn_defs_by_qual: dict[str, list[str]],
    fn_meta: dict[str, tuple[str, int, int]],
    file_index: dict[str, FileIndex],
    max_targets: int,
    iface_method_index: dict[str, list[str]] | None = None,
) -> list[str]:
    return _resolve_called_fids(
        caller_fid,
        caller_file,
        getattr(call_fact, "receiver", ""),
        getattr(call_fact, "callee_name", ""),
        fn_defs_by_name,
        fn_defs_by_qual,
        fn_meta,
        file_index,
        max_targets,
        iface_method_index=iface_method_index,
    )


def _has_phase1_facts_for_path(path_fids: tuple[str, ...],
                               assigns_by_fn: dict[str, list],
                               returns_by_fn: dict[str, list],
                               call_args_by_fn: dict[str, list]) -> bool:
    for fid in path_fids:
        if assigns_by_fn.get(fid) or returns_by_fn.get(fid) or call_args_by_fn.get(fid):
            return True
    return False


def _find_matching_call_facts(call_facts: list,
                              line: int,
                              method: str,
                              receiver: str) -> list:
    out = []
    for cf in call_facts:
        if getattr(cf, "line", -1) != line:
            continue
        if getattr(cf, "callee_name", "") != method:
            continue
        cf_recv = getattr(cf, "receiver", "") or ""
        recv = receiver or ""
        if recv and cf_recv and recv != cf_recv:
            continue
        out.append(cf)
    return out


def _seed_source_taint(src_fid: str,
                       source: CallSite,
                       call_args_by_fn: dict[str, list]) -> tuple[set[str], dict[str, str], list[TaintTransferEdge]]:
    tainted_locals: set[str] = set()
    local_origin: dict[str, str] = {}
    edges: list[TaintTransferEdge] = []
    src_ref = TaintSymbolRef(qnode=src_fid, symbol=f"source@{source.line}", kind="arg")
    call_facts = _find_matching_call_facts(
        call_args_by_fn.get(src_fid, []),
        source.line,
        source.method,
        source.receiver,
    )
    for cf in call_facts:
        target = getattr(cf, "target_symbol", None)
        if not target:
            continue
        tainted_locals.add(target)
        local_origin[target] = "source"
        edges.append(TaintTransferEdge(
            file=source.file,
            line=source.line,
            function_qnode=src_fid,
            src=src_ref,
            dst=TaintSymbolRef(qnode=src_fid, symbol=target, kind="local"),
            transfer_kind="source",
        ))
    return tainted_locals, local_origin, edges


# CWE-aware sanitizer table. Keys are CWE numeric strings (without "CWE-" prefix).
# "*" matches any CWE. Functions in the "*" bucket are true universal sanitizers.
# Functions only in specific buckets do NOT neutralize unrelated CWEs.
_SANITIZERS_BY_CWE: dict[str, frozenset[str]] = {
    "*": frozenset({
        "escape", "quote", "sanitize", "clean", "encode",
        "validate", "strip_tags", "html_escape", "xml_escape",
        "quote_plus", "urlencode", "bleach_clean",
        "prepared_statement", "parameterized",
    }),
    # Integer cast: safe for integer-injection sinks but NOT for path/SSRF/xss
    "89": frozenset({"to_int", "int", "float", "bool"}),   # SQLi only
    "90": frozenset({"to_int", "int", "float", "bool"}),   # LDAPi
}

def _is_sanitizer_for_cwe(func_name: str, sink_cwe: str) -> bool:
    """Return True only if func_name is a valid sanitizer for the given CWE."""
    cwe_num = _cwe_num(sink_cwe) if sink_cwe else ""
    universal = _SANITIZERS_BY_CWE.get("*", frozenset())
    if func_name in universal:
        return True
    specific = _SANITIZERS_BY_CWE.get(cwe_num, frozenset())
    return func_name in specific

# Backward-compat flat set (used by existing callers that do not pass CWE context).
_SANITIZER_NAMES: frozenset[str] = frozenset().union(*_SANITIZERS_BY_CWE.values())


def _apply_field_writes(
    fid: str,
    file: str,
    field_writes: list,
    tainted_locals: set[str],
    tainted_fields: set[tuple[str, str]],
) -> list[TaintTransferEdge]:
    """Propagate taint from a local into receiver.field."""
    edges: list[TaintTransferEdge] = []
    for fw in field_writes:
        src_sym = getattr(fw, "src_symbol", None)
        receiver = getattr(fw, "receiver", "")
        field_name = getattr(fw, "field", "")
        line = getattr(fw, "line", 0)
        if not src_sym or src_sym not in tainted_locals:
            continue
        key = (receiver, field_name)
        if key in tainted_fields:
            continue
        tainted_fields.add(key)
        edges.append(TaintTransferEdge(
            file=file,
            line=line,
            function_qnode=fid,
            src=TaintSymbolRef(qnode=fid, symbol=src_sym, kind="local"),
            dst=TaintSymbolRef(qnode=fid, symbol=f"{receiver}.{field_name}", kind="field"),
            transfer_kind="field_write",
        ))
    return edges


def _apply_field_reads(
    fid: str,
    file: str,
    field_reads: list,
    tainted_locals: set[str],
    tainted_fields: set[tuple[str, str]],
) -> list[TaintTransferEdge]:
    """Propagate taint from receiver.field into a local."""
    edges: list[TaintTransferEdge] = []
    for fr in field_reads:
        receiver = getattr(fr, "receiver", "")
        field_name = getattr(fr, "field", "")
        dst_sym = getattr(fr, "dst_symbol", None)
        line = getattr(fr, "line", 0)
        if not dst_sym:
            continue
        # Exact match OR wildcard sentinel (receiver, "*") from inter-procedural carry
        if (receiver, field_name) not in tainted_fields and (receiver, "*") not in tainted_fields:
            continue
        if dst_sym in tainted_locals:
            continue
        tainted_locals.add(dst_sym)
        edges.append(TaintTransferEdge(
            file=file,
            line=line,
            function_qnode=fid,
            src=TaintSymbolRef(qnode=fid, symbol=f"{receiver}.{field_name}", kind="field"),
            dst=TaintSymbolRef(qnode=fid, symbol=dst_sym, kind="local"),
            transfer_kind="field_read",
        ))
    return edges


def _apply_container_writes(
    fid: str,
    file: str,
    container_writes: list,
    tainted_locals: set[str],
    tainted_containers: set[str],
) -> list[TaintTransferEdge]:
    """Whole-container taint when a tainted element is written."""
    edges: list[TaintTransferEdge] = []
    for cw in container_writes:
        container_sym = getattr(cw, "container_symbol", "")
        element_sym = getattr(cw, "element_symbol", None)
        line = getattr(cw, "line", 0)
        if not element_sym or element_sym not in tainted_locals:
            continue
        if container_sym in tainted_containers:
            continue
        tainted_containers.add(container_sym)
        edges.append(TaintTransferEdge(
            file=file,
            line=line,
            function_qnode=fid,
            src=TaintSymbolRef(qnode=fid, symbol=element_sym, kind="local"),
            dst=TaintSymbolRef(qnode=fid, symbol=container_sym, kind="container"),
            transfer_kind="container_put",
        ))
    return edges


def _apply_sanitizers(
    fid: str,
    file: str,
    call_facts: list,
    tainted_locals: set[str],
    tainted_containers: set[str],
    sanitized_locals: set[str],
    sanitizer_names: frozenset[str] = _SANITIZER_NAMES,
    sink_cwe: str = "",
) -> list[TaintTransferEdge]:
    """Neutralize taint when data passes through a known sanitizer.

    GAP-GRAPH-01 residual fix: sanitizer only applies if it is valid for the
    sink CWE (uses CWE-aware table). Symbols are marked in sanitized_locals,
    but tainted state is not globally deleted here. Final suppression is done
    at sink consumption time, which avoids cross-branch false negatives.
    """
    edges: list[TaintTransferEdge] = []
    for cf in call_facts:
        callee = getattr(cf, "callee_name", "")
        # CWE-aware check: if sink_cwe provided, use specific check; else flat set.
        if sink_cwe:
            if not _is_sanitizer_for_cwe(callee, sink_cwe):
                continue
        elif callee not in sanitizer_names:
            continue
        target = getattr(cf, "target_symbol", None)
        arg_syms = list(getattr(cf, "arg_symbols", []) or [])
        line = getattr(cf, "line", 0)
        dst_sym = target or "__sanitized"
        tainted_inputs = [s for s in arg_syms if s in tainted_locals]
        tainted_cont_inputs = [s for s in arg_syms if s in tainted_containers]
        if not tainted_inputs and not tainted_cont_inputs:
            continue
        for s in tainted_inputs:
            # Mark only the sanitizer output symbol as sanitized. Keeping the
            # input symbol unsanitized avoids branch-insensitive false drops.
            edges.append(TaintTransferEdge(
                file=file,
                line=line,
                function_qnode=fid,
                src=TaintSymbolRef(qnode=fid, symbol=s, kind="local"),
                dst=TaintSymbolRef(qnode=fid, symbol=dst_sym, kind="local"),
                transfer_kind="sanitize",
            ))
        for s in tainted_cont_inputs:
            # Preserve container taint and only trust explicit output symbols.
            edges.append(TaintTransferEdge(
                file=file,
                line=line,
                function_qnode=fid,
                src=TaintSymbolRef(qnode=fid, symbol=s, kind="container"),
                dst=TaintSymbolRef(qnode=fid, symbol=dst_sym, kind="local"),
                transfer_kind="sanitize",
            ))
        if target:
            sanitized_locals.add(target)
    return edges


def _apply_local_aliases(fid: str,
                         file: str,
                         assigns: list,
                         tainted_locals: set[str],
                         local_origin: dict[str, str]) -> list[TaintTransferEdge]:
    edges: list[TaintTransferEdge] = []
    changed = True
    while changed:
        changed = False
        for a in assigns:
            src_sym = getattr(a, "src_symbol", None)
            dst_sym = getattr(a, "dst_symbol", "")
            line = getattr(a, "line", 0)
            if not src_sym or not dst_sym:
                continue
            if src_sym not in tainted_locals or dst_sym in tainted_locals:
                continue
            tainted_locals.add(dst_sym)
            local_origin[dst_sym] = local_origin.get(src_sym, "local")
            edges.append(TaintTransferEdge(
                file=file,
                line=line,
                function_qnode=fid,
                src=TaintSymbolRef(qnode=fid, symbol=src_sym, kind="local"),
                dst=TaintSymbolRef(qnode=fid, symbol=dst_sym, kind="local"),
                transfer_kind="assign",
            ))
            changed = True
    return edges


def _call_tainted_arg_slots(call_fact,
                            tainted_locals: set[str],
                            tainted_param_slots: set[int],
                            tainted_containers: set[str] | None = None) -> tuple[set[int], dict[int, str], dict[int, str]]:
    tainted_slots: set[int] = set()
    slot_src_symbol: dict[int, str] = {}
    slot_src_kind: dict[int, str] = {}
    args = list(getattr(call_fact, "arg_symbols", []) or [])
    for idx, sym in enumerate(args):
        if sym in tainted_locals:
            tainted_slots.add(idx)
            slot_src_symbol[idx] = sym
            slot_src_kind[idx] = "local"
        elif idx in tainted_param_slots:
            tainted_slots.add(idx)
            slot_src_symbol[idx] = _param_symbol(idx)
            slot_src_kind[idx] = "param"
        elif tainted_containers and sym in tainted_containers:
            tainted_slots.add(idx)
            slot_src_symbol[idx] = sym
            slot_src_kind[idx] = "container"
    return tainted_slots, slot_src_symbol, slot_src_kind


def _callee_may_return_tainted(callee_fid: str,
                               tainted_arg_slots: set[int],
                               returns_by_fn: dict[str, list]) -> bool:
    if not tainted_arg_slots:
        return False
    rets = returns_by_fn.get(callee_fid, [])
    ret_syms = {getattr(r, "symbol", None) for r in rets} - {None}
    if not ret_syms:
        return False
    tainted_param_syms = {_param_symbol(s) for s in tainted_arg_slots}
    if ret_syms & tainted_param_syms:
        return True
    return False


def _apply_return_to_local(
    fid: str,
    file: str,
    call_facts: list,
    tainted_locals: set[str],
    local_origin: dict[str, str],
    tainted_param_slots: set[int],
    fn_defs_by_name: dict[str, list[str]],
    fn_defs_by_qual: dict[str, list[str]],
    fn_meta: dict[str, tuple[str, int, int]],
    file_index: dict[str, FileIndex],
    returns_by_fn: dict[str, list],
    max_targets: int,
) -> list[TaintTransferEdge]:
    edges: list[TaintTransferEdge] = []
    for cf in call_facts:
        target = getattr(cf, "target_symbol", None)
        if not target:
            continue
        tainted_slots, _, _ = _call_tainted_arg_slots(cf, tainted_locals, tainted_param_slots)
        if not tainted_slots:
            continue
        targets = _call_targets_for_fact(
            fid,
            file,
            cf,
            fn_defs_by_name,
            fn_defs_by_qual,
            fn_meta,
            file_index,
            max_targets,
        )
        if not targets:
            continue
        if not any(_callee_may_return_tainted(callee_fid, tainted_slots, returns_by_fn)
                   for callee_fid in targets):
            continue
        if target in tainted_locals:
            continue
        tainted_locals.add(target)
        local_origin[target] = "return"
        callee_ref = TaintSymbolRef(qnode=targets[0], symbol="return", kind="return")
        edges.append(TaintTransferEdge(
            file=file,
            line=getattr(cf, "line", 0),
            function_qnode=fid,
            src=callee_ref,
            dst=TaintSymbolRef(qnode=fid, symbol=target, kind="local"),
            transfer_kind="return_to_local",
        ))
    return edges


def _transfer_closure(fid: str,
                      file: str,
                      tainted_locals: set[str],
                      local_origin: dict[str, str],
                      tainted_param_slots: set[int],
                      assigns_by_fn: dict[str, list],
                      call_args_by_fn: dict[str, list],
                      returns_by_fn: dict[str, list],
                      fn_defs_by_name: dict[str, list[str]],
                      fn_defs_by_qual: dict[str, list[str]],
                      fn_meta: dict[str, tuple[str, int, int]],
                      file_index: dict[str, FileIndex],
                      max_targets: int,
                      # Optional field/container/sanitize additions (backward compat):
                      field_writes_by_fn: dict[str, list] | None = None,
                      field_reads_by_fn: dict[str, list] | None = None,
                      container_writes_by_fn: dict[str, list] | None = None,
                      tainted_fields: set[tuple[str, str]] | None = None,
                      tainted_containers: set[str] | None = None,
                      sanitized_locals: set[str] | None = None,
                      sink_cwe: str = "") -> list[TaintTransferEdge]:
    edges: list[TaintTransferEdge] = []
    # Use provided mutable sets or local no-op sets
    _tf: set[tuple[str, str]] = tainted_fields if tainted_fields is not None else set()
    _tc: set[str] = tainted_containers if tainted_containers is not None else set()
    _sl: set[str] = sanitized_locals if sanitized_locals is not None else set()
    changed = True
    while changed:
        before_locals = len(tainted_locals)
        before_fields = len(_tf)
        before_containers = len(_tc)
        # 1. Sanitizers first — neutralize before propagating
        edges.extend(_apply_sanitizers(
            fid, file,
            call_args_by_fn.get(fid, []),
            tainted_locals, _tc, _sl,
            sink_cwe=sink_cwe,
        ))
        # 2. Field writes
        if field_writes_by_fn is not None:
            edges.extend(_apply_field_writes(
                fid, file,
                field_writes_by_fn.get(fid, []),
                tainted_locals, _tf,
            ))
        # 3. Field reads
        if field_reads_by_fn is not None:
            edges.extend(_apply_field_reads(
                fid, file,
                field_reads_by_fn.get(fid, []),
                tainted_locals, _tf,
            ))
        # 4. Container writes
        if container_writes_by_fn is not None:
            edges.extend(_apply_container_writes(
                fid, file,
                container_writes_by_fn.get(fid, []),
                tainted_locals, _tc,
            ))
        # 5. Local aliases
        edges.extend(_apply_local_aliases(
            fid,
            file,
            assigns_by_fn.get(fid, []),
            tainted_locals,
            local_origin,
        ))
        # 6. Return-to-local
        edges.extend(_apply_return_to_local(
            fid,
            file,
            call_args_by_fn.get(fid, []),
            tainted_locals,
            local_origin,
            tainted_param_slots,
            fn_defs_by_name,
            fn_defs_by_qual,
            fn_meta,
            file_index,
            returns_by_fn,
            max_targets,
        ))
        changed = (
            len(tainted_locals) > before_locals
            or len(_tf) > before_fields
            or len(_tc) > before_containers
        )
    return edges


def _build_taint_evidence_for_path(
    source: CallSite,
    sink: CallSite,
    path_fids: tuple[str, ...],
    fn_meta: dict[str, tuple[str, int, int]],
    assigns_by_fn: dict[str, list],
    returns_by_fn: dict[str, list],
    call_args_by_fn: dict[str, list],
    fn_defs_by_name: dict[str, list[str]],
    fn_defs_by_qual: dict[str, list[str]],
    file_index: dict[str, FileIndex],
    max_targets: int,
    # Field/container/sanitize additions:
    field_writes_by_fn: dict[str, list] | None = None,
    field_reads_by_fn: dict[str, list] | None = None,
    container_writes_by_fn: dict[str, list] | None = None,
) -> TaintEvidencePath | None:
    if not path_fids:
        return None
    src_fid = path_fids[0]
    src_ref = f"{source.file}:{source.line}"
    sink_ref = f"{sink.file}:{sink.line}"

    tainted_locals, local_origin, edges = _seed_source_taint(
        src_fid,
        source,
        call_args_by_fn,
    )
    tainted_param_slots: set[int] = set()
    # Per-path field/container/sanitize state
    tainted_fields: set[tuple[str, str]] = set()
    tainted_containers: set[str] = set()
    sanitized_locals: set[str] = set()

    for idx, fid in enumerate(path_fids):
        fmeta = fn_meta.get(fid)
        file = fmeta[0] if fmeta else source.file

        edges.extend(_transfer_closure(
            fid,
            file,
            tainted_locals,
            local_origin,
            tainted_param_slots,
            assigns_by_fn,
            call_args_by_fn,
            returns_by_fn,
            fn_defs_by_name,
            fn_defs_by_qual,
            fn_meta,
            file_index,
            max_targets,
            field_writes_by_fn=field_writes_by_fn,
            field_reads_by_fn=field_reads_by_fn,
            container_writes_by_fn=container_writes_by_fn,
            tainted_fields=tainted_fields,
            tainted_containers=tainted_containers,
            sanitized_locals=sanitized_locals,
            sink_cwe=sink.cwe,
        ))

        if idx == len(path_fids) - 1:
            # Sink function: taint must reach sink argument(s).
            sink_calls = _find_matching_call_facts(
                call_args_by_fn.get(fid, []),
                sink.line,
                sink.method,
                sink.receiver,
            )
            for cf in sink_calls:
                tainted_slots, slot_symbol, slot_kind = _call_tainted_arg_slots(
                    cf,
                    tainted_locals,
                    tainted_param_slots,
                    tainted_containers,
                )
                if tainted_slots:
                    unsanitized_slots: list[int] = []
                    for slot in sorted(tainted_slots):
                        sym = slot_symbol.get(slot, _param_symbol(slot))
                        kind = slot_kind.get(slot, "param")
                        is_sanitized = sym in sanitized_locals
                        if kind == "container" and sym in sanitized_locals:
                            is_sanitized = True
                        if not is_sanitized:
                            unsanitized_slots.append(slot)
                    if unsanitized_slots:
                        for slot in unsanitized_slots:
                            sym = slot_symbol.get(slot, _param_symbol(slot))
                            kind = slot_kind.get(slot, "param")
                            transfer = "local_to_sink"
                            if kind == "local" and local_origin.get(sym) == "return":
                                transfer = "return_to_sink"
                            elif kind == "container":
                                # Emit container_get edge then local_to_sink
                                edges.append(TaintTransferEdge(
                                    file=sink.file,
                                    line=sink.line,
                                    function_qnode=fid,
                                    src=TaintSymbolRef(qnode=fid, symbol=sym, kind="container"),
                                    dst=TaintSymbolRef(qnode=fid, symbol=f"arg{slot}", kind="arg"),
                                    transfer_kind="container_get",
                                ))
                                transfer = "local_to_sink"
                            if kind != "container":
                                edges.append(TaintTransferEdge(
                                    file=sink.file,
                                    line=sink.line,
                                    function_qnode=fid,
                                    src=TaintSymbolRef(qnode=fid, symbol=sym, kind=kind),
                                    dst=TaintSymbolRef(qnode=fid, symbol=f"arg{slot}", kind="arg"),
                                    transfer_kind=transfer,
                                ))
                        return TaintEvidencePath(
                            source_ref=src_ref,
                            sink_ref=sink_ref,
                            path_funcs=list(path_fids),
                            edges=edges,
                            sink_cwe=[sink.cwe] if sink.cwe else [],
                            sanitized=False,
                        )
                    # All tainted sink args are sanitized on this path.
                    return TaintEvidencePath(
                        source_ref=src_ref,
                        sink_ref=sink_ref,
                        path_funcs=list(path_fids),
                        edges=edges,
                        sink_cwe=[sink.cwe] if sink.cwe else [],
                        sanitized=True,
                    )
                # No tainted slots — check if any arg was sanitized (path
                # reaches sink via a sanitized value → report but mark sanitized)
                if sanitized_locals:
                    args = list(getattr(cf, "arg_symbols", []) or [])
                    if any(a in sanitized_locals for a in args):
                        return TaintEvidencePath(
                            source_ref=src_ref,
                            sink_ref=sink_ref,
                            path_funcs=list(path_fids),
                            edges=edges,
                            sink_cwe=[sink.cwe] if sink.cwe else [],
                            sanitized=True,
                        )
            return None

        next_fid = path_fids[idx + 1]
        call_facts = call_args_by_fn.get(fid, [])
        next_slots: set[int] = set()
        next_edges: list[TaintTransferEdge] = []
        for cf in call_facts:
            targets = _call_targets_for_fact(
                fid,
                file,
                cf,
                fn_defs_by_name,
                fn_defs_by_qual,
                fn_meta,
                file_index,
                max_targets,
            )
            if next_fid not in targets:
                continue
            tainted_slots, slot_symbol, slot_kind = _call_tainted_arg_slots(
                cf,
                tainted_locals,
                tainted_param_slots,
            )
            if not tainted_slots:
                continue
            next_slots.update(tainted_slots)
            for slot in sorted(tainted_slots):
                next_edges.append(TaintTransferEdge(
                    file=file,
                    line=getattr(cf, "line", 0),
                    function_qnode=fid,
                    src=TaintSymbolRef(
                        qnode=fid,
                        symbol=slot_symbol.get(slot, _param_symbol(slot)),
                        kind=slot_kind.get(slot, "param"),
                    ),
                    dst=TaintSymbolRef(qnode=next_fid, symbol=_param_symbol(slot), kind="param"),
                    transfer_kind="arg_to_param",
                ))
        if not next_slots:
            return None
        edges.extend(next_edges)
        tainted_param_slots = next_slots
        tainted_locals = set()
        local_origin = {}
        # Reset intra-function field/container state at function boundary;
        # sanitized_locals carries across (sanitized values may be passed as args).
        tainted_fields = set()
        tainted_containers = set()

    return None


def _apply_condition_taint(
    taint_state: dict[str, bool],
    condition_text: str,
    is_then_branch: bool,
) -> dict[str, bool]:
    """Apply path-sensitive taint reasoning at a conditional branch.

    On the *then* branch the condition is assumed satisfied, so taint flows
    through unchanged.  On the *else* branch the condition acts as an implicit
    gate: if the condition symbol itself is tainted the confidence is lowered
    (represented by flipping the tainted flag to False as a conservative
    neutralization); otherwise full neutralization is applied.

    Args:
        taint_state:    Mapping of symbol name → is_tainted.
        condition_text: Raw text of the branch condition, e.g. ``"is_admin"``.
        is_then_branch: True for the *then* (if) arm, False for the *else* arm.

    Returns:
        A *copy* of ``taint_state`` with neutralizations applied.
    """
    result = dict(taint_state)
    if is_then_branch:
        # Taint passes through on the satisfied branch.
        return result

    # Else branch: extract the bare symbol from the condition text.
    # Simple heuristic: strip common boolean prefixes and comparison operators.
    cond = condition_text.strip()
    # Remove leading "not " / "!" to get the core symbol.
    cond = re.sub(r"^(not\s+|!\s*)", "", cond, flags=re.IGNORECASE).strip()
    # Grab the first identifier (stops at spaces/operators/dots/brackets).
    m = re.match(r"([A-Za-z_][A-Za-z0-9_.]*)", cond)
    cond_sym = m.group(1) if m else ""

    if cond_sym and result.get(cond_sym, False):
        # Condition variable is itself tainted → lower confidence rather than
        # full drop.  We represent "lower confidence" by neutralizing the
        # condition symbol only (conservative: other tainted symbols survive).
        result[cond_sym] = False
    else:
        if cond_sym:
            # Condition checks an untainted variable — tainted data can still
            # flow on this branch.  Only clear the condition symbol itself.
            result[cond_sym] = False
        else:
            # No parseable condition symbol — conservative: wipe all taint.
            for sym in list(result.keys()):
                result[sym] = False
    return result


def _condition_edge_confidence(condition_text: str, fid: str,
                                assigns_by_fn: dict[str, list]) -> str:
    """Score confidence for a condition-gated edge.

    - "high"   if the condition variable is a function parameter (simple name)
    - "medium" if it looks like a field/property access (contains a dot)
    - "low"    if it is a complex expression (operators, calls, etc.)
    """
    cond = condition_text.strip()
    # Complex expression: contains operators, parentheses, or function calls.
    if re.search(r"[()&|!=<>]|and\b|or\b|not\b", cond, re.IGNORECASE):
        return "low"
    if "." in cond:
        return "medium"
    # Check if this matches a parameter symbol in the enclosing function.
    call_facts = assigns_by_fn.get(fid, [])
    param_syms = {getattr(a, "dst_symbol", "") for a in call_facts}
    if cond in param_syms:
        return "high"
    return "medium"  # Bare name not confirmed as a parameter — medium confidence.


def _solve_with_cfgs(
    file_indices: list[FileIndex],
    symbol_table: dict[str, object],
    assigns_by_fn: dict[str, list],
) -> list[TaintEvidencePath]:
    """Walk CFG blocks to produce path-sensitive taint evidence.

    For each file that has per-function CFGs, walks from the CFG entry block
    through successors, tracking taint state.  At conditional branch points
    (blocks with a non-None ``condition`` and exactly two successors) it forks
    the taint state: the *then* arm inherits taint unchanged; the *else* arm
    applies :func:`_apply_condition_taint`.  A
    :class:`~vvaharness.models.ConditionTaintEdge` is emitted at each branch.

    Args:
        file_indices:  All per-file AST/fact data (may include CFGs).
        symbol_table:  Mapping of qualified symbol name → arbitrary metadata
                       (currently used only as existence check for names).
        assigns_by_fn: Per-function assignment facts (for confidence scoring).

    Returns:
        A list of :class:`~vvaharness.models.TaintEvidencePath` objects, one
        per reachable block sequence that ends with a tainted symbol still live.
        Empty list when no CFGs are present or no taint is trackable.
    """
    results: list[TaintEvidencePath] = []

    for file_idx in file_indices:
        cfgs: dict[str, object] = getattr(file_idx, "cfgs", {}) or {}
        if not cfgs:
            continue

        for func_qnode, cfg in cfgs.items():
            if cfg is None:
                continue
            blocks = getattr(cfg, "blocks", {}) or {}
            entry = getattr(cfg, "entry", "B0")
            if entry not in blocks:
                continue

            # Symbolic taint state: symbol → is_tainted.
            # Seeded from the block's statement list (not parsed at MVP; kept
            # as empty so the CFG walk itself is exercised without false taint).
            initial_state: dict[str, bool] = {}
            edges: list[TaintTransferEdge] = []

            # BFS over CFG blocks; each queue item carries a snapshot of taint.
            visited_block_ids: set[str] = set()
            queue: deque[tuple[str, dict[str, bool]]] = deque(
                [(entry, dict(initial_state))]
            )

            while queue:
                block_id, ts = queue.popleft()
                if block_id in visited_block_ids:
                    continue
                visited_block_ids.add(block_id)

                node = blocks.get(block_id)
                if node is None:
                    continue

                successors: list[str] = getattr(node, "successors", []) or []
                condition: str | None = getattr(node, "condition", None)

                if condition and len(successors) == 2:
                    # Binary conditional branch: fork taint state.
                    then_blk, else_blk = successors[0], successors[1]
                    ts_then = _apply_condition_taint(ts, condition, is_then_branch=True)
                    ts_else = _apply_condition_taint(ts, condition, is_then_branch=False)
                    conf = _condition_edge_confidence(condition, func_qnode, assigns_by_fn)

                    # Emit a ConditionTaintEdge for the else (neutralizing) branch.
                    is_tainted_cond = any(ts.get(s, False)
                                         for s in re.findall(r"[A-Za-z_]\w*", condition))
                    edges.append(ConditionTaintEdge(
                        file=file_idx.file,
                        line=0,
                        function_qnode=func_qnode,
                        src=TaintSymbolRef(qnode=func_qnode, symbol=condition, kind="local"),
                        dst=TaintSymbolRef(qnode=func_qnode, symbol=else_blk, kind="local"),
                        transfer_kind="condition",
                        condition_text=condition,
                        is_tainted_condition=is_tainted_cond,
                        confidence=conf,
                    ))

                    if else_blk not in visited_block_ids:
                        queue.append((else_blk, ts_else))
                    if then_blk not in visited_block_ids:
                        queue.append((then_blk, ts_then))
                else:
                    # Unconditional: propagate unchanged taint to all successors.
                    for succ in successors:
                        if succ not in visited_block_ids:
                            queue.append((succ, dict(ts)))

            if edges:
                results.append(TaintEvidencePath(
                    source_ref=f"{file_idx.file}::{func_qnode}",
                    sink_ref=f"{file_idx.file}::{func_qnode}",
                    path_funcs=[func_qnode],
                    edges=edges,
                    sink_cwe=[],
                    sanitized=False,
                ))

    return results


def _resolve_reflection_targets(
    reflection_fact: ReflectionFact,
    symbol_table: dict[str, object],
    language: str,
) -> tuple[list[str], str]:
    """Resolve the static targets of a reflective call as precisely as possible.

    Resolution strategy (in priority order):

    1. **Literal string** — ``target_symbols`` contains a bare identifier or
       a dotted name that exists in ``symbol_table`` → high confidence.
    2. **Variable with known values** — ``target_symbols`` contains a name
       that can be resolved from the symbol table → medium confidence.
    3. **Dynamic / untraceable** — the target cannot be resolved statically →
       returns ``["*UNKNOWN*"]`` with low confidence.

    Args:
        reflection_fact: The :class:`~vvaharness.models.ReflectionFact` to
                         resolve.
        symbol_table:    Mapping of fully-qualified symbol names to metadata.
                         Keys are canonical ``file::function`` or
                         ``ClassName.method`` strings.
        language:        Source language (``"python"``, ``"java"``,
                         ``"csharp"``).  Used for name-matching heuristics.

    Returns:
        A ``(targets, confidence)`` tuple where *targets* is a list of
        resolved fully-qualified names and *confidence* is one of ``"high"``,
        ``"medium"``, or ``"low"``.
    """
    targets: list[str] = []
    confidence = "low"

    for sym in reflection_fact.target_symbols:
        if not sym:
            continue
        sym = sym.strip()
        # Heuristic 1: literal string that looks like a qualified name.
        # A literal typically starts with a quote or is a bare identifier with
        # no operator characters.
        is_literal = bool(re.match(r'^[A-Za-z_$][A-Za-z0-9_.$]*$', sym))
        if is_literal:
            # Direct lookup in symbol table.
            if sym in symbol_table:
                targets.append(sym)
                confidence = "high"
                continue
            # Try language-specific suffix matches.
            matches = [k for k in symbol_table if k.endswith(f".{sym}") or k.endswith(f"::{sym}")]
            if matches:
                targets.extend(matches[:3])  # Cap fanout.
                confidence = "high" if len(matches) == 1 else "medium"
                continue
            # Exists as a bare name (no qualifier) — partial match.
            bare_matches = [k for k in symbol_table
                            if k.split("::")[-1] == sym or k.split(".")[-1] == sym]
            if bare_matches:
                targets.extend(bare_matches[:3])
                confidence = max(confidence, "medium")  # type: ignore[arg-type]
                continue
            # Literal name not in table but looks concrete — keep with medium.
            targets.append(sym)
            confidence = max(confidence, "medium")  # type: ignore[arg-type]
        else:
            # Variable or expression: attempt constant propagation is out of
            # scope for the MVP.  Emit UNKNOWN placeholder.
            targets.append("*UNKNOWN*")

    if not targets:
        targets = ["*UNKNOWN*"]

    # Normalise confidence ordering.
    _ord = {"high": 2, "medium": 1, "low": 0}
    if confidence not in _ord:
        confidence = "low"
    return targets, confidence


def _emit_reflection_taint_edges(
    source_sym: TaintSymbolRef,
    reflection_fact: ReflectionFact,
    resolved_targets: list[str],
    confidence: str,
) -> list[ReflectionTaintEdge]:
    """Build :class:`~vvaharness.models.ReflectionTaintEdge` objects for each target.

    Each edge is speculative by construction — the taint *may* flow through the
    dynamically resolved target, but static analysis cannot be certain.

    Args:
        source_sym:       The tainted symbol that feeds the reflection call.
        reflection_fact:  The originating :class:`~vvaharness.models.ReflectionFact`.
        resolved_targets: Fully-qualified names from
                          :func:`_resolve_reflection_targets`.
        confidence:       Confidence string from the same function.

    Returns:
        One :class:`~vvaharness.models.ReflectionTaintEdge` per resolved target.
    """
    edges: list[ReflectionTaintEdge] = []
    conf_lit: str = confidence if confidence in {"high", "medium", "low"} else "low"
    for target in resolved_targets:
        dst = TaintSymbolRef(
            qnode=target,
            symbol=target,
            kind="local",
        )
        edges.append(ReflectionTaintEdge(
            file=source_sym.qnode.split("::")[0] if "::" in source_sym.qnode else "",
            line=reflection_fact.line,
            function_qnode=reflection_fact.function_qnode,
            src=source_sym,
            dst=dst,
            transfer_kind="reflect",
            reflected_targets=list(resolved_targets),
            confidence=conf_lit,
            is_speculative=True,
        ))
    return edges


def _apply_reflection_to_taint(
    taint_state: dict[str, bool],
    reflection_facts: list[ReflectionFact],
    symbol_table: dict[str, object],
    language: str,
    fid: str,
) -> tuple[dict[str, bool], list[ReflectionTaintEdge]]:
    """Apply reflection-based taint propagation to the current taint state.

    For each :class:`~vvaharness.models.ReflectionFact` in the current function:

    1. Resolve reflection targets via :func:`_resolve_reflection_targets`.
    2. If any ``target_symbol`` of the fact is currently tainted, propagate
       taint to all resolved targets (conservative over-approximation).
    3. Emit one :class:`~vvaharness.models.ReflectionTaintEdge` per transfer.

    The returned ``taint_state`` is an *updated copy* of the input mapping.

    Args:
        taint_state:      Current symbol → is_tainted mapping.
        reflection_facts: All reflection facts for the enclosing function.
        symbol_table:     Fully-qualified symbol registry for resolution.
        language:         Source language identifier.
        fid:              Fully-qualified function node id (``file::fn``).

    Returns:
        ``(updated_taint_state, emitted_edges)`` tuple.
    """
    result = dict(taint_state)
    emitted: list[ReflectionTaintEdge] = []

    for rf in reflection_facts:
        if rf.function_qnode and not fid.endswith(rf.function_qnode.split("::")[-1]):
            # Fast skip: this reflection fact belongs to a different function.
            continue
        # Check whether any target symbol in the reflection call is tainted.
        tainted_inputs = [s for s in rf.target_symbols if result.get(s, False)]
        if not tainted_inputs:
            continue

        resolved, conf = _resolve_reflection_targets(rf, symbol_table, language)
        for sym in tainted_inputs:
            source_sym = TaintSymbolRef(qnode=fid, symbol=sym, kind="local")
            new_edges = _emit_reflection_taint_edges(source_sym, rf, resolved, conf)
            emitted.extend(new_edges)
            # Conservatively mark every resolved target as tainted.
            for target in resolved:
                if target != "*UNKNOWN*":
                    result[target] = True

    return result, emitted


def _build_symbol_table(file_indices: list[FileIndex]) -> dict[str, object]:
    """Construct a flat symbol table from all file indices.

    Keys are function-qnode strings (``file::fn_name`` or
    ``ClassName.method_name``).  Values are placeholder ``True`` sentinels;
    the table is queried only for membership.

    Args:
        file_indices: All scanned file data.

    Returns:
        Dict mapping every known qualified symbol to ``True``.
    """
    table: dict[str, object] = {}
    for idx in file_indices:
        for fd in idx.functions:
            qnode = _fn_id(idx.file, fd.name)
            table[qnode] = True
            bare = fd.name
            table[bare] = True
            if getattr(fd, "class_name", ""):
                qual = f"{fd.class_name}.{fd.name}"
                table[qual] = True
    return table


def _build_framework_symbol_table(file_indices: list[FileIndex]) -> dict[str, list[str]]:
    """Extract framework markers and route facts into a parameter taint map.
    
    Builds a dict mapping function_qnode → list of parameter names that are
    tainted via framework annotations or route bindings (e.g., @RequestParam,
    request.GET, URL path parameters).
    
    Args:
        file_indices: All scanned file indices.
        
    Returns:
        Dict mapping function_qnode → [tainted parameter names].
        Example: {"UserController.getUser" → ["id", "name"]}
    """
    framework_params: dict[str, list[str]] = defaultdict(list)
    
    for idx in file_indices:
        # Extract framework markers (explicit annotations and implicit type-based markers)
        for marker in getattr(idx, "framework_markers", []) or []:
            qnode = getattr(marker, "function_qnode", "")
            if not qnode:
                continue
            param_names = getattr(marker, "parameter_names", []) or []
            for pname in param_names:
                if pname not in framework_params[qnode]:
                    framework_params[qnode].append(pname)
        
        # Extract route facts (URL path parameters bound to function arguments)
        for route in getattr(idx, "route_facts", []) or []:
            qnode = getattr(route, "function_qnode", "")
            if not qnode:
                continue
            param_name = getattr(route, "parameter_name", "")
            if param_name and getattr(route, "is_tainted", True):
                if param_name not in framework_params[qnode]:
                    framework_params[qnode].append(param_name)
    
    return dict(framework_params)


def _apply_framework_markers(taint_state: dict[str, bool],
                              framework_markers: list) -> dict[str, bool]:
    """Apply framework marker facts to the taint state.
    
    For each FrameworkMarkerFact, mark its parameter_names as tainted in the
    taint_state dict. Framework annotations are treated as high-confidence
    source markers (implicit entry points).
    
    Args:
        taint_state: Current taint state (symbol → bool).
        framework_markers: List of FrameworkMarkerFact objects.
        
    Returns:
        Updated taint_state with framework-marked parameters tainted.
    """
    result = dict(taint_state)
    for marker in framework_markers:
        param_names = getattr(marker, "parameter_names", []) or []
        for pname in param_names:
            result[pname] = True
    return result


# Marker names that signal an authentication/authorization guard on a function.
# If ANY of these appears on a function alongside a route/source marker, the
# function is auth-protected and should NOT be marked reachable_from_unauth.
_AUTH_ANNOTATION_MARKERS: frozenset[str] = frozenset({
    # Java Spring Security
    "@PreAuthorize", "@PostAuthorize", "@Secured", "@DenyAll",
    # Java JAX-RS / MicroProfile
    "@RolesAllowed", "@PermitAll",
    # Java Apache Shiro
    "@RequiresAuthentication", "@RequiresUser",
    "@RequiresRoles", "@RequiresPermissions",
    # C# ASP.NET Core
    "[Authorize]", "[RequireHttps]",
    # Python Flask-Login / Django / Flask-Principal
    "login_required", "permission_required", "requires_auth",
})


def _emit_framework_entry_points(file_indices: list[FileIndex]) -> list[EntryPoint]:
    """Emit synthetic entry points from framework markers.

    Finds all FrameworkMarkerFact instances and creates corresponding EntryPoint
    records with kind="framework" to distinguish them from reachability-based
    entry points.  reachable_from_unauth is True for route handlers that carry
    no auth-annotation marker, and False when an auth guard is detected on the
    same function.
    """
    # First pass: collect ALL marker names per (file, qnode) so we can see the
    # complete annotation set before deciding reachable_from_unauth.
    fn_markers: dict[tuple[str, str], list[str]] = {}
    for idx in file_indices:
        file = idx.file
        for marker in getattr(idx, "framework_markers", []) or []:
            qnode = getattr(marker, "function_qnode", "")
            if not qnode:
                continue
            marker_name = getattr(marker, "marker_name", "unknown")
            fn_markers.setdefault((file, qnode), []).append(marker_name)

    # Second pass: emit one EntryPoint per unique qnode.
    entry_points: list[EntryPoint] = []
    seen: set[str] = set()  # qnode
    for (file, qnode), marker_names in fn_markers.items():
        if qnode in seen:
            continue
        seen.add(qnode)
        fn_name = qnode.split("::")[-1] if "::" in qnode else qnode
        has_auth_guard = bool(set(marker_names) & _AUTH_ANNOTATION_MARKERS)
        entry_points.append(EntryPoint(
            file=file,
            function=fn_name,
            kind="framework",
            reachable_from_unauth=not has_auth_guard,
        ))

    return entry_points


def _apply_response_dataflow(evidence_paths: list[TaintEvidencePath],
                              response_dataflows: list) -> list[TaintEvidencePath]:
    """Enhance evidence paths with response dataflow information.
    
    For each evidence path, check if any response_dataflow fact is reachable.
    If tainted data reaches a response sink, enhance the evidence path with
    response output tracking (sets sink_cwe based on response type).
    
    Args:
        evidence_paths: List of taint evidence paths.
        response_dataflows: List of ResponseDataflowFact objects.
        
    Returns:
        Enhanced evidence paths with response dataflow annotations.
    """
    if not response_dataflows:
        return evidence_paths
    
    # Map function_qnode → list of ResponseDataflowFact for fast lookup
    response_by_fn: dict[str, list] = defaultdict(list)
    for rdf in response_dataflows:
        qnode = getattr(rdf, "function_qnode", "")
        if qnode:
            response_by_fn[qnode].append(rdf)
    
    # CWE mapping for response types (injection vulnerabilities)
    response_type_cwes: dict[str, str] = {
        "json": "CWE-90",       # JSON injection
        "html": "CWE-79",       # Cross-site scripting (XSS)
        "xml": "CWE-611",       # XML External Entity (XXE)
        "text": "CWE-117",      # Log injection
    }
    
    result = []
    for ep in evidence_paths:
        result.append(ep)
        
        # Check if any path function has response dataflows
        path_funcs = getattr(ep, "path_funcs", []) or []
        if not path_funcs:
            continue
        
        for pf in path_funcs:
            rdf_facts = response_by_fn.get(pf, [])
            if not rdf_facts:
                continue
            
            # For each response dataflow in a path function, enhance evidence
            # with response sink CWE (injection risk via response type)
            for rdf in rdf_facts:
                response_type = getattr(rdf, "response_type", "json") or "json"
                cwe = response_type_cwes.get(response_type, "CWE-90")
                
                # Enhance existing evidence with response CWE if not already present
                sink_cwe = getattr(ep, "sink_cwe", []) or []
                if cwe not in sink_cwe:
                    ep.sink_cwe = list(set(sink_cwe + [cwe]))
    
    return result


# Standard-library utility classes whose API methods (get, format, join, etc.)
# should NOT be classified as network-kind taint sources. They can still be
# sinks (e.g. String.format → sql injection) but are not input ingress points.
_STDLIB_UTIL_MODULES: frozenset[str] = frozenset({
    # Java
    "java.util", "java.util.properties", "java.util.map",
    "java.util.list", "java.util.set", "java.lang.string",
    "java.lang.stringbuilder", "java.lang.stringbuffer",
    "string", "stringbuilder", "stringbuffer",
    "optional", "collections", "arrays",
    # Python
    "str", "list", "dict", "set", "tuple",
    # JavaScript/TypeScript
    "array", "object", "map",
    # C#
    "system.string", "system.collections.generic",
})

_TEST_PATH_PATTERNS: tuple[str, ...] = (
    "/test/", "/tests/", "/test-", "Test.java", "Tests.java",
    "Spec.java", "spec.py", "_test.py", ".test.ts", ".spec.ts",
    ".test.js", ".spec.js", "mock", "Mock", "stub", "Stub",
    "__tests__",
)


def _is_test_file(file_path: str) -> bool:
    """Return True if the file path looks like a test or mock file."""
    for pat in _TEST_PATH_PATTERNS:
        if pat in file_path:
            return True
    return False


def _is_stdlib_util_source(cs: "CallSite") -> bool:
    """Return True when a source CallSite matches a stdlib utility whose receiver
    is not a real network ingress point (e.g. Properties.get, Map.get, String.format).
    These are legitimate sinks but not entry-point sources.
    """
    if (cs.kind or "").strip().lower() != "network":
        return False
    receiver = (cs.receiver or "").lower()
    method = (cs.method or "").lower()
    # Must have an explicit receiver — bare-function calls without a receiver
    # cannot be classified as stdlib-util without type information.
    if not receiver:
        return False
    # Resolve import-qualified receiver to check against the stdlib table.
    if method in {"get", "format", "join", "split", "substring", "tostring",
                  "valueof", "contains", "put", "remove", "size", "isempty"}:
        for mod in _STDLIB_UTIL_MODULES:
            if receiver == mod or receiver.startswith(mod + "."):
                return True
        # If receiver is a non-request variable name and method is .get(),
        # it is almost certainly a collection read, not a network source.
        if method == "get":
            _request_like = {"request", "response", "req", "res", "httprequest",
                             "httpresponse", "servletrequest", "exchange",
                             "ctx", "context", "session"}
            if receiver not in _request_like and len(receiver) > 1:
                return True
    return False


def build_taint_paths(indices: list[FileIndex],
                      rule_cwe: dict[str, list[str]],
                      max_targets: int = _DEFAULT_MAX_TARGETS_PER_CALL):
    """Return a fresh SeedPackage populated from the given file indices.

    ``max_targets`` caps how many def-sites an ambiguous callee resolves to; the
    caller threads ``step1.call_graph_max_targets`` here so this seed graph
    matches the s1 / ts_graph builders.
    
    Populates SeedPackage.call_graph_confidence with edge confidence scores:
    - 1.0: same-file call (most precise)
    - 0.9: receiver type resolved via import hints
    - 0.7–0.8: proximity match (shared directory prefix)
    - 0.5: name-only fallback (bare function name match)
    """
    from vvaharness.pipeline.stages.s0_seed import SeedPackage

    # fn_id → list[CallSite] for that function (source + sink hits)
    fn_source_hits: dict[str, list[CallSite]] = defaultdict(list)
    fn_sink_hits:   dict[str, list[CallSite]] = defaultdict(list)
    # fn_id → (file, start_line, end_line)
    fn_meta: dict[str, tuple[str, int, int]] = {}
    fn_display_name: dict[str, str] = {}
    function_signatures: dict[str, dict[str, object]] = {}
    # bare_name → list[fn_id] of definitions with that name (call resolution)
    fn_defs_by_name: dict[str, list[str]] = defaultdict(list)
    # qualified_name (e.g., "ClassName.method_name") → list[fn_id] (dual indexing)
    fn_defs_by_qual: dict[str, list[str]] = defaultdict(list)
    # fn_id → list[bare_name] of called methods (edges)
    # GAP-JAVA-02: interface method → implementing class method fids.
    # Maps "InterfaceName.methodName" → list[fid] for all implementing classes.
    iface_method_to_fids: dict[str, list[str]] = defaultdict(list)
    # fn_id → list[bare_name] of called methods (edges)
    fn_calls_out: dict[str, list[tuple[str, str]]] = defaultdict(list)
    file_index: dict[str, FileIndex] = {}
    assigns_by_fn: dict[str, list] = defaultdict(list)
    returns_by_fn: dict[str, list] = defaultdict(list)
    call_args_by_fn: dict[str, list] = defaultdict(list)
    # Field/container fact indexes
    field_writes_by_fn: dict[str, list] = defaultdict(list)
    field_reads_by_fn: dict[str, list] = defaultdict(list)
    container_writes_by_fn: dict[str, list] = defaultdict(list)

    for idx in indices:
        file_index[idx.file] = idx
        for fd in idx.functions:
            fn_key = getattr(fd, "qnode", "") or (
                f"{fd.class_name}.{fd.name}" if getattr(fd, "class_name", "") else fd.name
            )
            fid = _fn_id(idx.file, fn_key)
            fn_meta[fid] = (idx.file, fd.start_line, fd.end_line)
            fn_display_name[fid] = fd.name
            function_signatures[fid] = {
                "file": idx.file,
                "name": fd.name,
                "qnode": fn_key,
                "class_name": fd.class_name,
                "start_line": fd.start_line,
                "end_line": fd.end_line,
                "parameter_text": getattr(fd, "parameter_text", ""),
                "parameter_names": list(getattr(fd, "parameter_names", ()) or ()),
                "body_text": _bounded_function_body(idx.file, fd.start_line, fd.end_line, file_index),
            }
            # Dual indexing: bare name + qualified name (if class context present)
            fn_defs_by_name[fd.name].append(fid)
            if fd.class_name:  # NEW: If this is a class method
                qual_name = f"{fd.class_name}.{fd.name}"
                fn_defs_by_qual[qual_name].append(fid)
            # GAP-JAVA-02: register this method under all known base class / interface names.
            # Primary path: use the __supertype__:<cls>:<iface> keys emitted by the
            # Java extractor when it parses `implements` / `extends` clauses. These
            # keys give us the exact declared supertypes, so every method on the
            # implementing class is registered under each supertype.method key.
            if fd.class_name and fd.name:
                for imp_local, _imp_fq in (idx.imports or {}).items():
                    if imp_local.startswith(f"__supertype__:{fd.class_name}:"):
                        # key = __supertype__:ConcreteClass:InterfaceName
                        iface_simple = imp_local.split(":")[-1]
                        iface_key = f"{iface_simple}.{fd.name}"
                        if fid not in iface_method_to_fids[iface_key]:
                            iface_method_to_fids[iface_key].append(fid)
                # Fallback heuristic for languages/files that don't emit
                # __supertype__ keys: any import whose simple name != class_name.
                # This retains backward compat while the primary path is preferred.
                supertype_keys = {k for k in (idx.imports or {})
                                  if k.startswith(f"__supertype__:{fd.class_name}:")}
                if not supertype_keys:
                    for imp_local, imp_fq in (idx.imports or {}).items():
                        if (not imp_local.startswith("__")
                                and imp_local != fd.class_name and imp_fq):
                            iface_key = f"{imp_local}.{fd.name}"
                            if fid not in iface_method_to_fids[iface_key]:
                                iface_method_to_fids[iface_key].append(fid)
        for cs in idx.source_hits:
            # Skip test/mock files and stdlib-utility false positives so they
            # don't enter the BFS or inflate the entry-point count.
            if _is_test_file(idx.file) or _is_stdlib_util_source(cs):
                continue
            fid = _fn_id(idx.file, cs.containing_fn)
            fn_source_hits[fid].append(cs)
        for cs in idx.sink_hits:
            fid = _fn_id(idx.file, cs.containing_fn)
            fn_sink_hits[fid].append(cs)
        for a in getattr(idx, "assigns", []) or []:
            fid = _fact_fid(idx.file, getattr(a, "function_qnode", ""))
            assigns_by_fn[fid].append(a)
        for r in getattr(idx, "returns", []) or []:
            fid = _fact_fid(idx.file, getattr(r, "function_qnode", ""))
            returns_by_fn[fid].append(r)
        for c in getattr(idx, "call_args", []) or []:
            fid = _fact_fid(idx.file, getattr(c, "function_qnode", ""))
            call_args_by_fn[fid].append(c)
        # Index field/container facts
        for fw in getattr(idx, "field_writes", []) or []:
            fid = _fact_fid(idx.file, getattr(fw, "function_qnode", ""))
            field_writes_by_fn[fid].append(fw)
        for fr in getattr(idx, "field_reads", []) or []:
            fid = _fact_fid(idx.file, getattr(fr, "function_qnode", ""))
            field_reads_by_fn[fid].append(fr)
        for cw in getattr(idx, "container_writes", []) or []:
            fid = _fact_fid(idx.file, getattr(cw, "function_qnode", ""))
            container_writes_by_fn[fid].append(cw)
        # True call-edge set: every call site in the file, matched or not.
        # This is what makes cross-file BFS actually work.
        for containing_fn, receiver, called_method in idx.call_edges:
            fid = _fn_id(idx.file, containing_fn)
            fn_calls_out[fid].append((receiver, called_method))

    # Build a reusable call-graph artifact from the scanned AST inventory so
    # S1 can build upon S0 output instead of reparsing the same files.
    call_graph: dict[str, set[str]] = defaultdict(set)
    call_graph_confidence: dict[tuple[str, str], float] = {}
    for caller_fid, edges in fn_calls_out.items():
        if caller_fid not in fn_meta:
            continue
        caller_file = fn_meta[caller_fid][0]
        for receiver, called_name in edges:
            for callee_fid in _resolve_called_fids(
                    caller_fid,
                    caller_file,
                    receiver,
                    called_name,
                    fn_defs_by_name,
                fn_defs_by_qual,
                    fn_meta,
                    file_index,
                    max_targets,
                    iface_method_index=iface_method_to_fids,
            ):
                if callee_fid == caller_fid:
                    continue
                call_graph[caller_fid].add(callee_fid)
                # Capture edge confidence for downstream filtering.
                callee_file = fn_meta.get(callee_fid, ("", 0, 0))[0]
                conf = _edge_confidence(
                    caller_fid, callee_fid,
                    caller_file, callee_file,
                    receiver, called_name,
                    file_index, fn_meta,
                )
                call_graph_confidence[(caller_fid, callee_fid)] = conf

    relevant_qnodes: set[str] = set(call_graph.keys())
    for vals in call_graph.values():
        relevant_qnodes.update(vals)
    relevant_qnodes.update(fn_source_hits.keys())
    relevant_qnodes.update(fn_sink_hits.keys())

    call_graph_files: dict[str, list[str]] = defaultdict(list)
    def_spans: dict[str, list[int]] = {}
    for fid in sorted(relevant_qnodes):
        meta = fn_meta.get(fid)
        if not meta:
            continue
        file, start, end = meta
        name = fn_display_name.get(fid, _fid_name(fid))
        call_graph_files[name].append(f"{file}:{start}")
        def_spans[fid] = [start, end]

    entry_points: list[EntryPoint] = []
    unsafe_sinks: list[Sink] = []
    taint_paths: list[list[str]] = []
    taint_evidence: list[TaintEvidencePath] = []
    seen_ep: set[tuple[str, str]] = set()
    seen_sink: set[tuple[str, int, str]] = set()
    seen_path: set[tuple[str, ...]] = set()
    seen_evidence: set[tuple[str, str, tuple[str, ...]]] = set()

    def _path_min_edge_confidence(path_fids: tuple[str, ...]) -> float:
        if len(path_fids) <= 1:
            return 1.0
        confs: list[float] = []
        for i in range(len(path_fids) - 1):
            conf = call_graph_confidence.get((path_fids[i], path_fids[i + 1]))
            if conf is not None:
                confs.append(conf)
        return min(confs) if confs else 0.5

    def _annotate_evidence_confidence(evidence: TaintEvidencePath, conf: float) -> None:
        if evidence.sanitized:
            # Sanitized flows are retained as lower-confidence evidence only.
            conf *= 0.5
        conf = max(0.0, min(1.0, conf))
        note = f"min_edge_confidence={conf:.4f}"
        if evidence.sanitized:
            note += ";sanitized_path"
        extra = getattr(evidence, "__pydantic_extra__", None)
        if isinstance(extra, dict):
            extra["confidence"] = conf
            extra["notes"] = note
            return
        object.__setattr__(evidence, "confidence", conf)
        object.__setattr__(evidence, "notes", note)

    # Emit sinks unconditionally (every hit is worth surfacing).
    # Use containing function identity when available so downstream qnode
    # joins (file::function) align with call_graph nodes built from fn scopes.
    # Keep method-only fallback for module-level calls with no function scope.
    for idx in indices:
        for cs in idx.sink_hits:
            sink_fn = cs.containing_fn or cs.method
            key = (cs.file, cs.line, sink_fn)
            if key in seen_sink:
                continue
            seen_sink.add(key)
            unsafe_sinks.append(Sink(
                file=cs.file, line=cs.line, function=sink_fn,
                snippet=cs.snippet, cwe=[cs.cwe] if cs.cwe else [],
            ))

    # Emit entry points from source hits, skipping test/mock code.
    # Test files routinely call source APIs (e.g. Properties.get, Map.get) on
    # mock return values and would inflate entry-point counts without any
    # reachable path to a sink.
    for idx in indices:
        if _is_test_file(idx.file):
            continue
        for cs in idx.source_hits:
            key = (cs.file, cs.containing_fn or f"<line-{cs.line}>")
            if key in seen_ep:
                continue
            seen_ep.add(key)
            entry_points.append(EntryPoint(
                file=cs.file,
                function=cs.containing_fn or f"<line-{cs.line}>",
                kind=cs.kind or "other",
            ))

    # Intra-procedural paths.
    for fid, srcs in fn_source_hits.items():
        sinks = fn_sink_hits.get(fid, [])
        if not sinks:
            continue
        for s in srcs:
            for k in sinks:
                if not _compatible_taint_pair(s, k):
                    continue
                path_fids = (fid,)
                has_facts = _has_phase1_facts_for_path(
                    path_fids, assigns_by_fn, returns_by_fn, call_args_by_fn)
                evidence = None
                if has_facts:
                    evidence = _build_taint_evidence_for_path(
                        s,
                        k,
                        path_fids,
                        fn_meta,
                        assigns_by_fn,
                        returns_by_fn,
                        call_args_by_fn,
                        fn_defs_by_name,
                        fn_defs_by_qual,
                        file_index,
                        max_targets,
                        field_writes_by_fn=field_writes_by_fn,
                        field_reads_by_fn=field_reads_by_fn,
                        container_writes_by_fn=container_writes_by_fn,
                    )
                    # Fix: don't silently drop when evidence builder fails to
                    # trace the exact symbol path — fall back to positional
                    # evidence (same as the no-facts branch). The source and sink
                    # are in the same function; that structural co-location is
                    # meaningful even without a traced symbol chain.
                    if evidence is None:
                        evidence = TaintEvidencePath(
                            source_ref=f"{s.file}:{s.line}",
                            sink_ref=f"{k.file}:{k.line}",
                            path_funcs=[fid],
                            edges=[],
                            sink_cwe=[k.cwe] if k.cwe else [],
                        )
                else:
                    evidence = TaintEvidencePath(
                        source_ref=f"{s.file}:{s.line}",
                        sink_ref=f"{k.file}:{k.line}",
                        path_funcs=[fid],
                        edges=[],
                        sink_cwe=[k.cwe] if k.cwe else [],
                    )
                _annotate_evidence_confidence(evidence, 1.0)
                hops = (f"{s.file}:{s.line}", f"{k.file}:{k.line}")
                rule_key = (getattr(s, "matched_rule", ""), getattr(k, "matched_rule", ""))
                path_key = hops + rule_key
                if path_key not in seen_path and not evidence.sanitized:
                    seen_path.add(path_key)
                    taint_paths.append(list(hops))
                ev_key = (evidence.source_ref, evidence.sink_ref, tuple(evidence.path_funcs)) + rule_key
                if ev_key not in seen_evidence:
                    seen_evidence.add(ev_key)
                    taint_evidence.append(evidence)

    # Inter-procedural BFS with bounded depth. By default we keep shallow
    # traversal for runtime stability, but selectively allow deeper walks for
    # high-risk source/sink combinations.
    for src_fid, srcs in fn_source_hits.items():
        if src_fid not in fn_meta:
            continue
        src_file, src_fn_start, _ = fn_meta[src_fid]
        deep_mode = any(_is_high_risk(s) for s in srcs)
        max_hops = _HIGH_RISK_INTER_HOPS if deep_mode else _BASE_INTER_HOPS
        # BFS: (fid, path_of_fids)
        q: deque[tuple[str, tuple[str, ...]]] = deque(
            [(src_fid, (src_fid,))])
        visited: set[str] = {src_fid}
        while q:
            cur, path = q.popleft()
            if (len(path) - 1) > max_hops:
                continue
            cur_file = fn_meta.get(cur, ("", 0, 0))[0]
            for receiver, called_name in fn_calls_out.get(cur, ()):
                targets = _resolve_called_fids(
                    cur,
                    cur_file,
                    receiver,
                    called_name,
                    fn_defs_by_name,
                    fn_defs_by_qual,
                    fn_meta,
                    file_index,
                    max_targets,
                    iface_method_index=iface_method_to_fids,
                )
                for next_fid in targets:
                    if next_fid in visited:
                        continue
                    visited.add(next_fid)
                    new_path = (*path, next_fid)
                    q.append((next_fid, new_path))
                    hop_count = len(new_path) - 1
                    if hop_count > max_hops:
                        continue
                    # Emit for every sink in this reached function.
                    for k in fn_sink_hits.get(next_fid, ()):
                        # Selective deepening: only keep >base-hop chains for
                        # high-risk sink candidates.
                        if hop_count > _BASE_INTER_HOPS and not _is_high_risk(k):
                            continue
                        for s in srcs:
                            if not _compatible_taint_pair(s, k):
                                continue
                            has_facts = _has_phase1_facts_for_path(
                                new_path, assigns_by_fn, returns_by_fn, call_args_by_fn)
                            evidence = None
                            if has_facts:
                                evidence = _build_taint_evidence_for_path(
                                    s,
                                    k,
                                    new_path,
                                    fn_meta,
                                    assigns_by_fn,
                                    returns_by_fn,
                                    call_args_by_fn,
                                    fn_defs_by_name,
                                    fn_defs_by_qual,
                                    file_index,
                                    max_targets,
                                    field_writes_by_fn=field_writes_by_fn,
                                    field_reads_by_fn=field_reads_by_fn,
                                    container_writes_by_fn=container_writes_by_fn,
                                )
                                # Fix: fall back to positional evidence when the
                                # symbol-tracing evidence builder cannot complete
                                # the chain. The BFS proved structural reachability;
                                # that alone is worth emitting as a path.
                                if evidence is None:
                                    evidence = TaintEvidencePath(
                                        source_ref=f"{s.file}:{s.line}",
                                        sink_ref=f"{k.file}:{k.line}",
                                        path_funcs=list(new_path),
                                        edges=[],
                                        sink_cwe=[k.cwe] if k.cwe else [],
                                    )
                            else:
                                evidence = TaintEvidencePath(
                                    source_ref=f"{s.file}:{s.line}",
                                    sink_ref=f"{k.file}:{k.line}",
                                    path_funcs=list(new_path),
                                    edges=[],
                                    sink_cwe=[k.cwe] if k.cwe else [],
                                )
                            _annotate_evidence_confidence(
                                evidence,
                                _path_min_edge_confidence(new_path),
                            )
                            hop_list = [f"{s.file}:{s.line}"]
                            for fid in new_path[1:]:
                                fmeta = fn_meta.get(fid)
                                if fmeta:
                                    hop_list.append(f"{fmeta[0]}:{fmeta[1]}")
                            hop_list.append(f"{k.file}:{k.line}")
                            rule_key = (getattr(s, "matched_rule", ""), getattr(k, "matched_rule", ""))
                            key_t = tuple(hop_list) + rule_key
                            if key_t in seen_path:
                                continue
                            if not evidence.sanitized:
                                seen_path.add(key_t)
                                taint_paths.append(hop_list)
                            ev_key = (evidence.source_ref, evidence.sink_ref, tuple(evidence.path_funcs)) + rule_key
                            if ev_key not in seen_evidence:
                                seen_evidence.add(ev_key)
                                taint_evidence.append(evidence)

    # Bridge uncertainty edges from scanner-level cross-language handoff signals.
    bridge_uncertainty: list[dict[str, object]] = []
    for idx in indices:
        for raw in getattr(idx, "bridge_signals", []) or []:
            if not isinstance(raw, dict):
                continue
            try:
                edge = BridgeUncertaintyEdge.model_validate(raw)
            except Exception:
                continue
            bridge_uncertainty.append(edge.model_dump())

    # Apply Iterations A & G: Confidence-weighted path budgeting and global cap.
    # This reduces token cost by filtering low-confidence paths and capping
    # the total paths to prevent quadratic path explosion on large repos.
    taint_paths, uncertainty_edges = _filter_paths_by_budget(
        taint_paths,
        fn_source_hits,
        fn_sink_hits,
        fn_meta,
        rule_cwe,
    )
    if bridge_uncertainty:
        uncertainty_edges.extend(bridge_uncertainty)

    # Build a flat symbol table once for the entire scan.
    symbol_table = _build_symbol_table(indices)

    # 3a. Path-sensitive taint via CFG walking.
    # Emits ConditionTaintEdge-carrying TaintEvidencePath entries for functions
    # that have per-block CFGs attached to their FileIndex.
    try:
        cfg_evidence = _solve_with_cfgs(indices, symbol_table, assigns_by_fn)
        for ep in cfg_evidence:
            ev_key = (ep.source_ref, ep.sink_ref, tuple(ep.path_funcs))
            if ev_key not in seen_evidence:
                seen_evidence.add(ev_key)
                taint_evidence.append(ep)
    except Exception:
        _log.debug("CFG walk failed — continuing without CFG evidence",
                   exc_info=True)

    # 3b. Reflection / dynamic-dispatch taint propagation.
    # For every tainted function for which we have reflection facts, resolve
    # dynamic call targets and emit speculative ReflectionTaintEdge entries.
    try:
        for idx in indices:
            rf_facts: list[ReflectionFact] = getattr(idx, "reflection_facts", []) or []
            if not rf_facts:
                continue
            language = getattr(idx, "language", "python") or "python"
            # Determine which functions in this file are on a tainted path.
            tainted_fids: set[str] = set()
            for ep in taint_evidence:
                for pfid in ep.path_funcs:
                    if pfid.startswith(idx.file):
                        tainted_fids.add(pfid)
            if not tainted_fids:
                continue
            for fid in tainted_fids:
                # Seed a minimal taint state from tainted locals known to exist
                # in any evidence path for this function.
                ts: dict[str, bool] = {}
                for ep in taint_evidence:
                    if fid not in ep.path_funcs:
                        continue
                    for edge in ep.edges:
                        dst_sym = getattr(getattr(edge, "dst", None), "symbol", None)
                        if dst_sym:
                            ts[dst_sym] = True
                if not ts:
                    continue
                updated_ts, refl_edges = _apply_reflection_to_taint(
                    ts, rf_facts, symbol_table, language, fid
                )
                if not refl_edges:
                    continue
                # Merge reflection edges into an existing evidence path or
                # create a new one tagged to this function.
                merged = False
                for ep in taint_evidence:
                    if fid in ep.path_funcs:
                        ep.edges.extend(refl_edges)
                        merged = True
                        break
                if not merged:
                    refl_ep = TaintEvidencePath(
                        source_ref=f"{idx.file}::{fid}",
                        sink_ref=f"{idx.file}::{fid}",
                        path_funcs=[fid],
                        edges=list(refl_edges),
                        sink_cwe=[],
                        sanitized=False,
                    )
                    ev_key = (refl_ep.source_ref, refl_ep.sink_ref, tuple(refl_ep.path_funcs))
                    if ev_key not in seen_evidence:
                        seen_evidence.add(ev_key)
                        taint_evidence.append(refl_ep)
                    # Also update callee presence: newly-tainted reflection
                    # targets may expand fn_source_hits for downstream stages.
                    for edge in refl_edges:
                        target_qnode = getattr(getattr(edge, "dst", None), "qnode", "")
                        if target_qnode and target_qnode in fn_sink_hits:
                            # A reflection target directly hits a known sink.
                            for s_cs in fn_source_hits.get(fid, []):
                                for k_cs in fn_sink_hits.get(target_qnode, []):
                                    if not _compatible_taint_pair(s_cs, k_cs):
                                        continue
                                    hop = (f"{s_cs.file}:{s_cs.line}",
                                           f"{k_cs.file}:{k_cs.line}")
                                    if tuple(hop) not in seen_path:
                                        seen_path.add(tuple(hop))
                                        taint_paths.append(list(hop))
    except Exception:
        _log.debug("Reflection resolution failed — continuing without reflection edges",
                   exc_info=True)

    # After base taint solving, integrate framework detection results.
    try:
        # Build framework symbol table: function_qnode → [tainted parameter names]
        framework_symbol_table = _build_framework_symbol_table(indices)
        
        # Emit framework entry points (synthetic sources from annotations/bindings)
        framework_entry_points = _emit_framework_entry_points(indices)
        for fep in framework_entry_points:
            key = (fep.file, fep.function)
            if key not in seen_ep:
                seen_ep.add(key)
                entry_points.append(fep)
        
        # Apply response dataflow enhancement to evidence paths
        # This adds response sink CWE information for injection vulnerabilities
        response_dataflows = []
        for idx in indices:
            response_dataflows.extend(getattr(idx, "response_dataflow", []) or [])
        
        if response_dataflows:
            taint_evidence = _apply_response_dataflow(taint_evidence, response_dataflows)
    except Exception:
        _log.debug("Framework-level taint solving failed — continuing without framework results",
                   exc_info=True)

    seed_pkg = SeedPackage(
        entry_points=entry_points,
        unsafe_sinks=unsafe_sinks,
        taint_paths=taint_paths,
        taint_evidence=taint_evidence,
        rule_cwe=rule_cwe,
        call_graph={k: sorted(v) for k, v in call_graph.items() if v},
        call_graph_files={k: sorted(v) for k, v in call_graph_files.items() if v},
        def_spans=def_spans,
        function_signatures=function_signatures,
        call_graph_confidence=call_graph_confidence,
    )
    object.__setattr__(seed_pkg, "uncertainty_edges", uncertainty_edges)
    return seed_pkg


# NOTE — improvement path:
#   1. Add type inference for Python (via imported name resolution) to bind
#      variable receivers to their originating class — this lifts the "skip
#      variable receivers" limitation in _scan._match_call.
#   2. Add Java/JS/Go/C# plugins in _scan.py using the same LangPlugin shape.
