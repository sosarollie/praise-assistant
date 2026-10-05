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

"""Tree-sitter-native call-graph seed engine.

Used by the S0 wrapper's default ``callgraph`` engine. In ``rules`` mode it
loads source/sink YAML from ``step0.sources_yaml`` / ``step0.sinks_yaml`` or
the conventional generated filenames under ``vvaharness/rules/``. Those rule
files are not bundled in this revision, so rules mode returns an empty seed
unless the operator supplies them. It parses in-scope source with tree-sitter,
matches source and sink call sites, builds a static call graph, and emits the
``SeedPackage`` consumed by later stages.

Scope (v1):
        * Python, Java, JavaScript, TypeScript, Go, C# — parser plugins wired.
        * Other languages — plugin architecture is in place; `_scan.py`'s
            ``LANG_PLUGINS`` registry can be extended per language.

Path finding includes intra-procedural pairs and bounded inter-procedural BFS
(three hops normally, up to five for high-risk source/sink candidates). The
SeedPackage is a *seed*, not the final answer; downstream stages handle the
remaining discovery and confirmation work.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

_log = logging.getLogger(__name__)

from vvaharness.backends.harness.contract.errors import is_halt_error
from vvaharness.pipeline.stages.callgraph_engine._annotator import detect_specs
from vvaharness.pipeline.stages.callgraph_engine._graph import (
    build_taint_paths,
)
from vvaharness.pipeline.stages.callgraph_engine._rules import MatchSpec, load_rulepacks
from vvaharness.pipeline.stages.callgraph_engine._scan import (
    LANG_PLUGINS,
    FileIndex,
    _build_spec_index,
    scan_file,
)
from vvaharness.util.counters import COUNTERS


def run(repo_root: str, cfg, in_scope: set[str], langs: list[str]):
    """Public entry point invoked by s0_seed.run() when engine == 'callgraph'.

    Returns a SeedPackage, degrading to an empty package (or falling back
    from llm detection to rules mode) on ordinary failure so later pipeline
    stages can continue — with ONE deliberate exception: halt errors
    (VVAH-E001 authentication, VVAH-E002 proxy/TLS) are re-raised by the
    ``is_halt_error`` guard below. Those failures mean every later model call
    in the scan will fail the same way, so "degrading" here would silently
    downgrade an llm-detection scan to rules mode and spend the rest of the
    run on a dead credential or broken proxy. Do not restore the old "never
    raises" contract by wrapping the body in a blanket ``except Exception`` —
    re-swallowing the halt error is exactly the regression the guard exists
    to prevent."""
    # Deferred import keeps module import cost minimal until S0 actually runs.
    from vvaharness.pipeline.stages.s0_seed import SeedPackage

    step0 = getattr(cfg, "step0", None)
    detection_mode = str(getattr(step0, "callgraph_detection", "rules")
                         or "rules").strip().lower()
    if detection_mode not in {"rules", "llm"}:
        print(f"  [s0/callgraph] WARN: unknown step0.callgraph_detection="
              f"{detection_mode!r}; defaulting to 'rules'", file=sys.stderr)
        detection_mode = "rules"

    supported = set(LANG_PLUGINS.keys())
    active_langs = [l for l in langs if l in supported]
    if not active_langs:
        print(f"  [s0/callgraph] no language plugins for {langs!r} "
              f"(supported: {sorted(supported)!r}) — returning empty seed",
              file=sys.stderr)
        _log.warning("callgraph: no supported languages %s", langs)
        return SeedPackage(engine="callgraph", languages=langs)

    _log.info("callgraph: starting AST seed with languages=%s", active_langs)

    rules_dir = Path(__file__).resolve().parents[3] / "rules"
    source_specs: list[MatchSpec] = []
    sink_specs: list[MatchSpec] = []
    rule_cwe: dict[str, list[str]] = {}
    file_indices: list[FileIndex] = []
    used_llm_specs = False

    if detection_mode == "llm":
        observed = _scan_repo(
            repo_root,
            in_scope,
            source_specs=[],
            sink_specs=[],
            keep_predicate=lambda idx: bool(idx.functions or idx.observed_calls),
            collect_observed=True,
        )
        if not observed:
            print("  [s0/callgraph] WARN: llm detection found no parseable files; "
                  "falling back to configured rules YAML.", file=sys.stderr)
            detection_mode = "rules"
        else:
            try:
                source_specs, sink_specs, rule_cwe = detect_specs(
                    observed, active_langs, cfg, repo_root=repo_root)
                used_llm_specs = bool(source_specs or sink_specs)
                if not used_llm_specs:
                    print("  [s0/callgraph] WARN: llm detection produced 0 specs; "
                          "falling back to configured rules YAML.",
                          file=sys.stderr)
                    detection_mode = "rules"
            except Exception as e:  # noqa: BLE001
                if is_halt_error(e):
                    raise
                print("  [s0/callgraph] WARN: llm detection failed "
                      f"({e}); falling back to configured rules YAML.",
                      file=sys.stderr)
                detection_mode = "rules"

    # Resolve rule files. Defaults point at the two artifacts build_kb.py
    # emits — see rules/sources.generated.yaml + rules/sinks.generated.yaml.
    if detection_mode == "rules":
        sources_path = Path(
            getattr(step0, "sources_yaml", None)
            or (rules_dir / "sources.generated.yaml")
        )
        sinks_path = Path(
            getattr(step0, "sinks_yaml", None)
            or (rules_dir / "sinks.generated.yaml")
        )
        if not sources_path.is_file() and not sinks_path.is_file():
            print(f"  [s0/callgraph] neither {sources_path.name} nor "
                  f"{sinks_path.name} found under {rules_dir} — no rules to load; "
                  f"returning empty seed", file=sys.stderr)
            return SeedPackage(engine="callgraph", languages=langs)

        try:
            source_specs, sink_specs, rule_cwe = load_rulepacks(
                sources_path if sources_path.is_file() else None,
                sinks_path   if sinks_path.is_file()   else None,
                active_langs,
            )
        except Exception as e:                                # noqa: BLE001
            print(f"  [s0/callgraph] rule load failed: {e} — returning empty seed",
                  file=sys.stderr)
            return SeedPackage(engine="callgraph", languages=langs)

    if not source_specs and not sink_specs:
        print(f"  [s0/callgraph] 0 rules applicable to {active_langs!r} — "
              f"returning empty seed", file=sys.stderr)
        _log.error("callgraph: no applicable rules for languages %s", active_langs)
        return SeedPackage(engine="callgraph", languages=active_langs)

    print(f"  [s0/callgraph] {len(source_specs)} source specs, "
          f"{len(sink_specs)} sink specs, {len(active_langs)} langs "
          f"({', '.join(sorted(active_langs))})", file=sys.stderr)
    _log.info("callgraph: rules loaded - sources=%d sinks=%d langs=%s",
              len(source_specs), len(sink_specs), active_langs)

    # Per-file scan → list[FileIndex]. Skip files whose language has no plugin.
    file_indices = _scan_repo(
        repo_root,
        in_scope,
        source_specs=source_specs,
        sink_specs=sink_specs,
        keep_predicate=lambda idx: bool(idx.source_hits or idx.sink_hits or idx.functions),
    )
    _log.info("callgraph: AST scan completed - files_indexed=%d scope=%d",
              len(file_indices), len(in_scope))

    if not file_indices:
        if used_llm_specs:
            print("  [s0/callgraph] llm specs produced 0 matched files — "
                  "returning empty seed", file=sys.stderr)
        else:
            print("  [s0/callgraph] 0 files with source/sink matches — "
                  "returning empty seed", file=sys.stderr)
        return SeedPackage(engine="callgraph", languages=active_langs,
                           rule_cwe=rule_cwe)

    try:
        # Prefer step0.call_graph_max_targets; fall back to step1's value so
        # both stages use the same fanout cap when only step1 is configured.
        _s0 = getattr(cfg, "step0", None)
        _s1 = getattr(cfg, "step1", None)
        max_targets = int(
            getattr(_s0, "call_graph_max_targets", None)
            or getattr(_s1, "call_graph_max_targets", 3)
            or 3
        )
        seed = build_taint_paths(file_indices, rule_cwe, max_targets)
    except Exception as e:                                # noqa: BLE001
        print(f"  [s0/callgraph] taint-path build failed: {e} — "
              f"returning empty seed", file=sys.stderr)
        return SeedPackage(engine="callgraph", languages=active_langs,
                           rule_cwe=rule_cwe)
    seed.engine = "callgraph"
    seed.languages = active_langs
    print(f"  [s0/callgraph] seed: {len(seed.entry_points)} entry-points, "
          f"{len(seed.unsafe_sinks)} sinks, {len(seed.taint_paths)} taint "
          f"paths ({len(rule_cwe)} rules CWE-tagged)", file=sys.stderr)
    _log.info("callgraph: seed generated - entry_points=%d sinks=%d taint_paths=%d cwe_rules=%d",
              len(seed.entry_points), len(seed.unsafe_sinks), len(seed.taint_paths), len(rule_cwe))
    return seed


def _lang_of(rel: str) -> str | None:
    """Extension → vvaharness language key. Duplicates a slice of
    vvaharness.lang.hints.EXT_TO_LANG to keep the callgraph engine
    self-contained and cheap to import."""
    from vvaharness.lang.hints import EXT_TO_LANG
    ext = Path(rel).suffix.lower()
    return EXT_TO_LANG.get(ext)


def _scan_repo(
    repo_root: str,
    in_scope: set[str],
    source_specs: list[MatchSpec],
    sink_specs: list[MatchSpec],
    keep_predicate,
    collect_observed: bool = False,
) -> list[FileIndex]:
    """Scan in-scope files and keep indices selected by keep_predicate."""
    out: list[FileIndex] = []
    repo_root_p = Path(repo_root)
    # Build the spec indexes once for the whole scan, not per call site.
    source_index = _build_spec_index(source_specs)
    sink_index = _build_spec_index(sink_specs)
    
    total_files = 0
    parsed_files = 0
    files_with_sources = 0
    files_with_sinks = 0
    total_functions = 0
    
    for rel in sorted(in_scope):
        abs_p = repo_root_p / rel
        if not abs_p.is_file():
            continue
        total_files += 1
        lang = _lang_of(rel)
        if not lang or lang not in LANG_PLUGINS:
            continue
        try:
            idx = scan_file(abs_p, rel, lang, source_specs, sink_specs,
                            collect_observed=collect_observed,
                            source_index=source_index, sink_index=sink_index)
            if idx is not None:
                parsed_files += 1
                if idx.source_hits:
                    files_with_sources += 1
                if idx.sink_hits:
                    files_with_sinks += 1
                if idx.functions:
                    total_functions += len(idx.functions)
        except Exception as e:  # noqa: BLE001
            # Outer safety net: a malformed file must never crash the scan.
            # Reaching here drops the WHOLE file from the seed index —
            # genuine coverage loss — so it is counted (the manifest dumps
            # COUNTERS in full; note the report's own table renders only a
            # whitelisted subset that excludes this one) and logged at warning,
            # and the
            # message says "file dropped" to distinguish it from the narrower
            # per-fact / reflection-extraction containment inside scan_file,
            # which keeps the file. A ReflectionFact schema mismatch once
            # surfaced here and silently evicted the files holding a JS
            # app's eval() sinks; fact-level failures no longer propagate
            # this far.
            COUNTERS.bump("s0_files_dropped_scan_error")
            _log.warning("callgraph: AST scan failed for file=%s: %s", rel, e)
            print(f"  [s0/callgraph] scan failed for {rel}: {e} — "
                  f"whole file dropped from seed index", file=sys.stderr)
            continue
        if idx is not None and keep_predicate(idx):
            out.append(idx)
    
    _log.info("callgraph: AST parsing complete - total_files=%d parsed=%d "
              "with_sources=%d with_sinks=%d total_functions=%d",
              total_files, parsed_files, files_with_sources, files_with_sinks, total_functions)
    return out
