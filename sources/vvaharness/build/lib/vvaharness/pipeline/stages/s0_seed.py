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
Step 0 — Static seed.

Tree-sitter-backed source→sink seeding that emits ``EntryPoint`` / ``Sink``
lists plus pre-computed source→sink taint paths in the same shapes s1 already
populates on ``ContextPackage``.

The default, full, and taint-first profiles enable this stage. The taint profile also
sets s1 to ``mode: gap_fill``: a sufficiently strong seed skips agentic S1,
while sparse coverage on a large application escalates back to full discovery.
Together with ``step3.catchall_mode: reachable_only``, that can reduce later
analysis volume without treating a weak seed as complete coverage.

This stage is profile-controlled and runs when ``cfg.step0.enabled`` is truthy;
``default.yaml``, ``full.yaml`` and ``taint.yaml`` enable it, while ``sdk.yaml``
omits ``step0`` and inherits the disabled built-in default. In the default
``rules`` mode, missing, invalid, or inapplicable source/sink rule inputs
produce an empty seed. ``llm`` mode can supplement sparse model-produced specs
with deterministic observed-call heuristics. S0 degrades to an empty seed on
ordinary errors, but halt errors — authentication (VVAH-E001) or proxy/TLS
(VVAH-E002) — deliberately propagate and end the scan; see ``run()`` below.
"""
from __future__ import annotations

import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from vvaharness.models import EntryPoint, Sink, TaintEvidencePath

log = logging.getLogger(__name__)
from vvaharness.lang.hints import detect_languages
from vvaharness.pipeline.stages.s1_preprocess import _walk_repo
from vvaharness.rules import RULES_DIR
from vvaharness.rules.families import VVAH_LANGUAGES, canonical_lang

# ruleId / message tokens → EntryPoint.kind. Anything unmatched → "other";
# the model validator (_EP_KIND_ALIAS) further normalises.
_KIND_HINTS: dict[str, str] = {
    "http": "network", "request": "network", "route": "network",
    "controller": "network", "servlet": "network", "handler": "network",
    "graphql": "network", "grpc": "network", "websocket": "network",
    "queue": "ipc", "kafka": "ipc", "jms": "ipc", "amqp": "ipc",
    "argv": "cli", "stdin": "cli", "flag": "cli",
    "env": "file", "config": "file", "fileread": "file",
    "deseriali": "deserialization", "unmarshal": "deserialization",
    "pickle": "deserialization", "yaml-load": "deserialization",
}


def _filter_step0_languages(langs: list[str], cfg) -> list[str]:
    """Optionally constrain Step-0 engines to a language allowlist.

    Config: step0.languages: [python, java, csharp, ...]
    Aliases accepted via the shared table, e.g. dotnet/c# -> csharp,
    js -> javascript, ts -> typescript, c/cpp/c++ -> c-cpp, golang -> go.
    An entry that resolves to no known language is reported loudly rather than
    silently dropped.
    """
    step0 = getattr(cfg, "step0", None)
    raw = getattr(step0, "languages", None) if step0 is not None else None
    if not raw:
        return langs
    allow: set[str] = set()
    for x in raw:
        if not str(x).strip():
            continue
        canon = canonical_lang(x)
        allow.add(canon)
        # An operator-set language that resolves to no known vvaharness
        # language is almost certainly a typo or unsupported spelling. Surface
        # it loudly instead of silently narrowing scan scope
        # (docs/security.md:188 warns against silent coverage narrowing).
        if canon not in VVAH_LANGUAGES:
            print(f"  [s0] WARNING: step0.languages entry {x!r} is not a "
                  f"recognized language or alias; it will not match any file",
                  file=sys.stderr)
    return [l for l in langs if l in allow]


@dataclass
class SeedPackage:
    """Output of s0. Merged into ``ContextPackage`` by s1 when present."""
    entry_points: list[EntryPoint] = field(default_factory=list)
    framework_entry_points: list[EntryPoint] = field(default_factory=list)
    unsafe_sinks: list[Sink] = field(default_factory=list)
    # Pre-computed source→sink paths from the static graph: each item is a list
    # of "rel/path:line" hops, first = source, last = sink. Threaded through
    # s1 → ContextPackage.seed_taint_paths → s3._reachable_files so a file
    # the seed placed on a taint path is never dropped by
    # step3.catchall_mode=reachable_only, even when the call-graph missed the
    # edge (reflection/DI). s3 still runs its own BFS for chunk construction.
    taint_paths: list[list[str]] = field(default_factory=list)
    taint_evidence: list[TaintEvidencePath] = field(default_factory=list)
    # ruleId → CWE tags. Diagnostic only in the s0 checkpoint — CWE tags now
    # travel per-sink on ``Sink.cwe`` (populated below from this map) and reach
    # the s4 confirm/refute prompt via Chunk.sink_cwe.
    rule_cwe: dict[str, list[str]] = field(default_factory=dict)
    # Call-graph artifacts produced by the tree-sitter S0 engine. S1 can reuse
    # these directly instead of
    # rebuilding the same structures.
    call_graph: dict[str, list[str]] = field(default_factory=dict)
    call_graph_files: dict[str, list[str]] = field(default_factory=dict)
    def_spans: dict[str, list[int]] = field(default_factory=dict)
    function_signatures: dict[str, dict[str, object]] = field(default_factory=dict)
    uncertainty_edges: list[dict] = field(default_factory=list)
    call_graph_confidence: dict[tuple[str, str], float] = field(default_factory=dict)
    sarif_path: Path | None = None
    engine: str = "callgraph"
    languages: list[str] = field(default_factory=list)
    # Full recursive repo walk performed by s0, threaded to s1 so the tree is
    # walked (and stat'd) only once per scan. ``excluded`` carries the same
    # exclusion report s1 would otherwise recompute, so coverage reporting is
    # unaffected. Both are empty when s0 is disabled, in which case s1 falls
    # back to its own walk.
    all_files: list[str] = field(default_factory=list)
    excluded: dict = field(default_factory=dict)

    def __post_init__(self):
        """Merge framework entry points into entry_points and log counts."""
        # Count framework entries by kind before merging
        framework_count = len(self.framework_entry_points)
        reachability_count = len(self.entry_points)
        
        # Merge framework entries into the main entry_points list
        if self.framework_entry_points:
            self.entry_points.extend(self.framework_entry_points)
            log.debug(
                f"[s0] merged {framework_count} framework entry points with "
                f"{reachability_count} reachability entries; "
                f"total entry_points={len(self.entry_points)}"
            )
        # Keep framework_entry_points for reference but it's now duplicated in entry_points

    def __bool__(self) -> bool:
        return bool(
            self.entry_points
            or self.unsafe_sinks
            or self.taint_paths
            or self.taint_evidence
            or self.call_graph
            or self.call_graph_files
            or self.def_spans
            or self.function_signatures
            or self.uncertainty_edges
            or self.framework_entry_points
        )


def run(repo_root: str, cfg, ckpt_dir: Path | None = None) -> SeedPackage:
    """Execute the static seed.

    Degrades rather than fails on ordinary errors: returns an empty SeedPackage
    so later stages continue. The ONE exception is a halt error —
    authentication (VVAH-E001) or proxy/TLS (VVAH-E002) — which the callgraph
    engine deliberately re-raises and this function deliberately does not
    catch. Those will hit every later stage identically, so degrading here
    would burn S1-S9 against a dead credential and report the scan as merely
    "seedless".

    Consequence worth knowing: the s0 checkpoint is saved AFTER the work, so a
    halt error escaping here leaves no s0 checkpoint. The credential
    remediation text suggests `--resume`; on this path that re-runs s0 from
    scratch rather than resuming past it. That is cheap (s0 is the first stage)
    but it is not a no-op.

    Do not "fix" this by wrapping the body in a blanket ``except Exception`` —
    that re-swallows the halt error one frame above the guard and restores the
    silent-degradation bug the guard exists to prevent.
    """
    if not getattr(getattr(cfg, "step0", None), "enabled", False):
        log.debug("s0/seed: disabled via config")
        return SeedPackage()

    log.info("s0/seed: starting AST-based seed generation for %s", repo_root)
    all_files, excluded = _walk_repo(repo_root, cfg)
    in_scope = set(all_files)
    langs = _filter_step0_languages(detect_languages(all_files), cfg)
    log.info("s0/seed: file walk complete - total=%d excluded=%d in_scope=%d langs=%s",
             len(all_files) + len(excluded), len(excluded), len(in_scope), langs)
    # Tree-sitter-native BFS seeder. Rules mode consumes configured source/sink
    # artifacts; LLM mode may add deterministic observed-call heuristics. It
    # emits a SeedPackage without going through SARIF.
    from vvaharness.pipeline.stages.callgraph_engine import (
        run as _run_callgraph,
    )
    seed = _run_callgraph(repo_root, cfg, in_scope, langs)
    # Hand s1 the walk we just did so it need not re-walk the whole repo.
    seed.all_files = all_files
    seed.excluded = excluded
    log.info("s0/seed: seed generation complete - engine=%s entry_points=%d sinks=%d paths=%d",
             seed.engine, len(seed.entry_points), len(seed.unsafe_sinks), len(seed.taint_paths))
    return seed


def _resolve_rulepacks(cfg, langs: list[str], rules_dir: Path | None = None) -> list[str]:
    """Resolve Semgrep rulepacks in offline-only mode.

    Compatibility helper retained for tests and tooling that validate the old
    rulepack resolution contract.
    """
    base_rules = Path(rules_dir or RULES_DIR)
    packs: list[str] = [str(base_rules / "sources.yaml")]

    step0 = getattr(cfg, "step0", None)
    repo = getattr(step0, "semgrep_rules_repo", None) if step0 is not None else None
    if repo:
        repo_p = Path(repo)
        if not repo_p.is_dir():
            print(f"  [s0] WARN: semgrep_rules_repo {repo!r} does not exist; "
                  "degrading to vendored rules only", file=sys.stderr)
        else:
            lang_dirs = {
                "cpp": "c",
                "c-cpp": "c",
            }
            for lang in langs:
                sub = lang_dirs.get(lang, lang)
                p = repo_p / sub
                if p.is_dir():
                    packs.append(str(p))

    for rp in getattr(step0, "rulepacks", []) if step0 is not None else []:
        s = str(rp).strip()
        if not s:
            continue
        if s.startswith("p/") or s.startswith("r/"):
            print(f"  [s0] WARN: offline-only mode rejects registry rulepack "
                  f"reference {s!r}", file=sys.stderr)
            continue
        packs.append(s)

    # Stable de-dup preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for p in packs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _parse_sarif(sarif: dict, in_scope: set[str]) -> SeedPackage:
    """Parse a minimal SARIF payload into SeedPackage (compat shim).

    Kept for tests that validate CWE-tag propagation from driver.rules.
    """
    seed = SeedPackage()
    cwe_rx = re.compile(r"^cwe-", re.IGNORECASE)

    for run in sarif.get("runs", []) or []:
        rule_cwe: dict[str, list[str]] = {}
        rules = (((run.get("tool") or {}).get("driver") or {}).get("rules") or [])
        for r in rules:
            rid = str(r.get("id") or "").strip()
            if not rid:
                continue
            tags = (((r.get("properties") or {}).get("tags")) or [])
            keep = [str(t) for t in tags if isinstance(t, str) and cwe_rx.match(t.strip())]
            if keep:
                rule_cwe[rid] = keep
        seed.rule_cwe.update(rule_cwe)

        for res in run.get("results", []) or []:
            rid = str(res.get("ruleId") or "").strip()
            locs = res.get("locations") or []
            if not locs:
                continue
            phy = ((locs[0] or {}).get("physicalLocation") or {})
            rel = str(((phy.get("artifactLocation") or {}).get("uri") or "")).strip()
            if not rel or rel not in in_scope:
                continue
            region = phy.get("region") or {}
            line = int(region.get("startLine") or 0)
            snippet = str(((region.get("snippet") or {}).get("text") or ""))
            message = str(((res.get("message") or {}).get("text") or "")).strip()
            seed.unsafe_sinks.append(Sink(
                file=rel,
                line=line,
                function=message or "unknown",
                snippet=snippet,
                cwe=seed.rule_cwe.get(rid, []),
            ))
    return seed
