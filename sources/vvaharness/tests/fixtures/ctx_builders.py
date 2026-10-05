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

"""ContextPackage builders.

These three fixtures are NOT file trees — they are ``ContextPackage`` objects
built directly in memory, the same convention as ``_ctx_with(...)`` in
``tests/test_s3_decompose.py`` (def at `~:94`). Each reproduces a scan-quality problem
that cannot be reproduced from files on disk without actually running the
callgraph/AST preprocessing pass (entry-point ``kind``, ``reachable_from_unauth``,
and the AST frontier are all fields that pass *produces*, not filesystem facts).

``make_ctx(**overrides)`` is the general-purpose builder every other builder
here is written in terms of, so a test that needs a variant of one of these
three canonical shapes can call it directly instead of hand-rolling a whole
``ContextPackage(...)`` literal.

Every field used below exists on ``vvaharness.models`` as verified by reading
the class bodies before writing this module. Some fields that a future file-id
inventory or sharded-chunk feature would need — a path-to-id map on
``ContextPackage``, an id-based files list or a shard identifier on ``Chunk``
— do not exist on those classes yet. None of these three fixtures need them.
"""
from __future__ import annotations

from vvaharness.models import (
    ContextPackage,
    EntryPoint,
    Sink,
    TaintEvidencePath,
)

DEFAULT_REPO_ROOT = "/nonexistent-repo"


def make_ctx(**overrides) -> ContextPackage:
    """Minimal-but-valid ``ContextPackage``, override any field by name.

    Mirrors ``_ctx_with(...)`` in ``tests/test_s3_decompose.py`` but with no
    baked-in taint-path assumptions, so callers compose whatever shape they
    need. Only fields with sensible universal defaults are pre-filled.
    """
    defaults: dict = dict(
        repo_root=DEFAULT_REPO_ROOT,
        language="python",
        all_files=[],
        entry_points=[],
        unsafe_sinks=[],
        call_graph={},
    )
    defaults.update(overrides)
    return ContextPackage(**defaults)


def make_framework_eps_ctx(n: int = 300) -> ContextPackage:
    """300 ``framework``-kind, unauthenticated-reachable entry points.

    ``s2_threatmodel._repo_kind`` (def at `~s2_threatmodel.py:562`) decides
    whether a repository is a web API from its entry-point kinds. It used to
    test ``kind == "network"`` only, so a repository whose entry points are
    all agent-classified ``framework`` (e.g. Spring
    ``@RequestMapping``/Django URL-conf handlers reported by an LLM-driven
    callgraph mapper rather than the deterministic ``network`` heuristic)
    got zero web-api signal from entry points at all, even though every one
    of them is reachable from an unauthenticated actor. ``_repo_kind`` now
    accepts both kinds (``any(k in ("network", "framework") ...)``); this
    fixture is the shape that regresses if that ever narrows back. Combine
    with ``repo_nested_manifests`` (manifest one directory down, so the
    manifest-text web-api signal is *also* absent, leaving entry-point kind
    as the only signal) to reproduce the original failure mode: a repository
    that is entirely web-facing being classified as a plain library and
    given the wrong, much smaller, default threat baseline.
    """
    eps = [
        EntryPoint(
            file=f"src/svc_{i:03d}.py",
            function=f"handle_{i:03d}",
            kind="framework",
            reachable_from_unauth=True,
        )
        for i in range(n)
    ]
    return make_ctx(all_files=[e.file for e in eps], entry_points=eps)


def make_taint_multi_ctx() -> ContextPackage:
    """One file, three seeded functions, as ``TaintEvidencePath`` entries.

    ``_seed_paths_for_entry`` (def at `~s3_decompose.py:1054`) used to match
    seed evidence to an entry point by FILE only —
    ``if source_file != ep.file: continue`` was the sole gate, never the
    function. With three entry points in the same file and three evidence
    entries also anchored to that file (one per function), every entry point
    pulled in every evidence entry — up to 3x more taint hits than the 3
    distinct (function, sink) pairs actually seeded, i.e. near-duplicate
    chunks instead of one chunk per function. The match is now also keyed on
    the function when the evidence's qnode-shaped source ref
    (``"file::func"``) names one, which collapses this fixture back down to
    exactly one chunk per seeded function — the fixture's refs are all
    qnode-shaped precisely so that dropping the function key regresses to
    the 3x duplication. (Legacy ``"file:line"`` refs carry no function name
    and still fall back to file-only matching.)
    """
    file = "app/handlers.py"
    sink_file = "app/db.py"
    functions = ["func_a", "func_b", "func_c"]

    entry_points = [
        EntryPoint(file=file, function=fn, kind="network", reachable_from_unauth=True)
        for fn in functions
    ]
    unsafe_sinks = [
        Sink(file=sink_file, line=(i + 1) * 10, function=f"sink_{fn}", cwe=["CWE-89"])
        for i, fn in enumerate(functions)
    ]
    seed_taint_evidence = [
        TaintEvidencePath(
            source_ref=f"{file}::{fn}",
            sink_ref=f"{sink_file}:{(i + 1) * 10}",
            path_funcs=[f"{file}::{fn}", f"{sink_file}::sink_{fn}"],
            sink_cwe=["CWE-89"],
        )
        for i, fn in enumerate(functions)
    ]
    return make_ctx(
        all_files=[file, sink_file],
        entry_points=entry_points,
        unsafe_sinks=unsafe_sinks,
        seed_taint_evidence=seed_taint_evidence,
    )


def make_taint_distinct_sinks_ctx() -> ContextPackage:
    """Two seeded functions in one file, each sinking in a DIFFERENT file.

    The companion fixture above puts every sink in one shared file, so every
    evidence entry resolves to the same file set and the file-set merge collapses
    the duplicates whether or not seed matching is keyed on the function. That
    makes it unable to distinguish the fix from the merge.

    Here the two evidence entries have disjoint file sets, so a match keyed on
    the file alone cross-attributes: BOTH chunks end up carrying BOTH functions,
    where the correct output is one function each. That is the silent
    wrong-attribution this keying is meant to prevent, and it is only observable
    when the sinks do not share a file.
    """
    src = "app/handlers.py"
    pairs = [("func_a", "app/db.py", "sink_sql", "CWE-89"),
             ("func_b", "app/shell.py", "sink_cmd", "CWE-78")]

    return make_ctx(
        all_files=[src] + [sf for _, sf, _, _ in pairs],
        entry_points=[
            EntryPoint(file=src, function=fn, kind="network",
                       reachable_from_unauth=True)
            for fn, _, _, _ in pairs
        ],
        unsafe_sinks=[
            Sink(file=sf, line=10, function=sfn, cwe=[cwe])
            for _, sf, sfn, cwe in pairs
        ],
        seed_taint_evidence=[
            TaintEvidencePath(
                source_ref=f"{src}::{fn}",
                sink_ref=f"{sf}:10",
                path_funcs=[f"{src}::{fn}", f"{sf}::{sfn}"],
                sink_cwe=[cwe],
            )
            for fn, sf, sfn, cwe in pairs
        ],
    )


def make_frontier_ne_full_ctx(full_n: int = 50) -> ContextPackage:
    """AST frontier of 5 files while ``all_files`` is 50.

    A prompt's file inventory can be rendered from a reduced view of the
    repository (``ctx.ast_context_view(max_files=...)``, a small "frontier"),
    while individual file references in that same prompt get resolved
    against the full file list (``ctx.all_files``). The two are different,
    differently-sized lists, so the k-th entry of one sorted list is not the
    k-th entry of the other — an id or index built against one and resolved
    against the other silently addresses the wrong file. This fixture makes
    that divergence reproducible on a small scale: a 5-file frontier against
    a 50-file tree.

    ``all_files`` here is deliberately in DESCENDING name order (no entry
    points/sinks to seed the frontier from), so ``ast_context_view``'s
    fallback padding — which walks ``self.all_files`` in LIST order, not
    sorted order — picks up the numerically-largest 5 files first. Calling
    ``ctx.ast_context_view(max_files=5).all_files`` therefore yields a
    5-file frontier that, once sorted, disagrees with ``sorted(ctx.all_files)``
    almost everywhere (see the self-check in
    ``tests/test_fixtures_selfcheck.py`` for the exact assertion).
    """
    all_files = [f"src/mod_{i:02d}.py" for i in range(full_n - 1, -1, -1)]
    return make_ctx(all_files=all_files)
