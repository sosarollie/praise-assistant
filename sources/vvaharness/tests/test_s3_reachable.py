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
Unit tests for step3.catchall_mode=reachable_only.

Synthetic ContextPackage with a known file-level call graph; assert that
_reachable_files() returns exactly the forward-from-EP ∪ backward-from-sink
closure and that _add_catchall_chunks() drops the unreachable remainder onto
manifest.unreachable_files (never into a chunk).
"""
from __future__ import annotations

from types import SimpleNamespace

from vvaharness.models import ContextPackage, EntryPoint, Sink, TaskManifest
from vvaharness.pipeline.stages import s3_decompose as s3
from vvaharness.pipeline.stages.s1_preprocess import q_join


def _ctx(tmp_path) -> ContextPackage:
    """
    Graph (file-level edges shown):

        ctrl.py ──▶ svc.py ──▶ dao.py        (entry → … → sink)
                       │
                       └────▶ util.py        (forward-reachable, no sink)
        helper.py ──▶ dao.py                 (backward-reachable from sink)
        island.py                            (UNREACHABLE — must be dropped)
        const.py                             (UNREACHABLE — must be dropped)
    """
    files = ["ctrl.py", "svc.py", "dao.py", "util.py", "helper.py",
             "island.py", "const.py"]
    for f in files:
        (tmp_path / f).write_text("# stub\n", encoding="utf-8")
    return ContextPackage(
        repo_root=str(tmp_path),
        language="python",
        all_files=files,
        entry_points=[EntryPoint(file="ctrl.py", function="handle",
                                 kind="network")],
        unsafe_sinks=[Sink(file="dao.py", line=10, function="raw_query",
                           snippet="cur.execute(sql)")],
        call_graph={
            q_join("ctrl.py", "handle"):  [q_join("svc.py", "process")],
            q_join("svc.py", "process"):  [q_join("dao.py", "raw_query"),
                                           q_join("util.py", "fmt")],
            q_join("helper.py", "batch"): [q_join("dao.py", "raw_query")],
            # island/const have no edges
        },
        call_graph_files={},
    )


def _cfg(mode: str):
    """Minimal cfg.step3 surface s3 reads from."""
    step3 = SimpleNamespace(
        catchall_enabled=True, catchall_mode=mode,
        catchall_chunk_loc=10_000, catchall_max_files=100,
        max_files_per_chunk=100, pack_by="loc",
        taint_chunks=False,  # isolate the catch-all path
    )
    return SimpleNamespace(step3=step3)


def test_reachable_files_closure(tmp_path):
    ctx = _ctx(tmp_path)
    reach = s3._reachable_files(ctx)
    assert reach == {"ctrl.py", "svc.py", "dao.py", "util.py", "helper.py"}
    assert "island.py" not in reach
    assert "const.py" not in reach


def test_catchall_reachable_only_drops_islands(tmp_path):
    ctx = _ctx(tmp_path)
    manifest = TaskManifest(chunks=[], rationale="test")
    n = s3._add_catchall_chunks(manifest, ctx, _cfg("reachable_only"))

    chunk_files = {f for c in manifest.chunks for f in c.files}
    assert "island.py" not in chunk_files
    assert "const.py" not in chunk_files
    # reachable files DID land in catch-all chunks
    assert {"ctrl.py", "svc.py", "dao.py", "util.py",
            "helper.py"} <= chunk_files
    # dropped files recorded for the report appendix
    assert sorted(manifest.unreachable_files) == ["const.py", "island.py"]
    assert n >= 1


def test_catchall_mode_all_is_legacy(tmp_path):
    """default.yaml path: every eligible file is swept, nothing recorded."""
    ctx = _ctx(tmp_path)
    manifest = TaskManifest(chunks=[], rationale="test")
    s3._add_catchall_chunks(manifest, ctx, _cfg("all"))

    chunk_files = {f for c in manifest.chunks for f in c.files}
    assert {"island.py", "const.py"} <= chunk_files
    assert manifest.unreachable_files == []


def test_reachable_only_falls_back_when_no_anchors(tmp_path):
    """No EPs and no sinks → gating would drop everything; must fall back."""
    ctx = _ctx(tmp_path)
    ctx.entry_points = []
    ctx.unsafe_sinks = []
    manifest = TaskManifest(chunks=[], rationale="test")
    s3._add_catchall_chunks(manifest, ctx, _cfg("reachable_only"))

    chunk_files = {f for c in manifest.chunks for f in c.files}
    assert set(ctx.all_files) <= chunk_files     # full sweep preserved
    assert manifest.unreachable_files == []


def test_seed_codeflow_widens_reachability(tmp_path):
    """Gap-#1: a file semgrep placed on a codeFlow path is reachable even
    when the call-graph has NO edge to it (reflection/DI blind spot).
    reachable_only must never drop it."""
    ctx = _ctx(tmp_path)
    # island.py is not on the call graph, but s0 proved it sits on a
    # source→sink dataflow. It must NOT land in unreachable_files.
    ctx.seed_taint_paths = [["ctrl.py:1", "island.py:5", "dao.py:10"]]
    reach = s3._reachable_files(ctx)
    assert "island.py" in reach
    manifest = TaskManifest(chunks=[], rationale="test")
    s3._add_catchall_chunks(manifest, ctx, _cfg("reachable_only"))
    assert "island.py" not in manifest.unreachable_files
    assert manifest.unreachable_files == ["const.py"]     # only true islands drop


def test_polymorphic_widening_via_call_graph_files(tmp_path):
    """An interface call keeps EVERY def-site file in scope."""
    ctx = _ctx(tmp_path)
    # svc.process calls bare `save`; two impls live in dao.py and island.py.
    ctx.call_graph[q_join("svc.py", "process")].append(
        q_join("dao.py", "save"))
    ctx.call_graph_files = {"save": ["dao.py:40", "island.py:12"]}
    reach = s3._reachable_files(ctx)
    assert "island.py" in reach     # pulled in via polymorphic widening


def test_unsupported_language_files_stay_reachable(tmp_path):
    """F36: the call graph only covers the 6 plugin languages. Files in a
    language that contributed ZERO graph nodes must be treated as unknown
    (reachable), not deterministically dropped for lack of a parser."""
    files = ["ctrl.py", "svc.py", "app.rb", "lib.rb", "main.go"]
    for f in files:
        (tmp_path / f).write_text("# stub\n", encoding="utf-8")
    ctx = ContextPackage(
        repo_root=str(tmp_path),
        language="python",
        all_files=files,
        entry_points=[EntryPoint(file="ctrl.py", function="handle",
                                 kind="network")],
        unsafe_sinks=[Sink(file="svc.py", line=3, function="exec_sql")],
        # Graph mentions only python nodes (go/ruby have no s0 plugin here).
        call_graph={q_join("ctrl.py", "handle"): [q_join("svc.py", "exec_sql")]},
        call_graph_files={},
    )
    reach = s3._reachable_files(ctx)
    # Ruby files: no graph nodes for ruby → unknown → kept.
    assert "app.rb" in reach
    assert "lib.rb" in reach
    # Go likewise has no nodes here → kept (parser-blindness, not proof).
    assert "main.go" in reach
    # Python IS covered (ctrl/svc are nodes), so pruning still applies to it:
    # a python island with no path would be dropped — assert covered-lang
    # pruning is not disabled by adding an isolated python file.
    ctx.all_files = files + ["island.py"]
    (tmp_path / "island.py").write_text("# stub\n", encoding="utf-8")
    reach2 = s3._reachable_files(ctx)
    assert "island.py" not in reach2


def test_reachable_only_fails_open_when_too_sparse():
    """F36: a taint profile that opts into the min-ratio backstop reverts to
    mode=all instead of dropping most of the repo from catch-all review."""
    step3 = SimpleNamespace(
        catchall_reachable_min_ratio=0.5, catchall_reachable_min_files=0)
    cfg = SimpleNamespace(step3=step3)
    # 2 of 10 reachable = 20% < 50% → fail open.
    too_sparse, reason = s3._reachable_only_too_sparse(2, 10, cfg)
    assert too_sparse
    assert "ratio" in reason
    # 6 of 10 = 60% ≥ 50% → keep the pruning.
    ok, _ = s3._reachable_only_too_sparse(6, 10, cfg)
    assert not ok


# Gap-#2: Sink.cwe (from s0 seed) → Chunk.sink_cwe (via _add_taint_chunks)

def _cfg_taint():
    step3 = SimpleNamespace(
        taint_chunks=True, taint_max_hops=10, taint_max_chunks=20,
        taint_files_per_hop=5, catchall_enabled=False, catchall_mode="all",
    )
    return SimpleNamespace(step3=step3)


def test_taint_chunk_carries_seed_sink_cwe(tmp_path):
    """s0-seeded Sink.cwe must land on Chunk.sink_cwe so s4's confirm/refute
    prompt can splice CweKB guidance. This is the end-to-end wire the
    FP-reduction claim depends on."""
    ctx = _ctx(tmp_path)
    # Two sinks resolving to the same qnode: one seed-tagged, one agent-found
    # (empty cwe). Chunk must union them → ["CWE-89", "CWE-943"].
    ctx.unsafe_sinks = [
        Sink(file="dao.py", line=10, function="raw_query",
             cwe=["CWE-89", "CWE-943"]),
        Sink(file="dao.py", line=12, function="raw_query", cwe=[]),
    ]
    manifest = TaskManifest(chunks=[], rationale="test")
    n = s3._add_taint_chunks(manifest, ctx, _cfg_taint())
    assert n >= 1
    taint = [c for c in manifest.chunks if c.id.startswith("taint-")]
    assert taint, "no taint chunk emitted"
    c = taint[0]
    assert c.sink_cwe == ["CWE-89", "CWE-943"]
    assert c.source_ref == q_join("ctrl.py", "handle")
    assert c.sink_ref == "dao.py:10"
    assert q_join("dao.py", "raw_query") in c.path_funcs


def test_taint_chunk_sink_cwe_empty_for_agent_only_sink(tmp_path):
    """Agent-discovered sink (no s0 CWE) → sink_cwe stays [] and s4's KB
    block will omit itself (legacy prompt)."""
    ctx = _ctx(tmp_path)     # fixture Sink has default cwe=[]
    manifest = TaskManifest(chunks=[], rationale="test")
    s3._add_taint_chunks(manifest, ctx, _cfg_taint())
    taint = [c for c in manifest.chunks if c.id.startswith("taint-")]
    assert taint and taint[0].sink_cwe == []
