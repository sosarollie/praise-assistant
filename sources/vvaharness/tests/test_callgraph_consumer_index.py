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

"""F06: shared graph index in callgraph_consumer.

Pins the single, call-graph-first resolution that s3/s6/s7/s8 now all share —
in particular the fallback taken when def_spans do NOT cover the finding line,
which the four stages previously disagreed about (s6/s7 fell back to the call
graph, s8 gave up, s3 took the nearest span).
"""
from __future__ import annotations

from vvaharness.models import ContextPackage
from vvaharness.pipeline import callgraph_consumer as cc


def _ctx(**kw) -> ContextPackage:
    return ContextPackage(repo_root="/tmp/repo", language="python", **kw)


def test_build_span_index_sorted_and_skips_malformed():
    ctx = _ctx(def_spans={
        "app.py::b": [30, 40],
        "app.py::a": [8, 20],
        "app.py::bad": [],          # malformed (empty) → skipped
    })
    idx = cc.build_span_index(ctx)
    assert idx["app.py"] == [(8, 20, "app.py::a"), (30, 40, "app.py::b")]


def test_qnodes_at_prefers_overlapping_span():
    ctx = _ctx(
        def_spans={"app.py::danger": [8, 20], "app.py::other": [30, 40]},
        call_graph={"http.py::handle": ["app.py::danger"]},
    )
    view = cc.graph_view(ctx)
    assert cc.qnodes_at(view, "app.py", 10, 12) == ["app.py::danger"]


def test_qnodes_at_falls_back_to_call_graph_when_no_span_covers():
    # Call-graph-first: the line is not covered by any span, so the call
    # graph's file membership is authoritative — s6/s7's old behaviour, now
    # applied universally so s8 no longer returns nothing here.
    ctx = _ctx(
        def_spans={"app.py::danger": [8, 20]},
        call_graph={
            "http.py::handle": ["app.py::danger", "app.py::helper"],
            "app.py::helper": ["db.py::exec"],
        },
    )
    view = cc.graph_view(ctx)
    got = cc.qnodes_at(view, "app.py", 500, 500)
    assert "app.py::danger" in got and "app.py::helper" in got


def test_qnodes_at_nearest_only_when_requested_and_no_call_graph():
    ctx = _ctx(def_spans={"app.py::danger": [8, 20], "app.py::far": [200, 210]})
    view = cc.graph_view(ctx)
    # No call graph → default returns nothing…
    assert cc.qnodes_at(view, "app.py", 500, 500) == []
    # …but s3's single-anchor lookup opts into nearest-span behaviour.
    assert cc.qnodes_at(view, "app.py", 205, 205,
                        limit=1, nearest_if_empty=True) == ["app.py::far"]


def test_reverse_edges_deduped_insertion_order():
    ctx = _ctx(call_graph={
        "a::f": ["c::z"],
        "b::g": ["c::z"],
        "a::f2": ["c::z"],
    })
    rev = cc.reverse_edges(ctx)
    assert rev["c::z"] == ["a::f", "b::g", "a::f2"]


def test_neighborhood_returns_callers_and_callees():
    ctx = _ctx(call_graph={
        "http.py::handle": ["app.py::danger"],
        "app.py::danger": ["db.py::exec"],
    })
    view = cc.graph_view(ctx)
    around = cc.neighborhood(view, ["app.py::danger"])
    assert around["app.py::danger"]["callers"] == ["http.py::handle"]
    assert around["app.py::danger"]["callees"] == ["db.py::exec"]


def test_graph_view_is_memoized_per_ctx():
    ctx = _ctx(call_graph={"a::f": ["b::g"]})
    assert cc.graph_view(ctx) is cc.graph_view(ctx)
    assert cc.graph_view(_ctx()) is not cc.graph_view(ctx)
