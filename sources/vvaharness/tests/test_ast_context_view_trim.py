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

"""F28: ast_context_view was refactored for cost (set-based dedup, hoisted
inventory set, lazy edge classification). The observable output — which edges
survive the max_edges cut, in hot-before-cold order — must be unchanged."""
from __future__ import annotations

from vvaharness.models import ContextPackage, EntryPoint, Sink


def _ctx() -> ContextPackage:
    return ContextPackage(
        repo_root="/repo",
        language="python",
        all_files=["a.py", "b.py", "c.py"],
        entry_points=[EntryPoint(file="a.py", function="main", kind="cli")],
        unsafe_sinks=[Sink(file="c.py", function="sinkfn")],
        call_graph={
            "a.py::main": ["a.py::helper", "b.py::cold1"],  # main -> hot
            "b.py::cold1": ["b.py::cold2"],                 # cold
            "c.py::worker": ["c.py::sinkfn"],               # sinkfn -> hot
        },
    )


def test_edges_are_hot_before_cold_and_all_kept_when_uncapped():
    out = _ctx().ast_context_view(max_edges=120)
    assert out.call_graph == {
        "a.py::main": ["a.py::helper", "b.py::cold1"],
        "c.py::worker": ["c.py::sinkfn"],
        "b.py::cold1": ["b.py::cold2"],
    }


def test_max_edges_cut_respects_hot_first_ordering():
    # Cap below the hot-edge count: only the first two (both from the entry
    # function) survive; the sink-adjacent hot edge and the cold edge are cut.
    out = _ctx().ast_context_view(max_edges=2)
    assert out.call_graph == {"a.py::main": ["a.py::helper", "b.py::cold1"]}


def test_cold_edges_only_after_all_hot_edges():
    # Exactly the three hot edges fit; the lone cold edge (cold1->cold2) is
    # excluded even though it appears earlier in call_graph iteration order.
    out = _ctx().ast_context_view(max_edges=3)
    assert out.call_graph == {
        "a.py::main": ["a.py::helper", "b.py::cold1"],
        "c.py::worker": ["c.py::sinkfn"],
    }


def test_seed_files_dedup_and_inventory_fallback():
    out = _ctx().ast_context_view(max_edges=120)
    # Seeded files (entry a.py, sink c.py) come first in original order, then
    # the remaining inventory file b.py is appended by the fallback.
    assert out.all_files == ["a.py", "c.py", "b.py"]
