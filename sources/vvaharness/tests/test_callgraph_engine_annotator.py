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
Deterministic tests for the live LLM detection seam ``_annotator``.

These exercise the wired ``detect_specs`` entry point and its pure helpers
without any network / LLM call:

1. ``detect_specs`` returns empty specs when there are no observed calls
   (short-circuits before any model invocation).
2. ``_collect_candidates`` yields nothing for empty input.
3. Pure classification helpers map kinds/CWEs to stable semantic families.
"""

from types import SimpleNamespace

from vvaharness.pipeline.stages.callgraph_engine._annotator import (
    _collect_candidates,
    _norm_cwe,
    _semantic_family,
    detect_specs,
)


def test_detect_specs_empty_input_returns_empty():
    """No file indices -> empty specs, no LLM call, no model required."""
    sources, sinks, rule_cwe = detect_specs([], [], SimpleNamespace(),
                                            repo_root="/nonexistent-repo")
    assert sources == []
    assert sinks == []
    assert rule_cwe == {}


def test_collect_candidates_empty():
    assert _collect_candidates([], set(), 400) == []


def test_semantic_family_stable_mapping():
    assert _semantic_family("sql", "CWE-89") == "sql-exec"
    assert _semantic_family("cmd", "CWE-78") == "command-exec"
    assert _semantic_family("deserialize", "CWE-502") == "deserialization"
    assert _semantic_family("", "") == "other"


def test_norm_cwe_defaults_by_role():
    assert _norm_cwe("CWE-89", "sink") == "CWE-89"
    assert _norm_cwe("garbage", "source") == "CWE-20"
    assert _norm_cwe("garbage", "sink") == "CWE-78"


# ── self-consistency voting over the spec classifier ────────────────────────
# This single model call is the largest source of run-to-run variance in the
# pipeline: everything before it is byte-stable and everything after is a pure
# function of the spec set, yet replicates of identical code drew 4, 6 and 7
# source specs on one repo. Temperature cannot pin it — the shipped annotate
# models drop or reject the parameter. Voting is the available remedy, and it
# matters disproportionately because one marginal spec amplifies to ~56 sink
# sites, and because a candidate near the hard confidence cutoff is otherwise
# accepted or dropped by sampling luck.

import json as _json

from vvaharness.pipeline.stages.callgraph_engine import _annotator as ann
from vvaharness.pipeline.stages.callgraph_engine._scan import (
    FileIndex, ObservedCall)


def _idx_with_call(module="request", method="get", lang="python"):
    fi = FileIndex(file="app.py", language=lang, imports={}, functions=[])
    fi.observed_calls = [ObservedCall(
        file="app.py", line=3, language=lang, receiver=module,
        resolved_receiver=module, method=method, containing_fn="handler",
        snippet=f"{module}.{method}(x)")]
    return fi


def _cfg(self_consistency=3, min_conf=0.75):
    return SimpleNamespace(
        step0=SimpleNamespace(callgraph=SimpleNamespace(llm=SimpleNamespace(
            max_candidates=400, max_batch_candidates=150,
            min_source_confidence=min_conf, min_sink_confidence=min_conf,
            max_tokens=16000, failure_mode="empty",
            heuristic_supplement=False, min_sources=0, min_sinks=0,
            max_heuristic_specs=0, self_consistency=self_consistency))),
        models=SimpleNamespace(graph_annotate=SimpleNamespace(id="m", via="sdk")),
    )


def _stub(monkeypatch, responses):
    """Return successive canned responses, and record how many calls happened.

    Patches the dispatch seam the annotator now routes every model call
    through (`ann._deepagents.dispatch_prompt`) — the module import in
    `_annotator.py` keeps this monkeypatch seam working.
    """
    calls = {"n": 0, "kw": []}

    def fake(*a, **kw):
        i = min(calls["n"], len(responses) - 1)
        calls["n"] += 1
        calls["kw"].append(dict(kw))
        return _json.dumps({"results": responses[i]})

    monkeypatch.setattr(ann._deepagents, "dispatch_prompt", fake)
    return calls


def _row(role, conf, cid="c1", cwe="CWE-89", kind="sql"):
    return {"id": cid, "role": role, "confidence": conf, "cwe": cwe, "kind": kind}


def test_majority_role_wins_and_minority_flip_is_discarded(monkeypatch):
    # source, source, sink -> source holds the majority.
    calls = _stub(monkeypatch, [[_row("source", 0.9)],
                                [_row("source", 0.9)],
                                [_row("sink", 0.9)]])
    srcs, sinks, _ = detect_specs([_idx_with_call()], ["python"], _cfg(),
                              repo_root="/nonexistent-repo")
    assert calls["n"] == 3, "self_consistency=3 must sample three times"
    assert len(srcs) == 1 and sinks == []


def test_role_flipping_every_sample_reaches_no_majority(monkeypatch):
    # source, sink, none -> nothing reaches 2 of 3, so nothing is seeded.
    _stub(monkeypatch, [[_row("source", 0.95)],
                        [_row("sink", 0.95)],
                        [_row("none", 0.95)]])
    srcs, sinks, _ = detect_specs([_idx_with_call()], ["python"], _cfg(),
                              repo_root="/nonexistent-repo")
    assert srcs == [] and sinks == []


def test_threshold_flip_is_decided_on_the_mean_not_a_single_draw(monkeypatch):
    # Confidences straddle the 0.75 cutoff; the mean (0.80) clears it, so the
    # spec survives instead of depending on which draw was inspected.
    _stub(monkeypatch, [[_row("source", 0.70)],
                        [_row("source", 0.85)],
                        [_row("source", 0.85)]])
    srcs, _, _ = detect_specs([_idx_with_call()], ["python"], _cfg(),
                              repo_root="/nonexistent-repo")
    assert len(srcs) == 1

    # And the converse: a mean below the cutoff is still rejected. (0.70/0.70/
    # 0.85 would average to EXACTLY 0.75 and pass a `< 0.75` gate, so the values
    # here sit clearly below rather than on the boundary.)
    _stub(monkeypatch, [[_row("source", 0.60)],
                        [_row("source", 0.70)],
                        [_row("source", 0.85)]])
    srcs2, _, _ = detect_specs([_idx_with_call()], ["python"], _cfg(),
                              repo_root="/nonexistent-repo")
    assert srcs2 == []


def test_unusable_sample_does_not_raise_the_bar(monkeypatch):
    """An unparseable sample must not count toward the majority.

    Counting it would silently require the remaining samples to clear a higher
    bar than the operator asked for, turning a provider hiccup into lost
    coverage.
    """
    def fake(*a, **kw):
        fake.n = getattr(fake, "n", 0) + 1
        if fake.n == 1:
            return "not json at all"
        return _json.dumps({"results": [_row("source", 0.9)]})

    monkeypatch.setattr(ann._deepagents, "dispatch_prompt", fake)
    srcs, _, _ = detect_specs([_idx_with_call()], ["python"], _cfg(),
                              repo_root="/nonexistent-repo")
    # 2 usable samples, both agree -> majority of 2 is 2 -> seeded.
    assert len(srcs) == 1


def test_self_consistency_one_keeps_single_sample_behaviour(monkeypatch):
    calls = _stub(monkeypatch, [[_row("source", 0.9)]])
    srcs, _, _ = detect_specs([_idx_with_call()], ["python"],
                              _cfg(self_consistency=1),
                              repo_root="/nonexistent-repo")
    assert calls["n"] == 1
    assert len(srcs) == 1


def test_unconfigured_self_consistency_defaults_to_single_sample(monkeypatch):
    calls = _stub(monkeypatch, [[_row("source", 0.9)]])
    cfg = _cfg()
    del cfg.step0.callgraph.llm.self_consistency
    srcs, _, _ = detect_specs([_idx_with_call()], ["python"], cfg,
                              repo_root="/nonexistent-repo")
    assert calls["n"] == 1, "the shipped default is single-pass; voting is opt-in"
    assert len(srcs) == 1


# ── the dispatch seam ────────────────────────────────────────────────────────
# The annotator no longer imports `registry.prompt` by name: every model call
# goes through `_deepagents.dispatch_prompt`, the one place that branches on
# the resolved via ("deepagents" -> harness one-shot, else registry). These
# pin what the annotator hands that seam.

def test_model_call_goes_through_dispatch_with_repo_root_cwd_and_tag(monkeypatch):
    calls = _stub(monkeypatch, [[_row("source", 0.9)]])
    cfg = _cfg(self_consistency=1)
    detect_specs([_idx_with_call()], ["python"], cfg,
                 repo_root="/scanned/repo")
    kw = calls["kw"][0]
    assert kw["cwd"] == "/scanned/repo"
    assert kw["tag"] == "s0 callgraph-annotate"
    assert kw["cfg"] is cfg
    assert kw["max_tokens"] == 16000


def test_deepagents_via_routes_to_the_harness_never_the_registry(monkeypatch):
    """With `graph_annotate` on via:deepagents, the REAL dispatcher must pick
    the harness branch (this module's `prompt`) and never `registry.prompt`.
    Fakes one level below the dispatcher, so the branch itself is exercised."""
    from vvaharness.backends.llm import deepagents as _da
    from vvaharness.backends.llm import registry as _registry

    seen = {}

    def fake_prompt(user_prompt, *, model, cwd, tag=None, **kw):
        seen["cwd"] = cwd
        seen["tag"] = tag
        return _json.dumps({"results": [_row("source", 0.9)]})

    monkeypatch.setattr(_da, "prompt", fake_prompt)
    monkeypatch.setattr(
        _registry, "prompt",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("registry.prompt must not serve a deepagents role")),
    )
    cfg = _cfg(self_consistency=1)
    cfg.models.graph_annotate = SimpleNamespace(id="m", via="deepagents")
    srcs, _, _ = detect_specs([_idx_with_call()], ["python"], cfg,
                              repo_root="/scanned/repo")
    assert len(srcs) == 1
    assert seen == {"cwd": "/scanned/repo", "tag": "s0 callgraph-annotate"}
