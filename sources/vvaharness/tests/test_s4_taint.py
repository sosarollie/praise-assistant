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
Phase-4 tests: function-slice loader + confirm/refute prompt dispatch in s4.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.backends.llm import registry
from vvaharness.models import Chunk, ChunkSize, ContextPackage
from vvaharness.pipeline.stages import s4_deepdive as s4
from vvaharness.pipeline.stages.s1_preprocess import q_join

# fixtures

SVC = "\n".join(f"# pad {i}" for i in range(1, 21)) + """
def process(q):
    s = 'SELECT * FROM t WHERE x = ' + q
    return raw_query(s)
""" + "\n".join(f"# tail {i}" for i in range(1, 81))   # 100+ line file

CTRL = """\
def handle(req):
    q = req.args.get('q')
    return process(q)
"""

DAO = """\
import db

def raw_query(sql):
    return db.execute(sql)
"""


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "ctrl.py").write_text(CTRL, encoding="utf-8")
    (tmp_path / "svc.py").write_text(SVC, encoding="utf-8")
    (tmp_path / "dao.py").write_text(DAO, encoding="utf-8")
    return tmp_path


@pytest.fixture
def ctx(repo):
    return ContextPackage(
        repo_root=str(repo), language="python",
        all_files=["ctrl.py", "svc.py", "dao.py"],
        def_spans={
            q_join("ctrl.py", "handle"):    [1, 3],
            q_join("svc.py",  "process"):   [21, 23],
            q_join("dao.py",  "raw_query"): [3, 4],
        },
        call_graph_files={
            "handle":    ["ctrl.py:1"],
            "process":   ["svc.py:21"],
            "raw_query": ["dao.py:3"],
        },
    )


@pytest.fixture
def taint_chunk():
    return Chunk(
        id="taint-01", size=ChunkSize.SMALL, risk_rank=1,
        files=["ctrl.py", "svc.py", "dao.py"],
        focus_entry_points=["handle"],
        hypothesis="x",
        path_funcs=[q_join("ctrl.py", "handle"),
                    q_join("svc.py", "process"),
                    q_join("dao.py", "raw_query")],
        source_ref=q_join("ctrl.py", "handle"),
        sink_ref="dao.py:4",
        sink_cwe=["CWE-89"],
    )


def _cfg(slice_mode="function", prompt_mode="confirm_refute", taint_runs=1):
    return SimpleNamespace(
        step3=SimpleNamespace(taint_chunk_slice=slice_mode),
        step4=SimpleNamespace(
            taint_prompt_mode=prompt_mode, taint_runs=taint_runs,
            taint_model={"id": "claude-haiku-4-5", "via": "cli"},
            neighbor_context_lines=0, neighbor_context_max=0,
            line_bucket=10, runs=4, vote_threshold=3, specialist_runs=1,
            max_tokens=64000, timeout=1800,
        ),
        models=SimpleNamespace(deepdive=SimpleNamespace(id="claude-sonnet-4-6", via="cli")),
    )


def _cfg_s4_slice(step4_mode=None, step3_mode="file"):
    return SimpleNamespace(
        step3=SimpleNamespace(taint_chunk_slice=step3_mode),
        step4=SimpleNamespace(
            taint_chunk_slice=step4_mode,
            frontier_max_funcs_per_file=24,
            neighbor_context_lines=0,
            neighbor_context_max=0,
            line_bucket=10,
            runs=1,
            vote_threshold=1,
            specialist_runs=1,
            max_tokens=64000,
            timeout=1800,
            taint_prompt_mode="discover",
            taint_runs=1,
        ),
        models=SimpleNamespace(deepdive=SimpleNamespace(id="claude-sonnet-4-6", via="cli")),
    )


# _merge_ranges

def test_merge_ranges_overlap_and_gap():
    assert s4._merge_ranges([(1, 5), (3, 8), (20, 22)], gap=0) \
        == [(1, 8), (20, 22)]
    assert s4._merge_ranges([(1, 5), (8, 10)], gap=2) == [(1, 10)]
    assert s4._merge_ranges([(1, 5), (9, 10)], gap=2) == [(1, 5), (9, 10)]
    assert s4._merge_ranges([(10, 12), (1, 3)], gap=0) == [(1, 3), (10, 12)]


# _load_taint_slice

def test_taint_slice_ships_only_path_functions(repo, ctx, taint_chunk):
    out = s4._load_taint_slice(taint_chunk, ctx, repo, pad=2)
    # svc.py: process() is lines 21-23; with pad=2 → 19-25. The 80-line tail
    # (lines 25..100+) MUST NOT be in the prompt.
    assert "=== svc.py [lines 19-25] ===" in out
    assert "def process(q):" in out
    assert "# tail 50" not in out
    assert "# pad 5" not in out
    # real line numbers preserved for s6 citation
    assert "   21| def process(q):" in out
    # entry + sink files present
    assert "=== ctrl.py [lines 1-" in out
    assert "=== dao.py [lines 1-" in out
    # token win: slice is much smaller than whole-file load
    full = s4._load_files_full(taint_chunk.files, repo)
    assert len(out) < len(full) / 3


def test_taint_slice_falls_back_to_anchor_when_no_span(repo, ctx, taint_chunk):
    # Drop the AST span for process(); call_graph_files still has the def line.
    ctx.def_spans.pop(q_join("svc.py", "process"))
    out = s4._load_taint_slice(taint_chunk, ctx, repo, pad=3)
    assert "def process(q):" in out          # anchored on line 21 ±3
    assert "# tail 50" not in out


def test_taint_slice_empty_when_no_spans_at_all(repo, ctx, taint_chunk):
    ctx.def_spans = {}
    assert s4._load_taint_slice(taint_chunk, ctx, repo) == ""


# F32: per-file / per-node whole-file fallback (coverage-first)

def test_graph_slice_ships_ungraphed_file_whole_in_mixed_chunk(repo, ctx):
    # ctrl.py resolves a span; svc.py's span is removed so the call graph knows
    # nothing about it. Under the old per-chunk valve, ctrl.py's span kept the
    # valve shut and svc.py was truncated to its first 80 lines. Now svc.py is
    # shipped WHOLE so real code below the head is never silently dropped.
    ctx.def_spans.pop(q_join("svc.py", "process"))
    chunk = Chunk(id="mixed-01", size=ChunkSize.SMALL,
                  files=["ctrl.py", "svc.py"], hypothesis="x")
    out = s4._load_graph_slice(chunk, ctx, repo,
                               _cfg_s4_slice(step4_mode="function"), pad=2)
    # ctrl.py still sliced to its resolved span…
    assert "=== ctrl.py [lines 1-" in out
    # …but svc.py ships whole, including the tail past line 80.
    assert "=== svc.py [lines 1-" in out
    assert "# tail 50" in out


def test_graph_slice_zero_height_span_falls_back_to_whole_file(repo, ctx):
    # Regex fallback emits sentinel spans [ln, ln]. Treat these as invalid
    # function spans so the file is shipped whole, not as a 1-line window.
    ctx.def_spans[q_join("svc.py", "process")] = [21, 21]
    chunk = Chunk(id="zero-height-01", size=ChunkSize.SMALL,
                  files=["svc.py"], hypothesis="x")
    out = s4._load_chunk_code(chunk, ctx, repo,
                              _cfg_s4_slice(step4_mode="function"))
    assert "=== svc.py ===" in out
    assert "# tail 50" in out


def test_graph_slice_ships_clipped_file_whole(repo, ctx):
    # svc.py has more resolved functions than the per-file cap → rather than
    # dropping every function past the cap, the whole file is shipped.
    ctx.def_spans[q_join("svc.py", "process_2")] = [21, 23]
    cfg = _cfg_s4_slice(step4_mode="function")
    cfg.step4.frontier_max_funcs_per_file = 1
    chunk = Chunk(id="clip-01", size=ChunkSize.SMALL,
                  files=["svc.py"], hypothesis="x")
    out = s4._load_graph_slice(chunk, ctx, repo, cfg, pad=2)
    assert "# tail 50" in out


def test_taint_slice_degrades_hop_to_whole_file_when_no_span_or_anchor(
        repo, ctx, taint_chunk):
    # The process() hop loses both its AST span and its call_graph_files anchor.
    # The confirm/refute prompt tells the model the slice contains the whole
    # path, so the hop's file must ship whole rather than vanish.
    ctx.def_spans.pop(q_join("svc.py", "process"))
    ctx.call_graph_files.pop("process")
    out = s4._load_taint_slice(taint_chunk, ctx, repo, pad=2)
    assert "=== svc.py [lines 1-" in out
    assert "# tail 50" in out
    # the other hops are still sliced, not shipped whole
    assert "=== ctrl.py [lines" in out
    assert "=== dao.py [lines" in out


# _load_chunk_code dispatch

def test_load_chunk_code_slices_under_taint_profile(repo, ctx, taint_chunk):
    out = s4._load_chunk_code(taint_chunk, ctx, repo, _cfg("function"))
    assert "# tail 50" not in out


def test_load_chunk_code_whole_file_under_default(repo, ctx, taint_chunk):
    """default.yaml: taint_chunk_slice=file → byte-identical legacy path."""
    out = s4._load_chunk_code(taint_chunk, ctx, repo, _cfg("file"))
    assert "# tail 50" in out                 # whole file shipped


def test_load_chunk_code_falls_back_when_no_def_spans(repo, ctx, taint_chunk):
    ctx.def_spans = {}
    out = s4._load_chunk_code(taint_chunk, ctx, repo, _cfg("function"))
    assert "# tail 50" in out                 # fell through to whole-file


def test_non_taint_chunk_never_sliced(repo, ctx):
    risk = Chunk(id="chunk-01", size=ChunkSize.SMALL, files=["svc.py"],
                 hypothesis="x")
    out = s4._load_chunk_code(risk, ctx, repo, _cfg("function"))
    assert "# tail 50" not in out             # graph-sliced even without path_funcs


def test_load_chunk_code_logs_def_spans_absent_once(repo, ctx, taint_chunk, capsys):
    ctx.def_spans = {}
    s4._DEF_SPANS_ABSENT_WARNED = False
    s4._load_chunk_code(taint_chunk, ctx, repo, _cfg("function"))
    s4._load_chunk_code(taint_chunk, ctx, repo, _cfg("function"))
    err = capsys.readouterr().err
    assert err.count("def_spans absent") == 1
    assert "whole-file fallback mode" in err


def test_load_chunk_code_no_absent_def_spans_log_when_present(
        repo, ctx, taint_chunk, capsys):
    s4._DEF_SPANS_ABSENT_WARNED = False
    s4._load_chunk_code(taint_chunk, ctx, repo, _cfg("function"))
    err = capsys.readouterr().err
    assert "def_spans absent" not in err


def test_step4_slice_mode_overrides_step3(repo, ctx):
    risk = Chunk(id="chunk-02", size=ChunkSize.SMALL, files=["svc.py"],
                 hypothesis="x")
    out = s4._load_chunk_code(risk, ctx, repo,
                              _cfg_s4_slice(step4_mode="function", step3_mode="file"))
    assert "# tail 50" not in out


def test_slice_mode_backcompat_falls_back_to_step3(repo, ctx):
    risk = Chunk(id="chunk-03", size=ChunkSize.SMALL, files=["svc.py"],
                 hypothesis="x")
    out = s4._load_chunk_code(risk, ctx, repo,
                              _cfg_s4_slice(step4_mode=None, step3_mode="function"))
    assert "# tail 50" not in out


def test_graph_anchor_windows_prioritize_sink_line(repo, ctx):
    chunk = Chunk(
        id="large-01", size=ChunkSize.LARGE, risk_rank=1,
        files=["svc.py"],
        focus_entry_points=["handle"],
        hypothesis="x",
        sink_ref="svc.py:23",
    )
    text = s4._load_sliding_window(chunk, repo, ctx=ctx)
    assert "=== svc.py [lines" in text
    assert "   23|     return raw_query(s)" in text


# confirm/refute prompt + model dispatch

def test_confirm_refute_prompt_shape(ctx, taint_chunk):
    p = s4._build_confirm_refute_prompt(taint_chunk, ctx, "<CODE>")
    assert "confirm or refute" in p.lower()
    assert "handle()" in p and "ctrl.py" in p
    assert "dao.py:4" in p
    assert "CWE-89" in p
    assert "handle -> process -> raw_query" in p
    assert "<CODE>" in p
    assert "refuted_reason" in p
    # Gap-#2: sink_cwe MUST pull the CweKB block into the prompt — this is
    # the FP-reduction lever. cwe_kb.yaml ships a CWE-89 entry, so the KB
    # header + at-least-one sanitizer bullet must be present.
    assert "TAINT KB" in p
    assert "SANITIZERS" in p


def test_confirm_refute_prompt_no_kb_when_cwe_unknown(ctx, taint_chunk):
    """Agent-discovered sink (no seed CWE) → KB block omits itself and the
    prompt degrades to the pre-KB shape. class line falls back to 'infer'."""
    taint_chunk.sink_cwe = []
    p = s4._build_confirm_refute_prompt(taint_chunk, ctx, "<CODE>")
    assert "TAINT KB" not in p
    assert "(infer from sink)" in p


def _user_str(user) -> str:
    """Flatten a prompt arg (str or list[dict]) to plain text for assertions."""
    if isinstance(user, list):
        return "\n\n".join(b.get("text", "") for b in user
                             if isinstance(b, dict) and b.get("type") == "text")
    return user


def test_single_run_dispatches_confirm_refute_and_step_model(
        monkeypatch, ctx, taint_chunk):
    seen = {}

    def fake_prompt(user, *, model, **kw):
        seen["user"] = user
        seen["model"] = model
        return '{"findings": []}'

    monkeypatch.setattr(registry, "prompt", fake_prompt)
    s4._single_run(taint_chunk, ctx, "<CODE>", _cfg(prompt_mode="confirm_refute"))
    assert "confirm or refute" in _user_str(seen["user"]).lower()
    assert seen["model"].id == "claude-sonnet-4-6"     # models.deepdive applied


def test_single_run_legacy_under_discover_mode(
        monkeypatch, ctx, taint_chunk):
    seen = {}
    monkeypatch.setattr(registry, "prompt",
                        lambda u, *, model, **kw: (seen.update(
                            user=u, model=model) or '{"findings": []}'))
    s4._single_run(taint_chunk, ctx, "<CODE>", _cfg(prompt_mode="discover"))
    assert "RESEARCH LENS" in _user_str(seen["user"])     # legacy prompt
    assert seen["model"].id == "claude-sonnet-4-6"     # deepdive model


def test_single_run_non_taint_chunk_always_legacy(monkeypatch, ctx):
    seen = {}
    monkeypatch.setattr(registry, "prompt",
                        lambda u, *, model, **kw: (seen.update(
                            user=u, model=model) or '{"findings": []}'))
    risk = Chunk(id="chunk-01", size=ChunkSize.SMALL, files=["svc.py"],
                 hypothesis="x")
    s4._single_run(risk, ctx, "<CODE>", _cfg(prompt_mode="confirm_refute"))
    assert "RESEARCH LENS" in _user_str(seen["user"])
    assert seen["model"].id == "claude-sonnet-4-6"


def test_single_run_repairs_malformed_json_once(monkeypatch, ctx, taint_chunk):
    seen = []
    responses = iter([
        '{"findings": [{"file": "a.py", "line_start": 1, "line_end": 2',
        '{"findings": []}',
    ])

    def fake_prompt(user, *, model, **kw):
        seen.append(user)
        return next(responses)

    monkeypatch.setattr(registry, "prompt", fake_prompt)
    out = s4._single_run(taint_chunk, ctx, "<CODE>", _cfg(prompt_mode="discover"))

    assert out == []
    assert len(seen) == 2
    assert "REPAIR TASK" in seen[1]


# ─────────────────────────────────────────────────────────────────────────────
# Error accounting: a parse whose repair retry succeeds is a recovered
# transient and must not flip the stage to completed_with_errors; a chunk
# whose every run genuinely failed still must (marker dilution).
# ─────────────────────────────────────────────────────────────────────────────

def test_repaired_parse_closes_stage_plain_completed(monkeypatch, ctx,
                                                     taint_chunk):
    """A parse failure whose repair retry SUCCEEDS logs only a recovered=True
    record, so the stage closes as plain ``completed`` — the marker must not
    fire on a healthy run."""
    import json as _json

    from vvaharness.util import errlog
    from vvaharness.util.stage_telemetry import STAGES
    from vvaharness.util.status import stage

    responses = iter([
        '{"findings": [{"file": "a.py", "line_start": 1, "line_end": 2',
        '{"findings": []}',
    ])
    # Patch the ORIGIN, not a bound name: s4 calls _deepagents.dispatch_prompt,
    # whose non-deepagents branch resolves registry.prompt at call time (see the
    # stub_prompt fixture in conftest.py).
    from vvaharness.backends.llm import registry as _llm
    monkeypatch.setattr(_llm, "prompt", lambda u, *, model, **kw: next(responses))

    with stage("Step 4 — Deep dive", stage_id="s4"):
        out = s4._single_run(taint_chunk, ctx, "<CODE>",
                             _cfg(prompt_mode="discover"))

    assert out == []
    assert STAGES.snapshot()["s4"]["outcome"] == "completed"
    recs = [_json.loads(ln) for ln in
            errlog.current_path().read_text().splitlines() if ln.strip()]
    assert [r.get("recovered") for r in recs] == [True]  # diagnostic survives


def test_chunk_whose_every_run_fails_still_flips_stage_marker(
        monkeypatch, ctx, taint_chunk):
    """A parse failure whose repair ALSO fails raises out of the run; the run
    handler logs an UNMARKED record, so the stage closes
    ``completed_with_errors`` — real losses keep flipping the marker."""
    from pathlib import Path

    from vvaharness.util import errlog
    from vvaharness.util.stage_telemetry import STAGES
    from vvaharness.util.status import stage

    monkeypatch.setattr(s4, "_load_chunk_code", lambda *a, **k: "<CODE>")
    monkeypatch.setattr(s4, "_neighbor_context", lambda *a, **k: "")
    # Origin patch — see the note in the sibling test above.
    from vvaharness.backends.llm import registry as _llm
    monkeypatch.setattr(_llm, "prompt",
                        lambda u, *, model, **kw: '{"findings": [broken')

    with stage("Step 4 — Deep dive", stage_id="s4"):
        with pytest.raises(RuntimeError, match="all 1 run"):
            s4._deepdive_chunk(taint_chunk, ctx, Path("."),
                               _cfg(prompt_mode="discover"), 1, 1)

    assert STAGES.snapshot()["s4"]["outcome"] == "completed_with_errors"
    assert errlog.count_for_stage("s4", include_recovered=False) >= 1
