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

"""Behavioral tests for the taint threat-tag matching helper in s3_decompose.

The helper under test is the ``_threat_for(ep)`` closure inside
``_add_taint_chunks``. It associates a taint chunk with a threat by matching
the threat's ``surface`` against the entry function name on a whole-token /
exact basis. The security-relevant behavior:

  * exact (case-insensitive) name match wins outright;
  * otherwise the FIRST threat sharing a whole alphanumeric TOKEN with the
    function name is chosen;
  * it must NOT match a substring buried inside another token, and it must
    NOT match against the file PATH (over-tagging the coverage metric).

``_threat_for`` is a nested closure and cannot be imported, so we drive it
through the public ``_add_taint_chunks`` entry point and read the resulting
chunk's ``threat_id``.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fixtures.ctx_builders import make_ctx

from vvaharness.models import (
    Chunk,
    ContextPackage,
    EntryPoint,
    Sink,
    TaintEvidencePath,
    TaskManifest,
    Threat,
    ThreatModel,
)
from vvaharness.pipeline.stages import s3_decompose
from vvaharness.util import errlog
from vvaharness.util.counters import COUNTERS


# Global-state isolation: _count_loc / _count_chars consult module-level byte caches
# (_CHARS_CACHE, _LOC_CACHE) and tasks read process-wide COUNTERS; reset all three.
@pytest.fixture(autouse=True)
def _reset_module_state(monkeypatch):
    monkeypatch.setattr(s3_decompose, "_CHARS_CACHE", {}, raising=True)
    monkeypatch.setattr(s3_decompose, "_LOC_CACHE", {}, raising=True)
    COUNTERS.reset()
    yield
    COUNTERS.reset()


def _make_cfg():
    """Minimal cfg with the step3 knobs _add_taint_chunks reads."""
    step3 = SimpleNamespace(
        taint_chunks=True,
        taint_max_hops=8,
        taint_max_chunks=40,
        taint_files_per_hop=5,
        pack_by="loc",
        threat_surface_fallbacks=True,
        threat_fallback_max_files=12,
    )
    return SimpleNamespace(step3=step3)


def _threat(tid: str, surface: str) -> Threat:
    return Threat(
        id=tid,
        threat=f"threat {tid}",
        actor="remote_unauth",
        surface=surface,
        asset="user-data",
        impact="high",
        likelihood="likely",
    )


def _ctx_with(threats, *, fn="handle_login", ep_file="app/login.py",
              sink_fn="run_query", repo_root="/nonexistent-repo") -> ContextPackage:
    """ContextPackage with exactly one entry→sink taint path so that
    _add_taint_chunks emits exactly one taint chunk whose threat_id is the
    output of _threat_for(ep)."""
    ep_node = f"{ep_file}::{fn}"
    sink_node = f"{ep_file}::{sink_fn}"
    return ContextPackage(
        repo_root=repo_root,
        language="python",
        call_graph={ep_node: [sink_node]},
        entry_points=[EntryPoint(file=ep_file, function=fn, kind="network",
                                 reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file=ep_file, line=42, function=sink_fn)],
        all_files=[ep_file],
        threat_model=ThreatModel(threats=threats),
    )


def _run(ctx) -> TaskManifest:
    manifest = TaskManifest(chunks=[], rationale="test")
    n = s3_decompose._add_taint_chunks(manifest, ctx, _make_cfg())
    assert n == 1, f"expected exactly one taint chunk, got {n}"
    return manifest


def _taint_chunk(manifest: TaskManifest) -> Chunk:
    taints = [c for c in manifest.chunks if c.id.startswith("taint-")]
    assert len(taints) == 1
    return taints[0]


# Sanity: the harness actually produces a taint chunk we can inspect.
def test_taint_chunk_is_emitted_and_anchors_entry_function():
    manifest = _run(_ctx_with([_threat("T1", "handle_login")]))
    chunk = _taint_chunk(manifest)
    assert chunk.focus_entry_points == ["handle_login"]
    assert "app/login.py" in chunk.files


# Exact (case-insensitive) match wins.
def test_exact_match_assigns_threat_id():
    manifest = _run(_ctx_with([_threat("T1", "handle_login")]))
    assert _taint_chunk(manifest).threat_id == "T1"


def test_exact_match_is_case_insensitive():
    manifest = _run(_ctx_with([_threat("T7", "Handle_Login")],
                              fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T7"


def test_exact_match_beats_an_earlier_token_match():
    # T1 shares the "login" token (token match), but T2 is an exact match.
    # Exact must win even though it appears later in the list.
    threats = [_threat("T1", "login"), _threat("T2", "handle_login")]
    manifest = _run(_ctx_with(threats, fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T2"


# Whole-token match (no exact match available).
def test_shared_token_match_when_no_exact():
    # function "handle_login" shares token "login" with surface "login_v2".
    manifest = _run(_ctx_with([_threat("T9", "login_v2")], fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T9"


def test_first_token_sharing_threat_wins():
    # Both T1 and T2 share a token with handle_login; the FIRST in list wins.
    threats = [_threat("T1", "do_login"), _threat("T2", "handle_request")]
    manifest = _run(_ctx_with(threats, fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T1"


def test_token_match_is_case_insensitive():
    manifest = _run(_ctx_with([_threat("T3", "USER_LOGIN")], fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T3"


# Security-relevant negatives: no substring-in-token, no path matching.
def test_substring_inside_a_token_does_not_match():
    # surface "log" is a substring of the token "login" but is NOT a whole
    # token of "handle_login" → must NOT match.
    manifest = _run(_ctx_with([_threat("T5", "log")], fn="handle_login"))
    assert _taint_chunk(manifest).threat_id is None


def test_reverse_substring_does_not_match():
    # function token "auth" is a substring of surface token "authenticate";
    # token equality fails both directions → no match.
    manifest = _run(_ctx_with([_threat("T6", "authenticate")], fn="auth"))
    assert _taint_chunk(manifest).threat_id is None


def test_surface_matching_the_file_path_does_not_match():
    # The entry FILE path contains "login" (app/login.py) but the function is
    # "process". A surface equal to a path component must NOT tag the chunk —
    # matching is against the function NAME only, never the path.
    ctx = _ctx_with([_threat("T8", "login")], fn="process",
                    ep_file="app/login.py", sink_fn="run_query")
    manifest = _run(ctx)
    assert _taint_chunk(manifest).threat_id is None


def test_surface_matching_path_directory_does_not_match():
    ctx = _ctx_with([_threat("T8", "app")], fn="process",
                    ep_file="app/login.py", sink_fn="run_query")
    manifest = _run(ctx)
    assert _taint_chunk(manifest).threat_id is None


# Edge cases.
def test_empty_surface_is_skipped():
    # An empty-surface threat is ignored; the real token match still wins.
    threats = [_threat("T1", ""), _threat("T2", "login")]
    manifest = _run(_ctx_with(threats, fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T2"


def test_no_threats_yields_none():
    manifest = _run(_ctx_with([]))
    assert _taint_chunk(manifest).threat_id is None


def test_no_matching_threat_yields_none():
    manifest = _run(_ctx_with([_threat("T1", "totally_unrelated")],
                              fn="handle_login"))
    assert _taint_chunk(manifest).threat_id is None


def test_seed_taint_paths_are_promoted_into_taint_chunks():
    ctx = ContextPackage(
        repo_root="/nonexistent-repo",
        language="python",
        call_graph={},
        def_spans={
            "app/api.py::entry": [10, 30],
            "app/db.py::run_query": [40, 70],
        },
        entry_points=[EntryPoint(file="app/api.py", function="entry", kind="network",
                                 reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file="app/db.py", line=55, function="run_query",
                           cwe=["CWE-89"])],
        all_files=["app/api.py", "app/db.py"],
        seed_taint_paths=[["app/api.py:12", "app/db.py:55"]],
        threat_model=ThreatModel(threats=[_threat("T1", "entry")]),
    )
    manifest = TaskManifest(chunks=[], rationale="test")

    n = s3_decompose._add_taint_chunks(manifest, ctx, _make_cfg())

    assert n == 1
    chunk = _taint_chunk(manifest)
    assert chunk.source_ref == "app/api.py:12"
    assert chunk.sink_ref == "app/db.py:55"
    assert "CWE-89" in chunk.sink_cwe


def test_digit_tokens_participate_in_matching():
    # tokens are [a-z0-9]+, so a shared numeric token counts.
    manifest = _run(_ctx_with([_threat("T4", "endpoint_2")], fn="parse_2"))
    assert _taint_chunk(manifest).threat_id == "T4"


# Cross-check the documented tokenization regex directly so the behavioral
# expectations above are anchored to the same rule the source uses.
def test_tokenization_rule_matches_source_intent():
    """Exercise the module's OWN tokenizer, not a local copy of the pattern.

    This previously defined its own `re.findall` and asserted properties of
    that, so changing the real pattern left it green.
    """
    tok = s3_decompose._TOKEN_RX.findall
    assert tok("parse_2 endpoint_2") == ["parse", "2", "endpoint", "2"]
    # Lower-case only, so an upper-case run is skipped and only its
    # lower-case tail survives. Recorded because it is surprising.
    assert tok("HTTPServer") == ["erver"]
    assert tok("a1b2") == ["a1b2"]          # digits are word characters here

def test_threat_surface_fallback_adds_supply_chain_probe_chunk(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    app = tmp_path / "src"
    app.mkdir(parents=True)
    (app / "main.py").write_text("print('ok')\n", encoding="utf-8")

    ctx = ContextPackage(
        repo_root=str(tmp_path),
        language="python",
        all_files=[".github/workflows/ci.yml", "src/main.py"],
        threat_model=ThreatModel(threats=[
            Threat(
                id="T10",
                threat="CI/CD workflow tampering in build pipeline",
                actor="supply_chain",
                surface="github_actions",
                asset="release artifact",
                impact="high",
                likelihood="possible",
            )
        ]),
    )
    manifest = TaskManifest(
        chunks=[Chunk(id="spec-iac-01", files=[".github/workflows/ci.yml"], specialist="iac")],
        rationale="test",
    )

    n = s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, _make_cfg())

    assert n == 1
    fallback = next(c for c in manifest.chunks if c.id.startswith("threat-t10-fallback"))
    assert fallback.threat_id == "T10"
    assert ".github/workflows/ci.yml" in fallback.files


def test_threat_surface_fallback_adds_access_control_probe_chunk(tmp_path):
    svc = tmp_path / "src"
    svc.mkdir(parents=True)
    (svc / "authz.py").write_text("def allow(user):\n    return True\n", encoding="utf-8")
    (svc / "main.py").write_text("def run():\n    return 0\n", encoding="utf-8")

    ctx = ContextPackage(
        repo_root=str(tmp_path),
        language="python",
        all_files=["src/authz.py", "src/main.py"],
        threat_model=ThreatModel(threats=[
            Threat(
                id="T7",
                threat="Authorization policy bypass on tenant boundary",
                actor="remote_auth",
                surface="rbac policy",
                asset="tenant data",
                impact="high",
                likelihood="possible",
            )
        ]),
    )
    manifest = TaskManifest(chunks=[], rationale="test")

    n = s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, _make_cfg())

    assert n == 1
    fallback = next(c for c in manifest.chunks if c.id.startswith("threat-t7-fallback"))
    assert fallback.threat_id == "T7"
    assert "src/authz.py" in fallback.files


def test_threat_surface_fallback_skips_when_no_surface_candidates(tmp_path):
    p = tmp_path / "src"
    p.mkdir(parents=True)
    (p / "core.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    ctx = ContextPackage(
        repo_root=str(tmp_path),
        language="python",
        all_files=["src/core.py"],
        threat_model=ThreatModel(threats=[
            Threat(
                id="T99",
                threat="Air-gap side-channel in custom FPGA transport",
                actor="local_user",
                surface="fpga_dma",
                asset="compute node",
                impact="medium",
                likelihood="very_rare",
            )
        ]),
    )
    manifest = TaskManifest(chunks=[], rationale="test")

    n = s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, _make_cfg())

    assert n == 0
    assert all(c.threat_id != "T99" for c in manifest.chunks)


# ═════════════════════════════════════════════════════════════════════════════
# Prompt contract: the GROUNDING RULE, id-only file references, no "size".
# ═════════════════════════════════════════════════════════════════════════════

def test_system_prompt_states_the_file_inventory_grounding_rule():
    assert "GROUNDING RULE" in s3_decompose.SYSTEM
    assert "FILE INVENTORY" in s3_decompose.SYSTEM
    assert "file_ids" in s3_decompose.SYSTEM
    assert "focus_entry_point_ids" in s3_decompose.SYSTEM


def test_system_prompt_schema_no_longer_requests_a_size_field():
    assert '"size"' not in s3_decompose.SYSTEM


# ═════════════════════════════════════════════════════════════════════════════
# Id/path resolution: the rendered-view id map, suffix-tightened legacy path.
# ═════════════════════════════════════════════════════════════════════════════

def test_file_id_resolves_through_the_rendered_frontier_not_the_full_list(
    ctx_frontier_ne_full,
):
    """The whole point of ctx_frontier_ne_full: a 5-file frontier and the
    50-file full list disagree on what F001 names. Resolving against the
    full list (the old, wrong behaviour) would silently address a different
    file than the one actually offered to the model."""
    ctx = ctx_frontier_ne_full
    prompt_ctx = ctx.ast_context_view(max_files=5)
    assert sorted(ctx.all_files)[0] != sorted(prompt_ctx.all_files)[0]

    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=["F001"])], rationale="x")
    shapes = ["ids"]
    s3_decompose._normalize_chunk_files(manifest, ctx, prompt_ctx, shapes)

    expected = sorted(prompt_ctx.all_files)[0]
    assert manifest.chunks[0].files == [expected]
    assert expected != sorted(ctx.all_files)[0]


def test_resolution_rejects_an_object_other_than_the_one_rendered_from(
    ctx_frontier_ne_full,
):
    """The trip-wire a future refactor could otherwise silently defeat: if
    the id map is built from anything other than the exact object the
    prompt was rendered from, resolution must fail loudly, not address the
    wrong file quietly."""
    ctx = ctx_frontier_ne_full
    prompt_ctx = ctx.ast_context_view(max_files=5)
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=["F001"])], rationale="x")

    with pytest.raises(RuntimeError):
        s3_decompose._normalize_chunk_files(
            manifest, ctx, prompt_ctx, ["ids"],
            rendered_from_id=id(ctx))  # wrong object: ctx, not prompt_ctx


def test_unknown_file_id_is_dropped_and_counted():
    ctx = make_ctx(all_files=["a.py", "b.py", "c.py"])
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=["F999"])], rationale="x")

    s3_decompose._normalize_chunk_files(manifest, ctx, ctx, ["ids"])

    assert manifest.chunks[0].files == []
    assert COUNTERS.get("s3_unknown_file_ids") == 1


def test_legacy_files_shape_is_recorded_from_the_raw_json():
    data = {"chunks": [{"id": "chunk-01", "files": ["src/a.py"]}],
            "rationale": "x"}
    ctx = make_ctx(all_files=["src/a.py"])

    shapes, _raw_paths = s3_decompose._prepare_chunk_shapes(data, ctx)

    assert shapes == ["paths"]
    assert COUNTERS.snapshot()["s3_output_shape"] == "paths"


def test_id_shape_is_recorded_from_the_raw_json():
    data = {"chunks": [{"id": "chunk-01", "file_ids": ["F001"]}],
            "rationale": "x"}
    ctx = make_ctx(all_files=["src/a.py"])

    shapes, _raw_paths = s3_decompose._prepare_chunk_shapes(data, ctx)

    assert shapes == ["ids"]
    assert COUNTERS.snapshot()["s3_output_shape"] == "ids"


def test_invented_path_with_no_suffix_relation_is_dropped_not_relocated():
    """Regression pinned on the unique-basename case: an invented
    ``app/core/utils.py`` against a real ``vendor/third_party/utils.py`` — a
    bare-basename match would (wrongly) relocate this today; a suffix match
    correctly declines, because neither path is a "/"-anchored suffix of the
    other."""
    ctx = make_ctx(all_files=["vendor/third_party/utils.py"])
    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=["app/core/utils.py"])], rationale="x")

    s3_decompose._normalize_chunk_files(manifest, ctx, ctx, ["paths"])

    assert manifest.chunks[0].files == []
    assert COUNTERS.get("s3_dropped_paths") == 1


def test_model_dropped_directory_prefix_is_recovered_via_suffix_match():
    """The common, benign case the legacy path exists to recover: the model
    wrote ``core/utils.py`` for the real ``app/core/utils.py``."""
    ctx = make_ctx(all_files=["app/core/utils.py"])
    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=["core/utils.py"])], rationale="x")

    s3_decompose._normalize_chunk_files(manifest, ctx, ctx, ["paths"])

    assert manifest.chunks[0].files == ["app/core/utils.py"]
    assert COUNTERS.get("s3_relocated_paths") == 1


def test_relocation_is_recovered_and_does_not_flip_stage_marker():
    """A relocation SUCCEEDED — nothing was lost — so its errlog record is
    stamped recovered=True and the stage still closes plain ``completed``."""
    from vvaharness.util.stage_telemetry import STAGES
    from vvaharness.util.status import stage

    ctx = make_ctx(all_files=["app/core/utils.py"])
    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=["core/utils.py"])], rationale="x")

    with stage("Step 3 — Decompose", stage_id="s3"):
        s3_decompose._normalize_chunk_files(manifest, ctx, ctx, ["paths"])

    assert manifest.chunks[0].files == ["app/core/utils.py"]
    assert STAGES.snapshot()["s3"]["outcome"] == "completed"
    recs = [json.loads(ln) for ln in
            errlog.current_path().read_text().splitlines() if ln.strip()]
    assert [r.get("recovered") for r in recs] == [True]  # diagnostic survives


def test_dropped_path_still_flips_stage_marker():
    """A genuine drop is a real coverage loss: its record stays unmarked and
    the stage closes ``completed_with_errors``."""
    from vvaharness.util.stage_telemetry import STAGES
    from vvaharness.util.status import stage

    ctx = make_ctx(all_files=["vendor/third_party/utils.py"])
    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=["app/core/utils.py"])], rationale="x")

    with stage("Step 3 — Decompose", stage_id="s3"):
        s3_decompose._normalize_chunk_files(manifest, ctx, ctx, ["paths"])

    assert STAGES.snapshot()["s3"]["outcome"] == "completed_with_errors"
    assert errlog.count_for_stage("s3", include_recovered=False) == 1


def test_focus_entry_point_ids_resolve_to_function_names():
    """Chunk has no alias for focus_entry_points (unlike files/file_ids), so
    an id-shaped focus_entry_point_ids value has to be resolved in the RAW
    dict, before Pydantic validation silently drops the unrecognised key."""
    ctx = make_ctx(
        all_files=["app/api.py"],
        entry_points=[EntryPoint(file="app/api.py", function="handle",
                                 kind="network")],
    )
    data = {"chunks": [{"id": "chunk-01", "file_ids": ["F001"],
                        "focus_entry_point_ids": ["E001"]}],
            "rationale": "x"}

    s3_decompose._prepare_chunk_shapes(data, ctx)

    assert data["chunks"][0]["focus_entry_points"] == ["handle"]


# ═════════════════════════════════════════════════════════════════════════════
# Empty-chunk guard.
# ═════════════════════════════════════════════════════════════════════════════

def test_chunk_with_no_resolvable_files_is_dropped():
    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=[]), Chunk(id="c2", files=["x.py"])],
        rationale="x")

    s3_decompose._drop_empty_chunks(manifest)

    assert [c.id for c in manifest.chunks] == ["c2"]
    assert COUNTERS.get("s3_dropped_empty_chunks") == 1


# ═════════════════════════════════════════════════════════════════════════════
# Taint chunks are excluded from the generic oversize-risk-chunk splitter.
# ═════════════════════════════════════════════════════════════════════════════

def test_taint_chunks_are_not_split_by_the_generic_oversize_splitter(tmp_path):
    files = []
    for i in range(3):
        p = tmp_path / f"f{i}.py"
        p.write_text("x\n" * 50, encoding="utf-8")
        files.append(f"f{i}.py")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=files)
    chunk = Chunk(id="taint-01", files=files, source_ref="f0.py::a",
                 sink_ref="f2.py:1", path_funcs=["f0.py::a", "f2.py::b"])
    manifest = TaskManifest(chunks=[chunk], rationale="x")
    cfg = SimpleNamespace(step3=SimpleNamespace(
        risk_chunk_loc=10, max_files_per_chunk=1, pack_by="loc"))

    s3_decompose._split_oversize_risk_chunks(manifest, ctx, cfg)

    assert len(manifest.chunks) == 1
    assert manifest.chunks[0].id == "taint-01"
    assert manifest.chunks[0].files == files
    assert manifest.chunks[0].source_ref == "f0.py::a"


# ═════════════════════════════════════════════════════════════════════════════
# Sanitizer gating is CWE-specific, decided at sink arrival, not per hop.
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("fn", ["validate", "clean", "sanitize", "validate_user"])
def test_generic_validation_names_are_not_proven_sanitizers(fn):
    """Bare `validate`/`clean` must NOT suppress a taint path.

    The names matter: an earlier version of this test only used
    `validate_user`, which never matched the *bare* name under either the old
    or the new set — so it passed whether or not the generic names were
    treated as universal sanitizers, and could not detect them coming back.
    A function called `validate` is no evidence that a value is safe for any
    particular sink class, and treating it as such silently drops real
    command-injection findings.
    """
    graph = {"a::h": [f"a::{fn}"], f"a::{fn}": ["a::run_cmd"]}
    sinks = {"a::run_cmd"}
    sink_by_qn = {"a::run_cmd": [SimpleNamespace(cwe=["CWE-78"])]}

    hits = s3_decompose._bfs_to_sinks("a::h", graph, sinks, 8, sink_by_qn)

    assert hits, f"{fn}() must not silently sanitize a command sink"


def test_generic_validation_names_are_absent_from_both_sanitizer_sets():
    """Pin the sets directly as well, so the intent survives a refactor of the
    traversal that might stop consulting them in this shape."""
    for name in ("validate", "clean", "sanitize"):
        assert name not in s3_decompose._SANITIZER_UNIVERSAL
        assert name not in s3_decompose._SANITIZER_CLASS_NAMES


def test_to_int_sanitizes_a_sql_injection_sink():
    graph = {"a::h": ["a::to_int"], "a::to_int": ["a::run_query"]}
    sinks = {"a::run_query"}
    sink_by_qn = {"a::run_query": [SimpleNamespace(cwe=["CWE-89"])]}

    hits = s3_decompose._bfs_to_sinks("a::h", graph, sinks, 8, sink_by_qn)

    assert hits == []


def test_to_int_does_not_sanitize_a_command_injection_sink():
    """The same coercion that neutralizes CWE-89 does nothing for a command
    sink reached via a different path — the CWE-gated check must be
    evaluated per arriving sink, not fired universally the moment the name
    is seen."""
    graph = {"a::h": ["a::to_int"], "a::to_int": ["a::run_cmd"]}
    sinks = {"a::run_cmd"}
    sink_by_qn = {"a::run_cmd": [SimpleNamespace(cwe=["CWE-78"])]}

    hits = s3_decompose._bfs_to_sinks("a::h", graph, sinks, 8, sink_by_qn)

    assert hits


def test_universal_sanitizer_still_blocks_every_sink_class():
    graph = {"a::h": ["a::html_escape"], "a::html_escape": ["a::run_cmd"]}
    sinks = {"a::run_cmd"}
    sink_by_qn = {"a::run_cmd": [SimpleNamespace(cwe=["CWE-78"])]}

    hits = s3_decompose._bfs_to_sinks("a::h", graph, sinks, 8, sink_by_qn)

    assert hits == []


# ═════════════════════════════════════════════════════════════════════════════
# The dead `sanitized` guard is gone: s1 never sets the flag, so honouring it
# only ever suppressed real taint chunks. Now the flag is ignored outright.
# ═════════════════════════════════════════════════════════════════════════════

def test_seed_evidence_sanitized_flag_no_longer_suppresses_the_chunk():
    ctx = make_ctx(
        all_files=["app/api.py", "app/db.py"],
        entry_points=[EntryPoint(file="app/api.py", function="entry",
                                 kind="network", reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file="app/db.py", line=10, function="run_query")],
        seed_taint_evidence=[TaintEvidencePath(
            source_ref="app/api.py::entry",
            sink_ref="app/db.py:10",
            path_funcs=["app/api.py::entry", "app/db.py::run_query"],
            sanitized=True,
        )],
    )
    manifest = TaskManifest(chunks=[], rationale="test")

    n = s3_decompose._add_taint_chunks(manifest, ctx, _make_cfg())

    assert n == 1


# ═════════════════════════════════════════════════════════════════════════════
# Seed matching is keyed on (file, function): N functions in one file emit
# N chunks, not N^2 — and chunks sharing an identical resolved file set merge
# into one chunk recording every contributing function.
# ═════════════════════════════════════════════════════════════════════════════

def test_multi_function_seed_evidence_in_one_file_merges_to_one_chunk(
    ctx_taint_multi,
):
    manifest = TaskManifest(chunks=[], rationale="test")

    n = s3_decompose._add_taint_chunks(manifest, ctx_taint_multi, _make_cfg())

    # Before this fix, matching by file alone made every one of the 3
    # entry-point functions in app/handlers.py pull in all 3 evidence
    # entries (3 x 3 = 9 near-duplicate chunks). Matching by (file, function)
    # alone would bring that down to 3; merging chunks that resolve to an
    # identical file set collapses it further, to exactly 1.
    assert n == 1
    taints = [c for c in manifest.chunks if c.id.startswith("taint-")]
    assert len(taints) == 1
    assert sorted(taints[0].focus_entry_points) == ["func_a", "func_b", "func_c"]


# A suspected over-cap-bucket defect was checked directly against the
# packing logic and does NOT reproduce for multi-file buckets: the cap check
# runs BEFORE a candidate is added to the running bucket, so a multi-file
# bucket can never exceed max_loc/max_chars/max_files. Only a single file
# whose own size already exceeds the cap can produce an over-cap bucket, and
# that is structurally unavoidable (a file cannot be split further). No
# enforcement change was made; this pins that fact as a permanent regression
# guard.
# ═════════════════════════════════════════════════════════════════════════════

def test_pack_never_lets_a_multi_file_bucket_exceed_the_cap(tmp_path):
    (tmp_path / "a.py").write_text("\n".join(["x"] * 10), encoding="utf-8")
    (tmp_path / "big.py").write_text("\n".join(["x"] * 300), encoding="utf-8")
    (tmp_path / "b.py").write_text("\n".join(["x"] * 10), encoding="utf-8")
    (tmp_path / "c.py").write_text("\n".join(["x"] * 10), encoding="utf-8")
    groups = [("g", ["a.py", "big.py", "b.py", "c.py"])]

    buckets = s3_decompose._pack(groups, tmp_path, max_loc=100, max_files=100)

    for _, files, loc in buckets:
        if len(files) > 1:
            assert loc <= 100, f"multi-file bucket {files} exceeded the cap"
    # The one legitimately-unavoidable over-cap bucket is the single
    # oversize file, alone.
    over_cap_single = [f for _, files, loc in buckets
                       if len(files) == 1 and loc > 100 for f in files]
    assert over_cap_single == ["big.py"]


def test_pack_bumps_the_bucket_counter(tmp_path):
    (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
    groups = [("g", ["a.py"])]

    buckets = s3_decompose._pack(groups, tmp_path, max_loc=100, max_files=100)

    assert COUNTERS.get("s3_buckets") == len(buckets) == 1


# ═════════════════════════════════════════════════════════════════════════════
# _pack coalesces ADJACENT under-filled buckets (step3.pack_merge_underfilled).
# Without it the loop above emits at least one bucket per cohesion group and
# never back-fills, so bucket count tracks GROUP count instead of code volume
# — and every bucket costs one s4 model call per lens. The properties pinned
# here, in order: collapse with provenance in the label; both caps still bind;
# the flattened file sequence is bit-identical to the unmerged output (the
# security-critical property — a lost file is a lost lens sweep); the kill
# switch reproduces the one-bucket-per-group output exactly; a single oversize
# file stays isolated (and only ADJACENT buckets ever merge); the specialist
# pass stops paying per-directory; char-mode packing coalesces on chars.
# ═════════════════════════════════════════════════════════════════════════════

def _singleton_groups(tmp_path, n: int, loc: int, prefix: str = "pkg"):
    """`n` one-file cohesion groups of `loc` lines each, worst case for the
    one-bucket-per-group behaviour. Returns (groups, files) in emission order."""
    files = []
    for i in range(n):
        d = tmp_path / f"{prefix}{i:02d}"
        d.mkdir()
        rel = f"{prefix}{i:02d}/mod.py"
        (tmp_path / rel).write_text("\n".join(["x"] * loc), encoding="utf-8")
        files.append(rel)
    return [(f"{prefix}{i:02d}", [files[i]]) for i in range(n)], files


def test_underfilled_singleton_groups_coalesce_to_one_bucket(tmp_path):
    groups, files = _singleton_groups(tmp_path, n=10, loc=10)

    buckets = s3_decompose._pack(groups, tmp_path, max_loc=10000, max_files=40)

    assert len(buckets) == 1
    label, bucket_files, loc = buckets[0]
    assert bucket_files == files
    assert loc == 100
    # The label keeps provenance: first group's name plus a fold count.
    assert label == "pkg00 (+9 more groups)"


def test_coalescing_stops_at_the_loc_cap(tmp_path):
    # 12 × 25 LOC against a 100-LOC cap packs 4 files per bucket exactly:
    # ceil(12·25 / 100) = 3 buckets, and none may breach either cap.
    groups, files = _singleton_groups(tmp_path, n=12, loc=25)

    buckets = s3_decompose._pack(groups, tmp_path, max_loc=100, max_files=100)

    assert len(buckets) == 3
    for _, bucket_files, loc in buckets:
        assert loc <= 100
        assert len(bucket_files) <= 100


def test_coalescing_stops_at_the_file_cap(tmp_path):
    # 10 one-line files against a 4-file cap: ceil(10 / 4) = 3 buckets.
    groups, files = _singleton_groups(tmp_path, n=10, loc=1)

    buckets = s3_decompose._pack(groups, tmp_path, max_loc=10000, max_files=4)

    assert len(buckets) == 3
    assert [len(bf) for _, bf, _ in buckets] == [4, 4, 2]


def test_coalescing_preserves_file_union_and_order(tmp_path):
    # Mixed shape — a two-file group, an oversize single file, then three
    # singletons — exercises the skip-merge, isolate, and fold branches in
    # one pass. The flattened file sequence must be bit-identical either way:
    # a dropped or duplicated file here means a lost or double lens sweep.
    for name, loc in (("a.py", 10), ("b.py", 10), ("big.py", 300),
                      ("c.py", 10), ("d.py", 10), ("e.py", 10)):
        (tmp_path / name).write_text("\n".join(["x"] * loc), encoding="utf-8")
    groups = [("g1", ["a.py", "b.py"]), ("g2", ["big.py"]),
              ("g3", ["c.py"]), ("g4", ["d.py"]), ("g5", ["e.py"])]

    plain = s3_decompose._pack(groups, tmp_path, max_loc=100, max_files=3,
                               merge_underfilled=False)
    merged = s3_decompose._pack(groups, tmp_path, max_loc=100, max_files=3)

    flatten = lambda bs: [f for _, bf, _ in bs for f in bf]
    assert flatten(merged) == flatten(plain)
    assert len(flatten(merged)) == len(set(flatten(merged)))
    # And the merge actually happened where the caps allowed it.
    assert [bf for _, bf, _ in merged] == [
        ["a.py", "b.py"], ["big.py"], ["c.py", "d.py", "e.py"]]


def test_merge_kill_switch_reproduces_the_unmerged_packing(tmp_path):
    # step3.pack_merge_underfilled: false is the escape hatch if a target
    # regresses — it must restore the one-bucket-per-group output exactly,
    # labels and loc included, not merely the same file coverage.
    groups, files = _singleton_groups(tmp_path, n=10, loc=10)

    buckets = s3_decompose._pack(groups, tmp_path, max_loc=10000, max_files=40,
                                 merge_underfilled=False)

    assert buckets == [(f"pkg{i:02d}", [files[i]], 10) for i in range(10)]


def test_single_oversize_file_stays_isolated_and_still_warns(tmp_path, capsys):
    for name, loc in (("a.py", 10), ("big.py", 300), ("b.py", 10)):
        (tmp_path / name).write_text("\n".join(["x"] * loc), encoding="utf-8")
    groups = [("g1", ["a.py"]), ("g2", ["big.py"]), ("g3", ["b.py"])]

    buckets = s3_decompose._pack(groups, tmp_path, max_loc=100, max_files=100)

    # The oversize file neither absorbs a neighbour nor merges forward — and
    # because merging is ADJACENT-only, a.py and b.py (separated by it) stay
    # apart too, even though their union would fit the cap.
    assert [bf for _, bf, _ in buckets] == [["a.py"], ["big.py"], ["b.py"]]
    assert "single file exceeds the shard cap alone" in capsys.readouterr().err


def test_specialist_chunks_coalesce_across_singleton_directories(tmp_path):
    # 30 one-file directories totalling far under one specialist_chunk_loc
    # used to emit 30 chunks PER LENS (one model call each). Coalescing must
    # bring that to one chunk per lens with the identical file coverage.
    n_dirs = 30
    all_files = []
    for i in range(n_dirs):
        d = tmp_path / f"d{i:02d}"
        d.mkdir()
        rel = f"d{i:02d}/m.py"
        # One AES mention keeps the crypto lens gated ON (see _gate_specialists).
        content = ("AES = 1\n" if i == 0
                   else f"def fn{i}():\n    return {i}\n")
        (tmp_path / rel).write_text(content, encoding="utf-8")
        all_files.append(rel)
    ctx = make_ctx(repo_root=str(tmp_path), all_files=all_files)
    manifest = TaskManifest(chunks=[], rationale="x")
    cfg = SimpleNamespace(step3=SimpleNamespace(
        specialists=["crypto", "logic-bug"],
        specialist_chunk_loc=6000, max_files_per_chunk=80, pack_by="loc"))

    n_added = s3_decompose._add_specialist_chunks(manifest, ctx, cfg)

    assert n_added == 2  # one chunk per lens, not one per directory per lens
    by_lens: dict[str, list] = {}
    for c in manifest.chunks:
        by_lens.setdefault(c.specialist, []).append(c)
    assert set(by_lens) == {"crypto", "logic-bug"}
    for chunks in by_lens.values():
        assert len(chunks) == 1
        assert chunks[0].files == all_files


def test_pack_by_chars_coalesces_and_respects_the_char_cap(tmp_path):
    # 10 × 100-byte files against a 400-char cap: 4 per bucket, so 3 buckets.
    # max_loc=1 on purpose — in char mode the LOC cap must play no part in
    # the coalescing decision, exactly as it plays none in _pack's own split.
    files = []
    for i in range(10):
        rel = f"f{i}.py"
        (tmp_path / rel).write_text("x" * 99 + "\n", encoding="utf-8")
        files.append(rel)
    groups = [(f"g{i}", [files[i]]) for i in range(10)]

    buckets = s3_decompose._pack(groups, tmp_path, max_loc=1, max_files=100,
                                 max_chars=400)

    assert len(buckets) == 3
    for _, bucket_files, _ in buckets:
        assert sum(s3_decompose._count_chars(tmp_path / f)
                   for f in bucket_files) <= 400
    assert [f for _, bf, _ in buckets for f in bf] == files


# ═════════════════════════════════════════════════════════════════════════════
# Language tagging runs after every chunk producer, including threat-surface
# fallback chunks.
# ═════════════════════════════════════════════════════════════════════════════

def test_threat_fallback_chunks_are_language_tagged(stub_prompt, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "authz.py").write_text(
        "def allow(user):\n    return True\n", encoding="utf-8")
    ctx = make_ctx(
        repo_root=str(tmp_path),
        all_files=["src/authz.py"],
        threat_model=ThreatModel(threats=[
            Threat(id="T7", threat="Authorization bypass on tenant boundary",
                  actor="remote_auth", surface="rbac policy",
                  asset="tenant data", impact="high", likelihood="possible"),
        ]),
    )
    stub_prompt.set_response("s3", json.dumps({"chunks": [], "rationale": "x"}))
    cfg = SimpleNamespace(step3=SimpleNamespace(),
                          models=SimpleNamespace(decompose="stub-model"))

    manifest = s3_decompose.run(ctx, cfg)

    fallback = [c for c in manifest.chunks if c.id.startswith("threat-")]
    assert fallback, "expected a threat-surface fallback chunk for T7"
    assert fallback[0].languages == ["python"]


# ═════════════════════════════════════════════════════════════════════════════
# Threat-surface candidate ordering: entry-point hits survive truncation.
# ═════════════════════════════════════════════════════════════════════════════

def test_entry_point_hit_survives_truncation_to_one_file():
    ctx = make_ctx(
        all_files=["auth/login.py", "misc/utils.py"],
        entry_points=[EntryPoint(file="auth/login.py", function="handle_login",
                                 kind="network", reachable_from_unauth=True)],
    )
    t = Threat(id="T1", threat="crypto weakness in handle_login",
              actor="remote_unauth", surface="handle_login", asset="x",
              impact="high", likelihood="likely")
    specialist_files = {"crypto": ["misc/utils.py"]}

    files = s3_decompose._candidate_files_for_threat(
        t, ctx, specialist_files, max_files=1)

    assert files == ["auth/login.py"]


# ═════════════════════════════════════════════════════════════════════════════
# `controls` (mitigation text) no longer drives file selection.
# ═════════════════════════════════════════════════════════════════════════════

def test_controls_text_is_excluded_from_threat_text():
    t = Threat(id="T1", threat="something unrelated", actor="local_user",
              surface="something", asset="x", impact="high",
              likelihood="likely", controls="JWT signature validation enforced")

    txt = s3_decompose._threat_text(t)

    assert "jwt" not in txt.lower()


# ═════════════════════════════════════════════════════════════════════════════
# `.d.ts` ambient declaration files are excluded from generic source
# eligibility (`.map` and documentation extensions were already excluded
# upstream — no code or test change needed for those, confirmed no-ops).
# ═════════════════════════════════════════════════════════════════════════════

def test_ambient_typescript_declaration_files_are_not_source():
    assert s3_decompose._is_source("src/types.d.ts") is False
    assert s3_decompose._is_source("src/types.ts") is True


# ═════════════════════════════════════════════════════════════════════════════
# Extension-less convention filenames and shebang scripts get a known
# language, so they can land in the unknown-language fail-safe.
# ═════════════════════════════════════════════════════════════════════════════

def test_makefile_and_shebang_script_resolve_to_a_known_language(tmp_path):
    (tmp_path / "Makefile").write_text("build:\n\techo hi\n", encoding="utf-8")
    (tmp_path / "deploy").write_text(
        "#!/usr/bin/env bash\necho hi\n", encoding="utf-8")

    assert s3_decompose._lang_of_file("Makefile", tmp_path) == "make"
    assert s3_decompose._lang_of_file("deploy", tmp_path) == "shell"
    # Without a repo_root there is no I/O, so a shebang-only file's language
    # stays unknown rather than silently reading the filesystem.
    assert s3_decompose._lang_of_file("deploy") is None


# ═════════════════════════════════════════════════════════════════════════════
# the coverage hole: non-source eligible files get force-added back
# after the reachable_only prune; the source file stays dropped (logic-bug
# covers it unconditionally instead).
# ═════════════════════════════════════════════════════════════════════════════

def test_non_source_eligible_files_are_never_left_unreviewed(repo_extensionless):
    all_files = ["Makefile", "config/service.conf", "bin/deploy",
                "src/unreachable.py"]
    ctx = make_ctx(
        repo_root=str(repo_extensionless),
        all_files=all_files,
        entry_points=[EntryPoint(file="app.py", function="h", kind="network")],
        unsafe_sinks=[Sink(file="db.py", line=1, function="q")],
        # A REAL, non-empty call graph in "src/unreachable.py"'s own language
        # (python) — this is what makes that language "covered" by the graph
        # engine, so the unknown-language fail-safe correctly does NOT widen
        # this specific, disconnected file back in. An empty call graph would
        # make python's coverage "unknown" too, and the fail-safe would
        # (correctly, per its own purpose) treat every python file as
        # reachable — which is a different scenario than the one this test
        # targets.
        call_graph={"app.py::h": ["db.py::q"]},
    )
    manifest = TaskManifest(chunks=[], rationale="x")
    cfg = SimpleNamespace(step3=SimpleNamespace(
        catchall_mode="reachable_only", catchall_enabled=True, pack_by="loc"))

    s3_decompose._add_catchall_chunks(manifest, ctx, cfg)

    covered = {f for c in manifest.chunks for f in c.files}
    assert "Makefile" in covered
    assert "config/service.conf" in covered
    assert "bin/deploy" in covered
    assert "src/unreachable.py" not in covered
    assert "src/unreachable.py" in manifest.unreachable_files
    # Makefile and bin/deploy are rescued by the OTHER mechanism (the basename-table mechanism's
    # basename-table / shebang language detection feeds the unknown-language
    # fail-safe, so the graph never even considers them unreachable).
    # config/service.conf has no basename convention and no shebang, so it
    # is the one file that actually needs the force-add backstop here —
    # a real demonstration of the two fixes covering different files.
    assert COUNTERS.get("s3_forced_coverage_files") == 1


def test_catchall_mode_all_is_unaffected_by_the_force_add_rule():
    all_files = ["Makefile", "src/reachable.py"]
    ctx = make_ctx(repo_root="/nonexistent", all_files=all_files)
    manifest = TaskManifest(chunks=[], rationale="x")
    cfg = SimpleNamespace(step3=SimpleNamespace(
        catchall_mode="all", catchall_enabled=True, pack_by="loc"))

    s3_decompose._add_catchall_chunks(manifest, ctx, cfg)

    covered = {f for c in manifest.chunks for f in c.files}
    assert covered == set(all_files)
    assert COUNTERS.get("s3_forced_coverage_files") == 0


# ═════════════════════════════════════════════════════════════════════════════
# cohesive grouping keys on the immediate parent directory, not the
# whole depth-2 path (which made every depth-2 file its own group).
# ═════════════════════════════════════════════════════════════════════════════

def test_depth_two_files_group_by_parent_directory_not_by_file():
    ctx = make_ctx(all_files=[])

    groups = s3_decompose._cohesive_groups(
        ["main.py", "src/a.py", "src/b.py", "src/sub/c.py"], ctx)

    by_key = dict(groups)
    assert by_key["."] == ["main.py"]
    assert sorted(by_key["src"]) == ["src/a.py", "src/b.py"]
    assert by_key["src/sub"] == ["src/sub/c.py"]


def test_cohesion_group_overflow_merges_the_smallest_sibling_first():
    ctx = make_ctx(all_files=[])
    files = [f"pkg{i}/mod.py" for i in range(5)]

    groups = s3_decompose._cohesive_groups(files, ctx, max_groups=2)

    assert len(groups) <= 2
    assert sum(len(fs) for _, fs in groups) == 5


def test_cohesive_groups_bumps_the_group_counter():
    ctx = make_ctx(all_files=[])

    s3_decompose._cohesive_groups(["a.py", "src/b.py"], ctx)

    assert COUNTERS.get("s3_cohesion_groups") == 2


# ═════════════════════════════════════════════════════════════════════════════
# _count_loc is memoized the same way _count_chars already is.
# ═════════════════════════════════════════════════════════════════════════════

def test_count_loc_reads_the_file_at_most_once(tmp_path, monkeypatch):
    p = tmp_path / "f.py"
    p.write_text("a\nb\nc\n", encoding="utf-8")
    real_open = Path.open
    opens: list[Path] = []

    def counting_open(self, *a, **kw):
        opens.append(self)
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "open", counting_open)

    first = s3_decompose._count_loc(p)
    second = s3_decompose._count_loc(p)

    assert first == second == 3
    assert opens.count(p) == 1


# ═════════════════════════════════════════════════════════════════════════════
# the entry-point -> function index is built once per s3 run, not once
# per shard per lens.
# ═════════════════════════════════════════════════════════════════════════════

def test_specialist_entry_point_index_is_built_once_per_run(tmp_path):
    n_files = 4
    for i in range(n_files):
        (tmp_path / f"m{i}.py").write_text(
            f"def fn{i}():\n    return {i}  # AES\n", encoding="utf-8")
    all_files = [f"m{i}.py" for i in range(n_files)]

    class _CountingDict(dict):
        call_count = 0

        def items(self):
            _CountingDict.call_count += 1
            return super().items()

    cgf = _CountingDict({f"fn{i}": [f"m{i}.py:1"] for i in range(n_files)})
    ctx = make_ctx(repo_root=str(tmp_path), all_files=all_files,
                   call_graph_files=cgf)
    manifest = TaskManifest(chunks=[], rationale="x")
    cfg = SimpleNamespace(step3=SimpleNamespace(
        specialists=["crypto", "logic-bug"],
        specialist_chunk_loc=1, max_files_per_chunk=1, pack_by="loc"))

    s3_decompose._add_specialist_chunks(manifest, ctx, cfg)

    kinds = {c.specialist for c in manifest.chunks}
    assert kinds == {"crypto", "logic-bug"}
    assert len(manifest.chunks) > 2, "expected multiple shards x multiple lenses"
    assert _CountingDict.call_count == 1


# ═════════════════════════════════════════════════════════════════════════════
# An unknown-language fail-open concern was reproduced before fixing it: a
# single entry point registered in a language the call-graph engine never
# actually parsed was enough to mark that whole language "covered,"
# defeating the unknown-language fail-safe for every OTHER file in it.
# Verified against the pre-fix code before implementing the fix: with one
# EntryPoint in "app.py" and an EMPTY call graph, `_reachable_files` returned
# only {"app.py"} — the three other python files were excluded even though
# the graph engine has provably zero real support for python in this
# repository. Fixed by deriving `covered_langs` only from files the graph
# itself produced a node for.
# ═════════════════════════════════════════════════════════════════════════════

def test_unknown_language_failsafe_is_not_defeated_by_a_single_entry_point():
    ctx = make_ctx(
        all_files=["app.py", "other1.py", "other2.py", "other3.py"],
        entry_points=[EntryPoint(file="app.py", function="h", kind="network")],
        call_graph={},
    )

    reach = s3_decompose._reachable_files(ctx)

    assert {"other1.py", "other2.py", "other3.py"} <= reach


# ═════════════════════════════════════════════════════════════════════════════
# A sparsity-denominator bias concern was also reproduced before fixing it:
# the ratio was computed over `eligible` (files still uncovered after
# risk/taint chunks already claimed some), not over every catch-all-eligible
# file in the repo. Verified against the pre-fix code: 8 of 10 eligible files
# were genuinely reachable, but 7 of
# those 8 were already covered by an earlier chunk before the ratio was
# computed, leaving only 1 reachable / 3 remaining "eligible" = 33% — below a
# 50% min_ratio, wrongly triggering the mode=all fallback and letting 2
# genuinely-unreachable files into a catch-all chunk. Fixed by computing the
# ratio over every catch-all-eligible file regardless of prior coverage.
# ═════════════════════════════════════════════════════════════════════════════

def _t19_ctx_and_manifest():
    reachable = [f"reachable_{i}.py" for i in range(8)]
    unreachable = [f"unreachable_{i}.py" for i in range(2)]
    call_graph = {f"{reachable[i]}::f": [f"{reachable[i + 1]}::f"]
                 for i in range(len(reachable) - 1)}
    ctx = make_ctx(
        all_files=reachable + unreachable,
        entry_points=[EntryPoint(file=reachable[0], function="f", kind="network")],
        unsafe_sinks=[Sink(file=reachable[0], line=1, function="f")],
        call_graph=call_graph,
    )
    # Simulate risk/taint chunks having already claimed 7 of the 8 reachable
    # files before the catch-all pass runs — exactly why they are NOT in
    # `eligible` when the sparsity ratio gets computed.
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=reachable[:7])], rationale="x")
    return ctx, manifest, reachable, unreachable


def test_sparsity_ratio_is_not_biased_by_files_already_covered_elsewhere():
    ctx, manifest, reachable, unreachable = _t19_ctx_and_manifest()
    cfg = SimpleNamespace(step3=SimpleNamespace(
        catchall_enabled=True, catchall_mode="reachable_only",
        catchall_reachable_min_ratio=0.5, catchall_reachable_min_files=0,
        pack_by="loc"))

    s3_decompose._add_catchall_chunks(manifest, ctx, cfg)

    covered = {f for c in manifest.chunks for f in c.files}
    assert not (set(unreachable) & covered), (
        "the biased ratio would wrongly fall back to mode=all and let "
        "unreachable files into a catch-all chunk")
    assert set(manifest.unreachable_files) == set(unreachable)


# ═════════════════════════════════════════════════════════════════════════════
# threat-surface fallback: baseline exemption and a chunk-count cap.
# ═════════════════════════════════════════════════════════════════════════════

def test_baseline_derived_threats_are_exempt_from_fallback_chunks_and_denominator(
    capsys,
):
    baseline_threat = Threat(
        id="T1", threat="OWASP baseline placeholder", actor="remote_unauth",
        surface="generic_web_surface", asset="app", impact="medium",
        likelihood="rare", evidence="baseline: BL-WEB-A01")
    real_threat = Threat(
        id="T2", threat="Authorization bypass", actor="remote_auth",
        surface="rbac policy", asset="tenant data", impact="high",
        likelihood="possible")
    ctx = make_ctx(
        all_files=["src/authz.py"],
        threat_model=ThreatModel(threats=[baseline_threat, real_threat]),
    )
    manifest = TaskManifest(chunks=[], rationale="x")

    s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, _make_cfg())

    assert all(c.threat_id != "T1" for c in manifest.chunks), (
        "a baseline-derived threat must never get a dedicated fallback chunk")

    # The coverage denominator excludes the baseline threat entirely — it
    # must never appear in the printed ratio's UNCOVERED list, even though
    # it has no chunk citing it.
    s3_decompose._report_threat_coverage(manifest, ctx)
    printed = capsys.readouterr().err
    assert "T1" not in printed
    assert "1/1 threats" in printed  # denominator is just T2, not T1+T2


def test_fallback_chunk_count_is_capped(tmp_path):
    (tmp_path / "src").mkdir()
    threats = []
    for i in range(20):
        d = tmp_path / "src" / f"svc{i}"
        d.mkdir()
        (d / "authz.py").write_text("def allow():\n    return True\n",
                                    encoding="utf-8")
        threats.append(Threat(
            id=f"T{i}", threat=f"Authorization bypass {i}", actor="remote_auth",
            surface=f"rbac_policy_{i}", asset="tenant data", impact="high",
            likelihood="possible"))
    all_files = [f"src/svc{i}/authz.py" for i in range(20)]
    ctx = make_ctx(repo_root=str(tmp_path), all_files=all_files,
                   threat_model=ThreatModel(threats=threats))
    manifest = TaskManifest(chunks=[], rationale="x")
    step3 = SimpleNamespace(
        taint_chunks=False, threat_surface_fallbacks=True,
        threat_fallback_max_files=12, max_threat_fallback_chunks=5)
    cfg = SimpleNamespace(step3=step3)

    n = s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, cfg)

    assert n == 5
    assert COUNTERS.get("s3_fallback_chunks_dropped") == 15


# ═════════════════════════════════════════════════════════════════════════════
# specialist chunks emit shard-major, tagged with shard_id; the file
# set each lens sees is unchanged (a reordering, not a narrowing).
# ═════════════════════════════════════════════════════════════════════════════

def test_specialist_chunks_are_shard_major_and_lens_file_sets_are_unchanged(
    tmp_path,
):
    n_files = 6
    for i in range(n_files):
        content = "AES key = 1\n" if i == 0 else f"def fn{i}():\n    return {i}\n"
        (tmp_path / f"m{i}.py").write_text(content, encoding="utf-8")
    all_files = [f"m{i}.py" for i in range(n_files)]
    ctx = make_ctx(repo_root=str(tmp_path), all_files=all_files)
    manifest = TaskManifest(chunks=[], rationale="x")
    cfg = SimpleNamespace(step3=SimpleNamespace(
        specialists=["crypto", "logic-bug"],
        specialist_chunk_loc=1, max_files_per_chunk=1, pack_by="loc"))

    s3_decompose._add_specialist_chunks(manifest, ctx, cfg)

    specs = [c.specialist for c in manifest.chunks]
    assert set(specs) == {"crypto", "logic-bug"}
    assert all(c.shard_id for c in manifest.chunks)

    # Shard-major: once a shard_id is seen it may not reappear later,
    # non-consecutively, after a different shard_id has started.
    seen: list[str] = []
    for c in manifest.chunks:
        if not seen or seen[-1] != c.shard_id:
            assert c.shard_id not in seen, (
                f"shard_id {c.shard_id!r} reappeared non-consecutively")
            seen.append(c.shard_id)

    files_by_spec: dict[str, set] = {}
    for c in manifest.chunks:
        files_by_spec.setdefault(c.specialist, set()).update(c.files)
    assert files_by_spec["crypto"] == files_by_spec["logic-bug"] == set(all_files)


# ═════════════════════════════════════════════════════════════════════════════
# s3 degradation is reported through _errlog, alongside the existing
# stderr prints (never replacing them).
# ═════════════════════════════════════════════════════════════════════════════

def test_llm_call_failure_is_recorded_through_errlog(stub_prompt, capsys):
    stub_prompt.set_raise("s3", TimeoutError("simulated provider timeout"))
    ctx = make_ctx(all_files=["a.py"])
    cfg = SimpleNamespace(step3=SimpleNamespace(),
                          models=SimpleNamespace(decompose="stub-model"))

    s3_decompose.run(ctx, cfg)

    assert errlog.counts_by_stage().get("s3", 0) >= 1
    assert "strategist call failed" in capsys.readouterr().err


def test_unusable_response_is_recorded_through_errlog(stub_prompt, capsys):
    stub_prompt.set_response("s3", "not json at all")
    ctx = make_ctx(all_files=["a.py"])
    cfg = SimpleNamespace(step3=SimpleNamespace(),
                          models=SimpleNamespace(decompose="stub-model"))

    s3_decompose.run(ctx, cfg)

    assert errlog.counts_by_stage().get("s3", 0) >= 1
    assert "not usable" in capsys.readouterr().err


# ═════════════════════════════════════════════════════════════════════════════
# the raw-output echo is redacted, matching s8's pattern.
# ═════════════════════════════════════════════════════════════════════════════

def test_raw_output_echo_is_redacted(stub_prompt, capsys):
    stub_prompt.set_response(
        "s3", "not json, leaked key AKIAABCDEFGHIJKLMNOP in here")
    ctx = make_ctx(all_files=["a.py"])
    cfg = SimpleNamespace(step3=SimpleNamespace(),
                          models=SimpleNamespace(decompose="stub-model"))

    s3_decompose.run(ctx, cfg)

    err = capsys.readouterr().err
    assert "AKIAABCDEFGHIJKLMNOP" not in err
    assert "REDACTED" in err


# The test above places the key well inside the [:500] echo window, so it
# passes under BOTH redact(raw)[:500] and the shipped-broken redact(raw[:500])
# — it only catches a redact() call going missing entirely. This one pins the
# ORDER: the key straddles the cut, so truncating first bisects it, the
# surviving prefix matches no redaction pattern, and it reaches stderr and the
# errlog raw_head unmasked.

def test_raw_echo_key_straddling_the_truncation_cut_leaks_no_fragment(
        stub_prompt, capsys):
    from vvaharness.report.redact import redact
    secret = "AKIATESTKEYLEAK00042"          # canonical 20-char AWS key id
    # Guard the fixture itself: an 18-char "key" matches no pattern and would
    # make this test pass for the wrong reason.
    assert len(secret) == 20 and secret not in redact(secret)
    cut, before = 500, 14                    # 14 chars land before the cut …
    start = cut - before
    # … and 6 after it. Space-separated: glued padding ("xxxAKIA…") defeats
    # the pattern's word boundary and the fixture would never redact at all.
    raw = "x" * (start - 1) + " " + secret + " " + "y" * 40
    assert raw.index(secret) == start
    assert start < cut < start + len(secret) and cut - start >= 12  # straddles
    stub_prompt.set_response("s3", raw)      # non-JSON → the unusable path
    ctx = make_ctx(all_files=["a.py"])
    cfg = SimpleNamespace(step3=SimpleNamespace(),
                          models=SimpleNamespace(decompose="stub-model"))

    s3_decompose.run(ctx, cfg)

    err = capsys.readouterr().err
    logged = (errlog.current_path().read_text(encoding="utf-8")
              if errlog.current_path().exists() else "")
    assert "not usable" in err               # the degradation path did fire
    for i in range(len(secret) - 11):
        w = secret[i:i + 12]
        assert w not in err, f"key fragment {w!r} reached stderr"
        assert w not in logged, f"key fragment {w!r} reached errors.jsonl"


# ── The threat caps must be passed by the caller, not left to defaults ────────
#
# The rendering helper's own parameter defaults reproduce the historical
# hard-coded limits, so a bare call still truncates the threat list to twelve.
# Real models emit fifteen to thirty-odd threats, so that truncation silently
# dropped several from the strategist's prompt on every scan, losing ranking and
# targeting. The repair lives entirely in this stage passing the configured caps
# explicitly, which means a future cleanup that deletes "redundant" arguments
# matching the defaults would reintroduce it with a fully green suite.
#
# This test fails if the stage stops passing them.

def test_stage_passes_explicit_threat_caps_and_not_the_helper_defaults(
        stub_prompt, tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    seen: dict = {}
    real = ContextPackage.to_decompose_prompt_block

    def spy(self, **kw):
        seen.update(kw)
        return real(self, **kw)

    monkeypatch.setattr(ContextPackage, "to_decompose_prompt_block", spy)

    ctx = make_ctx(repo_root=str(tmp_path), all_files=["src/a.py"])
    stub_prompt.set_response("s3", json.dumps({"chunks": [], "rationale": "x"}))
    cfg = SimpleNamespace(step3=SimpleNamespace(),
                          models=SimpleNamespace(decompose="stub-model"))

    s3_decompose.run(ctx, cfg)

    assert seen, (
        "the stage called to_decompose_prompt_block with no keyword arguments, so "
        "the threat list is truncated to the helper's historical default of 12"
    )
    assert seen.get("max_threats") == 50
    assert seen.get("max_assets") == 20
    assert seen.get("max_boundaries") == 30
    assert seen.get("max_context_chars") == 2500


def test_a_thirty_threat_model_reaches_the_prompt_intact(stub_prompt, tmp_path):
    """End-to-end guard on the same defect, asserted on the rendered text.

    Thirty threats is inside the real observed range and above the historical
    cap, so a regression shows up as missing threat lines rather than as a
    changed call signature.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    threats = [
        Threat(id=f"T{i}", threat=f"threat number {i}", actor="remote_unauth",
               surface=f"endpoint {i}", asset="data", impact="high",
               likelihood="possible")
        for i in range(1, 31)
    ]
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["src/a.py"],
                   threat_model=ThreatModel(threats=threats))
    stub_prompt.set_response("s3", json.dumps({"chunks": [], "rationale": "x"}))
    cfg = SimpleNamespace(step3=SimpleNamespace(),
                          models=SimpleNamespace(decompose="stub-model"))

    s3_decompose.run(ctx, cfg)

    rendered = stub_prompt.calls[-1]["prompt"]
    for i in (1, 12, 13, 25, 30):
        assert f"T{i}" in rendered, f"threat T{i} missing from the rendered prompt"
    assert "(truncated)" not in rendered


# ── Baseline detection must match the emitter's pattern, not merely the word ──

def test_evidence_mentioning_baseline_without_an_id_is_a_real_threat():
    """A repo-specific threat whose evidence merely opens with the word must
    keep its fallback chunk and stay in the coverage denominator; only a
    well-formed checklist disposition is exempt."""
    real = Threat(id="T1", threat="x", actor="remote_unauth", surface="s",
                  asset="a", impact="high", likelihood="possible",
                  evidence="baseline: general note, no checklist id here")
    disposed = Threat(id="T2", threat="y", actor="remote_unauth", surface="s",
                      asset="a", impact="high", likelihood="possible",
                      evidence="baseline: BL-WEB-A01 no matching surface found")
    assert s3_decompose._is_baseline_threat(real) is False
    assert s3_decompose._is_baseline_threat(disposed) is True


def test_baseline_marked_threat_naming_a_real_file_keeps_its_guarantee(capsys):
    """Regression: the exemption keyed off the `baseline:` marker alone, but s2
    requires that marker on every disposed checklist item, so on a real repo
    most threats carry it. Keying off it stripped the coverage guarantee from
    threats naming concrete files and left it only to the ones with no
    evidence at all. The surface, not the marker, decides."""
    pinned = Threat(
        id="T1", threat="Injection in the B2B order endpoint",
        actor="remote_unauth", surface="routes/b2bOrder.ts::b2bOrder",
        asset="orders", impact="high", likelihood="likely",
        evidence="baseline: BL-WEB-A03")
    prose = Threat(
        id="T2", threat="Vulnerable dependencies", actor="supply_chain",
        surface="npm dependencies (express-jwt 0.1.3, sanitize-html 1.4.2)",
        asset="app", impact="high", likelihood="possible",
        evidence="baseline: BL-WEB-A08")
    all_files = {"routes/b2bOrder.ts"}

    assert s3_decompose._is_unmatched_baseline_threat(pinned, all_files) is False
    assert s3_decompose._is_unmatched_baseline_threat(prose, all_files) is True
    # Both still carry the marker — only the exemption verdict differs.
    assert s3_decompose._is_baseline_threat(pinned) is True

    ctx = make_ctx(all_files=sorted(all_files),
                   threat_model=ThreatModel(threats=[pinned, prose]))
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=["routes/b2bOrder.ts"],
                      threat_id="T1")],
        rationale="x")
    s3_decompose._report_threat_coverage(manifest, ctx)
    printed = capsys.readouterr().err
    # Denominator is T1 alone: the pinned threat counts, the prose one is
    # exempt and so must not appear as UNCOVERED either.
    assert "1/1 threats" in printed, printed
    assert "T2" not in printed, printed


def test_a_dropped_leading_directory_still_resolves_the_surface():
    """s2 routinely writes a partial path. The suffix idiom used for chunk-file
    resolution has to apply here too, or a real surface reads as prose."""
    t = Threat(id="T1", threat="x", actor="remote_auth",
               surface="insecurity.ts::decode(token)", asset="a",
               impact="high", likelihood="possible",
               evidence="baseline: BL-WEB-A02")
    assert s3_decompose._surface_names_a_real_file(t, {"lib/insecurity.ts"})
    assert not s3_decompose._surface_names_a_real_file(t, {"lib/other.ts"})


def test_baseline_pattern_matches_the_emitting_stage():
    """The two stages hold separate copies of this pattern because the emitter
    already imports from this module, so sharing one constant would be a cycle.
    This asserts they have not drifted apart."""
    from vvaharness.pipeline.stages import s2_threatmodel
    assert (s3_decompose._BASELINE_EVIDENCE_RX.pattern
            == s2_threatmodel._BASELINE_EVIDENCE_RX.pattern)


# ── A chunk sending both key shapes must not lose either payload ──────────────

def test_a_chunk_sending_both_shapes_keeps_the_paths_too(tmp_path):
    """Pydantic's alias makes `file_ids` win, so the `files` payload is
    unrecoverable after validation. A model that hedges with an empty
    `file_ids` beside real paths would otherwise lose the chunk entirely."""
    ctx = make_ctx(repo_root=str(tmp_path),
                   all_files=["app/core/utils.py", "src/a.py"])
    data = {"rationale": "r", "chunks": [
        {"id": "chunk-01", "risk_rank": 1, "hypothesis": "h",
         "file_ids": [], "files": ["app/core/utils.py"]},
    ]}
    shapes, raw_paths = s3_decompose._prepare_chunk_shapes(data, ctx)
    assert shapes == ["mixed"]
    assert raw_paths == [["app/core/utils.py"]]

    manifest = TaskManifest.model_validate(data)
    assert manifest.chunks[0].files == [], "alias should have won, ids empty"

    s3_decompose._normalize_chunk_files(manifest, ctx, ctx, shapes, raw_paths)
    assert manifest.chunks[0].files == ["app/core/utils.py"], (
        "the paths sent alongside the ids were discarded"
    )


# ── Config caps must never crash the stage or become a negative slice bound ───

@pytest.mark.parametrize("value,expected", [
    ("hello", 50),          # non-numeric: int() raises ValueError
    (float("inf"), 50),     # `.inf` is a valid YAML scalar; int() raises OverflowError
    (-5, 50),               # a negative would be used as a slice bound, silently
                            # dropping items from the end instead of capping
    (0, 50),                # this stage's documented "use the default" spelling
    (None, 50),
    (True, 1),
    (3.7, 3),
    (42, 42),
])
def test_cap_sanitises_hostile_config_values(value, expected):
    assert s3_decompose._cap(SimpleNamespace(k=value), "k", 50) == expected


def test_cap_falls_back_when_the_key_is_absent():
    assert s3_decompose._cap(SimpleNamespace(), "missing", 50) == 50


@pytest.mark.parametrize("bad", ["hello", float("inf"), -5])
def test_stage_survives_a_hostile_prompt_cap(stub_prompt, tmp_path, bad):
    """The whole stage, not just the helper: these previously raised out of
    `run()` before any model call, or silently truncated a list from the end."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["src/a.py"])
    stub_prompt.set_response("s3", json.dumps({"chunks": [], "rationale": "x"}))
    cfg = SimpleNamespace(step3=SimpleNamespace(max_prompt_threats=bad),
                          models=SimpleNamespace(decompose="stub-model"))
    manifest = s3_decompose.run(ctx, cfg)
    assert manifest.chunks, "deterministic coverage passes must still produce chunks"


def test_seed_matching_does_not_cross_attribute_across_functions():
    """Each seeded function must get its own chunk with its own function.

    Matching seed evidence to an entry point by FILE alone cross-attributes when
    two functions in one file sink in different files: every entry point pulls in
    every evidence entry, so both chunks claim both functions. The companion
    single-sink-file fixture cannot show this, because there the file-set merge
    collapses the duplicates regardless.
    """
    from fixtures.ctx_builders import make_taint_distinct_sinks_ctx
    ctx = make_taint_distinct_sinks_ctx()
    manifest = TaskManifest(chunks=[], rationale="x")
    s3_decompose._add_taint_chunks(manifest, ctx, _make_cfg())

    taint = [c for c in manifest.chunks if c.id.startswith("taint-")]
    assert len(taint) == 2, f"expected one chunk per seeded function, got {len(taint)}"
    for c in taint:
        assert len(c.focus_entry_points) == 1, (
            f"{c.id} claims {c.focus_entry_points} — seed evidence for one "
            f"function was attributed to another"
        )
    assert {c.focus_entry_points[0] for c in taint} == {"func_a", "func_b"}


# ── the strategist prompt must not demand threat ids that do not exist ───────
# s2 can legitimately produce no threat model: a parse failure there degrades
# the scan instead of aborting it. With the MUST-cite-threat_id rule
# unconditional, the prompt contradicted itself — no THREAT MODEL section was
# rendered, and an observed run refused outright ("No THREAT MODEL section was
# provided… I cannot invent threat ids"), which raised a ValidationError and
# lost the whole LLM ranking pass. chunk- is the top true-positive contributor,
# so a refusal is a real recall loss.

def test_threat_rule_has_both_forms_and_neither_leaks_a_placeholder():
    assert "{threat_rule}" not in s3_decompose.SYSTEM
    assert "{threat_rule}" not in s3_decompose._SYSTEM_NO_THREATS
    # The two prompts differ only in rule 4.
    assert s3_decompose.SYSTEM != s3_decompose._SYSTEM_NO_THREATS
    for shared in ("GROUNDING RULE", "FILE INVENTORY", "file_ids",
                   "focus_entry_point_ids"):
        assert shared in s3_decompose.SYSTEM
        assert shared in s3_decompose._SYSTEM_NO_THREATS


def test_threat_model_present_prompt_requires_a_threat_id():
    assert "MUST cite the threat_id" in s3_decompose.SYSTEM


def test_no_threat_model_prompt_waives_the_id_and_forbids_refusing():
    p = s3_decompose._SYSTEM_NO_THREATS
    assert "MUST cite" not in p
    assert "do NOT refuse" in p
    # It must also not invite invented ids, which the id-resolution pass would
    # only strip again.
    assert "Do NOT invent threat ids" in p


# ─────────────────────────────────────────────────────────────────────────────
# threat-fallback LOC trim, and the documented `risk_chunk_loc: 0` off switch
# ─────────────────────────────────────────────────────────────────────────────

def _big_threat_ctx(tmp_path, *, loc_per_file=400, files=6):
    """One uncovered access-control threat whose surface spans several files."""
    app = tmp_path / "src"
    app.mkdir(parents=True, exist_ok=True)
    names = []
    for i in range(files):
        rel = f"src/authz{i}.py"
        (tmp_path / rel).write_text("x = 1\n" * loc_per_file, encoding="utf-8")
        names.append(rel)
    return ContextPackage(
        repo_root=str(tmp_path), language="python", all_files=names,
        threat_model=ThreatModel(threats=[_threat("T7", "authorization")]),
    ), names


def test_threat_fallback_trims_files_to_the_loc_budget(tmp_path):
    """The trim exists because the splitter never sees fallback chunks, so an
    unbounded one would reach s4 whole. Bounded at BUILD time, not split after:
    splitting would turn one capped chunk into several and quietly multiply the
    operator's max_threat_fallback_chunks ceiling."""
    ctx, names = _big_threat_ctx(tmp_path, loc_per_file=400, files=6)
    cfg = _make_cfg()
    cfg.step3.risk_chunk_loc = 900          # ~2 files' worth

    manifest = TaskManifest(chunks=[], rationale="test")
    assert s3_decompose._add_threat_surface_fallback_chunks(
        manifest, ctx, cfg) == 1

    fb = next(c for c in manifest.chunks if c.id.startswith("threat-t7-fallback"))
    assert 0 < len(fb.files) < len(names), fb.files
    assert COUNTERS.get("s3_fallback_files_trimmed") == len(names) - len(fb.files)


def test_threat_fallback_keeps_one_file_even_if_it_busts_the_budget(tmp_path):
    """A single oversized file must still be reviewed rather than dropped."""
    ctx, _ = _big_threat_ctx(tmp_path, loc_per_file=5000, files=1)
    cfg = _make_cfg()
    cfg.step3.risk_chunk_loc = 10

    manifest = TaskManifest(chunks=[], rationale="test")
    s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, cfg)

    fb = next(c for c in manifest.chunks if c.id.startswith("threat-t7-fallback"))
    assert len(fb.files) == 1


def test_threat_fallback_honours_risk_chunk_loc_zero_as_off(tmp_path):
    """`risk_chunk_loc: 0` is documented "0 = off" in three shipped profiles and
    the splitter honours it. This pass must too: routing the key through _cap
    (whose 0-means-default idiom the s3 max_prompt_* family relies on) silently
    replaced the operator's off switch with a 10,000-LOC budget."""
    ctx, names = _big_threat_ctx(tmp_path, loc_per_file=4000, files=5)
    cfg = _make_cfg()
    cfg.step3.risk_chunk_loc = 0

    manifest = TaskManifest(chunks=[], rationale="test")
    s3_decompose._add_threat_surface_fallback_chunks(manifest, ctx, cfg)

    fb = next(c for c in manifest.chunks if c.id.startswith("threat-t7-fallback"))
    assert len(fb.files) == len(names), "0 must disable the trim entirely"
    assert COUNTERS.get("s3_fallback_files_trimmed") == 0


# ─────────────────────────────────────────────────────────────────────────────
# no-threats prompt dispatch
# ─────────────────────────────────────────────────────────────────────────────

def test_has_threats_is_false_for_a_present_but_empty_threat_model():
    """`getattr(ctx, "threat_model", None)` is ALWAYS truthy for a pydantic
    model, so the pre-fix check never fired and s3 demanded a threat_id for
    every chunk on a run that had no threats to cite."""
    ctx = ContextPackage(repo_root="/x", language="python", all_files=[],
                         threat_model=ThreatModel(threats=[]))
    assert s3_decompose._has_threats(ctx) is False

    ctx_none = ContextPackage(repo_root="/x", language="python", all_files=[])
    assert s3_decompose._has_threats(ctx_none) is False

    ctx_one = ContextPackage(
        repo_root="/x", language="python", all_files=[],
        threat_model=ThreatModel(threats=[_threat("T1", "authorization")]))
    assert s3_decompose._has_threats(ctx_one) is True


# ═════════════════════════════════════════════════════════════════════════════
# The dispatch seam: `via: deepagents` routes to the shared helper with the
# scanned repo as cwd; a harness failure degrades exactly like a legacy one
# (risk ranking lost, deterministic coverage kept) — never worse.
# ═════════════════════════════════════════════════════════════════════════════

def _deepagents_cfg():
    return SimpleNamespace(
        step3=SimpleNamespace(),
        models=SimpleNamespace(
            decompose=SimpleNamespace(id="harness-model", via="deepagents")),
    )


def test_deepagents_via_routes_through_dispatch_with_repo_root_cwd(
        stub_prompt, monkeypatch):
    seen = {}

    def fake_dispatch(user_prompt, **kw):
        seen.update(kw)
        return json.dumps({"chunks": [], "rationale": "x"})

    monkeypatch.setattr(s3_decompose._deepagents, "dispatch_prompt",
                        fake_dispatch)
    ctx = make_ctx(repo_root="/scanned/repo", all_files=["a.py"])
    cfg = _deepagents_cfg()

    s3_decompose.run(ctx, cfg)

    assert seen["cwd"] == "/scanned/repo"
    assert seen["tag"] == "s3 decompose"
    assert seen["cfg"] is cfg
    assert seen["max_tokens"] is None
    assert stub_prompt.calls == [], \
        "a deepagents role must never reach registry.prompt"


def test_deepagents_failure_degrades_to_deterministic_coverage(
        stub_prompt, monkeypatch, capsys):
    """docs/outputs.md documents risk=0 with non-zero taint/threat-fallback as
    the signature of a failed strategist call. A harness failure must surface
    the SAME way a legacy provider failure does: warn, errlog, empty manifest
    from the LLM, deterministic passes still sweep every file."""
    def fake_dispatch(*a, **kw):
        raise RuntimeError("DeepAgents session failed: simulated")

    monkeypatch.setattr(s3_decompose._deepagents, "dispatch_prompt",
                        fake_dispatch)
    ctx = make_ctx(repo_root="/scanned/repo", all_files=["a.py"])

    manifest = s3_decompose.run(ctx, _deepagents_cfg())

    assert errlog.counts_by_stage().get("s3", 0) >= 1
    assert "strategist call failed" in capsys.readouterr().err
    # The LLM ranking is lost, not the scan: the recovery manifest documents
    # the degradation and the deterministic passes still run to completion.
    assert "risk ranking unavailable" in manifest.rationale


# ═════════════════════════════════════════════════════════════════════════════
# injection specialist gate and reorder mode (catchall_deduct_lens_coverage)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("sink", [
    'requests.get("https://example.test")',
    'db.raw("SELECT * FROM users")',
    'collection.aggregate({"$match": query})',
    '{"$where": expression}',
    'subprocess.run(command, shell=True)',
    'exec.Command("sh", "-c", command)',
    'jdbcTemplate.query(sql, mapper)',
    'httpx.get(target_url)',
    'http.NewRequest("GET", target_url, nil)',
    'new SpelExpressionParser().parseExpression(expression)',
    'response.sendRedirect(next_url)',
    'element.innerHTML = value',
    'pathlib.Path(root / filename)',
    'Pattern.compile(user_pattern)',
])
def test_injection_specialist_gates_on_when_sink_present(tmp_path, sink):
    src = tmp_path / "svc.py"
    src.write_text(
        f"def handler(value):\n    return {sink}\n",
        encoding="utf-8",
    )
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["svc.py"])

    kept = s3_decompose._gate_specialists(["injection"], ctx, ["svc.py"])

    assert kept == ["injection"]


@pytest.mark.parametrize("non_sink", [
    "execute_plan = True",
    "client = HttpClientFactory()",
    "template = TemplateConfig()",
    "redirect_uri = '/callback'",
    "policy.setHeaderPolicy(value)",
    "fetcher = DataFetcher()",
])
def test_injection_specialist_gates_off_when_no_sink(tmp_path, non_sink):
    src = tmp_path / "math_util.py"
    src.write_text(
        f"def configure():\n    {non_sink}\n",
        encoding="utf-8",
    )
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["math_util.py"])

    kept = s3_decompose._gate_specialists(["injection"], ctx, ["math_util.py"])

    assert kept == []


def _reorder_cfg(*, deduct: bool, specialists: list[str],
                 catchall_enabled: bool = True) -> SimpleNamespace:
    # Minimal step3 config for exercising catch-all + specialists together.
    return SimpleNamespace(step3=SimpleNamespace(
        catchall_enabled=catchall_enabled,
        catchall_mode="all",
        catchall_deduct_lens_coverage=deduct,
        catchall_chunk_loc=4000,
        catchall_max_files=100,
        max_files_per_chunk=80,
        specialist_chunk_loc=10000,
        specialists=specialists,
        pack_by="loc",
    ))


@pytest.mark.parametrize("deduct", [False, True])
def test_catchall_enabled_false_wins_over_deduct_flag(tmp_path, deduct):
    (tmp_path / "svc.py").write_text("AES = 1\n", encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["svc.py"])
    manifest = TaskManifest(chunks=[], rationale="x")
    cfg = _reorder_cfg(
        deduct=deduct, specialists=["crypto"], catchall_enabled=False)

    n_catchall = s3_decompose._add_catchall_chunks(manifest, ctx, cfg)

    assert n_catchall == 0
    assert not any(c.id.startswith("catchall-") for c in manifest.chunks)


@pytest.mark.parametrize(("deduct", "expected"), [
    (False, ["catchall", "specialist", "threat-fallback"]),
    (True, ["specialist", "threat-fallback", "catchall"]),
])
def test_catchall_deduct_flag_controls_producer_order(
        tmp_path, monkeypatch, deduct, expected):
    cfg = _deepagents_cfg()
    cfg.step3.catchall_deduct_lens_coverage = deduct
    order = []

    monkeypatch.setattr(
        s3_decompose._deepagents, "dispatch_prompt",
        lambda *args, **kwargs: json.dumps({"chunks": [], "rationale": "x"}))
    monkeypatch.setattr(
        s3_decompose, "_add_catchall_chunks",
        lambda *args, **kwargs: order.append("catchall") or 0)
    monkeypatch.setattr(
        s3_decompose, "_add_specialist_chunks",
        lambda *args, **kwargs: order.append("specialist") or 0)
    monkeypatch.setattr(
        s3_decompose, "_add_threat_surface_fallback_chunks",
        lambda *args, **kwargs: order.append("threat-fallback") or 0)

    s3_decompose.run(
        make_ctx(repo_root=str(tmp_path), all_files=[]), cfg)

    assert order == expected


def test_catchall_still_covers_specialist_only_files_when_deduct_flag_on(tmp_path):
    # Two source files claimed only by the crypto specialist. A specialist
    # claim is scoped guidance, not a generic review, so with deduct=True
    # catch-all must still sweep them unscoped.
    (tmp_path / "a.py").write_text("AES = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def f(): return 1\n", encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["a.py", "b.py"])
    manifest = TaskManifest(chunks=[], rationale="x")

    cfg = _reorder_cfg(deduct=True, specialists=["crypto"])
    s3_decompose._add_specialist_chunks(manifest, ctx, cfg)
    n_catchall = s3_decompose._add_catchall_chunks(manifest, ctx, cfg)

    assert n_catchall >= 1, (
        "a specialist claim must not suppress catch-all's generic review "
        "of the same source file"
    )
    catchall_files = {f for c in manifest.chunks
                      if c.id.startswith("catchall-") for f in c.files}
    assert catchall_files == {"a.py", "b.py"}


def test_catchall_excludes_risk_chunk_files_when_deduct_flag_on(tmp_path):
    # A file already claimed by a risk (non-specialist) chunk must NOT be
    # re-swept by catch-all — only specialist claims are excluded from
    # "covered".
    (tmp_path / "a.py").write_text("AES = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def f(): return 1\n", encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["a.py", "b.py"])
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=["a.py"], risk_rank=1)],
        rationale="x")

    cfg = _reorder_cfg(deduct=True, specialists=["crypto"])
    s3_decompose._add_specialist_chunks(manifest, ctx, cfg)
    n_catchall = s3_decompose._add_catchall_chunks(manifest, ctx, cfg)

    catchall_files = {f for c in manifest.chunks
                      if c.id.startswith("catchall-") for f in c.files}
    assert "a.py" not in catchall_files, "risk-chunk-claimed files stay excluded"
    assert catchall_files == {"b.py"}
    assert n_catchall >= 1


def test_catchall_covers_source_when_deduct_flag_off(tmp_path):
    # Same repo shape, deduct=False → legacy order: catch-all runs first and
    # sweeps every eligible source file (specialists haven't run yet, so
    # `covered` is empty).
    (tmp_path / "a.py").write_text("AES = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def f(): return 1\n", encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["a.py", "b.py"])
    manifest = TaskManifest(chunks=[], rationale="x")

    cfg = _reorder_cfg(deduct=False, specialists=["crypto"])
    n_catchall = s3_decompose._add_catchall_chunks(manifest, ctx, cfg)

    assert n_catchall >= 1, (
        "with deduct=False, catch-all runs before any lens has claimed files "
        "and must review the source residue"
    )
    catchall_files = {f for c in manifest.chunks
                      if c.id.startswith("catchall-") for f in c.files}
    assert catchall_files == {"a.py", "b.py"}


def test_reorder_classification_and_crossover_when_deduct_flag_on(tmp_path):
    # The metrics classifier (_KIND_PREFIXES in util/metrics.py) keys off the
    # chunk ID prefix, not on producer order. Verify catch-all chunks under
    # the reordered mode still classify as "catchall", and that a specialist-
    # claimed SOURCE file (svc.py) now ALSO reaches catch-all — a specialist
    # claim is scoped, not a generic review, so it no longer suppresses it.
    (tmp_path / "cfg.yaml").write_text("key: value\n", encoding="utf-8")
    (tmp_path / "svc.py").write_text(
        "import requests\n"
        "def h(u): return requests.get(u).text\n",
        encoding="utf-8",
    )
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["cfg.yaml", "svc.py"])
    manifest = TaskManifest(chunks=[], rationale="x")

    cfg = _reorder_cfg(deduct=True, specialists=["injection"])
    s3_decompose._add_specialist_chunks(manifest, ctx, cfg)
    s3_decompose._add_catchall_chunks(manifest, ctx, cfg)

    catchall_ids = [c.id for c in manifest.chunks if c.id.startswith("catchall-")]
    spec_ids = [c.id for c in manifest.chunks if c.id.startswith("spec-")]
    assert catchall_ids, "catch-all should sweep every file no risk/taint/threat-fallback chunk claimed"
    assert spec_ids, "injection specialist should have claimed svc.py"
    catchall_files = {f for c in manifest.chunks
                      if c.id.startswith("catchall-") for f in c.files}
    spec_files = {f for c in manifest.chunks
                  if c.id.startswith("spec-") for f in c.files}
    assert "cfg.yaml" in catchall_files
    assert "svc.py" in spec_files
    assert "svc.py" in catchall_files, (
        "a specialist claim is scoped, not generic — svc.py must also reach "
        "catch-all now that specialist coverage no longer suppresses it"
    )

