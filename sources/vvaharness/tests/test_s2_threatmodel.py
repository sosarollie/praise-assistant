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

"""Behavioral tests for the step-2 threat-model stage.

Covers: deterministic, coverage-preserving threat ranking (replacing the old
positional truncation); capping of assets/trust boundaries; the mandatory
baseline-disposition convention and its machine-checkable audit; the two
SYSTEM prompt edits; timeout/error/emptiness handling; the repo-kind
classifier (including the `framework` entry-point kind and the bounded
manifest search); cap sanitization; repo-shape evidence sourced from the
full file list rather than the AST frontier sample; document and manifest
budgeting (including structural, format-aware manifest truncation);
containment of on-disk reads to the repository root; and the prompt block
reorder that removes the absolute host path from the rendered prompt.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from vvaharness.models import (
    Asset,
    AppProfile,
    Threat,
    ThreatModel,
    TrustBoundary,
)
from vvaharness.pipeline.stages import s2_threatmodel
from vvaharness.util import errlog
from vvaharness.util.counters import COUNTERS
from fixtures import repo_builders
from fixtures.ctx_builders import make_ctx


# COUNTERS isolation is provided by the autouse _reset_stage_counters fixture
# in tests/conftest.py (reset before and after every test).


def _threat(tid: str, *, surface: str, threat: str = "threat",
           actor: str = "remote_unauth", asset: str = "primary-asset",
           impact: str = "medium", likelihood: str = "possible",
           controls: str = "", evidence: str = "") -> Threat:
    return Threat(id=tid, threat=threat, actor=actor, surface=surface,
                 asset=asset, impact=impact, likelihood=likelihood,
                 controls=controls, evidence=evidence)


def _minimal_ev(**overrides) -> dict:
    ev = {
        "file_count": 0, "original_file_count": 0, "ast_frontier_stats": {},
        "primary_language": "",
        "languages": [], "top_dirs": [], "modules": [], "modules_truncated": False,
        "entry_points": [], "entry_points_truncated": False, "function_sites": [],
        "call_edges": [], "config_reps": [], "api_artefacts": [], "docs": [],
        "manifests": [], "s1_notes": "",
    }
    ev.update(overrides)
    return ev


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic threat ranking (replaces positional truncation)
# ─────────────────────────────────────────────────────────────────────────────

def test_ascending_severity_input_keeps_the_most_severe_threats():
    tm = ThreatModel(threats=[
        _threat("T1", surface="ep1", impact="low", likelihood="very_rare"),
        _threat("T2", surface="ep2", impact="medium", likelihood="possible"),
        _threat("T3", surface="ep3", impact="critical", likelihood="almost_certain"),
        _threat("T4", surface="ep4", impact="existential", likelihood="likely"),
    ])
    capped = s2_threatmodel._cap_threats(tm, 2)
    assert {t.id for t in capped.threats} == {"T3", "T4"}


def test_asset_sensitivity_breaks_ties_between_otherwise_identical_threats():
    tm = ThreatModel(
        assets=[Asset(name="crit-asset", sensitivity="critical"),
               Asset(name="low-asset", sensitivity="low")],
        threats=[
            _threat("T1", surface="ep1", asset="low-asset", impact="high",
                   likelihood="likely", actor="remote_unauth"),
            _threat("T2", surface="ep2", asset="crit-asset", impact="high",
                   likelihood="likely", actor="remote_unauth"),
        ],
    )
    capped = s2_threatmodel._cap_threats(tm, 1)
    assert capped.threats[0].id == "T2"


def test_non_numeric_threat_id_does_not_raise():
    tm = ThreatModel(threats=[
        _threat("THREAT-A", surface="ep1"),
        _threat("T2", surface="ep2"),
    ])
    capped = s2_threatmodel._cap_threats(tm, 2)
    assert {t.id for t in capped.threats} == {"THREAT-A", "T2"}


def test_truncation_to_one_with_two_sole_covered_boundaries_declines_promotion():
    """Two boundaries, each covered by exactly one threat, max_threats=1. There
    is no way to keep both boundaries covered with one slot, and the survivor
    is a sole cover of its own boundary, so promotion must be DECLINED rather
    than evicting the only kept threat — the specific outcome, not merely
    "some threat survives"."""
    tm = ThreatModel(
        trust_boundaries=[
            TrustBoundary(entry_point="ep-a", crossing="x -> y"),
            TrustBoundary(entry_point="ep-b", crossing="x -> y"),
        ],
        threats=[
            _threat("T1", surface="ep-a", impact="high", likelihood="likely"),
            _threat("T2", surface="ep-b", impact="medium", likelihood="possible"),
        ],
    )
    capped = s2_threatmodel._cap_threats(tm, 1)
    assert [t.id for t in capped.threats] == ["T1"]
    assert COUNTERS.get("s2_threats_promoted") == 0


@pytest.mark.parametrize("n_threats,n_boundaries,cap", [
    (10, 3, 5), (10, 8, 4), (1, 0, 5), (0, 0, 5), (5, 5, 0), (5, 5, 100),
])
def test_output_length_and_id_membership_invariant(n_threats, n_boundaries, cap):
    threats = [_threat(f"T{i}", surface=f"ep{i % max(n_boundaries, 1)}")
              for i in range(n_threats)]
    boundaries = [TrustBoundary(entry_point=f"ep{i}", crossing="x")
                 for i in range(n_boundaries)]
    tm = ThreatModel(threats=threats, trust_boundaries=boundaries)
    capped = s2_threatmodel._cap_threats(tm, cap)
    assert len(capped.threats) == min(n_threats, cap)
    input_ids = {t.id for t in threats}
    assert {t.id for t in capped.threats} <= input_ids


def test_no_dedup_fields_exist_on_the_threat_model():
    fields = Threat.model_fields
    for banned in ("stride", "group", "related_ids", "merged_from"):
        assert banned not in fields


def test_near_duplicate_threats_on_different_surfaces_both_survive():
    """The synthetic pair that trips a Jaccard-based dedup predicate
    ("tampers with the session token" vs "steals the session token") must
    both survive ranking/capping — merging them would erase per-boundary
    coverage, which is exactly the failure mode deduplication was rejected
    over."""
    tm = ThreatModel(
        trust_boundaries=[TrustBoundary(entry_point="ep-a", crossing="x"),
                          TrustBoundary(entry_point="ep-b", crossing="x")],
        threats=[
            _threat("T1", surface="ep-a", threat="attacker tampers with the session token"),
            _threat("T2", surface="ep-b", threat="attacker steals the session token"),
        ],
    )
    capped = s2_threatmodel._cap_threats(tm, 50)
    assert {t.id for t in capped.threats} == {"T1", "T2"}


# ─────────────────────────────────────────────────────────────────────────────
# Cap assets / trust boundaries
# ─────────────────────────────────────────────────────────────────────────────

def test_asset_cap_keeps_highest_sensitivity_first():
    assets = [Asset(name=f"low{i}", sensitivity="low") for i in range(90)] + \
             [Asset(name=f"crit{i}", sensitivity="critical") for i in range(10)]
    tm = ThreatModel(assets=assets)
    capped = s2_threatmodel._cap_assets(tm, 40)
    assert len(capped.assets) == 40
    assert all(a.sensitivity == "critical" for a in capped.assets[:10])


def test_trust_boundary_cap_keeps_highest_reachable_asset_count_first():
    boundaries = [TrustBoundary(entry_point=f"ep{i}", crossing="x", reachable_assets=["a"])
                 for i in range(70)]
    boundaries[35] = TrustBoundary(entry_point="big", crossing="x",
                                   reachable_assets=["a", "b", "c"])
    tm = ThreatModel(trust_boundaries=boundaries)
    capped = s2_threatmodel._cap_boundaries(tm, 60)
    assert len(capped.trust_boundaries) == 60
    assert capped.trust_boundaries[0].entry_point == "big"


# ─────────────────────────────────────────────────────────────────────────────
# Baseline block: mandatory disposition with stable ids
# ─────────────────────────────────────────────────────────────────────────────

def test_omit_silently_language_is_absent_from_the_module():
    src = Path(s2_threatmodel.__file__).read_text(encoding="utf-8")
    assert "omit silently" not in src


def test_baseline_audit_flags_items_with_neither_disposition():
    kinds = {"library"}
    tm = ThreatModel(
        threats=[_threat("T1", surface="ep", evidence="baseline: BL-LIB-INJ")],
        open_questions=["BL-LIB-PATH: no matching surface in this snapshot"],
    )
    undisposed = s2_threatmodel._baseline_audit(tm, kinds)
    assert undisposed == {"BL-LIB-DESER", "BL-LIB-REDOS"}


def test_baseline_audit_reports_nothing_undisposed_once_every_item_has_a_trace():
    kinds = {"iac"}
    ids = [bid for bid, _ in s2_threatmodel._BASELINES["iac"]]
    tm = ThreatModel(threats=[_threat(f"T{i}", surface="ep", evidence=f"baseline: {bid}")
                              for i, bid in enumerate(ids)])
    assert s2_threatmodel._baseline_audit(tm, kinds) == set()


def test_baseline_block_compiles_and_renders_kind_set_and_evidence_prefix():
    ev = _minimal_ev()
    kinds, text = s2_threatmodel._baseline_block(ev, None, "owasp")
    assert kinds == {"web-api"}
    assert "{web-api}" in text
    assert '"baseline: <ID>"' in text
    assert "[BL-WEB-A01]" in text
    assert "OWASP A01 Broken Access Control" in text


def test_baseline_block_mode_none_yields_no_text():
    kinds, text = s2_threatmodel._baseline_block(_minimal_ev(), None, "none")
    assert kinds == set()
    assert text == ""


def test_baseline_ids_match_the_documented_set():
    expected = {
        "web-api": {"BL-WEB-A01", "BL-WEB-A02", "BL-WEB-A03", "BL-WEB-A04",
                   "BL-WEB-A05", "BL-WEB-A07", "BL-WEB-A08", "BL-WEB-A10",
                   "BL-WEB-XSS", "BL-WEB-CSRF"},
        "mobile": {"BL-MOB-M1", "BL-MOB-M3", "BL-MOB-M5", "BL-MOB-M8", "BL-MOB-M9"},
        "native": {"BL-NAT-119", "BL-NAT-416", "BL-NAT-190", "BL-NAT-134",
                  "BL-NAT-362", "BL-NAT-78"},
        "iac": {"BL-IAC-IAM", "BL-IAC-NET", "BL-IAC-SECRETS", "BL-IAC-PRIV", "BL-IAC-TLS"},
        "library": {"BL-LIB-INJ", "BL-LIB-DESER", "BL-LIB-PATH", "BL-LIB-REDOS"},
    }
    for kind, ids in expected.items():
        assert {bid for bid, _ in s2_threatmodel._BASELINES[kind]} == ids


# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM prompt edits (model-behaviour defects: prompt-text assertions only)
# ─────────────────────────────────────────────────────────────────────────────

def test_system_prompt_no_longer_asks_the_model_to_sort():
    assert "Sort by (impact,likelihood)" not in s2_threatmodel.SYSTEM


def test_system_prompt_states_the_caller_ranks_and_recall_posture():
    assert "the caller ranks" in s2_threatmodel.SYSTEM
    assert "Do NOT drop a threat because you are unsure" in s2_threatmodel.SYSTEM


def test_system_prompt_requires_baseline_disposition():
    assert "Every MINIMUM BASELINE item" in s2_threatmodel.SYSTEM
    assert '"evidence" starting "baseline: <ID>"' in s2_threatmodel.SYSTEM
    assert "Never drop a baseline item without a" in s2_threatmodel.SYSTEM


def test_system_prompt_has_no_stride_output_field():
    assert '"stride"' not in s2_threatmodel.SYSTEM


# ─────────────────────────────────────────────────────────────────────────────
# Robustness: timeout, emptiness detection, correct `_errlog` usage
# ─────────────────────────────────────────────────────────────────────────────

def _cfg(**step2_kwargs):
    return SimpleNamespace(
        step2=SimpleNamespace(baseline="none", **step2_kwargs),
        models=SimpleNamespace(threatmodel="stub-model"),
    )


def test_provider_failure_is_recorded_and_propagated(stub_prompt):
    """A failed provider call must not be reported as a successful stage.

    The caller already wraps this stage, marks it failed and continues without a
    threat model, and every later stage handles its absence. Swallowing the
    error here would show the stage as succeeding while merely finding nothing,
    and would hand downstream an empty-but-present model, which renders as a
    hollow threat-model block in later prompts instead of being skipped.
    """
    stub_prompt.set_raise("s2", TimeoutError("simulated provider timeout"))
    with pytest.raises(TimeoutError):
        s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])
    assert errlog.counts_by_stage().get("s2", 0) >= 1


def test_unparseable_response_is_recorded_and_propagated(stub_prompt):
    """An unparseable response means there is no threat model, which is not the
    same thing as a threat model that found nothing."""
    stub_prompt.set_response("s2", "this is not json at all")
    with pytest.raises(Exception):
        s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])
    assert errlog.counts_by_stage().get("s2", 0) >= 1


def test_empty_json_response_yields_empty_model_and_zero_threat_record(stub_prompt):
    stub_prompt.set_response("s2", "{}")
    tm = s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])
    assert tm.threats == []
    assert errlog.counts_by_stage().get("s2", 0) >= 1


def test_timeout_kwarg_is_forwarded_to_prompt(stub_prompt):
    s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(timeout=42), [], [])
    assert stub_prompt.calls[-1]["kw"]["timeout"] == 42


def test_default_timeout_matches_the_registered_default(stub_prompt):
    s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])
    assert stub_prompt.calls[-1]["kw"]["timeout"] == 1800


def test_legitimately_empty_result_does_not_raise(stub_prompt):
    """Regression pin: a prior draft placed the zero-threat check inside the
    except handler, so a well-formed, legitimately empty response crashed
    instead of degrading gracefully."""
    stub_prompt.set_response("s2", json.dumps({
        "system_context": "nothing plausible here",
        "assets": [], "trust_boundaries": [], "threats": [], "open_questions": [],
    }))
    tm = s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])
    assert tm.threats == []
    assert errlog.counts_by_stage().get("s2", 0) >= 1


def test_errlog_module_is_imported_and_used_as_a_module_not_called_directly():
    src = Path(s2_threatmodel.__file__).read_text(encoding="utf-8")
    assert "from vvaharness.util import errlog as _errlog" in src
    assert "_errlog.log(" in src


# ─────────────────────────────────────────────────────────────────────────────
# Repo-kind classifier
# ─────────────────────────────────────────────────────────────────────────────

def test_framework_kind_entry_points_alone_classify_as_web_api(ctx_framework_eps):
    """300 unauthenticated `framework`-kind entry points and no
    other web-api signal (no API artefacts, no framework-name manifest text)
    must still be classified web-api, not the 4-item library default."""
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence("/nonexistent-repo", cfg, ctx_framework_eps)
    assert "web-api" in s2_threatmodel._repo_kind(ev, ctx_framework_eps)


def test_stride_by_kind_covers_framework_like_network():
    assert s2_threatmodel._STRIDE_BY_KIND["framework"] == "S T R I D E"


def test_nested_manifest_is_found_and_node_modules_manifest_is_not(repo_nested_manifests):
    hits = s2_threatmodel._find_manifests(repo_nested_manifests, max_depth=3,
                                          max_total=12, max_per_kind=2)
    rels = {(kind, str(p.relative_to(repo_nested_manifests))) for kind, p in hits}
    assert ("pom.xml", "services/api/pom.xml") in rels
    assert not any(kind == "package.json" for kind, _ in hits)


def test_csproj_under_excluded_dir_is_not_selected(tmp_path):
    root = tmp_path / "repo"
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / "node_modules" / "pkg" / "fake.csproj").write_text("<Project/>", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "Real.csproj").write_text("<Project/>", encoding="utf-8")
    hits = s2_threatmodel._find_manifests(root, max_depth=3, max_total=12, max_per_kind=2)
    rels = {str(p.relative_to(root)) for _, p in hits}
    assert "src/Real.csproj" in rels
    assert not any("node_modules" in r for r in rels)


def test_twelve_package_json_do_not_crowd_out_the_one_pom_xml(tmp_path):
    root = tmp_path / "repo"
    for i in range(12):
        d = root / f"svc_{i:02d}"
        d.mkdir(parents=True)
        (d / "package.json").write_text("{}", encoding="utf-8")
    (root / "pom.xml").write_text("<project/>", encoding="utf-8")
    hits = s2_threatmodel._find_manifests(root, max_depth=3, max_total=12, max_per_kind=2)
    kinds = [kind for kind, _ in hits]
    assert "pom.xml" in kinds
    assert kinds.count("package.json") <= 2


# ─────────────────────────────────────────────────────────────────────────────
# Cap sanitization
# ─────────────────────────────────────────────────────────────────────────────

def test_cap_int_zero_means_emit_none():
    assert s2_threatmodel._cap_int(SimpleNamespace(max_assets=0), "max_assets", 40) == 0


def test_cap_int_negative_falls_back_to_default():
    assert s2_threatmodel._cap_int(SimpleNamespace(max_assets=-5), "max_assets", 40) == 40


def test_cap_int_non_numeric_falls_back_to_default():
    assert s2_threatmodel._cap_int(SimpleNamespace(max_assets="abc"), "max_assets", 40) == 40


def test_negative_max_threats_falls_back_to_default_not_len_minus_one(stub_prompt):
    threats = [{"id": f"T{i}", "threat": "x", "actor": "remote_unauth",
               "surface": f"ep{i}", "asset": "a", "impact": "high",
               "likelihood": "likely"} for i in range(3)]
    stub_prompt.set_response("s2", json.dumps({
        "system_context": "c", "assets": [{"name": "a", "sensitivity": "high"}],
        "trust_boundaries": [{"entry_point": f"ep{i}", "crossing": "x"} for i in range(3)],
        "threats": threats, "open_questions": [],
    }))
    tm = s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(max_threats=-1), [], [])
    assert len(tm.threats) == 3


def test_non_numeric_max_threats_falls_back_to_default_without_raising(stub_prompt):
    threats = [{"id": f"T{i}", "threat": "x", "actor": "remote_unauth",
               "surface": f"ep{i}", "asset": "a", "impact": "high",
               "likelihood": "likely"} for i in range(3)]
    stub_prompt.set_response("s2", json.dumps({
        "system_context": "c", "assets": [], "trust_boundaries": [],
        "threats": threats, "open_questions": [],
    }))
    tm = s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(max_threats="abc"), [], [])
    assert len(tm.threats) == 3


def test_max_threats_zero_yields_zero_threats(stub_prompt):
    threats = [{"id": "T1", "threat": "x", "actor": "remote_unauth", "surface": "ep",
               "asset": "a", "impact": "high", "likelihood": "likely"}]
    stub_prompt.set_response("s2", json.dumps({
        "system_context": "c", "assets": [], "trust_boundaries": [],
        "threats": threats, "open_questions": [],
    }))
    tm = s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(max_threats=0), [], [])
    assert tm.threats == []


# ─────────────────────────────────────────────────────────────────────────────
# Repo-shape evidence from the full file list, not the AST frontier sample
# ─────────────────────────────────────────────────────────────────────────────

def test_shape_blocks_see_every_top_level_directory_not_just_the_frontier(repo_deep):
    """repo_deep has repo_builders.N_SERVICES (12) top-level
    service directories and 240 files, more than the 220-file default AST
    frontier cap. Shape blocks (top_dirs, config_reps) must be computed from
    the full file list, or the last service — including its config file —
    disappears from the evidence entirely despite being real."""
    all_files = repo_builders.all_files_of(repo_deep)
    ctx = make_ctx(repo_root=str(repo_deep), all_files=all_files)
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(repo_deep), cfg, ctx)
    assert len(ev["top_dirs"]) == repo_builders.N_SERVICES
    assert len(ev["config_reps"]) == repo_builders.N_SERVICES


def test_config_reps_dedup_by_immediate_parent_not_top_level_directory():
    full_files = [f"services/svc_{i:02d}/config.yml" for i in range(12)]
    reps = s2_threatmodel._select_config_reps(full_files, max_reps=80)
    assert len(reps) == 12


def test_config_reps_prefer_breadth_before_a_second_rep_in_one_directory():
    full_files = ["a/one.yml", "a/two.yml", "b/three.yml"]
    reps = s2_threatmodel._select_config_reps(full_files, max_reps=2)
    dirs = {str(PurePosixPath(r).parent) for r in reps}
    assert dirs == {"a", "b"}


def test_config_reps_prefer_security_named_basenames_within_a_directory():
    full_files = ["svc/random.yml", "svc/application.yml"]
    reps = s2_threatmodel._select_config_reps(full_files, max_reps=1)
    assert reps == ["svc/application.yml"]


# ─────────────────────────────────────────────────────────────────────────────
# Document and manifest budgeting
# ─────────────────────────────────────────────────────────────────────────────

def test_threat_model_doc_is_not_starved_by_readme_and_security(tmp_path):
    """Regression: with a README-first candidate order, README.md and
    SECURITY.md alone can exhaust the whole document budget, so
    THREAT_MODEL.md and ARCHITECTURE.md never get read at all — not
    truncated, simply never opened. Reordering the candidates and dividing
    the remaining budget into thirds instead of halves fixes it."""
    for name in ("README.md", "SECURITY.md", "THREAT_MODEL.md", "ARCHITECTURE.md"):
        (tmp_path / name).write_text("x" * 15000, encoding="utf-8")
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    names = {n for n, _ in ev["docs"]}
    assert "THREAT_MODEL.md" in names


def test_large_readme_is_truncated_while_small_threat_model_doc_survives_whole(tmp_path):
    (tmp_path / "README.md").write_text("R" * 60000, encoding="utf-8")
    (tmp_path / "THREAT_MODEL.md").write_text("T" * 2000, encoding="utf-8")
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    docs = dict(ev["docs"])
    assert docs["THREAT_MODEL.md"] == "T" * 2000
    assert docs["README.md"].startswith("R" * 100)
    assert "…(truncated" in docs["README.md"]


def test_manifest_aggregate_cap_bounds_the_whole_block():
    manifests = [(f"m{i}.json", "x" * 4000) for i in range(17)]
    capped = s2_threatmodel._apply_manifest_total_cap(manifests, 24000)
    assert sum(len(t) for _, t in capped) <= 24000


def test_package_json_structural_truncation_preserves_the_framework_signal():
    raw = json.dumps({"_comment": "m" * 5000, "dependencies": {"express": "^4.18.0"}})
    text = s2_threatmodel._structural_truncate("package.json", raw, 4000)
    assert "express" in text
    assert len(text) <= 4000 + 40


def test_pyproject_toml_uses_tomllib_and_preserves_the_framework_signal():
    padding = "# padding line\n" * 800
    raw = padding + '[project]\nname = "x"\ndependencies = ["fastapi"]\n'
    text = s2_threatmodel._structural_truncate("pyproject.toml", raw, 4000)
    assert "fastapi" in text


def test_malformed_manifest_of_each_format_falls_back_without_raising():
    for kind in ("package.json", "composer.json", "pyproject.toml", "pom.xml"):
        text = s2_threatmodel._structural_truncate(kind, "{not valid at all!!", 100)
        assert isinstance(text, str)


def test_web_framework_signal_survives_manifest_truncation_package_json(tmp_path):
    payload = {"_comment": "m" * 5000, "dependencies": {"express": "^4.18.0"}}
    (tmp_path / "package.json").write_text(json.dumps(payload), encoding="utf-8")
    cfg = SimpleNamespace(step2=SimpleNamespace(max_manifest_chars=4000))
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    assert "web-api" in s2_threatmodel._repo_kind(ev, None)


def test_web_framework_signal_survives_manifest_truncation_pyproject_toml(tmp_path):
    padding = "# padding line\n" * 800
    (tmp_path / "pyproject.toml").write_text(
        padding + '[project]\nname = "x"\ndependencies = ["fastapi"]\n', encoding="utf-8")
    cfg = SimpleNamespace(step2=SimpleNamespace(max_manifest_chars=4000))
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    assert "web-api" in s2_threatmodel._repo_kind(ev, None)


# ─────────────────────────────────────────────────────────────────────────────
# Containment: keep host files out of the prompt
# ─────────────────────────────────────────────────────────────────────────────

def test_symlink_escaping_the_repo_root_is_not_read(repo_symlink_escape):
    ns = repo_symlink_escape
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(ns.root), cfg, None)
    bodies = " ".join(body for _, body in ev["docs"])
    assert ns.escape_marker not in bodies


def test_in_repo_symlink_is_still_read(repo_symlink_escape):
    ns = repo_symlink_escape
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(ns.root), cfg, None)
    bodies = " ".join(body for _, body in ev["docs"])
    assert ns.in_repo_marker in bodies


def test_repo_root_itself_as_a_symlink_still_works(tmp_path):
    real_root = tmp_path / "real_repo"
    real_root.mkdir()
    (real_root / "README.md").write_text("hello from the real root", encoding="utf-8")
    link_root = tmp_path / "link_repo"
    link_root.symlink_to(real_root)
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(link_root), cfg, None)
    assert dict(ev["docs"]).get("README.md") == "hello from the real root"


def test_symlink_escape_is_logged_once_via_errlog(repo_symlink_escape):
    ns = repo_symlink_escape
    cfg = SimpleNamespace(step2=SimpleNamespace())
    s2_threatmodel._gather_evidence(str(ns.root), cfg, None)
    assert errlog.counts_by_stage().get("s2", 0) >= 1


def test_dangling_symlink_returns_empty_without_raising(tmp_path):
    link = tmp_path / "README.md"
    link.symlink_to(tmp_path / "does-not-exist.txt")
    assert s2_threatmodel._read_capped(tmp_path, link, 100) == ""


def test_contained_rejects_a_path_that_merely_shares_a_string_prefix(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    evil = tmp_path / "repo-evil"
    evil.mkdir()
    (evil / "secret.txt").write_text("nope", encoding="utf-8")
    assert s2_threatmodel._contained(root, evil / "secret.txt") is None


# ─────────────────────────────────────────────────────────────────────────────
# Prompt block reorder; `repo_root` removed
# ─────────────────────────────────────────────────────────────────────────────

def test_repo_root_is_not_a_parameter_of_the_user_prompt_builder():
    import inspect
    params = inspect.signature(s2_threatmodel._build_user_prompt).parameters
    assert "repo_root" not in params


def test_repo_root_does_not_appear_anywhere_in_the_rendered_prompt(tmp_path):
    host_marker = str(tmp_path)
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [])
    assert host_marker not in text


def test_prompt_block_header_sequence_matches_the_layout_law(tmp_path):
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [])
    headers = [
        "LANGUAGE BREAKDOWN:",
        "COMPONENTS (top-level directories):",
        "REPRESENTATIVE CONFIGURATION",
        "API CONTRACT ARTEFACTS",
        "DOCUMENTATION:",
        "BUILD / DEPENDENCY MANIFESTS:",
        "KNOWN PRIOR CVEs",
        "DESIGN CONTROLS",
        "TARGET:",
        "MODULES (",
        "ENTRY POINTS (",
        "AST FUNCTION SITES",
        "AST CALL EDGES",
    ]
    positions = [text.index(h) for h in headers]
    assert positions == sorted(positions)


def test_cmdb_block_omitted_when_app_profile_is_absent(tmp_path):
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [], app_profile=None)
    assert "CMDB APPLICATION PROFILE" not in text


def test_cmdb_block_present_and_ordered_before_language_breakdown(tmp_path):
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    profile = AppProfile(application_id="APP1", externally_facing=True)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [], app_profile=profile)
    assert text.index("CMDB APPLICATION PROFILE") < text.index("LANGUAGE BREAKDOWN:")


def test_minimum_baseline_block_is_ordered_first(tmp_path):
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    _, baseline = s2_threatmodel._baseline_block(ev, None, "owasp")
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [],
                                             baseline_block=baseline)
    assert text.index("MINIMUM BASELINE") < text.index("LANGUAGE BREAKDOWN:")


def test_reorder_preserves_every_block_header(tmp_path):
    """Content-preservation check for the block reorder.

    Named for what it actually asserts. It does NOT measure prompt length —
    an earlier name claimed a five-percent bound that the body never checked,
    so the test could not fail on any length change at all.
    """
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, None)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [])
    for header in ("LANGUAGE BREAKDOWN:", "COMPONENTS (top-level directories):",
                  "DOCUMENTATION:", "BUILD / DEPENDENCY MANIFESTS:"):
        assert header in text


# ─────────────────────────────────────────────────────────────────────────────
# Docstring
# ─────────────────────────────────────────────────────────────────────────────

def test_docstring_does_not_claim_the_verify_stage_reads_the_threat_model():
    """The docstring must not reassert a consumer that does not exist.

    The previous form was `assert X not in ... or "does NOT" in doc`, whose
    second branch is always true — so it passed even if the false claim were
    reinstated. This checks the actual claim shape instead: any line naming the
    verify stage must be one that denies it reads the model.
    """
    doc = s2_threatmodel.__doc__ or ""
    naming = [ln.strip() for ln in doc.splitlines() if "s6" in ln.lower()]
    assert naming, "expected the docstring to say something about the verify stage"
    for line in naming:
        assert ("does NOT" in line or "not read" in line), (
            f"docstring line implies the verify stage consumes the model: {line!r}"
        )

def test_docstring_names_the_verified_consumers():
    doc = s2_threatmodel.__doc__
    assert "_threat_for" in doc
    assert "_has_authz_surface" in doc
    assert "_trust_context_block" in doc
    assert "to_compact_prompt_block" in doc
    assert "ctx.to_prompt_block" not in doc


# ─────────────────────────────────────────────────────────────────────────────
# The one orchestrator-side checkpoint guard
# ─────────────────────────────────────────────────────────────────────────────

def _minimal_scan_cfg(tmp_path):
    return SimpleNamespace(
        models=SimpleNamespace(threatmodel="stub-threatmodel", preprocess="stub-preprocess"),
        step0=SimpleNamespace(), step1=SimpleNamespace(), step2=SimpleNamespace(),
        inject=SimpleNamespace(cve_file=str(tmp_path / "no-cves.json"),
                               controls_file=str(tmp_path / "no-controls.yaml")),
        _data={},
    )


def _run_scan_through_s2(tmp_path, monkeypatch, *, tm: ThreatModel):
    from vvaharness.orchestrator import scan as scan_mod

    repo = tmp_path / "repo"
    repo.mkdir()
    cfg = _minimal_scan_cfg(tmp_path)

    monkeypatch.setattr(scan_mod.s0_seed, "run",
                        lambda *a, **k: SimpleNamespace(entry_points=[], unsafe_sinks=[]))
    monkeypatch.setattr(scan_mod.s1_preprocess, "run",
                        lambda *a, **k: SimpleNamespace(all_files=[]))
    monkeypatch.setattr(scan_mod.s2_threatmodel, "run", lambda *a, **k: tm)

    saved: list[tuple[str, object]] = []
    monkeypatch.setattr(scan_mod, "save_ckpt",
                        lambda ckpt_dir, run_id, step, obj: saved.append((step, obj)))
    monkeypatch.setattr(scan_mod._store, "register_run", lambda *a, **k: None)
    monkeypatch.setattr(scan_mod._store, "reset_run", lambda *a, **k: 0)
    monkeypatch.setattr(scan_mod._store, "save_callgraph", lambda *a, **k: None)
    monkeypatch.setattr(scan_mod._store, "load_callgraph", lambda *a, **k: None)

    args = SimpleNamespace(resume=False, stop_after="s2",
                           config=str(tmp_path / "config.yaml"), auto_step1=False)
    scan_mod.scan_repo(repo, "fixture-repo", None, args, cfg)
    return saved


def test_empty_threat_model_is_not_checkpointed(tmp_path, monkeypatch):
    saved = _run_scan_through_s2(tmp_path, monkeypatch, tm=ThreatModel())
    assert not any(step == "s2" for step, _ in saved)
    assert COUNTERS.get("s2_degraded") == 1


def test_nonempty_threat_model_is_checkpointed(tmp_path, monkeypatch):
    tm = ThreatModel(threats=[_threat("T1", surface="ep")])
    saved = _run_scan_through_s2(tmp_path, monkeypatch, tm=tm)
    assert any(step == "s2" and obj is tm for step, obj in saved)
    assert COUNTERS.get("s2_degraded") == 0


def test_threat_model_with_only_assets_no_threats_is_still_checkpointed(tmp_path, monkeypatch):
    """The guard is `tm.threats or tm.assets or tm.trust_boundaries` — an
    asset- or boundary-only model is not the degenerate all-defaults case
    `ThreatModel.model_validate({})` produces, and must still be kept."""
    tm = ThreatModel(assets=[Asset(name="a", sensitivity="high")])
    saved = _run_scan_through_s2(tmp_path, monkeypatch, tm=tm)
    assert any(step == "s2" and obj is tm for step, obj in saved)
    assert COUNTERS.get("s2_degraded") == 0


# ── Model-supplied ids are not unique, and must not be treated as keys ────────

def test_duplicate_ids_do_not_collapse_the_threat_list():
    """A weak model labelling every threat "T1" is a routine failure mode.

    Addressing threats by id would make those threats indistinguishable and
    return a single one from a cap of twenty — fewer threats than the old
    positional truncation kept, in exactly the case the ranking rewrite was
    meant to survive.
    """
    threats = [
        Threat(id="T1", threat=f"distinct threat {i}", actor="remote_unauth",
               surface=f"endpoint {i}", asset="data", impact="high",
               likelihood="possible")
        for i in range(30)
    ]
    tm = ThreatModel(threats=threats)
    out = s2_threatmodel._cap_threats(tm, 20)
    assert len(out.threats) == 20, (
        f"expected the cap to be filled, got {len(out.threats)}"
    )
    assert len({t.threat for t in out.threats}) == 20, "distinct threats were merged"


def test_duplicate_ids_below_the_cap_are_all_retained():
    threats = [
        Threat(id="T1", threat=f"t{i}", actor="remote_unauth", surface=f"s{i}",
               asset="a", impact="high", likelihood="possible")
        for i in range(3)
    ]
    out = s2_threatmodel._cap_threats(ThreatModel(threats=threats), 10)
    assert len(out.threats) == 3


def test_an_unparseable_id_does_not_take_down_the_stage():
    """`str.isdigit()` is true for characters `int()` cannot parse, and the sort
    runs on every call whether or not truncation is needed — so one odd
    character in one id would otherwise discard a fully parsed threat model."""
    threats = [
        Threat(id="T²", threat="superscript id", actor="remote_unauth",
               surface="s", asset="a", impact="high", likelihood="possible"),
        Threat(id="T2", threat="ordinary id", actor="remote_unauth",
               surface="s2", asset="a", impact="high", likelihood="possible"),
    ]
    out = s2_threatmodel._cap_threats(ThreatModel(threats=threats), 10)
    assert len(out.threats) == 2
    assert s2_threatmodel._id_ordinal("T²") == 1_000_000
    assert s2_threatmodel._id_ordinal("T7") == 7
    assert s2_threatmodel._id_ordinal("THREAT-A") == 1_000_000


def test_an_infinite_cap_falls_back_to_the_default():
    """`max_threats: .inf` is a valid YAML scalar; `int(float("inf"))` raises
    OverflowError, which must fall back like any other unusable value."""
    s2 = SimpleNamespace(max_threats=float("inf"))
    assert s2_threatmodel._cap_int(s2, "max_threats", 50) == 50


# ── The baseline audit must judge the model, not the harness's own cap ────────

def test_baseline_audit_is_not_confounded_by_truncation(stub_prompt):
    """Baseline dispositions are deliberately low-likelihood, so they rank last
    and truncation removes them first. Auditing after the cap would report a
    fully compliant model as being in breach."""
    disposed = [
        Threat(id=f"B{i}", threat=f"baseline item {i}", actor="remote_unauth",
               surface=f"surface {i}", asset="data", impact="low",
               likelihood="rare", evidence=f"baseline: BL-WEB-A0{i}")
        for i in range(1, 4)
    ]
    strong = [
        Threat(id=f"T{i}", threat=f"strong finding {i}", actor="remote_unauth",
               surface=f"ep {i}", asset="data", impact="existential",
               likelihood="almost_certain")
        for i in range(1, 6)
    ]
    tm = ThreatModel(threats=strong + disposed)

    # The cap keeps only the strong threats; every baseline disposition is cut.
    capped = s2_threatmodel._cap_threats(tm, 5)
    assert all(not (t.evidence or "").startswith("baseline:") for t in capped.threats)

    required = {"BL-WEB-A01", "BL-WEB-A02", "BL-WEB-A03"}
    pre_cap = s2_threatmodel._baseline_audit(tm, {"web-api"})
    post_cap = s2_threatmodel._baseline_audit(capped, {"web-api"})

    assert not (required & pre_cap), (
        "a compliant model was reported as undisposed before any truncation"
    )
    assert required & post_cap, (
        "sanity check: auditing after the cap is what produced the false report"
    )


def test_a_sole_covering_threat_is_promoted_back_over_the_cap():
    """The coverage-preserving half of truncation, asserted positively.

    Only the decline case had a test, so the mechanism this rewrite exists for —
    promoting a dropped threat back when it is a boundary's only cover — had no
    positive assertion at all.

    Three boundaries; the threat covering the third ranks last and would be cut
    by a cap of two. One of the two survivors covers a boundary that the other
    also covers, so it can be evicted without uncovering anything, which is what
    makes room.
    """
    tm = ThreatModel(
        trust_boundaries=[
            TrustBoundary(entry_point="ep-a", crossing="x"),
            TrustBoundary(entry_point="ep-b", crossing="x"),
        ],
        threats=[
            # Two high-ranked threats both covering ep-a: the second is
            # redundant for coverage purposes and is therefore evictable.
            _threat("T1", surface="ep-a", impact="existential",
                    likelihood="almost_certain"),
            _threat("T2", surface="ep-a", impact="critical",
                    likelihood="almost_certain"),
            # Sole cover of ep-b, ranked last, cut by a cap of two.
            _threat("T3", surface="ep-b", impact="low", likelihood="very_rare"),
        ],
    )
    capped = s2_threatmodel._cap_threats(tm, 2)
    surfaces = {t.surface for t in capped.threats}
    assert surfaces == {"ep-a", "ep-b"}, (
        f"every boundary must keep a cover; got {surfaces}"
    )
    assert "T3" in {t.id for t in capped.threats}
    assert len(capped.threats) == 2, "the cap must still be respected"
    assert COUNTERS.get("s2_threats_promoted") == 1


def test_boundary_matching_ignores_case_and_surrounding_whitespace():
    """Boundary-to-surface matching is the hinge of the whole promotion step, so
    pin its normalisation explicitly."""
    tm = ThreatModel(
        trust_boundaries=[TrustBoundary(entry_point="  EP-A  ", crossing="x"),
                          TrustBoundary(entry_point="ep-b", crossing="x")],
        threats=[
            _threat("T1", surface="ep-b", impact="existential",
                    likelihood="almost_certain"),
            _threat("T2", surface="ep-b", impact="critical",
                    likelihood="likely"),
            _threat("T3", surface="eP-a", impact="low", likelihood="very_rare"),
        ],
    )
    capped = s2_threatmodel._cap_threats(tm, 2)
    assert "T3" in {t.id for t in capped.threats}, (
        "case/whitespace difference defeated boundary matching"
    )


def test_run_audits_the_baseline_before_applying_the_cap(stub_prompt, tmp_path):
    """Drive the stage, not just the audit helper.

    The helper's pre/post-cap semantics were already covered, but nothing
    exercised the ORDERING inside `run()` — which is the thing that matters,
    because baseline dispositions are deliberately low-likelihood, rank last,
    and are the first thing truncation removes. Auditing after the cap reports a
    fully compliant model as being in breach and blames it for the harness's own
    truncation.
    """
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "^4.18.0"}}', encoding="utf-8")

    strong = [
        {"id": f"T{i}", "threat": f"strong finding {i}", "actor": "remote_unauth",
         "surface": f"ep {i}", "asset": "data", "impact": "existential",
         "likelihood": "almost_certain"}
        for i in range(1, 6)
    ]
    # Compliant dispositions for the web-api checklist, ranked last by design.
    disposed = [
        {"id": f"B{n}", "threat": f"baseline {bid}", "actor": "remote_unauth",
         "surface": f"surface {n}", "asset": "data", "impact": "low",
         "likelihood": "rare", "evidence": f"baseline: {bid}"}
        for n, bid in enumerate(
            [b for b, _ in s2_threatmodel._BASELINES["web-api"]], start=1)
    ]
    stub_prompt.set_response("s2", json.dumps({"threats": strong + disposed}))

    # A cap that keeps only the strong threats, cutting every disposition.
    cfg = _cfg(max_threats=5)
    cfg.step2.baseline = "auto"      # _cfg pins it to "none"; the audit needs a kind
    s2_threatmodel.run(str(tmp_path), "repo", cfg, [], [],
                       ctx=make_ctx(repo_root=str(tmp_path),
                                    all_files=["package.json"]))

    undisposed = COUNTERS.snapshot().get("s2_baseline_undisposed", "")
    assert undisposed == "", (
        "a model that disposed of every baseline item was reported as being in "
        f"breach because the audit ran after truncation: {undisposed!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# The dispatch seam: `via: deepagents` reaches the harness, everything else
# reaches the legacy registry (the exact-kwarg tests above pin the latter).
# ─────────────────────────────────────────────────────────────────────────────

def _valid_tm_json() -> str:
    return json.dumps({
        "system_context": "ctx",
        "assets": [{"name": "a", "sensitivity": "high"}],
        "trust_boundaries": [{"entry_point": "ep", "crossing": "x",
                              "reachable_assets": ["a"]}],
        "threats": [{"id": "T1", "threat": "t", "actor": "remote_unauth",
                     "surface": "ep", "asset": "a", "impact": "high",
                     "likelihood": "possible"}],
        "open_questions": [],
    })


def _deepagents_cfg(**step2_kwargs):
    return SimpleNamespace(
        step2=SimpleNamespace(baseline="none", **step2_kwargs),
        models=SimpleNamespace(
            threatmodel=SimpleNamespace(id="harness-model", via="deepagents")),
    )


def test_deepagents_via_reaches_the_harness_oneshot_rooted_at_the_repo(
        stub_prompt, monkeypatch):
    """Fakes ONE LEVEL BELOW the dispatcher — the harness one-shot — so the
    REAL `dispatch_prompt` and the real deepagents `prompt()` run, proving the
    stage uses the shared helper's deepagents branch (options built with the
    scanned repo as cwd), not merely that it called something."""
    seen = {}

    def fake_run_oneshot(user_prompt, options):
        seen["prompt"] = user_prompt
        seen["options"] = options
        return SimpleNamespace(result_text=_valid_tm_json())

    monkeypatch.setattr(s2_threatmodel._deepagents, "run_oneshot",
                        fake_run_oneshot)
    tm = s2_threatmodel.run("/nonexistent-repo", "repo",
                            _deepagents_cfg(), [], [])
    assert tm.threats and tm.threats[0].id == "T1"
    assert seen["options"].cwd == Path("/nonexistent-repo")
    assert seen["options"].model == "harness-model"
    assert stub_prompt.calls == [], \
        "a deepagents role must never reach registry.prompt"


def test_repair_retry_stays_on_the_deepagents_route(stub_prompt, monkeypatch):
    """The one-shot repair retry goes through the same dispatch seam as the
    primary call: the registry has no deepagents backend any more, so a retry
    falling back to `registry.prompt` would raise `Unknown backend` instead of
    repairing the response."""
    responses = ['{"assets": ["bare-string-breaks-schema"]}', _valid_tm_json()]
    prompts = []

    def fake_run_oneshot(user_prompt, options):
        prompts.append(user_prompt)
        return SimpleNamespace(result_text=responses[len(prompts) - 1])

    monkeypatch.setattr(s2_threatmodel._deepagents, "run_oneshot",
                        fake_run_oneshot)
    tm = s2_threatmodel.run("/nonexistent-repo", "repo",
                            _deepagents_cfg(), [], [])
    assert tm.threats, "the repair retry must recover the threat model"
    assert len(prompts) == 2, "original call plus exactly one repair"
    assert prompts[1].startswith("REPAIR TASK:")
    assert stub_prompt.calls == [], \
        "neither the original call nor the retry may reach registry.prompt"
