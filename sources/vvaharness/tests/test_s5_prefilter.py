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

"""Unit tests for s5_prefilter AST/callgraph evidence backfill."""
from __future__ import annotations

from types import SimpleNamespace

from vvaharness.models import ContextPackage, EntryPoint, Finding, VulnClass
from vvaharness.pipeline.stages import s5_prefilter


def _cfg(*, require_evidence: bool = True,
         min_pre_confidence: float = 0.0,
         ast_backfill_evidence: bool = True,
         semantic: bool = False):
    return SimpleNamespace(
        step5_prefilter=SimpleNamespace(
            require_evidence=require_evidence,
            min_pre_confidence=min_pre_confidence,
            ast_backfill_evidence=ast_backfill_evidence,
        ),
        step6_verify=SimpleNamespace(),
        step7_dedup=SimpleNamespace(
            line_tolerance=3,
            pre_verify_threshold=999,
            semantic=semantic,
        ),
    )


def _finding(*, file: str = "svc.py", line: int = 42,
             vuln_class: VulnClass = VulnClass.INJECTION,
             source_ref=None, sink_ref=None) -> Finding:
    return Finding(
        chunk_id="taint-01",
        file=file,
        line_start=line,
        line_end=line,
        vuln_class=vuln_class,
        title="test finding",
        description="desc",
        code_snippet="snippet",
        confidence=0.9,
        source_ref=source_ref,
        sink_ref=sink_ref,
    )


def test_no_refs_dropped_even_when_backfill_can_reach_entry_anchor():
    # Precision-first: an entry anchor exists that COULD backfill this finding,
    # but require_evidence judges the finding's own (empty) refs first, so it is
    # dropped before backfill ever runs. Backfill decorates survivors only.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
        entry_points=[
            EntryPoint(file="svc.py", function="handle", kind="network", reachable_from_unauth=True)
        ],
        call_graph_files={"handle": ["svc.py:12"]},
    )
    f = _finding(file="svc.py", line=40, source_ref=None, sink_ref=None)

    keep, dropped = s5_prefilter.run([f], ctx, _cfg())

    assert keep == []
    assert len(dropped) == 1
    assert dropped[0].reason == "UNCONFIRMED"
    assert "missing source_ref/sink_ref" in dropped[0].detail


def test_no_refs_dropped_even_when_seed_taint_path_could_backfill():
    # A seed taint path could supply source/sink, but under require_evidence the
    # finding must arrive with its own evidence; backfill cannot manufacture it.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["api.py", "svc.py"],
        seed_taint_paths=[["api.py:9", "svc.py:40", "svc.py:44"]],
    )
    f = _finding(file="svc.py", line=44, source_ref=None, sink_ref=None)

    keep, dropped = s5_prefilter.run([f], ctx, _cfg())

    assert keep == []
    assert len(dropped) == 1
    assert dropped[0].reason == "UNCONFIRMED"


def test_finding_with_own_evidence_is_kept_and_backfill_decorates_it():
    # A finding that already carries the evidence the gate demands survives, and
    # backfill still decorates it on the keep-path (here filling the info-leak
    # source ref) without changing the kept/dropped outcome.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["config.py"],
    )
    f = _finding(file="config.py", line=7, vuln_class=VulnClass.INFO_LEAK,
                 source_ref="config.py:7", sink_ref="config.py:7")

    keep, dropped = s5_prefilter.run([f], ctx, _cfg())

    assert len(dropped) == 0
    assert len(keep) == 1
    assert keep[0].source_ref == "config.py:7"
    assert keep[0].sink_ref == "config.py:7"


def test_backfill_decorates_survivors_when_evidence_not_required():
    # With require_evidence off, a finding missing its sink ref survives the gate
    # and backfill fills the sink from the entry anchor on the keep-path.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
        entry_points=[
            EntryPoint(file="svc.py", function="handle", kind="network", reachable_from_unauth=True)
        ],
        call_graph_files={"handle": ["svc.py:12"]},
    )
    f = _finding(file="svc.py", line=40, source_ref=None, sink_ref=None)

    keep, dropped = s5_prefilter.run([f], ctx, _cfg(require_evidence=False))

    assert len(dropped) == 0
    assert len(keep) == 1
    assert keep[0].source_ref == "svc.py:12"
    assert keep[0].sink_ref == "svc.py:40"


def test_missing_evidence_still_drops_when_backfill_disabled():
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
    )
    f = _finding(file="svc.py", line=20, source_ref=None, sink_ref=None)

    keep, dropped = s5_prefilter.run(
        [f],
        ctx,
        _cfg(ast_backfill_evidence=False),
    )

    assert keep == []
    assert len(dropped) == 1
    assert dropped[0].reason == "UNCONFIRMED"
    assert "missing source_ref/sink_ref" in dropped[0].detail


def test_prefilter_does_not_collapse_different_cwes_in_same_class_overlap():
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
    )
    a = _finding(file="svc.py", line=40, vuln_class=VulnClass.LOGIC,
                 source_ref="svc.py:40", sink_ref="svc.py:45")
    b = _finding(file="svc.py", line=42, vuln_class=VulnClass.LOGIC,
                 source_ref="svc.py:42", sink_ref="svc.py:66")
    a.line_end = 45
    b.line_end = 66
    a.cwe = "CWE-863"
    b.cwe = "CWE-778"

    keep, dropped = s5_prefilter.run([a, b], ctx, _cfg(require_evidence=True))

    assert len(keep) == 2
    assert dropped == []


def test_prefilter_keeps_logic_overlap_when_one_cwe_missing():
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["svc.py"],
    )
    a = _finding(file="svc.py", line=40, vuln_class=VulnClass.LOGIC,
                 source_ref="svc.py:40", sink_ref="svc.py:45")
    b = _finding(file="svc.py", line=42, vuln_class=VulnClass.LOGIC,
                 source_ref="svc.py:42", sink_ref="svc.py:66")
    a.line_end = 45
    b.line_end = 66
    a.cwe = "CWE-863"
    b.cwe = None

    keep, dropped = s5_prefilter.run([a, b], ctx, _cfg(require_evidence=True))

    assert len(keep) == 2
    assert dropped == []


def test_hardcoded_cwe_exempt_from_require_evidence_gate_no_title_keywords():
    # CWE-798 finding with a terse title containing NO regex keywords and no
    # source/sink refs.  Must survive require_evidence because the CWE field
    # alone is sufficient — the committed value IS the evidence.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["settings.py"],
    )
    f = _finding(file="settings.py", line=25,
                 vuln_class=VulnClass.OTHER,   # scanner may emit OTHER for hardcoded creds
                 source_ref=None, sink_ref=None)
    f.cwe = "CWE-798"
    f.title = "settings.py exposes a literal value"  # intentionally no 'hardcoded' keyword

    keep, dropped = s5_prefilter.run([f], ctx, _cfg(require_evidence=True))

    assert len(keep) == 1, "CWE-798 must be kept even without source/sink refs"
    assert dropped == []


def test_hardcoded_cwe_256_exempt_from_require_evidence_gate():
    # CWE-256 (Plaintext Storage of a Password) is a point-of-occurrence finding;
    # no taint flow exists.  Must survive regardless of source/sink state.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["models.py"],
    )
    f = _finding(file="models.py", line=12,
                 vuln_class=VulnClass.OTHER,
                 source_ref=None, sink_ref=None)
    f.cwe = "CWE-256"
    f.title = "User model field stored without hashing"  # no regex keyword

    keep, dropped = s5_prefilter.run([f], ctx, _cfg(require_evidence=True))

    assert len(keep) == 1, "CWE-256 must be kept even without source/sink refs"
    assert dropped == []


def test_non_hardcoded_cwe_still_requires_evidence():
    # CWE-89 (SQL injection) with no source/sink must still be dropped —
    # the CWE-level bypass applies only to _HARDCODED_CWES.
    ctx = ContextPackage(
        repo_root=".",
        language="python",
        all_files=["views.py"],
    )
    f = _finding(file="views.py", line=50,
                 vuln_class=VulnClass.INJECTION,
                 source_ref=None, sink_ref=None)
    f.cwe = "CWE-89"
    f.title = "SQL query built from user input"  # no regex keyword match

    keep, dropped = s5_prefilter.run([f], ctx, _cfg(require_evidence=True))

    assert keep == []
    assert len(dropped) == 1
    assert "missing source_ref/sink_ref" in dropped[0].detail


# ── pre_verify_threshold: 0 means "always run", not "unset" and not "never" ──
# default.yaml documents `pre_verify_threshold: 0` as "0 = always run", but two
# independent layers broke that. The value was resolved with an `or` chain, so
# the falsy 0 fell through to step7_dedup's 25; and the trigger was guarded by
# `if pre_thresh and ...`, which reads 0 as "never run" — the exact inverse of
# the documented meaning. Every benchmark run logged "≥ pre_verify_threshold 25"
# while its profile asked for 0.

def _dedup_cfg(*, s5_thresh, s7_thresh=25):
    cfg = _cfg(require_evidence=False, semantic=True)
    cfg.step5_prefilter.pre_verify_threshold = s5_thresh
    cfg.step5_prefilter.pre_verify_semantic = True
    cfg.step7_dedup.pre_verify_threshold = s7_thresh
    return cfg


def _capture_dedup(monkeypatch):
    """Record the survivor count s7_dedup.run is called with, if at all."""
    calls: list[int] = []

    def fake_run(findings, cfg, label=None, ctx=None):
        calls.append(len(findings))
        return list(findings), []

    monkeypatch.setattr(s5_prefilter.s7_dedup, "run", fake_run)
    return calls


def test_pre_verify_threshold_zero_runs_dedup_on_a_single_finding(monkeypatch):
    calls = _capture_dedup(monkeypatch)
    ctx = ContextPackage(repo_root=".", language="python", all_files=["a.py"])
    f = _finding(file="a.py", line=10)

    keep, _ = s5_prefilter.run([f], ctx, _dedup_cfg(s5_thresh=0))

    assert calls == [1], (
        "threshold 0 must always run semantic dedup; it either fell through to "
        "the step7 default of 25 or was read as 'never run'")
    assert len(keep) == 1


def test_pre_verify_threshold_zero_does_not_inherit_step7_fallback(monkeypatch):
    # One survivor is far below step7's 25. If the `or` chain regressed, the
    # threshold becomes 25, 1 >= 25 is false, and dedup never runs.
    calls = _capture_dedup(monkeypatch)
    ctx = ContextPackage(repo_root=".", language="python", all_files=["a.py"])

    s5_prefilter.run([_finding(file="a.py", line=10)], ctx,
                     _dedup_cfg(s5_thresh=0, s7_thresh=25))

    assert calls, "step7's fallback of 25 suppressed an explicit 0"


def test_explicit_positive_threshold_still_gates(monkeypatch):
    # The knob must keep working: below the threshold, dedup is skipped.
    calls = _capture_dedup(monkeypatch)
    ctx = ContextPackage(repo_root=".", language="python", all_files=["a.py"])

    s5_prefilter.run([_finding(file="a.py", line=10)], ctx,
                     _dedup_cfg(s5_thresh=5))

    assert calls == [], "1 survivor is below a threshold of 5; dedup must skip"


def test_unset_threshold_falls_back_to_step7(monkeypatch):
    # Backward compatibility: a config that never migrated the key still
    # honours step7_dedup's value. None, unlike 0, genuinely means "unset".
    calls = _capture_dedup(monkeypatch)
    ctx = ContextPackage(repo_root=".", language="python", all_files=["a.py"])

    s5_prefilter.run([_finding(file="a.py", line=10)], ctx,
                     _dedup_cfg(s5_thresh=None, s7_thresh=1))

    assert calls == [1], "unset on step5 must inherit step7's threshold of 1"
