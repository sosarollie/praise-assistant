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

"""Unit tests for vvaharness.pipeline.stages.s8_chain.

Offline & deterministic: the LLM call is monkeypatched at the stage's shared
dispatch seam (s8_chain._deepagents.dispatch_prompt), no network, no real
`claude`. errlog is redirected into tmp_path so the shared module singleton
(_errlog._path) never escapes a test.
"""
from __future__ import annotations

import json

import pytest

from vvaharness.models import (
    Chain,
    ContextPackage,
    DroppedFinding,
    FinalReport,
    Finding,
    RankedFinding,
    Severity,
    VulnClass,
)
from vvaharness.pipeline.stages import s8_chain
from vvaharness.util import errlog as _errlog


def _finding(line_start: int, vc: VulnClass = VulnClass.OTHER,
             title: str = "f") -> Finding:
    return Finding(
        chunk_id="chunk-01",
        file="src/mod.c",
        line_start=line_start,
        line_end=line_start + 1,
        vuln_class=vc,
        title=title,
        description="desc",
        code_snippet="x = 1;",
        confidence=0.9,
    )


def _ctx() -> ContextPackage:
    return ContextPackage(repo_root="/repo", language="c")


class _Models:
    chain = "model-chain"


class _Step8:
    max_tokens = None
    timeout = 1800


class _Cfg:
    models = _Models()
    step8 = _Step8()


def _patch_prompt(monkeypatch, payload):
    """payload may be a str (returned verbatim) or a dict (json-encoded)."""
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    calls = {}

    def fake_prompt(user, **kwargs):
        calls["user"] = user
        calls["kwargs"] = kwargs
        return raw

    monkeypatch.setattr(s8_chain._deepagents, "dispatch_prompt", fake_prompt)
    return calls


def test_coerce_sev_allows_critical():
    # CVSS 3.1 compliance: "critical" is a first-class label (no collapse).
    assert s8_chain._coerce_sev("critical") is Severity.CRITICAL
    assert s8_chain._coerce_sev("CRITICAL") is Severity.CRITICAL
    assert s8_chain._coerce_sev("  Critical  ") is Severity.CRITICAL


def test_coerce_sev_enum_critical_passthrough():
    out = s8_chain._coerce_sev(Severity.CRITICAL.value)
    assert out is Severity.CRITICAL
    assert out.value == "critical"


def test_sev_from_band_maps_bands():
    assert s8_chain._sev_from_band("Critical") is Severity.CRITICAL
    assert s8_chain._sev_from_band("High") is Severity.HIGH
    assert s8_chain._sev_from_band("Medium") is Severity.MEDIUM
    assert s8_chain._sev_from_band("low") is Severity.LOW
    assert s8_chain._sev_from_band(None) is None
    assert s8_chain._sev_from_band("Unknown") is None
    assert s8_chain._sev_from_band("None") is None


def test_final_severity_prefers_vsvs_then_base_then_llm():
    from types import SimpleNamespace as NS
    # 1. VulContextSeverity (environmental) is authoritative when present.
    f = NS(vsvs_rating="Critical", cvss_rating="Medium")
    assert s8_chain._final_severity(f, Severity.LOW) is Severity.CRITICAL
    # 2. Base CVSS band when there is no environmental band.
    f = NS(vsvs_rating=None, cvss_rating="High")
    assert s8_chain._final_severity(f, Severity.LOW) is Severity.HIGH
    # 3. LLM label only when no CVSS vector exists at all.
    f = NS(vsvs_rating=None, cvss_rating=None)
    assert s8_chain._final_severity(f, Severity.HIGH) is Severity.HIGH
    f = NS(vsvs_rating=None, cvss_rating="Medium")
    assert s8_chain._final_severity(f, Severity.HIGH) is Severity.MEDIUM


def test_offensive_rank_orders_p1_first():
    from types import SimpleNamespace as NS
    assert s8_chain._offensive_rank(NS(offensive_priority="P1")) == 1
    assert s8_chain._offensive_rank(NS(offensive_priority="P4")) == 4
    assert s8_chain._offensive_rank(NS(offensive_priority=None)) == 9
    assert s8_chain._offensive_rank(NS(offensive_priority="bogus")) == 9


def test_coerce_sev_passthrough_valid_levels():
    assert s8_chain._coerce_sev("high") is Severity.HIGH
    assert s8_chain._coerce_sev("medium") is Severity.MEDIUM
    assert s8_chain._coerce_sev("low") is Severity.LOW
    assert s8_chain._coerce_sev("info") is Severity.INFO


def test_coerce_sev_falsy_and_unknown_default_to_info():
    assert s8_chain._coerce_sev(None) is Severity.INFO
    assert s8_chain._coerce_sev("") is Severity.INFO
    assert s8_chain._coerce_sev(0) is Severity.INFO
    assert s8_chain._coerce_sev("bogus") is Severity.INFO


def test_coerce_sev_non_string_truthy_coerced():
    # A truthy non-string (e.g. int 7) is str()'d, not a valid enum -> INFO.
    assert s8_chain._coerce_sev(7) is Severity.INFO
    # A list is truthy -> str() -> not valid -> INFO (never crashes).
    assert s8_chain._coerce_sev(["high"]) is Severity.INFO


def test_coerce_sev_now_returns_critical():
    assert s8_chain._coerce_sev("critical") is Severity.CRITICAL
    assert s8_chain._coerce_sev(Severity.CRITICAL.value) is Severity.CRITICAL


def test_run_no_findings_returns_empty_report(monkeypatch):
    # dispatch_prompt() must NOT be called when there are no findings.
    def boom(*a, **k):  # pragma: no cover - would fail the test if hit
        raise AssertionError("dispatch_prompt() called with no findings")
    monkeypatch.setattr(s8_chain._deepagents, "dispatch_prompt", boom)

    dropped = [DroppedFinding(file="a.c", line=1, vuln_class=VulnClass.OTHER,
                              title="t", chunk_id="c", reason="FALSE_POSITIVE")]
    rep = s8_chain.run([], _ctx(), _Cfg(), dropped=dropped,
                       raw_findings_count=3)
    assert isinstance(rep, FinalReport)
    assert rep.findings == []
    assert rep.chains == []
    assert rep.dropped == dropped
    assert rep.raw_findings_count == 3
    assert "No findings survived" in rep.summary


def test_run_ranks_findings_and_builds_chain(monkeypatch):
    findings = [_finding(10, title="A"), _finding(20, title="B"),
                _finding(30, title="C")]
    payload = {
        "summary": "Two bugs chain into RCE.",
        "ranked_findings": [
            {"index": 0, "severity": "high", "exploitability_notes": "n0"},
            {"index": 1, "severity": "medium", "exploitability_notes": "n1"},
            {"index": 2, "severity": "low", "exploitability_notes": "n2"},
        ],
        "chains": [
            {"title": "A->B", "steps": [0, 1], "severity": "critical",
             "blocked_by_controls": ["sandbox"], "narrative": "boom"},
        ],
    }
    calls = _patch_prompt(monkeypatch, payload)

    rep = s8_chain.run(findings, _ctx(), _Cfg(), raw_findings_count=3)

    # prompt was invoked with the configured model + tag.
    assert calls["kwargs"]["model"] == "model-chain"
    assert calls["kwargs"]["tag"] == "s8 chain"

    assert rep.summary == "Two bugs chain into RCE."
    assert len(rep.findings) == 3
    # Sorted by severity: HIGH(A) < MEDIUM(B) < LOW(C).
    sevs = [rf.severity for rf in rep.findings]
    assert sevs == [Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    assert rep.findings[0].finding.title == "A"
    assert rep.findings[0].exploitability_notes == "n0"

    assert len(rep.chains) == 1
    assert rep.chains[0].severity is Severity.CRITICAL
    assert rep.chains[0].blocked_by_controls == ["sandbox"]
    # steps remapped to post-sort indices and still reference A,B.
    titles = [rep.findings[i].finding.title for i in rep.chains[0].steps]
    assert set(titles) == {"A", "B"}


def test_run_uncovered_findings_default_to_info(monkeypatch):
    findings = [_finding(10, title="A"), _finding(20, title="B")]
    payload = {
        "summary": "s",
        "ranked_findings": [
            {"index": 0, "severity": "high", "exploitability_notes": "n0"},
        ],
        "chains": [],
    }
    _patch_prompt(monkeypatch, payload)
    rep = s8_chain.run(findings, _ctx(), _Cfg())

    # B was never ranked -> auto-added at INFO with the canned note.
    by_title = {rf.finding.title: rf for rf in rep.findings}
    assert by_title["A"].severity is Severity.HIGH
    assert by_title["B"].severity is Severity.INFO
    assert by_title["B"].exploitability_notes == "(not ranked by chaining pass)"
    # Both codepaths stamp the band onto the Finding too. It used to live only on the wrapper,
    # so anything holding a bare Finding -- a remediator, a validator, a case file -- had no
    # severity and silently defaulted to MEDIUM.
    assert by_title["A"].finding.severity is Severity.HIGH
    assert by_title["B"].finding.severity is Severity.INFO


def test_chain_out_of_range_step_filtered_and_annotated(monkeypatch):
    findings = [_finding(10, title="A"), _finding(20, title="B")]
    payload = {
        "summary": "s",
        "ranked_findings": [
            {"index": 0, "severity": "high", "exploitability_notes": "n0"},
            {"index": 1, "severity": "high", "exploitability_notes": "n1"},
        ],
        # step 99 is out of range -> dropped; 0 and 1 survive -> >=2 kept.
        "chains": [
            {"title": "T", "steps": [0, 99, 1], "severity": "high",
             "narrative": "base"},
        ],
    }
    _patch_prompt(monkeypatch, payload)
    rep = s8_chain.run(findings, _ctx(), _Cfg())

    assert len(rep.chains) == 1
    chain = rep.chains[0]
    # only the two valid steps remain.
    assert len(chain.steps) == 2
    for s in chain.steps:
        assert 0 <= s < len(rep.findings)
    # narrative annotated with the dropped index.
    assert "base" in chain.narrative
    assert "[99]" in chain.narrative
    assert "not in the verified" in chain.narrative


def test_chain_with_fewer_than_two_valid_steps_dropped(monkeypatch):
    findings = [_finding(10, title="A"), _finding(20, title="B")]
    payload = {
        "summary": "s",
        "ranked_findings": [
            {"index": 0, "severity": "high", "exploitability_notes": "n0"},
            {"index": 1, "severity": "high", "exploitability_notes": "n1"},
        ],
        # only one valid step (0); 50 and 51 out of range -> chain dropped.
        "chains": [
            {"title": "lonely", "steps": [0, 50, 51], "severity": "high",
             "narrative": "x"},
        ],
    }
    _patch_prompt(monkeypatch, payload)
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert rep.chains == []


def test_chain_non_int_steps_filtered(monkeypatch):
    findings = [_finding(10, title="A"), _finding(20, title="B")]
    payload = {
        "summary": "s",
        "ranked_findings": [
            {"index": 0, "severity": "high", "exploitability_notes": "n0"},
            {"index": 1, "severity": "high", "exploitability_notes": "n1"},
        ],
        # "0" (string) and True (bool) are NOT valid int steps.
        "chains": [
            {"title": "mixed", "steps": ["0", True, 0, 1], "severity": "high",
             "narrative": "n"},
        ],
    }
    _patch_prompt(monkeypatch, payload)
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert len(rep.chains) == 1
    assert len(rep.chains[0].steps) == 2
    assert "not in the verified" not in rep.chains[0].narrative
    assert rep.chains[0].narrative == "n"


def test_ranked_findings_off_schema_entries_skipped(monkeypatch):
    findings = [_finding(10, title="A"), _finding(20, title="B")]
    payload = {
        "summary": "s",
        "ranked_findings": [
            "not-a-dict",                       # skipped (not dict)
            {"index": "1"},                     # string index -> skipped
            {"index": True},                    # bool index -> skipped
            {"index": -1},                      # negative -> skipped
            {"index": 99},                      # out of range -> skipped
            {"index": 0, "severity": "high"},   # valid
            {"index": 0, "severity": "low"},    # duplicate index -> skipped
        ],
        "chains": [],
    }
    _patch_prompt(monkeypatch, payload)
    rep = s8_chain.run(findings, _ctx(), _Cfg())

    by_title = {rf.finding.title: rf for rf in rep.findings}
    # index 0 (A) ranked HIGH exactly once; the duplicate low entry ignored.
    assert by_title["A"].severity is Severity.HIGH
    # B never validly ranked -> INFO.
    assert by_title["B"].severity is Severity.INFO


def test_null_lists_do_not_crash(monkeypatch):
    findings = [_finding(10, title="A")]
    # explicit JSON null for both lists; .get returns None, must be guarded.
    payload = {"summary": "s", "ranked_findings": None, "chains": None}
    _patch_prompt(monkeypatch, payload)
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert len(rep.findings) == 1
    assert rep.findings[0].severity is Severity.INFO
    assert rep.chains == []


def test_dropped_duplicate_canonical_idx_remapped(monkeypatch):
    # Findings supplied in order [low, high]; sort reorders so orig idx 1
    # (high) becomes sorted idx 0. A DUPLICATE pointing at canonical_idx=1
    # must be remapped to 0.
    findings = [_finding(10, title="LOW"), _finding(20, title="HIGH")]
    payload = {
        "summary": "s",
        "ranked_findings": [
            {"index": 0, "severity": "low", "exploitability_notes": ""},
            {"index": 1, "severity": "high", "exploitability_notes": ""},
        ],
        "chains": [],
    }
    _patch_prompt(monkeypatch, payload)
    dup = DroppedFinding(file="d.c", line=5, vuln_class=VulnClass.OTHER,
                         title="dup", chunk_id="c", reason="DUPLICATE",
                         canonical_idx=1)
    rep = s8_chain.run(findings, _ctx(), _Cfg(), dropped=[dup])

    # post-sort: index 0 is HIGH. canonical_idx remapped 1 -> 0.
    assert rep.findings[0].finding.title == "HIGH"
    assert rep.dropped[0].canonical_idx == 0


def test_dropped_canonical_idx_not_remapped_when_hydration_fails(monkeypatch):
    findings = [_finding(10, title="LOW"), _finding(20, title="HIGH")]
    payload = {
        "summary": "s",
        "ranked_findings": [
            {"index": 0, "severity": "low", "exploitability_notes": ""},
            {"index": 1, "severity": "high", "exploitability_notes": ""},
        ],
        "chains": [
            {"title": "boom", "steps": [0, 1], "severity": "high",
             "blocked_by_controls": [{"not": "a string"}], "narrative": "n"},
        ],
    }
    _patch_prompt(monkeypatch, payload)
    dup = DroppedFinding(file="d.c", line=5, vuln_class=VulnClass.OTHER,
                         title="dup", chunk_id="c", reason="DUPLICATE",
                         canonical_idx=1)
    rep = s8_chain.run(findings, _ctx(), _Cfg(), dropped=[dup])

    # Degraded path: unranked INFO findings in ORIGINAL order, no chains.
    assert "hydration failed" in rep.summary
    assert [rf.finding.title for rf in rep.findings] == ["LOW", "HIGH"]
    # canonical_idx left at its ORIGINAL value (not remapped to 0).
    assert rep.dropped[0].canonical_idx == 1


def test_run_llm_failure_returns_unranked_report(monkeypatch, capsys):
    findings = [_finding(10, title="A"), _finding(20, title="B")]

    def boom(*a, **k):
        raise RuntimeError("provider down")
    monkeypatch.setattr(s8_chain._deepagents, "dispatch_prompt", boom)

    rep = s8_chain.run(findings, _ctx(), _Cfg(), raw_findings_count=2)
    assert len(rep.findings) == 2
    assert all(rf.severity is Severity.INFO for rf in rep.findings)
    # The degraded path stamps the Finding too, so a consumer downstream of it is not left
    # reading MEDIUM for something the report calls INFO.
    assert all(rf.finding.severity is Severity.INFO for rf in rep.findings)
    assert rep.chains == []
    assert "Chain analysis call failed" in rep.summary
    assert "provider down" in rep.summary
    # warning went to stderr, not stdout.
    err = capsys.readouterr().err
    assert "chain LLM call failed" in err


def test_llm_failure_summary_is_redacted(monkeypatch):
    """A provider error body can quote request fragments — credential-shaped
    material or repository source — and the summary ships in the DELIVERED
    report. It must pass through redact(), never raw `{e}`."""
    findings = [_finding(10, title="A")]

    def boom(*a, **k):
        raise RuntimeError("401 unauthorized; request used key "
                           "sk-ant-api03-verysecretmaterial")
    monkeypatch.setattr(s8_chain._deepagents, "dispatch_prompt", boom)

    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert "Chain analysis call failed" in rep.summary
    assert "verysecretmaterial" not in rep.summary
    assert "[REDACTED-ANTHROPIC-KEY]" in rep.summary


def test_none_response_degrades_instead_of_aborting(monkeypatch):
    """A backend that yields None makes extract_json raise TypeError; the old
    `except ValueError`-only parse handler let that escape and kill the run at
    the FINAL stage, after all detection spend. It must degrade to the
    unranked report like every other malformed-output shape."""
    findings = [_finding(10, title="A")]
    monkeypatch.setattr(s8_chain._deepagents, "dispatch_prompt",
                        lambda *a, **k: None)
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert rep.degraded is True
    assert "failed to parse" in rep.summary
    assert len(rep.findings) == 1


def test_raw_tail_redacted_before_truncation(monkeypatch, capsys):
    """Ordering hazard: truncating BEFORE redacting can bisect a secret so
    its pattern no longer matches. A key whose start lies outside the
    raw[-200:] window used to leak its body into stderr/errlog; the full text
    must be redacted first, then sliced."""
    findings = [_finding(10, title="A")]
    secret = "sk-ant-api03-verysecretmaterial"
    # tail window starts mid-secret: the truncated "t-api03-…" no longer
    # matches the sk-ant- pattern under the old order.
    raw = "no json here " + secret + ("y" * 175)
    _patch_prompt(monkeypatch, raw)
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    err = capsys.readouterr().err
    assert "verysecretmaterial" not in err
    assert "verysecretmaterial" not in rep.summary


def test_run_unparseable_response_returns_unranked_report(monkeypatch):
    findings = [_finding(10, title="A")]
    _patch_prompt(monkeypatch, "this is not json at all {{{")
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert len(rep.findings) == 1
    assert rep.findings[0].severity is Severity.INFO
    assert "failed to parse" in rep.summary


def test_run_non_object_json_returns_unranked_report(monkeypatch):
    findings = [_finding(10, title="A")]
    # a scalar JSON array decodes fine but is not chain/ranked-shaped -> degrade.
    _patch_prompt(monkeypatch, "[1, 2, 3]")
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert len(rep.findings) == 1
    assert rep.findings[0].severity is Severity.INFO
    assert "failed to parse" in rep.summary
    assert rep.degraded is True


def _rated(line, title, rating):
    f = _finding(line, title=title)
    return f.model_copy(update={"cvss_rating": rating,
                                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})


def test_unranked_fallback_is_severity_sorted_and_remaps_canonical_idx(monkeypatch):
    findings = [_rated(10, "LOW", "Low"), _rated(20, "HIGH", "High")]
    _patch_prompt(monkeypatch, "not json {{{")    # force the degraded fallback
    dup = DroppedFinding(file="d.c", line=5, vuln_class=VulnClass.OTHER,
                         title="dup", chunk_id="c", reason="DUPLICATE",
                         canonical_idx=0)   # points at LOW (original index 0)
    rep = s8_chain.run(findings, _ctx(), _Cfg(), dropped=[dup])
    assert rep.degraded is True
    assert [rf.finding.title for rf in rep.findings] == ["HIGH", "LOW"]
    assert rep.dropped[0].canonical_idx == 1   # remapped to HIGH's new position


def test_nonstring_summary_does_not_crash_and_coerces_empty(monkeypatch):
    findings = [_finding(10, title="A")]
    payload = {
        "summary": {"unexpected": "object"},
        "ranked_findings": [{"index": 0, "severity": "high",
                             "exploitability_notes": ""}],
        "chains": [],
    }
    _patch_prompt(monkeypatch, payload)
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert rep.degraded is False           # hydration succeeded
    assert rep.summary == ""               # off-schema summary -> empty, not repr
    assert len(rep.findings) == 1


def test_run_coerces_top_level_chain_array(monkeypatch):
    # The model emits a bare array of chain objects instead of {"chains":[...]}.
    findings = [_finding(10, title="A"), _finding(20, title="B")]
    payload = [{"title": "boom", "steps": [0, 1], "severity": "high",
                "narrative": "n"}]
    _patch_prompt(monkeypatch, payload)
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert rep.degraded is False
    assert len(rep.chains) == 1
    assert rep.chains[0].title == "boom"


def test_healthy_no_chains_is_not_degraded(monkeypatch):
    findings = [_finding(10, title="A")]
    _patch_prompt(monkeypatch, {"summary": "s", "ranked_findings": [], "chains": []})
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert rep.degraded is False
    md = rep.to_markdown()
    assert "No exploit chains were identified" in md
    assert "DEGRADED" not in md


def test_degraded_report_renders_banner_even_without_metrics(monkeypatch):
    findings = [_finding(10, title="A")]
    _patch_prompt(monkeypatch, "not json {{{")
    rep = s8_chain.run(findings, _ctx(), _Cfg())
    assert rep.degraded is True
    assert rep.metrics is None
    md = rep.to_markdown()
    assert "## Scan Health" in md
    assert "DEGRADED" in md
    assert "No exploit chains were identified" not in md


def test_zero_coverage_is_not_reported_as_a_clean_result(monkeypatch):
    # An empty findings list over an empty scope must not borrow the "nothing survived verification" sentence.
    from vvaharness.models import ScanMetrics
    monkeypatch.setattr(s8_chain._deepagents, "dispatch_prompt",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("no dispatch with no findings")))
    rep = s8_chain.run([], _ctx(), _Cfg(),
                       metrics=ScanMetrics(total_files_in_scope=0))
    assert rep.degraded is True
    assert "0 files analysed" in rep.summary
    assert "no conclusion can be drawn" in rep.summary
    assert "survived adversarial verification" not in rep.summary
    assert rep.degraded_reason == "scope was empty: 0 files reached analysis"
    assert "DEGRADED" in rep.to_markdown()


def test_no_findings_with_real_coverage_stays_clean(monkeypatch):
    # The opposite state: files were read and cleared, so the report is clean.
    from vvaharness.models import ScanMetrics
    monkeypatch.setattr(s8_chain._deepagents, "dispatch_prompt",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("no dispatch with no findings")))
    rep = s8_chain.run([], _ctx(), _Cfg(),
                       metrics=ScanMetrics(total_files_in_scope=19,
                                           analyzed_files_unique=18))
    assert rep.degraded is False
    assert rep.summary == "No findings survived adversarial verification."
    assert rep.degraded_reason == ""


def test_no_findings_without_metrics_stays_clean(monkeypatch):
    # metrics=None carries no coverage claim, so it must not be read as empty.
    monkeypatch.setattr(s8_chain._deepagents, "dispatch_prompt",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("no dispatch with no findings")))
    rep = s8_chain.run([], _ctx(), _Cfg())
    assert rep.degraded is False
    assert rep.summary == "No findings survived adversarial verification."
