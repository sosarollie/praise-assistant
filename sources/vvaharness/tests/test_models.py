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

"""Unit tests for vvaharness.models data contracts.

Pure pydantic models — no network, no LLM, no subprocess. Deterministic.
Focus: Finding uses line_start (not line), model defaults/validation,
the LLM-output coercion validators, and the Severity/VulnClass enums.
"""
import re

import pytest
from pydantic import ValidationError

from vvaharness.models import (
    Asset,
    Chain,
    Chunk,
    ChunkSize,
    Control,
    ContextPackage,
    DroppedFinding,
    DupLocation,
    Finding,
    ScanMetrics,
    ScopeEntry,
    Severity,
    Sink,
    TaskManifest,
    Threat,
    VulnClass,
)


def _minimal_finding(**overrides):
    """Finding with all required fields filled; override as needed."""
    base = dict(
        chunk_id="chunk-01",
        file="src/app.c",
        line_start=42,
        line_end=48,
        vuln_class=VulnClass.HEAP_OVERFLOW,
        title="heap overflow in parse",
        description="An attacker-controlled length leads to heap overflow.",
        code_snippet="memcpy(dst, src, len);",
        confidence=0.9,
    )
    base.update(overrides)
    return Finding(**base)


def test_finding_uses_line_start_not_line():
    f = _minimal_finding(line_start=100, line_end=120)
    assert f.line_start == 100
    assert f.line_end == 120
    # The field is line_start; there is no `line` attribute on Finding.
    assert not hasattr(f, "line")


def test_finding_requires_line_start_and_line_end():
    # Omitting line_start must raise — it is a required field with no default.
    with pytest.raises(ValidationError):
        Finding(
            chunk_id="c",
            file="f.c",
            line_end=10,
            vuln_class=VulnClass.OTHER,
            title="t",
            description="d",
            code_snippet="s",
            confidence=0.5,
        )


def test_finding_defaults():
    f = _minimal_finding()
    # Optional fields default to safe empties / None.
    assert f.cwe is None
    assert f.impact == ""
    assert f.exploit_scenario == ""
    assert f.preconditions == []
    assert f.recommendation == ""
    assert f.source_ref is None
    assert f.sink_ref is None
    assert f.votes == 1
    assert f.duplicates == []
    # Step-6 verification fields default unset.
    assert f.verdict is None
    assert f.verdict_confidence is None
    assert f.cvss_vector is None
    assert f.cvss_score is None
    # Post-s7 enrichment defaults.
    assert f.vsvs_score is None
    assert f.offensive_priority is None


def test_confidence_fraction_passthrough():
    assert _minimal_finding(confidence=0.73).confidence == pytest.approx(0.73)


def test_confidence_percent_scale_div_100():
    # 95 (a percent) maps to 0.95 — survives instead of failing le=1.0.
    assert _minimal_finding(confidence=95).confidence == pytest.approx(0.95)
    assert _minimal_finding(confidence="95%").confidence == pytest.approx(0.95)


def test_confidence_whole_number_2_to_10_uses_ten_point_scale():
    assert _minimal_finding(confidence=8).confidence == pytest.approx(0.8)
    assert _minimal_finding(confidence=10).confidence == pytest.approx(1.0)
    assert _minimal_finding(confidence="8").confidence == pytest.approx(0.8)


def test_confidence_slight_overshoot_clamped_not_scaled():
    # 1.5 is a near-1 fraction overshoot, clamped to 1.0 (NOT /100).
    assert _minimal_finding(confidence=1.5).confidence == pytest.approx(1.0)


def test_confidence_uninterpretable_falls_back_to_default():
    # "high" cannot be parsed → neutral 0.5 default; finding survives.
    assert _minimal_finding(confidence="high").confidence == pytest.approx(0.5)
    assert _minimal_finding(confidence=None).confidence == pytest.approx(0.5)


def test_confidence_defaults_for_a_caller_that_has_none():
    # An external caller has no vote count. 0.5 is this codebase's "no opinion" value, and
    # keeping it a float (not None) is deliberate: nine call sites in s4/s5/s8/enrich compare
    # or format it arithmetically.
    omitted = Finding(title="t", file="f.py", line_start=1, vuln_class=VulnClass.INJECTION)
    assert omitted.confidence == pytest.approx(0.5)


def test_confidence_nan_and_inf_fall_back():
    assert _minimal_finding(confidence=float("nan")).confidence == pytest.approx(0.5)
    assert _minimal_finding(confidence=float("inf")).confidence == pytest.approx(0.5)


def test_confidence_negative_clamped_to_zero():
    assert _minimal_finding(confidence=-3).confidence == pytest.approx(0.0)


def test_confidence_bool_treated_as_no_signal():
    # bool is a subclass of int but must NOT be read as 0/1 confidence.
    assert _minimal_finding(confidence=True).confidence == pytest.approx(0.5)


def test_canonical_key_buckets_line_number():
    a = _minimal_finding(line_start=142)
    b = _minimal_finding(line_start=145)
    # Same file + vuln_class + line bucket (//10) → identical identity.
    assert a.canonical_key() == b.canonical_key()
    assert a.canonical_key() == ("src/app.c", 14, VulnClass.HEAP_OVERFLOW)


def test_canonical_key_distinct_across_bucket_boundary():
    a = _minimal_finding(line_start=149)
    b = _minimal_finding(line_start=150)
    assert a.canonical_key() != b.canonical_key()


def test_severity_string_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"
    # str-Enum: members compare equal to their string value.
    assert Severity.CRITICAL == "critical"


def test_severity_constructed_from_string():
    assert Severity("critical") is Severity.CRITICAL
    assert Severity("info") is Severity.INFO


def test_severity_rejects_unknown_value():
    with pytest.raises(ValueError):
        Severity("catastrophic")


def test_vuln_class_values():
    assert VulnClass.UAF.value == "use-after-free"
    assert VulnClass.INJECTION.value == "injection"
    assert VulnClass.DESERIALIZATION.value == "unsafe-deserialization"
    assert VulnClass("logic-flaw") is VulnClass.LOGIC


def test_control_kind_exact_value():
    assert Control(name="gw", kind="auth").kind == "auth"


def test_control_kind_alias_maps_to_member():
    assert Control(name="gw", kind="authentication").kind == "auth"
    assert Control(name="waf", kind="WAF").kind == "input-validation"
    assert Control(name="sb", kind="seccomp").kind == "sandbox"


def test_control_kind_unknown_falls_back_to_other():
    assert Control(name="x", kind="quantum-shield").kind == "other"


def test_asset_sensitivity_default_and_alias():
    assert Asset(name="db").sensitivity == "medium"
    assert Asset(name="db", sensitivity="crit").sensitivity == "critical"
    assert Asset(name="db", sensitivity="bogus").sensitivity == "medium"


def test_threat_actor_alias_and_default():
    t = Threat(
        id="T1", threat="RCE", actor="anonymous", surface="api",
        asset="db", impact="critical", likelihood="likely",
    )
    assert t.actor == "remote_unauth"


def test_threat_actor_unknown_falls_back():
    t = Threat(
        id="T2", threat="x", actor="martian", surface="s",
        asset="a", impact="high", likelihood="rare",
    )
    assert t.actor == "remote_auth"


def test_threat_impact_existential_alias():
    t = Threat(
        id="T3", threat="x", actor="insider", surface="s",
        asset="a", impact="catastrophic", likelihood="possible",
    )
    assert t.impact == "existential"


def test_threat_likelihood_alias():
    t = Threat(
        id="T4", threat="x", actor="insider", surface="s",
        asset="a", impact="low", likelihood="very_unlikely",
    )
    assert t.likelihood == "very_rare"


def test_sink_line_default_and_string_coercion():
    assert Sink(file="f.c", function="strcpy").line == 0
    assert Sink(file="f.c", function="strcpy", line="57").line == 57


def test_sink_line_bad_value_falls_back_zero():
    assert Sink(file="f.c", function="strcpy", line="not-a-number").line == 0
    assert Sink(file="f.c", function="strcpy", line=None).line == 0


def test_chunk_defaults():
    c = Chunk(id="chunk-01")
    assert c.size is ChunkSize.MEDIUM
    assert c.risk_rank == 999
    assert c.files == []
    assert c.threat_id is None
    assert c.specialist is None


def test_chunk_size_alias_coercion():
    assert Chunk(id="c", size="tiny").size is ChunkSize.SMALL
    assert Chunk(id="c", size="xl").size is ChunkSize.LARGE
    assert Chunk(id="c", size="bogus").size is ChunkSize.MEDIUM


def test_chunk_risk_rank_string_coercion():
    assert Chunk(id="c", risk_rank="3").risk_rank == 3
    assert Chunk(id="c", risk_rank="garbage").risk_rank == 999


def test_chunk_threat_id_list_takes_first():
    # A strategist told to cover every threat with few chunks reasonably
    # groups several threat ids into one chunk; the schema holds one.
    assert Chunk(id="c", threat_id=["T45", "T46", "T47"]).threat_id == "T45"
    assert Chunk(id="c", threat_id=[]).threat_id is None


def test_task_manifest_survives_list_threat_id():
    # The observed strategist payload shape: a list-valued threat_id used to
    # fail the WHOLE manifest and discard the entire LLM ranking.
    payload = {
        "rationale": "r",
        "chunks": [{
            "id": "chunk-01",
            "risk_rank": 1,
            "file_ids": ["F001"],
            "hypothesis": "h",
            "threat_id": ["T45", "T46", "T47"],
            "related_cves": [],
        }],
    }
    m = TaskManifest.model_validate(payload)
    assert len(m.chunks) == 1
    assert m.chunks[0].threat_id == "T45"


@pytest.mark.parametrize("field,value,expected", [
    # list where a scalar string belongs → first element
    ("threat_id", ["T45", "T46"], "T45"),
    ("specialist", ["crypto"], "crypto"),
    ("shard_id", ["s1", "s2"], "s1"),
    # bare int where a string belongs → its string form
    ("id", 7, "7"),
    # explicit null where a defaulted string belongs → the default
    ("hypothesis", None, ""),
    ("source_ref", None, ""),
    # bare scalar where a list of strings belongs → wrapped
    ("files", "a.py", ["a.py"]),
    ("focus_entry_points", "main", ["main"]),
    ("related_cves", "CVE-2024-1234", ["CVE-2024-1234"]),
    ("languages", "python", ["python"]),
    ("sink_cwe", "CWE-79", ["CWE-79"]),
])
def test_chunk_off_schema_shape_coercion(field, value, expected):
    kwargs = {"id": "c", field: value}
    assert getattr(Chunk(**kwargs), field) == expected


def test_task_manifest_field_shape_coercion():
    m = TaskManifest.model_validate(
        {"chunks": [], "rationale": None, "unreachable_files": "a.py"})
    assert m.rationale == ""
    assert m.unreachable_files == ["a.py"]


def test_task_manifest_chunks_stays_strict():
    # A missing/null "chunks" key is the marker of a genuinely malformed
    # reply and must keep raising — shape coercion must not soften it.
    with pytest.raises(ValidationError):
        TaskManifest.model_validate({"rationale": "r"})
    with pytest.raises(ValidationError):
        TaskManifest.model_validate({"chunks": None, "rationale": "r"})


def test_chunk_coercion_rejects_unrecognisable_shapes():
    # The manifest is untrusted model output: coercion normalises the
    # recognisable off-schema shapes only, never arbitrary data.
    with pytest.raises(ValidationError):
        Chunk(id="c", threat_id={"id": "T1"})
    with pytest.raises(ValidationError):
        Chunk(risk_rank=1)                    # id missing stays missing


def test_manifest_salvage_keeps_good_chunks():
    # Per-chunk salvage at the s3 parse choke point: one irreparably bad
    # chunk loses that chunk, not the whole manifest.
    from vvaharness.pipeline.stages.s3_decompose import _salvage_chunks

    data = {
        "rationale": "r",
        "chunks": [
            {"id": "chunk-01", "risk_rank": 1, "files": ["a.py"]},
            {"risk_rank": 2, "files": ["b.py"]},   # no id — irreparable
            {"id": "chunk-03", "risk_rank": 3, "files": ["c.py"]},
        ],
    }
    kept, kept_idx, total = _salvage_chunks(data)
    assert [c.id for c in kept] == ["chunk-01", "chunk-03"]
    assert kept_idx == [0, 2]                 # shapes/raw_paths re-filter key
    assert total == 3
    # A reply with no usable "chunks" list salvages nothing — the caller's
    # empty-manifest fallback (deterministic coverage) still applies.
    assert _salvage_chunks({"rationale": "r"}) == ([], [], 0)
    assert _salvage_chunks(None) == ([], [], 0)


def test_finding_round_trip_model_dump():
    f = _minimal_finding(
        cwe="CWE-122",
        preconditions=["attacker controls length"],
        duplicates=[DupLocation(
            file="src/other.c", line_start=10, vuln_class=VulnClass.HEAP_OVERFLOW,
        )],
    )
    data = f.model_dump()
    assert data["line_start"] == 42
    assert "line" not in data            # confirms field name, not legacy `line`
    assert data["cwe"] == "CWE-122"
    assert data["confidence"] == pytest.approx(0.9)

    rebuilt = Finding(**data)
    assert rebuilt == f
    assert rebuilt.line_start == f.line_start
    assert rebuilt.duplicates[0].file == "src/other.c"


def test_dup_location_defaults():
    d = DupLocation(file="a.c", line_start=5, vuln_class=VulnClass.RACE)
    assert d.line_end == 0
    assert d.title == ""
    assert d.source_ref is None


def test_chain_round_trip_with_severity_enum():
    c = Chain(
        title="UAF -> arb write",
        steps=[0, 1],
        severity=Severity.CRITICAL,
        narrative="step chain",
    )
    data = c.model_dump()
    assert data["severity"] == "critical"
    rebuilt = Chain(**data)
    assert rebuilt.severity is Severity.CRITICAL
    assert rebuilt.blocked_by_controls == []


def test_dropped_finding_valid_reason():
    d = DroppedFinding(
        file="f.c", line=3, vuln_class=VulnClass.OTHER,
        title="t", chunk_id="c", reason="FALSE_POSITIVE",
    )
    assert d.reason == "FALSE_POSITIVE"
    assert d.canonical_idx is None


def test_dropped_finding_rejects_bad_reason():
    with pytest.raises(ValidationError):
        DroppedFinding(
            file="f.c", line=3, vuln_class=VulnClass.OTHER,
            title="t", chunk_id="c", reason="MAYBE",
        )


def test_scan_metrics_coverage_pct():
    m = ScanMetrics(total_files_in_scope=200, analyzed_files_unique=50)
    assert m.coverage_pct == pytest.approx(25.0)


def test_scan_metrics_coverage_pct_zero_scope():
    assert ScanMetrics().coverage_pct == 0.0


def test_scan_metrics_verification_precision_pct():
    m = ScanMetrics(raw_findings_count=10, true_positive_count=7)
    assert m.verification_precision_pct == pytest.approx(70.0)


def test_scan_metrics_precision_no_raw_findings():
    assert ScanMetrics(true_positive_count=5).verification_precision_pct == 0.0

from vvaharness.models import (
    AppProfile,
    FinalReport,
    RankedFinding,
    ThreatModel,
    _demote_md_headings,
    _md_cell,
)


def test_demote_md_headings_demotes_leading_atx():
    assert _demote_md_headings("## Analysis\nbody") == "**Analysis**\nbody"
    assert _demote_md_headings("# H1") == "**H1**"
    assert _demote_md_headings("###### H6") == "**H6**"


def test_demote_md_headings_preserves_inline_and_fenced():
    # inline '#' is not a heading
    assert _demote_md_headings("use C# or #1 or #define") == "use C# or #1 or #define"
    # '#' comment inside a fenced code block must survive
    src = "```python\n# a comment\nx = 1\n```"
    assert _demote_md_headings(src) == src
    # 4-space indent is a code block, not an ATX heading
    assert _demote_md_headings("    # indented") == "    # indented"


def test_demote_md_headings_empty_and_none():
    assert _demote_md_headings("") == ""
    assert _demote_md_headings(None) is None


def test_md_cell_escapes_pipe_and_newline():
    assert _md_cell("a|b") == "a\\|b"
    assert _md_cell("line1\nline2") == "line1 line2"
    assert _md_cell(None) == ""


def test_md_cell_escapes_backslash_before_pipe():
    # A supplied "\" must be doubled, else it consumes the escape added for "|" and the
    # raw delimiter survives into the rendered table.
    assert _md_cell(r"a\|b") == r"a\\\|b"


def test_md_cell_folds_all_line_break_forms():
    # Every separator str.splitlines() honours must fold to a space, or a value
    # could still forge a row/heading when the report is later split into lines.
    assert _md_cell("a\rb") == "a b"
    assert _md_cell("a\r\nb") == "a  b"          # CR and LF each become a space
    for sep in ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85",
                "\u2028", "\u2029"):
        assert _md_cell(f"a{sep}b") == "a b", repr(sep)
        assert not _md_cell(f"a{sep}b").splitlines()[1:], repr(sep)


def test_md_cell_strips_control_chars_keeps_tab():
    assert _md_cell("a\x00b\x08c\x7fd\x1be") == "abcde"
    assert _md_cell("a\tb") == "a\tb"            # tab is legitimate cell content


def test_md_cell_strips_bidi_and_zero_width():
    # Bidi overrides / isolates and zero-width chars can visually reorder or
    # hide rendered text (e.g. disguise a FAILED status) -- they must not survive.
    assert _md_cell("FA\u202eDELI") == "FADELI"   # RLO gone, no visual reversal
    for ch in ("\u200b", "\u200e", "\u200f", "\u202a", "\u202e",
               "\u2060", "\u2066", "\u2069", "\ufeff", "\u00ad", "\u061c"):
        assert _md_cell(f"a{ch}b") == "ab", repr(ch)


def test_md_cell_zero_width_cannot_split_escape():
    # A zero-width char between "\" and "|" must not defeat the delimiter escape.
    assert _md_cell("a\\\u200b|b") == r"a\\\|b"


def test_md_cell_non_string_and_whitespace():
    assert _md_cell(123) == "123"
    assert _md_cell("  padded  ") == "padded"


def test_to_markdown_excludes_raw_verifier_reasoning():
    f = _minimal_finding(
        verdict="TRUE_POSITIVE", verdict_confidence=8, verdict_reason="confirmed",
        verifier_reasoning="Let me analyze\n## Fake Section\nraw working notes",
    )
    rf = RankedFinding(finding=f, severity=Severity.HIGH, exploitability_notes="n")
    rep = FinalReport(repo_root="/x", findings=[rf], chains=[], summary="s")
    md = rep.to_markdown()
    assert "#### Adversarial verification" in md
    assert "**Verdict:** TRUE_POSITIVE (confidence: 8/10) — confirmed" in md
    assert "Let me analyze" not in md
    assert "Fake Section" not in md
    assert "raw working notes" not in md


def test_to_markdown_neutralizes_injected_precondition_bullet():
    # A model-supplied list field carrying a newline + ATX heading must not
    # break out of its bullet into a structural heading in the rendered report.
    f = _minimal_finding(preconditions=["ok\n## Injected Heading"])
    rf = RankedFinding(finding=f, severity=Severity.HIGH, exploitability_notes="n")
    rep = FinalReport(repo_root="/x", findings=[rf], chains=[], summary="s")
    md = rep.to_markdown()
    # no rendered LINE may start with the injected heading (newline collapsed)
    assert not any(ln.lstrip().startswith("## Injected")
                   for ln in md.splitlines())
    assert "- ok ## Injected Heading" in md     # flattened onto one bullet
    # the undetermined-verification line is rendered (0 here, additive)
    assert "Verifier errors (excluded" in md


def test_to_markdown_neutralizes_injected_cmdb_app_profile():
    # application_id / name / source come from --application-id and the CMDB CSV
    # (operator/enterprise-supplied). A crafted value with a newline must not
    # terminate the "Application profile (CMDB)" list and inject a real heading
    # or link into the rendered threat-model section.
    f = _minimal_finding()
    rf = RankedFinding(finding=f, severity=Severity.HIGH, exploitability_notes="n")
    ap = AppProfile(
        application_id="APP1\n## Pwned ID",
        name="evil\n## Pwned Name\n[click](http://evil)",
        source="src\n## Pwned Source",
    )
    rep = FinalReport(repo_root="/x", findings=[rf], chains=[], summary="s",
                      threat_model=ThreatModel(), app_profile=ap)
    md = rep.to_markdown()
    # The structural heading is still rendered…
    assert "### Application profile (CMDB)" in md
    # …but none of the injected payloads become real lines of their own.
    for ln in md.splitlines():
        assert not ln.lstrip().startswith("## Pwned")
        assert ln.strip() != "[click](http://evil)"
    # Newlines were collapsed (values flattened inline, not dropped).
    assert "## Pwned Name" in md          # present, but inline within the bullet


def _report_with(finding):
    rf = RankedFinding(finding=finding, severity=Severity.HIGH,
                       exploitability_notes="n")
    return FinalReport(repo_root="/x", findings=[rf], chains=[], summary="s")


def test_to_markdown_backfills_cwe_from_vuln_class_when_token_absent():
    # cwe is None but vuln_class=use-after-free → deterministic CWE-416 line.
    f = _minimal_finding(vuln_class=VulnClass.UAF, cwe=None)
    md = _report_with(f).to_markdown()
    assert "**CWE:** CWE-416" in md
    assert "data/definitions/416.html" in md


def test_to_markdown_uses_explicit_cwe_token_over_fallback():
    # An explicit cwe token is preserved (passes through cwe_for unchanged).
    f = _minimal_finding(vuln_class=VulnClass.UAF, cwe="CWE-787")
    md = _report_with(f).to_markdown()
    assert "**CWE:** CWE-787" in md
    assert "CWE-416" not in md


def test_to_markdown_other_class_renders_no_cwe_line():
    # "other" maps to no CWE → no **CWE:** line (honest: unclassified).
    f = _minimal_finding(vuln_class=VulnClass.OTHER, cwe=None)
    md = _report_with(f).to_markdown()
    assert "**CWE:**" not in md


# ── **File:** line: hostile paths cannot close the code span ──────────────────

def test_to_markdown_folds_backtick_in_file_path_and_round_trips():
    # Finding.file is model-authored (LLM JSON) and reflects an
    # attacker-nameable filename. A raw backtick would close the code span
    # early and truncate the path every downstream parser recovers.
    f = _minimal_finding(file="weird`file.py", line_start=10, line_end=10)
    md = _report_with(f).to_markdown()
    file_line = next(ln for ln in md.splitlines()
                     if ln.startswith("**File:**"))
    # No raw backtick between the span delimiters; folded to the U+02CB
    # lookalike instead.
    assert "`weird`" not in file_line
    assert "\u02cb" in file_line
    # The remediation agent's parser recovers the FULL folded location, not a path
    # truncated at the backtick. It splits `path:start-end` into typed fields, so the
    # round-trip is checked per field rather than against the raw span.
    from vvaharness.remediation_agent.report_parser.parse import parse_findings
    parsed = parse_findings(md)
    assert parsed
    assert parsed[0].file == "weird\u02cbfile.py"
    assert (parsed[0].finding.line_start, parsed[0].finding.line_end) == (10, 10)


def test_to_markdown_benign_file_path_renders_byte_identically():
    # CRITICAL INVARIANT: a legitimate path (no backtick / pipe / backslash /
    # newline / bidi character) must render exactly as before the escaping —
    # the report parsers and ~30 existing parse_findings tests depend on it.
    f = _minimal_finding()   # file="src/app.c", lines 42-48
    md = _report_with(f).to_markdown()
    assert "**File:** `src/app.c:42-48`" in md


def test_to_markdown_also_at_refs_fold_backticks_and_stay_parseable():
    # Duplicate call-site paths take the same model-authored channel; a
    # backtick there would corrupt the SARIF relatedLocations extraction.
    f = _minimal_finding(duplicates=[
        DupLocation(file="src/other.c", line_start=7,
                    vuln_class=VulnClass.RACE),
        DupLocation(file="bad`tick.c", line_start=3, line_end=9,
                    vuln_class=VulnClass.RACE),
    ])
    md = _report_with(f).to_markdown()
    also = next(ln for ln in md.splitlines() if ln.startswith("**Also at:**"))
    assert "bad`" not in also
    from vvaharness.report.enrich import ALSO_AT_REF_RX
    refs = [(m.group(1), m.group(2), m.group(3))
            for m in ALSO_AT_REF_RX.finditer(also)]
    assert ("src/other.c", "7", None) in refs
    assert ("bad\u02cbtick.c", "3", "9") in refs


def test_to_markdown_adversarial_file_paths_are_neutralised():
    # U+2028 line separator (forged row), U+202E bidi override (visually
    # reversed path), and an embedded newline must all be folded/stripped so
    # the **File:** line stays a single honest line.
    for hostile in ("a.py\u2028### 99. [CRITICAL] forged",
                    "src/\u202eyp.evil",
                    "a.py\n### 99. [CRITICAL] forged"):
        f = _minimal_finding(file=hostile)
        md = _report_with(f).to_markdown()
        assert "\u2028" not in md
        assert "\u202e" not in md
        assert not any(ln.startswith("### 99.") for ln in md.splitlines())


# ── Chunk: file_ids alias, shard_id, size default survives a trimmed schema ────

def test_chunk_file_ids_alias_populates_files():
    c = Chunk(id="c1", file_ids=["a.py", "b.py"])
    assert c.files == ["a.py", "b.py"]


def test_chunk_model_validate_file_ids_does_not_silently_empty_files():
    # Before the alias existed, a payload keyed "file_ids" validated
    # successfully with files left at its empty default — no ValidationError,
    # so a fallback path built for exactly this situation never fired.
    c = Chunk.model_validate({"id": "c1", "file_ids": ["a.py"]})
    assert c.files == ["a.py"]


def test_chunk_files_keyword_still_works():
    c = Chunk(id="c1", files=["x.py"])
    assert c.files == ["x.py"]


def test_chunk_model_validate_files_key_still_works():
    c = Chunk.model_validate({"id": "c1", "files": ["x.py"]})
    assert c.files == ["x.py"]


def test_chunk_shard_id_default_and_settable():
    assert Chunk(id="c1").shard_id == ""
    assert Chunk(id="c1", shard_id="shard-02").shard_id == "shard-02"


def test_chunk_size_default_preserved_without_size_in_payload():
    c = Chunk.model_validate({"id": "c1", "files": ["a.py"]})
    assert c.size is ChunkSize.MEDIUM


# ── TaskManifest.rationale defaults; chunks stays the required detector ───────

def test_task_manifest_rationale_defaults_when_absent():
    m = TaskManifest.model_validate({"chunks": [{"id": "c1"}]})
    assert m.rationale == ""


def test_task_manifest_still_requires_chunks():
    # Regression pin: chunks is what actually distinguishes a malformed reply.
    with pytest.raises(ValidationError):
        TaskManifest.model_validate({})


# ── ScanMetrics: new fields default; older serialized reports still parse ─────

def test_scan_metrics_new_fields_all_defaulted():
    m = ScanMetrics()
    assert m.s2_degraded is False
    assert m.s2_threats_raw == 0
    assert m.s2_threats_truncated == 0
    assert m.s2_threats_promoted == 0
    assert m.s2_baseline_undisposed == []
    assert m.s2_repo_kinds == []
    assert m.s3_output_shape == ""
    assert m.s3_unknown_file_ids == 0
    assert m.s3_dropped_paths == 0
    assert m.s3_relocated_paths == 0
    assert m.s3_dropped_empty_chunks == 0
    assert m.s3_forced_coverage_files == 0
    assert m.s3_fallback_chunks_dropped == 0
    assert m.s3_cohesion_groups == 0
    assert m.s3_buckets == 0
    assert m.s4_findings_truncated == 0
    assert m.chunks_by_kind == {}


def test_scan_metrics_legacy_payload_without_new_fields_still_validates():
    # A payload shaped like a report serialized before these fields existed.
    legacy = {
        "scan_id": "run-1",
        "chunks_total": 3,
        "chunks_risk": 1,
        "chunks_catchall": 1,
        "chunks_specialist": 1,
    }
    m = ScanMetrics.model_validate(legacy)
    assert m.chunks_total == 3
    assert m.s2_degraded is False
    assert m.chunks_by_kind == {}


def test_scope_entry_kind_widened_to_five_kinds_plus_other():
    for kind in ("risk", "catchall", "specialist", "taint", "threat_fallback", "other"):
        assert ScopeEntry(name="x", kind=kind, files=[]).kind == kind


def test_scope_entry_rejects_unknown_kind():
    with pytest.raises(ValidationError):
        ScopeEntry(name="x", kind="bogus", files=[])


# ── ContextPackage.to_decompose_prompt_block: threat caps are forwarded ──

def _threat(i: int) -> Threat:
    return Threat(
        id=f"T{i}", threat=f"threat number {i}", actor="remote_auth",
        surface="s", asset="a", impact="medium", likelihood="possible",
    )


def test_compact_prompt_block_bare_call_still_yields_twelve():
    # Default-pin, not an isolation proof: to_compact_prompt_block has exactly
    # one caller in the whole tree (to_decompose_prompt_block, which now
    # forwards explicit caps), so there is no second caller for this to
    # isolate from. This only pins that the method's own defaults are
    # unchanged.
    tm = ThreatModel(threats=[_threat(i) for i in range(50)])
    block = tm.to_compact_prompt_block()
    threat_lines = [ln for ln in block.splitlines() if re.match(r"^  - T\d+ ", ln)]
    assert len(threat_lines) == 12
    assert "…(truncated)" in block


def test_to_decompose_prompt_block_forwards_max_threats():
    tm = ThreatModel(threats=[_threat(i) for i in range(50)])
    ctx = ContextPackage(repo_root="/nonexistent-repo", language="python",
                         all_files=[], threat_model=tm)
    block = ctx.to_decompose_prompt_block(max_threats=50)
    threat_lines = [ln for ln in block.splitlines() if re.match(r"^  - T\d+ ", ln)]
    assert len(threat_lines) == 50
    assert "…(truncated)" not in block


def test_to_decompose_prompt_block_forwards_asset_and_boundary_caps():
    assets = [Asset(name=f"asset{i}", sensitivity="high") for i in range(100)]
    tm = ThreatModel(assets=assets)
    ctx = ContextPackage(repo_root="/nonexistent-repo", language="python",
                         all_files=[], threat_model=tm)
    block = ctx.to_decompose_prompt_block(max_assets=40)
    assert "Assets (40/100):" in block


def test_to_decompose_prompt_block_default_caps_match_compact_defaults():
    # A caller that passes none of the new keyword args renders exactly what
    # this method rendered before they existed.
    tm = ThreatModel(threats=[_threat(i) for i in range(50)])
    ctx = ContextPackage(repo_root="/nonexistent-repo", language="python",
                         all_files=[], threat_model=tm)
    block = ctx.to_decompose_prompt_block()
    threat_lines = [ln for ln in block.splitlines() if re.match(r"^  - T\d+ ", ln)]
    assert len(threat_lines) == 12


# ── ContextPackage.id_inventory / FILE INVENTORY: ids resolve to the object
#    they were rendered from, never a different (larger) file set ────────────

def test_id_inventory_resolves_against_the_rendered_view_not_the_full_tree(
        ctx_frontier_ne_full):
    full = ctx_frontier_ne_full
    view = full.ast_context_view(max_files=5)
    # Fixture guarantee: the reduced view's sorted order genuinely diverges
    # from the full tree's sorted order.
    assert sorted(view.all_files)[1] != sorted(full.all_files)[1]

    inv = view.id_inventory()
    assert inv["files"]["F002"] == sorted(view.all_files)[1]
    assert inv["files"]["F002"] != sorted(full.all_files)[1]
    # Every id in the map addresses a file that is actually in the rendered
    # view — not merely somewhere in the larger, un-rendered full tree.
    assert set(inv["files"].values()) == set(view.all_files)


def test_id_inventory_is_a_pure_function_of_self():
    ctx = ContextPackage(repo_root="/x", language="python",
                         all_files=["b.py", "a.py"])
    assert ctx.id_inventory() == ctx.id_inventory()


def test_id_inventory_covers_entry_points_and_sinks():
    from vvaharness.models import EntryPoint
    ctx = ContextPackage(
        repo_root="/x", language="python",
        all_files=["a.py", "b.py"],
        entry_points=[EntryPoint(file="b.py", function="handle",
                                 kind="network", reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file="a.py", line=10, function="exec", cwe=["CWE-78"])],
    )
    inv = ctx.id_inventory()
    assert inv["files"] == {"F001": "a.py", "F002": "b.py"}
    ((eid, ep),) = inv["entry_points"].items()
    assert ep == {"file_id": "F002", "function": "handle",
                 "kind": "network", "unauth": True}
    ((kid, sink),) = inv["sinks"].items()
    assert sink == {"file_id": "F001", "function": "exec",
                    "line": 10, "cwe": ["CWE-78"]}


def test_file_inventory_block_renders_ids_matching_id_inventory(
        ctx_frontier_ne_full):
    view = ctx_frontier_ne_full.ast_context_view(max_files=5)
    block = view.to_decompose_prompt_block()
    assert "FILE INVENTORY (authoritative" in block
    inv = view.id_inventory()
    for fid, path in inv["files"].items():
        assert f"{fid}  {path}" in block


def test_file_inventory_block_states_the_path_constraint():
    ctx = ContextPackage(repo_root="/x", language="python", all_files=["a.py"])
    block = ctx.to_decompose_prompt_block()
    assert "MUST resolve to one of the F### ids" in block


def test_to_decompose_prompt_block_docstring_no_longer_claims_no_inventory():
    doc = ContextPackage.to_decompose_prompt_block.__doc__ or ""
    assert "deliberately avoids repo-wide file inventories" not in doc


def test_to_decompose_prompt_block_order_inventory_then_threat_model_first():
    tm = ThreatModel(system_context="app context")
    ctx = ContextPackage(repo_root="/x", language="python",
                         all_files=["a.py"], threat_model=tm)
    block = ctx.to_decompose_prompt_block()
    assert block.index("FILE INVENTORY") < block.index("THREAT MODEL:")
    assert block.index("THREAT MODEL:") < block.index("REPO:")


# ── Dead ContextPackage methods removed; AppProfile/ThreatModel keep theirs ─

def test_context_package_dead_prompt_methods_removed():
    assert not hasattr(ContextPackage, "to_prompt_block")
    assert not hasattr(ContextPackage, "_call_graph_block")


def test_app_profile_and_threat_model_to_prompt_block_untouched():
    from vvaharness.models import AppProfile
    assert hasattr(AppProfile, "to_prompt_block")
    assert hasattr(ThreatModel, "to_prompt_block")


# ── ast_context_view no longer prints; breakdown travels on the object ────

def test_ast_context_view_returns_edge_breakdown_without_printing(capsys):
    ctx = ContextPackage(
        repo_root="/x", language="python",
        all_files=["a.py", "b.py"],
        call_graph={"a.py::f": ["b.py::g"]},
    )
    view = ctx.ast_context_view(max_files=10)
    captured = capsys.readouterr()
    assert "[s3]" not in captured.err
    assert "[s3]" not in captured.out
    stats = view.ast_frontier_stats
    assert stats["edges_kept"] == 1
    assert stats["edges_total"] == 1
    assert stats["hot"] + stats["cold"] == 1
    assert stats["dropped_by_cap"] == 0


def test_ast_frontier_stats_defaults_empty_on_an_unviewed_package():
    ctx = ContextPackage(repo_root="/x", language="python", all_files=[])
    assert ctx.ast_frontier_stats == {}


# ── Unreachable-files appendix splits covered vs. not-reviewed-by-anyone ──

def test_unreachable_appendix_splits_source_from_non_source_files():
    f = _minimal_finding()
    rf = RankedFinding(finding=f, severity=Severity.HIGH, exploitability_notes="n")
    rep = FinalReport(
        repo_root="/x", findings=[rf], chains=[], summary="s",
        unreachable_files=["src/app.py", "Makefile"],
    )
    md = rep.to_markdown()
    assert "### Still covered by specialist passes (1)" in md
    assert "### Not reviewed by any pass (1)" in md
    covered_idx = md.index("Still covered by specialist passes")
    not_reviewed_idx = md.index("Not reviewed by any pass")
    app_py_idx = md.index("src/app.py")
    makefile_idx = md.index("Makefile")
    assert covered_idx < app_py_idx < not_reviewed_idx
    assert not_reviewed_idx < makefile_idx


# ── _render_metrics: chunks_by_kind and the stage-counter diagnostics ─────────

def _report_with_metrics(m: ScanMetrics) -> FinalReport:
    f = _minimal_finding()
    rf = RankedFinding(finding=f, severity=Severity.HIGH, exploitability_notes="n")
    return FinalReport(repo_root="/x", findings=[rf], chains=[], summary="s", metrics=m)


def test_metrics_with_no_counters_renders_no_diagnostics_section():
    md = _report_with_metrics(ScanMetrics()).to_markdown()
    assert "Pipeline Diagnostics" not in md
    # the always-present chunk line still renders, from the legacy trio
    assert "- Chunks: 0 (risk=0, catch-all=0, specialist=0)" in md


def test_legacy_metrics_payload_still_renders_the_legacy_trio():
    # A payload shaped like a report serialized before any of the new fields
    # existed must still validate AND still render without raising.
    legacy = {
        "scan_id": "run-1", "chunks_total": 3,
        "chunks_risk": 1, "chunks_catchall": 1, "chunks_specialist": 1,
    }
    m = ScanMetrics.model_validate(legacy)
    md = _report_with_metrics(m).to_markdown()
    assert "- Chunks: 3 (risk=1, catch-all=1, specialist=1)" in md
    assert "Pipeline Diagnostics" not in md


def test_chunks_by_kind_renders_all_five_kinds_plus_other():
    m = ScanMetrics(chunks_total=6, chunks_by_kind={
        "risk": 1, "catchall": 1, "specialist": 1,
        "taint": 1, "threat_fallback": 1, "other": 1,
    })
    md = _report_with_metrics(m).to_markdown()
    assert ("- Chunks: 6 (risk=1, catch-all=1, specialist=1, taint=1, "
            "threat-fallback=1, other=1)") in md
    # chunks_by_kind takes over from the legacy trio when populated, even
    # though the legacy fields still default to 0 alongside it.
    assert "chunks_risk" not in md


def test_chunks_by_kind_empty_dict_falls_back_to_legacy_trio():
    m = ScanMetrics(chunks_total=2, chunks_risk=1, chunks_catchall=1, chunks_by_kind={})
    md = _report_with_metrics(m).to_markdown()
    assert "- Chunks: 2 (risk=1, catch-all=1, specialist=0)" in md


def test_pipeline_diagnostics_degraded_and_output_shape():
    m = ScanMetrics(s2_degraded=True, s3_output_shape="ids")
    md = _report_with_metrics(m).to_markdown()
    assert "### Pipeline Diagnostics" in md
    assert "Threat model: **degraded**" in md
    assert "Chunk file references from the strategist: id-based" in md


def test_pipeline_diagnostics_threat_counters():
    m = ScanMetrics(s2_threats_raw=15, s2_threats_truncated=3, s2_threats_promoted=1,
                    s2_baseline_undisposed=["BL-WEB-A03"], s2_repo_kinds=["web-api"])
    md = _report_with_metrics(m).to_markdown()
    assert "Threats identified before ranking: 15" in md
    assert "Threats truncated by the prompt cap: 3" in md
    assert "re-promoted after truncation" in md and "1" in md
    assert "BL-WEB-A03" in md
    assert "Repository kind(s) detected: web-api" in md


def test_pipeline_diagnostics_chunk_and_file_counters():
    m = ScanMetrics(
        s3_unknown_file_ids=2, s3_dropped_paths=1, s3_relocated_paths=4,
        s3_dropped_empty_chunks=1, s3_forced_coverage_files=5,
        s3_fallback_chunks_dropped=2, s3_cohesion_groups=8, s3_buckets=9,
    )
    md = _report_with_metrics(m).to_markdown()
    assert "matched no known file id: 2" in md
    assert "File references dropped (no matching file found): 1" in md
    assert "**File references repaired by a suffix match: 4**" in md
    assert "Empty chunks dropped: 1" in md
    assert "**Files added back by the coverage backstop: 5**" in md
    assert "Fallback chunks skipped" in md and "2" in md
    assert "Cohesion groups formed: 8" in md
    assert "Chunks packed into: 9 bucket(s)" in md


def test_pipeline_diagnostics_s4_truncation_renders_when_nonzero():
    m = ScanMetrics(s4_findings_truncated=4)
    md = _report_with_metrics(m).to_markdown()
    assert "### Pipeline Diagnostics" in md
    assert "**Deep-dive findings discarded by the per-call cap: 4**" in md


def test_pipeline_diagnostics_s4_truncation_absent_when_zero():
    md = _report_with_metrics(ScanMetrics()).to_markdown()
    assert "Deep-dive findings discarded" not in md


def test_pipeline_diagnostics_oversize_prompts_renders_when_nonzero():
    m = ScanMetrics(deepagents_oversize_prompts=3)
    md = _report_with_metrics(m).to_markdown()
    assert "### Pipeline Diagnostics" in md
    assert "**Calls refused as over-ceiling on the deepagents route: 3**" in md
    assert "VVAH-E004" in md


def test_pipeline_diagnostics_oversize_prompts_absent_when_zero():
    md = _report_with_metrics(ScanMetrics()).to_markdown()
    assert "over-ceiling on the deepagents route" not in md


def test_pipeline_diagnostics_truncated_replies_renders_when_nonzero():
    m = ScanMetrics(llm_truncated_replies=2)
    md = _report_with_metrics(m).to_markdown()
    assert "### Pipeline Diagnostics" in md
    assert "**LLM replies cut off by the output-token budget: 2**" in md
    assert "VVAH-E005" in md


def test_pipeline_diagnostics_truncated_replies_absent_when_zero():
    md = _report_with_metrics(ScanMetrics()).to_markdown()
    assert "cut off by the output-token budget" not in md


def test_pipeline_diagnostics_omits_fields_left_at_default():
    # Only one counter set — every other field (all still at their zero/empty
    # default) must NOT render a row.
    m = ScanMetrics(s3_relocated_paths=7)
    md = _report_with_metrics(m).to_markdown()
    assert "repaired by a suffix match: 7" in md
    for absent in ("Threats identified", "Threats truncated", "re-promoted",
                  "Baseline checklist", "Repository kind(s)",
                  "matched no known file id", "dropped (no matching file found)",
                  "Empty chunks dropped", "coverage backstop",
                  "Fallback chunks skipped", "Cohesion groups formed",
                  "Chunks packed into", "Deep-dive findings discarded",
                  "degraded", "strategist:"):
        assert absent not in md


def test_id_inventory_numbers_a_repeated_path_once():
    """A duplicated entry must not consume two ids.

    Numbering before deduplication left a gap: the second occurrence overwrote
    the first in the forward map, so the reverse map omitted the lower id and an
    id could appear in the rendered inventory yet resolve to nothing.
    """
    ctx = ContextPackage(repo_root="/r", language="python",
                         all_files=["a.py", "a.py", "b.py"])
    files = ctx.id_inventory()["files"]
    assert files == {"F001": "a.py", "F002": "b.py"}
    assert sorted(files) == [f"F{i:03d}" for i in range(1, len(files) + 1)], (
        "ids must be a contiguous run with no gap"
    )
