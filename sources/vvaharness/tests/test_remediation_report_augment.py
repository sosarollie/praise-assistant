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

"""Tests for combined-report augmentation: remediation results written into SARIF + MD.

Mirrors tests/test_validate_report_augment.py (the s11 validation analog). The
remediation results are read back from the per-finding ``finding_case.json`` records the
agent already wrote, so these tests construct those cases on disk and assert the copied
SARIF/MD gain the matching remediation block/section.

The report bucket is DERIVED from each case's attempt sequence (``derive.state_of``), so
these tests build the attempts that imply a bucket rather than writing a status string —
there is no longer a status string to write.
"""
import json
from pathlib import Path

from vvaharness.models import (
    Decision,
    Disposition,
    Finding,
    FindingCase,
    Provenance,
    Remediation,
    RemediationKind,
    Verdict,
)
from vvaharness.remediation_agent.report_augment import augment_reports

_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Agentic SAST"}},
        "results": [{
            "ruleId": "CWE-862",
            "level": "error",
            "message": {"text": "Missing authz on mutations  [CVSS 9.8]"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/svc.py"},
                "region": {"startLine": 134},
            }}],
            "properties": {"severity": "high"},
        }],
    }],
}

_MD = """# Agentic SAST — demo

## Findings (1)

### 1. [HIGH] Missing authz on mutations

#### Description
Unauthenticated mutation endpoints.

## Analysis
Confirmed.
"""


def _scan_repo(tmp_path: Path) -> Path:
    scan = tmp_path / "security-scan"
    scan.mkdir(parents=True)
    (scan / "demo_report.sarif").write_text(json.dumps(_SARIF, indent=2))
    (scan / "demo_report.md").write_text(_MD)
    return tmp_path


def _write_case(repo: Path, *, kind=RemediationKind.EDITS_APPLIED, disposition=None,
                decision=None, summary="parameterized JQL",
                files=("app/svc.py",), triage=None, slug="01_missing-authz",
                title="Missing authz on mutations", file="app/svc.py", line_start=134):
    """Write a per-finding finding_case.json (+ optional evidence/triage.json).

    *decision* attaches a validator verdict to the attempt, which is how a case reaches
    the VALIDATED / FAILED states — the augmenter must handle both without a status field."""
    d = repo / "security-remediation" / slug
    d.mkdir(parents=True, exist_ok=True)
    case = FindingCase(
        case_id=f"abc123-{slug}",
        finding=Finding(title=title, file=file, line_start=line_start,
                        vuln_class="injection"),
    ).with_attempt(Remediation(
        kind=kind, summary=summary, disposition=disposition,
        files_touched=tuple(files),
        produced_by=Provenance(engine="test"),
    ))
    if decision is not None:
        case = case.with_verdict(Verdict(decision=decision, rationale="because"))
    case.write(d / "finding_case.json")
    if triage is not None:
        ev = d / "evidence"
        ev.mkdir(parents=True, exist_ok=True)
        (ev / "triage.json").write_text(json.dumps(triage, indent=2))
    return d


def _write_denied(repo: Path, **kw) -> Path:
    """A case the policy gate refused: nothing attempted, reason in the sidecar."""
    return _write_case(repo, kind=RemediationKind.NO_ACTION,
                       disposition=Disposition.POLICY_DENIED, summary="",
                       files=(), **kw)


def _write_false_positive(repo: Path, **kw) -> Path:
    """A case an engine declined as a false positive."""
    return _write_case(repo, kind=RemediationKind.NO_ACTION,
                       disposition=Disposition.FALSE_POSITIVE, summary="",
                       files=(), **kw)


def test_copies_report_into_security_remediation(tmp_path: Path) -> None:
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    augment_reports(repo)
    assert (repo / "security-remediation" / "demo_report.sarif").exists()
    assert (repo / "security-remediation" / "demo_report.md").exists()


def test_sarif_gains_remediation_block(tmp_path: Path) -> None:
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    augment_reports(repo)
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    block = doc["runs"][0]["results"][0]["remediation"]
    assert block["remediationStatus"] == "remediated"
    assert "parameterized JQL" in block["remediationReason"]


def test_scan_original_untouched(tmp_path: Path) -> None:
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    augment_reports(repo)
    scan = json.loads((repo / "security-scan" / "demo_report.sarif").read_text())
    assert "remediation" not in scan["runs"][0]["results"][0]


def test_md_gains_remediation_section(tmp_path: Path) -> None:
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert "### Remediation" in md
    assert "**Status:** remediated" in md
    assert "**Summary:** parameterized JQL" in md
    assert "**Approach:**" in md
    assert "`app/svc.py`" in md


def test_files_touched_deduplicated(tmp_path: Path) -> None:
    """Each touched file is listed only once even if the DTO repeats it."""
    repo = _scan_repo(tmp_path)
    _write_case(repo, files=("app/svc.py", "app/svc.py", "app/util.py", "app/svc.py"))
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert md.count("`app/svc.py`") == 1
    assert md.count("`app/util.py`") == 1


def test_idempotent_no_duplicate_section(tmp_path: Path) -> None:

    repo = _scan_repo(tmp_path)
    _write_case(repo)
    augment_reports(repo)
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert md.count("### Remediation") == 1
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    assert isinstance(doc["runs"][0]["results"][0]["remediation"], dict)


def test_policy_denied_maps_to_deny(tmp_path: Path) -> None:
    repo = _scan_repo(tmp_path)
    _write_denied(repo, triage={"final_verdict": "REJECT",
                                "policy_reason": "CWE-89 denied by policy"})
    augment_reports(repo)
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    block = doc["runs"][0]["results"][0]["remediation"]
    assert block["remediationStatus"] == "deny"
    assert "denied by policy" in block["remediationReason"]
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert "**Status:** deny" in md


def test_policy_denied_without_sidecar_still_reads_deny(tmp_path: Path) -> None:
    """The bucket comes from the disposition, so a missing triage sidecar cannot
    downgrade a policy denial into a generic skip — only its reason gets less specific."""
    repo = _scan_repo(tmp_path)
    _write_denied(repo)
    augment_reports(repo)
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    block = doc["runs"][0]["results"][0]["remediation"]
    assert block["remediationStatus"] == "deny"
    assert block["remediationReason"] == "policy gate denied automated remediation"


def test_false_positive_maps_to_skipped(tmp_path: Path) -> None:
    repo = _scan_repo(tmp_path)
    _write_false_positive(repo)
    augment_reports(repo)
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    block = doc["runs"][0]["results"][0]["remediation"]
    assert block["remediationStatus"] == "skipped"
    assert block["remediationReason"] == "finding rejected as a false positive"


def test_validated_verdict_maps_to_remediated(tmp_path: Path) -> None:
    """A case the validator confirmed FIXED must land in the 'remediated' bucket,
    not fall through to 'skipped' (which would mislabel a confirmed fix on an
    out-of-order augment re-run)."""
    repo = _scan_repo(tmp_path)
    _write_case(repo, decision=Decision.FIXED, summary="confirmed fixed by s11")
    augment_reports(repo)
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    block = doc["runs"][0]["results"][0]["remediation"]
    assert block["remediationStatus"] == "remediated"
    assert "confirmed fixed by s11" in block["remediationReason"]
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert "**Status:** remediated" in md


def test_failed_validation_maps_to_skipped_with_rework_reason(tmp_path: Path) -> None:
    """A fix that landed but did NOT pass review is not remediated, and says why."""
    repo = _scan_repo(tmp_path)
    _write_case(repo, decision=Decision.NOT_FIXED, summary="")
    augment_reports(repo)
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    block = doc["runs"][0]["results"][0]["remediation"]
    assert block["remediationStatus"] == "skipped"
    assert block["remediationReason"] == (
        "fix applied but failed validation; needs rework")


def test_unprocessed_finding_gets_skipped_block_and_section(tmp_path: Path) -> None:
    # Two findings in the report, but only finding #1 has a DTO. Finding #2 was
    # never processed → it must still get an explicit skipped block + section.
    repo = _scan_repo(tmp_path)
    # add a second result + finding to the scan report
    import json as _json
    sarif = _json.loads((repo / "security-scan" / "demo_report.sarif").read_text())
    sarif["runs"][0]["results"].append({
        "ruleId": "CWE-89", "level": "error",
        "message": {"text": "SQL injection in reporting query"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app/reports.py"},
            "region": {"startLine": 50}}}],
        "properties": {"severity": "high"},
    })
    (repo / "security-scan" / "demo_report.sarif").write_text(_json.dumps(sarif, indent=2))
    md = (repo / "security-scan" / "demo_report.md").read_text()
    md += "\n### 2. [HIGH] SQL injection in reporting query\n\n#### Description\nUnsafe query.\n"
    (repo / "security-scan" / "demo_report.md").write_text(md)

    _write_case(repo)  # only finding #1
    augment_reports(repo)

    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    results = doc["runs"][0]["results"]
    # both results carry a remediation block
    assert all("remediation" in r for r in results)
    by_rule = {r["ruleId"]: r["remediation"]["remediationStatus"] for r in results}
    assert by_rule["CWE-862"] == "remediated"
    assert by_rule["CWE-89"] == "skipped"
    # MD has a skipped section for the unprocessed finding
    out_md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert out_md.count("### Remediation") == 2
    assert "finding not processed for remediation" in out_md


def test_md_gains_remediation_summary(tmp_path: Path) -> None:
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert "## Remediation Summary" in md
    assert "- Total findings (true positive): 1" in md
    assert "- Findings in scope for remediation: 1" in md
    assert "- Remediated: 1" in md
    assert "- Success Rate(remediated/true positive): 100%" in md


def test_summary_in_scope_is_case_count(tmp_path: Path) -> None:
    # 3 findings (3 case folders): one remediated, one false positive, one policy-denied.
    # "In scope" == a case file exists == 3, regardless of outcome.
    repo = _scan_repo(tmp_path)
    _write_case(repo, slug="01_a", title="Missing authz on mutations",
                file="app/svc.py", line_start=134)
    _write_false_positive(repo, slug="02_b", title="FP finding",
                          file="app/fp.py", line_start=1)
    _write_denied(repo, slug="03_c", title="Denied finding",
                  file="app/d.py", line_start=2,
                  triage={"final_verdict": "REJECT",
                          "policy_reason": "CWE-89 denied by policy"})
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    # true positives = 3 total - 1 FP = 2; in scope = 3 cases; remediated = 1.
    assert "- Total findings (true positive): 2" in md
    assert "- Findings in scope for remediation: 3" in md
    assert "- Remediated: 1" in md
    # success rate = remediated / in-scope = 1 / 3 = 33%.
    assert "- Success Rate(remediated/true positive): 33%" in md


def test_summary_idempotent(tmp_path: Path) -> None:
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    augment_reports(repo)
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert md.count("## Remediation Summary") == 1


def test_no_dtos_no_copy(tmp_path: Path) -> None:


    # security-scan/ present but no remediation DTOs → best-effort no-op.
    repo = _scan_repo(tmp_path)
    augment_reports(repo)
    assert not (repo / "security-remediation" / "demo_report.sarif").exists()


def test_missing_scan_report_no_crash(tmp_path: Path) -> None:
    # DTO present but no security-scan report → no crash, no copied report.
    _write_case(tmp_path)
    augment_reports(tmp_path)
    assert not (tmp_path / "security-remediation" / "demo_report.sarif").exists()


def test_md_summary_escapes_markdown_and_html(tmp_path: Path) -> None:
    """A model-controlled remediation summary containing Markdown/HTML must be
    neutralised in the rendered Markdown report — no raw tags, no active emphasis
    or links, and the structural ``### Remediation`` heading cannot be forged by
    embedded newlines."""
    repo = _scan_repo(tmp_path)
    nasty = (
        "<script>alert(1)</script> **bold** `code` "
        "[click](http://evil)\n### Remediation\n- **Status:** Fixed"
    )
    _write_case(repo, summary=nasty)
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()

    # Raw HTML tags are entity-escaped (inert in an HTML-capable renderer).
    assert "<script>" not in md
    assert "&lt;script&gt;" in md
    # Markdown metacharacters in the untrusted value are backslash-escaped.
    assert "\\*\\*bold\\*\\*" in md
    assert "\\`code\\`" in md
    assert "\\[click\\]" in md
    # The forged heading + embedded newline cannot create a second Remediation
    # block: only the genuine harness-emitted heading exists.
    assert md.count("### Remediation") == 1


def test_md_file_names_are_safe_code_spans(tmp_path: Path) -> None:
    """A malicious touched-file name with a backtick cannot break out of its
    inline code span to inject Markdown/HTML."""
    repo = _scan_repo(tmp_path)
    _write_case(repo, files=("app/svc.py`<script>bad</script>",))
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    # No raw tag survives; angle brackets are entity-escaped inside the span.
    assert "<script>" not in md
    assert "&lt;script&gt;bad&lt;/script&gt;" in md
    # The embedded backtick is stripped so the code span cannot be broken out of.
    assert "app/svc.py`" not in md


def test_md_escape_folds_unicode_line_separators() -> None:
    """U+2028/U+2029/NEL are honoured by str.splitlines() and some renderers, so an escaped value carrying one could still forge a second ``### Remediation`` heading."""
    from vvaharness.remediation_agent.report_augment.mdsafe import _md_escape
    for sep in ("\u2028", "\u2029", "\x85"):
        out = _md_escape(f"fixed{sep}### Remediation")
        assert "\n" not in out and sep not in out
        assert out == "fixed \\#\\#\\# Remediation"


def test_md_escape_strips_bidi_and_zero_width() -> None:
    """Bidi overrides / zero-width chars / BOM must be stripped so a status or summary cannot be visually reversed or hide content (Trojan-Source)."""
    from vvaharness.remediation_agent.report_augment.mdsafe import _md_escape
    out = _md_escape("fi\u202exed\u200b sta\ufefftus")
    assert out == "fixed status"


def test_md_code_span_strips_backtick_and_invisibles() -> None:
    from vvaharness.remediation_agent.report_augment.mdsafe import _md_code_span
    out = _md_code_span("app/`sv\u202ec\u2028.py")
    # Backtick stripped, bidi stripped, line separator folded to a space.
    assert out == "`app/svc .py`"


def test_mdsafe_shares_models_render_boundary_regexes() -> None:
    """Guard against re-duplication: mdsafe must keep using the shared render-boundary regexes from vvaharness.models, not a private copy."""
    from vvaharness import models
    from vvaharness.remediation_agent.report_augment import mdsafe
    assert mdsafe._MD_INVISIBLE_RX is models._MD_INVISIBLE_RX
    assert mdsafe._MD_LINEBREAK_RX is models._MD_LINEBREAK_RX


def _scan_repo_two_findings(tmp_path: Path, t1: str, t2: str) -> Path:
    """A scan report (SARIF + MD) carrying two findings with the given titles."""
    scan = tmp_path / "security-scan"
    scan.mkdir(parents=True)
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Agentic SAST"}},
            "results": [
                {"ruleId": "CWE-89", "level": "error",
                 "message": {"text": t1},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app/a.py"},
                     "region": {"startLine": 10}}}]},
                {"ruleId": "CWE-89", "level": "error",
                 "message": {"text": t2},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app/b.py"},
                     "region": {"startLine": 20}}}]},
            ],
        }],
    }
    (scan / "demo_report.sarif").write_text(json.dumps(sarif, indent=2))
    (scan / "demo_report.md").write_text(
        "# Agentic SAST — demo\n\n## Findings (2)\n\n"
        f"### 1. [HIGH] {t1}\n\n#### Description\nfirst.\n\n"
        f"### 2. [HIGH] {t2}\n\n#### Description\nsecond.\n")
    return tmp_path


def _remediation_section_for(md: str, heading_title: str) -> str:
    """Return the text of the finding segment whose heading carries *heading_title*.

    Bounds the segment by the NEXT numbered finding heading (``### N.``) so the
    inserted ``### Remediation`` subsection stays inside it."""
    import re as _re
    start = md.index(f"] {heading_title}")
    m = _re.search(r"\n### \d+\. ", md[start + 1:])
    end = (start + 1 + m.start()) if m else len(md)
    return md[start:end]


def test_md_overlapping_titles_match_correct_section(tmp_path: Path) -> None:
    """Two findings with overlapping titles must each receive THEIR OWN
    remediation result, not be cross-matched by substring."""
    t1 = "SQL injection"
    t2 = "SQL injection in reporting query"
    repo = _scan_repo_two_findings(tmp_path, t1, t2)
    _write_case(repo, slug="01_a", title=t1, file="app/a.py", line_start=10,
               summary="fix for short title")
    _write_case(repo, slug="02_b", title=t2, file="app/b.py", line_start=20,
               summary="fix for long title")
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()

    seg1 = _remediation_section_for(md, t1)
    seg2 = _remediation_section_for(md, t2)
    # Each finding's own remediation summary lands under its own heading.
    assert "fix for short title" in seg1
    assert "fix for long title" not in seg1
    assert "fix for long title" in seg2
    assert "fix for short title" not in seg2


def test_md_duplicate_exact_titles_are_not_misattributed(tmp_path: Path) -> None:
    """When two findings share the SAME exact title, the augmenter must refuse to
    guess and render them skipped rather than attaching the wrong DTO."""
    t = "Hardcoded credential"
    repo = _scan_repo_two_findings(tmp_path, t, t)
    _write_case(repo, slug="01_a", title=t, file="app/a.py", line_start=10,
               summary="unique-summary-A")
    _write_case(repo, slug="02_b", title=t, file="app/b.py", line_start=20,
               summary="unique-summary-B")
    augment_reports(repo)
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    # Ambiguous → neither finding is mis-attributed a specific summary; both fall
    # back to the "not processed" skipped section.
    assert "unique-summary-A" not in md
    assert "unique-summary-B" not in md
    assert md.count("finding not processed for remediation") == 2


def test_explicit_report_path_is_honoured(tmp_path: Path) -> None:
    """Passing the explicit canonical report binds augmentation to THAT file."""
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    report_md = repo / "security-scan" / "demo_report.md"
    augment_reports(repo, report_md)
    assert (repo / "security-remediation" / "demo_report.sarif").exists()
    out_md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert "### Remediation" in out_md


def test_planted_report_does_not_win_over_explicit(tmp_path: Path) -> None:
    """A planted, lexically-newer report in security-scan/ must NOT be selected
    when the caller passes the real canonical report."""
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    scan = repo / "security-scan"
    # Plant a newer (sorts last) attacker report whose findings differ.
    (scan / "zzz_99999999T999999Z_report.sarif").write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Agentic SAST"}},
                  "results": [{"ruleId": "CWE-1", "level": "note",
                               "message": {"text": "planted"},
                               "locations": [{"physicalLocation": {
                                   "artifactLocation": {"uri": "evil.py"},
                                   "region": {"startLine": 1}}}]}]}],
    }, indent=2))
    (scan / "zzz_99999999T999999Z_report.md").write_text(
        "# planted\n\n## Findings (1)\n\n### 1. [LOW] planted\n\n#### Description\nx.\n")

    real_md = scan / "demo_report.md"
    augment_reports(repo, real_md)
    # The canonical demo report is the one copied + augmented, not the planted one.
    assert (repo / "security-remediation" / "demo_report.sarif").exists()
    assert not (repo / "security-remediation"
                / "zzz_99999999T999999Z_report.sarif").exists()


def test_glob_fallback_refuses_ambiguous_multiple_reports(tmp_path: Path) -> None:
    """With NO explicit report and MULTIPLE candidates present, the glob fallback
    must refuse to guess (the old newest-wins was tamperable) — nothing copied."""
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    scan = repo / "security-scan"
    (scan / "second_20990101T000000Z_report.sarif").write_text(
        json.dumps(_SARIF, indent=2))
    (scan / "second_20990101T000000Z_report.md").write_text(_MD)
    augment_reports(repo)  # no explicit report → ambiguous → bail
    assert not (repo / "security-remediation" / "demo_report.sarif").exists()
    assert not (repo / "security-remediation"
                / "second_20990101T000000Z_report.sarif").exists()


def test_glob_fallback_single_report_still_works(tmp_path: Path) -> None:
    """Back-compat: with exactly one report and no explicit path, the glob
    fallback still augments it."""
    repo = _scan_repo(tmp_path)
    _write_case(repo)
    augment_reports(repo)  # single report present → proceed
    assert (repo / "security-remediation" / "demo_report.sarif").exists()


