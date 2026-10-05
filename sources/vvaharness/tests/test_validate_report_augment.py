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

"""Tests for combined-report augmentation: validation results written into SARIF + MD."""
import json
from pathlib import Path

from vvaharness.models import Finding, MergeReadiness
from vvaharness.validation.models import ValidationResult
from vvaharness.validation.report.augment import augment_reports
from vvaharness.validation.report.models import ValidatedFinding

# Fixture scores asserted below; named so the comparisons avoid bare magic literals.
_FIX_CONFIDENCE = 0.89
_ROOT_CAUSE_WEIGHT = 0.43

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


def _finding(
    title: str = "Missing authz on mutations", file: str = "app/svc.py", line: int = 134
) -> Finding:
    """The finding SARIF results are matched against, by (file, startLine) then by title."""
    return Finding(
        title=title, file=file, line_start=line, vuln_class="logic-flaw", case_id="F-1"
    )


def _result() -> ValidationResult:
    return ValidationResult(
        finding_number=0, tracking_id="F-1", finding_title="Missing authz on mutations",
        finding_description="", affected_files="app/svc.py",
        fixed="Yes", partially_fixed="No", not_fixed="No",
        files_needing_fixes="", reason_for_decision="Fixed (0.89)",
        severity="High", pr_merge_readiness=MergeReadiness.READY.value, recommendations="",
        fix_confidence=_FIX_CONFIDENCE,
        gate_results_json=json.dumps(
            {"root_cause": {"status": "pass", "weight": _ROOT_CAUSE_WEIGHT,
                            "weighted_score": _ROOT_CAUSE_WEIGHT}},
        ),
        justification="All mutation routes now require auth.",
    )


def _combined_repo(tmp_path: Path) -> Path:
    """Repo whose s10 combined report already sits in security-remediation/ (what s11 enriches)."""
    rem = tmp_path / "security-remediation"
    rem.mkdir(parents=True)
    (rem / "demo_report.sarif").write_text(json.dumps(_SARIF, indent=2))
    (rem / "demo_report.md").write_text(_MD)
    return tmp_path


def test_augments_report_in_security_remediation(tmp_path: Path) -> None:
    repo = _combined_repo(tmp_path)
    augment_reports(repo, [ValidatedFinding(_finding(), _result())])
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    assert "validation" in doc["runs"][0]["results"][0]


def test_sarif_gains_validation_block(tmp_path: Path) -> None:
    repo = _combined_repo(tmp_path)
    augment_reports(repo, [ValidatedFinding(_finding(), _result())])
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    block = doc["runs"][0]["results"][0]["validation"]
    assert block["validationStatus"] == "fixed"
    assert block["weightedScore"] == _FIX_CONFIDENCE
    assert block["mergeReadiness"] == MergeReadiness.READY.value
    assert block["gateScores"]["root_cause"]["weighted_score"] == _ROOT_CAUSE_WEIGHT


def test_scan_dir_is_never_read(tmp_path: Path) -> None:
    # A report planted in security-scan/ must be ignored — validation only reads
    # security-remediation/. The scan copy stays pristine; the remediation copy is augmented.
    repo = _combined_repo(tmp_path)
    scan = repo / "security-scan"
    scan.mkdir(parents=True)
    (scan / "demo_report.sarif").write_text(json.dumps(_SARIF, indent=2))
    (scan / "demo_report.md").write_text(_MD)
    augment_reports(repo, [ValidatedFinding(_finding(), _result())])
    scan_doc = json.loads((scan / "demo_report.sarif").read_text())
    assert "validation" not in scan_doc["runs"][0]["results"][0]
    rem_doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    assert "validation" in rem_doc["runs"][0]["results"][0]


def test_md_gains_validation_section(tmp_path: Path) -> None:
    repo = _combined_repo(tmp_path)
    augment_reports(repo, [ValidatedFinding(_finding(), _result())])
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert "### Validation" in md
    assert str(_FIX_CONFIDENCE) in md
    assert "**Status:** Fixed" in md
    # Gate table rendered. "_" is escaped as an emphasis metacharacter, so the raw source
    # carries "root\_cause" -- which renders back as "root_cause".
    assert r"root\_cause" in md


def test_idempotent_no_duplicate_section(tmp_path: Path) -> None:
    repo = _combined_repo(tmp_path)
    augment_reports(repo, [ValidatedFinding(_finding(), _result())])
    augment_reports(repo, [ValidatedFinding(_finding(), _result())])
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert md.count("### Validation") == 1
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    # still a single validation block, not nested/duplicated
    assert isinstance(doc["runs"][0]["results"][0]["validation"], dict)


def test_partially_fixed_status(tmp_path: Path) -> None:
    repo = _combined_repo(tmp_path)
    res = _result()
    res.fixed, res.partially_fixed = "No", "Yes"
    augment_reports(repo, [ValidatedFinding(_finding(), res)])
    doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    assert doc["runs"][0]["results"][0]["validation"]["validationStatus"] == "partially_fixed"


def test_missing_combined_report_no_crash(tmp_path: Path) -> None:
    # no combined report in security-remediation/ → best-effort no-op, no exception
    augment_reports(tmp_path, [ValidatedFinding(_finding(), _result())])
    assert not (tmp_path / "security-remediation").exists()


# A combined report as s10 leaves it: the finding, then a report-level
# ``## Remediation Summary`` H2 appended at EOF.
_MD_WITH_SUMMARY = """# Agentic SAST — demo

## Findings (1)

### 1. [HIGH] Missing authz on mutations

#### Description
Unauthenticated mutation endpoints.

## Remediation Summary
- 1 finding remediated.
"""


def _combined_repo_with_summary(tmp_path: Path) -> Path:
    rem = tmp_path / "security-remediation"
    rem.mkdir(parents=True)
    (rem / "demo_report.sarif").write_text(json.dumps(_SARIF, indent=2))
    (rem / "demo_report.md").write_text(_MD_WITH_SUMMARY)
    return tmp_path


def test_md_validation_stays_above_report_summary(tmp_path: Path) -> None:
    # The per-finding ``### Validation`` must land above the report-level
    # ``## Remediation Summary`` s10 appended at EOF, and the summary is preserved.
    repo = _combined_repo_with_summary(tmp_path)
    augment_reports(repo, [ValidatedFinding(_finding(), _result())])
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert "### Validation" in md
    assert "## Remediation Summary" in md
    assert "1 finding remediated." in md  # summary body preserved
    assert md.index("### Validation") < md.index("## Remediation Summary")


def test_md_summary_ordering_idempotent(tmp_path: Path) -> None:
    repo = _combined_repo_with_summary(tmp_path)
    augment_reports(repo, [ValidatedFinding(_finding(), _result())])
    augment_reports(repo, [ValidatedFinding(_finding(), _result())])
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert md.count("### Validation") == 1
    assert md.count("## Remediation Summary") == 1
    assert md.index("### Validation") < md.index("## Remediation Summary")


# agent-authored text is neutralized before it reaches the Markdown report


def test_md_escape_neutralizes_injection() -> None:
    from vvaharness.validation.report.augment import _md_escape
    out = _md_escape("see <script>alert(1)</script> [link](x) `code`\nsecond line\x00")
    assert "<script>" not in out and "&lt;script&gt;" in out  # HTML defanged
    assert "\\[" in out and "\\`" in out                      # link/code syntax escaped
    assert "\n" not in out                                    # newlines collapsed
    assert "\x00" not in out                                  # control chars stripped


def _every_occurrence_escaped(out: str, ch: str) -> bool:
    """True if every ``ch`` in ``out`` sits behind an odd-length backslash run.

    An odd run means the final backslash escapes ``ch``, so Markdown renders it as a
    literal. An even run means the backslashes escape each other and ``ch`` is live
    syntax -- which is exactly what a backslash-blind escaper produces.
    """
    for i, c in enumerate(out):
        if c != ch:
            continue
        run = 0
        j = i - 1
        while j >= 0 and out[j] == "\\":
            run += 1
            j -= 1
        if run % 2 == 0:
            return False
    return True


def test_md_escape_neutralizes_preceding_backslash() -> None:
    """A backslash in the untrusted text must not consume the escape that follows it."""
    from vvaharness.validation.report.augment import _md_escape
    link = _md_escape(r"X\[click](u)")
    assert _every_occurrence_escaped(link, "[")   # no live link
    assert _every_occurrence_escaped(link, "]")
    code = _md_escape(r"X\`code`")
    assert _every_occurrence_escaped(code, "`")   # no live code span


def test_md_cell_escapes_pipe_and_bounds_length() -> None:
    from vvaharness.validation.report.augment import _md_cell
    assert "\\|" in _md_cell("a | b")        # table delimiter escaped
    assert len(_md_cell("x" * 500)) <= 200   # cell length bounded
    # A supplied backslash must not defeat the delimiter escape.
    assert _every_occurrence_escaped(_md_cell(r"a\|b"), "|")


def test_md_cell_truncation_leaves_no_dangling_escape() -> None:
    """Truncation must not cut a doubled backslash in half and escape the next cell's ``|``.

    The leading "x" is load-bearing: it makes the 200-char cut land mid-pair. Escaping
    yields "x" + 600 backslashes, so truncation leaves an odd run of 199 that the trim must
    reduce to 198. Without the "x" the cut falls on an even boundary (200), the trim is a
    no-op, and the assertion holds even against a build with no trim at all.
    """
    from vvaharness.validation.report.augment import _md_cell
    out = _md_cell("x" + "\\" * 300)
    assert len(out) <= 200
    trailing = len(out) - len(out.rstrip("\\"))
    assert trailing % 2 == 0    # no dangling escape to consume the next delimiter
    assert trailing == 198      # the odd 199-run was trimmed, not left as-is


def test_md_escape_strips_bidi_and_zero_width() -> None:
    # Bidi overrides/isolates and zero-width chars can visually reorder or hide
    # rendered text (Trojan-Source style); they must never reach the report.
    from vvaharness.validation.report.augment import _md_escape
    out = _md_escape("Fi\u202exed\u200b \u2066ok\u2069\ufeff")
    for ch in ("\u202e", "\u200b", "\u2066", "\u2069", "\ufeff"):
        assert ch not in out
    assert out == "Fixed ok"


def test_md_escape_folds_unicode_line_separators() -> None:
    # U+2028/U+2029/NEL are not "\n" but str.splitlines() (and some renderers)
    # break on them -- they must fold to spaces like a newline.
    from vvaharness.validation.report.augment import _md_escape
    out = _md_escape("a\u2028b\u2029c\x85d")
    assert out == "a b c d"
    assert not out.splitlines()[1:]


def test_md_escape_and_cell_map_none_to_empty() -> None:
    # None must render as an empty cell/field, not the literal string "None"
    # (matches the structural cell escaper in vvaharness.models).
    from vvaharness.validation.report.augment import _md_cell, _md_escape
    assert _md_escape(None) == ""
    assert _md_cell(None) == ""


def test_malicious_justification_renders_inert(tmp_path: Path) -> None:
    repo = _combined_repo(tmp_path)
    result = _result()
    evil = result.model_copy(update={
        "justification": "Fixed </td><script>steal()</script> | extra `cmd` [x](y)",
    })
    augment_reports(repo, [ValidatedFinding(_finding(), evil)])
    md = (repo / "security-remediation" / "demo_report.md").read_text()
    assert "<script>" not in md            # the raw tag never reaches the rendered report
    assert "&lt;script&gt;" in md


# report pinning (#2): read from security-remediation/, survive repeated cycles


def _write_combined(repo: Path, stem: str, md: str = _MD) -> Path:
    rem = repo / "security-remediation"
    rem.mkdir(parents=True, exist_ok=True)
    (rem / f"{stem}.sarif").write_text(json.dumps(_SARIF, indent=2))
    md_path = rem / f"{stem}.md"
    md_path.write_text(md)
    return md_path


def _has_validation(repo: Path, stem: str) -> bool:
    doc = json.loads((repo / "security-remediation" / f"{stem}.sarif").read_text())
    return "validation" in doc["runs"][0]["results"][0]


def test_multi_run_enriches_newest(tmp_path: Path) -> None:
    # Two remediation cycles leave two timestamped reports; the newest (latest cycle,
    # matching the current DTOs) is enriched, the older one is left untouched.
    _write_combined(tmp_path, "demo_20260101T000000Z_report")
    _write_combined(tmp_path, "demo_20260202T000000Z_report")
    augment_reports(tmp_path, [ValidatedFinding(_finding(), _result())])
    assert _has_validation(tmp_path, "demo_20260202T000000Z_report")
    assert not _has_validation(tmp_path, "demo_20260101T000000Z_report")


def test_explicit_report_md_overrides_newest(tmp_path: Path) -> None:
    _write_combined(tmp_path, "demo_20260101T000000Z_report")
    _write_combined(tmp_path, "demo_20260202T000000Z_report")
    older = tmp_path / "security-remediation" / "demo_20260101T000000Z_report.md"
    augment_reports(tmp_path, [ValidatedFinding(_finding(), _result())], report_md=older)
    assert _has_validation(tmp_path, "demo_20260101T000000Z_report")
    assert not _has_validation(tmp_path, "demo_20260202T000000Z_report")


def test_explicit_scan_report_md_rebased_to_remediation(tmp_path: Path) -> None:
    # In-pipeline scan.py passes the canonical report_md under security-scan/; the locator must
    # rebase it onto security-remediation/ and leave the pristine scan copy untouched.
    repo = _combined_repo(tmp_path)
    scan = repo / "security-scan"
    scan.mkdir(parents=True)
    (scan / "demo_report.sarif").write_text(json.dumps(_SARIF, indent=2))
    (scan / "demo_report.md").write_text(_MD)
    augment_reports(repo, [ValidatedFinding(_finding(), _result())], report_md=scan / "demo_report.md")
    rem_doc = json.loads((repo / "security-remediation" / "demo_report.sarif").read_text())
    assert "validation" in rem_doc["runs"][0]["results"][0]
    scan_doc = json.loads((scan / "demo_report.sarif").read_text())
    assert "validation" not in scan_doc["runs"][0]["results"][0]


# fail-closed matching (#3) + path-separator robustness (#6)


def _pair(title: str, justification: str, line: int = 134) -> ValidatedFinding:
    """A validated finding whose title and justification are distinguishable in the output."""
    row = _result().model_copy(update={"finding_title": title, "justification": justification})
    return ValidatedFinding(_finding(title=title, line=line), row)


_MD_ONE_HEADING = "# R\n\n## Findings\n\n### 1. [HIGH] {t}\n\n#### Description\nx\n"


def test_duplicate_titles_render_skipped(tmp_path: Path) -> None:
    # Two findings share the exact heading title → ambiguous → no validation section attached.
    _write_combined(tmp_path, "demo_report", md=_MD_ONE_HEADING.format(t="Auth bug"))
    augment_reports(tmp_path, [_pair("Auth bug", "AAA"), _pair("Auth bug", "BBB")])
    out = (tmp_path / "security-remediation" / "demo_report.md").read_text()
    assert "### Validation" not in out


def test_overlapping_titles_attribute_correctly(tmp_path: Path) -> None:
    # Heading "SQL injection" must attach to the exact-title finding, not the overlapping
    # "SQL injection in reports" (the old first-bidirectional-substring bug). B is listed first.
    _write_combined(tmp_path, "demo_report", md=_MD_ONE_HEADING.format(t="SQL injection"))
    augment_reports(tmp_path, [_pair("SQL injection in reports", "BBB", line=200),
                               _pair("SQL injection", "AAA")])
    out = (tmp_path / "security-remediation" / "demo_report.md").read_text()
    assert "AAA" in out and "BBB" not in out


def test_loc_match_path_separator_insensitive(tmp_path: Path) -> None:
    # SARIF uri uses "/", the DTO file uses "\\"; location match must still succeed (title differs).
    _write_combined(tmp_path, "demo_report")
    finding = _finding(title="Totally different title", file="app\\svc.py")
    augment_reports(tmp_path, [ValidatedFinding(finding, _result())])
    doc = json.loads((tmp_path / "security-remediation" / "demo_report.sarif").read_text())
    assert "validation" in doc["runs"][0]["results"][0]
