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

# START GENAI
"""Tests for the typed scan result on disk and the SARIF ids stamped beside it.

The point of ``findings.json`` is that a second process no longer has to re-parse the rendered
Markdown to learn what the scan found. So the assertions are about the fields that regex path
could not recover — ``source_ref``, ``sink_ref``, ``duplicates`` and ``case_id`` — and about
the redaction the artefact shares with every other one.
"""
from __future__ import annotations

import json

from vvaharness.models import (
    DupLocation,
    FinalReport,
    Finding,
    RankedFinding,
    Severity,
)
from vvaharness.orchestrator.findings_json import (
    findings_json_path,
    read_findings_json,
    write_findings_json,
)
from vvaharness.orchestrator.sarif_ids import FINGERPRINT_KEY, stamp_case_ids


def _report(**over) -> FinalReport:
    fields = {
        "title": "SQLi in login", "file": "app/db.py", "line_start": 42,
        "line_end": 44, "vuln_class": "injection", "severity": Severity.CRITICAL,
        "cwe": "CWE-89", "source_ref": "app/web.py:11", "sink_ref": "app/db.py:42",
        "code_snippet": "cur.execute(q)", "confidence": 0.8, "case_id": "vvaf1_abc",
        "duplicates": [DupLocation(file="app/admin.py", line_start=77, line_end=79,
                                   vuln_class="injection",
                                   reasoning="same root cause")],
    }
    finding = Finding(**{**fields, **over})
    return FinalReport(
        repo_root="/w/repo", summary="s", chains=[], raw_findings_count=3,
        findings=[RankedFinding(finding=finding, severity=Severity.CRITICAL,
                                exploitability_notes="reachable")],
    )


def test_write_lands_under_security_scan(tmp_path):
    path = write_findings_json(_report(), tmp_path)
    assert path == findings_json_path(tmp_path)
    assert path.parent.name == "security-scan"


def test_roundtrip_keeps_what_the_markdown_parse_lost(tmp_path):
    """The typed document carries the evidence the regex path returned as None or dropped."""
    write_findings_json(_report(), tmp_path)
    loaded = read_findings_json(tmp_path)
    assert loaded is not None
    finding = loaded.findings[0].finding
    assert finding.source_ref == "app/web.py:11"
    assert finding.sink_ref == "app/db.py:42"
    assert finding.case_id == "vvaf1_abc"
    assert [(d.file, d.line_start, d.line_end) for d in finding.duplicates] == [
        ("app/admin.py", 77, 79)]
    assert finding.severity is Severity.CRITICAL


def test_unscored_confidence_round_trips_as_the_neutral_value(tmp_path):
    """A caller with no confidence signal gets 0.5, and it survives the round-trip.

    ``confidence`` is a plain float, not ``float | None``: nine sites across s4/s5/s8 and
    report/enrich compare or format it arithmetically, so 0.5 -- which this codebase has
    always used for "no opinion" -- is the value for absent rather than None.
    """
    write_findings_json(_report(confidence=None), tmp_path)
    loaded = read_findings_json(tmp_path)
    assert loaded is not None
    assert loaded.findings[0].finding.confidence == 0.5


def test_secrets_in_a_snippet_are_masked(tmp_path):
    """Same redaction gate as the Markdown and the SARIF — this artefact carries the same code."""
    path = write_findings_json(
        _report(code_snippet='conn = connect(password="hunter2seekrit")'), tmp_path)
    raw = path.read_text(encoding="utf-8")
    assert "hunter2seekrit" not in raw
    assert "REDACTED" in raw.upper()


def test_missing_file_reads_as_none(tmp_path):
    """A checkout with no scan on disk is a routine answer, not an error."""
    assert read_findings_json(tmp_path) is None


def test_unreadable_file_degrades_with_a_notice(tmp_path, capsys):
    """A document this build cannot understand is discarded loudly, never half-trusted."""
    path = findings_json_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8")
    assert read_findings_json(tmp_path) is None
    assert "not a readable scan result" in capsys.readouterr().err


def _sarif(uri: str, line: int) -> dict:
    return {"runs": [{"results": [{
        "ruleId": "injection",
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line},
        }}],
    }]}]}


def test_case_id_is_stamped_into_partial_fingerprints(tmp_path):
    """SARIF's own place for a producer identity, so a consumer can correlate two scans."""
    path = tmp_path / "r.sarif"
    path.write_text(json.dumps(_sarif("app/db.py", 42)), encoding="utf-8")
    assert stamp_case_ids(path, _report()) == 1
    result = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"][0]
    assert result["partialFingerprints"] == {FINGERPRINT_KEY: "vvaf1_abc"}


def test_a_mismatched_location_is_skipped_not_mislabelled(tmp_path, capsys):
    """Attaching the wrong id is worse than attaching none, so a divergence warns and skips."""
    path = tmp_path / "r.sarif"
    path.write_text(json.dumps(_sarif("app/db.py", 999)), encoding="utf-8")
    assert stamp_case_ids(path, _report()) == 0
    assert "did not match a SARIF result location" in capsys.readouterr().err
    result = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"][0]
    assert "partialFingerprints" not in result


def test_stamping_survives_the_real_markdown_to_sarif_round_trip(tmp_path):
    """The load-bearing assumption, exercised end to end.

    Matching is positional because the SARIF is built by re-parsing the Markdown the report
    just rendered. If either side's ordering ever diverges, the ids land on the wrong results —
    so this walks the actual render → parse → stamp path rather than a hand-built document,
    including a same-bucket collision (two CWE-89 findings in app/db.py, ten lines apart).
    """
    from vvaharness.orchestrator.case_ids import mint_case_ids
    from vvaharness.report import enrich

    def _finding(title: str, file: str, line: int, cwe: str) -> Finding:
        return Finding(title=title, file=file, line_start=line, vuln_class="injection",
                       cwe=cwe, description="desc", confidence=0.9,
                       cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       cvss_score=9.8, cvss_rating="Critical")

    report = FinalReport(
        repo_root="/w/repo", summary="s", chains=[], raw_findings_count=3,
        findings=[RankedFinding(finding=f, severity=Severity.HIGH,
                                exploitability_notes="n")
                  for f in (_finding("SQLi in login", "app/db.py", 42, "CWE-89"),
                            _finding("XSS in profile", "app/web.py", 10, "CWE-79"),
                            _finding("SQLi in search", "app/db.py", 45, "CWE-89"))],
    )
    assert mint_case_ids(report)["collisions"] == 1

    md = tmp_path / "r.md"
    md.write_text(report.to_markdown(), encoding="utf-8")
    sarif = tmp_path / "r.sarif"
    enrich.md_to_sarif(str(md), None, None, str(sarif))

    assert stamp_case_ids(sarif, report) == 3
    results = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
    stamped = [r["partialFingerprints"][FINGERPRINT_KEY] for r in results]
    assert stamped == [rf.finding.case_id for rf in report.findings]
    assert len(set(stamped)) == 3


def test_a_malformed_sarif_does_not_fail_the_scan(tmp_path, capsys):
    """The SARIF is already complete by the time this runs; stamping is additive."""
    path = tmp_path / "r.sarif"
    path.write_text("{oops", encoding="utf-8")
    assert stamp_case_ids(path, _report()) == 0
    assert "could not stamp case ids" in capsys.readouterr().err
