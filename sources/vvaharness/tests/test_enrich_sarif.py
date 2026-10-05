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

"""Behavioral tests for SARIF emission in vvaharness.report.enrich.

Covers md_to_sarif / generate_sarif:
  * SARIF result.rank is the 0-10 CVSS base score scaled into [0,100].
  * Run-level driver/properties never carry an empty-string informationUri;
    the CWE taxonomy informationUri is set from project (MITRE) metadata.
  * cvssRating / security-severity / region behavior preserved, including the
    intentional qualitative mapping (Critical severity with no CVSS reports a
    High cvssRating via the 9.0 fallback).
  * Redaction is applied at the SARIF write boundary (redact_tree) so card /
    credential material the model quoted never lands in the on-disk SARIF.
"""
import json

import pytest

from vvaharness.report import enrich
from vvaharness.report.enrich import (
    Finding,
    _cvss_rating,
    _security_severity,
    generate_sarif,
    md_to_sarif,
)

# A standard CVSS:3.1 vector used by several tests. AV:N/AC:L/PR:N/UI:N
# /S:U/C:H/I:H/A:H is the canonical "Critical" base score (9.8).
CRIT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _write_sarif(tmp_path, findings, app_id="42", app=None):
    """Run generate_sarif and return the parsed JSON document."""
    md = tmp_path / "findings.md"
    md.write_text("# placeholder\n", encoding="utf-8")
    out = tmp_path / "out.sarif"
    generate_sarif(str(md), findings, app_id, app, str(out))
    return json.loads(out.read_text(encoding="utf-8"))


def _only_result(doc):
    runs = doc["runs"]
    assert len(runs) == 1
    results = runs[0]["results"]
    assert len(results) == 1
    return results[0]


# rank: 0-10 CVSS base score scaled into [0, 100]
def test_rank_scaled_into_0_100(tmp_path):
    f = Finding(severity="HIGH", title="SQLi", file="a.py", line_no=5,
                cvss=CRIT_VECTOR, cvss_score=9.8)
    res = _only_result(_write_sarif(tmp_path, [f]))
    # 9.8 * 10 = 98.0 — inside the SARIF 0..100 priority range.
    assert res["rank"] == 98.0
    assert 0.0 <= res["rank"] <= 100.0


def test_rank_max_score_does_not_exceed_100(tmp_path):
    f = Finding(severity="HIGH", title="max", file="a.py", cvss_score=10.0)
    res = _only_result(_write_sarif(tmp_path, [f]))
    assert res["rank"] == 100.0
    assert res["rank"] <= 100.0


def test_rank_omitted_when_no_cvss_score(tmp_path):
    # cvss_score default -1.0 → no base score → rank must be absent (not 0/neg).
    f = Finding(severity="MEDIUM", title="no score", file="a.py")
    res = _only_result(_write_sarif(tmp_path, [f]))
    assert "rank" not in res


def test_rank_zero_score_present_and_in_range(tmp_path):
    f = Finding(severity="LOW", title="zero", file="a.py", cvss_score=0.0)
    res = _only_result(_write_sarif(tmp_path, [f]))
    assert res["rank"] == 0.0


# informationUri: set from metadata (MITRE taxonomy) or omitted, never ""
def test_cwe_taxonomy_information_uri_set_from_metadata(tmp_path):
    f = Finding(severity="HIGH", title="xss", file="a.py", cwe="CWE-79",
                cvss_score=7.0)
    doc = _write_sarif(tmp_path, [f])
    tax = doc["runs"][0]["taxonomies"]
    assert len(tax) == 1
    cwe_tax = tax[0]
    # informationUri is populated from project/MITRE metadata, never empty.
    assert cwe_tax["informationUri"] == "https://cwe.mitre.org/"
    assert cwe_tax["informationUri"] != ""
    assert cwe_tax["organization"] == "MITRE"


def test_no_empty_string_information_uri_anywhere(tmp_path):
    f = Finding(severity="HIGH", title="t", file="a.py", cvss_score=5.0)
    doc = _write_sarif(tmp_path, [f])

    seen = []

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "informationUri":
                    seen.append(v)
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(doc)
    # Every informationUri that appears must be a non-empty string; the key
    # is omitted rather than emitted as "".
    for uri in seen:
        assert isinstance(uri, str) and uri != ""


def test_driver_has_no_empty_information_uri(tmp_path):
    f = Finding(severity="HIGH", title="t", file="a.py", cvss_score=5.0)
    doc = _write_sarif(tmp_path, [f])
    driver = doc["runs"][0]["tool"]["driver"]
    # The driver carries name+version but intentionally omits informationUri.
    assert "informationUri" not in driver
    # SARIF 2.1.0 driver.name is the plain tool name; the release lives in
    # driver.version (the package version), so name must never embed one.
    assert driver["name"] == "Agentic SAST"
    assert driver["version"]  # non-empty package version


def test_taxonomy_per_cwe_help_uri(tmp_path):
    f = Finding(severity="HIGH", title="ssrf", file="a.py", cwe="CWE-918",
                cvss_score=8.0)
    doc = _write_sarif(tmp_path, [f])
    taxa = doc["runs"][0]["taxonomies"][0]["taxa"]
    assert len(taxa) == 1
    assert taxa[0]["id"] == "CWE-918"
    assert taxa[0]["helpUri"] == (
        "https://cwe.mitre.org/data/definitions/918.html"
    )
    assert taxa[0]["name"] == "Server-Side Request Forgery (SSRF)"


def test_driver_rules_catalog_resolves_every_result_ruleid(tmp_path):
    f1 = Finding(severity="HIGH", title="a", file="a.py",
                 category="sql-injection", cwe="CWE-89", cvss_score=7.0)
    f2 = Finding(severity="LOW", title="b", file="b.py",
                 category="xss", cvss_score=3.0)
    doc = _write_sarif(tmp_path, [f1, f2])
    driver = doc["runs"][0]["tool"]["driver"]
    rule_ids = {r["id"] for r in driver["rules"]}
    result_rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert result_rule_ids and result_rule_ids <= rule_ids   # all resolve
    assert {"sql-injection", "xss"} <= rule_ids
    # CWE name is borrowed as shortDescription where a finding carried a CWE.
    sqli = next(r for r in driver["rules"] if r["id"] == "sql-injection")
    assert sqli["shortDescription"]["text"]

def test_supported_taxonomies_resolves_taxa_by_guid(tmp_path):
    f = Finding(severity="HIGH", title="ssrf", file="a.py", cwe="CWE-918",
                cvss_score=8.0)
    run = _write_sarif(tmp_path, [f])["runs"][0]
    guid = run["taxonomies"][0]["guid"]
    assert run["tool"]["driver"]["supportedTaxonomies"][0]["guid"] == guid
    assert run["results"][0]["taxa"][0]["toolComponent"]["guid"] == guid

def test_sarif_default_has_no_invocations(tmp_path):
    f = Finding(severity="HIGH", title="t", file="a.py", cvss_score=7.0)
    doc = _write_sarif(tmp_path, [f])           # no scan_health
    assert "invocations" not in doc["runs"][0]


def _write_sarif_health(tmp_path, findings, health):
    md = tmp_path / "f.md"
    md.write_text("# x\n", encoding="utf-8")
    out = tmp_path / "o.sarif"
    generate_sarif(str(md), findings, "42", None, str(out), scan_health=health)
    return json.loads(out.read_text(encoding="utf-8"))


def test_sarif_degraded_run_marks_execution_unsuccessful(tmp_path):
    f = Finding(severity="HIGH", title="t", file="a.py", cvss_score=7.0)
    doc = _write_sarif_health(tmp_path, [f], {
        "executionSuccessful": False, "degraded": True,
        "chunks_failed": 2, "errors_by_stage": {"s4": 3}})
    run = doc["runs"][0]
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is False
    texts = " ".join(n["message"]["text"] for n in inv["toolExecutionNotifications"])
    assert "chunk" in texts and "s4" in texts
    assert run["properties"]["scanDegraded"] is True
    assert run["properties"]["unrankedFallback"] is True


def test_sarif_clean_scan_health_marks_success_no_notes(tmp_path):
    f = Finding(severity="HIGH", title="t", file="a.py", cvss_score=7.0)
    doc = _write_sarif_health(tmp_path, [f], {
        "executionSuccessful": True, "degraded": False,
        "chunks_failed": 0, "errors_by_stage": {}})
    inv = doc["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is True
    assert "toolExecutionNotifications" not in inv


# cvssRating / severity / region behavior preserved
def test_cvss_rating_uses_score_when_present(tmp_path):
    f = Finding(severity="HIGH", title="t", file="a.py", cvss_score=9.8)
    res = _only_result(_write_sarif(tmp_path, [f]))
    assert res["properties"]["cvssRating"] == "Critical"
    assert res["properties"]["security-severity"] == "9.8"


def test_cvss_rating_critical_severity_no_score_maps_to_critical(tmp_path):
    f = Finding(severity="CRITICAL", title="crit", file="a.py")
    assert _security_severity(f) == "9.0"
    assert _cvss_rating(f) == "Critical"
    res = _only_result(_write_sarif(tmp_path, [f]))
    assert res["properties"]["cvssRating"] == "Critical"
    assert res["properties"]["security-severity"] == "9.0"
    # severity property carries the raw (lowercased) finding severity verbatim.
    assert res["properties"]["severity"] == "critical"


def test_security_severity_fallback_by_severity(tmp_path):
    cases = {"HIGH": "7.0", "MEDIUM": "4.0", "LOW": "0.1"}
    for sev, expected in cases.items():
        f = Finding(severity=sev, title="t", file="a.py")
        assert _security_severity(f) == expected


def test_sarif_level_mapping(tmp_path):
    f_crit = Finding(severity="CRITICAL", title="c", file="a.py")
    f_high = Finding(severity="HIGH", title="h", file="a.py")
    f_med = Finding(severity="MEDIUM", title="m", file="a.py")
    f_low = Finding(severity="LOW", title="l", file="a.py")
    levels = {
        r["message"]["text"]: r["level"]
        for r in _write_sarif(tmp_path, [f_crit, f_high, f_med, f_low])
        ["runs"][0]["results"]
    }
    assert levels["c"] == "error"
    assert levels["h"] == "error"
    assert levels["m"] == "warning"
    assert levels["l"] == "note"


def test_region_start_line_preserved(tmp_path):
    f = Finding(severity="HIGH", title="t", file="src/app.py", line_no=137,
                cvss_score=7.0)
    res = _only_result(_write_sarif(tmp_path, [f]))
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/app.py"
    assert loc["region"]["startLine"] == 137


def test_region_defaults_uri_when_file_missing(tmp_path):
    f = Finding(severity="LOW", title="t", file=None, line_no=1)
    res = _only_result(_write_sarif(tmp_path, [f]))
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "unknown"
    assert loc["region"]["startLine"] == 1


def test_related_locations_region_endline(tmp_path):
    f = Finding(severity="HIGH", title="t", file="a.py", cvss_score=7.0,
                also_at=[("b.py", 10, 20), ("c.py", 5, 5)])
    res = _only_result(_write_sarif(tmp_path, [f]))
    related = res["relatedLocations"]
    assert len(related) == 2
    r0 = related[0]["physicalLocation"]["region"]
    assert r0 == {"startLine": 10, "endLine": 20}
    # When hi == lo, endLine is omitted.
    r1 = related[1]["physicalLocation"]["region"]
    assert r1 == {"startLine": 5}
    assert res["properties"]["dedupRelatedLocationCount"] == 2


# Redaction applied at the SARIF boundary
def test_redaction_masks_pan_in_description(tmp_path):
    # 4111111111111111 is a canonical public test PAN (passes Luhn + IIN gate).
    pan = "4111111111111111"
    f = Finding(severity="HIGH", title="leak", file="a.py", cvss_score=7.0,
                description=f"Card number {pan} was logged in cleartext.")
    doc = _write_sarif(tmp_path, [f])
    res = _only_result(doc)
    desc = res["properties"]["description"]
    assert pan not in desc
    assert "[REDACTED-PAN]" in desc


def test_redaction_masks_aws_key_in_message(tmp_path):
    # Fake-but-format-valid AWS key. Title flows into the SARIF message text.
    key = "AKIAIOSFODNN7EXAMPLE"
    f = Finding(severity="HIGH", title=f"hardcoded {key}", file="a.py",
                cvss_score=7.0)
    res = _only_result(_write_sarif(tmp_path, [f]))
    raw = json.dumps(res)
    assert key not in raw
    assert "[REDACTED-AWS-KEY]" in res["message"]["text"]


def test_redaction_full_document_has_no_pan(tmp_path):
    pan = "4111111111111111"
    f = Finding(severity="HIGH", title=f"PAN {pan} in code", file="a.py",
                cvss_score=7.0,
                description=f"second occurrence {pan} here")
    out = tmp_path / "out.sarif"
    md = tmp_path / "f.md"
    md.write_text("x\n", encoding="utf-8")
    generate_sarif(str(md), [f], "42", None, str(out))
    text = out.read_text(encoding="utf-8")
    # The raw PAN must not survive anywhere in the on-disk SARIF text.
    assert pan not in text
    assert "[REDACTED-PAN]" in text


def test_redaction_leaves_benign_text_intact(tmp_path):
    f = Finding(severity="LOW", title="benign", file="app/models.py",
                cvss_score=2.0,
                description="Ordinary description with no secrets here.")
    res = _only_result(_write_sarif(tmp_path, [f]))
    assert res["properties"]["description"] == (
        "Ordinary description with no secrets here."
    )


# Run-level properties + md_to_sarif end-to-end
def test_run_properties_application_id(tmp_path):
    f = Finding(severity="HIGH", title="t", file="a.py", cvss_score=7.0)
    doc = _write_sarif(tmp_path, [f], app_id="007")
    props = doc["runs"][0]["properties"]
    assert props["applicationId"] == "007"
    # No app → cmdbSource / applicationName must be absent (not empty-string).
    assert "cmdbSource" not in props
    assert "applicationName" not in props


def test_run_properties_with_appinfo(tmp_path):
    app = enrich.AppInfo(id="42", name="Example App", source="application")
    f = Finding(severity="HIGH", title="t", file="a.py", cvss_score=7.0)
    doc = _write_sarif(tmp_path, [f], app_id="42", app=app)
    props = doc["runs"][0]["properties"]
    assert props["applicationName"] == "Example App"
    assert props["cmdbSource"] == "application"


def test_md_to_sarif_parses_and_emits(tmp_path, capsys):
    md = tmp_path / "report.md"
    md.write_text(
        "## [HIGH] SQL Injection in login\n"
        "`auth/login.py:42` · sql-injection · confidence 0.95\n"
        "**CWE:** CWE-89\n"
        "**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`\n"
        "\nSome description text.\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.sarif"
    findings = md_to_sarif(str(md), "42", None, str(out))
    assert len(findings) == 1
    fnd = findings[0]
    assert fnd.cwe == "CWE-89"
    assert fnd.cvss_score > 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    res = _only_result(doc)
    assert res["ruleId"] == "sql-injection"
    assert res["properties"]["cweId"] == "CWE-89"
    # rank present and scaled into 0..100.
    assert 0.0 <= res["rank"] <= 100.0
    assert res["rank"] == pytest.approx(fnd.cvss_score * 10.0, abs=0.05)


def test_sarif_backfills_cwe_from_category_when_token_absent(tmp_path):
    # No CWE token, but category=use-after-free → deterministic CWE-416 in
    # props.cweId, result.taxa, and the run-level CWE taxonomy.
    f = Finding(severity="HIGH", title="UAF", file="a.py", line_no=5,
                category="use-after-free", cvss_score=7.0)
    doc = _write_sarif(tmp_path, [f])
    res = _only_result(doc)
    assert res["properties"]["cweId"] == "CWE-416"
    assert res["taxa"][0]["id"] == "CWE-416"
    tax_ids = {t["id"] for t in doc["runs"][0]["taxonomies"][0]["taxa"]}
    assert "CWE-416" in tax_ids


def test_sarif_other_category_emits_no_cwe(tmp_path):
    # category=other maps to no CWE → no cweId, no taxa, no taxonomy entries.
    f = Finding(severity="LOW", title="misc", file="a.py", line_no=1,
                category="other", cvss_score=2.0)
    doc = _write_sarif(tmp_path, [f])
    res = _only_result(doc)
    assert "cweId" not in res["properties"]
    assert "taxa" not in res
    assert doc["runs"][0]["taxonomies"][0]["taxa"] == []


def test_md_to_sarif_schema_and_version(tmp_path):
    md = tmp_path / "r.md"
    md.write_text("## [LOW] nothing\n`x.py:1` · misc · confidence 0.5\n",
                  encoding="utf-8")
    out = tmp_path / "r.sarif"
    md_to_sarif(str(md), None, None, str(out))
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    # app_id None → empty applicationId string (explicit, documented behavior).
    assert doc["runs"][0]["properties"]["applicationId"] == ""


# ---------------------------------------------------------------------------
# ALT_FILE_LINE: the pipeline's `**File:** \`path:start-end\`` location line
# ---------------------------------------------------------------------------
def test_alt_file_line_parses_benign_pipeline_location():
    m = enrich.ALT_FILE_LINE.match("**File:** `app/svc.py:134-140`")
    assert m is not None
    assert m.group(1) == "app/svc.py"
    assert m.group(2) == "134"


def test_alt_file_line_recovers_full_path_after_backtick_folding(tmp_path):
    # A hostile filename with a backtick is folded to the U+02CB lookalike by
    # models.FinalReport.to_markdown before it reaches this line; the regex
    # must recover the FULL folded path — a raw backtick would truncate the
    # SARIF artifactLocation.uri at the break-out point.
    m = enrich.ALT_FILE_LINE.match("**File:** `weirdˋfile.py:10-10`")
    assert m is not None
    assert m.group(1) == "weirdˋfile.py"
    assert m.group(2) == "10"
    # End-to-end: md_to_sarif carries the folded path into the SARIF uri.
    md = tmp_path / "r.md"
    md.write_text(
        "### 1. [HIGH] hostile name\n"
        "**File:** `weirdˋfile.py:10-10`\n"
        "**Class:** injection\n",
        encoding="utf-8",
    )
    out = tmp_path / "r.sarif"
    md_to_sarif(str(md), None, None, str(out))
    doc = json.loads(out.read_text(encoding="utf-8"))
    res = _only_result(doc)
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "weirdˋfile.py"
