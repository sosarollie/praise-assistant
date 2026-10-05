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

"""remediation_agent.report_parser.fields — rich per-finding field extraction."""
from __future__ import annotations

import re
from typing import Literal, cast, get_args

from vvaharness.remediation_agent.report_parser.field_sections import (
    _CLASS_RE,
    _CONF_RE,
    _CVSS_SCORE_RE,
    _CVSS_VECONLY_RE,
    _CWE_RE,
    _SINK_RE,
    _SOURCE_RE,
    _VERDICT_RE,
    _file_loc,
    _first_code_block,
    _sections,
)
from vvaharness.models import Finding as ScanFinding
from vvaharness.models import Severity, VulnClass
from vvaharness.remediation_agent.report_parser.finding import Finding

# The only two verdict labels the scan contract admits; typed as the Literal so a third label added here fails type-checking.
_VerdictLabel = Literal["TRUE_POSITIVE", "FALSE_POSITIVE"]
_VERDICT_LABELS: frozenset[str] = frozenset(get_args(_VerdictLabel))

# What the codebase means by "no opinion" — plain 0.0 would read as actively distrusted, not "the report did not say".
_NO_OPINION_CONFIDENCE = 0.5


def to_scan_finding(finding: Finding) -> ScanFinding:
    """Promote a markdown-parsed finding onto the typed scan contract; the only markdown-to-typed step left."""
    f = parse_finding_fields(finding)
    vuln_class = VulnClass(f["vuln_class"])
    return ScanFinding(
        title=f["title"],
        file=f["file"],
        line_start=f["line_start"],
        line_end=f["line_end"],
        vuln_class=vuln_class,
        vuln_class_label=f["vuln_class"] if vuln_class is VulnClass.OTHER else "",
        severity=_severity(finding.severity),
        cwe=f["cwe"],
        description=f["description"],
        recommendation=f["recommendation"],
        code_snippet=f["code_snippet"],
        impact=f["impact"],
        exploit_scenario=f["exploit_scenario"],
        preconditions=f["preconditions"],
        confidence=f["confidence"] or _NO_OPINION_CONFIDENCE,
        votes=f["votes"] or 1,
        source_ref=f["source_ref"],
        sink_ref=f["sink_ref"],
        verdict=_verdict_label(f["verdict"]),
        verdict_confidence=f["verdict_confidence"],
        verdict_reason=f["verdict_reason"],
        verifier_reasoning=f["verifier_reasoning"],
        cvss_vector=f["cvss_vector"],
        cvss_score=f["cvss_score"],
        cvss_rating=f["cvss_rating"],
    )


def _severity(label: str | None) -> Severity:
    """Fold the report's severity band, defaulting to MEDIUM on a label we do not know."""
    try:
        return Severity(label or "medium")
    except ValueError:
        return Severity.MEDIUM


def _verdict_label(value: str | None) -> _VerdictLabel | None:
    """Keep the verifier verdict only when it is one the contract admits."""
    return cast("_VerdictLabel", value) if value in _VERDICT_LABELS else None


def parse_finding_fields(finding: Finding) -> dict:
    """Extract the verbatim Finding fields from a finding's markdown ``body`` into a dict, degrading missing fields to safe empty defaults."""
    body = finding.body or ""
    secs = _sections(body)
    head = secs.get("", "")

    vuln_class = ""
    cwe = None
    file_ref = finding.file or ""
    file_path, line_start, line_end = _file_loc(file_ref) if file_ref else ("", 0, 0)
    confidence = 0.0
    votes = 0
    cvss_vector = cvss_rating = None
    cvss_score = None
    verdict = None
    verdict_confidence = None
    source_ref = sink_ref = None

    for line in head.splitlines():
        line = line.strip()
        if (m := _CLASS_RE.match(line)):
            vuln_class = m.group(1).strip()
        elif (m := _CWE_RE.match(line)):
            cwe = m.group(1).strip()
        elif (m := _CONF_RE.match(line)):
            confidence = float(m.group(1))
            votes = int(m.group(2))
        elif (m := _CVSS_SCORE_RE.match(line)):
            cvss_score = float(m.group(1))
            cvss_rating = m.group(2).strip()
            cvss_vector = m.group(3).strip()
        elif (m := _CVSS_VECONLY_RE.match(line)):
            cvss_vector = m.group(1).strip()
        elif (m := _SOURCE_RE.match(line)):
            source_ref = m.group(1).strip()
        elif (m := _SINK_RE.match(line)):
            sink_ref = m.group(1).strip()

    # `**Class:**` may itself carry the CWE (e.g. "CWE-89: SQL Injection") when no dedicated `**CWE:**` line was rendered.
    if cwe is None and vuln_class:
        cm = re.match(r"(CWE-\d+)", vuln_class)
        if cm:
            cwe = cm.group(1)

    # The adversarial-verification block carries the verdict, its reason, and the verifier's full reasoning.
    verdict, verdict_confidence, verdict_reason, verifier_reasoning = _verification(
        secs.get("adversarial verification", ""))

    preconds = [
        re.sub(r"^[-*]\s+", "", ln).strip()
        for ln in secs.get("preconditions", "").splitlines()
        if ln.strip().startswith(("-", "*"))
    ]

    return {
        "_source": "vvaharness s8 (verbatim Finding fields)",
        "title": finding.title,
        "vuln_class": vuln_class,
        "cwe": cwe,
        "file": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "source_ref": source_ref,
        "sink_ref": sink_ref,
        "description": secs.get("description", ""),
        "recommendation": secs.get("how to fix", ""),
        "code_snippet": _first_code_block(body),
        "impact": secs.get("impact", ""),
        "exploit_scenario": secs.get("exploit scenario", ""),
        "preconditions": preconds,
        "confidence": confidence,
        "votes": votes,
        "verdict": verdict,
        "verdict_confidence": verdict_confidence,
        "verdict_reason": verdict_reason,
        "verifier_reasoning": verifier_reasoning,
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
        "cvss_rating": cvss_rating,
    }


def _verification(section: str) -> tuple[str | None, int | None, str, str]:
    """Split the adversarial-verification block into verdict, confidence, reason, reasoning."""
    for i, line in enumerate(section.splitlines()):
        vm = _VERDICT_RE.match(line.strip())
        if vm:
            reasoning = "\n".join(section.splitlines()[i + 1:]).strip()
            return (vm.group(1).strip(), int(vm.group(2)),
                    vm.group(3).strip(), reasoning)
    return None, None, "", ""

