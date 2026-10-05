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

"""Exploit Verification surfacing — Finding fields and the Markdown render.

The Markdown report is the ONLY place a verification result surfaces. SARIF results
deliberately carry no verification entry, for either verifier — see
:func:`test_sarif_carries_no_verification_entry`.
"""
from __future__ import annotations

import json
import re

import pytest

from vvaharness.models import (FinalReport, Finding, RankedFinding, Severity,
                               VulnClass)
from vvaharness.report import enrich


def _finding(**kw):
    base = dict(chunk_id="c1", file="app.py", line_start=29, line_end=32,
                vuln_class=VulnClass.INJECTION, title="SQL injection in id",
                description="desc", code_snippet="x", confidence=1.0, cwe="CWE-89")
    base.update(kw)
    return Finding(**base)


def _report(f):
    return FinalReport(repo_root="/r", repo_name="t",
                       findings=[RankedFinding(finding=f, severity=Severity.CRITICAL,
                                               exploitability_notes="n")],
                       chains=[], dropped=[], summary="s", raw_findings_count=1)


# ── Finding schema round-trip (checkpoint-safety) ────────────────────────────

def test_ev_fields_survive_model_dump_round_trip():
    f = _finding(ev_status="CONFIRMED", ev_evidence="e", ev_repro="r",
                 ev_method="deterministic-backed", ev_confidence="high",
                 ev_cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 ev_cvss_score=9.8, ev_cvss_rating="Critical")
    f2 = Finding(**f.model_dump())
    assert (f2.ev_status, f2.ev_evidence, f2.ev_repro) == ("CONFIRMED", "e", "r")
    assert (f2.ev_method, f2.ev_confidence) == ("deterministic-backed", "high")
    assert (f2.ev_cvss_score, f2.ev_cvss_rating) == (9.8, "Critical")
    assert f2.ev_cvss_vector.startswith("CVSS:3.1")


def test_ev_fields_default_when_absent():
    f = Finding(**{k: v for k, v in _finding().model_dump().items()
                   if not k.startswith("ev_")})   # old checkpoint w/o ev_*
    assert f.ev_status is None and f.ev_evidence == "" and f.ev_repro == ""


# ── Markdown rendering ───────────────────────────────────────────────────────

def test_confirmed_renders_exploit_verified_line():
    f = _finding(ev_status="CONFIRMED", ev_evidence="SQL error via `id`",
                 ev_repro="GET /user [id]", verdict="TRUE_POSITIVE",
                 verdict_confidence=10, verdict_reason="exploit-verified live (sqli)")
    md = _report(f).to_markdown()
    assert "#### Exploit Verification" in md
    assert "**Exploit Verification:** CONFIRMED (beta)" in md   # the carrier line, own section
    assert "SQL error via" in md and "GET /user" in md


def test_no_stamp_when_not_confirmed():
    f = _finding(verdict="TRUE_POSITIVE", verdict_confidence=8,
                 verdict_reason="static", verifier_reasoning="traced")
    md = _report(f).to_markdown()
    assert "Exploit Verification" not in md               # EV never ran on this finding
    assert "#### Adversarial verification" in md         # static verdict still renders


def test_ev_evidence_markdown_headings_neutralized():
    f = _finding(ev_status="CONFIRMED", ev_evidence="ok\n## Injected Heading")
    md = _report(f).to_markdown()
    assert "## Injected Heading" not in md               # demoted to bold, not a heading


# ── SARIF carries no verification entry, by design ───────────────────────────
#
# Neither verifier gets a SARIF key: the static verdict has no property either (the
# builder never sees `verdict`/`verifier_reasoning`), so a dedicated EV block would make
# a live confirmation look like the more authoritative of the two — the reverse of how
# they actually rank, since static owns the verdict. Both live in the Markdown report,
# which is where a reader compares them side by side.
#
# Pinned as a test because the properties are easy to re-add in good faith.

# Matched by shape rather than by one literal name: a key added as `evStatus` or
# `liveVerdict` is the same defect as `exploitVerified`, and a single-prefix check would let
# it through. Narrow enough that nothing the SARIF writer legitimately emits matches —
# notably `confidence`, which is the finding's own static confidence and unrelated.
_VERIFICATION_KEY_RX = re.compile(r"verif|verdict|exploit|livetest", re.IGNORECASE)


def _verification_keys(props):
    """The keys in `props` that read as a verification result, under any plausible name."""
    return sorted(k for k in props
                  # `ev`-prefixed, matched case-sensitively so `event…` does not trip it
                  if _VERIFICATION_KEY_RX.search(k) or re.match(r"ev(?=[A-Z_])", k))


def test_verification_key_matcher_catches_the_names_it_guards():
    """The guard is a pattern, so pin both halves of it: a matcher that silently matched
    nothing would report a clean SARIF whatever the writer had emitted."""
    caught = ["exploitVerified", "exploitVerification", "evStatus", "ev_status",
              "evCvssScore", "liveTested", "verificationStatus", "verifiedLive", "verdict"]
    assert _verification_keys(dict.fromkeys(caught, 1)) == sorted(caught)
    legit = ["cwe", "cweId", "cweName", "cvssScore", "confidence", "votes", "description",
             "vulContextSeverityScore", "offensivePriorityReason",
             "dedupRelatedLocationCount"]
    assert _verification_keys(dict.fromkeys(legit, 1)) == []


def test_sarif_carries_no_verification_entry(tmp_path):
    """Even a fully-populated CONFIRMED finding adds no EV entry to SARIF."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    f = _finding(ev_status="CONFIRMED", ev_evidence="path marker root: found",
                 ev_repro="GET /read [path]", ev_method="deterministic-backed",
                 ev_confidence="high", ev_cvss_vector=vector, ev_cvss_score=9.8,
                 ev_cvss_rating="Critical", verdict="TRUE_POSITIVE",
                 verdict_confidence=10, verdict_reason="exploit-verified live (path)",
                 cvss_score=7.5, cvss_rating="High")
    md_file = tmp_path / "r.md"
    md_file.write_text(_report(f).to_markdown(), encoding="utf-8")
    sarif_file = tmp_path / "r.sarif"
    enrich.md_to_sarif(str(md_file), "app1", None, str(sarif_file))

    result = json.loads(sarif_file.read_text())["runs"][0]["results"][0]
    leaked = _verification_keys(result["properties"])
    assert leaked == [], f"verification entry leaked into SARIF properties: {leaked}"
    # and static's verdict has no key of its own either — the symmetry this rests on
    assert "verdict" not in result["properties"]


def test_md_carries_the_tier():
    """The method + confidence tier renders on its own line, so a reader can tell a
    tell-backed confirmation from one reached on reasoning alone."""
    f = _finding(ev_status="CONFIRMED", ev_evidence="SQL error via `id`",
                 ev_repro="GET /user [id]", ev_method="agent-judged", ev_confidence="medium",
                 verdict="TRUE_POSITIVE", verdict_confidence=9)
    md = _report(f).to_markdown()
    assert "**EV Method:** agent-judged (medium)" in md
    assert "SQL error via" in md                     # evidence rides along, unmangled


def test_ev_cvss_renders_on_its_own_line():
    """EV's advisory CVSS is rendered separately from static's authoritative score, so
    the two are never mistaken for one number."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    f = _finding(ev_status="CONFIRMED", ev_evidence="SQL error via `id`",
                 ev_repro="GET /user [id]", ev_method="deterministic-backed",
                 ev_confidence="high", ev_cvss_vector=vector, ev_cvss_score=9.8,
                 ev_cvss_rating="Critical", verdict="TRUE_POSITIVE", verdict_confidence=9,
                 cvss_score=7.5, cvss_rating="High")
    md = _report(f).to_markdown()
    assert "**EV CVSS:** 9.8 (Critical)" in md
    assert vector in md


# ── replayable repro block (curl + captured response) ────────────────────────

_LEAK = "SECRET-INTERNAL-REPO"


def _repro_detail(**kw):
    from vvaharness.exploit_verification.verify.model import ReproDetail
    base = dict(method="GET", url="http://127.0.0.1:8000/api/orders",
                authed=False, resp_status=200,
                resp_headers={"content-type": "application/json"},
                resp_body=f'[{{"repo":"{_LEAK}"}}]', elapsed=0.012)
    base.update(kw)
    return ReproDetail(**base).model_dump()


def _confirmed_with_repro(**kw):
    return _finding(ev_status="CONFIRMED", ev_evidence="endpoint returned 200 without creds",
                    ev_repro="GET http://127.0.0.1:8000/api/orders (unauthenticated)",
                    ev_method="deterministic", ev_confidence="high",
                    ev_repro_detail=_repro_detail(), verdict="TRUE_POSITIVE",
                    verdict_confidence=10, cvss_score=7.5, cvss_rating="High", **kw)


def test_repro_detail_survives_model_dump_round_trip():
    f = _confirmed_with_repro()
    assert Finding(**f.model_dump()).ev_repro_detail["url"].endswith("/api/orders")


def test_repro_detail_defaults_empty_for_old_checkpoints():
    f = Finding(**{k: v for k, v in _finding().model_dump().items()
                   if k != "ev_repro_detail"})
    assert f.ev_repro_detail == {}


def test_markdown_renders_curl_and_response():
    """The Markdown report is the only place a verification result surfaces, so the
    replayable curl, the request line and the observed response all have to be here."""
    md = _report(_confirmed_with_repro()).to_markdown()
    assert "**Curl:** `curl -i -X GET " in md
    assert "**Repro:** " in md and "127.0.0.1:8000" in md
    assert "<details><summary>Replay this request</summary>" in md
    assert "Response: `200`" in md


def test_no_repro_block_without_detail():
    f = _finding(ev_status="CONFIRMED", ev_evidence="e", ev_repro="GET /u")
    md = _report(f).to_markdown()
    assert "**Repro:**" in md and "<details>" not in md      # one-liner still carries it


def test_repro_block_does_not_leak_into_sarif_description(tmp_path):
    """Regression: the MD parser folds unmatched lines into `description`, so an
    un-skipped <details> block would push the captured response body — real target
    data — into every EV finding's SARIF description."""
    md_file = tmp_path / "r.md"
    md_file.write_text(_report(_confirmed_with_repro()).to_markdown(), encoding="utf-8")
    sarif_file = tmp_path / "r.sarif"
    enrich.md_to_sarif(str(md_file), "app1", None, str(sarif_file))
    desc = json.loads(sarif_file.read_text())["runs"][0]["results"][0]["properties"]["description"]
    for leaked in (_LEAK, "curl -i", "<details>", "Replay this request", "Response: `200`"):
        assert leaked not in desc, f"{leaked!r} leaked into the SARIF description"


def test_findings_after_a_repro_block_still_parse(tmp_path):
    """The <details> skip must not swallow the rest of the report."""
    first = _confirmed_with_repro()
    second = _finding(title="Second finding", verdict="TRUE_POSITIVE", verdict_confidence=8)
    report = FinalReport(
        repo_root="/r", repo_name="t",
        findings=[RankedFinding(finding=first, severity=Severity.CRITICAL,
                                exploitability_notes="n"),
                  RankedFinding(finding=second, severity=Severity.HIGH,
                                exploitability_notes="n")],
        chains=[], dropped=[], summary="s", raw_findings_count=2)
    md_file = tmp_path / "r.md"
    md_file.write_text(report.to_markdown(), encoding="utf-8")
    sarif_file = tmp_path / "r.sarif"
    enrich.md_to_sarif(str(md_file), "app1", None, str(sarif_file))
    results = json.loads(sarif_file.read_text())["runs"][0]["results"]
    assert len(results) == 2
    assert results[1]["message"]["text"].startswith("Second finding")


def test_response_body_cannot_truncate_or_inject_findings(tmp_path):
    """A captured response body lands verbatim inside the <details> block, so a hostile
    target could echo lines shaped like a section boundary (truncating every later
    finding) or a finding header (injecting a fake one). The parser must skip the block
    before either check runs, and an inline closing tag must not end it early."""
    hostile = "\n".join([
        "</details> echoed inline, must not close the block",
        "[INFO] Planted finding from the response body",
        "## Appendix",
    ])
    first = _confirmed_with_repro().model_copy(
        update={"ev_repro_detail": _repro_detail(resp_body=hostile)})
    second = _finding(title="Second finding", verdict="TRUE_POSITIVE", verdict_confidence=8)
    report = FinalReport(
        repo_root="/r", repo_name="t",
        findings=[RankedFinding(finding=first, severity=Severity.CRITICAL,
                                exploitability_notes="n"),
                  RankedFinding(finding=second, severity=Severity.HIGH,
                                exploitability_notes="n")],
        chains=[], dropped=[], summary="s", raw_findings_count=2)
    md_file = tmp_path / "r.md"
    md_file.write_text(report.to_markdown(), encoding="utf-8")
    parsed = enrich.parse_findings(str(md_file), None)
    # nothing injected, nothing truncated — the target's bytes control neither
    assert [f.title for f in parsed] == ["SQL injection in id", "Second finding"]


@pytest.mark.parametrize("first_line", ["</details>", "  </details>  ",
                                        "<details><summary>Replay this request</summary>"])
def test_a_bare_repro_tag_from_the_target_cannot_close_or_reopen_the_block(tmp_path, first_line):
    """The case the inline test above does NOT cover: a tag on a line of its own, which
    would end the skip early and let the target delete later findings from the SARIF and
    inject its own. Whitespace variants included because the parser strips before
    comparing."""
    hostile = "\n".join([
        first_line,
        "### 9. [CRITICAL] Planted finding from the response body",
        "**File:** `app/auth.py`",
        "## Appendix",
    ])
    first = _confirmed_with_repro().model_copy(
        update={"ev_repro_detail": _repro_detail(resp_body=hostile)})
    second = _finding(title="Second finding", verdict="TRUE_POSITIVE", verdict_confidence=8)
    report = FinalReport(
        repo_root="/r", repo_name="t",
        findings=[RankedFinding(finding=first, severity=Severity.CRITICAL,
                                exploitability_notes="n"),
                  RankedFinding(finding=second, severity=Severity.HIGH,
                                exploitability_notes="n")],
        chains=[], dropped=[], summary="s", raw_findings_count=2)
    md_file = tmp_path / "r.md"
    md_file.write_text(report.to_markdown(), encoding="utf-8")
    titles = [f.title for f in enrich.parse_findings(str(md_file), None)]
    assert titles == ["SQL injection in id", "Second finding"], (
        f"target bytes reached the parser as structure: {titles}")


def test_code_snippet_quoting_details_does_not_open_the_repro_skip(tmp_path):
    """A rendered `code_snippet` is emitted raw inside a fence, so a snippet that merely
    QUOTES a <details> element must not open the repro skip. It did while the opener was
    a substring test: the skip then ran to a closer the producer never wrote and every
    later finding vanished from the SARIF. Note this needs no EV and no hostile target —
    an XSS finding on that markup is the likeliest way to render such a snippet at all."""
    first = _finding(code_snippet="<details><summary>toggle</summary>Bio</details>")
    second = _finding(title="Second finding", verdict="TRUE_POSITIVE", verdict_confidence=8)
    report = FinalReport(
        repo_root="/r", repo_name="t",
        findings=[RankedFinding(finding=first, severity=Severity.CRITICAL,
                                exploitability_notes="n"),
                  RankedFinding(finding=second, severity=Severity.HIGH,
                                exploitability_notes="n")],
        chains=[], dropped=[], summary="s", raw_findings_count=2)
    md_file = tmp_path / "r.md"
    md_file.write_text(report.to_markdown(), encoding="utf-8")
    assert [f.title for f in enrich.parse_findings(str(md_file), None)] == [
        "SQL injection in id", "Second finding"]


def test_parser_repro_tags_match_what_the_producer_emits():
    """`enrich` keeps the repro block's tags as literals rather than importing them from
    exploit_verification, so the report parser stays independent of the EV package. That
    decoupling is only safe while the two agree: pin it here, because the skip is now an
    exact match and a reworded <summary> would silently stop skipping — folding captured
    target bytes back into every EV finding's SARIF description."""
    from vvaharness.exploit_verification.verify import repro
    from vvaharness.exploit_verification.verify.model import ReproDetail

    emitted = [ln.strip() for ln in repro.render_block(ReproDetail(**_repro_detail()))]
    assert enrich.EV_REPRO_OPEN in emitted, (
        "the producer no longer emits the exact line enrich.py skips on")
    assert enrich.EV_REPRO_CLOSE in emitted


# ── non-confirming verdicts are surfaced too (visibility, not just proof) ─────
#
# Every finding EV live-tested gets a verdict block — CONFIRMED and the non-confirming
# outcomes alike — so the report shows what EV tried, not only what it proved. The three
# non-confirming outcomes render the label, a `Why:` line carrying the reason and a tag for
# what authored it, and the standing note that the finding is still judged statically;
# method/CVSS/repro describe HOW something confirmed, so they appear for CONFIRMED only.
# Only ev_status None (EV did not run this scan) renders no block.
#
# The labels a reader sees are NOT the wire values: "INCONCLUSIVE" and "NOT TESTED" read as
# verdicts on the finding, so they render as REQUIRES REVIEW and SAST-ONLY while ev_status
# keeps its own vocabulary — see test_rendered_label_parses_back_to_the_wire_status.

def test_not_confirmed_renders_verdict_reason_and_note():
    f = _finding(ev_status="NOT_CONFIRMED", ev_reason_source="judge",
                 ev_evidence="the payload came back HTML-escaped in every response",
                 verdict="TRUE_POSITIVE", verdict_confidence=8)
    md = _report(f).to_markdown()
    assert "#### Exploit Verification" in md
    assert "**Exploit Verification:** NOT CONFIRMED (beta)" in md
    assert "**Why:** [judge] the payload came back HTML-escaped" in md
    assert "_Not a false positive:" in md
    # HOW-confirmed lines belong to a CONFIRMED verdict only
    assert "**EV Method:**" not in md and "**EV CVSS:**" not in md and "**Repro:**" not in md


def test_inconclusive_renders_as_requires_review():
    f = _finding(ev_status="INCONCLUSIVE", ev_reason_source="judge",
                 ev_evidence="the described behaviour was reproduced, but the claimed "
                             "consequence was not shown in any response",
                 verdict="TRUE_POSITIVE", verdict_confidence=7)
    md = _report(f).to_markdown()
    assert "**Exploit Verification:** REQUIRES REVIEW (beta)" in md
    # the word itself is what invites a reader to dismiss the static finding
    assert "INCONCLUSIVE" not in md
    assert "**Why:** [judge] the described behaviour was reproduced" in md
    assert "**EV Method:**" not in md and "**EV CVSS:**" not in md


def test_not_tested_renders_as_sast_only_with_its_rule_reason():
    f = _finding(ev_status="NOT_TESTED", ev_reason_source="rule",
                 ev_evidence="no endpoint in the supplied API collection maps to it",
                 verdict="TRUE_POSITIVE", verdict_confidence=8)
    md = _report(f).to_markdown()
    assert "#### Exploit Verification" in md
    assert "**Exploit Verification:** SAST-ONLY (beta; not live-testable)" in md
    assert "NOT TESTED" not in md
    assert "**Why:** [rule] no endpoint in the supplied API collection" in md
    # not a confirmation, so no HOW-confirmed detail
    assert "**EV Method:**" not in md and "**EV CVSS:**" not in md and "**Repro:**" not in md


def test_triage_reason_is_tagged_as_the_classifiers():
    """A model's one-clause reason and a deterministic routing fact read alike as bare
    prose, and are not worth the same; the tag is what tells them apart."""
    f = _finding(ev_status="NOT_TESTED", ev_reason_source="triage",
                 ev_evidence="the sink is an off-wire log write, so no request reaches it",
                 verdict="TRUE_POSITIVE", verdict_confidence=8)
    md = _report(f).to_markdown()
    assert "**Why:** [triage] the sink is an off-wire log write" in md


def test_untagged_reason_still_renders():
    """A finding restored from a checkpoint written before provenance existed carries no
    source; the reason must still render, just without a tag."""
    f = _finding(ev_status="INCONCLUSIVE", ev_evidence="every response was a 502",
                 verdict="TRUE_POSITIVE", verdict_confidence=8)
    md = _report(f).to_markdown()
    assert "**Why:** every response was a 502" in md
    assert "[rule]" not in md and "[judge]" not in md and "[triage]" not in md


def test_not_tested_without_a_reason_renders_bare_verdict():
    f = _finding(ev_status="NOT_TESTED", ev_evidence="",
                 verdict="TRUE_POSITIVE", verdict_confidence=8)
    md = _report(f).to_markdown()
    assert "**Exploit Verification:** SAST-ONLY (beta; not live-testable)" in md
    assert "**Why:**" not in md               # no empty Why line when there is no reason
    assert "_Not a false positive:" in md     # the standing note does not depend on one


def test_why_line_and_note_do_not_leak_into_sarif(tmp_path):
    """The MD parser folds unmatched lines into `description`, so the two lines now sitting
    below the verdict have to be recognised or they pollute every non-confirmed finding."""
    f = _finding(ev_status="INCONCLUSIVE", ev_reason_source="judge",
                 ev_evidence="nothing in the responses rules out the innocent reading",
                 verdict="TRUE_POSITIVE", verdict_confidence=8)
    md_file = tmp_path / "r.md"
    md_file.write_text(_report(f).to_markdown(), encoding="utf-8")
    sarif_file = tmp_path / "r.sarif"
    enrich.md_to_sarif(str(md_file), "app1", None, str(sarif_file))
    desc = json.loads(sarif_file.read_text())["runs"][0]["results"][0]["properties"]["description"]
    for leaked in ("REQUIRES REVIEW", "**Why:**", "Not a false positive",
                   "nothing in the responses rules out"):
        assert leaked not in desc, f"{leaked!r} leaked into the SARIF description"


def test_rendered_label_parses_back_to_the_wire_status():
    """The report renames two outcomes for the reader; a consumer keyed on `ev_status`
    must still see the wire vocabulary, and an older report must still parse."""
    for label, wire in (("SAST-ONLY (beta; not live-testable)", "NOT_TESTED"),
                        ("REQUIRES REVIEW (beta)", "INCONCLUSIVE"),
                        ("SAST-ONLY (not live-testable)", "NOT_TESTED"),
                        ("REQUIRES REVIEW", "INCONCLUSIVE"),
                        ("NOT TESTED — r", "NOT_TESTED"),         # retired spellings
                        ("INCONCLUSIVE — r", "INCONCLUSIVE")):
        m = enrich.EV_LINE.search(f"**Exploit Verification:** {label}")
        assert m, label
        assert enrich.EV_LABEL_TO_STATUS[m.group(1).upper()] == wire, label


def test_ev_confidence_renders_on_every_live_tested_outcome():
    """EV's 0-10 confidence rides on CONFIRMED and the non-confirming outcomes alike, on its
    own `**EV Confidence:**` line."""
    for status, score in (("CONFIRMED", 9), ("NOT_CONFIRMED", 7), ("INCONCLUSIVE", 4)):
        f = _finding(ev_status=status, ev_evidence="e", ev_reason_source="judge",
                     ev_confidence_score=score, verdict="TRUE_POSITIVE", verdict_confidence=8)
        md = _report(f).to_markdown()
        assert f"**EV Confidence:** {score}/10" in md, status


def test_not_tested_carries_no_ev_confidence():
    """A finding EV never live-tested has no reproduction confidence to report."""
    f = _finding(ev_status="NOT_TESTED", ev_reason_source="rule", ev_evidence="no endpoint",
                 ev_confidence_score=None, verdict="TRUE_POSITIVE", verdict_confidence=8)
    md = _report(f).to_markdown()
    assert "**EV Confidence:**" not in md


def test_ev_confidence_does_not_collide_with_static_confidence(tmp_path):
    """Regression: the finding's own static confidence renders as `**Confidence:**` and EV's
    as `**EV Confidence:**`. The `EV ` prefix must keep EV's 0-10 off the static
    CONFIDENCE_LINE parser — otherwise EV's `9/10` is read as the static confidence `9.0`
    and the real static confidence is lost. It must also stay out of the SARIF description."""
    f = _finding(ev_status="CONFIRMED", ev_evidence="marker reflected",
                 ev_method="deterministic-backed", ev_confidence="high",
                 ev_confidence_score=9, confidence=0.87, votes=3,
                 verdict="TRUE_POSITIVE", verdict_confidence=8)
    md_file = tmp_path / "r.md"
    md_file.write_text(_report(f).to_markdown(), encoding="utf-8")
    # both labels present and distinct
    body = md_file.read_text(encoding="utf-8")
    assert "**Confidence:** 0.87" in body and "**EV Confidence:** 9/10" in body
    # the parser keeps them apart — static confidence intact, EV confidence captured
    parsed = enrich.parse_findings(str(md_file), None)[0]
    assert parsed.confidence == 0.87 and parsed.ev_confidence_score == 9
    # and neither EV line pollutes the SARIF description
    sarif_file = tmp_path / "r.sarif"
    enrich.md_to_sarif(str(md_file), "app1", None, str(sarif_file))
    desc = json.loads(sarif_file.read_text())["runs"][0]["results"][0]["properties"]["description"]
    assert "EV Confidence" not in desc


def test_verification_summary_counts_the_live_tested():
    findings = [
        _finding(title="a", ev_status="CONFIRMED", ev_evidence="e"),
        _finding(title="b", ev_status="NOT_CONFIRMED", ev_evidence="e"),
        _finding(title="c", ev_status="INCONCLUSIVE", ev_evidence="e"),
        _finding(title="d", ev_status="NOT_TESTED", ev_evidence="e"),   # excluded
        _finding(title="e"),                                            # EV did not run
    ]
    report = FinalReport(
        repo_root="/r", repo_name="t", chains=[], dropped=[], summary="s",
        raw_findings_count=5,
        findings=[RankedFinding(finding=f, severity=Severity.HIGH, exploitability_notes="n")
                  for f in findings])
    md = report.to_markdown()
    assert ("- Exploit verification: 1 confirmed live, 1 not confirmed, "
            "1 requiring review (3 live-tested)") in md
    assert "additive and positive-only" in md


def test_no_summary_line_when_ev_did_not_run():
    f = _finding(verdict="TRUE_POSITIVE", verdict_confidence=8)   # ev_status None
    md = _report(f).to_markdown()
    assert "Exploit verification:" not in md
