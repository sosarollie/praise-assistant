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

"""Unit tests for the deterministic dedup helpers in s7_dedup.

Covers overlapping/nested same-file range merging, the "additional call site"
attachment (disjoint-only, so an overlapping re-detection is not counted as a
new site), de-duplication of the collapsed-location set, the parse-miss
telemetry of the semantic pass (loud fail-open), and the required-ctx
precondition. Pure functions plus the faked deepagents route.
"""
import json

import pytest

from vvaharness.models import ContextPackage, Finding, VulnClass
from vvaharness.pipeline.stages import s7_dedup
from vvaharness.util.counters import COUNTERS


def _f(file: str, ls: int, le: int, vc: VulnClass = VulnClass.OTHER) -> Finding:
    return Finding(
        chunk_id="c", file=file, line_start=ls, line_end=le,
        vuln_class=vc, title="t", description="d", code_snippet="x",
        confidence=0.9,
    )


def test_collapse_trivial_merges_overlapping_ranges():
    findings = [_f("a.py", 10, 20), _f("a.py", 15, 25)]
    canon = s7_dedup._collapse_trivial(findings, line_tol=3)
    assert canon == {1: 0}


def test_collapse_trivial_keeps_disjoint_ranges_separate():
    findings = [_f("a.py", 10, 12), _f("a.py", 80, 82)]
    canon = s7_dedup._collapse_trivial(findings, line_tol=3)
    assert canon == {}


def test_collapse_trivial_keeps_overlapping_findings_with_different_cwe():
    a = _f("svc.py", 40, 45, VulnClass.LOGIC)
    b = _f("svc.py", 42, 66, VulnClass.LOGIC)
    a.cwe = "CWE-863"
    b.cwe = "CWE-778"
    canon = s7_dedup._collapse_trivial([a, b], line_tol=10)
    assert canon == {}


def test_collapse_trivial_still_merges_when_cwe_matches():
    a = _f("svc.py", 40, 45, VulnClass.LOGIC)
    b = _f("svc.py", 42, 66, VulnClass.LOGIC)
    a.cwe = "CWE-863"
    b.cwe = "CWE-863"
    canon = s7_dedup._collapse_trivial([a, b], line_tol=10)
    assert canon == {1: 0}


def test_collapse_trivial_keeps_logic_overlap_when_cwe_missing_on_one_side():
    a = _f("svc.py", 40, 45, VulnClass.LOGIC)
    b = _f("svc.py", 42, 66, VulnClass.LOGIC)
    a.cwe = "CWE-863"
    b.cwe = None
    canon = s7_dedup._collapse_trivial([a, b], line_tol=10)
    assert canon == {}


def test_attach_duplicates_skips_same_site_overlap():
    findings = [_f("a.py", 10, 20), _f("a.py", 15, 25)]
    s7_dedup._attach_duplicates(findings, {1: 0}, {1: "dup"})
    assert findings[0].duplicates == []


def test_attach_duplicates_records_disjoint_site():
    findings = [_f("a.py", 10, 12), _f("b.py", 50, 52)]
    s7_dedup._attach_duplicates(findings, {1: 0}, {1: "dup"})
    assert len(findings[0].duplicates) == 1
    assert findings[0].duplicates[0].file == "b.py"


def test_attach_duplicates_dedupes_identical_locations():
    findings = [_f("a.py", 10, 12), _f("b.py", 50, 52), _f("b.py", 50, 52)]
    s7_dedup._attach_duplicates(findings, {1: 0, 2: 0}, {1: "d", 2: "d"})
    assert len(findings[0].duplicates) == 1


def test_graph_context_for_finding_uses_def_span_candidates():
    f = _f("src/app.py", 10, 12)
    f.source_ref = "src/http.py:22"
    f.sink_ref = "src/app.py:11"
    ctx = ContextPackage(
        repo_root="/tmp/repo",
        language="python",
        call_graph={
            "src/http.py::handle": ["src/app.py::danger"],
            "src/app.py::danger": ["src/db.py::exec"],
        },
        def_spans={
            "src/app.py::danger": [8, 20],
            "src/http.py::handle": [20, 30],
        },
    )

    g = s7_dedup._graph_context_for_finding(f, ctx)
    assert g["available"] is True
    assert "src/app.py::danger" in g["qnodes"]
    around = g["around"]["src/app.py::danger"]
    assert "src/http.py::handle" in around["callers"]
    assert "src/db.py::exec" in around["callees"]


def test_graph_context_for_finding_handles_missing_graph():
    f = _f("src/app.py", 10, 12)
    ctx = ContextPackage(repo_root="/tmp/repo", language="python")
    g = s7_dedup._graph_context_for_finding(f, ctx)
    assert g == {"available": False}


# --------------------------------------------------------------------------
# §9.4 contract preservation: the plain-text dedup grammar survives the
# `via: deepagents` route end-to-end.
#
# This deliberately does NOT stub dispatch_prompt(): the harness is faked at
# the module's own `get_harness` seam (the pattern of
# tests/test_backend_deepagents.py), so the call really flows
# _semantic_dedup() -> _deepagents.dispatch_prompt() (via resolution) ->
# _deepagents.prompt() (option building) -> run_oneshot() -> the fake harness,
# and the raw result text comes back through the whole route into
# _parse_dedup_output. A parse failure in production is SILENT (semantic dedup
# returns [] and the scan reports "no duplicates"), so the assertion is on the
# parsed groupings, never the raw string: any transport that wrapped the reply
# in JSON, forced structured output, or mangled the text would leave all four
# findings canonical and fail the length/dropped assertions below.
# --------------------------------------------------------------------------

def test_semantic_dedup_grammar_parses_through_deepagents_route(monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace

    from vvaharness.backends.harness import OneShotResult
    from vvaharness.backends.llm import deepagents as _deepagents

    # A realistic reply in the exact grammar the SYSTEM prompt demands:
    # plain text, no markdown, no fences, one line per input index.
    reply = (
        'index=0 is_duplicate=false canonical=-1 reasoning="distinct string-built query in orders"\n'
        'index=1 is_duplicate=false canonical=-1 reasoning="independent command execution sink"\n'
        'index=2 is_duplicate=true canonical=0 reasoning="same root cause as index 0, second angle"\n'
        'index=3 is_duplicate=false canonical=-1 reasoning="unrelated missing auth check"\n'
    )

    class _OneShotHarness:
        """Fake harness recording run_oneshot invocations."""

        def __init__(self):
            self.calls = []

        async def run_oneshot(self, prompt, options):
            self.calls.append((prompt, options))
            return OneShotResult(result_text=reply)

    fake = _OneShotHarness()
    monkeypatch.setattr(_deepagents, "get_harness", lambda _via: fake)

    # Four findings in four files: the deterministic pre-filter resolves
    # nothing, so all of them reach the semantic (LLM) pass.
    findings = [_f("orders.py", 10, 20), _f("runner.py", 30, 40),
                _f("query_util.py", 50, 60), _f("auth.py", 70, 80)]
    cfg = SimpleNamespace(
        step7_dedup=SimpleNamespace(line_tolerance=5, semantic=True, max_tokens=800),
        models=SimpleNamespace(dedup=SimpleNamespace(id="claude-sonnet-4-6",
                                                     via="deepagents")),
    )
    ctx = ContextPackage(repo_root="/scans/repo", language="python")

    canonical, dropped = s7_dedup.run(findings, cfg, ctx=ctx)

    # The fake harness was really invoked — the deepagents route ran.
    assert fake.calls, "dispatch_prompt() never reached the deepagents harness"
    prompt_sent, options = fake.calls[0]
    assert "FINDINGS TO DEDUPLICATE" in prompt_sent
    # The stage's cwd plumbing reached the options DTO: the scanned repo root.
    assert options.cwd == Path("/scans/repo")

    # The PARSED groupings, not the raw text: index 2 collapsed onto index 0.
    assert [f.file for f in canonical] == ["orders.py", "runner.py", "auth.py"]
    assert len(dropped) == 1
    assert dropped[0].file == "query_util.py"
    assert dropped[0].reason == "DUPLICATE"
    assert dropped[0].detail == "same root cause as index 0, second angle"
    assert dropped[0].canonical_idx == 0
    # The collapsed finding surfaces as an additional call site on its canonical.
    assert [d.file for d in findings[0].duplicates] == ["query_util.py"]


# --------------------------------------------------------------------------
# Parse-miss telemetry: a reply that breaks the plain-text grammar must stay
# fail-open (every finding survives) but degrade LOUDLY — counter bump, WARN
# on stderr, errlog record with a redacted raw head. A legitimate all-clear
# reply (every line is_duplicate=false) and an empty reply must stay quiet,
# or the warning becomes noise operators learn to ignore.
# --------------------------------------------------------------------------

def _route_cfg():
    from types import SimpleNamespace
    return SimpleNamespace(
        step7_dedup=SimpleNamespace(line_tolerance=5, semantic=True,
                                    max_tokens=800),
        models=SimpleNamespace(dedup=SimpleNamespace(id="claude-sonnet-4-6",
                                                     via="deepagents")),
    )


def _fake_reply_harness(monkeypatch, reply: str):
    """Fake the deepagents harness at the get_harness seam (same pattern as
    the grammar contract test above) so the reply flows the real route."""
    from vvaharness.backends.harness import OneShotResult
    from vvaharness.backends.llm import deepagents as _deepagents

    class _H:
        def __init__(self):
            self.calls = []

        async def run_oneshot(self, prompt, options):
            self.calls.append((prompt, options))
            return OneShotResult(result_text=reply)

    fake = _H()
    monkeypatch.setattr(_deepagents, "get_harness", lambda _via: fake)
    return fake


def test_unparseable_reply_is_loud_but_fail_open(monkeypatch, tmp_path, capsys):
    """Loud fail-open AND the redact-ordering guard for the quoted raw head.

    The head must be ``redact(raw)[:500]``, never ``redact(raw[:500])``:
    ``redact`` masks a complete credential, but any prefix/suffix FRAGMENT of
    one matches no redaction pattern and passes through unmasked. Truncating
    first bisects the token and the surviving piece reaches stderr and the
    errlog in the clear. To detect the wrong ordering, the reply places a
    canonical 20-char AWS access key STRADDLING the 500-char cut (~12 chars
    before it, 8 after): redact-then-truncate masks it whole; truncate-then-
    redact leaks its 12-char prefix. Each geometric precondition is asserted
    in-test so padding/pattern drift cannot silently re-vacuate the test.
    """
    from vvaharness.report.redact import redact
    from vvaharness.util import errlog as _errlog

    cut = 500  # the truncation width _parse_dedup_output applies to the head
    secret = "AKIAIOSFODNN7EXAMPLE"  # canonical 20-char AWS key: AKIA + 16
    # Vacuity guard 1: the literal really is redactable on its own. (An
    # 18-char stand-in is NOT matched by redact() and would make the leak
    # assertions below pass for the wrong reason.)
    assert secret not in redact(secret)

    # Space-separated filler — glued padding ("xxxAKIA…") would defeat the
    # AWS pattern's word boundary, so the key would never redact even in
    # correct code. Sized so the key starts 12 chars before the cut.
    before = "x " * ((cut - 12) // 2)
    reply = (before + secret
             + " and then prose that matches no dedup grammar line at all")
    offset = reply.index(secret)
    # Vacuity guard 2: the key genuinely straddles the cut with this padding.
    # If a later edit moves the whole token to one side, fail HERE.
    assert 12 <= cut - offset <= 14, (
        f"key no longer straddles the {cut}-char cut: starts at {offset}")
    assert offset + len(secret) > cut
    assert len(reply) > cut

    fake = _fake_reply_harness(monkeypatch, reply)
    errfile = tmp_path / "scan_errors.jsonl"
    monkeypatch.setattr(_errlog, "_path", errfile)

    findings = [_f("orders.py", 10, 20), _f("runner.py", 30, 40),
                _f("query_util.py", 50, 60), _f("auth.py", 70, 80)]
    ctx = ContextPackage(repo_root="/scans/repo", language="python")

    canonical, dropped = s7_dedup.run(findings, _route_cfg(), ctx=ctx)

    assert fake.calls, "the deepagents route never ran"
    # Fail-open: the parser's [] keeps every finding and drops nothing.
    assert [f.file for f in canonical] == [
        "orders.py", "runner.py", "query_util.py", "auth.py"]
    assert dropped == []
    # Loud: counter + WARN + errlog record, all with the raw head REDACTED.
    assert COUNTERS.get("s7_dedup_parse_miss") == 1
    err = capsys.readouterr().err
    assert "WARN" in err and "no grammar lines" in err
    recs = [json.loads(ln) for ln in errfile.read_text().splitlines()
            if ln.strip()]
    hits = [r for r in recs
            if r["stage"] == "s7-dedup" and r["unit"] == "semantic-parse"]
    assert len(hits) == 1
    assert "REDACTED" in hits[0]["raw_head"]
    # Sweep EVERY 12-char window of the key over both outputs, so no
    # fragment of it survives anywhere — this is the assertion that goes RED
    # when the source truncates before redacting.
    record = json.dumps(hits[0])
    for i in range(len(secret) - 11):
        fragment = secret[i:i + 12]
        assert fragment not in err, (
            f"key fragment {fragment!r} leaked to stderr")
        assert fragment not in record, (
            f"key fragment {fragment!r} leaked to the errlog record")


def test_all_false_reply_is_quiet(capsys):
    # The grammar's legitimate "no duplicates" shape: one is_duplicate=false
    # line per index. Parses to [] with NO warning and NO counter bump.
    reply = (
        'index=0 is_duplicate=false canonical=-1 reasoning="distinct"\n'
        'index=1 is_duplicate=false canonical=-1 reasoning="distinct"\n'
    )
    assert s7_dedup._parse_dedup_output(reply, 2) == []
    assert COUNTERS.get("s7_dedup_parse_miss") == 0
    assert "WARN" not in capsys.readouterr().err


def test_empty_reply_is_quiet(capsys):
    assert s7_dedup._parse_dedup_output("", 3) == []
    assert s7_dedup._parse_dedup_output("  \n ", 3) == []
    assert COUNTERS.get("s7_dedup_parse_miss") == 0
    assert "WARN" not in capsys.readouterr().err


def test_run_requires_ctx():
    # cwd roots the model's virtual filesystem at the scanned repo, so ctx is
    # a required keyword — omitting it fails fast at the call, not as
    # Path(None) deep inside the backend.
    findings = [_f("a.py", 10, 20), _f("b.py", 80, 90)]
    with pytest.raises(TypeError, match="ctx"):
        s7_dedup.run(findings, _route_cfg())


def test_a_parse_miss_is_attributed_to_the_calling_stage(monkeypatch, tmp_path, capsys):
    """The semantic pass runs for TWO stages, so its diagnostics must name the caller.

    ``run`` takes *label* because s5's pre-verify pre-dedup reuses this module, and
    "s5-prefilter" is already the registered name for that phase in
    ``stage_telemetry.PHASE_MAP`` and in ``TOKENS.phase``. The two private helpers that
    emit diagnostics did not receive it and hardcoded "s7-dedup", so an error raised
    during s5 was filed under s7. That is not cosmetic: ``errlog.count_for_stage`` is
    what ``status.stage`` uses to decide between ``✓`` and ``⚠``, and it matches on the
    stage prefix — "s7-dedup" never matches "s5", so s5 completed with an unrecovered
    error and still printed ``✓``, while the manifest credited the error to s7.
    """
    from vvaharness.util import errlog as _errlog

    fake = _fake_reply_harness(monkeypatch, "no grammar lines here at all")
    errfile = tmp_path / "scan_errors.jsonl"
    monkeypatch.setattr(_errlog, "_path", errfile)

    findings = [_f("orders.py", 10, 20), _f("runner.py", 30, 40),
                _f("query_util.py", 50, 60), _f("auth.py", 70, 80)]
    ctx = ContextPackage(repo_root="/scans/repo", language="python")

    s7_dedup.run(findings, _route_cfg(), label="s5-prefilter", ctx=ctx)

    assert fake.calls, "the deepagents route never ran"
    recs = [json.loads(ln) for ln in errfile.read_text().splitlines() if ln.strip()]
    stages = {r["stage"] for r in recs}
    # BOTH spellings follow the caller: the hyphenated errlog/telemetry key, and the
    # spaced human-readable tag the response-quality floors and VVAH-E003 carry.
    assert stages == {"s5-prefilter", "s5 prefilter"}, stages
    # The consequence, pinned at the function that decides the glyph: the CALLING
    # stage sees its own errors, and s7 is not blamed for them. Both spellings
    # prefix-match "s5", which is why both had to move.
    assert _errlog.count_for_stage("s5", errfile) == 2          # both records
    assert _errlog.count_for_stage("s7", errfile) == 0          # none stolen by s7
    # Only the parse miss is an unrecovered loss, so only it can turn s5's line to ⚠;
    # the VVAH-E003 intermediate warning is stamped recovered=True and must not.
    assert _errlog.count_for_stage("s5", errfile, include_recovered=False) == 1
    assert _errlog.count_for_stage("s7", errfile, include_recovered=False) == 0
    # stderr names the caller too, so the log and the errlog agree.
    assert "[s5-prefilter] WARN" in capsys.readouterr().err


def test_the_default_label_keeps_s7_attribution(monkeypatch, tmp_path):
    """s7's own call passes no label, and must keep filing under s7-dedup."""
    from vvaharness.util import errlog as _errlog

    _fake_reply_harness(monkeypatch, "no grammar lines here at all")
    errfile = tmp_path / "scan_errors.jsonl"
    monkeypatch.setattr(_errlog, "_path", errfile)

    findings = [_f("orders.py", 10, 20), _f("runner.py", 30, 40)]
    ctx = ContextPackage(repo_root="/scans/repo", language="python")

    s7_dedup.run(findings, _route_cfg(), ctx=ctx)

    recs = [json.loads(ln) for ln in errfile.read_text().splitlines() if ln.strip()]
    assert {r["stage"] for r in recs} == {"s7-dedup", "s7 dedup"}
    assert _errlog.count_for_stage("s7", errfile) == 2
    assert _errlog.count_for_stage("s7", errfile, include_recovered=False) == 1
    assert _errlog.count_for_stage("s5", errfile, include_recovered=False) == 0
