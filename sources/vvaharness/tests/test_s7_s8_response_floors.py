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

"""VVAH-E003 stage-floor tests for s7 (dedup) and s8 (chain).

The defect under test: the global degenerate-response floors (150 chars /
30 output tokens, sized for prose stages) misfire on a legitimate
"nothing to report" reply from s7 and s8 — s7's shortest grammar-valid
all-clear is two ~52-char lines (~103 chars) and s8's shortest
schema-conforming reply is a one-finding JSON object (~101 chars), both
below the defaults — so a correct answer was logged as a VVAH-E003
degenerate response. The fix scopes per-stage floors around each
dispatch via stage_floors(), keyed on the exact tag the backend receives.

The observable is STDERR, never the return value: an intermediate
VVAH-E003 failure only warns (the reply still flows to the caller), so a
return-value assertion passes with the fix reverted and proves nothing.
Each fake backend reproduces the real backends' contract — it calls
check_response_quality(text, stage=tag, output_tokens=...) with the tag
verbatim, exactly as backends/llm/sdk.py does — so the stage_floors scope
in the stage under test is what decides whether the warning fires.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vvaharness.models import ContextPackage, Finding, VulnClass
from vvaharness.pipeline.stages import s7_dedup, s8_chain
from vvaharness.util import response_quality


@pytest.fixture(autouse=True)
def _fresh_quality_counters():
    """The consecutive-failure tally is a process-global keyed by tag; a
    trip left behind by one test would change another's warn/raise step."""
    response_quality.reset_counters()
    yield
    response_quality.reset_counters()


def _fake_dispatch(reply: str, output_tokens: int, seen: dict):
    """Stand-in for _deepagents.dispatch_prompt that honours the backend
    contract the fix depends on: the quality gate runs INSIDE the dispatch,
    keyed by the verbatim tag (sdk.py: check_response_quality(text,
    stage=tag, output_tokens=...))."""
    def fake(user_prompt, **kwargs):
        seen["tag"] = kwargs.get("tag")
        response_quality.check_response_quality(
            reply.strip(), stage=kwargs.get("tag") or "",
            output_tokens=output_tokens)
        return reply
    return fake


# ── s7 dedup ────────────────────────────────────────────────────────────────

# The shortest reply the s7 parser accepts: _semantic_dedup is only
# dispatched with >= 2 unresolved findings and the grammar demands one line
# per index even when nothing is a duplicate, so the minimum legitimate
# all-clear is two lines (105 chars here, ~22 visible-text tokens).
_S7_MIN_ALL_CLEAR = (
    'index=0 is_duplicate=false canonical=-1 reasoning=""\n'
    'index=1 is_duplicate=false canonical=-1 reasoning=""'
)


def _s7_cfg():
    return SimpleNamespace(
        step7_dedup=SimpleNamespace(line_tolerance=5, semantic=True,
                                    max_tokens=800),
        models=SimpleNamespace(dedup="model-dedup"),
    )


def _s7_findings():
    # Two findings in different files: the deterministic pre-filter resolves
    # nothing, so both reach the semantic (LLM) pass.
    return [
        Finding(title="sqli", file="orders.py", line_start=10, line_end=12,
                vuln_class=VulnClass.OTHER),
        Finding(title="cmdi", file="runner.py", line_start=30, line_end=32,
                vuln_class=VulnClass.OTHER),
    ]


def _run_s7(monkeypatch, reply: str, output_tokens: int):
    seen: dict = {}
    monkeypatch.setattr(s7_dedup._deepagents, "dispatch_prompt",
                        _fake_dispatch(reply, output_tokens, seen))
    canonical, dropped = s7_dedup.run(
        _s7_findings(), _s7_cfg(),
        ctx=ContextPackage(repo_root="/repo", language="python"))
    return canonical, dropped, seen


def test_s7_minimal_all_clear_is_not_flagged_degenerate(monkeypatch, capsys):
    """A grammar-valid two-finding all-clear (105 chars / 22 tokens — the
    stage's true minimum) must pass the quality gate silently. Red-proof:
    with the stage_floors scope removed from _semantic_dedup, the 150/30
    defaults apply and the WARN VVAH-E003 line appears on stderr."""
    canonical, dropped, seen = _run_s7(monkeypatch, _S7_MIN_ALL_CLEAR, 22)
    err = capsys.readouterr().err
    assert "VVAH-E003" not in err
    # The all-clear parsed as a real answer, not a parse miss.
    assert "matched no grammar lines" not in err
    assert len(canonical) == 2 and dropped == []
    # The wrapper is keyed on the exact tag the backend received; drift
    # between the two would make the override a silent no-op.
    assert seen["tag"] == "s7 dedup"


def test_s7_token_floor_override_applies(monkeypatch, capsys):
    """Isolates min_tokens: a reply comfortably above BOTH char floors but
    with a reported token count between the stage floor (15) and the global
    default (30). Synthetic pairing — the fake controls output_tokens
    independently of the text — chosen so the char axis cannot mask the
    token axis in either direction. Red-proof: without the override the
    30-token default flags it."""
    reply = (
        'index=0 is_duplicate=false canonical=-1 reasoning="distinct '
        'string-built query with its own sanitiser gap in orders"\n'
        'index=1 is_duplicate=false canonical=-1 reasoning="independent '
        'command execution sink; separate patch required"'
    )
    assert len(reply) > 150  # above even the default char floor
    _, _, _ = _run_s7(monkeypatch, reply, output_tokens=16)
    assert "VVAH-E003" not in capsys.readouterr().err


def test_s7_floor_still_catches_genuine_degenerate(monkeypatch, capsys):
    """Guard, not red-proof (it passes with or without the fix): the relaxed
    floors must still flag the archetypes they exist for — a one-word
    acknowledgement is below 90 chars / 15 tokens."""
    canonical, dropped, _ = _run_s7(monkeypatch, "ok", output_tokens=1)
    err = capsys.readouterr().err
    assert "VVAH-E003" in err
    # First trip only warns; the degenerate reply still flowed onward and
    # fail-open kept every finding.
    assert len(canonical) == 2 and dropped == []


# ── s8 chain ────────────────────────────────────────────────────────────────

# The shortest reply conforming to s8's SYSTEM schema: one ranked_findings
# entry per finding (run() dispatches with >= 1), empty summary/notes, no
# chains — 101 chars, ~26 visible-text tokens.
_S8_MIN_CONFORMING = (
    '{"summary":"","ranked_findings":[{"index":0,"severity":"low",'
    '"exploitability_notes":""}],"chains":[]}'
)


def _s8_cfg():
    return SimpleNamespace(
        models=SimpleNamespace(chain="model-chain"),
        step8=SimpleNamespace(max_tokens=None, timeout=1800),
    )


def _run_s8(monkeypatch, reply: str, output_tokens: int, n_findings: int = 1):
    seen: dict = {}
    monkeypatch.setattr(s8_chain._deepagents, "dispatch_prompt",
                        _fake_dispatch(reply, output_tokens, seen))
    # n_findings > 1 only for the chain-hydration case: _hydrate_report discards
    # any chain whose remapped steps number fewer than two, so a chain needs at
    # least two verified findings to survive.
    findings = [
        Finding(title=f"sqli{i}", file=f"src/mod{i}.c", line_start=10 + i,
                line_end=11 + i, vuln_class=VulnClass.OTHER)
        for i in range(n_findings)
    ]
    report = s8_chain.run(
        findings, ContextPackage(repo_root="/repo", language="c"), _s8_cfg())
    return report, seen


def test_s8_minimal_conforming_reply_is_not_flagged_degenerate(monkeypatch,
                                                               capsys):
    """The one-finding, empty-chains reply (101 chars / 26 tokens — the
    schema minimum) must pass the quality gate silently AND hydrate as a
    ranked (non-backfilled) finding. Red-proof: with the stage_floors scope
    removed from run(), the 150/30 defaults flag it as VVAH-E003."""
    report, seen = _run_s8(monkeypatch, _S8_MIN_CONFORMING, 26)
    err = capsys.readouterr().err
    assert "VVAH-E003" not in err
    assert "carried no ranked_findings" not in err
    assert len(report.findings) == 1
    # Hydrated FROM the reply's entry ("" notes), not the uncovered-finding
    # backfill — proof the short reply was treated as a real answer.
    assert report.findings[0].exploitability_notes == ""
    assert seen["tag"] == "s8 chain"


def test_s8_token_floor_override_applies(monkeypatch, capsys):
    """Isolates min_tokens for s8, same construction as the s7 twin: text
    above both char floors, reported tokens between the stage floor (15)
    and the global default (30)."""
    reply = json.dumps({
        "summary": "Single verified finding; no chain partners exist in "
                   "this set, so it stands alone at its CVSS severity.",
        "ranked_findings": [{"index": 0, "severity": "low",
                             "exploitability_notes": "standalone"}],
        "chains": [],
    })
    assert len(reply) > 150
    report, _ = _run_s8(monkeypatch, reply, output_tokens=16)
    assert "VVAH-E003" not in capsys.readouterr().err
    assert len(report.findings) == 1


def test_s8_parseable_reply_without_ranked_findings_is_loud(monkeypatch,
                                                            capsys):
    """The s4-lesson structural check: a reply that clears the floors and
    parses as JSON but carries no ranked_findings used to ship every
    finding silently unranked in a report NOT marked degraded. It must now
    warn and log. Red-proof: with the structural check removed from run(),
    no warning appears and this fails."""
    reply = ('{"summary":"Reviewed the findings; no exploit chains or rank '
             'adjustments were identified in this set.","chains":[]}')
    assert len(reply) >= 90  # clears the stage char floor by construction
    report, _ = _run_s8(monkeypatch, reply, output_tokens=40)
    err = capsys.readouterr().err
    assert "VVAH-E003" not in err
    assert "ship unranked" in err
    # Behaviour (not just telemetry) documented: the finding survives via
    # the CVSS-anchored backfill and the report is not the degraded variant.
    assert len(report.findings) == 1
    assert report.findings[0].exploitability_notes == \
        "(not ranked by chaining pass)"
    assert report.degraded is False


def test_s8_empty_object_trips_both_layers(monkeypatch, capsys):
    """Guard: '{}' (2 chars) is the parseable-but-empty degenerate case.
    Layer 1 (floor) warns at the backend; layer 2 (structural check) makes
    the silent-unranked consequence loud; the report still ships with the
    finding backfilled."""
    report, _ = _run_s8(monkeypatch, "{}", output_tokens=2)
    err = capsys.readouterr().err
    assert "VVAH-E003" in err
    assert "ship unranked" in err
    assert len(report.findings) == 1


# ── s8 coverage check: the two cases emptiness got backwards ─────────────────

def test_s8_entries_discarded_by_index_filters_are_loud(monkeypatch, capsys):
    """A NON-EMPTY ranked_findings whose entries all fail hydration's filters.

    This is the silent case the first version of the check missed: it tested
    only that the list was non-empty, so a string index (or out-of-range, or a
    duplicate) sailed through, every finding was backfilled as "(not ranked by
    chaining pass)" at INFO, and report.degraded stayed False. 118 chars clears
    both the stage floor and the old 150-char default, so the length axis
    cannot catch it either — only coverage can.
    """
    reply = ('{"summary":"No chains identified.","ranked_findings":'
             '[{"index":"0","severity":"high","exploitability_notes":""}],'
             '"chains":[]}')
    assert len(reply) >= 90
    _report, _ = _run_s8(monkeypatch, reply, output_tokens=40)
    err = capsys.readouterr().err
    assert "VVAH-E003" not in err, "length is fine; this is a shape problem"
    assert "ranked 0/1 findings" in err
    assert "ship unranked" in err


def test_s8_salvaged_chains_array_stays_quiet(monkeypatch, capsys):
    """A top-level chains array is a WORKING reply and must not be reported.

    _coerce_list_payload deliberately maps it to {"chains": [...]}, which has no
    ranked_findings key by design. The first version of the check fired a WARN
    and an UNMARKED errlog record here, flipping s8 to completed_with_errors on
    a reply that hydrated correctly — an error record that fires on the working
    path and is silent on the broken one desensitises the artifact.
    """
    reply = ('[{"title":"UAF -> arb write","steps":[0,1],"severity":"high",'
             '"narrative":"chain via the same sink"}]')
    report, _ = _run_s8(monkeypatch, reply, output_tokens=40, n_findings=2)
    err = capsys.readouterr().err
    assert "ship unranked" not in err, (
        "the salvaged chains-array path is working, not degraded")
    assert len(report.chains) == 1, "the chain must still hydrate"
