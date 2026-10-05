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

"""S4 VVAH-E003 response floors + the structural findings-list check.

The SYSTEM schema explicitly allows an empty ``{"findings": []}`` reply
(~15-16 chars, 11-12 provider-reported output tokens live), so the global
150-char / 30-token floors flagged every findings-free chunk as degenerate —
a confirmation run logged 55 such warnings, all on ``s4 <chunk-id>`` tags.
_single_run now wraps BOTH its dispatches in ``stage_floors`` keyed on the
exact per-unit tag each backend receives (``s4 <chunk-id>`` and
``s4 <chunk-id> json-repair`` — the mechanism is non-reentrant per key, so
one wrapper keyed on a shared prefix cannot cover the two).

Lowering the floor releases the valid-JSON-wrong-shape replies the 150-char
default caught by accident (``{"findings": null}``, ``{"findigns": []}`` —
both silently yielded zero findings), so ``_findings_list`` now validates the
parsed object structurally and routes violations through the existing
JSON-repair path.

The backend quality gate is SIMULATED inside the fake backend (patching
``_deepagents.prompt`` bypasses the real one), exactly the
test_s6_verdict_reask_wave1 pattern: the fake calls check_response_quality
with the tag it received, which runs inside whatever stage_floors scope the
stage installed — the observable is the VVAH-E003 warning on stderr.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.models import Chunk, ChunkSize, ContextPackage
from vvaharness.pipeline.stages import s4_deepdive as s4
from vvaharness.util import response_quality

# What the live run most plausibly saw: the schema's minimal valid reply.
# 16 chars; the run's provider reported 11 output tokens for this length.
_EMPTY_FINDINGS = '{"findings": []}'
_EMPTY_FINDINGS_TOKENS = 11


def _ctx() -> ContextPackage:
    return ContextPackage(repo_root="/nonexistent-repo", language="python",
                          all_files=[], entry_points=[], unsafe_sinks=[],
                          call_graph={})


def _cfg():
    return SimpleNamespace(
        step4=SimpleNamespace(taint_prompt_mode="discover", taint_model=None,
                              max_tokens=64000, timeout=1800),
        models=SimpleNamespace(
            deepdive=SimpleNamespace(id="claude-test", via="deepagents")),
        sdk=SimpleNamespace(api_key="sk-test"),
    )


def _chunk(cid: str = "chunk-01") -> Chunk:
    return Chunk(id=cid, size=ChunkSize.MEDIUM, file_ids=["a.py"],
                 hypothesis="x")


def _install_backend(monkeypatch, replies_by_call, tokens_by_call, seen):
    """Fake deepagents backend that replays canned replies and runs the REAL
    quality gate against the tag it was handed — inside whatever stage_floors
    scope the caller installed, exactly like the shipped backends (they all
    pass stage=tag verbatim)."""
    def fake_prompt(user_prompt, **kw):
        i = len(seen)
        seen.append({"tag": kw["tag"], "user": user_prompt,
                     "floors_installed_for_tag":
                         kw["tag"] in response_quality._stage_floors})
        reply = replies_by_call[i]
        response_quality.check_response_quality(
            reply.strip(), stage=kw["tag"], output_tokens=tokens_by_call[i])
        return reply

    monkeypatch.setattr(s4._deepagents, "prompt", fake_prompt)


# ── floors on the PRIMARY dispatch tag ───────────────────────────────────────

def test_minimal_valid_empty_reply_not_flagged_degenerate(monkeypatch, capsys):
    """The exact live failure: a findings-free chunk answering with the
    schema's minimal valid object must pass the quality gate silently.

    This also pins the EXACT-tag keying: were the wrapper keyed on a shared
    prefix like "s4", the gate (checking stage="s4 chunk-01", as the backends
    do) would fall back to the 150/30 defaults and warn."""
    errlog_calls = []
    monkeypatch.setattr(response_quality._errlog, "log",
                        lambda *a, **k: errlog_calls.append((a, k)))
    seen: list[dict] = []
    _install_backend(monkeypatch, [_EMPTY_FINDINGS],
                     [_EMPTY_FINDINGS_TOKENS], seen)

    out = s4._single_run(_chunk(), _ctx(), "code", _cfg())

    assert out == []
    assert [c["tag"] for c in seen] == ["s4 chunk-01"]
    assert seen[0]["floors_installed_for_tag"], \
        "stage_floors must be keyed on the exact per-chunk tag"
    assert "VVAH-E003" not in capsys.readouterr().err
    assert errlog_calls == []                 # no recovered E003 record either
    # Scoped override, not a leak: the tag's floors are gone after dispatch.
    assert "s4 chunk-01" not in response_quality._stage_floors


# ── floors on the JSON-REPAIR dispatch tag ───────────────────────────────────

def test_minimal_valid_repair_reply_not_flagged_degenerate(monkeypatch, capsys):
    """The repair dispatch hands the backend a DIFFERENT tag, so it needs its
    own stage_floors scope. The primary reply here is long enough to pass even
    the 150/30 defaults, so this test goes red only if the repair-site wrapper
    is missing."""
    broken = '{"findings": [' + '"x", ' * 40   # >150 chars, never balances
    seen: list[dict] = []
    _install_backend(monkeypatch, [broken, _EMPTY_FINDINGS],
                     [80, _EMPTY_FINDINGS_TOKENS], seen)

    out = s4._single_run(_chunk(), _ctx(), "code", _cfg())

    assert out == []
    assert [c["tag"] for c in seen] == \
        ["s4 chunk-01", "s4 chunk-01 json-repair"]
    assert seen[1]["user"].startswith("REPAIR TASK:")
    assert seen[1]["floors_installed_for_tag"], \
        "the repair dispatch needs its own exact-tag stage_floors scope"
    assert "VVAH-E003" not in capsys.readouterr().err
    assert "s4 chunk-01 json-repair" not in response_quality._stage_floors


# ── the structural findings-list check (§ the detection the 150-char floor
#    was providing by accident) ───────────────────────────────────────────────

def test_findings_null_rides_repair_and_raises_when_still_malformed(
        monkeypatch, capsys):
    """``{"findings": null}`` (18 chars) passes the lowered floors, and the old
    ``data.get("findings", [])`` + isinstance coercion turned it into ZERO
    findings silently. It must instead ride the existing repair retry, and a
    repair that is STILL malformed must raise out of the run — same trail as a
    repair that fails to parse — so the run/chunk handlers record the loss."""
    seen: list[dict] = []
    _install_backend(monkeypatch, ['{"findings": null}', '{"findings": null}'],
                     [12, 12], seen)

    with pytest.raises(ValueError, match="'findings' list"):
        s4._single_run(_chunk(), _ctx(), "code", _cfg())

    assert [c["tag"] for c in seen] == \
        ["s4 chunk-01", "s4 chunk-01 json-repair"]
    assert "retrying repair" in capsys.readouterr().err


def test_misspelled_findings_key_repaired_and_recovered(monkeypatch):
    """``{"findigns": []}`` (16 chars — indistinguishable from the valid reply
    by length alone) must trigger the repair; a conforming repaired reply then
    completes the run normally."""
    seen: list[dict] = []
    _install_backend(monkeypatch, ['{"findigns": []}', _EMPTY_FINDINGS],
                     [_EMPTY_FINDINGS_TOKENS, _EMPTY_FINDINGS_TOKENS], seen)

    out = s4._single_run(_chunk(), _ctx(), "code", _cfg())

    assert out == []
    assert len(seen) == 2
    assert seen[1]["user"].startswith("REPAIR TASK:")


def test_findings_list_contract():
    """The helper's full accept/reject contract, including the pre-existing
    tolerance for a bare top-level array (extract_json can return one)."""
    assert s4._findings_list({"findings": []}) == []
    item = {"file": "a.py", "line_start": 1}
    assert s4._findings_list({"findings": [item]}) == [item]
    assert s4._findings_list([item]) == [item]        # bare array: kept

    for bad in ({"findings": None},        # null value
                {"findigns": []},          # misspelled key
                {"findings": {"n": 0}},    # non-list value
                {}):                       # no key at all
        with pytest.raises(ValueError, match="'findings' list"):
            s4._findings_list(bad)
