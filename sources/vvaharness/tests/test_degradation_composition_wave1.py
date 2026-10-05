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

"""Degradation-marker composition tests — the suite that was missing.

Both halves of the spurious-degradation defect (RCA-D1) were individually
tested and both suites passed while the composition was broken: the S1
record test monkeypatched ``s1._errlog.log`` into a Python list, so the
record never met the real ``errors.jsonl`` counter, and the predicate tests
in test_robustness.py hand-logged synthetic records that were classified
correctly by construction. No test ever ran a REAL emission path inside a
real ``status.stage()`` window against a real errors file — which is exactly
the seam where the defect lived.

This module closes that gap in three layers:

  1. Composed emission-under-predicate tests: each informational site
     (s1 call-graph rejection, s2 containment refusal) is driven through its
     real code path inside ``status.stage()`` with the real errlog file — NO
     monkeypatching of ``_errlog.log`` anywhere in this module — and the
     stage must close plain ``completed`` while the diagnostic record
     persists.
  2. The same composition for the deliberately-UNMARKED records (s2 zero
     threats, s2 baseline items undisposed, s4 empty-chunk skip — the last
     had a recovered=True stamp that was reverted on review, see its test):
     real emission must still flip the stage to ``completed_with_errors``,
     because those records are genuine capability loss and stamping them
     would re-silence it. Plus the ✓-line wording pin: the count is of
     UNRECOVERED records (``include_recovered=False``), so it must render
     as "unrecovered", never the inverted "recoverable".
  3. A static classification guard over every ``_errlog.log`` call site in
     the product: a site either stamps ``recovered=True`` (informational /
     recovered transient) or appears in the justified degrading/out-of-window
     allowlist below. A new, unclassified site fails a named test here
     instead of shipping the next spurious flip to a live run.
"""
from __future__ import annotations

import ast
import json
import types
from pathlib import Path
from types import SimpleNamespace

from vvaharness.models import Chunk, ChunkSize, ContextPackage
from vvaharness.pipeline.stages import s1_preprocess as s1
from vvaharness.pipeline.stages import s2_threatmodel as s2
from vvaharness.pipeline.stages import s4_deepdive as s4
from vvaharness.util import errlog
from vvaharness.util import status
from vvaharness.util.stage_telemetry import STAGES

PRODUCT_ROOT = Path(__file__).resolve().parents[1] / "vvaharness"


def _written_records(stage: str | None = None) -> list[dict]:
    """Every record actually written to the (per-test, conftest-isolated)
    errors.jsonl — the real file, not a captured argument list."""
    p = errlog.current_path()
    if not p.exists():
        return []
    recs = [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip()]
    return [r for r in recs if stage is None or r.get("stage") == stage]


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — informational sites: real emission, real predicate, no flip.
# ─────────────────────────────────────────────────────────────────────────────

def _supp_cfg(**over):
    # Same shape as tests/test_s1_preprocess.py's helper — duplicated rather
    # than imported so this module never executes another test module's
    # import-time monkeypatching or fixtures.
    base = dict(exclude_dirs=None, exclude_exts=None, exclude_globs=None,
                max_file_kb=1024, follow_symlinks=False,
                call_graph_supplement=True, call_graph_validate=True,
                call_graph_rounds=3, call_graph_max_targets=3)
    base.update(over)
    return types.SimpleNamespace(step1=types.SimpleNamespace(**base))


def test_s1_call_graph_rejection_composed_keeps_stage_completed(
        tmp_path, capsys):
    """THE test that would have caught RCA-D1: the validator correctly
    rejecting a hallucinated edge is the contract working, so the stage must
    close plain ``completed`` — while the rejection diagnostic still lands in
    the real errors.jsonl. The two-file fixture is the same shape as
    test_supplement_counts_one_rejection_per_edge_not_per_caller_site, but
    ``_errlog.log`` is deliberately NOT monkeypatched: the record must reach
    the real counter that ``status.stage`` diffs."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "h.py").write_text(
        "def handler(x):\n    library_sink(x)\n", encoding="utf-8")
    (tmp_path / "b" / "h.py").write_text(
        "def handler(x):\n    return x\n", encoding="utf-8")

    data = {"call_graph": {"handler": ["library_sink"]}}
    with status.stage("Step 1 — Preprocess", stage_id="s1"):
        s1._supplement_call_graph(data, ["a/h.py", "b/h.py"], tmp_path,
                                  _supp_cfg())

    # Healthy outcome AND persisted diagnostic — both, not either.
    assert STAGES.snapshot()["s1"]["outcome"] == "completed"
    assert errlog.count_for_stage("s1") == 1
    recs = [r for r in _written_records("s1")
            if r.get("reason") == "call_graph_edges_rejected"]
    assert len(recs) == 1
    assert recs[0]["recovered"] is True
    err = capsys.readouterr().err
    # Load-bearing in the OTHER direction now that degraded
    # stages ⚠: this record is recovered=True, n_err is counted with
    # include_recovered=False, so n_err == 0 and the line must stay ✓. It is the
    # pin that stops the new glyph firing on a healthy run — the failure mode
    # status.py's own comment calls out, since a marker that appears on healthy
    # stages is one operators learn to ignore.
    assert "✓" in err and "⚠" not in err
    assert "unrecovered error" not in err and "recoverable error" not in err


def test_s2_containment_refusal_composed_keeps_stage_completed(tmp_path):
    """The containment guard refusing an off-root read is the guard working
    exactly as designed: the same unconditional host-file-disclosure policy
    s1's walk applies (which excludes off-root symlinks from scope without a
    degrading record), so nothing the stage is permitted to read is lost.
    In the product the live trigger is a root-level document that is a
    symlink resolving outside the repo (see the in-code comment for why the
    other callers cannot reach the refusal); the test drives an off-root
    path straight through the chokepoint, which exercises the same branch."""
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.txt"   # exists, but outside the repo root
    outside.write_text("must never be read", encoding="utf-8")

    with status.stage("Step 2 — Threat model", stage_id="s2"):
        out = s2._read_capped(root, outside, 1000)

    assert out == ""                     # the refusal itself still holds
    assert STAGES.snapshot()["s2"]["outcome"] == "completed"
    assert errlog.count_for_stage("s2") == 1
    rec = _written_records("s2")[0]
    assert rec["recovered"] is True
    assert rec["reason"] == "containment_refused"


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — genuinely-degrading records: real emission still flips, and the
# ✓ line names the count with the RIGHT word.
# ─────────────────────────────────────────────────────────────────────────────

def test_s4_empty_chunk_skip_composed_still_degrades(monkeypatch):
    """DELIBERATELY-UNMARKED site (a recovered=True stamp was REVERTED here
    on review — wave-1 F6, and this test flipped with it): the stamp's
    justification cited s3's unmarked drop records as the loss-path
    backstop, but s3's ``_drop_empty_chunks`` removes every chunk its own
    normalisation empties before s4 ever sees the manifest (and --resume
    loads the post-drop checkpoint), so the ONLY way this record can fire is
    a producer that bypassed s3's guard — exactly the path with no backstop.
    A chunk of the manifest silently leaving analysis is genuine coverage
    loss, so the stage must close ``completed_with_errors``. The skip itself
    stays the designed outcome: no model call is paid for (the stub raises
    to prove it) and outcomes still says "skipped" (metrics.py keeps it out
    of chunks_failed)."""
    from vvaharness.backends.llm import registry

    def _no_model_call(*a, **kw):
        raise AssertionError("empty chunk must never reach the model")

    monkeypatch.setattr(registry, "prompt", _no_model_call)
    ctx = ContextPackage(repo_root="/nonexistent-repo", language="python",
                         all_files=[], entry_points=[], unsafe_sinks=[],
                         call_graph={})
    empty_chunk = Chunk(id="chunk-empty", size=ChunkSize.MEDIUM, files=[],
                        hypothesis="x")
    cfg = SimpleNamespace(
        step4=SimpleNamespace(parallel=1, line_bucket=10, runs=1,
                              vote_threshold=1, specialist_runs=1,
                              max_tokens=64000, timeout=1800,
                              taint_prompt_mode="discover", taint_runs=1,
                              taint_model=None),
        models=SimpleNamespace(deepdive=SimpleNamespace(
            id="claude-sonnet-4-6", via="cli")),
    )

    with status.stage("Step 4 — Deep-dive", stage_id="s4"):
        findings, outcomes = s4.run([empty_chunk], ctx, cfg)

    assert findings == [] and outcomes["chunk-empty"] == "skipped"
    assert STAGES.snapshot()["s4"]["outcome"] == "completed_with_errors"
    assert errlog.count_for_stage("s4") == 1
    rec = _written_records("s4")[0]
    assert "recovered" not in rec
    assert rec["reason"] == "empty_chunk_skipped"


def _s2_cfg(**step2_kwargs):
    step2_kwargs.setdefault("baseline", "none")
    return SimpleNamespace(step2=SimpleNamespace(**step2_kwargs),
                           models=SimpleNamespace(threatmodel="stub-model"))


def test_s2_zero_threats_real_emission_still_degrades(stub_prompt, capsys):
    """DELIBERATELY-UNMARKED site #1: a parseable-but-empty threat model is a
    real downstream capability loss (attribution, threat-surface fallback and
    the specialist force-on all disable), and this record is the only
    structural signal separating it from a healthy run. Stamping it would
    close s2 green on a model that silently produced nothing — this test
    pins the owner decision that it must keep flipping the stage."""
    stub_prompt.set_response("s2", "{}")
    with status.stage("Step 2 — Threat model", stage_id="s2"):
        tm = s2.run("/nonexistent-repo", "repo", _s2_cfg(), [], [])

    assert tm.threats == []
    assert STAGES.snapshot()["s2"]["outcome"] == "completed_with_errors"
    zero = [r for r in _written_records("s2") if "zero threats" in r["error"]]
    assert zero and "recovered" not in zero[0]
    err = capsys.readouterr().err
    # The count is of UNRECOVERED records (include_recovered=False); the old
    # "recoverable" wording applied errlog's vocabulary to its complement.
    assert "1 unrecovered error(s)" in err and "errors.jsonl" in err
    assert "recoverable" not in err


def test_s2_baseline_undisposed_real_emission_still_degrades(stub_prompt):
    """DELIBERATELY-UNMARKED site #2: an undisposed baseline item is a
    deliverable gap — s3 consumes baseline-disposition threats for chunk
    targeting — so the record must keep flipping the stage. The stubbed model
    emits one valid threat with NO baseline disposition against the owasp
    baseline (kinds={web-api}), so exactly this record fires (a non-empty
    threat list keeps the zero-threats record out of the delta)."""
    stub_prompt.set_response("s2", json.dumps({
        "system_context": "a web api",
        "assets": [], "trust_boundaries": [],
        "threats": [{
            "id": "T1", "threat": "SQL injection", "actor": "remote_unauth",
            "surface": "POST /search", "asset": "db", "impact": "medium",
            "likelihood": "possible", "controls": "", "evidence": "",
        }],
        "open_questions": [],
    }))
    with status.stage("Step 2 — Threat model", stage_id="s2"):
        tm = s2.run("/nonexistent-repo", "repo", _s2_cfg(baseline="owasp"),
                    [], [])

    assert tm.threats
    assert STAGES.snapshot()["s2"]["outcome"] == "completed_with_errors"
    recs = [r for r in _written_records("s2")
            if r.get("reason") == "baseline_items_undisposed"]
    assert recs and "recovered" not in recs[0]


def test_unrecovered_count_renders_as_unrecovered_not_recoverable(capsys):
    """The wording pin, in isolation: gpt55-oai permanently lost its report
    ranking to an s8 failure and the operator was told the error was
    "recoverable". The ✓-line note counts records logged WITHOUT the
    recovered stamp, so the word must be "unrecovered"."""
    with status.stage("Step 8 — Chain", stage_id="s8"):
        errlog.log("s8", "chain", "empty chain response — report ships unranked")
    assert STAGES.snapshot()["s8"]["outcome"] == "completed_with_errors"
    err = capsys.readouterr().err
    assert "1 unrecovered error(s)" in err and "errors.jsonl" in err
    assert "recoverable" not in err


# ─────────────────────────────────────────────────────────────────────────────
# Layer 3 — the class guard: every _errlog.log call site is classified.
# ─────────────────────────────────────────────────────────────────────────────
#
# The root cause of RCA-D1 was not one missing flag but a missing duty: the
# outcome predicate turned _errlog.log() from "append a diagnostic" into
# "assert this stage degraded, unless flagged", and nothing forced a new call
# site to pick a side. This guard is that review rule made executable: a site
# either passes recovered=True literally, or its key appears below with a
# one-line justification. Keys deliberately carry NO line numbers, so
# ordinary drift never breaks the guard — only adding or reclassifying a
# site does.
#
# Key = (path relative to the repo root, discriminator), where the
# discriminator is the site's first available constant among: reason= kwarg,
# phase= kwarg, scope= kwarg ("scope:<v>"), the unit argument
# ("unit:<v>"), the error-message head ("msg:<first 48 chars>"), else
# "unclassified:<stage>" from the constant stage argument. Several degrading
# sites legitimately share a key (e.g. the four s4 chunk-failure handlers);
# an allowlist is a set of justified shapes, not a per-line census.

DEGRADING_SITES: dict[tuple[str, str], str] = {
    # ── Genuinely degrading, inside a stage window: must stay unmarked so
    #    the completed_with_errors flip fires on real loss. ──
    ("vvaharness/pipeline/stages/s1_autoexclude.py",
     "s1_autoexclude_empty_scope"):
        "model proposed a scope-emptying overlay; the overlay is "
        "discarded so no coverage is lost, but a model that tried to delete "
        "the repo must not be filed as routine — logged before s1's window "
        "opens, so it lands in the err0 snapshot",
    ("vvaharness/pipeline/stages/s1_preprocess.py", "symlink_resolve_failed"):
        "file excluded from scan scope — coverage loss",
    ("vvaharness/pipeline/stages/s1_preprocess.py", "stat_failed"):
        "file excluded from scan scope — coverage loss",
    ("vvaharness/pipeline/stages/s1_preprocess.py",
     "mapper_response_unparseable"):
        "agentic mapping lost; degraded to deterministic inventory",
    ("vvaharness/pipeline/stages/s1_preprocess.py", "s1_zero_output"):
        "S1 contributed nothing — the loss-path backstop that makes stamping "
        "call_graph_edges_rejected safe",
    ("vvaharness/pipeline/stages/s2_threatmodel.py",
     "threat_model_call_failed"):
        "provider call failed; s3–s8 get no threat context",
    ("vvaharness/pipeline/stages/s2_threatmodel.py",
     "threat_model_parse_failed"):
        "unparseable after one repair retry; no threat model at all",
    ("vvaharness/pipeline/stages/s2_threatmodel.py", "unit:threatmodel"):
        "zero threats — deliberate owner decision: real downstream capability "
        "loss, and the only signal separating a vacuous reply from a healthy "
        "run (see the in-code comment)",
    ("vvaharness/pipeline/stages/s2_threatmodel.py",
     "baseline_items_undisposed"):
        "deliverable gap — s3 loses baseline-derived chunk targeting "
        "(deliberate owner decision, see the in-code comment)",
    ("vvaharness/pipeline/stages/s3_decompose.py", "llm_call_failed"):
        "decompose call failed",
    ("vvaharness/pipeline/stages/s3_decompose.py", "chunks_partially_dropped"):
        "chunks lost from the manifest",
    ("vvaharness/pipeline/stages/s3_decompose.py", "response_unusable"):
        "deterministic fallback substituted for the model manifest",
    ("vvaharness/pipeline/stages/s3_decompose.py", "unclassified:s3"):
        "unknown-file-id / non-existent-file drops — scope loss "
        "(two sites of the same shape)",
    ("vvaharness/pipeline/stages/s3_decompose.py",
     "msg:empty chunk after normalization"):
        "derivative of the unmarked drop records above; never fires alone",
    ("vvaharness/pipeline/stages/s4_deepdive.py", "empty_chunk_skipped"):
        "reachable only via a producer that bypassed s3's _drop_empty_chunks "
        "guard — the one path with NO unmarked s3 backstop, so a manifest "
        "slice left analysis; a recovered=True stamp here was reverted "
        "(wave-1 F6, see the in-code comment)",
    ("vvaharness/pipeline/stages/s4_deepdive.py", "scope:chunk"):
        "guardrail-blocked / failed chunk — coverage loss "
        "(four sites of the same shape)",
    ("vvaharness/pipeline/stages/s4_deepdive.py", "scope:run"):
        "a deep-dive run failed",
    ("vvaharness/pipeline/stages/s4_deepdive.py", "scope:item"):
        "non-object / malformed finding dropped",
    ("vvaharness/pipeline/stages/s6_verify.py", "unclassified:s6-verify"):
        "guardrail / batch failure — verdicts lost "
        "(sites of the same shape)",
    ("vvaharness/pipeline/stages/s6_verify.py",
     "msg:no VERDICT line in verifier output after one rep"):
        "unparseable verdict after the repair re-ask — finding disposition "
        "lost",
    ("vvaharness/pipeline/stages/s7_dedup.py", "unit:semantic"):
        "semantic dedup failed; deterministic-only fallback",
    ("vvaharness/pipeline/stages/s7_dedup.py", "unit:semantic-parse"):
        "semantic dedup response unparseable",
    ("vvaharness/pipeline/stages/s8_chain.py", "unit:chain"):
        "chain failure / unparseable — report ships unranked/degraded",
    ("vvaharness/pipeline/stages/s8_chain.py", "unit:chain-hydrate"):
        "hydrate failure — report ships unranked/degraded",
    # ── Outside any stage window: no stage() context is open when these
    #    log, so they can never flip an outcome (verified in FIX-C). ──
    ("vvaharness/injectors/cve_feed.py", "unclassified:inject.cves"):
        "outside any stage window",
    ("vvaharness/injectors/cve_feed.py", "unclassified:inject.cves.item"):
        "outside any stage window",
    ("vvaharness/injectors/design_controls.py",
     "unclassified:inject.controls"):
        "outside any stage window",
    ("vvaharness/orchestrator/batch.py", "unclassified:batch"):
        "outside any stage window (two sites)",
    ("vvaharness/orchestrator/batch.py", "unclassified:batch.clone"):
        "outside any stage window",
    ("vvaharness/orchestrator/entry.py", "unclassified:auth"):
        "outside any stage window",
    ("vvaharness/orchestrator/entry.py", "unclassified:proxy"):
        "outside any stage window",
    ("vvaharness/orchestrator/entry.py", "unclassified:scan"):
        "outside any stage window",
    ("vvaharness/orchestrator/entry.py", "empty_scope"):
        "0 files reached analysis; the run is refused with exit 2 "
        "rather than reported, so there is no stage window left to flip",
    ("vvaharness/orchestrator/scan.py", "unclassified:s1.autoexclude"):
        "logged before s1's window opens; lands in the err0 snapshot",
    ("vvaharness/orchestrator/scan.py", "unclassified:s2"):
        "outer except after the s2 window already closed the stage as error",
    ("vvaharness/orchestrator/scan.py", "unclassified:s10.preflight"):
        "stage marked disabled; its window never opens",
    ("vvaharness/orchestrator/scan.py", "unclassified:s11.preflight"):
        "stage marked disabled; its window never opens",
}

# ponytail: a RECOVERED_WITHOUT_REASON registry (plus its enforcing test,
# test_every_recovered_site_carries_a_machine_readable_reason) used to live
# here, requiring every recovered=True site to also carry a constant reason=.
# Deleted: nothing consumes that convention — the classification guard below
# skips recovered sites BEFORE it discriminates on reason=, so the registry
# had zero readers. reason= remains useful on individual records as a stored
# errors.jsonl field for diagnosis; re-add the convention test only when
# something actually enumerates recovered sites by reason.


def _errlog_call_sites():
    """AST walk (not regex — keyword args must be read reliably) over every
    ``_errlog.log(...)`` / ``errlog.log(...)`` call under vvaharness/."""
    repo_root = PRODUCT_ROOT.parent
    for py in sorted(PRODUCT_ROOT.rglob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "log"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in ("_errlog", "errlog")):
                yield py.relative_to(repo_root).as_posix(), node


def _const_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _discriminator(node: ast.Call) -> str:
    kws = {k.arg: k.value for k in node.keywords if k.arg}
    for name in ("reason", "phase"):
        v = _const_str(kws.get(name))
        if v is not None:
            return v
    v = _const_str(kws.get("scope"))
    if v is not None:
        return f"scope:{v}"
    if len(node.args) >= 2 and (u := _const_str(node.args[1])) is not None:
        return f"unit:{u}"
    if len(node.args) >= 3 and (m := _const_str(node.args[2])) is not None:
        return f"msg:{m[:48]}"
    stage = _const_str(node.args[0]) if node.args else None
    return f"unclassified:{stage or '<dynamic>'}"


def test_every_errlog_call_site_is_classified():
    """The executable review rule: every _errlog.log site either stamps
    recovered=True (informational diagnostic or recovered transient — see
    errlog.log's docstring for which sites may be marked) or appears in
    DEGRADING_SITES with a justification. An unmarked, unlisted site is the
    exact shape that shipped RCA-D1; fail it here, not on a live run."""
    unclassified = []
    for relpath, node in _errlog_call_sites():
        kws = {k.arg: k.value for k in node.keywords if k.arg}
        rec = kws.get("recovered")
        if rec is not None:
            # The stamp must be the literal True: the counter matches
            # `is True` strictly, so a dynamic/falsy value silently degrades
            # to "counts", which is the fail-safe but not what the author
            # of a stamped site intended.
            assert (isinstance(rec, ast.Constant) and rec.value is True), (
                f"{relpath}:{node.lineno}: recovered= must be the literal "
                f"True (the outcome predicate matches `is True` strictly)")
            continue
        key = (relpath, _discriminator(node))
        if key not in DEGRADING_SITES:
            unclassified.append(f"{relpath}:{node.lineno} key={key!r}")
    assert not unclassified, (
        "Unclassified _errlog.log call site(s). Inside a stage window an "
        "unmarked record flips the stage to completed_with_errors — decide "
        "which bin each site belongs to: stamp recovered=True (nothing lost; "
        "designed behaviour whose loss-paths log their own unmarked records) "
        "or add its key to DEGRADING_SITES in this file with a one-line "
        "justification:\n  " + "\n  ".join(unclassified))


def test_no_stale_allowlist_entries():
    """The inverse direction: an allowlist entry whose site no longer exists
    (moved file, renamed reason, site deleted or stamped) must be removed —
    a stale entry is a hole a future unclassified site could fall through."""
    live = set()
    for relpath, node in _errlog_call_sites():
        kws = {k.arg for k in node.keywords if k.arg}
        if "recovered" in kws:
            continue
        live.add((relpath, _discriminator(node)))
    stale = set(DEGRADING_SITES) - live
    assert not stale, f"stale DEGRADING_SITES entries: {sorted(stale)}"
