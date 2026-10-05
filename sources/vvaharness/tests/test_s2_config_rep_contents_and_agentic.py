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

"""Phase-9 s2 behaviour: config-rep CONTENTS and the dark agentic switch.

Covers the two halves of the Spec §13 change to the threat-model stage:

1. Representative config files are packed as redacted, length-capped
   CONTENTS — capped per file at `step2.max_config_rep_chars`, limited to
   the first `step2.max_config_rep_bodies` files (the remainder stays
   path-only), redacted through `report.redact` before any prompt sees
   them, and still subject to `_read_capped`'s repo-root containment.

2. `step2.agentic` (default false) swaps `prompt()` for `agentic()`. The
   default path must be byte-identical to today (prompt() called, agentic()
   never); the agentic path must forward `allowed_tools`/`max_turns` and
   must NOT forward `max_tokens`/`temperature` (the registry discards
   extras and each agentic route applies its own output ceiling — see
   `_threatmodel_call`'s docstring). The allowlist guard is via-aware,
   exactly as s1/s6: `via: cli` honours the allowlist verbatim (Bash there
   is a shipped, documented capability); on `via: sdk` a mutating tool
   would delegate to the Agent SDK backend and silently enable repo
   mutation during a detection stage, so sdk/openai/deepagents stay
   read-only.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from fixtures.ctx_builders import make_ctx

from vvaharness.pipeline.stages import s2_threatmodel


def _valid_response() -> str:
    """A minimal, schema-valid threat-model JSON body."""
    return json.dumps({
        "system_context": "test system context",
        "assets": [{"name": "a", "sensitivity": "high"}],
        "trust_boundaries": [{"entry_point": "ep", "crossing": "x",
                              "reachable_assets": ["a"]}],
        "threats": [{"id": "T1", "threat": "t", "actor": "remote_unauth",
                     "surface": "ep", "asset": "a", "impact": "high",
                     "likelihood": "possible"}],
        "open_questions": [],
    })


def _cfg(**step2_kwargs: Any) -> SimpleNamespace:
    """A minimal stage config in the shape run() expects."""
    return SimpleNamespace(
        step2=SimpleNamespace(baseline="none", **step2_kwargs),
        models=SimpleNamespace(threatmodel="stub-model"),
    )


class _AgenticRecorder:
    """Callable stand-in for the agentic dispatch seam
    (`_deepagents.dispatch_agentic`), recording every call it receives."""

    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def __call__(self, user_prompt: str, *, model: Any = None, **kw: Any) -> str:
        self.calls.append({"prompt": user_prompt, "model": model, "kw": dict(kw)})
        return self.response


# ─────────────────────────────────────────────────────────────────────────────
# Part 1 — config-rep contents: packed, capped, limited, redacted, contained
# ─────────────────────────────────────────────────────────────────────────────

def test_config_rep_contents_are_packed_into_the_prompt(tmp_path):
    (tmp_path / "application.yml").write_text(
        "datasource:\n  url: jdbc:postgresql://db.internal:5432/orders\n",
        encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["application.yml"])
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, ctx)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [])
    assert "=== application.yml ===" in text
    assert "jdbc:postgresql://db.internal:5432/orders" in text


def test_config_rep_body_is_capped_at_max_config_rep_chars(tmp_path):
    (tmp_path / "big.yml").write_text("k: " + "v" * 5000, encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["big.yml"])
    cfg = SimpleNamespace(step2=SimpleNamespace(max_config_rep_chars=100))
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, ctx)
    bodies = dict(ev["config_reps"])
    assert "…(truncated" in bodies["big.yml"]
    # The cap plus the fixed truncation suffix bounds the body.
    assert len(bodies["big.yml"]) < 100 + 50


def test_only_max_config_rep_bodies_files_get_contents_rest_are_path_only(tmp_path):
    files = []
    for i in range(4):
        d = tmp_path / f"svc{i}"
        d.mkdir()
        (d / "config.yml").write_text(f"marker_{i}: value_{i}_body\n",
                                      encoding="utf-8")
        files.append(f"svc{i}/config.yml")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=files)
    cfg = SimpleNamespace(step2=SimpleNamespace(max_config_rep_bodies=2))
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, ctx)
    reps = ev["config_reps"]
    assert len(reps) == 4
    with_body = [rel for rel, body in reps if body]
    without_body = [rel for rel, body in reps if not body]
    assert len(with_body) == 2
    assert len(without_body) == 2
    # The remainder is still LISTED, path-only, in the rendered prompt.
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [])
    for rel in without_body:
        assert f"  - {rel}" in text
        assert f"=== {rel} ===" not in text


def test_secret_in_a_config_rep_never_reaches_the_prompt_verbatim(tmp_path):
    """The highest-value assertion in this file: config bodies are the one
    place s2 now egresses raw config content, and they must pass through
    `report.redact` before any prompt is built."""
    secret = "sUp3r-s3cret-DB-value-9911"
    (tmp_path / "app.yml").write_text(
        f"db:\n  password: {secret}\n", encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["app.yml"])
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, ctx)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [])
    assert secret not in text
    assert "[REDACTED-SECRET]" in text


def test_secret_straddling_the_cap_boundary_leaks_no_fragment(tmp_path):
    """Redaction must run BEFORE the per-file cap. Truncating first bisects
    a secret at the cap boundary: with cap=30, the raw prefix ends mid-key
    (`ANTHROPIC_API_KEY="sk-ant-abcd`), the fragment matches no redaction
    pattern, and a partial credential egresses under a header advertising
    the content as redacted. Redact-then-cap masks the whole key and then
    harmlessly truncates inside the placeholder."""
    secret = "sk-ant-abcdefghijklmnopqrstuvwxyz1234567890"
    (tmp_path / "app.yml").write_text(
        f'ANTHROPIC_API_KEY="{secret}"\n', encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["app.yml"])
    cfg = SimpleNamespace(step2=SimpleNamespace(max_config_rep_chars=30))
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, ctx)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [])
    assert secret not in text
    # The exact fragment the old truncate-then-redact order egressed …
    assert "sk-ant-abcd" not in text
    # … and a distinctive interior slice, in case the cut point drifts.
    assert "abcdefghij" not in text
    # The masked, then-truncated body is still packed and still announces
    # the truncation.
    body = dict(ev["config_reps"])["app.yml"]
    assert "[REDACTED-" in body
    assert "…(truncated" in body


def test_config_rep_symlink_escaping_the_repo_root_is_not_read(tmp_path):
    """Containment holds for config-rep bodies exactly as it does for docs:
    `_read_capped` refuses the escaping target, and the entry degrades to
    path-only rather than leaking host content."""
    outside = tmp_path / "outside.yml"
    escape_marker = "HOST-ONLY-CONFIG-MARKER-1337"
    outside.write_text(f"leak: {escape_marker}\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "evil.yml").symlink_to(outside)
    ctx = make_ctx(repo_root=str(root), all_files=["evil.yml"])
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(root), cfg, ctx)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [])
    assert escape_marker not in text
    assert "  - evil.yml" in text          # still listed, path-only


def test_config_rep_header_no_longer_overclaims(tmp_path):
    """The prompt header must describe what is actually sent: contents for
    the entries carrying a per-file header, names only for the rest."""
    ctx = make_ctx(repo_root=str(tmp_path), all_files=[])
    cfg = SimpleNamespace(step2=SimpleNamespace())
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, ctx)
    text = s2_threatmodel._build_user_prompt("fixture-repo", ev, [], [])
    assert "REPRESENTATIVE CONFIGURATION" in text
    assert "redacted, length-capped file contents" in text
    assert "present by name only" in text


def test_config_rep_chars_zero_means_no_bodies(tmp_path):
    """`0` survives `_cap_int` as a legitimate operator choice: emit no
    bodies at all, keeping the block path-only as it was before Phase 9."""
    (tmp_path / "c.yml").write_text("k: value-that-must-not-appear\n",
                                    encoding="utf-8")
    ctx = make_ctx(repo_root=str(tmp_path), all_files=["c.yml"])
    cfg = SimpleNamespace(step2=SimpleNamespace(max_config_rep_chars=0))
    ev = s2_threatmodel._gather_evidence(str(tmp_path), cfg, ctx)
    assert dict(ev["config_reps"])["c.yml"] == ""


# ─────────────────────────────────────────────────────────────────────────────
# Part 2 — the agentic switch, shipped dark
# ─────────────────────────────────────────────────────────────────────────────

def test_agentic_false_default_calls_prompt_and_never_agentic(stub_prompt, monkeypatch):
    recorder = _AgenticRecorder(_valid_response())
    monkeypatch.setattr(s2_threatmodel._deepagents, "dispatch_agentic",
                        recorder, raising=True)
    s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])
    assert recorder.calls == []
    assert stub_prompt.calls, "the single-shot prompt() path must still run"
    kw = stub_prompt.calls[-1]["kw"]
    # Byte-identical to today: same kwargs the pre-Phase-9 call carried.
    assert kw["max_tokens"] == 16000
    assert kw["timeout"] == 1800
    assert kw["tag"] == "s2 threatmodel"


def test_agentic_true_calls_agentic_with_tools_and_turns_not_tokens(stub_prompt, monkeypatch):
    recorder = _AgenticRecorder(_valid_response())
    monkeypatch.setattr(s2_threatmodel._deepagents, "dispatch_agentic",
                        recorder, raising=True)
    tm = s2_threatmodel.run("/nonexistent-repo", "repo",
                            _cfg(agentic=True), [], [])
    assert len(recorder.calls) == 1
    assert stub_prompt.calls == [], "no prompt() call on a clean agentic run"
    kw = recorder.calls[0]["kw"]
    assert kw["allowed_tools"] == ["Read", "Glob", "Grep"]
    assert kw["max_turns"] == 12
    assert kw["cwd"] == "/nonexistent-repo"
    # agentic() has no max_tokens kwarg (each route applies its own output
    # ceiling) and registry.agentic() discards temperature.
    assert "max_tokens" not in kw
    assert "temperature" not in kw
    assert "max_budget_usd" not in kw      # no-op on sdk/openai; not advertised
    assert tm.threats, "the parsed threat model must come from the agentic raw"


def test_agentic_true_forwards_configured_tools_and_turns(monkeypatch):
    recorder = _AgenticRecorder(_valid_response())
    monkeypatch.setattr(s2_threatmodel._deepagents, "dispatch_agentic",
                        recorder, raising=True)
    s2_threatmodel.run("/nonexistent-repo", "repo",
                       _cfg(agentic=True, allowed_tools=["Read"], max_turns=5),
                       [], [])
    kw = recorder.calls[0]["kw"]
    assert kw["allowed_tools"] == ["Read"]
    assert kw["max_turns"] == 5


def test_agentic_system_prompt_gains_exactly_the_one_tool_line(monkeypatch):
    recorder = _AgenticRecorder(_valid_response())
    monkeypatch.setattr(s2_threatmodel._deepagents, "dispatch_agentic",
                        recorder, raising=True)
    s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(agentic=True), [], [])
    sysp = recorder.calls[0]["kw"]["system_prompt"]
    assert sysp == s2_threatmodel.SYSTEM + s2_threatmodel._AGENTIC_SYSTEM_LINE
    assert "read-only tools (Read, Glob, Grep)" in sysp


def test_single_shot_system_prompt_does_not_carry_the_tool_line(stub_prompt):
    s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])
    assert stub_prompt.calls[-1]["kw"]["system_prompt"] == s2_threatmodel.SYSTEM


def test_agentic_true_with_deepagents_via_routes_to_the_dispatch_seam(
        stub_prompt, monkeypatch):
    """`step2.agentic: true` with `via: deepagents` is a SERVED combination
    now: the harness module implements `agentic()`, and the stage routes
    every agentic call through `_deepagents.dispatch_agentic`, whose
    deepagents branch reaches it. The old use-site ValueError guard — which
    existed because the deleted adapter had no agentic() seam — is gone; the
    deepagents role must reach the seam, never `registry.agentic` (the
    registry has no deepagents backend and would raise `Unknown backend`)."""
    recorder = _AgenticRecorder(_valid_response())
    monkeypatch.setattr(s2_threatmodel._deepagents, "dispatch_agentic",
                        recorder, raising=True)
    cfg = SimpleNamespace(
        step2=SimpleNamespace(baseline="none", agentic=True),
        models=SimpleNamespace(
            threatmodel=SimpleNamespace(id="some-model", via="deepagents")),
    )
    tm = s2_threatmodel.run("/nonexistent-repo", "repo", cfg, [], [])
    assert len(recorder.calls) == 1
    kw = recorder.calls[0]["kw"]
    assert recorder.calls[0]["model"] is cfg.models.threatmodel
    assert kw["cwd"] == "/nonexistent-repo"
    assert kw["cfg"] is cfg
    assert kw["tag"] == "s2 threatmodel"
    assert stub_prompt.calls == [], "no prompt()-shaped call on an agentic run"
    assert tm.threats, "the parsed threat model must come from the agentic raw"


# ── the allowlist guard ───────────────────────────────────────────────────────

def _via_cfg(via: str, **step2_kwargs: Any) -> SimpleNamespace:
    """Like `_cfg`, but with an explicit `via` on the threatmodel model node
    (a bare string model resolves to the default via, `cli`)."""
    return SimpleNamespace(
        step2=SimpleNamespace(baseline="none", **step2_kwargs),
        models=SimpleNamespace(
            threatmodel=SimpleNamespace(id="stub-model", via=via)),
    )


def test_allowlist_guard_fires_through_run_and_threads_the_resolved_via(monkeypatch):
    """The stage-specific WIRING pin (the guard's own truth table — per-via
    rejections, the cli exemption, the default trio, YAML-shape errors — is
    pinned once in tests/test_backend_llm.py):

    1. Rejection half: a mutating tool on a strict via aborts run() BEFORE
       any dispatch, naming the stage key `step2.allowed_tools`.
    2. Acceptance half — REGRESSION: s2 called the shared guard without
       threading the resolved via, so the strict read-only rule always
       applied and a valid `via: cli` + `step2.agentic: true` + `[Read,
       Bash]` profile aborted the whole scan at S2 — a config s1 and s6
       accept, and Bash on `via: cli` is a shipped, documented capability.
       The same allowlist must reach the dispatch seam verbatim.
    """
    recorder = _AgenticRecorder(_valid_response())
    monkeypatch.setattr(s2_threatmodel._deepagents, "dispatch_agentic",
                        recorder, raising=True)

    with pytest.raises(ValueError, match="step2.allowed_tools"):
        s2_threatmodel.run(
            "/nonexistent-repo", "repo",
            _via_cfg("sdk", agentic=True, allowed_tools=["Read", "Bash"]), [], [])
    assert recorder.calls == [], "no agentic call may precede the guard"

    tm = s2_threatmodel.run(
        "/nonexistent-repo", "repo",
        _via_cfg("cli", agentic=True, allowed_tools=["Read", "Bash"]), [], [])
    assert len(recorder.calls) == 1
    assert recorder.calls[0]["kw"]["allowed_tools"] == ["Read", "Bash"]
    assert tm.threats


# ── parser tolerance of tool-use chatter ─────────────────────────────────────

def test_parse_threat_model_survives_tool_use_chatter_around_the_json():
    raw = (
        "I'll examine the config files first.\n"
        "[tool_use: Read svc/application.yml]\n"
        "[tool_result: datasource url found]\n"
        "Based on that, here is the threat model:\n"
        + _valid_response()
        + "\nThat completes my analysis."
    )
    tm = s2_threatmodel._parse_threat_model(raw)
    assert [t.id for t in tm.threats] == ["T1"]
    assert tm.trust_boundaries[0].entry_point == "ep"


def test_oversize_config_body_is_path_only_not_truncated(tmp_path):
    """REGRESSION: the raw read ceiling truncated BEFORE redact(), so a secret
    straddling it was bisected and its unmatched prefix egressed under a header
    advertising the content as redacted. An oversize file must go path-only.
    """
    root = tmp_path
    rel = "application.properties"
    # A private-key blob that redaction collapses to one placeholder, then a
    # secret positioned past the ceiling -- the shape that leaked a prefix.
    ceiling = s2_threatmodel._CONFIG_REP_RAW_CEILING
    blob = "-----BEGIN PRIVATE KEY-----\n" + ("QUJDREVG" * 8 + "\n") * 8000 \
           + "-----END PRIVATE KEY-----\n"
    tail = "aws_id = AKIAIOSFODNN7EXAMPLE\n"
    (root / rel).write_text("server.port=8443\n" + blob + tail, encoding="utf-8")
    assert len((root / rel).read_text()) > ceiling, "fixture must exceed the ceiling"

    reps = s2_threatmodel._config_rep_contents(root, [rel], cap_chars=2000, max_bodies=12)
    (emitted_rel, body), = reps
    assert emitted_rel == rel          # breadth view keeps the path...
    assert body == ""                  # ...but no body at all
    # Nothing from the file reached the caller -- in particular no key prefix.
    assert "AKIA" not in body and "BEGIN PRIVATE KEY" not in body


def test_undersize_config_body_is_still_read_and_redacted(tmp_path):
    """The whole_or_nothing guard must not suppress ordinary bodies."""
    root = tmp_path
    rel = "app.yml"
    (root / rel).write_text("url: https://db\naws_id: AKIAIOSFODNN7EXAMPLE\n",
                            encoding="utf-8")
    (_rel, body), = s2_threatmodel._config_rep_contents(root, [rel], cap_chars=2000,
                                           max_bodies=12)
    assert "url: https://db" in body          # content present
    assert "AKIAIOSFODNN7EXAMPLE" not in body   # secret masked


# ── the permanent-parse-failure errlog record ─────────────────────────────────
#
# When both the primary parse and the one repair retry fail, run() errlogs the
# head of the final unparseable text as raw_head=<text>[:500]. errlog redacts
# its string fields INTERNALLY, but only after receiving them — so the slice
# must be taken from redact()ed-while-WHOLE text. A key straddling the [:500]
# cut is bisected by truncate-first, matches no pattern, and lands in
# errors.jsonl unmasked. (A key entirely inside the window is masked under
# both orderings and proves nothing.)

def test_parse_failure_errlog_head_redacts_a_key_straddling_the_cut(stub_prompt):
    from vvaharness.report.redact import redact
    from vvaharness.util import errlog

    secret = "AKIATESTKEYLEAK00042"          # canonical 20-char AWS key id
    # Guard the fixture: an 18-char "key" matches no pattern and would make
    # this test pass for the wrong reason.
    assert len(secret) == 20 and secret not in redact(secret)
    cut, before = 500, 14
    start = cut - before                     # 14 chars before the cut, 6 after
    # Space-separated: glued padding defeats the pattern's word boundary.
    raw = "x" * (start - 1) + " " + secret + " " + "y" * 40
    assert raw.index(secret) == start
    assert start < cut < start + len(secret) and cut - start >= 12  # straddles

    # The stub keys on the tag's first word, so the primary call AND the
    # json-repair retry both return the same unparseable text → permanent
    # failure → the errlog record, then the re-raise.
    stub_prompt.set_response("s2", raw)
    with pytest.raises(Exception):
        s2_threatmodel.run("/nonexistent-repo", "repo", _cfg(), [], [])

    logged = (errlog.current_path().read_text(encoding="utf-8")
              if errlog.current_path().exists() else "")
    assert "threat_model_parse_failed" in logged   # the record was written
    for i in range(len(secret) - 11):
        w = secret[i:i + 12]
        assert w not in logged, f"key fragment {w!r} reached errors.jsonl"
