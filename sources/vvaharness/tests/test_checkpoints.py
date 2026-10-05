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

"""Unit tests for vvaharness.orchestrator.checkpoints — SQLite-backed
checkpoint I/O. Every legitimate per-step payload must round-trip (no
--resume regression), and a hostile or malformed payload must degrade to
"re-run the step" rather than crash or be trusted.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from vvaharness.models import (
    ContextPackage,
    DroppedFinding,
    EntryPoint,
    FinalReport,
    Finding,
    RankedFinding,
    Severity,
    Sink,
    TaskManifest,
    ThreatModel,
)
from vvaharness.orchestrator import checkpoints as ck
from vvaharness.orchestrator import store
from vvaharness.pipeline.stages.s0_seed import SeedPackage

RID = "testrun"


@pytest.fixture(autouse=True)
def _state_dir(tmp_path, monkeypatch):
    """Every test gets a fresh, isolated state DB under tmp_path.

    ``prune_stale_steps`` remembers what it has already pruned for the life of the process, so
    that memory is cleared too — otherwise the second test to prune a run would silently no-op.
    """
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path))
    ck._PRUNED.clear()
    yield tmp_path
    ck._PRUNED.clear()


def _raw_insert(run_id: str, step: str, payload: bytes) -> None:
    """Bypass save_ckpt's serialisation to plant arbitrary bytes — used by
    the malformed/tampered tests."""
    con = store.connect()
    with con:
        con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) "
                    "VALUES (?, '')", (run_id,))
        con.execute("INSERT OR REPLACE INTO checkpoints"
                    "(run_id, step, payload, size) VALUES (?, ?, ?, ?)",
                    (run_id, step, payload, len(payload)))
    con.close()


def _finding() -> Finding:
    return Finding(chunk_id="c1", file="a.py", line_start=1, line_end=2,
                   vuln_class="other", title="t", description="d",
                   code_snippet="x=1", confidence=0.5)


def _dropped() -> DroppedFinding:
    return DroppedFinding(file="a.py", line=1, vuln_class="other",
                           title="t", chunk_id="c1", reason="DUPLICATE")


@pytest.mark.parametrize("step,obj", [
    ("s1", ContextPackage(repo_root="/r", language="python",
                          all_files=["a.py"], notes="n")),
    ("s2", ThreatModel(system_context="sc", open_questions=["q"])),
    ("s3", TaskManifest(chunks=[], rationale="why")),
    ("s4", {"findings": [_finding()], "outcomes": {"c1": "ok"}}),
    ("s5", {"findings": [_finding()], "pre_dropped": [_dropped()]}),
    ("s6", {"verified": [_finding()], "dropped": [_dropped()]}),
    ("s7", ([_dropped()], [_finding()], [_dropped()], [_finding()],
            [_dropped()])),
    ("s8", FinalReport(repo_root="/r", summary="s", raw_findings_count=1,
                       chains=[],
                       findings=[RankedFinding(finding=_finding(),
                                               severity=Severity.LOW,
                                               exploitability_notes="e")])),
    ("s9", "/out/report.sarif"),
])
def test_checkpoint_roundtrips_legit_payloads(tmp_path, step, obj):
    ck.save_ckpt(tmp_path, RID, step, obj)
    # Stored payload is JSON.
    con = store.connect()
    raw = con.execute("SELECT payload FROM checkpoints WHERE run_id=? "
                      "AND step=?", (RID, step)).fetchone()[0]
    con.close()
    json.loads(raw)
    got = ck.load_ckpt(tmp_path, RID, step)
    assert got is not None and type(got) is type(obj)
    assert got == obj


def _populated_seed() -> SeedPackage:
    """A SeedPackage with the call-graph / def-span maps filled and a Path
    ``sarif_path`` — the structures that carry the s0 checkpoint's real
    payload."""
    return SeedPackage(
        entry_points=[EntryPoint(file="ctrl.py", function="handle",
                                 kind="network", reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file="dao.py", line=40, function="raw_query")],
        taint_paths=[["ctrl.py:10", "dao.py:40"]],
        rule_cwe={"py.sqli": ["CWE-89"]},
        call_graph={"ctrl.py::handle": ["dao.py::raw_query"]},
        call_graph_files={"handle": ["ctrl.py:10"],
                          "raw_query": ["dao.py:40"]},
        def_spans={"ctrl.py::handle": [10, 20],
                   "dao.py::raw_query": [40, 45]},
        sarif_path=Path("/out/seed.sarif"),
        languages=["python"],
        all_files=["ctrl.py", "dao.py"],
    )


def test_s0_seedpackage_roundtrips_populated(tmp_path):
    """A *populated* SeedPackage must survive the s0 checkpoint round-trip so
    ``--resume`` can skip Step 0. Every persisted map is keyed by a JSON
    object key (a string); a non-JSON-native key (e.g. a ``dict`` keyed by a
    tuple) would ``dump_json`` to a comma-joined string that ``validate_json``
    cannot rebuild, so ``load_ckpt`` would return ``None`` and this test would
    fail on the ``got is not None`` / ``got == seed`` assertions."""
    seed = _populated_seed()
    ck.save_ckpt(tmp_path, RID, "s0", seed)
    # Stored payload is JSON, and every checkpointed dict uses string keys.
    con = store.connect()
    raw = con.execute("SELECT payload FROM checkpoints WHERE run_id=? "
                      "AND step=?", (RID, "s0")).fetchone()[0]
    con.close()
    doc = json.loads(raw)
    for field_name in ("call_graph", "call_graph_files", "def_spans",
                       "rule_cwe"):
        assert all(isinstance(k, str) for k in doc[field_name])
    got = ck.load_ckpt(tmp_path, RID, "s0")
    assert got is not None and type(got) is SeedPackage
    assert got == seed


def test_checkpoint_refuses_malformed_payload(capsys):
    """Non-JSON / corrupt bytes degrade to "re-run", never crash."""
    _raw_insert(RID, "s7", b"\x00not-json\xff")
    assert ck.load_ckpt(None, RID, "s7") is None
    assert "untrusted" in capsys.readouterr().err


@pytest.mark.parametrize(("step", "payload"), [
    ("s5", {"findings": "not-a-list", "pre_dropped": []}),
    ("s6", {"verified": [], "dropped": "not-a-list"}),
])
def test_s5_s6_checkpoint_refuses_wrong_shape(step, payload):
    _raw_insert(RID, step, json.dumps(payload).encode())

    assert ck.load_ckpt(None, RID, step) is None


def test_tampered_field_fails_validation():
    """Well-formed JSON whose value violates a field validator (list[str]
    field set to a scalar) must be rejected by validate_json — the stage
    re-runs rather than receiving a poisoned object."""
    ctx = ContextPackage(repo_root="/r", language="python",
                         all_files=["a.py"], notes="n")
    doc = json.loads(ctx.model_dump_json())
    doc["all_files"] = "$(touch /tmp/pwned)"
    _raw_insert(RID, "s1", json.dumps(doc).encode())
    assert ck.load_ckpt(None, RID, "s1") is None


def test_oversized_checkpoint_is_refused(monkeypatch, capsys):
    """A payload larger than _CKPT_MAX_BYTES is refused at save time —
    guards against multi-GB resource-exhaustion blobs. Verified by
    shrinking the cap and saving a long-but-valid s9 string."""
    monkeypatch.setattr(ck, "_CKPT_MAX_BYTES", 32)
    ck.save_ckpt(None, RID, "s9", "x" * 2048)
    assert "not persisted" in capsys.readouterr().err
    assert ck.load_ckpt(None, RID, "s9") is None


def test_oversized_row_rejected_by_check_constraint():
    """Defence-in-depth: a direct INSERT that bypasses save_ckpt and lies
    about size still cannot exceed the schema CHECK."""
    import sqlite3
    con = store.connect()
    with pytest.raises(sqlite3.IntegrityError):
        with con:
            con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) "
                        "VALUES (?, '')", (RID,))
            con.execute("INSERT INTO checkpoints(run_id, step, payload, size)"
                        " VALUES (?, 's9', ?, ?)",
                        (RID, b"x", 120 * 1024 * 1024))
    con.close()


def test_no_pickle_import():
    """CWE-502 regression guard: the checkpoints module must never reach
    ``import pickle`` again — JSON is the only payload format. Checked via
    AST so the docstring's prose mention doesn't false-positive."""
    import ast

    import vvaharness.orchestrator.checkpoints as m
    tree = ast.parse(open(m.__file__, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(a.name != "pickle" for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "pickle"


def test_store_bootstrap_idempotent(tmp_path, monkeypatch):
    """connect() creates the DB on first call and skips DDL thereafter —
    no "is this the first time?" branch needed at any call site, and the
    hot path never touches executescript()."""
    p = store.db_path()
    assert p.parent == tmp_path
    assert not p.exists()
    store.connect().close()
    assert p.exists()
    # Second open: user_version already set → _migrate must NOT run.
    called = []
    monkeypatch.setattr(store, "_migrate",
                        lambda *a, **k: called.append(1))
    con = store.connect()
    assert called == []
    assert con.execute("PRAGMA user_version").fetchone()[0] \
        == store._SCHEMA_VERSION
    con.close()


def test_store_connection_pragmas():
    """Concurrency/durability best-practice pragmas are applied on every
    connection (per-connection ones) and persisted (per-DB ones)."""
    con = store.connect()
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert con.execute("PRAGMA synchronous").fetchone()[0] == 1   # NORMAL
    assert con.execute("PRAGMA auto_vacuum").fetchone()[0] == 2   # INCREMENTAL
    assert con.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
    con.close()


def test_register_run_upsert():
    store.register_run(RID, repo_root="/r1", repo_name="m", app_id="A1")
    store.register_run(RID, repo_root="/r2", repo_name="m2", app_id="A2")
    con = store.connect()
    row = con.execute("SELECT repo_root, repo_name, app_id FROM runs "
                      "WHERE run_id=?", (RID,)).fetchone()
    con.close()
    assert row == ("/r2", "m2", "A2")


def test_prune_checkpoints():
    """gc keeps the newest N, drops the rest, and deletes anything past the
    age cutoff regardless of count. dry_run reports without deleting; ON
    DELETE CASCADE removes the per-step blobs with the run row."""
    con = store.connect()
    with con:
        # 4 runs: r0 newest … r3 oldest (10 days old)
        for i, age in enumerate([0, 1, 2, 10]):
            con.execute(
                "INSERT INTO runs(run_id, repo_root, started_at, updated_at)"
                " VALUES (?, '', datetime('now', ?), datetime('now', ?))",
                (f"r{i}", f"-{age} days", f"-{age} days"))
            con.execute(
                "INSERT INTO checkpoints(run_id, step, payload, size) "
                "VALUES (?, 's1', ?, 2)", (f"r{i}", b"{}"))
    con.close()

    # dry-run: nothing removed; "kept" reports the post-gc count, not total
    r = ck.prune_checkpoints(keep_runs=2, max_age_days=5, dry_run=True)
    assert set(r["deleted"]) == {"r2", "r3"} and r["kept"] == 2
    con = store.connect()
    assert con.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 4
    con.close()

    # real run: keep newest 2; r3 also fails age (10d > 5d)
    r = ck.prune_checkpoints(keep_runs=2, max_age_days=5)
    assert set(r["deleted"]) == {"r2", "r3"} and r["kept"] == 2
    con = store.connect()
    left_runs = {x[0] for x in con.execute("SELECT run_id FROM runs")}
    left_ckpt = {x[0] for x in con.execute("SELECT run_id FROM checkpoints")}
    con.close()
    assert left_runs == {"r0", "r1"}
    assert left_ckpt == {"r0", "r1"}   # CASCADE fired


def test_prune_checkpoints_no_root(tmp_path, monkeypatch):
    """No DB yet → prune is a no-op (creates an empty one), not an error."""
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "fresh"))
    r = ck.prune_checkpoints(keep_runs=100, max_age_days=5)
    assert r["kept"] == 0 and r["deleted"] == []


def test_step_key_routes_to_the_right_adapter():
    """The prefix stays in plaintext so ``_schema_for`` can still resolve a hashed key."""
    rem = ck.step_key_for(ck.REMEDIATE_PREFIX, engine_id="e", engine_version="1",
                          case_id="vvaf1_a")
    assert rem.startswith("remediate_")
    assert ck._schema_for(rem) is ck._REMEDIATE_STEP_SCHEMA
    val = ck.step_key_for(ck.VALIDATE_PREFIX, engine_id="e", engine_version="1",
                          case_id="vvaf1_a")
    assert val.startswith("validate_")
    assert ck._schema_for(val) is ck._validate_schema()


def test_step_key_is_stable_and_case_scoped():
    """Same engine + same case is the same row; a different case is a different row."""
    args = {"engine_id": "vvaharness.agentic", "engine_version": "1.2.0"}
    first = ck.step_key_for(ck.VALIDATE_PREFIX, case_id="vvaf1_a", **args)
    assert first == ck.step_key_for(ck.VALIDATE_PREFIX, case_id="vvaf1_a", **args)
    assert first != ck.step_key_for(ck.VALIDATE_PREFIX, case_id="vvaf1_b", **args)


@pytest.mark.parametrize("over", [
    {"engine_id": "other.engine"},
    {"engine_version": "2.0.0"},
])
def test_a_different_engine_cannot_load_the_previous_engines_row(over):
    """Engine identity is IN THE KEY.

    It used to be in neither the key nor the guard, so swapping engines and passing --resume
    loaded the prior engine's row and republished its verdict as this run's.
    """
    base = {"engine_id": "vvaharness.agentic", "engine_version": "1.2.0",
            "case_id": "vvaf1_a"}
    mine = ck.step_key_for(ck.REMEDIATE_PREFIX, **base)
    theirs = ck.step_key_for(ck.REMEDIATE_PREFIX, **{**base, **over})
    assert mine != theirs
    ck.save_ckpt(None, RID, mine, {"kind": "edits_applied"})
    assert ck.load_ckpt(None, RID, theirs) is None


def test_step_key_tolerates_an_unstamped_provenance():
    """``Provenance()`` defaults to empty strings and an unstamped attempt is legal."""
    assert ck.step_key_for(ck.REMEDIATE_PREFIX, engine_id="", engine_version="",
                           case_id="vvaf1_a").startswith("remediate_")


def test_step_key_refuses_an_unroutable_prefix():
    """A key ``_schema_for`` could not route would surface as a KeyError deep in a load."""
    with pytest.raises(ValueError, match="unknown dynamic checkpoint prefix"):
        ck.step_key_for("bogus_", engine_id="e", engine_version="1", case_id="c")


def test_prune_stale_steps_drops_only_unclaimed_rows_of_that_prefix(capsys):
    """Standalone remediate/validate never call reset_run, so their rows linger forever.

    Pruning must leave the fixed pipeline steps and the other dynamic family untouched.
    """
    ck.save_ckpt(None, RID, "s9", "/tmp/r.sarif")
    ck.save_ckpt(None, RID, "remediate_live", {"a": 1})
    ck.save_ckpt(None, RID, "remediate_stale", {"a": 1})
    _raw_insert(RID, "validate_other_family", b"{}")

    removed = ck.prune_stale_steps(RID, ck.REMEDIATE_PREFIX, ["remediate_live"])

    assert removed == ["remediate_stale"]
    assert "pruned 1 stale remediate_* checkpoint row(s)" in capsys.readouterr().err
    con = store.connect()
    left = {r[0] for r in con.execute("SELECT step FROM checkpoints WHERE run_id=?", (RID,))}
    con.close()
    assert left == {"s9", "remediate_live", "validate_other_family"}


def test_prune_stale_steps_runs_once_per_process(capsys):
    """Safe to call from a per-case loop: only the first call for a (run, prefix) acts."""
    ck.save_ckpt(None, RID, "remediate_stale", {"a": 1})
    assert ck.prune_stale_steps(RID, ck.REMEDIATE_PREFIX, []) == ["remediate_stale"]
    capsys.readouterr()
    ck.save_ckpt(None, RID, "remediate_other", {"a": 1})
    assert ck.prune_stale_steps(RID, ck.REMEDIATE_PREFIX, []) == []
    assert "pruned" not in capsys.readouterr().err


def test_prune_stale_steps_silent_when_nothing_is_stale(capsys):
    ck.save_ckpt(None, RID, "remediate_live", {"a": 1})
    capsys.readouterr()
    assert ck.prune_stale_steps(RID, ck.REMEDIATE_PREFIX, ["remediate_live"]) == []
    assert "pruned" not in capsys.readouterr().err


def _ctx_with_graph() -> ContextPackage:
    return ContextPackage(
        repo_root="/r",
        language="python",
        all_files=["ctrl.py", "dao.py"],
        entry_points=[EntryPoint(file="ctrl.py", function="handle",
                                 kind="network", reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file="dao.py", line=40, function="raw_query")],
        call_graph={"ctrl.py::handle": ["dao.py::raw_query"]},
        call_graph_files={
            "handle": ["ctrl.py:10"],
            "raw_query": ["dao.py:40"],
        },
        def_spans={
            "ctrl.py::handle": [10, 20],
            "dao.py::raw_query": [40, 45],
        },
    )


# State-DB permissions — the DB holds ContextPackage/checkpoint payloads,
# i.e. scanned-source snippets; it used to land at the umask default (0644,
# world-readable). Owner-only modes are asserted here; anything permission-
# related must degrade to a warning, never crash a scan.

posix_only = pytest.mark.skipif(os.name != "posix",
                                reason="POSIX file modes only")


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


@pytest.fixture(autouse=True)
def _fresh_perm_warnings():
    """_warn_once() is once-per-path-per-process; clear between tests."""
    store._PERM_WARNED.clear()
    yield
    store._PERM_WARNED.clear()


@posix_only
def test_new_db_and_state_dir_created_owner_only(tmp_path, monkeypatch):
    root = tmp_path / "fresh-state"
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(root))
    store.connect().close()
    assert _mode(root) == 0o700
    assert _mode(root / "vvaharness.db") == 0o600


@posix_only
def test_preexisting_world_readable_db_and_sidecars_tightened_on_open():
    store.connect().close()
    p = store.db_path()
    os.chmod(p, 0o644)                     # legacy release left it open
    wal = p.with_name(p.name + "-wal")     # lingering sidecar from a crash,
    wal.write_bytes(b"")                   # same payload bytes as the DB
    os.chmod(wal, 0o644)
    con = store.connect()
    try:
        # asserted while the connection is open — SQLite may checkpoint and
        # remove the WAL on close, but the tightening happens at open.
        assert _mode(p) == 0o600
        assert _mode(wal) == 0o600
    finally:
        con.close()


@posix_only
def test_chmod_failure_warns_once_and_never_crashes(monkeypatch, capsys):
    store.connect().close()
    p = store.db_path()
    os.chmod(p, 0o644)

    def deny(path, mode):
        raise PermissionError("operation not permitted")
    monkeypatch.setattr(store.os, "chmod", deny)
    store.connect().close()                # must not raise
    assert "could not tighten permissions" in capsys.readouterr().err
    store.connect().close()                # second open: warned once only
    assert "could not tighten" not in capsys.readouterr().err


@posix_only
def test_operator_precreated_loose_state_dir_warns_not_fails(
        tmp_path, monkeypatch, capsys):
    shared = tmp_path / "shared-state"
    shared.mkdir()
    os.chmod(shared, 0o755)
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(shared))
    store.connect().close()
    assert _mode(shared) == 0o755          # operator's choice preserved
    assert _mode(shared / "vvaharness.db") == 0o600
    assert "group/other-accessible" in capsys.readouterr().err


def test_non_posix_platform_degrades_gracefully(monkeypatch, tmp_path):
    """Windows has no meaningful chmod: with the store's POSIX gate off, the
    hardening is skipped entirely and connect() still works.

    The gate is disabled via ``store._POSIX``, NOT by patching ``os.name`` to
    ``"nt"``: on Python 3.13+ ``pathlib.Path()`` picks its flavour from
    ``os.name`` at call time, so under a patched ``os.name`` the absolute
    ``tmp_path`` becomes a ``WindowsPath`` whose ``str()`` is one
    backslash-joined string — which POSIX syscalls treat as a single literal
    *cwd-relative* filename, polluting whatever directory pytest was started
    from (historically, the repo root). The chdir below confines any such
    stray relative creation to the pytest temp dir, and the assertions at the
    end make that failure mode loud instead of silent.
    """
    start_cwd = Path.cwd()
    monkeypatch.chdir(tmp_path)      # stray relative paths land in tmp_path
    root = tmp_path / "nt-state"
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(root))
    monkeypatch.setattr(store, "_POSIX", False)
    store.connect().close()                # no chmod path taken, no crash
    assert (root / "vvaharness.db").exists()
    # Regression guard: no backslash-mangled literal filename may be created
    # anywhere — neither in the temp dir nor outside it (the signature of the
    # WindowsPath failure mode described in the docstring).
    assert not [n for n in os.listdir(tmp_path) if "\\" in n]
    assert not [n for n in os.listdir(start_cwd) if "\\" in n]


def test_save_callgraph_dedupes_snapshot_and_records_stage_refs():
    ctx = _ctx_with_graph()
    g1 = store.save_callgraph(RID, "s1", ctx)
    g2 = store.save_callgraph(RID, "s2", ctx)
    assert g1 and g1 == g2

    con = store.connect()
    snap = con.execute(
        "SELECT node_count, edge_count, entry_point_count, sink_count "
        "FROM callgraph_snapshots WHERE run_id=? AND graph_id=?",
        (RID, g1),
    ).fetchone()
    refs = con.execute(
        "SELECT step, graph_id FROM callgraph_stage_refs WHERE run_id=? "
        "ORDER BY step",
        (RID,),
    ).fetchall()
    nodes = con.execute(
        "SELECT qnode, is_entry_point, entry_kind, reachable_from_unauth, "
        "is_sink, sink_line FROM callgraph_nodes WHERE run_id=? ORDER BY qnode",
        (RID,),
    ).fetchall()
    edges = con.execute(
        "SELECT caller_qnode, callee_qnode FROM callgraph_edges WHERE run_id=?",
        (RID,),
    ).fetchall()
    con.close()

    assert snap == (2, 1, 1, 1)
    assert refs == [("s1", g1), ("s2", g1)]
    assert nodes == [
        ("ctrl.py::handle", 1, "network", 1, 0, 0),
        ("dao.py::raw_query", 0, "", 0, 1, 40),
    ]
    assert edges == [("ctrl.py::handle", "dao.py::raw_query")]


def test_load_callgraph_roundtrip_from_stage_ref():
    ctx = _ctx_with_graph()
    store.save_callgraph(RID, "s1", ctx)

    loaded = store.load_callgraph(RID, "s1")
    assert loaded is not None
    assert loaded["node_count"] == 2
    assert loaded["edge_count"] == 1
    assert loaded["call_graph"] == {"ctrl.py::handle": ["dao.py::raw_query"],
                                    "dao.py::raw_query": []}
    assert loaded["call_graph_files"] == {
        "handle": ["ctrl.py:10"],
        "raw_query": ["dao.py:40"],
    }
    assert loaded["def_spans"] == {
        "ctrl.py::handle": [10, 20],
        "dao.py::raw_query": [40, 45],
    }


def test_load_callgraph_missing_stage_ref_returns_none():
    assert store.load_callgraph(RID, "s2") is None


def test_reset_run_clears_callgraph_state_too():
    ctx = _ctx_with_graph()
    store.save_callgraph(RID, "s1", ctx)
    ck.save_ckpt(None, RID, "s9", "/tmp/report.sarif")
    cleared = store.reset_run(RID)
    assert cleared == 2

    con = store.connect()
    counts = con.execute(
        "SELECT "
        " (SELECT COUNT(*) FROM checkpoints WHERE run_id=?),"
        " (SELECT COUNT(*) FROM callgraph_snapshots WHERE run_id=?),"
        " (SELECT COUNT(*) FROM callgraph_stage_refs WHERE run_id=?),"
        " (SELECT COUNT(*) FROM callgraph_nodes WHERE run_id=?),"
        " (SELECT COUNT(*) FROM callgraph_edges WHERE run_id=?)",
        (RID, RID, RID, RID, RID),
    ).fetchone()
    con.close()
    assert counts == (0, 0, 0, 0, 0)


# One state root, resolved in one place, created in one place

@posix_only
def test_auto_step1_ckpt_dir_is_owner_only(tmp_path, monkeypatch):
    """The third creator. `--auto-step1` writes a step1.yaml overlay here that a
    later stage reads as configuration, and it used to be a bare mkdir at the umask
    default. Every level must be tightened, not only the leaf: parents=True creates
    `checkpoints/` on the way to `checkpoints/<run_id>/`."""
    root = tmp_path / "fresh-state"
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(root))
    leaf = store.ensure_state_dir("checkpoints", "a" * 32)
    assert leaf == root / "checkpoints" / ("a" * 32)
    assert _mode(root) == 0o700
    assert _mode(root / "checkpoints") == 0o700
    assert _mode(leaf) == 0o700


def test_state_root_does_not_create_anything(tmp_path, monkeypatch):
    """Justifies two helpers rather than one: scan.py composes its checkpoint path
    before the in-target safety check and before an early --stop-after return, so a
    resolver with a side effect would make a metadata-only run write into the
    operator's home."""
    root = tmp_path / "never-created"
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(root))
    assert store.state_root() == root
    assert not root.exists()


def test_state_root_is_resolved_in_exactly_one_place(tmp_path, monkeypatch):
    """The consolidation pin: the env var was read in three places, and three copies
    of one path expression drift. batch's marker root and scan's checkpoint root must
    both agree with store's."""
    from vvaharness.orchestrator import batch

    root = tmp_path / "one-root"
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(root))
    assert store.state_root() == root
    assert batch._state_root() == root
    marker = batch._stage_marker_path(tmp_path / "dest")
    assert marker.parent == root / "stage-markers"


def test_db_path_is_unchanged_by_the_refactor(tmp_path, monkeypatch):
    """Exactly the assertion a silent refactor regression would trip."""
    root = tmp_path / "state"
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(root))
    assert store.db_path() == root / "vvaharness.db"
    monkeypatch.delenv("VVAHARNESS_STATE_DIR")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert store.db_path() == tmp_path / "home" / ".vvaharness" / "state" / "vvaharness.db"


@posix_only
def test_default_state_root_loose_mode_is_repaired(tmp_path, monkeypatch, capsys):
    """The default root is ours, not the operator's. They never named the path, so a
    loose mode on it is an older release's leftover or an accident rather than a
    decision — repair it and say so. Contrast
    test_operator_precreated_loose_state_dir_warns_not_fails, where the operator DID
    name the path and keeps the last word on its mode."""
    monkeypatch.delenv("VVAHARNESS_STATE_DIR", raising=False)
    home = tmp_path / "home"
    default = home / ".vvaharness" / "state"
    default.mkdir(parents=True)
    os.chmod(default, 0o755)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    store.connect().close()

    assert _mode(default) == 0o700
    err = capsys.readouterr().err
    assert "tightened" in err and "700" in err
    assert "consider `chmod 700`" not in err     # not the operator-owned wording


@posix_only
def test_repair_never_loosens_an_already_tight_default_root(tmp_path, monkeypatch,
                                                           capsys):
    """A 0700 root must be left alone and must not warn: a message that fires on a
    healthy run is one operators learn to ignore. 0o750 is also not widened."""
    monkeypatch.delenv("VVAHARNESS_STATE_DIR", raising=False)
    home = tmp_path / "home"
    default = home / ".vvaharness" / "state"
    default.mkdir(parents=True)
    os.chmod(default, 0o700)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    store.connect().close()

    assert _mode(default) == 0o700
    assert "tightened" not in capsys.readouterr().err
