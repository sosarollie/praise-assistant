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

"""orchestrator.store — single-file SQLite state store under ``$VVAHARNESS_STATE_DIR`` holding per-run checkpoint blobs, callgraph snapshots, and run metadata."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import stat
from collections import defaultdict
from collections.abc import Collection
from pathlib import Path

from vvaharness.util.warn_once import warn_once

_SCHEMA_VERSION = 3

# A stored replay bundle is small (baseline + one payload, response bodies capped at
# 512 bytes); anything approaching this is corruption or abuse. Enforced here AND by a
# CHECK constraint, so a hostile direct INSERT is rejected too.
_REPLAY_MAX_BYTES = 1024 * 1024

# ── State-DB confidentiality ──────────────────────────────────────────────────
# Hazard: checkpoint payloads embed ContextPackage data and findings — i.e.
# scanned REPOSITORY SOURCE snippets. sqlite3.connect() creates files at the
# umask default (typically 0644, world-readable), so the DB, its WAL/SHM/
# journal sidecars (which carry the same payload bytes), and the state
# directory are pinned to owner-only modes here. Tightening 0644 → 0600 does
# not change behaviour for the owning user — the only legitimate reader; every
# consumer of this DB (scan --resume, gc, S10/S11 checkpoints) runs in-process
# as that same user — it only removes group/other read access.
_DB_FILE_MODE = 0o600
_STATE_DIR_MODE = 0o700
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
# Windows has no meaningful chmod/POSIX mode bits: every hardening step below
# is gated on this so the code degrades gracefully instead of raising there.
_POSIX = os.name == "posix"
_PERM_WARNED: set[str] = set()


def _warn_once(key: str, message: str) -> None:
    """Permission problems degrade to a single stderr warning per path per
    process — a confidentiality hardening step must never crash a scan."""
    warn_once(_PERM_WARNED, key, f"  [store] WARN: {message}")


def _tighten_mode(path: Path, mode: int) -> None:
    """Best-effort chmod of *path* down to *mode* when it is looser.

    Never raises: a chmod failure (e.g. a file owned by another user) warns
    instead of aborting, an already-tighter mode is left alone (never
    loosened), and non-POSIX platforms (Windows has no meaningful chmod) are
    skipped entirely.
    """
    if not _POSIX:
        return
    try:
        current = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return  # absent (e.g. no sidecar yet) — nothing to tighten
    if not (current & ~mode):
        return  # already at least as tight as the target
    try:
        os.chmod(path, mode)
    except OSError as e:
        _warn_once(str(path),
                   f"could not tighten permissions on {path} (mode "
                   f"{current:o}; it holds scanned-source snippets): {e}")

# auto_vacuum MUST precede the first CREATE TABLE or it is silently ignored; journal_mode=WAL persists once set.
_DDL = """
PRAGMA auto_vacuum  = INCREMENTAL;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS runs (
  run_id     TEXT PRIMARY KEY,
  repo_root  TEXT NOT NULL,
  repo_name  TEXT,
  app_id     TEXT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS checkpoints (
  run_id     TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  step       TEXT    NOT NULL,
  payload    BLOB    NOT NULL,
  size       INTEGER NOT NULL CHECK (size <= 104857600),
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (run_id, step)
);

-- Exploit-verification replay bundles: the confirming exchange for each live-verified
-- finding, kept so a later `ev-replay` (a SEPARATE invocation, after the fix is
-- deployed) can re-send it and re-decide. Deliberately NOT a `checkpoints` row: unlike
-- resume state, these must SURVIVE a fresh rescan's reset_run() so replay works after a
-- remediate+rescan cycle. They are still reaped by delete_run()/prune (FK cascade).
CREATE TABLE IF NOT EXISTS ev_replays (
  run_id      TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  finding_key TEXT    NOT NULL,
  payload     BLOB    NOT NULL,
  size        INTEGER NOT NULL CHECK (size <= 1048576),
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (run_id, finding_key)
);

-- Exploit-verification probe log: EVERY payload EV sent this run (confirmed or not),
-- one row per request, tagged with the finding it came from and the endpoint it hit.
-- Distinct from ev_replays (which keeps only the single CONFIRMING exchange per verified
-- finding): this is the broad corpus for replay/analysis, written only when the profile
-- opts in (step6_exploit_verification.store_probes). The caller redacts credential
-- material (JWTs and credential-named values) from the request/response fields before
-- insert; auth_applied holds channel NAMES only, never a token.
CREATE TABLE IF NOT EXISTS ev_probes (
  id              INTEGER PRIMARY KEY,
  run_id          TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  finding_key     TEXT    NOT NULL,
  finding_title   TEXT,
  file            TEXT,
  line_start      INTEGER,
  line_end        INTEGER,
  cwe             TEXT,
  vuln_class      TEXT,
  ev_class        TEXT,
  ev_subtype      TEXT,
  ev_verdict      TEXT,
  endpoint_method TEXT,
  endpoint_path   TEXT,
  payload_label   TEXT,
  injection_point TEXT,
  req_method      TEXT,
  req_url         TEXT,
  req_query       TEXT,
  req_body        TEXT,
  authed          INTEGER,
  auth_applied    TEXT,
  resp_status     INTEGER,
  resp_ms         INTEGER,
  resp_snippet    TEXT,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_ev_probes_run ON ev_probes(run_id);
CREATE INDEX IF NOT EXISTS ix_ev_probes_finding ON ev_probes(run_id, finding_key);

CREATE TABLE IF NOT EXISTS callgraph_snapshots (
    run_id            TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    graph_id          TEXT    NOT NULL,
    node_count        INTEGER NOT NULL DEFAULT 0,
    edge_count        INTEGER NOT NULL DEFAULT 0,
    entry_point_count INTEGER NOT NULL DEFAULT 0,
    sink_count        INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (run_id, graph_id)
);

CREATE TABLE IF NOT EXISTS callgraph_nodes (
    run_id                 TEXT    NOT NULL,
    graph_id               TEXT    NOT NULL,
    qnode                  TEXT    NOT NULL,
    file_path              TEXT    NOT NULL DEFAULT '',
    function_name          TEXT    NOT NULL DEFAULT '',
    start_line             INTEGER NOT NULL DEFAULT 0,
    end_line               INTEGER NOT NULL DEFAULT 0,
    is_entry_point         INTEGER NOT NULL DEFAULT 0,
    entry_kind             TEXT    NOT NULL DEFAULT '',
    reachable_from_unauth  INTEGER NOT NULL DEFAULT 0,
    is_sink                INTEGER NOT NULL DEFAULT 0,
    sink_line              INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, graph_id, qnode),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS callgraph_edges (
    run_id        TEXT NOT NULL,
    graph_id      TEXT NOT NULL,
    caller_qnode  TEXT NOT NULL,
    callee_qnode  TEXT NOT NULL,
    PRIMARY KEY (run_id, graph_id, caller_qnode, callee_qnode),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS callgraph_stage_refs (
    run_id      TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    step        TEXT NOT NULL,
    graph_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (run_id, step),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_runs_updated ON runs(updated_at);
CREATE INDEX IF NOT EXISTS ix_callgraph_stage_refs_graph
    ON callgraph_stage_refs(run_id, graph_id);
CREATE INDEX IF NOT EXISTS ix_callgraph_nodes_file
    ON callgraph_nodes(run_id, file_path, function_name);
CREATE INDEX IF NOT EXISTS ix_callgraph_edges_caller
    ON callgraph_edges(run_id, caller_qnode);
CREATE INDEX IF NOT EXISTS ix_callgraph_edges_callee
    ON callgraph_edges(run_id, callee_qnode);
"""

_DDL_V2 = """
CREATE TABLE IF NOT EXISTS callgraph_snapshots (
    run_id            TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    graph_id          TEXT    NOT NULL,
    node_count        INTEGER NOT NULL DEFAULT 0,
    edge_count        INTEGER NOT NULL DEFAULT 0,
    entry_point_count INTEGER NOT NULL DEFAULT 0,
    sink_count        INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (run_id, graph_id)
);

CREATE TABLE IF NOT EXISTS callgraph_nodes (
    run_id                 TEXT    NOT NULL,
    graph_id               TEXT    NOT NULL,
    qnode                  TEXT    NOT NULL,
    file_path              TEXT    NOT NULL DEFAULT '',
    function_name          TEXT    NOT NULL DEFAULT '',
    start_line             INTEGER NOT NULL DEFAULT 0,
    end_line               INTEGER NOT NULL DEFAULT 0,
    is_entry_point         INTEGER NOT NULL DEFAULT 0,
    entry_kind             TEXT    NOT NULL DEFAULT '',
    reachable_from_unauth  INTEGER NOT NULL DEFAULT 0,
    is_sink                INTEGER NOT NULL DEFAULT 0,
    sink_line              INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (run_id, graph_id, qnode),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS callgraph_edges (
    run_id        TEXT NOT NULL,
    graph_id      TEXT NOT NULL,
    caller_qnode  TEXT NOT NULL,
    callee_qnode  TEXT NOT NULL,
    PRIMARY KEY (run_id, graph_id, caller_qnode, callee_qnode),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS callgraph_stage_refs (
    run_id      TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    step        TEXT NOT NULL,
    graph_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (run_id, step),
    FOREIGN KEY (run_id, graph_id)
        REFERENCES callgraph_snapshots(run_id, graph_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_callgraph_stage_refs_graph
    ON callgraph_stage_refs(run_id, graph_id);
CREATE INDEX IF NOT EXISTS ix_callgraph_nodes_file
    ON callgraph_nodes(run_id, file_path, function_name);
CREATE INDEX IF NOT EXISTS ix_callgraph_edges_caller
    ON callgraph_edges(run_id, caller_qnode);
CREATE INDEX IF NOT EXISTS ix_callgraph_edges_callee
    ON callgraph_edges(run_id, callee_qnode);
"""

# v2→v3 migration: add the exploit-verification tables (ev_replays + ev_probes) to an
# existing database. Idempotent, so a v0 (fresh) DB gets them from _DDL above and never
# runs this. One migration rather than two because neither table has shipped: no database
# outside development sits between them, so there is no intermediate state to step through.
_DDL_V3 = """
CREATE TABLE IF NOT EXISTS ev_replays (
  run_id      TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  finding_key TEXT    NOT NULL,
  payload     BLOB    NOT NULL,
  size        INTEGER NOT NULL CHECK (size <= 1048576),
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (run_id, finding_key)
);
    
CREATE TABLE IF NOT EXISTS ev_probes (
  id              INTEGER PRIMARY KEY,
  run_id          TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  finding_key     TEXT    NOT NULL,
  finding_title   TEXT,
  file            TEXT,
  line_start      INTEGER,
  line_end        INTEGER,
  cwe             TEXT,
  vuln_class      TEXT,
  ev_class        TEXT,
  ev_subtype      TEXT,
  ev_verdict      TEXT,
  endpoint_method TEXT,
  endpoint_path   TEXT,
  payload_label   TEXT,
  injection_point TEXT,
  req_method      TEXT,
  req_url         TEXT,
  req_query       TEXT,
  req_body        TEXT,
  authed          INTEGER,
  auth_applied    TEXT,
  resp_status     INTEGER,
  resp_ms         INTEGER,
  resp_snippet    TEXT,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_ev_probes_run ON ev_probes(run_id);
CREATE INDEX IF NOT EXISTS ix_ev_probes_finding ON ev_probes(run_id, finding_key);
"""



def state_root() -> Path:
    """Where scan state lives, resolved and nothing more.

    Deliberately performs NO I/O, because two callers only need to compose a path:
    scan.py builds its checkpoint path before the in-target safety check runs and
    before a metadata-only run returns, so a resolver that created the directory as
    a side effect would have a ``--stop-after`` run write into the operator's home
    for no reason. Use `ensure_state_dir` when the directory has to exist.
    """
    return Path(os.environ.get("VVAHARNESS_STATE_DIR")
                or Path.home() / ".vvaharness" / "state")


def ensure_state_dir(*parts: str) -> Path:
    """Return ``state_root()/ *parts``, creating each level owner-only.

    The single place any directory under the state root is created, so one policy
    covers all of them: the DB's root here, batch's stage markers, and the per-run
    checkpoint directory. Every level is tightened, not just the leaf --
    ``parents=True`` would otherwise leave an intermediate at the umask default,
    and an intermediate is in the same confidentiality class as its children.
    """
    root = state_root()
    if root.is_dir():
        # A pre-existing root splits into two cases that are NOT the same decision:
        #
        #   VVAHARNESS_STATE_DIR set — the operator named this directory, so its mode
        #   is theirs. They may be sharing it deliberately, and silently undoing that
        #   on every run would fight a supported configuration we cannot see the
        #   reason for. Warn and leave it. The DB and its sidecars are 0600 anyway
        #   (see connect()), so what a group/other reader gains is a filename.
        #
        #   default root — nobody chose this mode. The operator never named the
        #   path, so a loose one is an older release's leftover (from before this
        #   module hardened anything) or an accident, not a decision. Repair it.
        if _POSIX:
            try:
                mode = stat.S_IMODE(root.stat().st_mode)
            except OSError:
                mode = 0
            if mode & 0o077:
                if os.environ.get("VVAHARNESS_STATE_DIR"):
                    _warn_once(
                        str(root),
                        f"state directory {root} is group/other-accessible "
                        f"(mode {mode:o}) and holds scanned-source snippets — "
                        "consider `chmod 700` if it is not shared on purpose")
                else:
                    _tighten_mode(root, _STATE_DIR_MODE)
                    _warn_once(
                        str(root),
                        f"tightened {root} from mode {mode:o} to 700 — it holds "
                        "scanned-source snippets. Set VVAHARNESS_STATE_DIR to a "
                        "path you manage if you need to share this state")
    else:
        root.mkdir(parents=True, exist_ok=True)
        # A directory this process created is owner-only by construction.
        _tighten_mode(root, _STATE_DIR_MODE)
    path = root
    for part in parts:
        path = path / part
        path.mkdir(parents=True, exist_ok=True)
        _tighten_mode(path, _STATE_DIR_MODE)
    return path


def db_path() -> Path:
    """Resolve the state DB path the same way scan.py resolves the legacy ``checkpoints/`` root, so ``--resume`` and the in-target safety check see the same location."""
    return ensure_state_dir() / "vvaharness.db"


def connect() -> sqlite3.Connection:
    """Open the state DB, ensure the schema exists, and return a connection — cheap enough to call per operation since sqlite3 connections are thread-affine."""
    path = db_path()
    if _POSIX and not path.exists():
        # Create the DB file owner-only BEFORE sqlite3 can create it at the
        # umask default (0644): a zero-length file is a valid empty database,
        # and the umask can only mask O_CREAT's 0600 tighter, never looser.
        try:
            os.close(os.open(path, os.O_CREAT | os.O_RDWR, _DB_FILE_MODE))
        except OSError:
            pass  # sqlite3.connect() below surfaces the real error
    con = sqlite3.connect(path)
    # Per-connection pragmas — must be set on every handle.
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 30000")
    con.execute("PRAGMA synchronous  = NORMAL")
    # Schema bootstrap — skipped entirely once user_version matches, so the hot path is three pragmas + one integer read, no executescript on every save_ckpt().
    have = con.execute("PRAGMA user_version").fetchone()[0]
    if have != _SCHEMA_VERSION:
        _migrate(con, have)
    # Tighten a DB a previous release left at 0644, plus any lingering WAL/
    # SHM/journal sidecars (a WAL carries the same payload bytes). SQLite's
    # unix VFS gives NEW sidecars the main DB's mode, so 0600 propagates.
    for p in (path, *(path.with_name(path.name + s)
                      for s in _SIDECAR_SUFFIXES)):
        _tighten_mode(p, _DB_FILE_MODE)
    return con


def _migrate(con: sqlite3.Connection, have: int) -> None:
    # A v0 (fresh) DB gets the whole schema from _DDL. An existing DB runs each
    # migration it is behind, in order — cumulatively, so a v1 DB gets both V2 and V3.
    if have == 0:
        con.executescript(_DDL)
    else:
        if have < 2:
            con.executescript(_DDL_V2)
        if have < 3:
            con.executescript(_DDL_V3)
    con.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
    con.commit()


def register_run(run_id: str, *, repo_root: str,
                 repo_name: str | None = None,
                 app_id: str | None = None) -> None:
    """Upsert the per-run metadata row, called once at the top of ``scan_repo()`` so ``gc`` can rank runs by recency."""
    con = connect()
    with con:
        con.execute(
            "INSERT INTO runs(run_id, repo_root, repo_name, app_id) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(run_id) DO UPDATE SET "
            "  repo_root = excluded.repo_root, "
            "  repo_name = excluded.repo_name, "
            "  app_id    = excluded.app_id, "
            "  updated_at = datetime('now')",
            (run_id, repo_root, repo_name, app_id),
        )
    con.close()


def _qnode(file_path: str, function_name: str) -> str:
    file_part = (file_path or "").replace("\\", "/")
    fn_part = function_name or ""
    return f"{file_part}::{fn_part}" if file_part or fn_part else ""


def _split_qnode(qnode: str) -> tuple[str, str]:
    # Split on the LAST "::" to match the canonical q_split in s1_preprocess, or a hydrated graph points at the wrong file for a name that itself contains "::" (C++, C#).
    if "::" not in qnode:
        return "", qnode
    f, _, n = qnode.rpartition("::")
    return f, n


def _line_from_site(site: str) -> int:
    _file, sep, raw = site.rpartition(":")
    if not sep:
        return 0
    try:
        return int(raw)
    except ValueError:
        return 0


def _graph_rows(obj) -> tuple[list[dict], list[tuple[str, str]]] | None:
    call_graph = dict(getattr(obj, "call_graph", {}) or {})
    call_graph_files = dict(getattr(obj, "call_graph_files", {}) or {})
    def_spans = dict(getattr(obj, "def_spans", {}) or {})
    entry_points = list(getattr(obj, "entry_points", ()) or ())
    unsafe_sinks = list(getattr(obj, "unsafe_sinks", ()) or ())
    if not (call_graph or call_graph_files or def_spans or entry_points or unsafe_sinks):
        return None

    entry_meta: dict[str, tuple[str, int]] = {}
    for ep in entry_points:
        qn = _qnode(getattr(ep, "file", ""), getattr(ep, "function", ""))
        if qn:
            entry_meta[qn] = (
                (getattr(ep, "kind", "") or ""),
                1 if bool(getattr(ep, "reachable_from_unauth", False)) else 0,
            )

    sink_meta: dict[str, int] = {}
    for sink in unsafe_sinks:
        qn = _qnode(getattr(sink, "file", ""), getattr(sink, "function", ""))
        if qn:
            line = int(getattr(sink, "line", 0) or 0)
            prev = sink_meta.get(qn)
            sink_meta[qn] = line if prev is None or (line and line < prev) else prev

    qnodes: set[str] = set(call_graph)
    edges: set[tuple[str, str]] = set()
    for caller, callees in call_graph.items():
        if not caller:
            continue
        qnodes.add(caller)
        for callee in callees or ():
            if not callee:
                continue
            qnodes.add(callee)
            edges.add((caller, callee))
    qnodes.update(qn for qn in entry_meta if qn)
    qnodes.update(qn for qn in sink_meta if qn)
    qnodes.update(qn for qn in def_spans if qn)

    node_rows: list[dict] = []
    for qn in sorted(qnodes):
        file_path, function_name = _split_qnode(qn)
        span = def_spans.get(qn) or []
        start_line = int(span[0]) if len(span) >= 1 else 0
        end_line = int(span[1]) if len(span) >= 2 else 0
        if not start_line and function_name:
            for site in call_graph_files.get(function_name, ()):
                site_file, _, _raw = site.rpartition(":")
                if site_file == file_path:
                    start_line = _line_from_site(site)
                    if not end_line:
                        end_line = start_line
                    break
        entry_kind, unauth = entry_meta.get(qn, ("", 0))
        sink_line = sink_meta.get(qn, 0)
        node_rows.append({
            "qnode": qn,
            "file_path": file_path,
            "function_name": function_name,
            "start_line": start_line,
            "end_line": end_line,
            "is_entry_point": 1 if qn in entry_meta else 0,
            "entry_kind": entry_kind,
            "reachable_from_unauth": unauth,
            "is_sink": 1 if qn in sink_meta else 0,
            "sink_line": sink_line,
        })

    return node_rows, sorted(edges)


def save_callgraph(run_id: str, step: str, obj) -> str | None:
    """Persist a normalized callgraph snapshot and bind the current step to it, storing rows rather than a single BLOB so large graphs remain queryable."""
    rows = _graph_rows(obj)
    if rows is None:
        return None
    node_rows, edge_rows = rows
    payload = json.dumps({
        "nodes": node_rows,
        "edges": edge_rows,
    }, sort_keys=True, separators=(",", ":")).encode()
    graph_id = hashlib.sha256(payload).hexdigest()[:32]

    con = connect()
    try:
        with con:
            con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) VALUES (?, '')",
                        (run_id,))
            con.execute("UPDATE runs SET updated_at = datetime('now') WHERE run_id = ?",
                        (run_id,))
            exists = con.execute(
                "SELECT 1 FROM callgraph_snapshots WHERE run_id=? AND graph_id=?",
                (run_id, graph_id),
            ).fetchone()
            if exists is None:
                con.execute(
                    "INSERT INTO callgraph_snapshots"
                    "(run_id, graph_id, node_count, edge_count, entry_point_count, sink_count) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        graph_id,
                        len(node_rows),
                        len(edge_rows),
                        sum(r["is_entry_point"] for r in node_rows),
                        sum(r["is_sink"] for r in node_rows),
                    ),
                )
                con.executemany(
                    "INSERT INTO callgraph_nodes"
                    "(run_id, graph_id, qnode, file_path, function_name, start_line, end_line, "
                    " is_entry_point, entry_kind, reachable_from_unauth, is_sink, sink_line) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [(
                        run_id,
                        graph_id,
                        row["qnode"],
                        row["file_path"],
                        row["function_name"],
                        row["start_line"],
                        row["end_line"],
                        row["is_entry_point"],
                        row["entry_kind"],
                        row["reachable_from_unauth"],
                        row["is_sink"],
                        row["sink_line"],
                    ) for row in node_rows],
                )
                con.executemany(
                    "INSERT INTO callgraph_edges"
                    "(run_id, graph_id, caller_qnode, callee_qnode) VALUES (?, ?, ?, ?)",
                    [(run_id, graph_id, caller, callee) for caller, callee in edge_rows],
                )
            con.execute(
                "INSERT OR REPLACE INTO callgraph_stage_refs(run_id, step, graph_id) VALUES (?, ?, ?)",
                (run_id, step, graph_id),
            )
        return graph_id
    finally:
        con.close()


def load_callgraph(run_id: str, step: str) -> dict | None:
    """Load a normalized callgraph snapshot bound to ``(run_id, step)``, or ``None`` when the step has no bound graph."""
    con = connect()
    try:
        ref = con.execute(
            "SELECT graph_id FROM callgraph_stage_refs WHERE run_id=? AND step=?",
            (run_id, step),
        ).fetchone()
        if ref is None:
            return None
        graph_id = ref[0]
        node_rows = con.execute(
            "SELECT qnode, file_path, function_name, start_line, end_line, "
            "is_entry_point, reachable_from_unauth, is_sink "
            "FROM callgraph_nodes WHERE run_id=? AND graph_id=?",
            (run_id, graph_id),
        ).fetchall()
        edge_rows = con.execute(
            "SELECT caller_qnode, callee_qnode FROM callgraph_edges "
            "WHERE run_id=? AND graph_id=?",
            (run_id, graph_id),
        ).fetchall()
    finally:
        con.close()

    node_meta: dict[str, tuple[int, int, int]] = {}
    call_graph_files: dict[str, list[str]] = defaultdict(list)
    def_spans: dict[str, list[int]] = {}
    for (qn, file_path, fn_name, start_line, end_line,
         is_ep, unauth, is_sink) in node_rows:
        node_meta[qn] = (int(is_ep or 0), int(unauth or 0), int(is_sink or 0))
        if fn_name and file_path and start_line:
            site = f"{file_path}:{int(start_line)}"
            sites = call_graph_files[fn_name]
            if site not in sites:
                sites.append(site)
        if start_line or end_line:
            def_spans[qn] = [int(start_line or 0), int(end_line or 0)]

    def _edge_score(caller: str, callee: str) -> tuple[int, int, int, str, str]:
        c_ep, c_unauth, c_sink = node_meta.get(caller, (0, 0, 0))
        t_ep, t_unauth, t_sink = node_meta.get(callee, (0, 0, 0))
        return (
            -max(c_unauth, t_unauth),
            -max(c_ep, t_ep),
            -max(c_sink, t_sink),
            caller,
            callee,
        )

    ordered_edges = sorted(
        {(caller, callee) for caller, callee in edge_rows if caller and callee},
        key=lambda e: _edge_score(e[0], e[1]),
    )

    call_graph: dict[str, list[str]] = defaultdict(list)
    for caller, callee in ordered_edges:
        call_graph[caller].append(callee)

    # Preserve isolated nodes as keys to keep graph shape stable across save/load even when a function currently has no outgoing edge.
    for qn in node_meta:
        call_graph.setdefault(qn, [])

    return {
        "graph_id": graph_id,
        "call_graph": dict(call_graph),
        "call_graph_files": {k: v for k, v in call_graph_files.items()},
        "def_spans": def_spans,
        "node_count": len(node_rows),
        "edge_count": len(ordered_edges),
    }


def reset_run(run_id: str) -> int:
    """Delete every checkpoint row for one run (fixed s1..s9 steps and dynamic remediate_/validate_ steps), called
    by a FRESH (non ``--resume``) scan. Returns rows deleted.

    ``ev_replays`` is DELIBERATELY NOT cleared here: those bundles must outlive a
    fresh rescan so ``ev-replay`` still works after a remediate+rescan cycle. The
    exploit-verification pass overwrites its own run's bundles when it re-runs (see
    ``store.save_replays``); ``delete_run``/``prune_checkpoints`` still reap them via
    the runs FK cascade.
    """
    con = connect()
    try:
        with con:
            cleared = 0
            cur = con.execute("DELETE FROM checkpoints WHERE run_id = ?", (run_id,))
            cleared += cur.rowcount or 0
            cur = con.execute("DELETE FROM callgraph_snapshots WHERE run_id = ?", (run_id,))
            cleared += cur.rowcount or 0
            return cleared
    finally:
        con.close()


def save_replays(run_id: str, items: list[tuple[str, bytes]]) -> int:
    """Replace this run's exploit-verification replay bundles with ``items``.

    ``items`` is ``[(finding_key, payload_bytes), …]`` — the confirming exchange for
    each finding the EV pass verified live this run. The whole set is replaced
    atomically (delete-then-insert), so re-running EV re-establishes ground truth:
    stale bundles for findings no longer confirmed are dropped, and an empty ``items``
    clears the run's bundles entirely. Callers MUST invoke this only when the EV pass
    actually ran — a SAST-only rescan must leave a prior run's bundles untouched.

    Payloads are ``ReplayBundle`` JSON (never pickle), re-validated on load. An
    oversized bundle is skipped with a warning rather than persisted. Returns the
    number of bundles written."""
    con = connect()
    written = 0
    try:
        with con:
            con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) VALUES (?, '')",
                        (run_id,))
            con.execute("UPDATE runs SET updated_at = datetime('now') WHERE run_id = ?",
                        (run_id,))
            con.execute("DELETE FROM ev_replays WHERE run_id = ?", (run_id,))
            for key, blob in items:
                if len(blob) > _REPLAY_MAX_BYTES:
                    print(f"  [ev-replay] WARN: bundle {key[:12]}… is {len(blob)} bytes "
                          f"(> {_REPLAY_MAX_BYTES}); not persisted", file=sys.stderr)
                    continue
                con.execute(
                    "INSERT OR REPLACE INTO ev_replays(run_id, finding_key, payload, size) "
                    "VALUES (?, ?, ?, ?)", (run_id, key, blob, len(blob)))
                written += 1
    finally:
        con.close()
    return written


def prune_replays(run_id: str, keep_keys) -> int:
    """Drop this run's replay bundles whose ``finding_key`` is not in ``keep_keys``.

    ``save_replays`` runs at the end of S6, before S7 collapses duplicates — so without
    this the table can hold a bundle for a finding that never reaches the report, and
    ``ev-replay`` would then report on a finding the operator cannot find. Returns the
    number of bundles removed.

    Called only after a dedup pass that actually ran; an empty ``keep_keys`` therefore
    means "nothing survived dedup" and correctly clears the run's bundles.
    """
    keep = set(keep_keys or ())
    stale: list[str] = []
    con = connect()
    try:
        with con:
            rows = con.execute("SELECT finding_key FROM ev_replays WHERE run_id = ?",
                               (run_id,)).fetchall()
            stale = [r[0] for r in rows if r[0] not in keep]
            for key in stale:
                con.execute("DELETE FROM ev_replays WHERE run_id = ? AND finding_key = ?",
                            (run_id, key))
    finally:
        con.close()
    return len(stale)


def load_replays(run_id: str) -> list[tuple[str, bytes]]:
    """Return this run's replay bundles as ``[(finding_key, payload_bytes), …]``,
    oldest first (stable order for the report). Bytes are validated by the caller
    (``ev-replay``) via the pydantic model — a bad row is skipped, never trusted."""
    con = connect()
    try:
        rows = con.execute(
            "SELECT finding_key, payload, size FROM ev_replays WHERE run_id = ? "
            "ORDER BY created_at, finding_key", (run_id,)).fetchall()
    finally:
        con.close()
    out: list[tuple[str, bytes]] = []
    for key, payload, size in rows:
        if size > _REPLAY_MAX_BYTES:               # belt-and-braces; CHECK enforces it
            print(f"  [ev-replay] WARN: bundle {key[:12]}… exceeds {_REPLAY_MAX_BYTES} "
                  f"bytes; ignoring", file=sys.stderr)
            continue
        out.append((key, payload))
    return out


def delete_replays(run_id: str) -> int:
    """Drop this run's replay bundles. Returns rows deleted."""
    con = connect()
    try:
        with con:
            cur = con.execute("DELETE FROM ev_replays WHERE run_id = ?", (run_id,))
            return cur.rowcount or 0
    finally:
        con.close()


#: Columns of ``ev_probes`` accepted from a row dict, in insert order. Anything a caller
#: omits is stored NULL; anything extra is ignored — the writer never trusts the caller
#: to match the schema exactly.
_EV_PROBE_COLS = (
    "finding_key", "finding_title", "file", "line_start", "line_end", "cwe", "vuln_class",
    "ev_class", "ev_subtype", "ev_verdict", "endpoint_method", "endpoint_path",
    "payload_label", "injection_point", "req_method", "req_url", "req_query", "req_body",
    "authed", "auth_applied", "resp_status", "resp_ms", "resp_snippet")


def save_ev_probes(run_id: str, rows: list[dict]) -> int:
    """Replace this run's exploit-verification probe log with ``rows``.

    Each row is one probe EV sent this run (see ``_EV_PROBE_COLS``). The whole set is
    replaced atomically (delete-then-insert), so re-running EV re-establishes ground
    truth. Callers MUST invoke this only when the EV pass actually ran and the profile
    opted in — a SAST-only rescan must leave a prior run's probes untouched. Returns the
    number of rows written. The caller (``router._probe_rows``) redacts credential
    material before insert — JWTs and credential-named query/body/response values are
    masked, and ``auth_applied`` holds channel names only, never a token."""
    cols = ", ".join(_EV_PROBE_COLS)
    ph = ", ".join("?" for _ in _EV_PROBE_COLS)
    con = connect()
    written = 0
    try:
        with con:
            con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) VALUES (?, '')",
                        (run_id,))
            con.execute("UPDATE runs SET updated_at = datetime('now') WHERE run_id = ?",
                        (run_id,))
            con.execute("DELETE FROM ev_probes WHERE run_id = ?", (run_id,))
            for r in rows:
                con.execute(
                    f"INSERT INTO ev_probes(run_id, {cols}) VALUES (?, {ph})",
                    (run_id, *(r.get(c) for c in _EV_PROBE_COLS)))
                written += 1
    finally:
        con.close()
    return written


def load_ev_probes(run_id: str) -> list[dict]:
    """Every stored probe for ``run_id`` as column dicts, in insertion order."""
    con = connect()
    try:
        con.row_factory = sqlite3.Row
        cur = con.execute(
            f"SELECT id, run_id, {', '.join(_EV_PROBE_COLS)}, created_at "
            f"FROM ev_probes WHERE run_id = ? ORDER BY id", (run_id,))
        return [dict(row) for row in cur.fetchall()]
    finally:
        con.close()


def steps_with_prefix(run_id: str, prefix: str) -> list[str]:
    """Return *run_id*'s checkpoint step keys starting with *prefix*, sorted — the dynamic keys hash engine identity and a case id, so no caller can reconstruct one to look it up directly."""
    con = connect()
    try:
        rows = con.execute("SELECT step FROM checkpoints WHERE run_id = ?",
                           (run_id,)).fetchall()
        return sorted(r[0] for r in rows if r[0].startswith(prefix))
    finally:
        con.close()


def delete_steps(run_id: str, prefix: str, keep: Collection[str]) -> list[str]:
    """Delete *run_id*'s checkpoint rows whose step starts with *prefix* and is not in *keep* — the complement of :func:`reset_run` for the standalone remediate/validate commands. Returns the deleted keys, sorted."""
    con = connect()
    try:
        with con:
            rows = con.execute("SELECT step FROM checkpoints WHERE run_id = ?",
                               (run_id,)).fetchall()
            victims = sorted(r[0] for r in rows
                             if r[0].startswith(prefix) and r[0] not in keep)
            con.executemany("DELETE FROM checkpoints WHERE run_id = ? AND step = ?",
                            [(run_id, v) for v in victims])
        return victims
    finally:
        con.close()


def delete_run(run_id: str) -> bool:
    """Fully evict a single run: delete its ``runs`` row (dropping ``checkpoints`` and ``ev_replays`` via ON DELETE CASCADE) and reclaim
    freed pages. Returns True if a run row was deleted."""
    con = connect()
    try:
        with con:
            cur = con.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
            deleted = cur.rowcount or 0
        if deleted:
            con.execute("PRAGMA incremental_vacuum")
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return deleted > 0
    finally:
        con.close()
