"""PraiseAssistant runtime: the standard-library CLI/state/control layer.

This module owns the engagement lifecycle and every state transition:

* scoped initialization and scope loading,
* SHA256-anchored evidence artifacts,
* class-aware candidate gating,
* two distinct clean-state reproductions before confirmation,
* producer-family independence checks for final decisions,
* explicit stage dispatch against a single authoritative role catalog,
* serialized, durable chat projection,
* controlled HTTP proof-of-concept requests,
* fail-closed fix validation.

All durable state lives in the engagement SQLite database; the Markdown chat
file and any JSON responses are projections of that state, never authority.
Standard library only; no third-party imports.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import evidence as response_evidence, policy

try:
    import fcntl  # POSIX file locking for serialized chat projection
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

__all__ = [
    "PraiseError",
    "init_engagement",
    "load_scope",
    "connect",
    "artifact",
    "model_family",
    "get_candidate",
    "record_event",
    "create_candidate",
    "gate_candidate",
    "add_reproduction",
    "record_verdict",
    "dispatch",
    "perform_request",
    "validate_fix",
    "show",
    "read_json_input",
    "load_roles",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DB_FILENAME = "state.sqlite3"
_SCOPE_FILENAME = "scope.json"
_CHAT_FILENAME = "agentschat.md"
_EVIDENCE_DIRNAME = "evidence"

#: Explicit workflow stages. Dispatch validates against this fixed list rather
#: than free text, so stage routing is never keyword-driven.
STAGES = ("plan", "recon", "discover", "gate", "proof", "verdict", "patch")

#: Candidate lifecycle statuses.
CANDIDATE_STATUSES = (
    "candidate",
    "substantiated",
    "gated",
    "reproduced",
    "confirmed",
    "held",
    "rejected",
    "duplicate",
)

#: Gate decisions.
GATE_DECISIONS = ("pass", "hold", "drop")

#: Verdict decisions.
VERDICT_DECISIONS = ("confirmed", "needs-more-proof", "rejected", "duplicate")

#: Fix-validation gate names and their allowed statuses.
FIX_GATES = ("root_cause", "instance_coverage", "no_new_vulnerabilities", "security_best_practices")
FIX_GATE_STATUSES = ("pass", "partial", "fail", "skip")

#: Conservative cap on response bytes read for a proof request.
MAX_RESPONSE_BYTES = 65536
#: Conservative request timeout, seconds.
REQUEST_TIMEOUT = 10.0

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PraiseError(Exception):
    """A fail-closed runtime error surfaced to the CLI as a JSON error."""


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def _now() -> str:
    """UTC timestamp with microseconds, ISO 8601 (``+00:00`` suffix)."""
    return datetime.now(timezone.utc).isoformat()


def _now_z() -> str:
    """UTC timestamp in the ``Z``-suffixed form used by chat headers."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_directory(directory: str) -> str:
    if not isinstance(directory, str) or not directory.strip():
        raise PraiseError("engagement directory must be a non-empty path")
    return os.path.abspath(directory)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _lock_file(fh) -> None:
    if fcntl is not None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)


def _unlock_file(fh) -> None:
    if fcntl is not None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def _tx(conn: sqlite3.Connection):
    """Serialize a write transaction; callers must not nest transactions."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


# ---------------------------------------------------------------------------
# Model families
# ---------------------------------------------------------------------------

#: Known model families, matched by model-name prefix after the provider and
#: reasoning suffixes are stripped. A family is the unit of independence for
#: checker-vs-producer judgments.
_MODEL_FAMILIES = (
    ("deepseek", ("deepseek",)),
    ("gpt", ("gpt", "sol", "o1", "o3", "o4", "openai")),
    ("grok", ("grok",)),
    ("glm", ("glm",)),
    ("mimo", ("mimo",)),
    ("claude", ("claude",)),
    ("gemini", ("gemini",)),
    ("llama", ("llama",)),
    ("qwen", ("qwen",)),
    ("mistral", ("mistral",)),
)


def model_family(model: object) -> str | None:
    """Return the known family for an observed model identifier, or ``None``.

    Accepts forms like ``provider/model:reasoning``, ``provider/model``, or a
    bare model name. Unknown identifiers yield ``None`` (never raise); callers
    fail closed on an unknown family for final decisions.
    """
    if not isinstance(model, str) or not model.strip():
        return None
    name = model.strip().split("/")[-1]
    name = name.split(":")[0].strip().lower()
    if not name:
        return None
    for family, prefixes in _MODEL_FAMILIES:
        for prefix in prefixes:
            if name.startswith(prefix):
                return family
    return None


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


def load_roles() -> dict:
    """Load the single authoritative role catalog (``praiseassistant/roles.json``)."""
    try:
        from importlib import resources

        data = resources.files("praiseassistant").joinpath("roles.json").read_text(encoding="utf-8")
    except Exception:  # pragma: no cover - fallback for source-tree use
        data = Path(__file__).parent.joinpath("roles.json").read_text(encoding="utf-8")
    return json.loads(data)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """
    CREATE TABLE IF NOT EXISTS candidates (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        title TEXT,
        summary TEXT,
        tool TEXT,
        tool_version TEXT,
        producer_model TEXT NOT NULL,
        producer_family TEXT,
        source_ref TEXT,
        sink_ref TEXT,
        boundary_invariant TEXT,
        evidence_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS transitions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        candidate_id TEXT,
        action TEXT NOT NULL,
        decision TEXT,
        reason TEXT,
        model TEXT,
        detail_json TEXT,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS reproductions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        candidate_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        clean_state_id TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        evidence_sha256 TEXT NOT NULL,
        model TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(candidate_id, run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        role TEXT NOT NULL,
        model TEXT NOT NULL,
        summary TEXT NOT NULL,
        ask TEXT,
        close TEXT,
        evidence_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS request_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        candidate_id TEXT,
        clean_state_id TEXT,
        url TEXT NOT NULL,
        method TEXT NOT NULL,
        role TEXT NOT NULL,
        model TEXT NOT NULL,
        status_code INTEGER,
        content_length INTEGER,
        content_type TEXT,
        truncated INTEGER,
        artifact_ref TEXT,
        error TEXT,
        epoch REAL NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
)


def _init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)
    conn.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1')"
    )


def connect(directory: str) -> sqlite3.Connection:
    """Open a fresh connection to ``<directory>/state.sqlite3`` and ensure schema.

    Creates the runtime-owned core tables only (candidates, transitions,
    reproductions, events, request_log, meta). The learning slice adds its own
    tables on top and never touches this schema. Each call returns an
    independent connection.
    """
    directory = _resolve_directory(directory)
    load_scope(directory)
    path = os.path.join(directory, _DB_FILENAME)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.isolation_level = None  # explicit transaction control
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        _init_schema(conn)
    except BaseException:
        conn.close()
        raise
    return conn


# ---------------------------------------------------------------------------
# Scope and initialization
# ---------------------------------------------------------------------------


def load_scope(directory: str) -> dict:
    """Read and validate ``<directory>/scope.json``; return a normalized scope."""
    directory = _resolve_directory(directory)
    path = os.path.join(directory, _SCOPE_FILENAME)
    if not os.path.isfile(path):
        raise PraiseError(f"not an engagement: missing {_SCOPE_FILENAME!r} in {directory}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PraiseError(f"cannot read scope: {exc}") from exc
    try:
        return policy.validate_scope(raw)
    except ValueError as exc:
        raise PraiseError(f"invalid scope: {exc}") from exc


def init_engagement(
    directory: str,
    *,
    program: str,
    basis: str,
    assets: list[str],
    mode: str = "source",
    methods: list[str] | None = None,
    max_requests: int = 0,
    interval_seconds: float = 1.0,
    created_at: str | None = None,
) -> dict:
    """Initialize an engagement directory (scope.json, DB, chat, evidence/).

    Never implies authorization outside the attested assets. Refuses to
    truncate a pre-existing, non-empty ``agentschat.md``.
    """
    directory = _resolve_directory(directory)

    program_s = "" if not isinstance(program, str) else program.strip()
    basis_s = "" if not isinstance(basis, str) else basis.strip()
    if not program_s:
        raise PraiseError("program is required")
    if not basis_s:
        raise PraiseError("authorization basis is required")
    if mode not in policy.ALLOWED_MODES:
        raise PraiseError(f"mode must be one of {policy.ALLOWED_MODES!r}, got {mode!r}")
    if not assets:
        raise PraiseError("at least one --asset is required")

    norm_methods = []
    for m in methods if methods else ["GET"]:
        if not isinstance(m, str) or not m.strip():
            raise PraiseError("allowed methods must be non-empty strings")
        norm_methods.append(m.strip().upper())


    # Validate and classify every asset before touching the filesystem.
    for asset in assets:
        try:
            policy.validate_asset(asset, mode, require_existing=True)
        except ValueError as exc:
            raise PraiseError(f"invalid asset {asset!r}: {exc}") from exc

    created = created_at or _now()
    scope = {
        "program": program_s,
        "authorization_basis": basis_s,
        "mode": mode,
        "assets": list(assets),
        "allowed_methods": norm_methods,
        "max_requests": max_requests,
        "interval_seconds": interval_seconds,
        "created_at": created,
    }
    try:
        policy.validate_scope(scope)
    except ValueError as exc:
        raise PraiseError(f"invalid scope: {exc}") from exc

    # --- Filesystem: refuse to overwrite, never truncate a manual log -----
    if os.path.exists(directory) and not os.path.isdir(directory):
        raise PraiseError(f"{directory} exists and is not a directory")

    scope_path = os.path.join(directory, _SCOPE_FILENAME)
    if os.path.exists(scope_path):
        raise PraiseError(f"engagement already initialized ({scope_path} exists)")

    chat_path = os.path.join(directory, _CHAT_FILENAME)
    if os.path.exists(chat_path):
        try:
            with open(chat_path, "r", encoding="utf-8") as fh:
                existing = fh.read()
        except OSError as exc:
            raise PraiseError(f"cannot inspect existing {_CHAT_FILENAME}: {exc}") from exc
        if existing.strip():
            raise PraiseError(
                f"refusing to overwrite existing {_CHAT_FILENAME}; migrate it explicitly"
            )

    os.makedirs(directory, exist_ok=True)
    os.makedirs(os.path.join(directory, _EVIDENCE_DIRNAME), exist_ok=True)


    # Atomic scope write, then DB, then a touch for the (empty) chat log.
    tmp_scope = scope_path + ".tmp"
    with open(tmp_scope, "w", encoding="utf-8") as fh:
        json.dump(scope, fh, indent=2, sort_keys=True)
    os.replace(tmp_scope, scope_path)

    conn = connect(directory)
    conn.close()

    if not os.path.exists(chat_path):
        with open(chat_path, "a", encoding="utf-8"):
            pass

    return policy.validate_scope(scope)


# ---------------------------------------------------------------------------
# Evidence artifacts
# ---------------------------------------------------------------------------


def artifact(directory: str, ref: str) -> dict:
    """Resolve an evidence reference; return ``{"path", "sha256"}``.

    ``ref`` is interpreted relative to ``<directory>/evidence/`` (absolute refs
    are resolved as-is). Raises ``ValueError`` for an empty reference or an
    escape, and ``FileNotFoundError`` for a missing artifact. ``realpath``
    resolves symlinks, so a link that points outside the evidence directory is
    rejected as an escape.
    """
    directory = _resolve_directory(directory)
    if not isinstance(ref, str) or not ref.strip():
        raise ValueError("empty evidence reference")

    evidence_dir = os.path.realpath(os.path.join(directory, _EVIDENCE_DIRNAME))
    if os.path.isabs(ref):
        candidate = os.path.realpath(ref)
    else:
        candidate = os.path.realpath(os.path.join(evidence_dir, ref))

    if candidate != evidence_dir and not candidate.startswith(evidence_dir + os.sep):
        raise ValueError("evidence reference escapes the evidence directory")
    if not os.path.isfile(candidate):
        raise FileNotFoundError(f"evidence artifact not found: {ref!r}")
    return {"path": candidate, "sha256": _sha256_file(candidate)}


def _anchor_evidence(directory: str, refs: list[str]) -> list[dict]:
    anchors = []
    for ref in refs:
        art = artifact(directory, ref)
        anchors.append({"ref": ref, "sha256": art["sha256"]})
    return anchors


def _verify_anchors(directory: str, anchors: list[dict], label: str) -> None:
    for item in anchors:
        art = artifact(directory, item["ref"])
        if art["sha256"] != item["sha256"]:
            raise PraiseError(
                f"{label} evidence {item['ref']!r} changed since recording (hash mismatch)"
            )


# ---------------------------------------------------------------------------
# Candidates and transitions
# ---------------------------------------------------------------------------


def _new_candidate_id() -> str:
    return "C" + uuid.uuid4().hex[:12]


def read_json_input(path: str) -> object:
    """Read and JSON-parse an input file, converting errors to ``PraiseError``."""
    if not isinstance(path, str) or not path.strip():
        raise PraiseError("input path must be a non-empty string")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PraiseError(f"cannot read input {path!r}: {exc}") from exc


def create_candidate(directory: str, finding: object) -> dict:
    """Create a candidate from a generic normalized finding.

    ``tool``/``tool_version`` are provenance only and never treated as a model
    identity; the observed ``producer_model`` is required and authoritative for
    family checks.
    """
    directory = _resolve_directory(directory)
    if not isinstance(finding, dict):
        raise PraiseError("candidate input must be a JSON object")

    producer_model = finding.get("producer_model")
    if not isinstance(producer_model, str) or not producer_model.strip():
        raise PraiseError("candidate requires a non-empty producer_model (observed model id)")
    producer_model = producer_model.strip()

    evidence = finding.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise PraiseError("candidate requires a non-empty evidence array")
    refs: list[str] = []
    for i, ref in enumerate(evidence):
        if not isinstance(ref, str) or not ref.strip():
            raise PraiseError(f"evidence[{i}] must be a non-empty reference string")
        refs.append(ref.strip())

    source_ref = finding.get("source_ref")
    sink_ref = finding.get("sink_ref")
    boundary_invariant = finding.get("boundary_invariant")
    has_source = bool(isinstance(source_ref, str) and source_ref.strip())
    has_sink = bool(isinstance(sink_ref, str) and sink_ref.strip())
    has_invariant = bool(isinstance(boundary_invariant, str) and boundary_invariant.strip())

    if has_source != has_sink:
        raise PraiseError("candidate needs both source_ref and sink_ref, or neither")

    candidate_id = finding.get("id")
    if candidate_id is None or (isinstance(candidate_id, str) and not candidate_id.strip()):
        candidate_id = _new_candidate_id()
    if not isinstance(candidate_id, str) or not candidate_id.strip():
        raise PraiseError("candidate id must be a non-empty string")
    candidate_id = candidate_id.strip()

    anchors = _anchor_evidence(directory, refs)
    producer_family = model_family(producer_model)
    now = _now()

    title = finding.get("title")
    summary = finding.get("summary")
    tool = finding.get("tool")
    tool_version = finding.get("tool_version")

    conn = connect(directory)
    try:
        if conn.execute("SELECT 1 FROM candidates WHERE id = ?", (candidate_id,)).fetchone():
            raise PraiseError(f"candidate id {candidate_id!r} already exists")
        with _tx(conn):
            conn.execute(
                "INSERT INTO candidates (id, status, title, summary, tool, tool_version,"
                " producer_model, producer_family, source_ref, sink_ref, boundary_invariant,"
                " evidence_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    candidate_id,
                    "candidate",
                    title,
                    summary,
                    tool,
                    tool_version,
                    producer_model,
                    producer_family,
                    source_ref if has_source else None,
                    sink_ref if has_sink else None,
                    boundary_invariant if has_invariant else None,
                    json.dumps(anchors),
                    now,
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO transitions (candidate_id, action, decision, reason, model,"
                " detail_json, created_at) VALUES (?,?,?,?,?,?,?)",
                (
                    candidate_id,
                    "candidate",
                    None,
                    "finding submitted",
                    producer_model,
                    json.dumps({"tool": tool, "tool_version": tool_version}),
                    now,
                ),
            )
    finally:
        conn.close()

    return {
        "id": candidate_id,
        "status": "candidate",
        "producer_model": producer_model,
        "producer_family": producer_family,
        "evidence": anchors,
        "source_ref": source_ref if has_source else None,
        "sink_ref": sink_ref if has_sink else None,
        "boundary_invariant": boundary_invariant if has_invariant else None,
        "tool": tool,
        "tool_version": tool_version,
        "created_at": now,
    }


def _fetch_candidate(conn: sqlite3.Connection, candidate_id: str) -> dict:
    row = conn.execute("SELECT * FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
    if row is None:
        raise PraiseError(f"candidate not found: {candidate_id}")
    return dict(row)


def _producer_models(candidate: dict, repros: list[sqlite3.Row]) -> list[str]:
    models: list[str] = []
    for m in [candidate["producer_model"]] + [r["model"] for r in repros]:
        if m and m not in models:
            models.append(m)
    return models


def get_candidate(directory: str, candidate_id: str) -> dict | None:
    """Return a candidate with ``status``, ``producer_models``, and history.

    Returns ``None`` when the id is not found. ``producer_models`` lists the
    distinct observed producer identifiers: the candidate's producer first,
    then reproduction models in insertion order.
    """
    directory = _resolve_directory(directory)
    conn = connect(directory)
    try:
        row = conn.execute("SELECT * FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
        if row is None:
            return None
        candidate = dict(row)
        repros = conn.execute(
            "SELECT * FROM reproductions WHERE candidate_id = ? ORDER BY id", (candidate_id,)
        ).fetchall()
        transitions = conn.execute(
            "SELECT * FROM transitions WHERE candidate_id = ? ORDER BY id", (candidate_id,)
        ).fetchall()

        candidate["evidence"] = json.loads(candidate["evidence_json"] or "[]")
        candidate["producer_models"] = _producer_models(candidate, repros)
        candidate["reproductions"] = [
            {
                "run_id": r["run_id"],
                "clean_state_id": r["clean_state_id"],
                "evidence_ref": r["evidence_ref"],
                "evidence_sha256": r["evidence_sha256"],
                "model": r["model"],
                "created_at": r["created_at"],
            }
            for r in repros
        ]
        candidate["transitions"] = [
            {
                "action": t["action"],
                "decision": t["decision"],
                "reason": t["reason"],
                "model": t["model"],
                "created_at": t["created_at"],
            }
            for t in transitions
        ]
        candidate.pop("evidence_json", None)
        return candidate
    finally:
        conn.close()


def gate_candidate(directory: str, candidate_id: str, decision: str, reason: str, model: str) -> dict:
    """Apply a gate decision. ``pass`` is class-aware: it requires concrete
    evidence plus source/sink references or a named boundary invariant, but no
    runtime reproduction."""
    directory = _resolve_directory(directory)
    if decision not in GATE_DECISIONS:
        raise PraiseError(f"invalid gate decision {decision!r}")
    if not reason or not reason.strip():
        raise PraiseError("gate reason is required")
    if not model or not model.strip():
        raise PraiseError("gate model is required")

    conn = connect(directory)
    try:
        with _tx(conn):
            candidate = _fetch_candidate(conn, candidate_id)
            status = candidate["status"]
            if status not in ("candidate", "substantiated", "held"):
                raise PraiseError(
                    f"cannot gate candidate in status {status!r}; expected candidate/substantiated/held"
                )

            if decision == "pass":
                evidence = json.loads(candidate["evidence_json"] or "[]")
                if not evidence:
                    raise PraiseError("cannot pass gate: candidate has no evidence")
                has_refs = bool(candidate["source_ref"] and candidate["sink_ref"])
                has_invariant = bool(candidate["boundary_invariant"])
                if not (has_refs or has_invariant):
                    raise PraiseError(
                        "cannot pass gate: candidate has neither source_ref+sink_ref nor a boundary_invariant"
                    )
                _verify_anchors(directory, evidence, "candidate")
                new_status = "gated"
            elif decision == "hold":
                new_status = "held"
            else:
                new_status = "rejected"

            now = _now()
            conn.execute(
                "UPDATE candidates SET status = ?, updated_at = ? WHERE id = ?",
                (new_status, now, candidate_id),
            )
            conn.execute(
                "INSERT INTO transitions (candidate_id, action, decision, reason, model,"
                " detail_json, created_at) VALUES (?,?,?,?,?,?,?)",
                (candidate_id, "gate", decision, reason, model, None, now),
            )
    finally:
        conn.close()

    return {"candidate_id": candidate_id, "decision": decision, "status": new_status, "model": model}


def add_reproduction(
    directory: str,
    candidate_id: str,
    run_id: str,
    clean_state_id: str,
    evidence_ref: str,
    model: str,
) -> dict:
    """Record one clean-state reproduction of a gated candidate."""
    directory = _resolve_directory(directory)
    if not run_id or not run_id.strip():
        raise PraiseError("run id is required")
    if not clean_state_id or not clean_state_id.strip():
        raise PraiseError("clean-state id is required")
    if not model or not model.strip():
        raise PraiseError("reproduction model is required")
    run_id = run_id.strip()
    clean_state_id = clean_state_id.strip()
    model = model.strip()

    art = artifact(directory, evidence_ref)  # raises on missing/traversal

    conn = connect(directory)
    try:
        with _tx(conn):
            candidate = _fetch_candidate(conn, candidate_id)
            status = candidate["status"]
            if status not in ("gated", "reproduced"):
                raise PraiseError(
                    f"cannot reproduce candidate in status {status!r}; expected gated or reproduced"
                )
            if conn.execute(
                "SELECT 1 FROM reproductions WHERE candidate_id = ? "
                "AND (run_id = ? OR evidence_ref = ? OR evidence_sha256 = ?)",
                (candidate_id, run_id, evidence_ref, art["sha256"]),
            ).fetchone():
                raise PraiseError("reproduction run and evidence artifact must not be reused")

            now = _now()
            conn.execute(
                "INSERT INTO reproductions (candidate_id, run_id, clean_state_id,"
                " evidence_ref, evidence_sha256, model, created_at) VALUES (?,?,?,?,?,?,?)",
                (candidate_id, run_id, clean_state_id, evidence_ref, art["sha256"], model, now),
            )
            conn.execute(
                "UPDATE candidates SET status = ?, updated_at = ? WHERE id = ?",
                ("reproduced", now, candidate_id),
            )
            conn.execute(
                "INSERT INTO transitions (candidate_id, action, decision, reason, model,"
                " detail_json, created_at) VALUES (?,?,?,?,?,?,?)",
                (
                    candidate_id,
                    "reproduce",
                    None,
                    f"clean-state reproduction {run_id}",
                    model,
                    json.dumps({"run_id": run_id, "clean_state_id": clean_state_id}),
                    now,
                ),
            )
    finally:
        conn.close()

    distinct = _distinct_clean_states(directory, candidate_id)
    return {
        "candidate_id": candidate_id,
        "run_id": run_id,
        "clean_state_id": clean_state_id,
        "evidence_ref": evidence_ref,
        "evidence_sha256": art["sha256"],
        "status": "reproduced",
        "distinct_clean_states": len(distinct),
    }


def _distinct_clean_states(directory: str, candidate_id: str) -> set[str]:
    conn = connect(directory)
    try:
        rows = conn.execute(
            "SELECT DISTINCT clean_state_id FROM reproductions WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchall()
        return {r["clean_state_id"] for r in rows}
    finally:
        conn.close()


def _verify_checker_family(candidate: dict, repros: list[sqlite3.Row], model: str) -> str:
    family = model_family(model)
    if family is None:
        raise PraiseError(
            f"checker model family is unknown: {model!r}; cannot issue a final decision"
        )
    producer_families: set[str] = set()
    for m in _producer_models(candidate, repros):
        f = model_family(m)
        if f is None:
            raise PraiseError(
                f"cannot verify checker independence: producer model {m!r} has unknown family"
            )
        producer_families.add(f)
    if family in producer_families:
        raise PraiseError(
            f"independence violation: checker family {family!r} matches a producer family"
            f" {sorted(producer_families)!r}"
        )
    return family


def record_verdict(
    directory: str,
    candidate_id: str,
    decision: str,
    reason: str,
    model: str,
    evidence_refs: list[str] | None = None,
) -> dict:
    """Record a verdict. Confirmation requires two distinct clean-state IDs and
    intact evidence; every decision requires an independent, known-family checker."""
    directory = _resolve_directory(directory)
    evidence_refs = list(evidence_refs or [])
    if decision not in VERDICT_DECISIONS:
        raise PraiseError(f"invalid verdict decision {decision!r}")
    if not reason or not reason.strip():
        raise PraiseError("verdict reason is required")
    if not model or not model.strip():
        raise PraiseError("verdict model is required")

    conn = connect(directory)
    try:
        with _tx(conn):
            candidate = _fetch_candidate(conn, candidate_id)
            status = candidate["status"]
            if status in ("confirmed", "rejected", "duplicate"):
                raise PraiseError(f"candidate {candidate_id!r} is already closed ({status})")
            repros = conn.execute(
                "SELECT * FROM reproductions WHERE candidate_id = ? ORDER BY id", (candidate_id,)
            ).fetchall()
            checker_family = _verify_checker_family(candidate, repros, model)
            _verify_anchors(directory, json.loads(candidate["evidence_json"] or "[]"), "candidate")
            for r in repros:
                art = artifact(directory, r["evidence_ref"])
                if art["sha256"] != r["evidence_sha256"]:
                    raise PraiseError(
                        f"reproduction evidence {r['evidence_ref']!r} changed since recording (hash mismatch)"
                    )
            verdict_anchors = _anchor_evidence(directory, evidence_refs)
            distinct = {r["clean_state_id"] for r in repros}
            if decision == "confirmed":
                if status != "reproduced":
                    raise PraiseError(
                        f"cannot confirm: candidate status is {status!r}, requires 'reproduced'"
                    )
                if len(distinct) < 2 or len({r["evidence_sha256"] for r in repros}) < 2:
                    raise PraiseError(
                        "confirmation requires two distinct clean-state IDs and evidence artifacts"
                    )
                new_status = "confirmed"
            elif decision == "needs-more-proof":
                new_status = status
            elif decision == "rejected":
                new_status = "rejected"
            else:
                new_status = "duplicate"

            now = _now()
            conn.execute(
                "UPDATE candidates SET status = ?, updated_at = ? WHERE id = ?",
                (new_status, now, candidate_id),
            )
            conn.execute(
                "INSERT INTO transitions (candidate_id, action, decision, reason, model,"
                " detail_json, created_at) VALUES (?,?,?,?,?,?,?)",
                (
                    candidate_id,
                    "verdict",
                    decision,
                    reason,
                    model,
                    json.dumps({"evidence": verdict_anchors, "checker_family": checker_family}),
                    now,
                ),
            )
    finally:
        conn.close()

    return {
        "candidate_id": candidate_id,
        "decision": decision,
        "status": new_status,
        "checker_model": model,
        "checker_family": checker_family,
        "producer_models": _producer_models(candidate, repros),
        "distinct_clean_states": sorted(distinct),
        "reproduction_count": len(repros),
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def _select_independent_model(role_models: list[str], producer_models: list[str], agent: str) -> str:
    producer_families: set[str] = set()
    for m in producer_models:
        f = model_family(m)
        if f is None:
            raise PraiseError(
                f"cannot select an independent checker: producer model {m!r} has unknown family"
            )
        producer_families.add(f)
    for m in role_models:
        f = model_family(m)
        if f is not None and f not in producer_families:
            return m
    raise PraiseError(
        f"no independent checker model available for {agent!r} against producer families"
        f" {sorted(producer_families)!r}"
    )


def dispatch(
    directory: str,
    stage: str,
    candidate_id: str | None = None,
    escalated: bool = False,
    reason: str | None = None,
) -> dict:
    """Resolve an explicit stage to an agent and model from the role catalog.

    Checker stages (verdict/patch) select a model from a different known family
    than the candidate's recorded producers. ``proof`` requires a gated or
    reproduced candidate. No candidate is required for plan/recon/discover/gate.
    """
    directory = _resolve_directory(directory)
    load_scope(directory)
    if stage not in STAGES:
        raise PraiseError(f"unknown stage {stage!r}; expected one of {STAGES!r}")

    roles = load_roles()
    stages = roles.get("stages", {})
    escalations = roles.get("escalations", {})

    if escalated:
        if not reason or not reason.strip():
            raise PraiseError("escalation requires a specific unresolved reason")
        if stage not in escalations:
            raise PraiseError(f"stage {stage!r} has no escalation lane")
        agent = escalations[stage]
    else:
        agent = stages.get(stage)
    if not agent:
        raise PraiseError(f"no agent mapped for stage {stage!r}")

    role = roles.get("roles", {}).get(agent)
    if not role:
        raise PraiseError(f"no role definition for agent {agent!r}")

    producer_models: list[str] = []
    if stage in ("proof", "verdict", "patch"):
        if not candidate_id:
            raise PraiseError(f"stage {stage!r} requires --candidate")
        candidate = get_candidate(directory, candidate_id)
        if candidate is None:
            raise PraiseError(f"candidate not found: {candidate_id}")
        if stage == "proof" and candidate["status"] not in ("gated", "reproduced"):
            raise PraiseError(
                f"proof dispatch requires a gated or reproduced candidate"
                f" (status={candidate['status']!r})"
            )
        producer_models = candidate["producer_models"]

    candidates = role.get("models", [])
    if not candidates:
        raise PraiseError(f"role {agent!r} declares no models")

    if role.get("independent"):
        model = _select_independent_model(candidates, producer_models, agent)
    else:
        model = candidates[0]

    result: dict = {
        "stage": stage,
        "agent": agent,
        "model": model,
        "family": model_family(model),
        "escalated": bool(escalated),
    }
    if candidate_id:
        result["candidate_id"] = candidate_id
        if stage in ("verdict", "patch"):
            result["producer_models"] = producer_models
            result["producer_families"] = sorted(
                {model_family(m) for m in producer_models if model_family(m)}
            )
    return result


# ---------------------------------------------------------------------------
# Chat projection
# ---------------------------------------------------------------------------


def _append_chat_projection(
    fh,
    directory: str,
    seq: int,
    role: str,
    model: str,
    summary: str,
    ask: str | None,
    close: str | None,
    evidence_refs: list[str],
    created_at_z: str,
) -> None:
    """The caller holds the projection lock across the DB commit and this append."""
    escaped = lambda text: json.dumps(text, ensure_ascii=False)[1:-1]
    target = escaped(os.path.basename(directory))
    lines = [f"### {created_at_z} | {role} | {model} | {target} | seq={seq}", f"SUMMARY: {escaped(summary)}"]
    if evidence_refs:
        lines.append("EVIDENCE: " + json.dumps(evidence_refs, ensure_ascii=False))
    if ask is not None:
        lines.append(f"ASK: {escaped(ask)}")
    else:
        lines.append(f"CLOSE: {escaped(close)}")
    block = "\n".join(lines) + "\n\n"

    fh.write(block)
    fh.flush()
    os.fsync(fh.fileno())


def record_event(
    directory: str,
    role: str,
    model: str,
    summary: str,
    ask: str | None = None,
    close: str | None = None,
    evidence: list[str] | None = None,
) -> dict:
    """Record a durable chat event and append its Markdown projection.

    Each entry requires exactly one of ``ask`` or ``close`` and a non-empty
    role, observed model, and summary.
    """
    directory = _resolve_directory(directory)
    if not role or not role.strip():
        raise PraiseError("chat role is required")
    if not model or not model.strip():
        raise PraiseError("chat model is required")
    if any(char in role + model for char in "\r\n|"):
        raise PraiseError("chat role and model must be single-line identifiers without '|'")
    if not summary or not summary.strip():
        raise PraiseError("chat summary is required")
    if (ask is None) == (close is None):
        raise PraiseError("chat entry requires exactly one of ask or close")
    if ask is not None and not ask.strip():
        raise PraiseError("ask must be non-empty when provided")
    if close is not None and not close.strip():
        raise PraiseError("close must be non-empty when provided")

    evidence = list(evidence or [])
    anchors = _anchor_evidence(directory, evidence)
    conn = connect(directory)
    try:
        with open(os.path.join(directory, _CHAT_FILENAME), "a", encoding="utf-8") as fh:
            _lock_file(fh)
            try:
                created_at = _now()
                with _tx(conn):
                    cur = conn.execute(
                        "INSERT INTO events (role, model, summary, ask, close, evidence_json, created_at)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (role.strip(), model.strip(), summary.strip(), ask, close, json.dumps(anchors), created_at),
                    )
                    seq = cur.lastrowid
                _append_chat_projection(
                    fh, directory, seq, role.strip(), model.strip(), summary.strip(),
                    ask, close, [a["ref"] for a in anchors], created_at.replace("+00:00", "Z"),
                )
            finally:
                _unlock_file(fh)
    finally:
        conn.close()

    return {
        "seq": seq,
        "role": role.strip(),
        "model": model.strip(),
        "summary": summary.strip(),
        "ask": ask,
        "close": close,
        "evidence": [a["ref"] for a in anchors],
        "created_at": created_at,
    }


# ---------------------------------------------------------------------------
# Controlled HTTP requests
# ---------------------------------------------------------------------------


def _build_opener() -> urllib.request.OpenerDirector:
    # Deliberately omit ProxyHandler (disables environment proxies) and
    # HTTPRedirectHandler (redirects are never followed). HTTPSHandler uses the
    # verified default TLS context.
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.UnknownHandler())
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    return opener


def _http_fetch(req: urllib.request.Request) -> tuple[int | None, int, str | None, bool, bytes]:
    opener = _build_opener()
    resp = opener.open(req, timeout=REQUEST_TIMEOUT)
    try:
        status = None
        for attr in ("status", "code"):
            status = getattr(resp, attr, None)
            if status is not None:
                break
        if status is None and hasattr(resp, "getcode"):
            status = resp.getcode()

        headers = getattr(resp, "headers", None)
        content_type = headers.get("Content-Type") if headers is not None else None

        body = resp.read(MAX_RESPONSE_BYTES + 1)
        truncated = len(body) > MAX_RESPONSE_BYTES
        body = body[:MAX_RESPONSE_BYTES]
        content_length = len(body)
    finally:
        resp.close()
    return status, content_length, content_type, truncated, body


def _reserve_request(
    conn: sqlite3.Connection,
    scope: dict,
    candidate_id: str | None,
    clean_state_id: str | None,
    url: str,
    method: str,
    role: str,
    model: str,
) -> int:
    """Atomically enforce the shared request budget and throttle, reserving a slot."""
    max_requests = scope["max_requests"]
    interval = scope["interval_seconds"]
    now_epoch = time.time()
    created_at = _now()

    with _tx(conn):
        if candidate_id is not None:
            candidate = _fetch_candidate(conn, candidate_id)
            if candidate["status"] not in ("gated", "reproduced"):
                raise PraiseError("candidate-bound proof requests require a gated or reproduced candidate")
        count = conn.execute("SELECT COUNT(*) AS c FROM request_log").fetchone()["c"]
        if count >= max_requests:
            raise PraiseError(f"request budget exhausted ({count}/{max_requests})")
        if interval > 0:
            last = conn.execute("SELECT MAX(epoch) AS e FROM request_log").fetchone()["e"]
            if last is not None and (now_epoch - last) < interval:
                raise PraiseError(f"throttle: requests must be at least {interval:g}s apart")

        cur = conn.execute(
            "INSERT INTO request_log (candidate_id, clean_state_id, url, method, role, model,"
            " epoch, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (candidate_id, clean_state_id, url, method, role, model, now_epoch, created_at),
        )
        return cur.lastrowid


def _finalize_request(
    directory: str,
    request_id: int,
    status_code: int | None = None,
    content_length: int | None = None,
    content_type: str | None = None,
    truncated: bool | None = None,
    artifact_ref: str | None = None,
    error: str | None = None,
) -> None:
    conn = connect(directory)
    try:
        with _tx(conn):
            conn.execute(
                "UPDATE request_log SET status_code=?, content_length=?, content_type=?,"
                " truncated=?, artifact_ref=?, error=? WHERE id=?",
                (
                    status_code,
                    content_length,
                    content_type,
                    1 if truncated else 0,
                    artifact_ref,
                    error,
                    request_id,
                ),
            )
    finally:
        conn.close()


def _write_request_artifact(
    directory: str,
    request_id: int,
    url: str,
    method: str,
    status: int | None,
    content_length: int,
    content_type: str | None,
    truncated: bool,
    response_body: object,
) -> str:
    evidence_dir = os.path.join(directory, _EVIDENCE_DIRNAME)
    os.makedirs(evidence_dir, exist_ok=True)
    ref = f"request-{request_id}.json"
    path = os.path.join(evidence_dir, ref)
    # Persist only bounded, redacted text/JSON, never request credentials or raw headers.
    payload = {
        "request_id": request_id,
        "url": url,
        "method": method,
        "status_code": status,
        "content_length": content_length,
        "content_type": content_type,
        "truncated": bool(truncated),
        "response_body": response_body,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return ref


def perform_request(
    directory: str,
    url: str,
    method: str = "GET",
    role: str = "",
    model: str = "",
    candidate_id: str | None = None,
    clean_state_id: str | None = None,
    headers: dict | None = None,
    body: str | None = None,
) -> dict:
    """Perform one controlled, in-scope HTTP request and record bounded evidence.

    Enforces exact asset boundaries, allowed methods, disabled proxy/redirects,
    verified TLS, a conservative byte cap and timeout, and atomic cross-process
    request budgets/throttle. No generic shell tool is involved.
    """
    directory = _resolve_directory(directory)
    scope = load_scope(directory)

    method = (method or "GET").strip().upper()
    if method not in scope["allowed_methods"]:
        raise PraiseError(f"method {method!r} is not in allowed methods {scope['allowed_methods']!r}")
    if not role or not role.strip():
        raise PraiseError("request role is required")
    if not model or not model.strip():
        raise PraiseError("request model is required")

    try:
        policy.split_url(url)  # reject credentials/traversal/encoding
    except ValueError as exc:
        raise PraiseError(f"URL rejected: {exc}") from exc

    if not any(policy.url_allowed(asset, url) for asset in scope["url_assets"]):
        raise PraiseError("URL is outside the allowed assets")

    if headers is None:
        headers = {}
    if not isinstance(headers, dict):
        raise PraiseError("headers must be a JSON object")
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
        raise PraiseError("header names and values must be strings")
    forbidden_headers = {"host", "content-length", "transfer-encoding", "connection", "proxy-connection", "proxy-authorization", "upgrade", "te", "trailer"}
    for name, value in headers.items():
        if name.lower() in forbidden_headers:
            raise PraiseError(f"routing/framing header {name!r} is not allowed")
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name) or "\r" in value or "\n" in value:
            raise PraiseError("invalid header name or value")
    if body is not None and not isinstance(body, str):
        raise PraiseError("request body must be text")

    data = None if body is None else body.encode("utf-8")
    if data is not None and len(data) > MAX_RESPONSE_BYTES:
        raise PraiseError("request body exceeds the 64 KiB cap")
    secrets = response_evidence.secrets_for_request(url, headers, body)
    safe_url = response_evidence.redact_url(url)
    req = urllib.request.Request(url, data=data, headers=dict(headers), method=method)

    conn = connect(directory)
    try:
        request_id = _reserve_request(
            conn, scope, candidate_id, clean_state_id, safe_url, method, role.strip(), model.strip()
        )
    finally:
        conn.close()

    try:
        status, content_length, content_type, truncated, raw_body = _http_fetch(req)
    except Exception as exc:
        error = response_evidence.redact_text(f"{type(exc).__name__}: {exc}", secrets)
        _finalize_request(directory, request_id, error=error)
        raise PraiseError(f"request failed: {error}") from exc

    response_body = response_evidence.capture_body(raw_body, content_type, secrets)
    artifact_ref = _write_request_artifact(
        directory, request_id, safe_url, method, status, content_length, content_type, truncated, response_body
    )
    _finalize_request(
        directory,
        request_id,
        status_code=status,
        content_length=content_length,
        content_type=content_type,
        truncated=truncated,
        artifact_ref=artifact_ref,
    )

    return {
        "request_id": request_id,
        "url": safe_url,
        "method": method,
        "status_code": status,
        "content_length": content_length,
        "content_type": content_type,
        "truncated": truncated,
        "response_body": response_body,
        "redirect_followed": False,
        "artifact_ref": artifact_ref,
        "candidate_id": candidate_id,
        "clean_state_id": clean_state_id,
    }


# ---------------------------------------------------------------------------
# Fix validation
# ---------------------------------------------------------------------------


def _evaluate_fix_gates(directory: str, gates: object) -> tuple[str, dict, dict]:
    if not isinstance(gates, dict):
        raise PraiseError("validate-fix input must be a JSON object")

    summary: dict[str, str] = {}
    anchors: dict[str, list] = {}
    for name in FIX_GATES:
        if name not in gates:
            summary[name] = "missing"
            continue
        gate = gates[name]
        if not isinstance(gate, dict):
            raise PraiseError(f"gate {name!r} must be an object")
        status = gate.get("status")
        if status not in FIX_GATE_STATUSES:
            raise PraiseError(f"gate {name!r} has invalid status {status!r}")
        evidence = gate.get("evidence", [])
        if not isinstance(evidence, list):
            raise PraiseError(f"gate {name!r} evidence must be an array")
        anchors[name] = _anchor_evidence(directory, evidence)
        summary[name] = "missing-evidence" if status == "pass" and not anchors[name] else status

    statuses = set(summary.values())
    if statuses & {"fail", "partial"}:
        result = "not-fixed"
    elif statuses == {"pass"}:
        result = "fixed"
    else:
        result = "unverifiable"
    return result, summary, anchors


def validate_fix(directory: str, candidate_id: str, model: str, gates: object) -> dict:
    """Validate a proposed fix against exactly four evidence-backed gates.

    ``fixed`` requires every gate to pass; a failed or partial gate is never
    overridden by a score, and a missing or skipped gate is unverifiable.
    """
    directory = _resolve_directory(directory)
    if not model or not model.strip():
        raise PraiseError("validate-fix model is required")

    conn = connect(directory)
    try:
        with _tx(conn):
            candidate = _fetch_candidate(conn, candidate_id)
            repros = conn.execute(
                "SELECT * FROM reproductions WHERE candidate_id = ? ORDER BY id", (candidate_id,)
            ).fetchall()
            checker_family = _verify_checker_family(candidate, repros, model)
            result, gate_summary, anchors = _evaluate_fix_gates(directory, gates)
            now = _now()
            conn.execute(
                "INSERT INTO transitions (candidate_id, action, decision, reason, model,"
                " detail_json, created_at) VALUES (?,?,?,?,?,?,?)",
                (
                    candidate_id,
                    "validate_fix",
                    result,
                    "fix validation",
                    model,
                    json.dumps({"gates": gate_summary, "evidence": anchors, "checker_family": checker_family}),
                    now,
                ),
            )
    finally:
        conn.close()

    return {
        "candidate_id": candidate_id,
        "result": result,
        "gates": gate_summary,
        "reviewer_model": model,
        "reviewer_family": checker_family,
    }


# ---------------------------------------------------------------------------
# Show
# ---------------------------------------------------------------------------


def show(directory: str, candidate_id: str | None = None) -> dict:
    """Return the engagement state, or a single candidate when ``candidate_id``.

    The scope projection includes ``source_roots`` (authorized local directory
    roots) and ``url_assets`` so an extension can constrain native reads.
    """
    directory = _resolve_directory(directory)
    scope = load_scope(directory)
    conn = connect(directory)
    try:
        events = conn.execute(
            "SELECT seq, role, model, summary, ask, close, evidence_json, created_at"
            " FROM events ORDER BY seq DESC LIMIT 20"
        ).fetchall()
        recent_events = []
        for row in reversed(events):
            event = dict(row)
            event["evidence"] = json.loads(event.pop("evidence_json"))
            recent_events.append(event)
    finally:
        conn.close()

    if candidate_id is not None:
        candidate = get_candidate(directory, candidate_id)
        if candidate is None:
            raise PraiseError(f"candidate not found: {candidate_id}")
        return {"directory": directory, "scope": scope, "candidate": candidate, "recent_events": recent_events}

    conn = connect(directory)
    try:
        rows = conn.execute(
            "SELECT id, status, title, producer_model, producer_family, created_at, updated_at"
            " FROM candidates ORDER BY created_at, id"
        ).fetchall()
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        candidates = [dict(r) for r in rows]
    finally:
        conn.close()

    return {
        "directory": directory,
        "scope": scope,
        "candidates": candidates,
        "counts": counts,
        "recent_events": recent_events,
    }
