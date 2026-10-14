"""PraiseAssistant runtime: the standard-library CLI/state/control layer.

This module owns the engagement lifecycle and every state transition:

* scoped initialization and scope loading,
* SHA256-anchored evidence artifacts,
* class-aware candidate gating,
* two distinct clean-state reproductions before confirmation,
* producer-family independence checks for final decisions,
* explicit stage dispatch against a single authoritative role catalog,
* addressed JSON messages and incremental durable inboxes,
* controlled HTTP proof-of-concept requests,
* fail-closed fix validation.

All durable state lives in the engagement SQLite database; the Markdown audit
file and JSON responses are projections of that state, never authority.
Standard library only; no third-party imports.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import tempfile
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
    "register_agent",
    "send_message",
    "inbox",
    "peers",
    "emit_message",
    "project_messages",
    "create_candidate",
    "gate_candidate",
    "add_reproduction",
    "record_verdict",
    "record_review",
    "lead_launch",
    "create_packet",
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
STAGES = ("plan", "recon", "discover", "gate", "proof", "verdict", "review", "patch")

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
REVIEW_DECISIONS = ("approved", "needs-more-proof", "rejected")
TIERS = ("normal", "deep", "expert", "expert-max")

#: Fix-validation gate names and their allowed statuses.
FIX_GATES = ("root_cause", "instance_coverage", "no_new_vulnerabilities", "security_best_practices")
FIX_GATE_STATUSES = ("pass", "partial", "fail", "skip")

#: Conservative cap on response bytes read for a proof request.
MAX_RESPONSE_BYTES = 65536
#: Conservative request timeout, seconds.
REQUEST_TIMEOUT = 10.0

MAX_MESSAGE_BYTES = 2048
MAX_ENVELOPE_BYTES = 4096
MAX_INBOX_BYTES = 8192
MESSAGE_TOPICS = frozenset({"@lead", "@learning", *(f"@{stage}" for stage in STAGES)})

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
    ("catjam", ("cat-jam", "catjam")),
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
    """Load the single authoritative role catalog (``praise/roles.json``)."""
    try:
        from importlib import resources

        data = resources.files("praise").joinpath("roles.json").read_text(encoding="utf-8")
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
        producer_agent TEXT,
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
        producer_agent TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(candidate_id, run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS participants (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        model TEXT NOT NULL,
        candidate_id TEXT,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS messages (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        kind TEXT NOT NULL,
        candidate_id TEXT,
        reply_to INTEGER,
        data_json TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        role TEXT NOT NULL,
        model TEXT NOT NULL,
        created_at TEXT NOT NULL,
        dedup_key TEXT,
        UNIQUE(sender, dedup_key)
    )
    """,
    "CREATE INDEX IF NOT EXISTS messages_recipient_seq ON messages (recipient, seq)",
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
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
    version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone() if exists else None
    if version and version[0] == "2":
        return
    if version and version[0] != "1":
        raise PraiseError(f"unsupported engagement schema version: {version[0]}")
    with _tx(conn):
        for statement in _SCHEMA:
            conn.execute(statement)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(candidates)")}
        if "producer_agent" not in columns:
            conn.execute("ALTER TABLE candidates ADD COLUMN producer_agent TEXT")
        repro_columns = {row[1] for row in conn.execute("PRAGMA table_info(reproductions)")}
        if "producer_agent" not in repro_columns:
            conn.execute("ALTER TABLE reproductions ADD COLUMN producer_agent TEXT")
        if version:
            # Preserve history without replaying old requests into live worker inboxes.
            for row in conn.execute("SELECT * FROM events ORDER BY seq").fetchall():
                data = {"summary": row["summary"], "ask" if row["ask"] is not None else "close": row["ask"] or row["close"]}
                conn.execute(
                    "INSERT INTO messages (seq,sender,recipient,kind,data_json,evidence_json,role,model,created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (row["seq"], row["role"], "@archive", "ask" if row["ask"] is not None else "close",
                     json.dumps(data, ensure_ascii=False, separators=(",", ":")), row["evidence_json"],
                     row["role"], row["model"], row["created_at"]),
                )
        conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('schema_version','2')")


def connect(directory: str) -> sqlite3.Connection:
    """Open a fresh connection to ``<directory>/state.sqlite3`` and ensure schema.

    Creates the runtime-owned core tables (candidates, transitions,
    reproductions, participants, messages, request_log, meta). The learning
    slice adds its own tables on top. Each call returns an independent connection.
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



def _bounded_text(value: object, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum:
        raise PraiseError(f"{label} must be nonempty text of at most {maximum} UTF-8 bytes")
    return value


def _bounded_strings(value: object, label: str, maximum: int = 16, width: int = 512) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise PraiseError(f"{label} must be a list of at most {maximum} strings")
    for item in value:
        _bounded_text(item, label, width)
    return value


def _relative_artifact(directory: str, ref: object) -> dict:
    _bounded_text(ref, "artifact reference")
    if os.path.isabs(ref) or ".." in Path(ref).parts:
        raise PraiseError("packet artifact references must be relative and confined to evidence/")
    return artifact(directory, ref)


def _read_packet(directory: str, ref: str, candidate_id: str | None) -> dict:
    art = _relative_artifact(directory, ref)
    with open(art["path"], "rb") as fh:
        raw = fh.read(8193)
    if len(raw) > 8192:
        raise PraiseError("evidence packet exceeds 8192 UTF-8 bytes")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise PraiseError("evidence packet must be valid UTF-8 JSON") from exc
    _validate_packet(directory, data, candidate_id)
    if hashlib.sha256(raw).hexdigest() != art["sha256"]:
        raise PraiseError("packet changed while being read")
    return {"ref": ref, "sha256": art["sha256"], "data": data}


def _validate_packet(directory: str, data: object, candidate_id: str | None) -> None:
    required = {"hypothesis", "question", "relevant_sources", "observations", "evidence", "proof_status"}
    allowed = required | {"finding_id", "target", "source_excerpts", "contradictions",
                          "unresolved_questions", "complexity", "confidence", "execution_failure"}
    if not isinstance(data, dict) or not required <= data.keys() or data.keys() - allowed:
        raise PraiseError("evidence packet has missing or unknown fields")
    for field in ("hypothesis", "question"):
        _bounded_text(data[field], field, 1024)
    for field in ("relevant_sources", "observations", "contradictions", "unresolved_questions"):
        if field in data:
            _bounded_strings(data[field], field)
    if "source_excerpts" in data:
        _bounded_strings(data["source_excerpts"], "source_excerpts", 8, 1024)
    if "target" in data:
        _bounded_text(data["target"], "target")
    if data.get("finding_id") != candidate_id:
        raise PraiseError("packet finding_id must match the dispatched candidate")
    if data["proof_status"] not in ("confirmed", "rejected", "unresolved"):
        raise PraiseError("packet proof_status is invalid")
    _validate_report_values(data, status_field="proof_status")
    refs = _bounded_strings(data["evidence"], "packet evidence", 8)
    if not refs:
        raise PraiseError("evidence packet requires artifact evidence")
    for evidence_ref in refs:
        _relative_artifact(directory, evidence_ref)


def create_packet(directory: str, data: object, model: str, agent: str | None = None) -> dict:
    """Write only validated, content-addressed evidence packets for scoped tools."""
    directory = _resolve_directory(directory)
    load_scope(directory)
    model = _identifier(model, "observed packet author model")
    conn = connect(directory)
    try:
        participant = _check_actor(conn, agent, model)
        if isinstance(data, dict) and data.get("finding_id") is not None:
            _identifier(data["finding_id"], "packet finding_id")
        candidate_id = data.get("finding_id") if isinstance(data, dict) else None
        if candidate_id is not None:
            _fetch_candidate(conn, candidate_id)
        if participant is not None and participant["candidate_id"] not in (None, candidate_id):
            raise PraiseError("packet must match the registered task candidate")
        _validate_packet(directory, data, candidate_id)
        try:
            raw = _json(data).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise PraiseError("packet must contain finite JSON values") from exc
        if len(raw) > 8192:
            raise PraiseError("evidence packet exceeds 8192 UTF-8 bytes")
        sha256 = hashlib.sha256(raw).hexdigest()
        ref = f"packet-{sha256}.json"
        evidence_dir = os.path.realpath(os.path.join(directory, _EVIDENCE_DIRNAME))
        if evidence_dir != os.path.join(os.path.realpath(directory), _EVIDENCE_DIRNAME):
            raise PraiseError("packet evidence directory cannot be redirected")
        destination = os.path.join(evidence_dir, ref)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=evidence_dir, prefix=".packet-", delete=False) as fh:
                temporary = fh.name
                fh.write(raw)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                if os.path.islink(destination):
                    raise PraiseError("content-addressed packet cannot be a symlink")
                with open(destination, "rb") as fh:
                    if fh.read(8193) != raw:
                        raise PraiseError("content-addressed packet already exists with different content")
        finally:
            if temporary is not None:
                os.unlink(temporary)
        return {"ref": ref, "sha256": sha256, "bytes": len(raw)}
    finally:
        conn.close()


def _validate_report_values(data: dict, *, status_field: str = "status") -> None:
    if data.get(status_field) not in ("confirmed", "rejected", "unresolved"):
        raise PraiseError("worker report status must be confirmed, rejected, or unresolved")
    if "confidence" in data:
        value = data["confidence"]
        if type(value) not in (int, float) or not 0 <= value <= 1:
            raise PraiseError("worker report confidence must be finite and between 0 and 1")
    if "complexity" in data and data["complexity"] not in ("low", "medium", "high"):
        raise PraiseError("worker report complexity is invalid")
    failure = data.get("execution_failure")
    if failure is not None:
        if failure not in ("refusal", "model", "tool") or data[status_field] != "unresolved":
            raise PraiseError("refusal/execution failure must be unresolved, never a rejected finding")
    for field in ("contradictions", "unresolved_questions"):
        if field in data:
            _bounded_strings(data[field], field)


def _model_base(model: str) -> str:
    return model.rsplit(":", 1)[0]


def _model_matches(observed: str, selector: str) -> bool:
    # SDK identities may omit effort; an explicit different effort cannot match.
    return observed == selector or observed == _model_base(selector)


def _current_proofs(directory: str, candidate: dict, repros) -> None:
    _verify_anchors(directory, json.loads(candidate["evidence_json"]), "candidate")
    if len({r["clean_state_id"] for r in repros}) < 2 or len({r["evidence_sha256"] for r in repros}) < 2:
        raise PraiseError("current review/verdict escalation requires two distinct clean-state proofs and artifacts")
    _verify_anchors(directory, [
        {"ref": r["evidence_ref"], "sha256": r["evidence_sha256"]} for r in repros
    ], "reproduction")


def _review_binding(directory: str, conn, candidate: dict) -> tuple[dict, list]:
    if candidate["status"] != "confirmed":
        raise PraiseError("final review requires a confirmed candidate")
    repros = conn.execute("SELECT * FROM reproductions WHERE candidate_id=? ORDER BY id", (candidate["id"],)).fetchall()
    _current_proofs(directory, candidate, repros)
    verdict = conn.execute(
        "SELECT * FROM transitions WHERE candidate_id=? AND action='verdict' ORDER BY id DESC LIMIT 1",
        (candidate["id"],),
    ).fetchone()
    if verdict is None or verdict["decision"] != "confirmed":
        raise PraiseError("final review requires a current confirmed verdict")
    _verify_checker_family(candidate, repros, verdict["model"])
    detail = json.loads(verdict["detail_json"])
    _verify_anchors(directory, detail.get("evidence", []), "verdict")
    binding = {"verdict_id": verdict["id"], "candidate_evidence": json.loads(candidate["evidence_json"]),
               "proofs": [{"id": r["id"], "ref": r["evidence_ref"], "sha256": r["evidence_sha256"],
                           "clean_state_id": r["clean_state_id"], "model": r["model"]} for r in repros]}
    return binding, repros


def _review_state(directory: str, conn, candidate: dict) -> dict:
    latest = conn.execute(
        "SELECT * FROM transitions WHERE candidate_id=? AND action='review' ORDER BY id DESC LIMIT 1",
        (candidate["id"],),
    ).fetchone()
    status = "pending" if candidate["status"] == "confirmed" else "not-applicable"
    ready = False
    if latest is not None:
        status = latest["decision"]
        try:
            binding, repros = _review_binding(directory, conn, candidate)
            detail = json.loads(latest["detail_json"])
            roles = load_roles()
            configured = roles["roles"][roles["stages"]["review"]]["models"]
            if not any(_model_matches(latest["model"], m) for m in configured):
                raise PraiseError("review model no longer matches its configured lane")
            _verify_checker_family(candidate, repros, latest["model"])
            if not detail.get("evidence") or detail.get("binding") != binding:
                raise PraiseError("review does not cover current case")
            _verify_anchors(directory, detail["evidence"], "review")
            ready = status == "approved"
        except (PraiseError, ValueError, OSError, KeyError, TypeError):
            status = "stale"
    return {"review_status": status, "report_ready": ready}

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
    producer_agent = finding.get("producer_agent")

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
            _check_actor(conn, producer_agent, producer_model)
            conn.execute(
                "INSERT INTO candidates (id, status, title, summary, tool, tool_version,"
                " producer_model, producer_family, producer_agent, source_ref, sink_ref, boundary_invariant,"
                " evidence_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    candidate_id,
                    "candidate",
                    title,
                    summary,
                    tool,
                    tool_version,
                    producer_model,
                    producer_family,
                    producer_agent,
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
            message = _workflow_message(
                conn, producer_agent, producer_model, "candidate.created", "@gate", candidate_id,
                {"next": "gate"}, anchors,
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
        "_messages": [message],
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
        candidate.update(_review_state(directory, conn, candidate))
        candidate.pop("evidence_json", None)
        return candidate
    finally:
        conn.close()


def gate_candidate(directory: str, candidate_id: str, decision: str, reason: str, model: str,
                   agent: str | None = None) -> dict:
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
            recipient = {"pass": "@proof", "hold": candidate["producer_agent"] or "@discover", "drop": "@lead"}[decision]
            event = {"pass": "gate.passed", "hold": "gate.held", "drop": "gate.dropped"}[decision]
            message = _workflow_message(
                conn, agent, model, event, recipient, candidate_id, {"status": new_status},
            )
            messages = [message]
            if decision == "drop":
                messages.append(_workflow_message(
                    conn, agent, model, "case.closed", "@learning", candidate_id,
                    {"next": "learn.observe", "status": new_status},
                ))
    finally:
        conn.close()

    return {"candidate_id": candidate_id, "decision": decision, "status": new_status, "model": model, "_messages": messages}


def add_reproduction(
    directory: str,
    candidate_id: str,
    run_id: str,
    clean_state_id: str,
    evidence_ref: str,
    model: str,
    agent: str | None = None,
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
                " evidence_ref, evidence_sha256, model, producer_agent, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (candidate_id, run_id, clean_state_id, evidence_ref, art["sha256"], model, agent, now),
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
            distinct = conn.execute(
                "SELECT COUNT(DISTINCT clean_state_id) FROM reproductions WHERE candidate_id=?", (candidate_id,),
            ).fetchone()[0]
            message = _workflow_message(
                conn, agent, model, "proof.recorded", "@verdict" if distinct >= 2 else agent or "@proof",
                candidate_id, {"distinct_clean_states": distinct}, [{"ref": evidence_ref, "sha256": art["sha256"]}],
            )
    finally:
        conn.close()

    return {
        "candidate_id": candidate_id,
        "run_id": run_id,
        "clean_state_id": clean_state_id,
        "evidence_ref": evidence_ref,
        "evidence_sha256": art["sha256"],
        "status": "reproduced",
        "distinct_clean_states": distinct,
        "_messages": [message],
    }




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
    agent: str | None = None,
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
            owner = next((r["producer_agent"] for r in reversed(repros) if r["producer_agent"]), "@proof")
            messages = [_workflow_message(
                conn, agent, model, "verdict.recorded",
                owner if decision == "needs-more-proof" else "@review" if decision == "confirmed" else "@lead",
                candidate_id, {"status": new_status, "decision": decision}, verdict_anchors,
            )]
            if new_status in ("confirmed", "rejected"):
                messages.append(_workflow_message(
                    conn, agent, model, "case.closed", "@learning", candidate_id, {"next": "learn.observe", "status": new_status},
                ))
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
        "_messages": messages,
    }


def record_review(directory: str, candidate_id: str, decision: str, reason: str, model: str,
                  evidence_refs: list[str] | None = None, agent: str | None = None) -> dict:
    """Record independent final review without changing the immutable verdict."""
    if decision not in REVIEW_DECISIONS:
        raise PraiseError("invalid final review decision")
    _bounded_text(reason, "review reason", 2048)
    model = _identifier(model, "observed review model")
    refs = list(evidence_refs or [])
    if not refs or len(refs) > 8:
        raise PraiseError("final review requires its own nonempty artifact evidence (at most 8)")
    anchors = _anchor_evidence(directory, refs)
    catalog = load_roles()
    review_agent = catalog["stages"]["review"]
    configured = catalog["roles"][review_agent]["models"]
    if not any(_model_matches(model, m) for m in configured):
        raise PraiseError("final review model is not the configured reviewer")
    conn = connect(directory)
    try:
        with _tx(conn):
            candidate = _fetch_candidate(conn, candidate_id)
            binding, repros = _review_binding(directory, conn, candidate)
            family = _verify_checker_family(candidate, repros, model)
            participant = _check_actor(conn, agent, model)
            if participant is not None and (
                participant["role"] != "review" or participant["candidate_id"] != candidate_id
            ):
                raise PraiseError("final review actor must be registered for this candidate's review")
            used = {a["ref"] for a in binding["candidate_evidence"]}
            used.update(p["ref"] for p in binding["proofs"])
            verdict = conn.execute("SELECT detail_json FROM transitions WHERE id=?", (binding["verdict_id"],)).fetchone()
            used.update(a["ref"] for a in json.loads(verdict["detail_json"]).get("evidence", []))
            used_hashes = {a["sha256"] for a in binding["candidate_evidence"]}
            used_hashes.update(p["sha256"] for p in binding["proofs"])
            used_hashes.update(a["sha256"] for a in json.loads(verdict["detail_json"]).get("evidence", []))
            if any(a["ref"] in used or a["sha256"] in used_hashes for a in anchors):
                raise PraiseError("final review must provide its own evidence, not reuse source/proof/verdict artifacts")
            conn.execute(
                "INSERT INTO transitions (candidate_id,action,decision,reason,model,detail_json,created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (candidate_id, "review", decision, reason, model,
                 _json({"evidence": anchors, "binding": binding, "checker_family": family}), _now()),
            )
            state = _review_state(directory, conn, candidate)
            message = _workflow_message(conn, agent, model, "review.recorded",
                                        "@patch" if decision == "approved" else "@lead",
                                        candidate_id, {"decision": decision, **state}, anchors)
    finally:
        conn.close()
    return {"candidate_id": candidate_id, "decision": decision, "reviewer_model": model,
            "reviewer_family": family, **state, "_messages": [message]}


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


def _prior_attempt(directory: str, conn, attempt: int, stage: str, candidate_id: str | None,
                   worker: str, tier: str, models: list[str], packet: dict | None = None) -> dict:
    if type(attempt) is not int or attempt < 1:
        raise PraiseError("escalation requires a positive durable close-message attempt")
    row = conn.execute("SELECT * FROM messages WHERE seq=?", (attempt,)).fetchone()
    if row is None or row["kind"] != "close" or row["candidate_id"] != candidate_id:
        raise PraiseError("attempt must be a same-candidate durable close report")
    participant = _participant(conn, row["sender"])
    data = json.loads(row["data_json"])
    if participant["role"] != stage or row["role"] != stage or data.get("worker") != worker:
        raise PraiseError("attempt worker does not match the predecessor stage")
    if participant["candidate_id"] not in (None, candidate_id) or data.get("finding_id") != candidate_id:
        raise PraiseError("attempt finding identity does not match the task")
    if data.get("tier") != tier or not any(_model_matches(row["model"], m) for m in models):
        raise PraiseError("attempt tier/observed model does not match the configured predecessor")
    latest = conn.execute(
        "SELECT seq FROM messages WHERE kind='close' AND role=? AND candidate_id IS ?"
        " ORDER BY seq DESC LIMIT 1", (stage, candidate_id),
    ).fetchone()
    if latest["seq"] != attempt:
        raise PraiseError("attempt was superseded by a newer stage report")
    _validate_report_values(data)
    if data["status"] != "unresolved" or not (
        data.get("unresolved_questions") or data.get("contradictions") or data.get("execution_failure")
    ):
        raise PraiseError("escalation requires a concrete unresolved gap or execution failure")
    if tier == "expert" and not (data.get("unresolved_questions") or data.get("contradictions")):
        raise PraiseError("expert-max requires substantive unresolved questions or contradictions")
    anchors = json.loads(row["evidence_json"])
    if not anchors:
        raise PraiseError("attempt requires current anchored artifact evidence")
    _verify_anchors(directory, anchors, "attempt")
    if packet is not None:
        anchored = {a["ref"]: a["sha256"] for a in anchors}
        if packet["ref"] in anchored and anchored[packet["ref"]] != packet["sha256"]:
            raise PraiseError("original report packet must remain hash-current")
        for ref in packet["data"]["evidence"]:
            if anchored.get(ref) != artifact(directory, ref)["sha256"]:
                raise PraiseError("packet evidence must be anchored in the predecessor report")
    return data


def dispatch(
    directory: str,
    stage: str,
    candidate_id: str | None = None,
    escalated: bool | None = None,
    reason: str | None = None,
    *,
    tier: str | None = None,
    packet: str | None = None,
    attempt: int | None = None,
) -> dict:
    """Resolve explicit routing metadata, using durable evidence for each higher tier."""
    directory = _resolve_directory(directory)
    scope = load_scope(directory)
    if stage not in STAGES:
        raise PraiseError(f"unknown stage {stage!r}; expected one of {STAGES!r}")
    if escalated is not None and type(escalated) is not bool:
        raise PraiseError("escalated must be boolean when supplied")
    tier = tier if tier is not None else "deep" if escalated else "normal"
    if tier not in TIERS or (escalated is False and tier != "normal") or (escalated is True and tier == "normal"):
        raise PraiseError("tier conflicts with explicit escalated metadata")
    roles = load_roles()
    mapping = roles.get("stages" if tier == "normal" else "escalations" if tier == "deep" else "experts", {})
    agent = mapping.get(stage)
    if not agent or (stage == "review" and tier != "normal"):
        raise PraiseError(f"stage {stage!r} has no {tier!r} lane")
    role = roles.get("roles", {}).get(agent)
    if not role or not role.get("models"):
        raise PraiseError(f"role {agent!r} declares no models")
    if tier != "normal":
        _bounded_text(reason, "escalation reason")
    if (tier != "normal" or stage == "review") and packet is None:
        raise PraiseError("escalation/final review requires a minimal evidence packet")
    packet_object = _read_packet(directory, packet, candidate_id) if packet is not None else None
    if tier == "normal" and attempt is not None:
        raise PraiseError("normal routing does not accept an escalation attempt")
    producer_models = []
    review_state = None
    conn = connect(directory)
    try:
        with _tx(conn):
            candidate = _fetch_candidate(conn, candidate_id) if candidate_id is not None else None
            if stage in ("proof", "verdict", "review", "patch") and candidate is None:
                raise PraiseError(f"stage {stage!r} requires --candidate")
            repros = conn.execute("SELECT * FROM reproductions WHERE candidate_id=? ORDER BY id", (candidate_id,)).fetchall()
            if candidate is not None:
                producer_models = _producer_models(candidate, repros)
            if stage == "proof" and candidate["status"] not in ("gated", "reproduced"):
                raise PraiseError("proof dispatch requires a gated or reproduced candidate")
            if stage == "review":
                binding, repros = _review_binding(directory, conn, candidate)
                verdict = conn.execute("SELECT detail_json FROM transitions WHERE id=?", (binding["verdict_id"],)).fetchone()
                anchors = binding["candidate_evidence"] + [
                    {"ref": p["ref"], "sha256": p["sha256"]} for p in binding["proofs"]
                ] + json.loads(verdict["detail_json"]).get("evidence", [])
                anchored = {a["ref"]: a["sha256"] for a in anchors}
                refs = packet_object["data"]["evidence"]
                if any(anchored.get(ref) != artifact(directory, ref)["sha256"] for ref in refs):
                    raise PraiseError("review packet must cite only current candidate/proof/verdict evidence")
                selected_proofs = [r for r in repros if r["evidence_ref"] in refs]
                if len({r["clean_state_id"] for r in selected_proofs}) < 2 or len({
                    r["evidence_sha256"] for r in selected_proofs
                }) < 2:
                    raise PraiseError("review packet must include two distinct current clean-state proof artifacts")
            if stage == "patch" and scope["mode"] != "patch" and candidate["status"] == "confirmed":
                review_state = _review_state(directory, conn, candidate)
                if not review_state["report_ready"]:
                    raise PraiseError("confirmed-case patch dispatch requires approved current final review")
            if tier != "normal":
                if candidate is not None:
                    _verify_anchors(directory, json.loads(candidate["evidence_json"]), "candidate")
                if stage == "verdict":
                    if candidate["status"] != "reproduced":
                        raise PraiseError("deep verdict requires a credible reproduced candidate")
                    _current_proofs(directory, candidate, repros)
                conflict = False
                if stage == "verdict" and tier == "deep" and attempt is None:
                    normal_agent = roles["stages"]["verdict"]
                    normal_models = roles["roles"][normal_agent]["models"]
                    families = {model_family(m) for m in producer_models}
                    if None in families or any(model_family(m) is None for m in normal_models):
                        raise PraiseError("unknown family cannot establish independence conflict")
                    conflict = all(model_family(m) in families for m in normal_models)
                if not conflict:
                    previous_tier = {"deep": "normal", "expert": "deep", "expert-max": "expert"}[tier]
                    previous_map = roles["stages" if previous_tier == "normal" else "escalations" if previous_tier == "deep" else "experts"]
                    previous_agent = previous_map.get(stage)
                    if not previous_agent:
                        raise PraiseError("missing predecessor lane")
                    _prior_attempt(directory, conn, attempt, stage, candidate_id, previous_agent, previous_tier,
                                   roles["roles"][previous_agent]["models"], packet_object)
                elif packet_object:
                    # The exception has no report: every packet artifact must belong to the current case.
                    anchors = json.loads(candidate["evidence_json"]) + [
                        {"ref": r["evidence_ref"], "sha256": r["evidence_sha256"]} for r in repros]
                    anchored = {a["ref"]: a["sha256"] for a in anchors}
                    if any(anchored.get(ref) != artifact(directory, ref)["sha256"]
                           for ref in packet_object["data"]["evidence"]):
                        raise PraiseError("independence-conflict packet must cite current case evidence")
            case_projection = None
            if candidate is not None:
                case_projection = {"id": candidate["id"], "status": candidate["status"],
                                   "producer_models": producer_models, **_review_state(directory, conn, candidate)}
    finally:
        conn.close()
    models = [role.get("max_model")] if tier == "expert-max" else role["models"]
    if not all(isinstance(m, str) and m for m in models):
        raise PraiseError("expert-max role declares no explicit max_model")
    model = _select_independent_model(models, producer_models, agent) if role.get("independent") else models[0]
    result = {"stage": stage, "agent": agent, "model": model, "family": model_family(model),
              "escalated": tier != "normal", "tier": tier}
    if candidate_id is not None:
        result["candidate_id"] = candidate_id
        result["case"] = case_projection
    if stage in ("verdict", "review", "patch"):
        result["producer_models"] = producer_models
        result["producer_families"] = sorted({model_family(m) for m in producer_models if model_family(m)})
    if packet_object is not None:
        result["packet"] = packet_object
    if review_state is not None:
        result.update(review_state)
    return result


def lead_launch(directory: str, recover: int | None = None) -> list[str]:
    """Build the operator's native launcher; never change global model defaults."""
    directory = _resolve_directory(directory)
    load_scope(directory)
    roles = load_roles()
    model = roles.get("lead_model")
    if model_family(model) is None:
        raise PraiseError("catalog must declare a known-family lead model")
    if recover is not None:
        conn = connect(directory)
        try:
            data = _prior_attempt(directory, conn, recover, "lead", None, "lead", "normal", [model])
            if not data.get("execution_failure"):
                raise PraiseError("lead recovery requires durable refusal/model/tool execution failure")
        finally:
            conn.close()
        model = roles.get("lead_recovery_model")
        if not model or model_family(model) != "deepseek":
            raise PraiseError("catalog must declare explicit Flash lead recovery")
    return ["omp", "--cwd", directory, "--model", model]


# ---------------------------------------------------------------------------
# JSON communication and append-only audit projection
# ---------------------------------------------------------------------------


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256 or any(c in value for c in "\r\n|"):
        raise PraiseError(f"{label} must be a non-empty single-line identifier of at most 256 characters")
    return value.strip()


def _participant(conn: sqlite3.Connection, agent: str) -> sqlite3.Row:
    if not isinstance(agent, str) or not re.fullmatch(r"a[0-9a-f]{1,16}", agent):
        raise PraiseError("unknown agent in this engagement")
    row = conn.execute("SELECT * FROM participants WHERE seq=?", (int(agent[1:], 16),)).fetchone()
    if row is None:
        raise PraiseError("unknown agent in this engagement")
    return row


def register_agent(directory: str, session_id: str, name: str, role: str, model: str,
                   candidate_id: str | None = None) -> dict:
    session_id = _identifier(session_id, "session")
    name = _identifier(name, "agent name")
    model = _identifier(model, "observed model")
    if role not in ("lead", "agent", "coordinator"):
        raise PraiseError("unknown communication role")
    conn = connect(directory)
    try:
        with _tx(conn):
            if candidate_id is not None:
                _fetch_candidate(conn, candidate_id)
            row = conn.execute("SELECT * FROM participants WHERE session_id=?", (session_id,)).fetchone()
            if row:
                if (row["name"], row["role"], row["candidate_id"]) != (name, role, candidate_id):
                    raise PraiseError("a registered session cannot change its task identity")
                if row["model"] != model:
                    conn.execute("UPDATE participants SET model=? WHERE seq=?", (model, row["seq"]))
                seq = row["seq"]
            else:
                seq = conn.execute(
                    "INSERT INTO participants (session_id,name,role,model,candidate_id,created_at)"
                    " VALUES (?,?,?,?,?,?)", (session_id, name, role, model, candidate_id, _now()),
                ).lastrowid
        result = {"agent": f"a{seq:x}", "role": role}
        if candidate_id is not None:
            result["candidate_id"] = candidate_id
        return result
    finally:
        conn.close()


def _message_envelope(row) -> dict:
    result = {"seq": row["seq"], "from": row["sender"], "to": row["recipient"],
              "kind": row["kind"], "data": json.loads(row["data_json"])}
    if row["candidate_id"] is not None:
        result["case"] = row["candidate_id"]
    if row["reply_to"] is not None:
        result["reply"] = row["reply_to"]
    anchors = json.loads(row["evidence_json"])
    if anchors:
        result["refs"] = [a["ref"] for a in anchors[:8]]
        if len(anchors) > 8:
            result["more_refs"] = len(anchors) - 8
    return result


def emit_message(conn: sqlite3.Connection, *, role: str, model: str, to: str, kind: str,
                 data: dict, candidate_id: str | None = None, evidence: list[dict] | None = None,
                 sender: str = "runtime", reply_to: int | None = None, key: str | None = None) -> dict:
    """Insert inside the caller's state transaction; never commit or touch files."""
    if not conn.in_transaction:
        raise PraiseError("message emission requires the owning state transaction")
    data_json = _json(data)
    evidence_json = _json(evidence or [])
    fields = (sender, to, kind, candidate_id, reply_to, data_json, evidence_json, role, model)
    if key is not None:
        old = conn.execute("SELECT * FROM messages WHERE sender=? AND dedup_key=?", (sender, key)).fetchone()
        if old:
            old_fields = tuple(old[k] for k in (
                "sender", "recipient", "kind", "candidate_id", "reply_to", "data_json", "evidence_json", "role", "model",
            ))
            if old_fields != fields:
                raise PraiseError("idempotency key already belongs to different message content")
            return _message_envelope(old)
    seq = conn.execute(
        "INSERT INTO messages (sender,recipient,kind,candidate_id,reply_to,data_json,evidence_json,"
        "role,model,created_at,dedup_key) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (*fields, _now(), key),
    ).lastrowid
    return _message_envelope(conn.execute("SELECT * FROM messages WHERE seq=?", (seq,)).fetchone())


def _check_actor(conn: sqlite3.Connection, actor: str | None, model: str):
    if actor is None:
        return None
    participant = _participant(conn, actor)
    if participant["model"] != model:
        raise PraiseError("operation model differs from the registered observed model")
    return participant


def _workflow_message(conn: sqlite3.Connection, actor: str | None, model: str, event: str,
                      to: str, candidate_id: str, data: dict, evidence: list[dict] | None = None) -> dict:
    participant = _check_actor(conn, actor, model)
    _identifier(model, "observed model")
    return emit_message(
        conn, role=participant["role"] if participant else event.split(".")[0], model=model,
        to=to, kind="event", data={"event": event, **data}, candidate_id=candidate_id,
        evidence=evidence, sender=actor or "runtime",
    )


def _can_receive(row, participant) -> bool:
    if row["recipient"] == f"a{participant['seq']:x}":
        return True
    if participant["role"] == "lead" and row["kind"] == "event":
        return True
    topics = {f"@{participant['role']}"}
    if participant["role"] == "lead":
        topics.add("@learning")
    return row["recipient"] in topics and (
        participant["candidate_id"] is None or row["candidate_id"] is None
        or participant["candidate_id"] == row["candidate_id"]
    )


def send_message(directory: str, sender: str, model: str, to: str, kind: str, data: object,
                 candidate_id: str | None = None, reply_to: int | None = None,
                 evidence: list[str] | None = None, key: str | None = None) -> dict:
    model = _identifier(model, "observed model")
    if kind not in ("ask", "reply", "close"):
        raise PraiseError("manual message kind must be ask, reply, or close")
    if not isinstance(data, dict):
        raise PraiseError("message data must be a JSON object")
    try:
        encoded = _json(data)
    except (TypeError, ValueError) as exc:
        raise PraiseError("message data must contain finite JSON values") from exc
    if len(encoded.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise PraiseError(f"message data exceeds {MAX_MESSAGE_BYTES} UTF-8 bytes; reference an artifact")
    refs = list(evidence or [])
    if len(refs) > 8:
        raise PraiseError("message may reference at most 8 artifacts")
    if key is not None:
        key = _identifier(key, "idempotency key")
    if reply_to is not None and (type(reply_to) is not int or reply_to < 1):
        raise PraiseError("reply_to must be a positive message sequence")
    anchors = _anchor_evidence(directory, refs)
    conn = connect(directory)
    try:
        with _tx(conn):
            participant = _participant(conn, sender)
            if participant["model"] != model:
                raise PraiseError("message model differs from the registered observed model")
            if "status" in data:
                if kind != "close":
                    raise PraiseError("normalized worker reports must use close messages")
                _validate_report_values(data)
                if data.get("finding_id") != candidate_id:
                    raise PraiseError("worker report finding_id must match the message candidate")
                if participant["candidate_id"] not in (None, candidate_id):
                    raise PraiseError("worker report must match the registered task candidate")
                if data.get("tier") not in TIERS:
                    raise PraiseError("worker report requires canonical tier")
                if participant["role"] == "lead":
                    if data.get("worker") != "lead" or data["status"] != "unresolved" or not data.get("execution_failure"):
                        raise PraiseError("lead may report execution failure, not analyze or rule on findings")
                else:
                    catalog = load_roles()
                    mapping = catalog.get("stages" if data["tier"] == "normal" else "escalations"
                                          if data["tier"] == "deep" else "experts", {})
                    if data.get("worker") != mapping.get(participant["role"]):
                        raise PraiseError("worker report role does not match its canonical tier")
                if "evidence" in data:
                    _bounded_strings(data["evidence"], "worker evidence", 8)
                    if not set(data["evidence"]) <= set(refs):
                        raise PraiseError("worker report evidence must be supplied as anchored message evidence")
            if to not in MESSAGE_TOPICS:
                _participant(conn, to)
            if candidate_id is not None:
                _fetch_candidate(conn, candidate_id)
            if kind == "reply" and reply_to is None:
                raise PraiseError("reply requires reply_to")
            if reply_to is not None:
                original = conn.execute("SELECT * FROM messages WHERE seq=?", (reply_to,)).fetchone()
                if original is None or not _can_receive(original, participant):
                    raise PraiseError("cannot reply to a message not addressed to this agent")
                if original["sender"] != to or original["candidate_id"] != candidate_id:
                    raise PraiseError("reply must return to the original sender and candidate")
            old = conn.execute("SELECT seq FROM messages WHERE sender=? AND dedup_key=?", (sender, key)).fetchone() if key else None
            message = emit_message(
                conn, role=participant["role"], model=model, to=to, kind=kind, data=data,
                candidate_id=candidate_id, evidence=anchors, sender=sender, reply_to=reply_to, key=key,
            )
            if len(_json(message).encode("utf-8")) > MAX_ENVELOPE_BYTES:
                raise PraiseError(f"message envelope exceeds {MAX_ENVELOPE_BYTES} UTF-8 bytes")
        return {"seq": message["seq"], "duplicate": bool(old), "_messages": [] if old else [message]}
    finally:
        conn.close()


def inbox(directory: str, agent: str, after: int = 0, limit: int = 32) -> dict:
    if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 32:
        raise PraiseError("inbox requires a nonnegative cursor and limit between 1 and 32")
    conn = connect(directory)
    try:
        # The page and high-water mark must share one WAL read snapshot.
        conn.execute("BEGIN")
        participant = _participant(conn, agent)
        topics = [f"@{participant['role']}"]
        if participant["role"] == "lead":
            topics.append("@learning")
        marks = ",".join("?" for _ in topics)
        rows = conn.execute(
            f"SELECT * FROM messages WHERE seq>? AND (recipient=? OR (recipient IN ({marks})"
            " AND (? IS NULL OR candidate_id IS NULL OR candidate_id=?)) OR (? AND kind='event')) ORDER BY seq LIMIT ?",
            (after, agent, *topics, participant["candidate_id"], participant["candidate_id"], participant["role"] == "lead", limit + 1),
        ).fetchall()
        messages = []
        size = 64
        for row in rows[:limit]:
            message = _message_envelope(row)
            encoded_size = len(_json(message).encode("utf-8"))
            if encoded_size > MAX_ENVELOPE_BYTES:
                # Historical v1 prose remains in the archive; never slice JSON.
                message = {"seq": row["seq"], "from": row["sender"], "to": row["recipient"],
                           "kind": row["kind"], "data": {"legacy_event": row["seq"], "archive": _CHAT_FILENAME}}
                encoded_size = len(_json(message).encode("utf-8"))
            if size + encoded_size > MAX_INBOX_BYTES:
                break
            messages.append(message)
            size += encoded_size + 1
        more = len(rows) > len(messages)
        cursor = messages[-1]["seq"] if messages else after
        if not more:
            cursor = max(cursor, conn.execute("SELECT COALESCE(MAX(seq),0) FROM messages").fetchone()[0])
        return {"messages": messages, "cursor": cursor, "more": more}
    finally:
        conn.close()


def peers(directory: str, candidate_id: str | None = None) -> dict:
    conn = connect(directory)
    try:
        where = "WHERE candidate_id IS NULL OR candidate_id=?" if candidate_id else ""
        rows = conn.execute(
            f"SELECT seq,name,role,candidate_id FROM participants {where} ORDER BY seq DESC LIMIT 33",
            (candidate_id,) if candidate_id else (),
        ).fetchall()
        agents = []
        for row in reversed(rows[:32]):
            item = {"id": f"a{row['seq']:x}", "name": row["name"], "role": row["role"]}
            if row["candidate_id"] is not None:
                item["candidate_id"] = row["candidate_id"]
            agents.append(item)
        return {"agents": agents, "more": len(rows) > 32}
    finally:
        conn.close()


def project_messages(directory: str) -> dict:
    """Batch append committed messages; a crash can recover from the audit tail."""
    directory = _resolve_directory(directory)
    conn = connect(directory)
    try:
        with open(os.path.join(directory, _CHAT_FILENAME), "a+b") as fh:
            _lock_file(fh)
            try:
                cursor_row = conn.execute("SELECT value FROM meta WHERE key='projection_cursor'").fetchone()
                cursor = int(cursor_row[0]) if cursor_row else 0
                fh.seek(0, os.SEEK_END)
                fh.seek(max(0, fh.tell() - 65536) if cursor else 0)
                for line in fh:
                    match = re.match(rb"### .* \| seq=(\d+)\r?\n", line)
                    if match:
                        cursor = max(cursor, int(match[1]))
                rows = conn.execute("SELECT * FROM messages WHERE seq>? ORDER BY seq", (cursor,)).fetchall()
                target = _json(os.path.basename(directory))[1:-1]
                for row in rows:
                    message = _message_envelope(row)
                    close = row["kind"] in ("reply", "close") or row["recipient"] in ("@lead", "@learning")
                    block = (
                        f"### {row['created_at'].replace('+00:00', 'Z')} | {row['role']} | {row['model']} | {target} | seq={row['seq']}\n"
                        f"JSON: {_json(message)}\n{'CLOSE' if close else 'ASK'}: {row['recipient']}\n\n"
                    )
                    fh.write(block.encode("utf-8"))
                    cursor = row["seq"]
                if rows:
                    fh.flush()
                    os.fsync(fh.fileno())
                with _tx(conn):
                    conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('projection_cursor',?)", (str(cursor),))
                return {"projected": len(rows), "cursor": cursor}
            finally:
                _unlock_file(fh)
    finally:
        conn.close()


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


def validate_fix(directory: str, candidate_id: str, model: str, gates: object,
                 agent: str | None = None) -> dict:
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
            event_anchors = list({a["ref"]: a for group in anchors.values() for a in group}.values())
            message = _workflow_message(
                conn, agent, model, "patch.validated", "@lead", candidate_id, {"result": result}, event_anchors,
            )
    finally:
        conn.close()

    return {
        "candidate_id": candidate_id,
        "result": result,
        "gates": gate_summary,
        "reviewer_model": model,
        "reviewer_family": checker_family,
        "_messages": [message],
    }


# ---------------------------------------------------------------------------
# Show
# ---------------------------------------------------------------------------


def show(directory: str, candidate_id: str | None = None, *, compact: bool = False) -> dict:
    """State only; communication is consumed through addressed incremental inboxes."""
    directory = _resolve_directory(directory)
    if not compact:
        scope = load_scope(directory)
        if candidate_id is not None:
            candidate = get_candidate(directory, candidate_id)
            if candidate is None:
                raise PraiseError(f"candidate not found: {candidate_id}")
            return {"directory": directory, "scope": scope, "candidate": candidate}
    conn = connect(directory)
    try:
        if compact and candidate_id is not None:
            row = conn.execute(
                "SELECT id,status,source_ref,sink_ref,boundary_invariant,evidence_json,producer_model"
                " FROM candidates WHERE id=?", (candidate_id,),
            ).fetchone()
            if row is None:
                raise PraiseError(f"candidate not found: {candidate_id}")
            models = [row["producer_model"]]
            for item in conn.execute("SELECT DISTINCT model FROM reproductions WHERE candidate_id=?", (candidate_id,)):
                if item["model"] not in models:
                    models.append(item["model"])
            candidate = {"id": row["id"], "status": row["status"], "producer_models": models}
            candidate.update(_review_state(directory, conn, dict(row)))
            for field in ("source_ref", "sink_ref", "boundary_invariant"):
                if row[field] is not None:
                    if len(str(row[field]).encode("utf-8")) <= 512:
                        candidate[field] = row[field]
                    else:
                        candidate["detail_available"] = True
            anchors = json.loads(row["evidence_json"])
            candidate["refs"] = [a["ref"] for a in anchors[:8]]
            if len(anchors) > 8:
                candidate["more_refs"] = len(anchors) - 8
            candidate["history_count"] = conn.execute(
                "SELECT COUNT(*) FROM transitions WHERE candidate_id=?", (candidate_id,),
            ).fetchone()[0]
            for field in ("refs", "boundary_invariant", "sink_ref", "source_ref", "producer_models", "id"):
                if len(_json(candidate).encode("utf-8")) <= 4000:
                    break
                candidate.pop(field, None)
                candidate["detail_available"] = True
            return {"candidate": candidate}
        counts = {r["status"]: r["n"] for r in conn.execute("SELECT status,COUNT(*) AS n FROM candidates GROUP BY status")}
        if compact:
            rows = conn.execute("SELECT id,status FROM candidates ORDER BY created_at DESC,id DESC LIMIT 17").fetchall()
            candidates = []
            size = len(_json(counts).encode("utf-8")) + 64
            for row in rows[:16]:
                item = dict(row)
                item.update(_review_state(directory, conn, _fetch_candidate(conn, item["id"])))
                item_size = len(_json(item).encode("utf-8"))
                if size + item_size > 4000:
                    break
                candidates.append(item)
                size += item_size + 1
            return {"counts": counts, "candidates": candidates, "more": sum(counts.values()) > len(candidates)}
        candidates = [dict(r) for r in conn.execute(
            "SELECT id,status,title,producer_model,producer_family,created_at,updated_at"
            " FROM candidates ORDER BY created_at,id",
        )]
        for candidate in candidates:
            candidate.update(_review_state(directory, conn, _fetch_candidate(conn, candidate["id"])))
        return {"directory": directory, "scope": scope, "candidates": candidates, "counts": counts}
    finally:
        conn.close()
