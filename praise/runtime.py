"""Engagement-local participants, durable JSON messages and audit projection.

SQLite owns coordination state. The Markdown audit is recoverable output, never
an inbox. Legacy tables remain archival; this module performs no target requests.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone

from . import policy
from .config import ROLE_NAMES
from .errors import PraiseError

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

__all__ = ["init_engagement", "load_scope", "connect", "artifact", "register_agent",
           "send_message", "inbox", "peers", "project_messages", "show"]
MAX_MESSAGE_BYTES = 2048
MAX_ENVELOPE_BYTES = 4096
MAX_INBOX_BYTES = 8192
MESSAGE_TOPICS = frozenset(f"@{role}" for role in ROLE_NAMES)
_LEGACY_ROLES = dict(zip(
    ("plan", "recon", "discover", "gate", "proof", "verdict", "review", "patch"),
    ("planner", "scout", "finder", "verifier", "exploiter", "skeptic", "reviewer", "tester"),
))
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """CREATE TABLE IF NOT EXISTS participants (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL, role TEXT NOT NULL, model TEXT NOT NULL,
        created_at TEXT NOT NULL, agent_id TEXT UNIQUE, parent TEXT,
        model_source TEXT NOT NULL DEFAULT 'asserted')""",
    """CREATE TABLE IF NOT EXISTS messages (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL,
        recipient TEXT NOT NULL, kind TEXT NOT NULL, reply_to INTEGER,
        data_json TEXT NOT NULL, evidence_json TEXT NOT NULL, role TEXT NOT NULL,
        model TEXT NOT NULL, created_at TEXT NOT NULL, dedup_key TEXT,
        archived INTEGER NOT NULL DEFAULT 0, UNIQUE(sender,dedup_key))""",
    "CREATE INDEX IF NOT EXISTS messages_recipient_seq ON messages (recipient,seq)",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def _directory(directory) -> str:
    try:
        value = os.fspath(directory)
    except TypeError as exc:
        raise PraiseError("engagement directory must be a non-empty path") from exc
    if not isinstance(value, str) or not value.strip():
        raise PraiseError("engagement directory must be a non-empty path")
    return os.path.abspath(value)


def _identifier(value: object, label: str, maximum: int = 256) -> str:
    if (not isinstance(value, str) or not value.strip()
            or len(value.encode("utf-8")) > maximum or any(c in value for c in "\r\n|")):
        raise PraiseError(f"{label} must be nonempty single-line text of at most {maximum} UTF-8 bytes")
    return value.strip()


@contextlib.contextmanager
def _tx(conn: sqlite3.Connection):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def _init_schema(conn: sqlite3.Connection) -> None:
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
    version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone() if exists else None
    if version and version[0] == "3":
        return
    with _tx(conn):
        conn.execute(_SCHEMA[0])
        version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if version and version[0] == "3":
            return
        if version and version[0] not in ("1", "2"):
            raise PraiseError(f"unsupported engagement schema version: {version[0]}")
        for statement in _SCHEMA[1:]:
            conn.execute(statement)
        additions = {
            "participants": {"agent_id": "TEXT", "parent": "TEXT",
                             "model_source": "TEXT NOT NULL DEFAULT 'asserted'"},
            "messages": {"archived": "INTEGER NOT NULL DEFAULT 0"},
        }
        for table, fields in additions.items():
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            for name, definition in fields.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        # Keep legacy IDs and all direct-message and reply links unchanged.
        for row in conn.execute("SELECT seq FROM participants WHERE agent_id IS NULL").fetchall():
            conn.execute("UPDATE participants SET agent_id=? WHERE seq=?", (f"a{row[0]:x}", row[0]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS participants_agent_id ON participants(agent_id)")
        events = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone()
        if version and version[0] == "1" and events:
            # Original v1 rows stay intact. Their projection is historical, not work.
            for row in conn.execute("SELECT * FROM events ORDER BY seq").fetchall():
                kind = "ask" if row["ask"] is not None else "close"
                data = {"summary": row["summary"], kind: row["ask"] if kind == "ask" else row["close"]}
                conn.execute(
                    "INSERT OR IGNORE INTO messages (seq,sender,recipient,kind,data_json,evidence_json,"
                    "role,model,created_at,archived) VALUES (?,?,?,?,?,?,?,?,?,1)",
                    (row["seq"], row["role"], "@archive", kind, _json(data), row["evidence_json"],
                     row["role"], row["model"], row["created_at"]),
                )
        for old, new in _LEGACY_ROLES.items():
            conn.execute("UPDATE participants SET role=? WHERE role=?", (new, old))
            conn.execute("UPDATE messages SET role=? WHERE role=?", (new, old))
            conn.execute("UPDATE messages SET recipient=? WHERE recipient=?", (f"@{new}", f"@{old}"))
        # Old runtime events and learning messages cannot trigger new delegation.
        conn.execute("UPDATE messages SET archived=1 WHERE kind='event' OR recipient IN ('@learning','@archive')")
        conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('schema_version','3')")


def connect(directory) -> sqlite3.Connection:
    directory = _directory(directory)
    load_scope(directory)
    conn = sqlite3.connect(os.path.join(directory, "state.sqlite3"), isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _init_schema(conn)
    except BaseException:
        conn.close()
        raise
    return conn


def load_scope(directory) -> dict:
    path = os.path.join(_directory(directory), "scope.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return policy.validate_scope(json.load(fh))
    except (OSError, ValueError) as exc:
        raise PraiseError(f"cannot load engagement scope: {exc}") from exc


def init_engagement(directory, *, program, basis, assets, mode="source", methods=None,
                    max_requests=0, interval_seconds=1.0) -> dict:
    directory = _directory(directory)
    scope = {"program": program, "authorization_basis": basis, "assets": assets,
             "mode": mode, "allowed_methods": ["GET"] if methods is None else methods,
             "max_requests": max_requests, "interval_seconds": interval_seconds, "created_at": _now()}
    try:
        scope = policy.validate_scope(scope)
        for asset in assets:
            policy.validate_asset(asset, mode, require_existing=True)
    except ValueError as exc:
        raise PraiseError(f"invalid scope: {exc}") from exc
    os.makedirs(directory, exist_ok=True)
    chat = os.path.join(directory, "agentschat.md")
    if os.path.exists(chat) and os.path.getsize(chat):
        raise PraiseError("refusing to overwrite existing agentschat.md")
    path = os.path.join(directory, "scope.json")
    # Publish a complete attestation atomically without replacing an existing one.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as fh:
            temporary = fh.name
            json.dump(scope, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.link(temporary, path)
    except FileExistsError as exc:
        raise PraiseError("engagement already initialized") from exc
    finally:
        if temporary is not None:
            os.unlink(temporary)
    os.makedirs(os.path.join(directory, "evidence"), exist_ok=True)
    connect(directory).close()
    with open(chat, "a", encoding="utf-8"):
        pass
    return scope


def artifact(directory, ref: str) -> dict:
    """Resolve only regular evidence files within this engagement, with SHA-256."""
    _identifier(ref, "evidence reference", 512)
    directory = os.path.realpath(_directory(directory))
    root = os.path.realpath(os.path.join(directory, "evidence"))
    if os.path.commonpath((directory, root)) != directory:
        raise PraiseError("evidence directory escapes the engagement")
    path = os.path.realpath(os.path.join(root, ref))
    if os.path.commonpath((root, path)) != root:
        raise PraiseError("evidence reference escapes the evidence directory")
    if not os.path.isfile(path):
        raise PraiseError(f"evidence artifact not found: {ref!r}")
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return {"path": path, "sha256": digest.hexdigest()}


def _participant(conn, agent):
    if not isinstance(agent, str) or not re.fullmatch(r"a[0-9a-f]{1,16}", agent):
        raise PraiseError("unknown agent in this engagement")
    row = conn.execute("SELECT * FROM participants WHERE agent_id=?", (agent,)).fetchone()
    if row is None or row["role"] not in ROLE_NAMES:
        raise PraiseError("unknown agent in this engagement")
    return row


def _participant_info(row, *, roster=False) -> dict:
    item = {"id" if roster else "agent": row["agent_id"], "role": row["role"],
            "model": row["model"], "model_source": row["model_source"]}
    if roster:
        item["name"] = row["name"]
    if row["parent"] is not None:
        item["parent"] = row["parent"]
    return item


def register_agent(directory, session_id, name, role, model, *, parent=None, observed=False) -> dict:
    session_id = _identifier(session_id, "session")
    name = _identifier(name, "agent name")
    model = _identifier(model, "model")
    if role not in ROLE_NAMES or type(observed) is not bool:
        raise PraiseError("registration requires a canonical role and boolean observed flag")
    source = "host" if observed else "asserted"
    conn = connect(directory)
    try:
        with _tx(conn):
            if parent is not None:
                _participant(conn, parent)
            row = conn.execute("SELECT * FROM participants WHERE session_id=?", (session_id,)).fetchone()
            messages = []
            if row:
                if (row["name"], row["role"], row["model"], row["parent"], row["model_source"]) != (
                        name, role, model, parent, source):
                    raise PraiseError("a registered session cannot change its identity or provenance")
            else:
                agent = "a" + uuid.uuid4().hex[:16]
                conn.execute("INSERT INTO participants (session_id,name,role,model,created_at,agent_id,parent,model_source)"
                             " VALUES (?,?,?,?,?,?,?,?)", (session_id, name, role, model, _now(), agent, parent, source))
                row = _participant(conn, agent)
                if parent is not None:
                    messages.append(_emit_message(
                        conn, sender=agent, role=role, model=model, to=parent, kind="event",
                        data={"event": "agent.started", **_participant_info(row)},
                    ))
            return {**_participant_info(row), "_messages": messages}
    finally:
        conn.close()


def _message_envelope(row) -> dict:
    result = {"seq": row["seq"], "from": row["sender"], "to": row["recipient"],
              "kind": row["kind"], "data": json.loads(row["data_json"])}
    if row["reply_to"] is not None:
        result["reply"] = row["reply_to"]
    anchors = json.loads(row["evidence_json"])
    if anchors:
        result["refs"] = [a["ref"] for a in anchors[:8]]
        if len(anchors) > 8:
            result["more_refs"] = len(anchors) - 8
    return result


def _emit_message(conn, *, sender, role, model, to, kind, data, evidence=None, reply_to=None, key=None) -> dict:
    """Insert under the owner's transaction; no filesystem writes or nested commit."""
    if not conn.in_transaction:
        raise PraiseError("message emission requires a transaction")
    fields = (sender, to, kind, reply_to, _json(data), _json(evidence or []), role, model)
    if key is not None:
        old = conn.execute("SELECT * FROM messages WHERE sender=? AND dedup_key=?", (sender, key)).fetchone()
        if old:
            if tuple(old[k] for k in ("sender", "recipient", "kind", "reply_to", "data_json",
                                       "evidence_json", "role", "model")) != fields:
                raise PraiseError("idempotency key already belongs to different message content")
            return _message_envelope(old)
    seq = conn.execute(
        "INSERT INTO messages (sender,recipient,kind,reply_to,data_json,evidence_json,role,model,created_at,dedup_key)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)", (*fields, _now(), key),
    ).lastrowid
    message = _message_envelope(conn.execute("SELECT * FROM messages WHERE seq=?", (seq,)).fetchone())
    if len(_json(message).encode("utf-8")) > MAX_ENVELOPE_BYTES:
        raise PraiseError(f"message envelope exceeds {MAX_ENVELOPE_BYTES} UTF-8 bytes")
    return message


def _can_receive(row, participant) -> bool:
    return not row["archived"] and row["recipient"] in (participant["agent_id"], f"@{participant['role']}")


def send_message(directory, sender, model, to, kind, data, *, reply_to=None, evidence=None, key=None) -> dict:
    model = _identifier(model, "model")
    if kind not in ("ask", "reply", "close") or not isinstance(data, dict):
        raise PraiseError("message requires ask, reply or close kind and JSON object data")
    try:
        encoded = _json(data)
    except (TypeError, ValueError, RecursionError) as exc:
        raise PraiseError("message data must contain finite JSON values") from exc
    if len(encoded.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise PraiseError(f"message data exceeds {MAX_MESSAGE_BYTES} UTF-8 bytes; reference an artifact")
    if evidence is not None and (not isinstance(evidence, list) or len(evidence) > 8):
        raise PraiseError("message evidence must be an array of at most 8 references")
    anchors = [{"ref": ref, "sha256": artifact(directory, ref)["sha256"]} for ref in evidence or []]
    if key is not None:
        key = _identifier(key, "idempotency key")
    if reply_to is not None and (type(reply_to) is not int or not 1 <= reply_to <= 2**63 - 1):
        raise PraiseError("reply_to must be a positive SQLite message sequence")
    if kind == "reply" and reply_to is None:
        raise PraiseError("reply requires reply_to")
    conn = connect(directory)
    try:
        with _tx(conn):
            participant = _participant(conn, sender)
            if participant["model"] != model:
                raise PraiseError("message model differs from registered model")
            if not isinstance(to, str) or to not in MESSAGE_TOPICS:
                _participant(conn, to)
            if reply_to is not None:
                original = conn.execute("SELECT * FROM messages WHERE seq=?", (reply_to,)).fetchone()
                if original is None or not _can_receive(original, participant):
                    raise PraiseError("cannot reply to a message not addressed to this agent")
                if original["sender"] != to:
                    raise PraiseError("reply must return to the original sender")
            old = conn.execute("SELECT seq FROM messages WHERE sender=? AND dedup_key=?", (sender, key)).fetchone() if key else None
            message = _emit_message(conn, sender=sender, role=participant["role"], model=model,
                                    to=to, kind=kind, data=data, evidence=anchors, reply_to=reply_to, key=key)
            return {"seq": message["seq"], "duplicate": bool(old), "_messages": [] if old else [message]}
    finally:
        conn.close()


def inbox(directory, agent, after=0, limit=32) -> dict:
    if (type(after) is not int or not 0 <= after <= 2**63 - 1
            or type(limit) is not int or not 1 <= limit <= 32):
        raise PraiseError("inbox requires a nonnegative SQLite cursor and limit between 1 and 32")
    conn = connect(directory)
    try:
        # Page and high-water mark must share one WAL read snapshot.
        conn.execute("BEGIN")
        participant = _participant(conn, agent)
        rows = conn.execute(
            "SELECT * FROM messages WHERE seq>? AND archived=0 AND recipient IN (?,?) ORDER BY seq LIMIT ?",
            (after, agent, f"@{participant['role']}", limit + 1),
        ).fetchall()
        messages, size = [], 128
        for row in rows[:limit]:
            message = _message_envelope(row)
            encoded_size = len(_json(message).encode("utf-8"))
            if encoded_size > MAX_ENVELOPE_BYTES:
                message = {"seq": row["seq"], "from": row["sender"], "to": row["recipient"],
                           "kind": row["kind"], "data": {"legacy_message": row["seq"], "archive": "agentschat.md"}}
                encoded_size = len(_json(message).encode("utf-8"))
            if size + encoded_size + 1 > MAX_INBOX_BYTES:
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


def peers(directory) -> dict:
    conn = connect(directory)
    try:
        marks = ",".join("?" for _ in ROLE_NAMES)
        rows = conn.execute(f"SELECT * FROM participants WHERE role IN ({marks}) ORDER BY seq DESC LIMIT 33", ROLE_NAMES).fetchall()
        return {"agents": [_participant_info(row, roster=True) for row in reversed(rows[:32])], "more": len(rows) > 32}
    finally:
        conn.close()


def project_messages(directory) -> dict:
    """Append committed messages, recovering a lost cursor from complete audit blocks."""
    directory = _directory(directory)
    conn = connect(directory)
    try:
        with open(os.path.join(directory, "agentschat.md"), "a+b") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                # Recover only the suffix since the last fsynced checkpoint.
                checkpoint = dict(conn.execute(
                    "SELECT key,value FROM meta WHERE key IN ('projection_cursor','projection_offset')"
                ).fetchall())
                cursor = int(checkpoint.get("projection_cursor", "0"))
                offset = int(checkpoint.get("projection_offset", "0"))
                if "projection_cursor" not in checkpoint or offset > os.fstat(fh.fileno()).st_size:
                    cursor, offset = 0, 0
                fh.seek(offset)
                pending = None
                for line in fh:
                    match = re.match(rb"### .* \| seq=(\d+)\r?\n$", line)
                    if match:
                        pending = int(match[1])
                    elif pending is not None and line.startswith((b"ASK: ", b"CLOSE: ")) and line.endswith(b"\n"):
                        cursor = max(cursor, pending)
                        pending = None
                count = 0
                high_water = conn.execute("SELECT COALESCE(MAX(seq),0) FROM messages").fetchone()[0]
                target = _json(os.path.basename(directory))[1:-1]
                while True:
                    rows = conn.execute("SELECT * FROM messages WHERE seq>? AND seq<=? ORDER BY seq LIMIT 128",
                                        (cursor, high_water)).fetchall()
                    if not rows:
                        break
                    for row in rows:
                        close = row["kind"] in ("reply", "close")
                        block = (
                            f"\n### {row['created_at'].replace('+00:00', 'Z')} | {row['role']} | {row['model']} | {target} | seq={row['seq']}\n"
                            f"JSON: {_json(_message_envelope(row))}\n{'CLOSE' if close else 'ASK'}: {row['recipient']}\n\n"
                        )
                        fh.write(block.encode("utf-8"))
                        cursor = row["seq"]
                        count += 1
                if count:
                    fh.flush()
                    os.fsync(fh.fileno())
                with _tx(conn):
                    conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('projection_cursor',?)", (str(cursor),))
                    conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('projection_offset',?)", (str(fh.tell()),))
                return {"projected": count, "cursor": cursor}
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        conn.close()


def show(directory) -> dict:
    roster = peers(directory)
    return {"scope": load_scope(directory), "participants": roster["agents"], "more": roster["more"]}
