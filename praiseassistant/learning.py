"""Evidence-backed workflow learning for PraiseAssistant.

``learning`` records immutable proposals observed from closed candidate cases,
evaluates them against paired baseline/learned cases, requires an explicit
independent promotion before a lesson is approved, and supports rollback while
preserving full history.

Lesson content is untrusted data. It is stored, hashed, and returned as bounded
data records; it is never executed and never used to rewrite safety policy,
credentials, scopes, model weights, or role definitions.

Durable state lives in the engagement SQLite database inside learning-owned
tables. The candidate schema is owned by ``praiseassistant.runtime`` and is
never modified here.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone

from praiseassistant.runtime import artifact, connect, get_candidate, model_family

#: Hard cap on how many lesson records ``learn list`` may return, keeping the
#: retrieval bounded regardless of accumulated history size.
MAX_LIST_ROWS = 1000

#: Hard cap on proposal summary length, so every stored and retrieved record
#: stays bounded. Over-long proposals are rejected fail-closed rather than
#: silently truncated (lesson content is the actual learned payload).
MAX_SUMMARY_CHARS = 4000

#: Only these candidate statuses are closed cases eligible for observation.
_CLOSED_STATUSES = ("confirmed", "rejected")

#: Lesson lifecycle states. ``active`` separately records deactivation.
_STATUS_PROPOSED = "proposed"
_STATUS_EVALUATED = "evaluated"
_STATUS_APPROVED = "approved"
_STATUS_ROLLED_BACK = "rolled_back"


class LearningError(Exception):
    """A fail-closed learning error surfaced to the CLI as a JSON error."""


def configure_parser(subparsers):
    """Attach the ``learn`` command tree to ``subparsers``.

    ``subparsers`` is the top-level ``argparse`` subparsers action owned by
    ``praiseassistant.cli``. The global ``--engagement`` option is owned by
    ``cli`` and is not re-declared here.
    """
    learn = subparsers.add_parser(
        "learn", help="Evidence-backed workflow learning (observe/evaluate/promote/rollback/list)"
    )
    learn_sub = learn.add_subparsers(dest="learn_command", metavar="COMMAND", required=True)

    observe = learn_sub.add_parser(
        "observe", help="Record an immutable proposal from a closed case"
    )
    observe.add_argument("--candidate", required=True, help="Closed candidate id (confirmed or rejected)")
    observe.add_argument("--summary", required=True, help="Proposal text (untrusted data)")
    observe.add_argument("--model", required=True, help="Observed producer model identifier")
    observe.add_argument("--evidence", required=True, help="Evidence reference")

    evaluate = learn_sub.add_parser(
        "evaluate", help="Evaluate a proposal against paired cases"
    )
    evaluate.add_argument("--lesson", required=True, help="Lesson id")
    evaluate.add_argument("--input", required=True, help="JSON file with a 'cases' array")

    promote = learn_sub.add_parser(
        "promote", help="Explicit independent approval of a lesson"
    )
    promote.add_argument("--lesson", required=True, help="Lesson id")
    promote.add_argument("--reviewer-model", required=True, help="Observed reviewer model identifier")
    promote.add_argument("--reason", required=True, help="Approval reason")

    rollback = learn_sub.add_parser(
        "rollback", help="Deactivate a lesson while preserving history"
    )
    rollback.add_argument("--lesson", required=True, help="Lesson id")
    rollback.add_argument("--reason", required=True, help="Rollback reason")

    list_parser = learn_sub.add_parser("list", help="List lessons as bounded data records")
    list_parser.add_argument("--approved", action="store_true", help="Only approved, active lessons")


_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS lessons (
        id TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL,
        summary TEXT NOT NULL,
        producer_model TEXT NOT NULL,
        producer_family TEXT,
        evidence_ref TEXT NOT NULL,
        evidence_path TEXT NOT NULL,
        evidence_sha256 TEXT NOT NULL,
        status TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        approved_at TEXT,
        reviewer_model TEXT,
        reviewer_family TEXT,
        promotion_reason TEXT,
        rollback_at TEXT,
        rollback_reason TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS lesson_evaluations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        lesson_id TEXT NOT NULL,
        cases_json TEXT NOT NULL,
        evidence_sha256_json TEXT NOT NULL,
        input_sha256 TEXT NOT NULL,
        baseline_correct INTEGER NOT NULL,
        baseline_total INTEGER NOT NULL,
        learned_correct INTEGER NOT NULL,
        learned_total INTEGER NOT NULL,
        passed INTEGER NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_lesson_evaluations_lesson ON lesson_evaluations(lesson_id)",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _engagement_dir(args) -> str:
    """Resolve the engagement directory from args, env, or cwd (in that order)."""
    explicit = getattr(args, "engagement", None)
    if explicit:
        return os.path.abspath(explicit)
    env = os.environ.get("PRAISEASSISTANT_ENGAGEMENT")
    if env:
        return os.path.abspath(env)
    return os.path.abspath(os.getcwd())


def _init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _connect(directory: str) -> sqlite3.Connection:
    """Open a connection to the engagement DB and initialize learning tables."""
    conn = connect(directory)
    if not isinstance(conn, sqlite3.Connection):
        raise LearningError("runtime.connect did not return a sqlite3 connection")
    conn.isolation_level = None  # explicit transaction control below
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


@contextlib.contextmanager
def _transaction(conn: sqlite3.Connection):
    """Serialize a write transaction. Callers must not nest transactions."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def _row_to_dict(row) -> dict | None:
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def _resolve_family(model: str, role: str):
    """Resolve a model family, failing closed if resolution itself errors."""
    try:
        return model_family(model)
    except Exception as exc:  # noqa: BLE001 - convert to a controlled CLI error
        raise LearningError(
            f"cannot resolve model family for {role} model {model!r}: {exc}"
        ) from exc


def _get_candidate(directory: str, candidate_id: str):
    """Fetch a candidate, failing closed whether runtime returns None or raises."""
    try:
        return get_candidate(directory, candidate_id)
    except Exception as exc:  # noqa: BLE001 - missing candidate id surfaces cleanly
        raise LearningError(f"candidate not found: {candidate_id}") from exc


def _resolve_artifact(directory: str, ref: str) -> dict:
    """Resolve an evidence reference through runtime.artifact, failing closed."""
    try:
        result = artifact(directory, ref)
    except Exception as exc:  # noqa: BLE001 - missing/traversal/symlink escape
        raise LearningError(f"evidence {ref!r} not available: {exc}") from exc
    if not isinstance(result, dict) or "path" not in result or "sha256" not in result:
        raise LearningError(f"artifact() returned a malformed result for {ref!r}")
    return result


def _load_lesson(conn: sqlite3.Connection, lesson_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM lessons WHERE id = ?", (lesson_id,)).fetchone()
    return _row_to_dict(row)


def _latest_evaluation(conn: sqlite3.Connection, lesson_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM lesson_evaluations WHERE lesson_id = ? ORDER BY id DESC LIMIT 1",
        (lesson_id,),
    ).fetchone()
    evaluation = _row_to_dict(row)
    if evaluation is not None:
        evaluation["passed"] = bool(evaluation["passed"])
    return evaluation


def _run_observe(directory: str, args) -> dict:
    candidate = _get_candidate(directory, args.candidate)
    if not candidate:
        raise LearningError(f"candidate not found: {args.candidate}")
    status = candidate.get("status")
    if status not in _CLOSED_STATUSES:
        raise LearningError(
            f"candidate {args.candidate} is not a closed case "
            f"(status={status!r}); observe requires confirmed or rejected"
        )
    if len(args.summary) > MAX_SUMMARY_CHARS:
        raise LearningError(
            f"summary exceeds {MAX_SUMMARY_CHARS} characters; shorten before observing"
        )

    art = _resolve_artifact(directory, args.evidence)
    producer_family = _resolve_family(args.model, "producer")
    lesson_id = "L" + uuid.uuid4().hex
    created_at = _now()

    conn = _connect(directory)
    try:
        with _transaction(conn):
            conn.execute(
                "INSERT INTO lessons (id, candidate_id, summary, producer_model,"
                " producer_family, evidence_ref, evidence_path, evidence_sha256,"
                " status, active, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    lesson_id,
                    args.candidate,
                    args.summary,
                    args.model,
                    producer_family,
                    args.evidence,
                    art["path"],
                    art["sha256"],
                    _STATUS_PROPOSED,
                    1,
                    created_at,
                ),
            )
    finally:
        conn.close()

    return {
        "lesson_id": lesson_id,
        "candidate_id": args.candidate,
        "status": _STATUS_PROPOSED,
        "producer_model": args.model,
        "producer_family": producer_family,
        "evidence_sha256": art["sha256"],
        "created_at": created_at,
    }


def _read_input(path: str) -> tuple[list, str]:
    """Read and validate the paired-case input file; return (cases, input_sha256)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise LearningError(f"cannot read input {path!r}: {exc}") from exc

    input_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LearningError(f"input {path!r} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or "cases" not in data:
        raise LearningError("input must be a JSON object with a 'cases' array")
    cases = data["cases"]
    if not isinstance(cases, list) or not cases:
        raise LearningError("'cases' must be a non-empty array")

    seen_ids: set[str] = set()
    positive = 0
    negative = 0
    parsed: list[dict] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise LearningError(f"case {index} is not an object")
        for key in ("id", "expected", "baseline", "learned", "evidence"):
            if key not in case:
                raise LearningError(f"case {index} is missing field {key!r}")

        case_id = case["id"]
        if not isinstance(case_id, str) or not case_id:
            raise LearningError(f"case {index} has an invalid id")
        if case_id in seen_ids:
            raise LearningError(f"duplicate case id {case_id!r}")
        seen_ids.add(case_id)

        for key in ("expected", "baseline", "learned"):
            if not isinstance(case[key], bool):
                raise LearningError(f"case {case_id!r} field {key!r} must be a boolean")

        evidence = case["evidence"]
        if not isinstance(evidence, str) or not evidence:
            raise LearningError(f"case {case_id!r} has an invalid evidence reference")

        if case["expected"]:
            positive += 1
        else:
            negative += 1

        parsed.append(
            {
                "id": case_id,
                "expected": case["expected"],
                "baseline": case["baseline"],
                "learned": case["learned"],
                "evidence": evidence,
            }
        )

    if positive == 0 or negative == 0:
        raise LearningError(
            "paired cases require both positive and negative controls (at least one"
            " expected true and one expected false)"
        )

    return parsed, input_sha256


def _run_evaluate(directory: str, args) -> dict:
    cases, input_sha256 = _read_input(args.input)

    # Evidence hashing is file I/O and independent of DB lifecycle state, so it
    # stays outside the transaction.
    evidence_sha256: dict[str, str] = {}
    for case in cases:
        art = _resolve_artifact(directory, case["evidence"])
        evidence_sha256[case["evidence"]] = art["sha256"]

    total = len(cases)
    baseline_correct = sum(1 for c in cases if c["baseline"] == c["expected"])
    learned_correct = sum(1 for c in cases if c["learned"] == c["expected"])
    regressions = [
        c for c in cases if c["baseline"] == c["expected"] and c["learned"] != c["expected"]
    ]
    passed = learned_correct > baseline_correct and not regressions

    conn = _connect(directory)
    try:
        with _transaction(conn):
            # Lifecycle read, insert, and status update share one transaction so
            # a concurrent rollback cannot retire the lesson mid-evaluation.
            lesson = _load_lesson(conn, args.lesson)
            if lesson is None:
                raise LearningError(f"lesson not found: {args.lesson}")
            if not lesson["active"]:
                raise LearningError(f"lesson {args.lesson} is rolled back")

            created_at = _now()
            conn.execute(
                "INSERT INTO lesson_evaluations (lesson_id, cases_json,"
                " evidence_sha256_json, input_sha256, baseline_correct,"
                " baseline_total, learned_correct, learned_total, passed, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    args.lesson,
                    json.dumps(cases, sort_keys=True),
                    json.dumps(evidence_sha256, sort_keys=True),
                    input_sha256,
                    baseline_correct,
                    total,
                    learned_correct,
                    total,
                    1 if passed else 0,
                    created_at,
                ),
            )
            # Do not demote an already-approved lesson back to "evaluated".
            conn.execute(
                "UPDATE lessons SET status = ? WHERE id = ? AND status NOT IN (?, ?)",
                (_STATUS_EVALUATED, args.lesson, _STATUS_APPROVED, _STATUS_ROLLED_BACK),
            )
    finally:
        conn.close()

    return {
        "lesson_id": args.lesson,
        "passed": passed,
        "baseline_correct": baseline_correct,
        "baseline_total": total,
        "learned_correct": learned_correct,
        "learned_total": total,
        "case_count": total,
        "input_sha256": input_sha256,
        "evidence_sha256": evidence_sha256,
    }


def _run_promote(directory: str, args) -> dict:
    reviewer_family = _resolve_family(args.reviewer_model, "reviewer")

    conn = _connect(directory)
    approved_at = None
    try:
        # Lifecycle reads, evidence checks, and the update share one write
        # transaction. BEGIN IMMEDIATE acquires the write lock up front, so a
        # concurrent rollback cannot retire the lesson between the active check
        # and the UPDATE -- which would otherwise resurrect a retired lesson.
        with _transaction(conn):
            lesson = _load_lesson(conn, args.lesson)
            if lesson is None:
                raise LearningError(f"lesson not found: {args.lesson}")
            if not lesson["active"]:
                raise LearningError(f"lesson {args.lesson} is rolled back")
            if not lesson["producer_family"]:
                raise LearningError(
                    f"lesson {args.lesson} producer family is unknown; cannot verify independence"
                )
            if not reviewer_family:
                raise LearningError(
                    f"reviewer model {args.reviewer_model!r} family is unknown;"
                    " cannot verify independence"
                )
            if reviewer_family == lesson["producer_family"]:
                raise LearningError(
                    f"reviewer must be from a different model family than the producer"
                    f" ({lesson['producer_family']})"
                )

            evaluation = _latest_evaluation(conn, args.lesson)
            if evaluation is None:
                raise LearningError(f"lesson {args.lesson} has no paired evaluation")
            if not evaluation["passed"]:
                raise LearningError(f"lesson {args.lesson} evaluation did not pass")

            # Current-evidence check: the lesson evidence and every
            # evaluation-case evidence must still hash to the value recorded
            # when it was captured.
            lesson_art = _resolve_artifact(directory, lesson["evidence_ref"])
            if lesson_art["sha256"] != lesson["evidence_sha256"]:
                raise LearningError(
                    f"lesson {args.lesson} evidence changed since observe (hash mismatch)"
                )
            evaluation_hashes = json.loads(evaluation["evidence_sha256_json"])
            for ref, expected_hash in evaluation_hashes.items():
                current = _resolve_artifact(directory, ref)
                if current["sha256"] != expected_hash:
                    raise LearningError(
                        f"evaluation evidence {ref!r} changed since evaluate (hash mismatch)"
                    )

            approved_at = _now()
            cursor = conn.execute(
                "UPDATE lessons SET status = ?, active = ?, approved_at = ?,"
                " reviewer_model = ?, reviewer_family = ?, promotion_reason = ?"
                " WHERE id = ? AND active = 1",
                (
                    _STATUS_APPROVED,
                    1,
                    approved_at,
                    args.reviewer_model,
                    reviewer_family,
                    args.reason,
                    args.lesson,
                ),
            )
            if cursor.rowcount != 1:
                raise LearningError(
                    f"lesson {args.lesson} state changed concurrently; promotion aborted"
                )
    finally:
        conn.close()

    return {
        "lesson_id": args.lesson,
        "status": _STATUS_APPROVED,
        "reviewer_model": args.reviewer_model,
        "reviewer_family": reviewer_family,
        "approved_at": approved_at,
    }


def _run_rollback(directory: str, args) -> dict:
    conn = _connect(directory)
    rollback_at = None
    try:
        with _transaction(conn):
            lesson = _load_lesson(conn, args.lesson)
            if lesson is None:
                raise LearningError(f"lesson not found: {args.lesson}")
            if not lesson["active"]:
                raise LearningError(f"lesson {args.lesson} is already rolled back")

            rollback_at = _now()
            conn.execute(
                "UPDATE lessons SET status = ?, active = ?, rollback_at = ?,"
                " rollback_reason = ? WHERE id = ? AND active = 1",
                (_STATUS_ROLLED_BACK, 0, rollback_at, args.reason, args.lesson),
            )
    finally:
        conn.close()

    return {"lesson_id": args.lesson, "status": _STATUS_ROLLED_BACK, "rollback_at": rollback_at}


def _serialize_lesson(lesson: dict, evaluation: dict | None) -> dict:
    record = {
        "id": lesson["id"],
        "candidate_id": lesson["candidate_id"],
        "summary": lesson["summary"],
        "status": lesson["status"],
        "active": bool(lesson["active"]),
        "producer_model": lesson["producer_model"],
        "producer_family": lesson["producer_family"],
        "evidence_ref": lesson["evidence_ref"],
        "evidence_sha256": lesson["evidence_sha256"],
        "created_at": lesson["created_at"],
        "approved_at": lesson["approved_at"],
        "reviewer_model": lesson["reviewer_model"],
        "reviewer_family": lesson["reviewer_family"],
        "promotion_reason": lesson["promotion_reason"],
        "rollback_at": lesson["rollback_at"],
        "rollback_reason": lesson["rollback_reason"],
    }
    if evaluation is None:
        record["evaluation"] = None
    else:
        record["evaluation"] = {
            "passed": bool(evaluation["passed"]),
            "baseline_correct": evaluation["baseline_correct"],
            "baseline_total": evaluation["baseline_total"],
            "learned_correct": evaluation["learned_correct"],
            "learned_total": evaluation["learned_total"],
            "input_sha256": evaluation["input_sha256"],
        }
    return record


def _run_list(directory: str, args) -> dict:
    conn = _connect(directory)
    try:
        if getattr(args, "approved", False):
            where = "status = ? AND active = 1"
            params = (_STATUS_APPROVED,)
        else:
            where = "1 = 1"
            params = ()

        rows = conn.execute(
            f"SELECT * FROM lessons WHERE {where} ORDER BY created_at DESC, id DESC LIMIT ?",
            (*params, MAX_LIST_ROWS),
        ).fetchall()

        lessons = []
        for row in rows:
            lesson = _row_to_dict(row)
            lessons.append(_serialize_lesson(lesson, _latest_evaluation(conn, lesson["id"])))
        return {"lessons": lessons}
    finally:
        conn.close()


def _emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


def _fail(message: str) -> int:
    sys.stderr.write(json.dumps({"error": message}, sort_keys=True) + "\n")
    return 2


def run(args) -> int:
    """Dispatch a parsed ``learn`` command; prints JSON and returns an exit code.

    The caller (``praiseassistant.cli``) propagates the returned integer as the
    process exit code. Success is 0; every failure is fail-closed at 2.
    """
    command = getattr(args, "learn_command", None)
    if command is None:
        return _fail("missing learn subcommand")

    handlers = {
        "observe": _run_observe,
        "evaluate": _run_evaluate,
        "promote": _run_promote,
        "rollback": _run_rollback,
        "list": _run_list,
    }
    handler = handlers.get(command)
    if handler is None:
        return _fail(f"unknown learn command: {command!r}")

    try:
        result = handler(_engagement_dir(args), args)
    except LearningError as exc:
        return _fail(str(exc))
    except Exception as exc:  # noqa: BLE001 - fail closed without leaking internals
        return _fail(f"learning {command} failed: {type(exc).__name__}")

    _emit(result)
    return 0
