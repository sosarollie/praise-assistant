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


from __future__ import annotations

"""Checkpoint/resume key derivation and JSON-backed storage in the SQLite state store."""
import hashlib
import json
import sys
from collections.abc import Iterable
from pathlib import Path

from pydantic import TypeAdapter, ValidationError
from typing_extensions import TypedDict

from vvaharness.models import (
    ContextPackage,
    DroppedFinding,
    FinalReport,
    Finding,
    TaskManifest,
    ThreatModel,
)
from vvaharness.orchestrator import store


# TypeAdapter both serialises (dump_json) and validates on load (validate_json), rejecting a tampered value instead of smuggling it into the pipeline.
class _S4Ckpt(TypedDict):
    findings: list[Finding]
    outcomes: dict[str, str]


class _S5Ckpt(TypedDict):
    findings: list[Finding]
    pre_dropped: list[DroppedFinding]


class _S6Ckpt(TypedDict):
    verified: list[Finding]
    dropped: list[DroppedFinding]


_S7Ckpt = tuple[list[DroppedFinding],   # pre_dropped
                list[Finding],          # verified
                list[DroppedFinding],   # dropped
                list[Finding],          # canonical
                list[DroppedFinding]]   # dup_dropped


from vvaharness.pipeline.stages.s0_seed import SeedPackage

_STEP_SCHEMA: dict[str, TypeAdapter] = {
    # s0 is a plain @dataclass; TypeAdapter serialises/rebuilds it too, Path field included.
    "s0": TypeAdapter(SeedPackage),
    "s1": TypeAdapter(ContextPackage),
    "s2": TypeAdapter(ThreatModel),
    "s3": TypeAdapter(TaskManifest),
    "s4": TypeAdapter(_S4Ckpt),
    "s5": TypeAdapter(_S5Ckpt),
    "s6": TypeAdapter(_S6Ckpt),
    "s7": TypeAdapter(_S7Ckpt),
    "s8": TypeAdapter(FinalReport),
    "s9": TypeAdapter(str),
}

# Step 10 checkpoints one dict per finding under a dynamic remediate_<digest> key, so it can't live in the fixed table above.
_REMEDIATE_STEP_SCHEMA: TypeAdapter = TypeAdapter(dict)

#: The two dynamic step families; the prefix stays in plaintext so ``_schema_for`` can sniff it after the rest is hashed.
REMEDIATE_PREFIX = "remediate_"
VALIDATE_PREFIX = "validate_"

_DYNAMIC_PREFIXES: tuple[str, ...] = (REMEDIATE_PREFIX, VALIDATE_PREFIX)

#: 96 bits of digest; names a checkpoint row, not a directory, so it only needs collision-freedom within one run's finding set.
_STEP_DIGEST_CHARS = 24

# Built lazily: ValidationResult lives in vvaharness.validation, which already imports this package, so a module-level import here would cycle.
_VALIDATE_STEP_SCHEMA: TypeAdapter | None = None


def _validate_schema() -> TypeAdapter:
    """Lazily build and cache the TypeAdapter for ``validate_<id>`` checkpoint steps."""
    global _VALIDATE_STEP_SCHEMA  # cached adapter — intentional module-level state
    if _VALIDATE_STEP_SCHEMA is None:
        from vvaharness.validation.models import ValidationResult
        _VALIDATE_STEP_SCHEMA = TypeAdapter(ValidationResult)
    return _VALIDATE_STEP_SCHEMA


#: Step key holding the normalized exploit-verification collection. Checkpointed so
#: a ``--resume`` run can re-enable EV without the operator re-supplying
#: ``EV_API_COLLECTION``; the variable, when set, overwrites it. Named (not an
#: ``s<n>`` step) because it is an *input* to S6 rather than one stage's output.
EV_COLLECTION_STEP = "ev_collection"

_EV_COLLECTION_SCHEMA: TypeAdapter | None = None


def _ev_collection_schema() -> TypeAdapter:
    """Lazily build and cache the TypeAdapter for the ``ev_collection`` step.

    Lazy for the same reason as :func:`_validate_schema`: exploit verification is an
    additive feature, and a module-level import would put its package in the import
    graph of every checkpoint save/load, including SAST-only runs.
    """
    global _EV_COLLECTION_SCHEMA  # cached adapter — intentional module-level state
    if _EV_COLLECTION_SCHEMA is None:
        from vvaharness.exploit_verification.collection.model import \
            NormalizedCollection
        _EV_COLLECTION_SCHEMA = TypeAdapter(NormalizedCollection)
    return _EV_COLLECTION_SCHEMA


def _schema_for(step: str) -> TypeAdapter:
    """Resolve the TypeAdapter for a checkpoint step. Fixed pipeline steps come
    from ``_STEP_SCHEMA``; the exploit-verification collection, the Remediation
    Agent's dynamic ``remediate_<N>`` steps and the validator's ``validate_<id>``
    steps use their own adapters."""
    """Resolve the TypeAdapter for a checkpoint step, fixed or dynamic."""
    if step in _STEP_SCHEMA:
        return _STEP_SCHEMA[step]
    if step == EV_COLLECTION_STEP:
        return _ev_collection_schema()
    if step.startswith(REMEDIATE_PREFIX):
        return _REMEDIATE_STEP_SCHEMA
    if step.startswith(VALIDATE_PREFIX):
        return _validate_schema()
    return _STEP_SCHEMA[step]   # unknown step → KeyError (caller bug, fail loud)


def step_key_for(prefix: str, *, engine_id: str, engine_version: str,
                 case_id: str, model: str = "", backend: str = "") -> str:
    """Build the dynamic checkpoint step key for one case under one engine, so ``--resume`` cannot republish another producer's result as this run's."""
    if prefix not in _DYNAMIC_PREFIXES:
        msg = (f"unknown dynamic checkpoint prefix {prefix!r}; expected one of "
               f"{_DYNAMIC_PREFIXES} so _schema_for can still route the key")
        raise ValueError(msg)
    material = "\n".join((engine_id, engine_version, case_id, model, backend)).encode()
    return prefix + hashlib.sha256(material).hexdigest()[:_STEP_DIGEST_CHARS]


# One prune per (run_id, prefix) per process: the standalone remediate/validate commands never call reset_run, so without this their rows accumulate forever.
_PRUNED: set[tuple[str, str]] = set()


def prune_stale_steps(run_id: str, prefix: str, live_keys: Iterable[str]) -> list[str]:
    """Delete this run's *prefix* rows that no live case claims, at most once per ``(run_id, prefix)`` per process. Returns the keys removed."""
    once = (run_id, prefix)
    if once in _PRUNED:
        return []
    _PRUNED.add(once)
    removed = store.delete_steps(run_id, prefix, set(live_keys))
    if removed:
        print(f"  [ckpt] pruned {len(removed)} stale {prefix}* checkpoint row(s) for "
              f"{run_id[:12]}… — written by an earlier engine or finding set",
              file=sys.stderr)
    return removed


# Oversized payload is corruption or a resource-exhaustion attempt; enforced here AND by a CHECK constraint on checkpoints.size so a direct INSERT can't bypass it.
_CKPT_MAX_BYTES = 100 * 1024 * 1024


def save_ckpt(ckpt_dir: Path, run_id: str, step: str, obj) -> None:
    """Persist ``obj`` for ``(run_id, step)`` to the SQLite state store; ``ckpt_dir`` is kept only for call-site compatibility."""
    del ckpt_dir
    blob = _schema_for(step).dump_json(obj)  # JSON, never pickle — avoids CWE-502 RCE on a hostile checkpoint
    if len(blob) > _CKPT_MAX_BYTES:
        print(f"  [ckpt] WARN: {step} payload {len(blob)} bytes exceeds "
              f"{_CKPT_MAX_BYTES}; not persisted", file=sys.stderr)
        return
    con = store.connect()
    try:
        with con:   # one transaction == atomic; replaces .tmp + os.replace()
            # Ensure a parent runs row exists even when register_run() was skipped (tests, ad-hoc callers), so the FK + ON DELETE CASCADE hold.
            con.execute("INSERT OR IGNORE INTO runs(run_id, repo_root) "
                        "VALUES (?, '')", (run_id,))
            con.execute("UPDATE runs SET updated_at = datetime('now') "
                        "WHERE run_id = ?", (run_id,))
            con.execute(
                "INSERT OR REPLACE INTO checkpoints"
                "(run_id, step, payload, size) VALUES (?, ?, ?, ?)",
                (run_id, step, blob, len(blob)),
            )
    finally:
        con.close()
    print(f"  [ckpt] saved {step}", file=sys.stderr)


def load_ckpt(ckpt_dir: Path, run_id: str, step: str):
    """Return the rehydrated checkpoint for ``(run_id, step)``, or ``None`` if absent, oversized, or schema-invalid — the caller re-runs the step."""
    del ckpt_dir
    con = store.connect()
    try:
        row = con.execute(
            "SELECT payload, size FROM checkpoints WHERE run_id=? AND step=?",
            (run_id, step),
        ).fetchone()
    finally:
        con.close()
    if row is None:
        if step == "s1":
            print(f"  [ckpt] no checkpoints for {run_id[:12]}… in "
                  f"{store.db_path()} — if you expected resume, check "
                  f"$VVAHARNESS_STATE_DIR", file=sys.stderr)
        return None
    payload, size = row
    if size > _CKPT_MAX_BYTES:   # belt-and-braces; CHECK already enforces
        print(f"  [ckpt] WARN: {step} exceeds {_CKPT_MAX_BYTES} bytes; "
              f"ignoring and re-running", file=sys.stderr)
        return None
    try:
        obj = _schema_for(step).validate_json(payload)
    except (ValidationError, ValueError) as e:
        # Both branches re-run the step; only distinction the bytes support is "is this valid JSON at all?".
        try:
            json.loads(payload)
        except (ValueError, TypeError):
            # Not even well-formed JSON: truncated, corrupt, or a substituted non-checkpoint blob.
            print(f"  [ckpt] WARN: {step} unreadable — payload is not valid "
                  f"JSON (corrupt or untrusted) ({e}); ignoring and "
                  f"re-running", file=sys.stderr)
        else:
            # Well-formed JSON failing the pydantic schema is usually a checkpoint from a different tool version, not a tampering signal.
            print(f"  [ckpt] WARN: {step} schema mismatch — likely written by "
                  f"an incompatible tool version ({e}); discarding and "
                  f"re-running", file=sys.stderr)
        return None
    print(f"  [ckpt] resumed {step} from db", file=sys.stderr)
    return obj


def run_id_for(repo: str | Path) -> str:
    """Stable, non-reversible SHA-256 run id per repo path, so the checkpoint filename leaks nothing about the host's directory layout."""
    return hashlib.sha256(str(Path(repo).resolve()).encode()).hexdigest()[:32]


def prune_checkpoints(*, keep_runs: int = 100, max_age_days: int = 5,
                      dry_run: bool = False) -> dict:
    """Delete ``runs`` rows (and their checkpoints, via ON DELETE CASCADE) older than ``max_age_days`` or beyond the ``keep_runs`` most-recent; ``dry_run`` reports without touching the DB."""
    con = store.connect()
    try:
        total = con.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        victims = [r[0] for r in con.execute(
            """SELECT run_id FROM runs
               WHERE updated_at < datetime('now', ?)
                  OR run_id NOT IN (
                       SELECT run_id FROM runs
                       ORDER BY updated_at DESC LIMIT ?)
               ORDER BY updated_at""",
            (f"-{max_age_days} days", keep_runs),
        )]
        if not dry_run and victims:
            with con:
                con.executemany("DELETE FROM runs WHERE run_id = ?",
                                [(v,) for v in victims])
            # Truncate the -wal file too, or it can sit at the high-water-mark of the largest deleted blob.
            con.execute("PRAGMA incremental_vacuum")
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        con.close()
    return {"root": str(store.db_path()),
            "kept": total - len(victims), "deleted": victims}
