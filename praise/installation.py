"""Transactional installation of packaged OMP integration, with reversible removals."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from importlib import resources
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys

from . import config
from .config import atomic_write
from .errors import PraiseError

LEGACY_ROLES = tuple(f"pentest-{role}{suffix}" for role in config.ROLE_NAMES[1:] for suffix in ("", "-deep", "-expert", "-expert-max")) + ("security-reviewer",)
OWNED_OVERRIDES = frozenset(config.ROLE_NAMES + LEGACY_ROLES)
OBSOLETE = ("crew.json", "agents/agent.md", "extensions/crew-router.js", "skills/agents-chat/SKILL.md") + tuple(f"agents/{name}.md" for name in LEGACY_ROLES) + tuple(
    f"skills/{name}/SKILL.md" for name in ("bounty-report", "patch-validation", "praiseassistant-workflow", "praiseassistant-learning")
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe(root: Path, relative: str) -> Path:
    root = root.resolve()
    part = Path(relative)
    if part.is_absolute() or ".." in part.parts:
        raise PraiseError(f"unsafe installation path: {relative}")
    target = root / part
    # Refuse symlinks even when they happen to resolve inside the allowed root.
    current = target
    while current != root:
        if current.is_symlink():
            raise PraiseError(f"symlink installation path: {relative}")
        current = current.parent
    if not target.resolve().is_relative_to(root) or (target.exists() and not target.is_file()):
        raise PraiseError(f"not a regular installation destination: {target}")
    return target


def model_settings(content: str, models: dict | None = None) -> bytes:
    """Migrate old role overrides into the model map and preserve unrelated YAML."""
    lines = content.splitlines(keepends=True)
    candidates = [i for i, line in enumerate(lines) if re.match(r"^(?:task|['\"]task['\"])\s*:", line)]
    if not candidates:
        if any(re.match(r"^<<\s*:", line) for line in lines):
            raise PraiseError("inherited task mappings are unsafe for automatic cleanup")
        return content.encode()
    if len(candidates) != 1 or not re.fullmatch(r"task:\s*(?:#.*)?", lines[candidates[0]].rstrip("\r\n")):
        raise PraiseError("task settings must use one plain YAML block mapping")
    start = candidates[0] + 1
    end = next((i for i in range(start, len(lines)) if lines[i].strip() and not lines[i][0].isspace() and not lines[i].startswith("#")), len(lines))
    section = lines[start:end]
    if any("\t" in line or re.match(r"\s*<<\s*:", line) for line in section):
        raise PraiseError("complex task mapping refused")
    matches = [i for i in range(start, end) if re.match(r"\s*(?:agentModelOverrides|['\"]agentModelOverrides['\"])\s*:", lines[i])]
    if not matches:
        return content.encode()
    if len(matches) == 1 and re.fullmatch(r"  agentModelOverrides: *\{\} *(?:#.*)?", lines[matches[0]].rstrip("\r\n")):
        return content.encode()
    if len(matches) != 1 or not re.fullmatch(r"  agentModelOverrides:\s*(?:#.*)?", lines[matches[0]].rstrip("\r\n")):
        raise PraiseError("role overrides must use one plain YAML block mapping")
    at = matches[0]
    stop = next((i for i in range(at + 1, end) if lines[i].strip() and not lines[i].lstrip().startswith("#") and len(lines[i]) - len(lines[i].lstrip()) <= 2), end)
    retained = []
    seen = set()
    entries = 0
    for line in lines[at + 1:stop]:
        if not line.strip() or line.lstrip().startswith("#"):
            retained.append(line)
            continue
        match = re.fullmatch(r"    ([A-Za-z0-9_-]+):[ \t]+([^\r\n]+)(?:\r?\n)?", line)
        if match is None or match[1] in seen:
            raise PraiseError("complex or duplicate role override mapping refused")
        seen.add(match[1])
        value = match[2].split(" #", 1)[0].rstrip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:-]*", value):
            raise PraiseError("complex role override value refused")
        if match[1] not in OWNED_OVERRIDES:
            entries += 1
            retained.append(line)
        elif models is not None:
            role = match[1]
            if role == "security-reviewer":
                role = "reviewer"
            elif role.startswith("pentest-"):
                role = role.removeprefix("pentest-")
            if role in models:
                models[role] = config.validate_model(value)
    # Empty YAML blocks mean null, not a mapping; use an explicit empty mapping.
    if entries:
        lines[at + 1:stop] = retained
    elif seen:
        ending = "\r\n" if lines[at].endswith("\r\n") else "\n"
        comment = lines[at].rstrip("\r\n").partition("#")[2]
        lines[at:stop] = ["  agentModelOverrides: {}" + (" #" + comment if comment else "") + ending, *retained]
    return "".join(lines).encode()


def _walk(source, prefix=""):
    for entry in sorted(source.iterdir(), key=lambda item: item.name):
        name = f"{prefix}{entry.name}"
        if entry.is_dir():
            yield from _walk(entry, name + "/")
        elif entry.is_file():
            yield name, entry.read_bytes()
        else:
            raise PraiseError(f"unsupported packaged resource: {name}")


def plans(home=None) -> list[tuple[Path, bytes | None, int]]:
    directory = config.agent_dir(home)
    user_home = Path(home).expanduser().resolve() if home is not None else Path.home().resolve()
    entries = []
    root = resources.files("praise").joinpath("integration")
    required = {"RULES.md", "extensions/praise-router.js", "extensions/json-client.mjs", "skills/praise-coordination/SKILL.md"} | {f"agents/{role}.md" for role in config.ROLE_NAMES}
    packaged = dict(_walk(root))
    if not required.issubset(packaged):
        raise PraiseError("packaged Praise integration is incomplete: " + ", ".join(sorted(required - packaged.keys())))
    for relative, data in packaged.items():
        entries.append((safe(directory, relative), data, 0o600))
    role_path = safe(directory, "praise.json")
    catalog = config._read_roles(directory)
    # Reinstall preserves the new source of truth. Initial migration also retains
    # the effective native task overrides previously selected by the operator.
    existing = role_path.exists()
    yaml = safe(directory, "config.yml")
    if yaml.exists():
        cleaned = model_settings(yaml.read_bytes().decode("utf-8"), None if existing else catalog["models"])
        entries.append((yaml, cleaned, stat.S_IMODE(yaml.stat().st_mode)))
    entries.append((role_path, role_path.read_bytes() if existing else config.role_bytes(catalog), 0o600))
    for relative in OBSOLETE:
        target = safe(directory, relative)
        if target not in {row[0] for row in entries} and target.exists():
            entries.append((target, None, 0))
    executable = shlex.quote(str(Path(sys.executable).absolute()))
    entries.append((safe(user_home, ".local/bin/praise"), f'#!/bin/sh\nexec {executable} -m praise "$@"\n'.encode(), 0o700))
    for relative in (".local/bin/praiseassistant", ".local/bin/praise-assistant"):
        target = safe(user_home, relative)
        if target.exists():
            entries.append((target, None, 0))
    return entries


def _target(home: Path, directory: Path, record: dict) -> Path:
    if "agent_dir" in record and record["agent_dir"] != str(directory):
        raise PraiseError("backup belongs to a different OMP agent profile")
    return safe(directory if record.get("root") == "agent" else home, record["path"])


def _record_target(home: Path, directory: Path, target: Path) -> tuple[str, str]:
    if target.is_relative_to(directory):
        return "agent", str(target.relative_to(directory))
    return "home", str(target.relative_to(home))


def _restore_records(home: Path, directory: Path, backup: Path, records: list) -> None:
    for record in reversed(records):
        target = _target(home, directory, record)
        if record["original_sha256"] is None:
            target.unlink(missing_ok=True)
        else:
            saved = safe(backup, record.get("backup_path", record["path"]))
            atomic_write(target, saved.read_bytes(), record["original_mode"])


def rollback(home: Path, backup: Path, *, directory=None) -> dict:
    home = Path(home).expanduser().resolve()
    directory = config.agent_dir(home) if directory is None else Path(directory).resolve()
    backup = Path(backup).expanduser().absolute()
    base = home / ".local/state/praise/install-backups"
    if not backup.is_relative_to(base):
        raise PraiseError("backup must belong to this installation home")
    manifest = safe(home, str((backup / "manifest.json").relative_to(home)))
    records = json.loads(manifest.read_text())
    with config.config_lock(directory):
        for record in records:
            target = _target(home, directory, record)
            installed = record["installed_sha256"]
            if (installed is None and target.exists()) or (installed is not None and (not target.exists() or digest(target.read_bytes()) != installed)):
                raise PraiseError(f"destination changed after installation: {target}")
            if record["original_sha256"] is not None:
                saved = safe(backup, record.get("backup_path", record["path"]))
                if digest(saved.read_bytes()) != record["original_sha256"]:
                    raise PraiseError(f"backup integrity failure: {saved}")
        _restore_records(home, directory, backup, records)
    return {"restored": len(records), "backup": str(backup)}


def install(home=None, *, overwrite=False, dry_run=False, restore_backup=None) -> dict:
    user_home = Path(home).expanduser().resolve() if home is not None else Path.home().resolve()
    directory = config.agent_dir(home)
    if restore_backup is not None:
        if overwrite or dry_run:
            raise PraiseError("rollback does not accept --dry-run or --overwrite")
        return rollback(user_home, Path(restore_backup), directory=directory)
    # Validate resources, paths, YAML and selectors before any configuration mutation.
    initial = plans(home)
    if dry_run:
        return _apply(user_home, directory, initial, overwrite=overwrite, dry_run=True)
    with config.config_lock(directory):
        return _apply(user_home, directory, plans(home), overwrite=overwrite, dry_run=False)


def _apply(home: Path, directory: Path, entries, *, overwrite: bool, dry_run: bool) -> dict:
    updates = []
    conflicts = []
    for target, data, mode in entries:
        if data is None and not target.exists():
            continue
        if data is not None and target.exists() and target.read_bytes() == data and stat.S_IMODE(target.stat().st_mode) == mode:
            continue
        updates.append((target, data, mode))
        if target.exists():
            conflicts.append(str(target))
    if dry_run:
        return {"home": str(home), "agent_dir": str(directory), "changes": [str(row[0]) for row in updates], "conflicts": conflicts}
    if conflicts and not overwrite:
        raise PraiseError("existing owned files differ; use --overwrite to preserve backups: " + ", ".join(conflicts))
    if not updates:
        return {"installed": 0, "home": str(home), "agent_dir": str(directory)}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    manifest = safe(home, f".local/state/praise/install-backups/{stamp}/manifest.json")
    backup = manifest.parent
    backup.mkdir(parents=True, mode=0o700)
    records = []
    for index, (target, data, mode) in enumerate(updates):
        original = target.read_bytes() if target.exists() else None
        original_mode = stat.S_IMODE(target.stat().st_mode) if original is not None else None
        backup_path = f"files/{index}"
        if original is not None:
            atomic_write(safe(backup, backup_path), original, original_mode)
        root, relative = _record_target(home, directory, target)
        records.append({"root": root, "path": relative, "agent_dir": str(directory), "backup_path": backup_path, "original_sha256": digest(original) if original is not None else None, "original_mode": original_mode, "installed_sha256": digest(data) if data is not None else None})
    atomic_write(backup / "manifest.json", (json.dumps(records, indent=2) + "\n").encode(), 0o600)
    applied = []
    try:
        for (target, data, mode), record in zip(updates, records):
            # Track before the operation, including failures after atomic replacement.
            applied.append(record)
            if data is None:
                target.unlink(missing_ok=True)
            else:
                atomic_write(target, data, mode)
    except Exception:
        _restore_records(home, directory, backup, applied)
        raise
    return {"installed": len(updates), "removed": sum(data is None for _, data, _ in updates), "home": str(home), "agent_dir": str(directory), "backup": str(backup)}
