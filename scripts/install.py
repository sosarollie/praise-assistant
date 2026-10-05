#!/usr/bin/env python3
"""Install PraiseAssistant's owned OMP integration with conflict checks and rollback."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ("agents-chat", "bounty-report", "praiseassistant-workflow", "praiseassistant-learning", "patch-validation")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe(home: Path, relative: str) -> Path:
    path = Path(relative)
    target = home / path
    if path.is_absolute() or ".." in path.parts or target.is_symlink() or not target.resolve().is_relative_to(home):
        raise ValueError(f"Unsafe installation path: {relative}")
    if target.exists() and not target.is_file():
        raise ValueError(f"Not a regular destination: {target}")
    return target


def model_settings(content: str, catalog: dict) -> bytes:
    """Update only owned entries in a plain OMP YAML mapping; refuse complex forms."""
    lines = content.splitlines(keepends=True)
    positions = [i for i, line in enumerate(lines) if re.match(r"^task:\s*(?:#.*)?$", line.rstrip())]
    if len(positions) > 1:
        raise ValueError("Duplicate task settings; resolve them before installation")
    if not positions:
        if any(re.match(r"^task\s*:", line) for line in lines):
            raise ValueError("Task settings must use a plain YAML block mapping")
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        positions = [len(lines)]
        lines += ["task:\n"]
    start = positions[0] + 1
    end = next((i for i in range(start, len(lines)) if lines[i].strip() and not lines[i][0].isspace() and not lines[i].startswith("#")), len(lines))
    matches = [i for i in range(start, end) if re.match(r"^  agentModelOverrides:\s*(?:#.*)?$", lines[i].rstrip())]
    if len(matches) > 1:
        raise ValueError("Duplicate role override mappings")
    if not matches:
        if any("agentModelOverrides:" in lines[i] for i in range(start, end)):
            raise ValueError("Role overrides must use a plain YAML block mapping")
        at = end
        lines.insert(at, "  agentModelOverrides:\n")
        stop = at + 1
    else:
        at = matches[0]
        stop = next((i for i in range(at + 1, end) if lines[i].strip() and len(lines[i]) - len(lines[i].lstrip()) <= 2), end)
    retained = []
    for line in lines[at + 1:stop]:
        if not line.strip() or line.lstrip().startswith("#"):
            retained.append(line)
            continue
        match = re.fullmatch(r"    ([A-Za-z0-9_-]+):\s*([^\n]+)\n?", line)
        if match is None:
            raise ValueError("Complex role override mapping refused; preserve it manually")
        if match.group(1) not in catalog["roles"]:
            retained.append(line)
    generated = [f"    {name}: {entry['models'][0]}\n" for name, entry in catalog["roles"].items()]
    lines[at + 1:stop] = retained + generated
    return "".join(lines).encode()


def atomic_write(target: Path, data: bytes, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            temporary.chmod(mode)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)


def plans(home: Path) -> list[tuple[str, bytes, int]]:
    importlib.metadata.version("praiseassistant")
    catalog_bytes = (ROOT / "praiseassistant/roles.json").read_bytes()
    catalog = json.loads(catalog_bytes)
    entries = []
    for folder in (ROOT / "home/.omp/agent/agents", ROOT / "home/.omp/agent/extensions"):
        for source in sorted(folder.glob("*")):
            if source.is_file() and not source.is_symlink():
                entries.append((str(source.relative_to(ROOT / "home")), source.read_bytes(), 0o600))
    policy = ROOT / "home/.omp/agent/RULES.md"
    entries.append((".omp/agent/RULES.md", policy.read_bytes(), 0o600))
    for skill in SKILLS:
        folder = ROOT / "home/.omp/agent/skills" / skill
        if not (folder / "SKILL.md").is_file():
            raise ValueError(f"Missing workflow skill: {skill}")
        for source in sorted(folder.rglob("*")):
            if source.is_symlink():
                raise ValueError(f"Symlink source refused: {source}")
            if source.is_file():
                entries.append((str(source.relative_to(ROOT / "home")), source.read_bytes(), 0o600))
    entries.append((".omp/agent/crew.json", catalog_bytes, 0o600))
    config = safe(home, ".omp/agent/config.yml")
    content = config.read_text() if config.exists() else "providers:\n  maxInFlightRequests:\n    openai-codex: 3\n"
    entries.append((".omp/agent/config.yml", model_settings(content, catalog), 0o600))
    executable = str(Path(sys.executable).absolute())
    launcher = f"#!/bin/sh\nexec {shlex.quote(executable)} -m praiseassistant \"$@\"\n".encode()
    entries.append((".local/bin/praiseassistant", launcher, 0o700))
    return entries


def rollback(home: Path, backup: Path) -> dict:
    base = home / ".local/state/praiseassistant/install-backups"
    if not backup.resolve().is_relative_to(base.resolve()):
        raise ValueError("Backup must belong to this installation home")
    records = json.loads((backup / "manifest.json").read_text())
    for record in records:
        target = safe(home, record["path"])
        if target.exists() and digest(target.read_bytes()) != record["installed_sha256"]:
            raise ValueError(f"Destination changed after installation: {target}")
        if record["original_sha256"] is not None:
            saved = safe(backup.resolve(), record["path"])
            if digest(saved.read_bytes()) != record["original_sha256"]:
                raise ValueError(f"Backup integrity failure: {saved}")
    for record in records:
        target = safe(home, record["path"])
        if record["original_sha256"] is None:
            target.unlink(missing_ok=True)
        else:
            atomic_write(target, (backup / record["path"]).read_bytes(), record["original_mode"])
    return {"restored": len(records), "backup": str(backup)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--overwrite", action="store_true", help="Back up and replace differing owned files")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--restore-backup", type=Path)
    args = parser.parse_args()
    home = args.home.expanduser().resolve()
    if args.restore_backup:
        if args.dry_run or args.overwrite:
            parser.error("Rollback does not accept --dry-run or --overwrite")
        print(json.dumps(rollback(home, args.restore_backup.expanduser().resolve()), indent=2))
        return
    updates = []
    conflicts = []
    for relative, data, mode in plans(home):
        target = safe(home, relative)
        if target.exists() and target.read_bytes() == data and stat.S_IMODE(target.stat().st_mode) == mode:
            continue
        updates.append((relative, data, mode))
        if target.exists():
            conflicts.append(relative)
    if args.dry_run:
        print(json.dumps({"home": str(home), "changes": [row[0] for row in updates], "conflicts": conflicts}, indent=2))
        return
    if conflicts and not args.overwrite:
        raise ValueError("Existing owned files differ; use --overwrite to preserve backups: " + ", ".join(conflicts))
    if not updates:
        print(json.dumps({"installed": 0, "home": str(home)}))
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = home / ".local/state/praiseassistant/install-backups" / stamp
    backup.mkdir(parents=True, mode=0o700)
    records = []
    for relative, data, mode in updates:
        target = safe(home, relative)
        original = target.read_bytes() if target.exists() else None
        original_mode = stat.S_IMODE(target.stat().st_mode) if original is not None else None
        if original is not None:
            atomic_write(backup / relative, original, original_mode)
        records.append({"path": relative, "original_sha256": digest(original) if original is not None else None, "original_mode": original_mode, "installed_sha256": digest(data)})
    atomic_write(backup / "manifest.json", json.dumps(records, indent=2).encode(), 0o600)
    for relative, data, mode in updates:
        atomic_write(safe(home, relative), data, mode)
    print(json.dumps({"installed": len(updates), "home": str(home), "backup": str(backup)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, importlib.metadata.PackageNotFoundError) as error:
        raise SystemExit(str(error)) from error
