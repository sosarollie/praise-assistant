#!/usr/bin/env python3
"""Verify and restore this snapshot; never import credentials or engagement data."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile

REPO = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def within(root: Path, relative: str) -> Path:
    rel = PurePosixPath(relative)
    if rel.is_absolute() or ".." in rel.parts or not rel.parts:
        raise ValueError(f"Unsafe snapshot path: {relative}")
    target = root.joinpath(*rel.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes its root: {relative}")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home(), help="Restore home; paths are relocated when it differs from the original")
    parser.add_argument("--verify-only", action="store_true", help="Verify hashes and runtime members without restoring anything")
    parser.add_argument("--overwrite", action="store_true", help="Back up and replace differing existing files; replace existing uv tools")
    parser.add_argument("--skip-tools", action="store_true", help="Restore files and binaries without installing Python tools")
    args = parser.parse_args()
    manifest = json.loads((REPO / "snapshot.json").read_text())
    if manifest["format"] != 1:
        raise ValueError("Unsupported snapshot format")
    files = manifest["files"]
    parts = manifest["runtime"]["parts"]
    for record in files + parts:
        source = within(REPO, record["path"])
        if not source.is_file() or digest(source) != record["sha256"]:
            raise ValueError(f"Snapshot integrity failure: {record['path']}")
    runtime_records = manifest["runtime"]["files"]
    expected = {record["restore_path"]: record for record in runtime_records}
    if len(expected) != len(runtime_records):
        raise ValueError("Duplicate runtime paths")
    with tempfile.TemporaryDirectory(prefix="praise-restore-") as scratch:
        stage = Path(scratch)
        archive = stage / "runtime.tar.gz"
        with archive.open("wb") as output:
            for record in parts:
                with within(REPO, record["path"]).open("rb") as source:
                    shutil.copyfileobj(source, output)
        seen = set()
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle:
                if not member.isfile() or member.name not in expected or member.name in seen:
                    raise ValueError(f"Unexpected runtime member: {member.name}")
                target = within(stage / "runtime", member.name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                if digest(target) != expected[member.name]["sha256"]:
                    raise ValueError(f"Runtime integrity failure: {member.name}")
                seen.add(member.name)
        if seen != set(expected):
            raise ValueError("Runtime members are missing")
        archive.unlink()
        print(f"Verified {len(files)} snapshot files, {len(parts)} archive parts, and {len(seen)} runtime files")
        if args.verify_only:
            return
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
            raise ValueError("Bundled runtime requires Linux x86_64 (glibc)")
        home = args.home.expanduser().resolve()
        plans = []
        for record in files + runtime_records:
            relative = record.get("restore_path")
            if relative is None:
                continue
            target = within(home, relative)
            if target.is_symlink() or (target.exists() and not target.is_file()):
                raise ValueError(f"Refusing non-regular destination: {target}")
            source = within(REPO, record["path"]) if "path" in record else within(stage / "runtime", relative)
            if record.get("group") == "assistant" and str(home) != manifest["origin_home"]:
                relocated = within(stage / "relocated", relative)
                relocated.parent.mkdir(parents=True, exist_ok=True)
                relocated.write_bytes(source.read_bytes().replace(manifest["origin_home"].encode(), str(home).encode()))
                source = relocated
            same = target.exists() and digest(target) == digest(source) and stat.S_IMODE(target.stat().st_mode) == record["mode"]
            if not same:
                plans.append((source, target, record["mode"]))
        conflicts = [str(target) for _, target, _ in plans if target.exists()]
        if conflicts and not args.overwrite:
            raise ValueError("Existing files differ; use --overwrite to preserve backups and replace them:\n" + "\n".join(conflicts))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        rollback = home / ".local/state/praise-LLM-Assistant/restore-backups" / stamp
        for source, target, mode in plans:
            if target.exists():
                saved = within(rollback, str(target.relative_to(home)))
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, saved)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(mode)
        print(f"Restored {len(plans)} files under {home}")
        if conflicts:
            print(f"Replaced-file backups: {rollback}")
        shutil.rmtree(stage)
        if args.skip_tools:
            print("Python tool installation skipped; run again without --skip-tools to install")
            return
        uv = home / ".local/bin/uv"
        environment = dict(os.environ, HOME=str(home), UV_TOOL_DIR=str(home / ".local/share/uv/tools"), UV_TOOL_BIN_DIR=str(home / ".local/bin"), UV_PYTHON_INSTALL_DIR=str(home / ".local/share/uv/python"), UV_CACHE_DIR=str(home / ".cache/uv"))
        for name, metadata in manifest["sources"].items():
            if name not in ("frame", "vvaharness"):
                continue
            source = home / ".local/share/praise-LLM-Assistant/sources" / name
            package = str(source) + ("[scan]" if name == "frame" else "")
            command = [str(uv), "tool", "install", "--python", manifest["python_tool_version"], "--with-requirements", str(REPO / "requirements" / f"{name}.txt")]
            if args.overwrite:
                command.append("--force")
            subprocess.run(command + [package], env=environment, check=True)
        print("Frame and Visa harness installed with the captured dependency versions")
        print("Add ~/.local/bin to PATH and reauthenticate OMP providers; see README.md")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
