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

"""Sandboxed Read/Glob/Grep for non-CLI backends (sdk.py, openai.py); skips shelling to `claude`.
Jailed to `cwd` AND to the scan's exclusion-filtered file inventory once
s1_preprocess registers it (set_scope); read-only; Bash NOT provided; fix mode
mutates via agent_sdk.py's gate instead. Also the shared binary/data-URI
prompt-packing guard (sanitize_packed_text).
"""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

from vvaharness.report.redact import redact_counts

_MAX_BYTES = 200_000
_MAX_MATCHES = 200
_MAX_GLOB = 500
# Per-line ceiling for the Grep scan — a ReDoS bound, since the pattern is model-supplied.
_MAX_GREP_LINE = 50_000

# ── Read-surface scoping ────────────────────────────────────────────────────
# The path jail below (root containment) is necessary but not sufficient: it
# still lets a model Read .git/config, the pipeline's own security-scan/
# output, or directories an operator excluded from the scan precisely to keep
# them away from the model. s1_preprocess registers its exclusion-filtered
# file inventory here (set_scope) before dispatching any agentic call; once
# registered, Read/Glob/Grep are confined to that inventory. Until/unless a
# scope is registered (e.g. a --resume that skipped s1), the confinement-
# critical directory names below are refused unconditionally — they mirror the
# VCS/scan-output entries of s1's _DEFAULT_EXCLUDE_DIRS, which cannot be
# imported here without inverting the backends→pipeline layering.
_ALWAYS_EXCLUDED_DIRS = frozenset({".git", ".hg", ".svn",
                                   "checkpoints", "security-scan"})
_SCOPE: dict[str, frozenset[str]] = {}
_SCOPE_LOCK = threading.Lock()


def set_scope(root: str | Path, files) -> None:
    """Register the scan's in-scope file inventory (repo-relative posix paths)
    for *root*. Idempotent; the latest registration for a root wins."""
    key = str(Path(root).resolve())
    inv = frozenset(str(f).replace("\\", "/") for f in files)
    with _SCOPE_LOCK:
        _SCOPE[key] = inv


def _scope_for(root: Path) -> frozenset[str] | None:
    try:
        key = str(root.resolve())
    except OSError:
        key = str(root)
    return _SCOPE.get(key)


def _excluded_rel(rel: str, scope: frozenset[str] | None) -> bool:
    """True when the repo-relative posix path is outside the tool read
    surface: under an always-excluded directory, or (when an inventory is
    registered) absent from it."""
    parts = rel.split("/")
    if any(part.lower() in _ALWAYS_EXCLUDED_DIRS for part in parts[:-1]):
        return True
    return scope is not None and rel not in scope


def _excluded_target(rel: str, scope: frozenset[str] | None) -> bool:
    """_excluded_rel for an explicit Grep target, which unlike a Read target
    may name a directory. Decides from the path string alone — no filesystem
    access — so it can run BEFORE any existence check and the refusal cannot
    act as an existence oracle. Refuses always-excluded names in every
    component (including the final one: the directory itself); with an
    inventory registered, the target must be an inventory file or an ancestor
    directory of one."""
    parts = rel.split("/")
    if any(part.lower() in _ALWAYS_EXCLUDED_DIRS for part in parts):
        return True
    if scope is None or rel in scope:
        return False
    prefix = rel + "/"
    return not any(f.startswith(prefix) for f in scope)


_SCOPE_ERROR = ("ERROR: path '{path}' is excluded from the scan scope "
                "(not in the scanned file inventory)")

# ── Binary / data-URI guard ─────────────────────────────────────────────────
# Shared choke-point guard for text bound for a model prompt. Two residual
# exposures survive the walk-level extension filter: binary content inside
# text-decoded files (extensionless/unlisted binaries read with
# errors="replace"), and base64 data-URIs embedded in otherwise-text files —
# the latter observed live to make a gateway reject whole requests. Used by
# _read/_grep here; the s4 prompt-packing loaders are the other intended
# caller.
_BINARY_SNIFF_CHARS = 8192
_DATA_URI_RX = re.compile(
    r"data:([\w.+-]+/[\w.+-]+);base64,([A-Za-z0-9+/=]*)")


def _is_binary_text(text: str) -> bool:
    """Cheap binary sniff on the decoded head: a null byte is the
    conventional test; a high U+FFFD density catches non-UTF-8 binaries that
    errors="replace" already mangled."""
    head = text[:_BINARY_SNIFF_CHARS]
    if "\x00" in head:
        return True
    return bool(head) and head.count("�") / len(head) > 0.10


def _elide_data_uris(text: str) -> str:
    # The `data:<type>;base64,` MARKER itself is neutralised, not just its
    # payload: a gateway was observed 400-rejecting whole requests on sniffing
    # that marker in prompt text even when the payload was an empty template
    # placeholder (ISS-15), so preserving the prefix — or skipping short/empty
    # payloads — reopens the defect. Do not "restore" the prefix. The media
    # type stays legible, and the replacement is newline-free so line numbers
    # never shift.
    return _DATA_URI_RX.sub(
        lambda m: (f"[data-uri {m.group(1)} elided: {len(m.group(2))} chars]"
                   if m.group(2) else f"[data-uri {m.group(1)} elided]"),
        text)


def sanitize_packed_text(text: str, rel: str = "") -> str:
    """Guard *text* before it is packed into a prompt: binary content becomes
    a visible elision marker (never mojibake), and base64 data-URIs are
    neutralised in place with a marker, so the model is told what was removed
    instead of being shown (or billed for) the raw bytes."""
    if _is_binary_text(text):
        return f"[binary content elided: {rel or 'file'} is not text]"
    return _elide_data_uris(text)


def _jail(root: Path, p: str) -> Path | None:
    try:
        cand = (root / p).resolve() if not os.path.isabs(p) else Path(p).resolve()
    except (OSError, ValueError):
        return None
    try:
        cand.relative_to(root)
    except ValueError:
        return None
    return cand


def _read(root: Path, path: str, offset: int = 0, limit: int = 2000) -> str:
    fp = _jail(root, path)
    if fp is None:
        return f"ERROR: path '{path}' is outside the repository root"
    # Scope check BEFORE the existence check so an excluded path is refused
    # without acting as an existence oracle for it.
    rel = str(fp.relative_to(root)).replace("\\", "/")
    if _excluded_rel(rel, _scope_for(root)):
        return _SCOPE_ERROR.format(path=path)
    if not fp.is_file():
        return f"ERROR: file not found: {path}"
    try:
        with open(fp, "r", encoding="utf-8", errors="replace") as f:
            # Binary/data-URI guard at the choke point: elide rather than pack
            # mojibake or a base64 blob into the conversation.
            lines = sanitize_packed_text(f.read(_MAX_BYTES * 4), rel).splitlines()
    except OSError as e:
        return f"ERROR: cannot read {path}: {e}"
    start = max(0, int(offset))
    end = start + max(1, int(limit))
    out = []
    for i, line in enumerate(lines[start:end], start + 1):
        out.append(f"{i}\t{line}")
    body = "\n".join(out)
    if len(body) > _MAX_BYTES:
        body = body[:_MAX_BYTES] + "\n... [truncated]"
    if not body:
        body = "(file is empty or offset past EOF)"
    return body


def _glob(root: Path, pattern: str) -> str:
    pat = pattern.lstrip("/").lstrip("\\")
    scope = _scope_for(root)
    try:
        hits = sorted(
            rel
            for p in root.glob(pat)
            if p.is_file()
            and _jail(root, rel := str(p.relative_to(root)).replace("\\", "/"))
            is not None
            and not _excluded_rel(rel, scope)
        )
    except (OSError, ValueError) as e:
        return f"ERROR: invalid glob '{pattern}': {e}"
    if not hits:
        return "No files found"
    if len(hits) > _MAX_GLOB:
        return "\n".join(hits[:_MAX_GLOB]) + f"\n... ({len(hits) - _MAX_GLOB} more)"
    return "\n".join(hits)


def _grep(root: Path, pattern: str, path: str | None = None,
          glob: str | None = None, ignore_case: bool = False,
          context: int = 0) -> str:
    flags = re.IGNORECASE if ignore_case else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        return f"ERROR: invalid regex '{pattern}': {e}"

    scope = _scope_for(root)

    def _in_surface(p: Path) -> bool:
        return (p.is_file() and _jail(root, str(p)) is not None
                and not _excluded_rel(
                    str(p.relative_to(root)).replace("\\", "/"), scope))

    if path:
        target = _jail(root, path)
        if target is None:
            return f"ERROR: path '{path}' is outside the repository root"
        # Scope check BEFORE the is_file/is_dir branch split so an excluded
        # path gets the same refusal whether or not it exists — no existence
        # oracle over excluded paths (mirrors _read's ordering). "." is the
        # root itself, never excluded.
        rel = str(target.relative_to(root)).replace("\\", "/")
        if rel != "." and _excluded_target(rel, scope):
            return _SCOPE_ERROR.format(path=path)
        if target.is_dir():
            files = sorted(p for p in target.rglob("*") if _in_surface(p))
        else:
            files = [target] if target.is_file() else []
    elif glob:
        files = sorted(
            p for p in root.glob(glob.lstrip("/")) if _in_surface(p))
    else:
        files = sorted(p for p in root.rglob("*") if _in_surface(p))

    out: list[str] = []
    n = 0
    ctx = max(0, min(200, int(context)))
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > _MAX_BYTES * 8:
            text = text[: _MAX_BYTES * 8]
        # Binary files yield only mojibake matches — skip them (conventional
        # grep behaviour); neutralise base64 data-URIs so a matched line can't
        # carry the marker or a blob into the conversation.
        if _is_binary_text(text):
            continue
        text = _elide_data_uris(text)
        lines = text.splitlines()
        rel = str(fp.relative_to(root)).replace("\\", "/")

        def _clip(s: str) -> str:
            # Cap the bytes both searched and emitted per line; mark when cut.
            return s if len(s) <= _MAX_GREP_LINE else s[:_MAX_GREP_LINE] + " …[line clipped]"

        for i, line in enumerate(lines):
            # Search only the bounded prefix so a model-supplied pattern can't blow up on a line.
            if rx.search(line[:_MAX_GREP_LINE]):
                if ctx:
                    lo, hi = max(0, i - ctx), min(len(lines), i + ctx + 1)
                    for j in range(lo, hi):
                        mark = ":" if j == i else "-"
                        out.append(f"{rel}:{j + 1}{mark}{_clip(lines[j])}")
                    out.append("--")
                else:
                    out.append(f"{rel}:{i + 1}:{_clip(line)}")
                n += 1
                if n >= _MAX_MATCHES:
                    out.append(f"... (stopped at {_MAX_MATCHES} matches)")
                    return "\n".join(out)
    return "\n".join(out) if out else "No matches found"


# Public surface used by backends/llm/openai.py

_SCHEMAS = {
    "Read": {
        "description": "Read a file from the repository. Returns numbered lines.",
        "parameters": {
            "type": "object",
            "properties": {
                "path":   {"type": "string",
                           "description": "Path relative to the repo root"},
                "offset": {"type": "integer",
                           "description": "0-based line to start from (default 0)"},
                "limit":  {"type": "integer",
                           "description": "Max lines to return (default 2000)"},
            },
            "required": ["path"],
        },
    },
    "Glob": {
        "description": "List files in the repository matching a glob pattern "
                       "(e.g. **/*.java).",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
            },
            "required": ["pattern"],
        },
    },
    "Grep": {
        "description": "Search file contents for a regex. Returns "
                       "file:line:text for each match.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern":     {"type": "string",
                                "description": "Python regex"},
                "path":        {"type": "string",
                                "description": "Restrict to this file or directory"},
                "glob":        {"type": "string",
                                "description": "Restrict to files matching this glob"},
                "ignore_case": {"type": "boolean"},
                "context":     {"type": "integer",
                                "description": "Lines of context around each match"},
            },
            "required": ["pattern"],
        },
    },
}

_EXEC = {
    "Read": lambda root, a: _read(root, a.get("path", ""),
                                  a.get("offset", 0), a.get("limit", 2000)),
    "Glob": lambda root, a: _glob(root, a.get("pattern", "")),
    "Grep": lambda root, a: _grep(root, a.get("pattern", ""),
                                  a.get("path"), a.get("glob"),
                                  bool(a.get("ignore_case", False)),
                                  a.get("context", 0)),
}


def schemas_for(allowed: list[str]) -> list[dict]:
    """Return OpenAI `tools=[...]` entries for the requested tool names.
    Unsupported names (e.g. Bash) are skipped — the caller decides whether
    that's fatal."""
    out = []
    for name in allowed:
        spec = _SCHEMAS.get(name)
        if spec:
            out.append({"type": "function",
                        "function": {"name": name, **spec}})
    return out


def anthropic_schemas_for(allowed: list[str]) -> list[dict]:
    """Return Anthropic Messages-API `tools=[...]` entries for the requested
    tool names. Same source schemas as schemas_for(); only the envelope
    differs (`input_schema` vs OpenAI's nested `function.parameters`)."""
    out = []
    for name in allowed:
        spec = _SCHEMAS.get(name)
        if spec:
            out.append({"name": name,
                        "description": spec["description"],
                        "input_schema": spec["parameters"]})
    return out


def supported(allowed: list[str]) -> tuple[list[str], list[str]]:
    ok = [t for t in allowed if t in _SCHEMAS]
    missing = [t for t in allowed if t not in _SCHEMAS]
    return ok, missing


def summarize_args(args: dict | None) -> str:
    """Return a bounded, non-sensitive summary for a local-tool invocation."""
    parts: list[str] = []
    for key in ("path", "pattern", "glob"):
        value = (args or {}).get(key)
        if value:
            text = str(value)
            parts.append(f"{key}={text[:60]}{'...' if len(text) > 60 else ''}")
    return ", ".join(parts) or "..."


def execute(name: str, args: dict, *, cwd: str) -> str:
    root = Path(cwd).resolve()
    fn = _EXEC.get(name)
    if fn is None:
        return f"ERROR: tool '{name}' is not available on this backend"
    try:
        result = fn(root, args or {})
    except Exception as e:  # noqa: BLE001 — tool errors are data, not crashes
        return f"ERROR: {type(e).__name__}: {e}"
    # Read/Grep results carry file CONTENT and must not be egressed unredacted; Glob returns paths.
    if name in ("Read", "Grep") and not result.startswith("ERROR:"):
        result, _ = redact_counts(result)
    return result
