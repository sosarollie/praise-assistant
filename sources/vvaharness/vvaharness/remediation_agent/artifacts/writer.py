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

"""Orchestrates the per-finding on-disk layout with secrets redacted at persistence."""
from __future__ import annotations

import json
import re
from pathlib import Path

from vvaharness.models import FindingCase, Remediation
from vvaharness.remediation_agent.artifacts.layout import (
    DIFF_PATCH,
    EVIDENCE_DIR,
    FINDING_CASE_JSON,
    SUMMARY_MD,
    TRIAGE_JSON,
)
from vvaharness.remediation_agent.artifacts.report import build_report
from vvaharness.remediation_agent.artifacts.summary import render_summary
from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.remediation_agent.target import RemediationTarget
from vvaharness.report.redact import redact, redact_tree

__all__ = ["write_case"]

_HUNK_HEADER_RE = re.compile(
    r"^@@ -\d+(?:,(?P<old_count>\d+))? \+\d+(?:,(?P<new_count>\d+))? @@"
)
_DIFF_STRUCTURE_PREFIXES = (
    "diff --git ",
    "index ",
    "--- ",
    "+++ ",
    "old mode ",
    "new mode ",
    "new file mode ",
    "deleted file mode ",
    "similarity index ",
    "dissimilarity index ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "Binary files ",
    "GIT binary patch",
    "literal ",
    "delta ",
    "# (synthesized diff ",
)
_SAFE_CONFIG_READ_RE = re.compile(
    r"(?:\bos\.environ\[\s*['\"][A-Z_][A-Z0-9_]*['\"]\s*\]"
    r"|\bos\.(?:environ\.get|getenv)\(\s*['\"][A-Z_][A-Z0-9_]*['\"]\s*\)"
    r"|\b(?:config|settings|secrets)\[\s*['\"][A-Z_][A-Z0-9_.-]*['\"]\s*\]"
    r"|\b(?:config|settings)\.[A-Z_][A-Z0-9_]*\b"
    r"|\bprocess\.env(?:\.[A-Z_][A-Z0-9_]*"
    r"|\[\s*['\"][A-Z_][A-Z0-9_]*['\"]\s*\]))"
)
_SECRET_ASSIGNMENT_PREFIX_RE = re.compile(
    r"(?i)(?:\b|(?<=[a-z])|(?<=_))(?:pass(?:word|wd)?|pwd|secret|"
    r"api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|token|"
    r"credential)s?\b['\"`]?\s*[:=]\s*$"
)
_SAFE_CONFIG_SUFFIX_RE = re.compile(
    r"\s*[)\]}]*[,;]?\s*(?:(?:#|//).*)?$"
)
_PEM_BOUNDARY_RE = re.compile(
    r"-{5}(?:BEGIN|END) [A-Z0-9 ]*PRIVATE KEY-{5}"
)
_PEM_HEADER_RE = re.compile(r"^(?:Proc-Type|DEK-Info):", re.IGNORECASE)
_PEM_FRAGMENT_RE = re.compile(
    r"^\s*[\"'`]?(?P<body>[A-Za-z0-9+/]{2,}={0,2})[\"'`]?[;,]?\s*$"
)
_PEM_WRAPPED_FRAGMENT_RE = re.compile(
    r"(?:[\"'`]|>\s*)(?P<body>[A-Za-z0-9+/]{2,}={0,2})"
    r"(?=(?:\\[rn])?(?:[\"'`]|<))"
)
_PEM_SHORT_CONTEXT_RE = re.compile(
    r"(?:<(?:[A-Za-z0-9_.-]+:)?(?:private[-_]?key|pem(?:[-_]?key)?|"
    r"key(?:data|value|material)?)(?:\s[^>]*)?>\s*"
    r"[A-Za-z0-9+/]{4,}={0,2}<"
    r"|(?:private[-_]?key|pem(?:[-_]?key)?)\s*[\"'`]?\s*[:=]\s*"
    r"[\"'`][A-Za-z0-9+/]{4,}={0,2}(?:\\[rn])?[\"'`])",
    re.IGNORECASE,
)


def write_case(out_dir: Path, verdict: RemediationVerdict,
               remediation: Remediation, *, meta: dict,
               target: RemediationTarget | None = None,
               reverted_paths: tuple[str, ...] = ()) -> None:
    """Persist one remediation attempt under *out_dir*: ``finding_case.json`` at the root plus evidence/ (``triage.json``, ``summary.md``, ``diff.patch``); the case file is only emitted when *target* is supplied."""
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = out_dir / EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)
    payload = {**verdict.model_dump(), **meta, "diff_captured": bool(remediation.diff)}

    # Redact string leaves BEFORE serialising, so a secret match can't corrupt JSON quotes/escapes in an already-serialised string.
    (evidence_dir / TRIAGE_JSON).write_text(
        json.dumps(redact_tree(payload), indent=2), encoding="utf-8")
    # summary.md is prose, so the rendered string is masked directly.
    (evidence_dir / SUMMARY_MD).write_text(
        redact(render_summary(verdict, meta=meta)), encoding="utf-8")
    if remediation.diff:
        (evidence_dir / DIFF_PATCH).write_text(
            _redact_diff(remediation.diff), encoding="utf-8", newline="")

    if target is not None:
        case = build_report(target, remediation, reverted_paths=reverted_paths)
        _write_json(out_dir / FINDING_CASE_JSON, _redacted_case(case))


def _redacted_case(case: FindingCase) -> dict:
    """Serialise *case* with prose and structure-preserving diffs masked."""
    payload = redact_tree(case.model_dump(mode="json"))
    for attempt, source in zip(payload["attempts"], case.attempts, strict=True):
        attempt["remediation"]["diff"] = _redact_diff(source.remediation.diff)
    return payload


def _line_parts(line: str) -> tuple[str, str]:
    """Split one physical line without normalising its line ending."""
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith(("\r", "\n")):
        return line[:-1], line[-1:]
    return line, ""


def _private_key_payloads(body: str) -> list[tuple[int, int, str]]:
    matches: list[tuple[int, int, str]] = []
    bare = _PEM_FRAGMENT_RE.fullmatch(body)
    if bare is not None:
        matches.append((*bare.span("body"), bare.group("body")))
    matches.extend(
        (*match.span("body"), match.group("body"))
        for match in _PEM_WRAPPED_FRAGMENT_RE.finditer(body)
    )
    return list(dict.fromkeys(matches))


def _short_private_key_fragment(body: str) -> bool:
    return any(
        len(payload) >= 4 and len(payload) % 4 == 0
        for _, _, payload in _private_key_payloads(body)
    )


def _private_key_fragment(body: str, *, continuation: bool) -> bool:
    """Recognise conservative PEM payload fragments without local delimiters."""
    explicit_context = _PEM_SHORT_CONTEXT_RE.search(body) is not None
    if _PEM_HEADER_RE.match(body.strip()):
        return True
    return any(
        payload.startswith(("MII", "MHc", "MIG"))
        or len(payload) >= 24
        or ((continuation or explicit_context) and len(payload) % 4 == 0)
        for _, _, payload in _private_key_payloads(body)
    )


def _replace_spans(text: str, spans: list[tuple[int, int]]) -> str:
    for start, end in sorted(set(spans), reverse=True):
        text = text[:start] + "[REDACTED-PRIVATE-KEY]" + text[end:]
    return text


def _mask_private_key_body(body: str) -> str:
    spans = [match.span() for match in _PEM_BOUNDARY_RE.finditer(body)]
    spans.extend((start, end) for start, end, _ in _private_key_payloads(body))
    return _replace_spans(body, spans) if spans else "[REDACTED-PRIVATE-KEY]"


def _mask_diff_line(line: str) -> str:
    content, ending = _line_parts(line)
    return content[:1] + _mask_private_key_body(content[1:]) + ending


def _redact_diff_text(text: str) -> str:
    """Redact text while retaining complete credential reads from safe sources."""
    safe_reads = [
        match
        for match in _SAFE_CONFIG_READ_RE.finditer(text)
        if _SECRET_ASSIGNMENT_PREFIX_RE.search(text[:match.start()])
        and _SAFE_CONFIG_SUFFIX_RE.fullmatch(text[match.end():])
    ]
    if not safe_reads:
        return redact(text)

    protected = text
    replacements: list[tuple[str, str]] = []
    for index, match in reversed(list(enumerate(safe_reads))):
        marker = f"${{VVAHARNESS_SAFE_CONFIG_READ_{index}}}"
        while marker in text:
            marker += "_"
        replacements.append((marker, match.group(0)))
        protected = protected[:match.start()] + marker + protected[match.end():]

    masked = redact(protected)
    for marker, source in replacements:
        masked = masked.replace(marker, source)
    return masked


def _redact_unstructured_diff_text(text: str, *, continuation: bool = False) -> str:
    if (
        _PEM_BOUNDARY_RE.search(text) is not None
        or _private_key_fragment(text, continuation=continuation)
    ):
        text = _mask_private_key_body(text)
    return _redact_diff_text(text)


def _redact_diff(diff: str) -> str:
    """Mask hunk payloads while preserving diff framing and line endings exactly."""
    redacted: list[str] = []
    old_remaining = new_remaining = 0
    old_private_key = new_private_key = False
    old_fragment = new_fragment = False
    old_pending: int | None = None
    new_pending: int | None = None

    for physical_line in diff.splitlines(keepends=True):
        line, ending = _line_parts(physical_line)
        header = _HUNK_HEADER_RE.match(line)
        if header is not None:
            old_private_key = new_private_key = False
            old_fragment = new_fragment = False
            old_pending = new_pending = None
            old_remaining = int(header.group("old_count") or 1)
            new_remaining = int(header.group("new_count") or 1)
            redacted.append(
                line[:header.end()]
                + _redact_unstructured_diff_text(line[header.end():])
                + ending
            )
            continue

        in_hunk = old_remaining > 0 or new_remaining > 0
        if line.startswith("\\"):
            redacted.append("\\" + _redact_diff_text(line[1:]) + ending)
            continue

        prefix = line[:1]
        if not in_hunk:
            old_private_key = new_private_key = False
            old_fragment = new_fragment = False
            old_pending = new_pending = None
            if line.startswith(_DIFF_STRUCTURE_PREFIXES):
                redacted.append(physical_line)
            else:
                redacted.append(_redact_unstructured_diff_text(line) + ending)
            continue

        if prefix not in {" ", "+", "-"}:
            if line.startswith(_DIFF_STRUCTURE_PREFIXES):
                old_remaining = new_remaining = 0
                old_private_key = new_private_key = False
                old_fragment = new_fragment = False
                old_pending = new_pending = None
                redacted.append(physical_line)
            else:
                # Unknown in-hunk input is content, not proof that the hunk ended.
                # Keep the parser in its safe state so later payload lines cannot
                # fall back to raw passthrough.
                redacted.append(
                    _redact_unstructured_diff_text(
                        line, continuation=old_private_key or new_private_key
                    ) + ending
                )
            continue

        body = line[1:]
        old_line = prefix in {" ", "-"}
        new_line = prefix in {" ", "+"}
        boundary = _PEM_BOUNDARY_RE.search(body) is not None
        begins = "-----BEGIN " in body and "PRIVATE KEY-----" in body
        ends = "-----END " in body and "PRIVATE KEY-----" in body
        if ends:
            pending = {
                index for index in (
                    old_pending if old_line else None,
                    new_pending if new_line else None,
                ) if index is not None
            }
            for index in pending:
                redacted[index] = _mask_diff_line(redacted[index])

        fragment = _private_key_fragment(
            body,
            continuation=(old_line and old_fragment) or (new_line and new_fragment),
        )
        mask = (
            boundary
            or fragment
            or (old_line and old_private_key)
            or (new_line and new_private_key)
        )
        safe_body = _mask_private_key_body(body) if mask else _redact_diff_text(body)
        redacted.append(prefix + safe_body + ending)
        output_index = len(redacted) - 1
        short_fragment = _short_private_key_fragment(body)

        if old_line:
            old_private_key = (old_private_key or begins) and not ends
            old_fragment = fragment and not ends
            old_pending = output_index if short_fragment and not ends else None
            if old_remaining > 0:
                old_remaining -= 1
        if new_line:
            new_private_key = (new_private_key or begins) and not ends
            new_fragment = fragment and not ends
            new_pending = output_index if short_fragment and not ends else None
            if new_remaining > 0:
                new_remaining -= 1

        if old_remaining == 0 and new_remaining == 0:
            old_private_key = new_private_key = False
            old_fragment = new_fragment = False
            old_pending = new_pending = None

    return "".join(redacted)


def _write_json(path: Path, payload: dict) -> None:
    """Write *payload* atomically, so a concurrent reader never sees a partial file."""
    tmp = path.with_suffix(f"{path.suffix}.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
