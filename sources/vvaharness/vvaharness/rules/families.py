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

"""Shared semantic-family, CWE and language vocabulary for the rule/callgraph stages."""

from __future__ import annotations

import re

# Sink families whose taint paths survive per-family pruning: reaching any of them
# is on its own worth reporting, so path-budget trimming must not drop the last one.
PROTECTED_SEMANTIC_FAMILIES: frozenset[str] = frozenset({
    "html-response",
    "command-exec",
    "sql-exec",
    "url-fetch",
    "file-io",
    "deserialization",
})

# Family set used by callgraph planning/gating; anything else collapses to "other".
CANONICAL_FAMILIES: frozenset[str] = frozenset({
    "html-response",
    "command-exec",
    "sql-exec",
    "url-fetch",
    "file-io",
    "deserialization",
    "credentials",
    "other",
})

# OWASP Top 10 2025 categories per semantic family. Families absent here fall back
# to Injection, which is the modal category for a taint sink.
OWASP_2025_BY_SEMANTIC: dict[str, tuple[str, ...]] = {
    "html-response": ("A03:2025-Injection",),
    "command-exec": ("A03:2025-Injection",),
    "sql-exec": ("A03:2025-Injection",),
    "url-fetch": ("A10:2025-SSRF", "A03:2025-Injection"),
    "file-io": ("A01:2025-Broken-Access-Control", "A03:2025-Injection"),
    "deserialization": ("A08:2025-Software-and-Data-Integrity-Failures",),
    "template-render": ("A03:2025-Injection",),
    "credentials": ("A02:2025-Cryptographic-Failures",),
}

_DEFAULT_OWASP: tuple[str, ...] = ("A03:2025-Injection",)

# Languages vvaharness can parse, i.e. the extractor registry in _scan.py.
VVAH_LANGUAGES: frozenset[str] = frozenset({
    "python",
    "java",
    "javascript",
    "typescript",
    "go",
    "csharp",
})

# Spellings operators and rule packs use, mapped to a vvaharness language key.
# Mirrors _SEMGREP_TO_VVAH in callgraph_engine/_rules.py, plus common aliases.
_LANG_ALIASES: dict[str, str] = {
    "python": "python", "py": "python", "python3": "python",
    "java": "java",
    "javascript": "javascript", "js": "javascript", "node": "javascript",
    "typescript": "typescript", "ts": "typescript",
    "go": "go", "golang": "go",
    "csharp": "csharp", "c#": "csharp", "cs": "csharp", "dotnet": "csharp",
    "kotlin": "kotlin", "kt": "kotlin",
    "scala": "scala",
    "ruby": "ruby", "rb": "ruby",
    "php": "php",
    "c": "c-cpp", "cpp": "c-cpp", "c++": "c-cpp", "cxx": "c-cpp",
}

_CWE_RE = re.compile(r"CWE[-_ ]?0*(\d{1,4})", re.I)


def norm_cwe(value: object) -> str | None:
    """Canonicalize a CWE reference: 'cwe_089', 'CWE-0089', '89' -> 'CWE-89'.

    Scalar, because every caller uses the result as a dict key or ``or ""`` default.
    """
    match = _CWE_RE.search(str(value or ""))
    return f"CWE-{int(match.group(1))}" if match else None


def canonical_family(value: str) -> str:
    """Collapse *value* to a canonical family, or "other"."""
    return value if value in CANONICAL_FAMILIES else "other"


def owasp_labels(semantic_family: str) -> tuple[str, ...]:
    """OWASP-2025 label tuple for a semantic family (default: Injection)."""
    return OWASP_2025_BY_SEMANTIC.get(semantic_family, ("A03:2025-Injection",))


def resolve_semantic_family(meta: dict, *, fallback: str) -> str:
    """Resolve a rule's semantic family, corpus value first.

    The rule corpus is the single source of truth: ``build_kb`` writes a clamped
    ``metadata.semantic_family`` per rule. Scan-time loaders READ that stored
    value rather than re-deriving it. When the field is absent (older corpora,
    LLM-annotated rules), fall back to the caller's derivation. The result is
    always clamped to the canonical vocabulary.
    """
    stored = str((meta or {}).get("semantic_family") or "").strip().lower()
    return canonical_family(stored) if stored else canonical_family(fallback)


def canonical_lang(value: object) -> str:
    """Normalize a language spelling to its vvaharness key.

    Unknown spellings are returned lowercased rather than mapped to a default: the
    caller warns when the result is outside VVAH_LANGUAGES, and silently rewriting
    a typo to a real language would narrow scan scope without saying so.
    """
    key = str(value or "").strip().lower()
    return _LANG_ALIASES.get(key, key)


__all__ = [
    "CANONICAL_FAMILIES",
    "OWASP_2025_BY_SEMANTIC",
    "PROTECTED_SEMANTIC_FAMILIES",
    "VVAH_LANGUAGES",
    "canonical_family",
    "canonical_lang",
    "norm_cwe",
    "owasp_labels",
    "resolve_semantic_family",
]
