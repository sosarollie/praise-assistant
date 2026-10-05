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

"""Generic OWASP/CWE taint knowledge base.

This is the user-facing starter pack: small, broad, and intentionally
opinionated. It is separate from the corpus-mined adapters so the default
product path can stay simple while still covering the common attack shapes.

OWASP attack patterns and antipatterns are related but not identical:
attack patterns describe how an exploit manifests, while antipatterns are the
unsafe coding or design habits that make those exploits likely. The starter
pack includes both so the verifier can reason about the exploit shape and the
bad practice that enabled it.

The file is designed to be written as ``rules/generic.kb.yaml`` and loaded by
``CweKB.load()`` alongside ``cwe_kb.yaml`` and any other ``*.kb.yaml``
siblings.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import yaml

from vvaharness import __version__ as _VVAH_VERSION
from vvaharness.backends.llm.registry import prompt
from vvaharness.rules import _norm_cwe

_GENERIC_TOPICS: list[dict] = [
    {
        "cwe": "CWE-89",
        "title": "OWASP A03 Injection: SQL query concatenation",
        "sources": [
            "user input, request params, form fields, query strings",
            "path params, headers, JSON bodies, cookies",
        ],
        "sinks": [
            "string-built SQL passed to execute/query/update",
            "dynamic SQL fragments used for table, column, or ORDER BY names",
        ],
        "sanitizers": [
            "parameterized queries / prepared statements",
            "server-side allow-lists for dynamic identifiers",
        ],
        "non_sanitizers": [
            "manual escaping",
            "regex blacklists for SQL keywords",
        ],
        "fp_checks": [
            "taint reaches a bound parameter value, not the SQL string",
            "query is fully static and only values are interpolated via binds",
        ],
    },
    {
        "cwe": "CWE-78",
        "title": "OWASP A03 Injection: command execution",
        "sources": ["user input, argv/env, request params, config values"],
        "sinks": [
            "shell invocation, Runtime.exec, Process.Start, child_process.exec",
            "any string passed to a shell or eval-style command runner",
        ],
        "sanitizers": [
            "argv-array execution with shell disabled",
            "strict allow-list of commands and arguments",
        ],
        "non_sanitizers": ["quoting only", "blocking punctuation characters"],
        "fp_checks": ["command is constant and arguments are not attacker-controlled"],
    },
    {
        "cwe": "CWE-79",
        "title": "OWASP A03 Injection: HTML / template output",
        "sources": ["HTTP input, comments, markdown, profiles, stored text"],
        "sinks": [
            "innerHTML, document.write, render_template_string, res.send(html)",
            "template raw blocks, safe markers, triple-stache, Markup()",
        ],
        "sanitizers": [
            "context-aware HTML encoding",
            "template auto-escape that stays enabled end-to-end",
        ],
        "non_sanitizers": ["strip_tags", "URL encoding", "JSON serialization"],
        "fp_checks": ["sink is textContent / innerText / JSON response"],
    },
    {
        "cwe": "CWE-22",
        "title": "OWASP A01 Broken Access Control: path traversal",
        "sources": ["user-supplied filename, path, archive member, upload name"],
        "sinks": [
            "open/read/write/delete/sendFile/serveFile on attacker-influenced paths",
        ],
        "sanitizers": [
            "canonicalize then verify inside a fixed base directory",
            "server-side id to path mapping with no raw path joins",
        ],
        "non_sanitizers": ["basename alone", "single ../ replacement", "prefix check before resolve"],
        "fp_checks": ["path is constant or fully server-derived"],
    },
    {
        "cwe": "CWE-918",
        "title": "OWASP A10 SSRF: server-side URL fetch",
        "sources": ["user URL, webhook target, callback URL, redirect URL"],
        "sinks": ["requests/fetch/HttpClient/curl/file_get_contents on remote URLs"],
        "sanitizers": [
            "host allow-list after DNS resolution",
            "private-range and loopback blocking on every hop",
        ],
        "non_sanitizers": ["scheme allow-list only", "string prefix checks on hosts"],
        "fp_checks": ["URL is fixed or drawn from a trusted allow-list"],
    },
    {
        "cwe": "CWE-502",
        "title": "OWASP A08 Software / data integrity: unsafe deserialization",
        "sources": ["untrusted blob, file, message, cookie, session payload"],
        "sinks": [
            "pickle.loads, ObjectInputStream.readObject, BinaryFormatter.Deserialize",
            "YAML/native object loaders that execute constructors or gadgets",
        ],
        "sanitizers": ["safe_load / data-only parsing", "class allow-list filters before object creation"],
        "non_sanitizers": ["signature check after deserialization", "class-name blacklists"],
        "fp_checks": ["input is immutable trusted data and cannot be attacker-writable"],
    },
    {
        "cwe": "CWE-611",
        "title": "OWASP A08 software integrity: XML external entity expansion",
        "sources": ["XML input from request, file, message, or partner system"],
        "sinks": ["XML parsers with DTD/entity resolution enabled"],
        "sanitizers": ["disable DTDs and external entities before parsing"],
        "non_sanitizers": ["post-parse exception handling", "schema validation alone"],
        "fp_checks": ["defused XML parser or equivalent hardened factory is used"],
    },
    {
        "cwe": "CWE-601",
        "title": "OWASP A01 Broken Access Control: open redirect",
        "sources": ["next, returnUrl, redirect, callback, destination parameters"],
        "sinks": ["response redirects and client-side navigation sinks"],
        "sanitizers": ["relative-path allow-list or exact host allow-list"],
        "non_sanitizers": ["startswith('/')", "substring host checks"],
        "fp_checks": ["redirect target is fully server constant"],
    },
    {
        "cwe": "CWE-117",
        "title": "OWASP A09 logging / monitoring: log injection",
        "sources": ["user-controlled strings, headers, stack traces, request bodies"],
        "sinks": ["raw log lines, audit events, CSV export of logs"],
        "sanitizers": ["structured logging with escaping or field separation"],
        "non_sanitizers": ["trimming", "length checks", "removing a few delimiters"],
        "fp_checks": ["output is structured and encoded before log emission"],
    },
    {
        "cwe": "CWE-352",
        "title": "OWASP A01 / session integrity: CSRF on state-changing actions",
        "sources": ["browser-originated requests, forms, fetches, cookies"],
        "sinks": ["state-changing endpoints without anti-CSRF verification"],
        "sanitizers": ["anti-CSRF token or same-site gate checked on every state change"],
        "non_sanitizers": ["custom header names only", "Referer check alone"],
        "fp_checks": ["action is read-only or token is required and validated"],
    },
    {
        "cwe": "CWE-306",
        "title": "OWASP A07 authentication: missing auth check",
        "sources": ["public route, anonymous request, unauthenticated job trigger"],
        "sinks": ["privileged endpoint or command without authentication gate"],
        "sanitizers": ["authentication required before the sensitive action"],
        "non_sanitizers": ["UI-only restriction", "client-side gating"],
        "fp_checks": ["route is internal-only and unreachable from any external entry point"],
    },
    {
        "cwe": "CWE-862",
        "title": "OWASP A01 broken access control: missing authorization",
        "sources": ["tenant id, object id, row id, account id, URL path id"],
        "sinks": ["object access without ownership / role / policy checks"],
        "sanitizers": ["server-side authorization check tied to the resource"],
        "non_sanitizers": ["hiding the id from the UI", "guessable ids are not enough"],
        "fp_checks": ["resource is global or intentionally public"],
    },
    {
        "cwe": "CWE-639",
        "title": "OWASP A01 broken access control: IDOR / object reference",
        "sources": ["object identifiers from request path, query, or body"],
        "sinks": ["fetch/update/delete of another user's object"],
        "sanitizers": ["ownership lookup against authenticated principal"],
        "non_sanitizers": ["UUIDs alone", "random ids alone"],
        "fp_checks": ["identifier is scoped by server-side tenant context before use"],
    },
    {
        "cwe": "CWE-20",
        "title": "OWASP A04 insecure design: missing input validation",
        "sources": ["any untrusted field crossing a trust boundary"],
        "sinks": ["security-sensitive business logic consuming unchecked input"],
        "sanitizers": ["strict type, range, format, and allow-list validation"],
        "non_sanitizers": ["null checks", "length checks only"],
        "fp_checks": ["all attacker-controlled inputs are normalized and validated before use"],
    },
    {
        "cwe": "CWE-327",
        "title": "OWASP A02 cryptographic failures: weak or broken crypto",
        "sources": ["secrets, credentials, tokens, PII, payment data"],
        "sinks": ["MD5/SHA1 for security, hard-coded IVs, obsolete protocols"],
        "sanitizers": ["modern authenticated encryption and strong hash choices"],
        "non_sanitizers": ["HMAC with weak hash", "password hashing with unsalted fast hash"],
        "fp_checks": ["crypto is legacy-only and not used for security decisions"],
    },
    {
        "cwe": "CWE-295",
        "title": "OWASP A02 transport: TLS verification disabled",
        "sources": ["client configuration, deployment config, README instructions"],
        "sinks": ["verify=false, rejectUnauthorized=false, InsecureSkipVerify"],
        "sanitizers": ["TLS verification enabled with trusted CA / pinning policy"],
        "non_sanitizers": ["accepting any certificate", "environmental trust without verification"],
        "fp_checks": ["dev-only harness or isolated test fixture that never ships"],
    },
    {
        "cwe": "CWE-798",
        "title": "OWASP A02 credentials: hardcoded secret or token",
        "sources": ["source code literals, checked-in configs, fixtures, docs"],
        "sinks": ["API keys, passwords, JWTs, private keys, cloud credentials"],
        "sanitizers": ["secret manager lookup or runtime injection from secure storage"],
        "non_sanitizers": ["base64 encoding", "renaming the variable"],
        "fp_checks": ["string is clearly a non-secret placeholder or a public example token"],
    },
    {
        "cwe": "CWE-434",
        "title": "OWASP A05 misconfiguration: unrestricted file upload",
        "sources": ["user file uploads, multipart forms, drag-and-drop files"],
        "sinks": ["storage or execution of uploaded content without validation"],
        "sanitizers": ["type / extension / size allow-lists and safe storage outside web root"],
        "non_sanitizers": ["extension blacklists", "MIME type alone"],
        "fp_checks": ["upload is converted to inert data or stored under a non-executable path"],
    },
    {
        "cwe": "CWE-1333",
        "title": "OWASP A04 availability: regex denial of service",
        "sources": ["attacker-controlled text evaluated by complex regex"],
        "sinks": ["catastrophic-backtracking patterns in search / validation"],
        "sanitizers": ["linear-time regex or bounded matching with input limits"],
        "non_sanitizers": ["short-circuit checks that still leave the bad regex path"],
        "fp_checks": ["pattern is precompiled and not evaluated on attacker-controlled length"],
    },
    {
        "cwe": "CWE-400",
        "title": "OWASP A04 availability: unbounded resource consumption",
        "sources": ["user-controlled pagination, loops, recursion, batch size, uploads"],
        "sinks": ["CPU / memory / disk amplification without hard caps"],
        "sanitizers": ["server-side quotas, paging limits, timeouts, and bounded queues"],
        "non_sanitizers": ["client hints", "best-effort throttling"],
        "fp_checks": ["resource use is bounded by server-enforced limits"],
    },
    {
        "cwe": "CWE-94",
        "title": "OWASP A03 injection: code / expression evaluation",
        "sources": ["template fragments, user expressions, rule text, scripts"],
        "sinks": ["eval, exec, ScriptEngine, new Function, template eval"],
        "sanitizers": ["literal allow-lists and sandboxed expression engines"],
        "non_sanitizers": ["character stripping", "blacklists", "string concatenation"],
        "fp_checks": ["expression is fully authored by trusted code and never data-derived"],
    },
    {
        "cwe": "CWE-117",
        "title": "OWASP A09 observability: sensitive data in logs",
        "sources": ["PII, PAN, tokens, secrets, debug traces"],
        "sinks": ["logs, metrics tags, tracing spans, error telemetry"],
        "sanitizers": ["redaction before write, field-level masking, structured fields"],
        "non_sanitizers": ["manual truncation", "suffix masking only"],
        "fp_checks": ["sensitive fields are redacted before emission"],
    },
    {
        "cwe": "CWE-200",
        "title": "OWASP A01 / A02 information exposure",
        "sources": ["stack traces, debug flags, config dumps, internal ids"],
        "sinks": ["public responses, error pages, diagnostic endpoints"],
        "sanitizers": ["least-information responses and internal-only diagnostics"],
        "non_sanitizers": ["hiding the UI button", "client-side only protections"],
        "fp_checks": ["response is explicitly internal and inaccessible to external actors"],
    },
    {
        "cwe": "CWE-22",
        "title": "OWASP A01 broken access control: archive / path member traversal",
        "sources": ["zip member names, tar entries, upload names, import paths"],
        "sinks": ["file extraction or access using raw member names"],
        "sanitizers": ["member name normalization and base-dir checks"],
        "non_sanitizers": ["single-pass replacement of '../'", "basename alone"],
        "fp_checks": ["archive members are validated against a fixed extraction root"],
    },
    {
        "cwe": "CWE-269",
        "title": "OWASP A01 privilege issue: over-privileged action",
        "sources": ["privileged command, admin endpoint, service token, host OS action"],
        "sinks": ["write/delete/execute beyond the caller's privilege boundary"],
        "sanitizers": ["least-privilege execution / role enforcement / policy checks"],
        "non_sanitizers": ["UI hints", "obscurity", "self-declared role strings"],
        "fp_checks": ["operation is already confined to the caller's minimal privilege"],
    },
    {
        "cwe": "CWE-306",
        "title": "OWASP A07 auth: unauthenticated control plane action",
        "sources": ["scheduler jobs, webhooks, admin APIs, CLI switches"],
        "sinks": ["sensitive control plane operations without auth"],
        "sanitizers": ["auth gate plus server-side permission check"],
        "non_sanitizers": ["hidden routes", "unguarded localhost assumptions"],
        "fp_checks": ["endpoint is unreachable from any untrusted entry point"],
    },
    {
        "cwe": "CWE-326",
        "title": "OWASP A02 cryptography: insufficient encryption strength",
        "sources": ["data at rest, data in transit, long-lived tokens"],
        "sinks": ["weak algorithms, truncated keys, low-entropy secrets"],
        "sanitizers": ["strong modern algorithm and key-size choices"],
        "non_sanitizers": ["homegrown crypto", "security through obscurity"],
        "fp_checks": ["algorithm is non-security legacy only"],
    },
]

_OWASP_ANTIPATTERNS: list[str] = [
    "client-side validation only",
    "manual escaping instead of parameterization or context-aware encoding",
    "blacklist / regex filtering instead of allow-lists",
    "prefix or substring checks before canonicalization / resolution",
    "UI-only auth or authorization checks",
    "hardcoded secrets, tokens, or credentials in source",
    "TLS verification disabled in client code",
    "weak crypto for security decisions",
    "catch-and-ignore after parsing or deserialization",
    "trusting Referer / Origin / SameSite alone for state change protection",
]


def _generic_entries() -> list[dict]:
    entries: list[dict] = []
    for topic in _GENERIC_TOPICS:
        cwe = _norm_cwe(topic["cwe"])
        if not cwe:
            continue
        entries.append({
            "cwe": cwe,
            "origin": "generic",
            "title": topic["title"],
            "sources": list(topic.get("sources") or []),
            "sinks": list(topic.get("sinks") or []),
            "sanitizers": list(topic.get("sanitizers") or []),
            "non_sanitizers": list(topic.get("non_sanitizers") or []),
            "fp_checks": list(topic.get("fp_checks") or []),
            "aliases": topic.get("aliases") or [],
        })
    return entries


def _generic_llm_model(via: str = "sdk", model_id: str = "claude-haiku-4-5"):
    return SimpleNamespace(id=model_id, via=via)


def refine_generic_entries_with_llm(entries: list[dict], *, via: str = "sdk",
                                    model_id: str = "claude-haiku-4-5") -> list[dict]:
    """Use a low-cost model to polish the generic starter pack.

    The model is intentionally pinned to Haiku unless the caller overrides it.
    On parse or schema failure we return the static starter pack unchanged.
    """
    model = _generic_llm_model(via=via, model_id=model_id)
    prompt_payload = {
        "goal": "Polish a small generic CWE/OWASP taint knowledge base for end users.",
        "constraints": [
            "Keep the same number of entries and the same CWEs.",
            "Do not invent new CWEs.",
            "Keep titles short and human-readable.",
            "Keep sources/sinks/sanitizers/non_sanitizers/fp_checks focused on generic attack patterns and antipatterns.",
            "Return ONLY JSON: {\"entries\": [...]}.",
        ],
        "antipatterns": _OWASP_ANTIPATTERNS,
        "entries": entries,
    }
    raw = prompt(
        json.dumps(prompt_payload, indent=2),
        model=model,
        max_tokens=12000,
        timeout=1800,
        output_format="json",
        tag="generic-rulepack-llm",
    )
    try:
        from vvaharness.util.json_extract import extract_json

        data = extract_json(raw)
        rows = (data or {}).get("entries") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            return entries
        by_cwe = {str(e["cwe"]): e for e in entries}
        out: list[dict] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            cwe = _norm_cwe(row.get("cwe"))
            if not cwe or cwe not in by_cwe:
                continue
            base = dict(by_cwe[cwe])
            for key in ("title", "origin", "aliases", "sources", "sinks",
                        "sanitizers", "non_sanitizers", "fp_checks"):
                if key in row and row.get(key) is not None:
                    base[key] = row[key]
            out.append(base)
        return out if out else entries
    except Exception:
        return entries


def write_generic_kb(out_path: Path, *, llm: bool = False,
                     via: str = "sdk", model_id: str = "claude-haiku-4-5") -> Path:
    """Write ``generic.kb.yaml`` into ``out_dir``.

    When ``llm`` is true, a Haiku-backed polish pass is run first.
    """
    entries = _generic_entries()
    if llm:
        entries = refine_generic_entries_with_llm(entries, via=via, model_id=model_id)
    if out_path.suffix in {".yaml", ".yml"}:
        p = out_path
        p.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_path.mkdir(parents=True, exist_ok=True)
        p = out_path / "generic.kb.yaml"
    doc = {"entries": entries}
    p.write_text(
        "# Generated generic CWE/OWASP starter pack.\n"
        "# This file is the user-facing default: broad patterns, short titles,\n"
        "# and OWASP attack-pattern + antipattern guidance for common findings.\n"
        f"# builder={_VVAH_VERSION} llm={llm} via={via} model={model_id}\n"
        + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )
    return p
