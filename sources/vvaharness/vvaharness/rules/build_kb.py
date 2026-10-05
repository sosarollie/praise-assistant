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

"""
Offline corpus → ``*.kb.yaml`` compiler.

Reads the three local rule-corpus clones and emits one ``rules/<origin>.kb.yaml``
per corpus in the schema documented at the top of ``cwe_kb.yaml`` — so
:class:`vvaharness.rules.CweKB` auto-merges them on next scan with **zero code
change**.

    git clone https://github.com/semgrep/semgrep-rules
    git clone https://github.com/find-sec-bugs/find-sec-bugs
    git clone https://github.com/github/codeql

    python -m vvaharness.rules.build_kb \\
        --semgrep ./semgrep-rules --findsecbugs ./find-sec-bugs --codeql ./codeql

Each corpus is independent and optional. Adding a fourth corpus = add one
``extract_<name>() -> list[dict]`` and register it in ``EXTRACTORS`` — the
writer, dedup, CLI and CweKB loader are all generic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import yaml

from vvaharness import __version__ as _VVAH_VERSION
from vvaharness.rules import _LIST_KEYS, RULES_DIR, _norm_cwe
from vvaharness.rules.families import (
    CANONICAL_FAMILIES as _FAMILIES_CANONICAL,
)
from vvaharness.rules.families import (
    OWASP_2025_BY_SEMANTIC as _FAMILIES_OWASP,
)
from vvaharness.rules.families import (
    canonical_family as _families_canonical_family,
)
from vvaharness.rules.generic_pack import write_generic_kb

_META_RX = re.compile(r"\$[A-Za-z_]\w*|\.\.\.|\[[^]]*]")


def _compact(p: str, max_len: int = 160) -> str:
    """Squash a multi-line semgrep pattern / FSB signature into one line and
    strip metavars/ellipses so it reads as a human hint, not a matcher."""
    p = _META_RX.sub("", p)
    p = re.sub(r"\s+", " ", p).strip(" .")
    return p[:max_len]


def _scoped(lang: str | None, item: str) -> str:
    return f"{lang}: {item}" if lang else item


def _entry(cwe: str, origin: str, *, title: str = "",
           lang: str | None = None,
           sources=(), sinks=(), sanitizers=(), non_sanitizers=(),
           fp_checks=()) -> dict:
    e = {"cwe": cwe, "origin": origin}
    if title:
        e["title"] = title
    for k, vals in (("sources", sources), ("sinks", sinks),
                    ("sanitizers", sanitizers),
                    ("non_sanitizers", non_sanitizers),
                    ("fp_checks", fp_checks)):
        vals = [_scoped(lang, _compact(v)) for v in vals if _compact(v)]
        if vals:
            e[k] = sorted(set(vals))
    return e


# Only taint-mode rules contribute KB value (they carry explicit
# pattern-sources / pattern-sinks / pattern-sanitizers). The full rule files
# themselves are consumed live by s0 — this extractor only harvests the
# SANITIZER knowledge for s4.

def _flatten(node):
    if node is None:
        return
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for n in node:
            yield from _flatten(n)
    elif isinstance(node, dict):
        for k in ("pattern", "pattern-either", "patterns", "pattern-inside",
                  "pattern-regex", "pattern-not-regex"):
            if k in node:
                yield from _flatten(node[k])


def extract_semgrep(root: Path) -> list[dict]:
    out: list[dict] = []
    for f in (*root.rglob("*.yaml"), *root.rglob("*.yml")):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for r in (doc or {}).get("rules") or []:
            if r.get("mode") != "taint":
                continue
            meta = r.get("metadata") or {}
            cwes = [c for c in (meta.get("cwe") if isinstance(meta.get("cwe"), list)
                                else [meta.get("cwe")]) if c]
            langs = r.get("languages") or [None]
            for raw_cwe in cwes:
                cwe = _norm_cwe(raw_cwe)
                if not cwe:
                    continue
                for lang in langs:
                    out.append(_entry(
                        cwe, "semgrep",
                        title=str(raw_cwe).split(":", 1)[-1].strip(),
                        lang=str(lang).lower() if lang else None,
                        sources=_flatten(r.get("pattern-sources")),
                        sinks=_flatten(r.get("pattern-sinks")),
                        sanitizers=_flatten(r.get("pattern-sanitizers")),
                    ))
    return out


# Plain-text JVM sink-signature lists under
#   plugin/src/main/resources/injection-sinks/*.txt

_FSB_MAP: dict[str, tuple[str, str]] = {
    "sql":        ("CWE-89",  "SQL Injection"),
    "command":    ("CWE-78",  "OS Command Injection"),
    "ldap":       ("CWE-90",  "LDAP Injection"),
    "xpath":      ("CWE-643", "XPath Injection"),
    "xss":        ("CWE-79",  "Cross-Site Scripting"),
    "el":         ("CWE-917", "Expression Language Injection"),
    "ognl":       ("CWE-917", "OGNL Injection"),
    "spel":       ("CWE-917", "SpEL Injection"),
    "script":     ("CWE-94",  "Script Engine Injection"),
    "file":       ("CWE-22",  "Path Traversal"),
    "path":       ("CWE-22",  "Path Traversal"),
    "redirect":   ("CWE-601", "Open Redirect"),
    "ssrf":       ("CWE-918", "Server-Side Request Forgery"),
    "xxe":        ("CWE-611", "XML External Entity"),
    "crlf":       ("CWE-113", "HTTP Response Splitting"),
    "log":        ("CWE-117", "Log Injection"),
    "deserial":   ("CWE-502", "Insecure Deserialization"),
}

_FSB_SIG_RX = re.compile(r"^([\w/$.]+)\.([\w<>$]+)\(")


def extract_findsecbugs(root: Path) -> list[dict]:
    sink_dir = next((d for d in root.rglob("injection-sinks") if d.is_dir()),
                    None)
    if not sink_dir:
        print(f"  [build-kb] findsecbugs: injection-sinks/ not found under "
              f"{root}", file=sys.stderr)
        return []
    out: list[dict] = []
    for f in sorted(sink_dir.glob("*.txt")):
        base = f.stem.lower()
        meta = next((v for k, v in _FSB_MAP.items() if base.startswith(k)), None)
        if not meta:
            continue
        cwe, title = meta
        sinks: list[str] = []
        for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith(("#", "//", "-")):
                continue
            m = _FSB_SIG_RX.match(ln)
            if m:
                sinks.append(f"{m.group(1).replace('/', '.')}.{m.group(2)}")
            else:
                sinks.append(ln)
        if sinks:
            out.append(_entry(cwe, "findsecbugs", title=title,
                              lang="java", sinks=sinks))
    return out


# Heuristic regex mine of *.qll for `class X extends …Source/Sink/Sanitizer…`
# and harvest quoted API names from the class body. CWE is taken from the
# enclosing path (…/CWE-079/…).

_QL_LANGS = {"java": "java", "python": "python", "javascript": "javascript",
             "go": "go", "ruby": "ruby", "csharp": "csharp", "cpp": "cpp",
             "swift": "swift"}
_QL_CLASS_PREFIX_RX = re.compile(r"class\s+\w+\s+extends\s+")
_QL_BASES_RX = re.compile(r"[\w\s,.:]+")
_QL_STR_RX = re.compile(r'"([\w$./:%-]{3,200})"')


def _iter_ql_classes(txt: str) -> Iterator[tuple[str, str]]:
    """Yield QLL base lists and bodies without regex backtracking over bodies.

    The input is an operator-supplied corpus, so malformed declarations must
    not make extraction superlinear.  Each search resumes after the region it
    inspected, and ``str.find`` locates the existing heuristic's ``\n}`` body
    terminator in linear time.
    """
    pos = 0
    while prefix := _QL_CLASS_PREFIX_RX.search(txt, pos):
        bases = _QL_BASES_RX.match(txt, prefix.end())
        if bases is None:
            pos = prefix.end()
            continue

        brace = bases.end()
        if brace >= len(txt) or txt[brace] != "{":
            # Skip the whole valid base-character run.  Retrying at embedded
            # ``class`` tokens would repeatedly scan the same malformed text.
            pos = brace
            continue

        body_start = brace + 1
        body_end = txt.find("\n}", body_start)
        if body_end < 0:
            return

        yield bases.group().rstrip(), txt[body_start:body_end]
        pos = body_end + 2


def _ql_role(bases: str) -> str | None:
    b = bases.lower()
    if "sanitizer" in b or "barrier" in b or "guard" in b:
        return "sanitizers"
    if "remoteflowsource" in b or re.search(r"\bsource\b", b):
        return "sources"
    if "sink" in b:
        return "sinks"
    return None


def extract_codeql(root: Path) -> list[dict]:
    out: list[dict] = []
    for lang, dirname in _QL_LANGS.items():
        lroot = root / dirname
        if not lroot.is_dir():
            continue
        bucket: dict[tuple[str, str], set[str]] = defaultdict(set)
        for f in lroot.rglob("*.qll"):
            low = str(f).lower()
            if not any(t in low for t in ("security", "dataflow", "concepts",
                                          "flowsources")):
                continue
            cwe = _norm_cwe(str(f)) or ""
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for bases, body in _iter_ql_classes(txt):
                role = _ql_role(bases)
                if not role:
                    continue
                key_cwe = cwe or _norm_cwe(body) or ""
                if not key_cwe:
                    continue
                for s in _QL_STR_RX.findall(body):
                    if " " in s or s.startswith(("http", "CWE")):
                        continue
                    bucket[(key_cwe, role)].add(s)
        # Also mine the structured MaD (Model-as-Data) YAML files, which are
        # far more comprehensive than the free-form .qll heuristic above.
        _extract_codeql_mad(lroot, lang, bucket)
        for cwe in sorted({c for c, _ in bucket}):
            out.append(_entry(
                cwe, "codeql", lang=lang,
                sources=bucket.get((cwe, "sources"), ()),
                sinks=bucket.get((cwe, "sinks"), ()),
                sanitizers=bucket.get((cwe, "sanitizers"), ()),
            ))
    return out


# Each *.model.yml file lists structured rows with a `kind` label (e.g.
# "sql-injection", "path-injection") that maps cleanly to a CWE. This yields
# ~50× more entries than the .qll regex mine on the same clone.

# CodeQL sink/source `kind` → CWE. Missing kinds are dropped rather than
# guessed. Cross-checked against:
#   codeql/shared/mad/config/*.model.yml   (definitions)
#   codeql/<lang>/ql/lib/ext/*.model.yml   (usage)
_MAD_KIND_TO_CWE: dict[str, str] = {
    # injection family
    "sql-injection":        "CWE-89",
    "command-injection":    "CWE-78",
    "ldap-injection":       "CWE-90",
    "xpath-injection":      "CWE-643",
    "xss":                  "CWE-79",
    "html-injection":       "CWE-79",
    "log-injection":        "CWE-117",
    "code-injection":       "CWE-94",
    "script-injection":     "CWE-94",
    "template-injection":   "CWE-1336",
    "regex-injection":      "CWE-1333",
    "header-injection":     "CWE-113",
    # expression-language / dynamic-eval family
    "ognl-injection":       "CWE-917",
    "spel-injection":       "CWE-917",
    "el-injection":         "CWE-917",
    "jexl-injection":       "CWE-917",
    "mvel-injection":       "CWE-917",
    "groovy-injection":     "CWE-94",
    "jndi-injection":       "CWE-74",
    "fragment-injection":   "CWE-79",
    "intent-redirection":   "CWE-926",
    # traversal / redirection
    "path-injection":       "CWE-22",
    "url-redirection":      "CWE-601",
    "open-url":             "CWE-601",
    # server / network
    "request-forgery":      "CWE-918",
    "ssrf":                 "CWE-918",
    # deserialization
    "unsafe-deserialization": "CWE-502",
    # credentials / secrets
    "credentials-key":       "CWE-798",
    "credentials-password":  "CWE-798",
    "credentials-username":  "CWE-798",
    # android-specific
    "pending-intents":       "CWE-927",
    "contentprovider":       "CWE-926",
    "file-content-store":    "CWE-538",
    # notifications
    "notification":          "CWE-200",
}

# Source `kind` → coarse CWE bucket (sources are tainted-input entry points,
# not vulnerabilities per se; we file them under generic input-validation
# categories so s4 sees them when a matching sink is chosen).
_MAD_SOURCE_KIND_TO_CWE: dict[str, str] = {
    "remote":       "CWE-20",   # untrusted remote input
    "file":         "CWE-22",   # untrusted filesystem input
    "environment":  "CWE-807",  # env / config input
    "database":     "CWE-89",
    "commandargs":  "CWE-88",
}

# Rows in *.model.yml are fixed-length arrays. Column count tells us the model
# kind without having to keep the `extensible:` header in scope.
#   sink/source: 9 or 10 columns
#   summary:     10 or 11 columns  (has both input AND output slot)
#   neutral:     6 or 7 columns    (kind = "sanitizer" | "neutral")


def _mad_signature(row: list) -> str:
    """Build a stable, cross-provenance signature 'package.class.method' from
    a MaD data row. First three columns are always [package, class, subtypes]
    and the method name is at index 3."""
    if len(row) < 4:
        return ""
    pkg = str(row[0] or "").strip()
    cls = str(row[1] or "").strip()
    mth = str(row[3] or "").strip()
    parts = [p for p in (pkg, cls, mth) if p]
    return ".".join(parts)


def _extract_codeql_mad(lroot: Path, lang: str,
                        bucket: "defaultdict[tuple[str, str], set[str]]") -> None:
    """Mine *.model.yml files under a CodeQL language root. Adds to the same
    (cwe, role) bucket the .qll mine uses so the two sources merge cleanly."""
    for f in lroot.rglob("*.model.yml"):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, yaml.YAMLError):
            continue
        for ext in (doc or {}).get("extensions") or []:
            addsto = ext.get("addsTo") or {}
            kind_of_model = str(addsto.get("extensible") or "").lower()
            # Only mine sink / source / neutral / experimental variants; skip
            # summaryModel (flow-through, not an actionable KB fact).
            if not any(k in kind_of_model for k in ("sink", "source", "neutral", "barrier")):
                continue
            role = ("sinks"      if "sink"    in kind_of_model
                    else "sources"    if "source"  in kind_of_model
                    else "sanitizers")
            for row in ext.get("data") or []:
                if not isinstance(row, list) or len(row) < 4:
                    continue
                sig = _mad_signature(row)
                if not sig:
                    continue
                # `kind` slot is second-to-last; provenance is last.
                kind = str(row[-2] or "").strip().lower()
                if role == "sinks":
                    cwe = _MAD_KIND_TO_CWE.get(kind)
                elif role == "sources":
                    cwe = _MAD_SOURCE_KIND_TO_CWE.get(kind)
                else:
                    cwe = "CWE-20"   # sanitizer/neutral → generic input-validation
                if not cwe:
                    continue
                bucket[(cwe, role)].add(sig)


EXTRACTORS = {
    "semgrep":     extract_semgrep,
    "findsecbugs": extract_findsecbugs,
    "codeql":      extract_codeql,
}


def _collapse(entries: list[dict]) -> list[dict]:
    """Merge same-CWE entries within ONE corpus so the emitted YAML has one
    block per CWE (CweKB would merge anyway; this is for human readability)."""
    by_cwe: dict[str, dict] = {}
    for e in entries:
        slot = by_cwe.setdefault(e["cwe"], {"cwe": e["cwe"],
                                            "origin": e["origin"]})
        if e.get("title") and "title" not in slot:
            slot["title"] = e["title"]
        for k in _LIST_KEYS:
            if e.get(k):
                slot.setdefault(k, [])
                for v in e[k]:
                    if v not in slot[k]:
                        slot[k].append(v)
    return [by_cwe[c] for c in sorted(by_cwe)]


def write_kb(origin: str, entries: list[dict], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"{origin}.kb.yaml"
    doc = {"entries": _collapse(entries)}
    p.write_text(
        f"# Generated by `python -m vvaharness.rules.build_kb --{origin} …`.\n"
        f"# Do not edit by hand — re-run the builder against an updated "
        f"corpus clone.\n"
        + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8")
    return p


# The KB `sources:` field feeds the s4 LLM prompt — it's API-name vocabulary,
# not runnable patterns. To let *semgrep itself* (at s0) tag entry points in
# the target repo so it produces richer source→sink codeFlows, we need actual
# semgrep rules. The 267 taint-mode rules in semgrep-rules already carry
# `pattern-sources:` blocks that ARE valid semgrep patterns — we just lift
# them into standalone `mode: search` rules and hand the result back to
# semgrep via `step0.rulepacks`.

# Words in a rule's `id` or top-level directory that map to an entry-point
# kind (mirrors EntryPoint.kind in models.py). Order matters: first hit wins.
_EP_KIND_HINTS: tuple[tuple[str, str], ...] = (
    ("http",           "network"),
    ("route",          "network"),
    ("request",        "network"),
    ("servlet",        "network"),
    ("controller",     "network"),
    ("api",            "network"),
    ("rest",           "network"),
    ("graphql",        "network"),
    ("websocket",      "network"),
    ("cli",            "cli"),
    ("argv",           "cli"),
    ("argparse",       "cli"),
    ("stdin",          "cli"),
    ("env",            "env"),
    ("environment",    "env"),
    ("file",           "filesystem"),
    ("path",           "filesystem"),
    ("upload",         "filesystem"),
    ("kafka",          "ipc"),
    ("jms",            "ipc"),
    ("rabbit",         "ipc"),
    ("queue",          "ipc"),
    ("message",        "ipc"),
    ("intent",         "ipc"),      # Android
    ("deserial",       "network"),  # gadget input usually crosses a boundary
    ("cookie",         "network"),
    ("header",         "network"),
    ("form",           "network"),
    ("param",          "network"),
)


def _guess_ep_kind(rule_id: str, path: str) -> str:
    """Guess EntryPoint.kind from the rule id and its file path."""
    blob = f"{rule_id} {path}".lower()
    for kw, kind in _EP_KIND_HINTS:
        if kw in blob:
            return kind
    return "network"


def _slug(s: str) -> str:
    """Turn a rule id / path into a safe semgrep rule id fragment."""
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()[:96] or "src"


# CWE → coarse sink-action label. Used to tag lifted sink rules with a
# `sink_kind` metadata field that downstream call-graph engines (Path A/B/C)
# can consume without re-parsing the CWE. Missing → "other".
_SINK_KIND_FROM_CWE: dict[str, str] = {
    "CWE-89":   "sql",
    "CWE-78":   "cmd",
    "CWE-88":   "cmd",
    "CWE-79":   "xss",
    "CWE-113":  "header",
    "CWE-117":  "log-injection",
    "CWE-22":   "path",
    "CWE-73":   "path",
    "CWE-94":   "dyn-eval",
    "CWE-95":   "dyn-eval",
    "CWE-502":  "deserialize",
    "CWE-601":  "redirect",
    "CWE-918":  "ssrf",
    "CWE-611":  "xxe",
    "CWE-643":  "xpath",
    "CWE-90":   "ldap",
    "CWE-917":  "el-injection",
    "CWE-74":   "jndi",
    "CWE-798":  "credentials",
    "CWE-1333": "regex",
    "CWE-1336": "template",
    "CWE-327":  "crypto",
    "CWE-338":  "crypto",
    "CWE-352":  "csrf",
    "CWE-926":  "intent-redirection",
    "CWE-927":  "pending-intent",
}


def _guess_sink_kind(cwe: str) -> str:
    """Map a CWE string (e.g. 'CWE-89') to a coarse sink-action label."""
    return _SINK_KIND_FROM_CWE.get(cwe or "", "other")


_OWASP_2025_BY_SEMANTIC: dict[str, tuple[str, ...]] = _FAMILIES_OWASP

# Canonical family set used by callgraph planning/gating.
_CANONICAL_FAMILIES: frozenset[str] = _FAMILIES_CANONICAL


def _canonical_family(v: str) -> str:
    return _families_canonical_family(v)


def _semantic_family_from_sink(cwe: str, sink_kind: str, rule_id: str = "") -> str:
    """Infer a stable sink family for callgraph grouping and LLM prompts."""
    k = (sink_kind or "").lower().strip()
    rid = (rule_id or "").lower()
    c = (cwe or "").upper()
    if ("79" in c or k == "xss" or "render_template" in rid
            or k == "template"):
        return "html-response"
    if "78" in c or k in {"cmd", "dyn-eval"} or "subprocess" in rid:
        return "command-exec"
    if "89" in c or "90" in c or k == "sql":
        return "sql-exec"
    if "918" in c or k == "ssrf":
        return "url-fetch"
    if "22" in c or k == "path":
        return "file-io"
    if "502" in c or k == "deserialize":
        return "deserialization"
    if k in {"credentials", "secret"}:
        return "credentials"
    # Keep the family ontology stable; long-tail sink kinds remain annotations.
    return "other"


def _semantic_family_from_source(cwe: str, ep_kind: str, rule_id: str = "") -> str:
    """Infer a coarse source family so source/sink metadata has parity."""
    k = (ep_kind or "").lower().strip()
    c = (cwe or "").upper()
    rid = (rule_id or "").lower()
    if "502" in c or "deserial" in rid or k == "deserialization":
        return "deserialization"
    if k == "filesystem":
        return "file-io"
    if "89" in c:
        return "sql-exec"
    if "78" in c:
        return "command-exec"
    if "79" in c:
        return "html-response"
    if "918" in c or k == "network":
        return "url-fetch"
    return "other"


def _owasp_2025_labels(semantic_family: str) -> list[str]:
    sf = _canonical_family(semantic_family)
    return list(_OWASP_2025_BY_SEMANTIC.get(
        sf, ("A03:2025-Injection",)))


def _source_meta(cwe: str, ep_kind: str, rule_id: str) -> dict[str, object]:
    semantic_family = _canonical_family(_semantic_family_from_source(cwe, ep_kind, rule_id))
    return {
        "ep_kind": ep_kind,
        "cwe": cwe,
        "semantic_family": semantic_family,
        "owasp_top10_2025": _owasp_2025_labels(semantic_family),
    }


def _sink_meta(cwe: str, sink_kind: str, rule_id: str) -> dict[str, object]:
    semantic_family = _canonical_family(
        _semantic_family_from_sink(cwe, sink_kind, rule_id)
    )
    return {
        "sink_kind": sink_kind,
        "cwe": cwe,
        "semantic_family": semantic_family,
        "owasp_top10_2025": _owasp_2025_labels(semantic_family),
    }


def _print_rule_quality_summary(rules: list[dict], role: str) -> None:
    """Emit a compact quality summary for generated callgraph rulepacks."""
    by_lang: dict[str, int] = defaultdict(int)
    by_family: dict[str, int] = defaultdict(int)
    by_kind: dict[str, int] = defaultdict(int)
    role_key = role.rstrip("s").lower()
    for r in rules:
        for l in (r.get("languages") or []):
            by_lang[str(l)] += 1
        meta = r.get("metadata") or {}
        fam = str(meta.get("semantic_family") or "other")
        by_family[_canonical_family(fam)] += 1
        kind_key = "ep_kind" if role_key == "source" else "sink_kind"
        kind = str(meta.get(kind_key) or "other")
        by_kind[kind] += 1
    fam_top = ", ".join(
        f"{k}:{v}" for k, v in sorted(by_family.items(), key=lambda kv: kv[1], reverse=True)[:8]
    )
    kind_top = ", ".join(
        f"{k}:{v}" for k, v in sorted(by_kind.items(), key=lambda kv: kv[1], reverse=True)[:8]
    )
    print(
        f"  [build-kb] {role} quality: langs={dict(sorted(by_lang.items()))} "
        f"families={fam_top or 'none'} kinds={kind_top or 'none'}",
        file=sys.stderr,
    )


# Iteration 1 default coverage: keep common app languages enabled so
# family-focused rule curation does not silently narrow scan scope.
_CALLGRAPH_DEFAULT_LANGS: tuple[str, ...] = (
    "python",
    "java",
    "javascript",
    "typescript",
    "go",
    "csharp",
)


def _parse_lang_list(raw: str | None) -> frozenset[str]:
    vals = [x.strip().lower() for x in str(raw or "").split(",") if x.strip()]
    if any(v in {"all", "*"} for v in vals):
        # Empty set means "no language filtering" downstream.
        return frozenset()
    return frozenset(vals) if vals else frozenset(_CALLGRAPH_DEFAULT_LANGS)


def _load_rule_file(path: Path) -> list[dict]:
    """Load a semgrep-style rule file (`rules: [...]`)."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, yaml.YAMLError):
        return []
    rows = (doc or {}).get("rules") if isinstance(doc, dict) else None
    return [r for r in (rows or []) if isinstance(r, dict)]


def _normalize_callgraph_rule(rule: dict,
                              *,
                              role: str,
                              callgraph_langs: frozenset[str],
                              strict: bool) -> dict | None:
    """Normalize and validate one rule for callgraph consumption.

    - keeps only target languages (default python/java)
    - enforces minimal metadata required by callgraph mode
    - returns cleaned rule or None (dropped)
    """
    rid = str(rule.get("id") or "").strip() or "<missing-id>"
    langs = [str(l).strip().lower() for l in (rule.get("languages") or [])
             if str(l).strip()]
    if callgraph_langs:
        langs = sorted({l for l in langs if l in callgraph_langs})
    else:
        langs = sorted(set(langs))
    if not langs:
        return None
    out = dict(rule)
    out["languages"] = langs
    meta = dict(out.get("metadata") or {})
    cwe = _norm_cwe(meta.get("cwe")) or ""
    if not cwe:
        msg = f"[build-kb] rule {rid}: missing/invalid metadata.cwe"
        if strict:
            raise ValueError(msg)
        # Keep recall broad for LLM/cloned corpora in non-strict mode.
        cwe = "CWE-20"
        print(f"  {msg} — defaulting to {cwe}", file=sys.stderr)
    meta["cwe"] = cwe
    if role == "source":
        ep_kind = str(meta.get("ep_kind") or "").strip().lower()
        if not ep_kind:
            msg = f"[build-kb] source rule {rid}: missing metadata.ep_kind"
            if strict:
                raise ValueError(msg)
            ep_kind = "network"
            print(f"  {msg} — defaulting to {ep_kind}", file=sys.stderr)
        meta.update(_source_meta(cwe, ep_kind, rid))
    else:
        sink_kind = str(meta.get("sink_kind") or _guess_sink_kind(cwe)).strip().lower()
        if not sink_kind:
            msg = f"[build-kb] sink rule {rid}: missing metadata.sink_kind"
            if strict:
                raise ValueError(msg)
            sink_kind = "other"
            print(f"  {msg} — defaulting to {sink_kind}", file=sys.stderr)
        sf = str(meta.get("semantic_family") or "").strip().lower()
        if not sf:
            sf = _semantic_family_from_sink(cwe, sink_kind, rid)
        sf = _canonical_family(sf)
        owasp = meta.get("owasp_top10_2025")
        if not isinstance(owasp, list) or not owasp:
            owasp = _owasp_2025_labels(sf)
        meta["sink_kind"] = sink_kind
        meta["semantic_family"] = sf
        meta["owasp_top10_2025"] = list(owasp)
    out["metadata"] = meta
    return out


def _prepare_callgraph_rules(rules: list[dict],
                             *,
                             role: str,
                             callgraph_langs: frozenset[str],
                             strict: bool) -> list[dict]:
    out: list[dict] = []
    for r in rules:
        nr = _normalize_callgraph_rule(
            r,
            role=role,
            callgraph_langs=callgraph_langs,
            strict=strict,
        )
        if nr is not None:
            out.append(nr)
    return out


# semgrep fields that are ONLY valid inside `mode: taint`. If we leave them on
# a lifted source block, `mode: search` returns a fatal schema error and the
# whole file is rejected. Enumerated from semgrep's rule_schema_v1.yaml.
_TAINT_ONLY_KEYS: frozenset[str] = frozenset({
    "label",
    "requires",
    "by-side-effect",
    "at-exit",
})

# Semgrep pattern operators — anything else at a nested level is a leaf we
# should preserve as-is (metavariable-regex, metavariable-pattern,
# focus-metavariable, etc.).
_PATTERN_OPS: frozenset[str] = frozenset({
    "pattern", "patterns", "pattern-either", "pattern-inside",
    "pattern-not", "pattern-not-inside", "pattern-regex",
    "pattern-not-regex", "metavariable-regex", "metavariable-pattern",
    "metavariable-comparison", "focus-metavariable",
})


def _strip_taint_keys(node):
    """Recursively drop taint-mode-only keys so a lifted source expression is
    valid under `mode: search`. Returns the cleaned structure (or None if it
    collapses to nothing usable)."""
    if isinstance(node, dict):
        cleaned = {}
        for k, v in node.items():
            if k in _TAINT_ONLY_KEYS:
                continue
            cv = _strip_taint_keys(v)
            if cv is not None:
                cleaned[k] = cv
        # A dict that only carried taint-only keys is now empty → drop it.
        return cleaned or None
    if isinstance(node, list):
        cleaned_list = [_strip_taint_keys(x) for x in node]
        cleaned_list = [x for x in cleaned_list if x is not None
                        and not (isinstance(x, dict) and not x)]
        return cleaned_list or None
    return node


def _lift_pattern_sources(psrc) -> dict | None:
    """Turn a semgrep taint rule's `pattern-sources:` value into a top-level
    pattern operator suitable for a `mode: search` rule.

    Input shapes (all valid semgrep):
        list[dict]   — most common; each dict has {pattern|patterns|
                       pattern-either|pattern-inside|pattern-regex}
        dict         — single source expression
    Output: a dict with exactly one of the top-level pattern operators, ready
    to splice into a rule dict. Returns None if the shape is unrecognized or
    empty. All taint-only keys (label, requires, by-side-effect, at-exit) are
    stripped so the result is valid under `mode: search`.
    """
    psrc = _strip_taint_keys(psrc)
    if not psrc:
        return None
    if isinstance(psrc, dict):
        return psrc if any(k in psrc for k in (
            "pattern", "patterns", "pattern-either", "pattern-regex")) else None
    if isinstance(psrc, list):
        clean = [p for p in psrc if isinstance(p, dict) and any(
            k in p for k in ("pattern", "patterns", "pattern-either",
                             "pattern-inside", "pattern-regex"))]
        if not clean:
            return None
        if len(clean) == 1:
            return clean[0]
        return {"pattern-either": clean}
    return None


def extract_semgrep_source_rules(root: Path) -> list[dict]:
    """Harvest `pattern-sources:` from every taint-mode rule in the semgrep-
    rules corpus and repackage as standalone `mode: search` rules. The result
    is a valid semgrep rule list that s0_seed can load via `step0.rulepacks`.
    """
    rules: list[dict] = []
    seen_ids: set[str] = set()
    for f in (*root.rglob("*.yaml"), *root.rglob("*.yml")):
        rel = str(f.relative_to(root)).replace("\\", "/")
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for r in (doc or {}).get("rules") or []:
            if r.get("mode") != "taint":
                continue
            block = _lift_pattern_sources(r.get("pattern-sources"))
            if not block:
                continue
            original_id = str(r.get("id") or "").strip()
            if not original_id:
                continue
            langs = r.get("languages") or []
            if not langs:
                continue
            meta = r.get("metadata") or {}
            cwe_raw = meta.get("cwe")
            cwes = [c for c in (cwe_raw if isinstance(cwe_raw, list)
                                else [cwe_raw]) if c]
            cwe = _norm_cwe(cwes[0]) if cwes else ""
            new_id = f"vvah.gen.source.{_slug(original_id)}"
            if new_id in seen_ids:
                new_id = f"{new_id}.{_slug(rel)[:32]}"
            if new_id in seen_ids:
                continue
            seen_ids.add(new_id)
            new_rule: dict = {
                "id":         new_id,
                "languages":  langs,
                "severity":   "INFO",
                "message":    f"Untrusted input source (from {original_id})",
                "metadata": {
                    **_source_meta(cwe or "CWE-20", _guess_ep_kind(original_id, rel), original_id),
                    "source_of":   original_id,
                    "vvah_gen":    True,
                    "category":    "security",
                },
            }
            new_rule.update(block)
            rules.append(new_rule)
    return rules


def _lift_pattern_sinks(psinks) -> dict | None:
    """`pattern-sinks:` blocks have the same schema as `pattern-sources:`
    in semgrep taint mode (see semgrep rule_schema_v1.yaml). Delegate to the
    shared normalizer so a lifted sink expression is a valid `mode: search`
    top-level pattern operator."""
    return _lift_pattern_sources(psinks)


def extract_semgrep_sink_rules(root: Path) -> list[dict]:
    """Harvest `pattern-sinks:` from every taint-mode rule in the semgrep-
    rules corpus and repackage as standalone `mode: search` rules. Each
    lifted rule carries the parent taint rule's CWE tag verbatim, so
    semgrep-at-s0 emits proper `properties.tags: [CWE-XX]` in SARIF and
    :func:`_parse_sarif` picks it up onto each Sink.
    """
    rules: list[dict] = []
    seen_ids: set[str] = set()
    for f in (*root.rglob("*.yaml"), *root.rglob("*.yml")):
        rel = str(f.relative_to(root)).replace("\\", "/")
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for r in (doc or {}).get("rules") or []:
            if r.get("mode") != "taint":
                continue
            block = _lift_pattern_sinks(r.get("pattern-sinks"))
            if not block:
                continue
            original_id = str(r.get("id") or "").strip()
            if not original_id:
                continue
            langs = r.get("languages") or []
            if not langs:
                continue
            meta = r.get("metadata") or {}
            cwe_raw = meta.get("cwe")
            cwes = [c for c in (cwe_raw if isinstance(cwe_raw, list)
                                else [cwe_raw]) if c]
            cwe = _norm_cwe(cwes[0]) if cwes else ""
            new_id = f"vvah.gen.sink.{_slug(original_id)}"
            if new_id in seen_ids:
                new_id = f"{new_id}.{_slug(rel)[:32]}"
            if new_id in seen_ids:
                continue
            seen_ids.add(new_id)
            sink_kind = _guess_sink_kind(cwe)
            new_rule: dict = {
                "id":         new_id,
                "languages":  langs,
                "severity":   "INFO",
                "message":    f"Unsafe sink (from {original_id})",
                "metadata": {
                    **_sink_meta(cwe or "CWE-20", sink_kind, original_id),
                    "sink_of":     original_id,
                    "vvah_gen":    True,
                    "category":    "security",
                },
            }
            new_rule.update(block)
            rules.append(new_rule)
    return rules


def _git_sha_for(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        p = path.resolve()
    except OSError:
        return ""
    try:
        r = subprocess.run(
            ["git", "-C", str(p), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:  # noqa: BLE001
        return ""
    if r.returncode != 0:
        return ""
    return (r.stdout or "").strip()


def _artifact_provenance(*,
                         artifact_type: str,
                         rules: list[dict],
                         callgraph_langs: frozenset[str],
                         strict_callgraph: bool,
                         semgrep_dir: Path | None = None,
                         codeql_dir: Path | None = None,
                         findsecbugs_dir: Path | None = None,
                         llm_sources_in: Path | None = None,
                         llm_sinks_in: Path | None = None) -> dict:
    payload = json.dumps(rules, sort_keys=True, separators=(",", ":")).encode("utf-8")
    inputs: dict[str, dict] = {}

    def _input(path: Path | None) -> dict | None:
        if path is None:
            return None
        rec: dict[str, str] = {"path": str(path)}
        sha = _git_sha_for(path)
        if sha:
            rec["git_sha"] = sha
        return rec

    for key, val in (
        ("semgrep", _input(semgrep_dir)),
        ("codeql", _input(codeql_dir)),
        ("findsecbugs", _input(findsecbugs_dir)),
        ("llm_sources_in", _input(llm_sources_in)),
        ("llm_sinks_in", _input(llm_sinks_in)),
    ):
        if val is not None:
            inputs[key] = val

    return {
        "artifact_type": artifact_type,
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "builder_version": _VVAH_VERSION,
        "strict_callgraph": bool(strict_callgraph),
        "callgraph_languages": sorted(callgraph_langs) if callgraph_langs else ["all"],
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "inputs": inputs,
    }


def write_sources_yaml(rules: list[dict], out_path: Path,
                       *, provenance: dict | None = None) -> Path:
    """Emit a semgrep-loadable rule file at `out_path`."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Auto-generated by `python -m vvaharness.rules.build_kb "
        "--semgrep <dir> [--codeql <dir>] --sources-out <path>`.\n"
        "# Contents:\n"
        "#   (a) every `pattern-sources:` block from taint-mode rules in the\n"
        "#       semgrep-rules corpus, repackaged as standalone `mode: search`\n"
        "#       rules, and\n"
        "#   (b) one import-scoped rule per (language, package, class) group\n"
        "#       from CodeQL Model-as-Data `sourceModel` rows (java/csharp/go).\n"
        "# So semgrep at s0 tags matching code as taint entry points and\n"
        "# produces richer source->sink codeFlows in SARIF while the same\n"
        "# YAML remains usable as the callgraph engine's rule-backed input.\n"
        "#\n"
        "# To load this file at scan time, add its path to `step0.rulepacks`\n"
        "# in your profile (alongside or instead of the vendored\n"
        "# `rules/sources.yaml`). Do NOT hand-edit — re-run the builder.\n"
    )
    doc = {"rules": rules}
    if provenance:
        doc["vvah_artifact"] = provenance
    out_path.write_text(
        header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True,
                                width=200),
        encoding="utf-8")
    return out_path


def write_sinks_yaml(rules: list[dict], out_path: Path,
                     *, provenance: dict | None = None) -> Path:
    """Emit a semgrep-loadable sink-rule file at `out_path`. Mirrors
    :func:`write_sources_yaml` — same rule schema, different provenance."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Auto-generated by `python -m vvaharness.rules.build_kb "
        "--semgrep <dir> [--codeql <dir>] --sinks-out <path>`.\n"
        "# Contents:\n"
        "#   (a) every `pattern-sinks:` block from taint-mode rules in the\n"
        "#       semgrep-rules corpus, repackaged as standalone `mode: search`\n"
        "#       rules, and\n"
        "#   (b) one import-scoped rule per (language, package, class) group\n"
        "#       from CodeQL Model-as-Data `sinkModel` rows (java/csharp/go).\n"
        "# Each rule carries `metadata.cwe`, `metadata.sink_kind`,\n"
        "# `metadata.semantic_family`, and `metadata.owasp_top10_2025` so a\n"
        "# downstream call-graph engine can group rules deterministically,\n"
        "# and a future LLM-backed detection mode can consume compact graph\n"
        "# metadata without re-deriving the family label.\n"
        "#\n"
        "# To load this file at scan time, add its path to `step0.rulepacks`\n"
        "# in your profile. Do NOT hand-edit — re-run the builder.\n"
    )
    doc = {"rules": rules}
    if provenance:
        doc["vvah_artifact"] = provenance
    out_path.write_text(
        header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True,
                                width=200),
        encoding="utf-8")
    return out_path


# The MaD sourceModel data rows are structured API signatures (package + class
# + method) but semgrep needs a syntactic pattern. We generate ONE rule per
# (language, package, class) that:
#   1. Requires the target file to *import* the class (pattern-inside), so
#      false positives are kept to the same-name-different-lib case only, and
#   2. Matches any `$X.$METHOD(...)` where $METHOD ∈ the modeled method set.
# Languages without a clean import→pattern mapping (JS "Member[X]" DSL rows,
# Python placeholder files, C++ #include) are skipped intentionally.

# Which CodeQL corpus dirs contribute → which semgrep language(s) to target.
# Kotlin shares the JVM import surface, so java sources apply to both.
_QL_SOURCE_LANGS: dict[str, list[str]] = {
    "java":   ["java", "kotlin"],
    "csharp": ["csharp"],
    "go":     ["go"],
}

# Method names too generic to give any useful source signal even when
# import-scoped — they fire on unrelated code with matching names.
_NOISY_METHOD_NAMES: frozenset[str] = frozenset({
    "toString", "equals", "hashCode", "clone", "compareTo",
    "iterator", "size", "length", "isEmpty",
    "of", "from", "to",
})


def _import_pattern(lang_dir: str, pkg: str, cls: str) -> str | None:
    """Return the semgrep `pattern-inside` text that requires the target
    source file to import the modeled class. Returns None when the shape is
    unusable (empty package, un-mappable language).
    """
    if not pkg:
        return None
    if lang_dir == "java":
        # `import <pkg>.<class>;` — or wildcard `import <pkg>.*;` — either
        # form should satisfy pattern-inside via metavariable ellipsis.
        if not cls:
            return f"import {pkg}.*;\n..."
        return (f"import {pkg}.{cls};\n"
                f"...\n")
    if lang_dir == "csharp":
        # C# `using` imports a namespace, not a class.
        return f"using {pkg};\n...\n"
    if lang_dir == "go":
        # Go imports look like `import "path/pkg"` or a grouped block.
        return f'import "{pkg}"\n...\n'
    return None


def _call_pattern(lang_dir: str, cls: str) -> str:
    """Semgrep pattern for a receiver-qualified method call. We match any
    receiver so the pattern-inside import scope does the class-narrowing.
    Standalone functions (empty class) get `<method>(...)` in Go.
    """
    if lang_dir == "go" and not cls:
        # Standalone Go function: use bare-name pattern; import scope narrows.
        return "$METHOD(...)"
    return "$X.$METHOD(...)"


def extract_codeql_source_rules(root: Path) -> list[dict]:
    """Harvest MaD `sourceModel` rows and generate one semgrep rule per
    (language, package, class) group. Requires the class's import to be
    present in the target file — this keeps method-name false positives
    bounded to the same-name-different-library case."""
    if not root.is_dir():
        return []
    # (lang_dir, package, class) -> { method: kind }
    groups: dict[tuple[str, str, str], dict[str, str]] = defaultdict(dict)
    for lang_dir in _QL_SOURCE_LANGS:
        lroot = root / lang_dir
        if not lroot.is_dir():
            continue
        for f in lroot.rglob("*.model.yml"):
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8",
                                                 errors="ignore"))
            except (OSError, yaml.YAMLError):
                continue
            for ext in (doc or {}).get("extensions") or []:
                addsto = ext.get("addsTo") or {}
                if "source" not in str(addsto.get("extensible") or "").lower():
                    continue
                for row in ext.get("data") or []:
                    if not isinstance(row, list) or len(row) < 4:
                        continue
                    pkg = str(row[0] or "").strip()
                    cls = str(row[1] or "").strip()
                    mth = str(row[3] or "").strip()
                    kind = str(row[-2] or "").strip().lower()
                    if not pkg or not mth or mth in _NOISY_METHOD_NAMES:
                        continue
                    # Skip rows where the "method" is actually a constructor
                    # named identical to the class — sources from those are
                    # already covered by object-creation semgrep patterns.
                    if cls and mth == cls:
                        continue
                    groups[(lang_dir, pkg, cls)][mth] = kind
    rules: list[dict] = []
    for (lang_dir, pkg, cls), methods in sorted(groups.items()):
        if not methods:
            continue
        inside = _import_pattern(lang_dir, pkg, cls)
        if inside is None:
            continue
        # Pick a representative kind from the modeled methods to map -> CWE.
        # Most groups have a single dominant kind; if mixed, we take the most
        # common and keep others in metadata for traceability.
        kind_counts: dict[str, int] = defaultdict(int)
        for k in methods.values():
            kind_counts[k] += 1
        dominant_kind = max(kind_counts.items(), key=lambda x: x[1])[0]
        cwe = _MAD_SOURCE_KIND_TO_CWE.get(dominant_kind, "CWE-20")
        # Build a compact, alternation-friendly method regex.
        meth_names = sorted(methods.keys())
        regex = "^(" + "|".join(re.escape(m) for m in meth_names) + ")$"
        rule_id_seed = f"codeql-{lang_dir}-{pkg}-{cls or 'top'}"
        rule_id = f"vvah.gen.source.{_slug(rule_id_seed)}"
        message = (f"CodeQL-modeled untrusted input source ({pkg}."
                   f"{cls or '<pkg-level>'}) [{dominant_kind}]")
        rule: dict = {
            "id":         rule_id,
            "languages":  list(_QL_SOURCE_LANGS[lang_dir]),
            "severity":   "INFO",
            "message":    message,
            "metadata": {
                **_source_meta(cwe, _guess_ep_kind(rule_id_seed, ""), rule_id_seed),
                "codeql_kinds":  sorted(kind_counts.keys()),
                "codeql_pkg":    pkg,
                "codeql_class":  cls,
                "vvah_gen":      True,
                "category":      "security",
            },
            "patterns": [
                {"pattern-inside": inside},
                {"pattern":        _call_pattern(lang_dir, cls)},
                {"metavariable-regex": {
                    "metavariable": "$METHOD",
                    "regex":        regex,
                }},
            ],
        }
        rules.append(rule)
    return rules


# Same shape as extract_codeql_source_rules() but filters for `sinkModel`
# rows and maps each row's `kind` slot to a CWE via _MAD_KIND_TO_CWE. Groups
# by (lang, package, class); noisy method names are dropped.
_QL_SINK_LANGS: dict[str, list[str]] = {
    "java":   ["java", "kotlin"],
    "csharp": ["csharp"],
    "go":     ["go"],
}


def extract_codeql_sink_rules(root: Path) -> list[dict]:
    """Harvest MaD `sinkModel` rows and emit one semgrep rule per
    (language, package, class) group. Import-scoped like the source
    extractor — pattern-inside requires the class's import in the target
    file, bounding false positives to same-name-different-lib cases."""
    if not root.is_dir():
        return []
    # (lang_dir, package, class) -> { method: cwe }
    groups: dict[tuple[str, str, str], dict[str, str]] = defaultdict(dict)
    for lang_dir in _QL_SINK_LANGS:
        lroot = root / lang_dir
        if not lroot.is_dir():
            continue
        for f in lroot.rglob("*.model.yml"):
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8",
                                                 errors="ignore"))
            except (OSError, yaml.YAMLError):
                continue
            for ext in (doc or {}).get("extensions") or []:
                addsto = ext.get("addsTo") or {}
                if "sink" not in str(addsto.get("extensible") or "").lower():
                    continue
                for row in ext.get("data") or []:
                    if not isinstance(row, list) or len(row) < 4:
                        continue
                    pkg = str(row[0] or "").strip()
                    cls = str(row[1] or "").strip()
                    mth = str(row[3] or "").strip()
                    kind = str(row[-2] or "").strip().lower()
                    cwe = _MAD_KIND_TO_CWE.get(kind)
                    if not pkg or not mth or not cwe:
                        continue
                    if mth in _NOISY_METHOD_NAMES:
                        continue
                    # Constructors: same-named as class — usually covered by
                    # `new $CLS(...)` patterns elsewhere.
                    if cls and mth == cls:
                        continue
                    groups[(lang_dir, pkg, cls)][mth] = cwe
    rules: list[dict] = []
    for (lang_dir, pkg, cls), methods in sorted(groups.items()):
        if not methods:
            continue
        inside = _import_pattern(lang_dir, pkg, cls)
        if inside is None:
            continue
        # Dominant CWE across all methods in this group → the rule's tag.
        cwe_counts: dict[str, int] = defaultdict(int)
        for c in methods.values():
            cwe_counts[c] += 1
        dominant_cwe = max(cwe_counts.items(), key=lambda x: x[1])[0]
        sink_kind = _guess_sink_kind(dominant_cwe)
        meth_names = sorted(methods.keys())
        regex = "^(" + "|".join(re.escape(m) for m in meth_names) + ")$"
        rule_id_seed = f"codeql-{lang_dir}-{pkg}-{cls or 'top'}"
        rule_id = f"vvah.gen.sink.{_slug(rule_id_seed)}"
        message = (f"CodeQL-modeled unsafe sink ({pkg}."
                   f"{cls or '<pkg-level>'}) [{sink_kind}]")
        sink_meta = _sink_meta(dominant_cwe, sink_kind, rule_id_seed)
        rule: dict = {
            "id":         rule_id,
            "languages":  list(_QL_SINK_LANGS[lang_dir]),
            "severity":   "INFO",
            "message":    message,
            "metadata": {
            **sink_meta,
                "codeql_cwes":   sorted(cwe_counts.keys()),
                "codeql_pkg":    pkg,
                "codeql_class":  cls,
                "vvah_gen":      True,
                "category":      "security",
            },
            "patterns": [
                {"pattern-inside": inside},
                {"pattern":        _call_pattern(lang_dir, cls)},
                {"metavariable-regex": {
                    "metavariable": "$METHOD",
                    "regex":        regex,
                }},
            ],
        }
        rules.append(rule)
    return rules


# FSB carries the largest curated JVM sink corpus we have — plain-text lists
# of JVM binary signatures grouped by injection class. Each line is
#   <pkg>/<Class>.<method>(<jvm-sig>)<ret>:<paramidx[,paramidx]>
# Constructors use `<init>`. Companion objects / inner classes carry a `$`
# in the class name (e.g. Scala `Process$`, Java `Map$Entry`).


def _fsb_sink_langs(base: str) -> list[str]:
    """Pick the semgrep languages a given injection-sinks/*.txt file targets.
    Filename convention in the FSB repo:
      - contains "kotlin" → kotlin only
      - contains "scala"  → scala only
      - everything else   → java + kotlin (JVM interop surface)
    """
    b = base.lower()
    if "kotlin" in b:
        return ["kotlin"]
    if "scala" in b:
        return ["scala"]
    return ["java", "kotlin"]


def _jvm_to_source_class(fqcn_slash: str) -> tuple[str, str, str]:
    """`java/util/Map$Entry` → ("java.util", "Map", "Map.Entry").
    Returns (package_dot, top_class, source_class).
    `$` is used both for Java inner classes and Scala companion objects — we
    treat it uniformly as an in-source dot separator, then trim any trailing
    dot (companion object `Process$` → `Process`).
    """
    parts = fqcn_slash.split("/")
    if len(parts) < 2:
        return ("", "", fqcn_slash.replace("$", ".").rstrip("."))
    pkg = ".".join(parts[:-1])
    inner = parts[-1].replace("$", ".").rstrip(".")
    top = inner.split(".")[0] if inner else ""
    return (pkg, top, inner)


def extract_findsecbugs_sink_rules(root: Path) -> list[dict]:
    """Harvest JVM sink signatures from `injection-sinks/*.txt` and emit
    import-scoped semgrep rules. Emits up to two rules per (langs, pkg,
    source_class) group — one for regular methods, one for constructors.
    """
    sink_dir = next((d for d in root.rglob("injection-sinks") if d.is_dir()),
                    None)
    if not sink_dir:
        return []
    # (langs_key, pkg, source_class) -> {"methods": {name: cwe},
    #                                    "ctors":   {"<init>": cwe}}
    groups: dict[tuple[str, str, str], dict[str, dict[str, str]]] = defaultdict(
        lambda: {"methods": {}, "ctors": {}})
    # langs_key ("java+kotlin") -> ["java", "kotlin"] for later output.
    langs_for_key: dict[str, list[str]] = {}
    for f in sorted(sink_dir.glob("*.txt")):
        base = f.stem.lower()
        meta = next((v for k, v in _FSB_MAP.items() if base.startswith(k)),
                    None)
        if not meta:
            continue
        cwe, _title = meta
        langs = _fsb_sink_langs(f.stem)
        langs_key = "+".join(langs)
        langs_for_key[langs_key] = langs
        for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith(("#", "//", "-")):
                continue
            m = _FSB_SIG_RX.match(ln)
            if not m:
                continue
            fqcn_slash = m.group(1)
            mth = m.group(2)
            if not fqcn_slash or not mth:
                continue
            pkg, _top, src_cls = _jvm_to_source_class(fqcn_slash)
            if not pkg or not src_cls:
                continue
            slot = groups[(langs_key, pkg, src_cls)]
            if mth == "<init>":
                slot["ctors"][src_cls] = cwe
            elif mth in _NOISY_METHOD_NAMES:
                continue
            else:
                slot["methods"][mth] = cwe
    rules: list[dict] = []
    for (langs_key, pkg, src_cls), slot in sorted(groups.items()):
        langs = langs_for_key[langs_key]
        # Pick a dominant CWE across both method and ctor buckets for the
        # rule-level tag; downstream Sink.cwe is unaffected either way.
        all_cwes: list[str] = list(slot["methods"].values()) + list(
            slot["ctors"].values())
        if not all_cwes:
            continue
        cwe_counts: dict[str, int] = defaultdict(int)
        for c in all_cwes:
            cwe_counts[c] += 1
        dominant_cwe = max(cwe_counts.items(), key=lambda x: x[1])[0]
        sink_kind = _guess_sink_kind(dominant_cwe)
        sink_meta = _sink_meta(dominant_cwe, sink_kind,
                               f"fsb-{langs_key}-{pkg}-{src_cls}")
        top_class = src_cls.split(".")[0]
        # Java/Kotlin: `import <pkg>.<top>;` — Scala also uses dotted imports.
        inside = f"import {pkg}.{top_class};\n...\n"
        base_meta = {
            **sink_meta,
            "fsb_cwes":   sorted(cwe_counts.keys()),
            "fsb_pkg":    pkg,
            "fsb_class":  src_cls,
            "vvah_gen":   True,
            "category":   "security",
        }
        if slot["methods"]:
            meth_names = sorted(slot["methods"].keys())
            regex = "^(" + "|".join(re.escape(m) for m in meth_names) + ")$"
            rid_seed = f"fsb-{langs_key}-{pkg}-{src_cls}-call"
            rules.append({
                "id":         f"vvah.gen.sink.{_slug(rid_seed)}",
                "languages":  list(langs),
                "severity":   "INFO",
                "message":    (f"FindSecBugs-modeled unsafe sink call "
                               f"({pkg}.{src_cls}) [{sink_kind}]"),
                "metadata":   dict(base_meta),
                "patterns": [
                    {"pattern-inside":     inside},
                    {"pattern":            "$X.$METHOD(...)"},
                    {"metavariable-regex": {"metavariable": "$METHOD",
                                            "regex":        regex}},
                ],
            })
        if slot["ctors"]:
            # Match `new <last-segment>(...)` — same-name shadowing is bounded
            # by the pattern-inside import scope.
            leaf = src_cls.split(".")[-1]
            leaf_regex = f"^{re.escape(leaf)}$"
            rid_seed = f"fsb-{langs_key}-{pkg}-{src_cls}-ctor"
            rules.append({
                "id":         f"vvah.gen.sink.{_slug(rid_seed)}",
                "languages":  list(langs),
                "severity":   "INFO",
                "message":    (f"FindSecBugs-modeled unsafe sink constructor "
                               f"({pkg}.{src_cls}) [{sink_kind}]"),
                "metadata":   dict(base_meta),
                "patterns": [
                    {"pattern-inside":     inside},
                    {"pattern":            "new $CLS(...)"},
                    {"metavariable-regex": {"metavariable": "$CLS",
                                            "regex":        leaf_regex}},
                ],
            })
    return rules


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m vvaharness.rules.build_kb",
        description="Compile local rule-corpus clones into rules/*.kb.yaml "
                    "(consumed by the s4 confirm/refute prompt).")
    for name in EXTRACTORS:
        ap.add_argument(f"--{name}", type=Path, metavar="DIR",
                        help=f"path to local {name} corpus clone")
    ap.add_argument("--out", type=Path, default=RULES_DIR,
                    help=f"output directory (default: {RULES_DIR})")
    ap.add_argument("--sources-out", type=Path, default=None, metavar="PATH",
                    help="also compile a semgrep-loadable sources.yaml file "
                         "from --semgrep taint-mode `pattern-sources:` blocks "
                         "(requires --semgrep; skipped otherwise)")
    ap.add_argument("--sinks-out", type=Path, default=None, metavar="PATH",
                    help="also compile a semgrep-loadable sinks.yaml file "
                         "from --semgrep taint-mode `pattern-sinks:` blocks "
                         "and --codeql MaD `sinkModel` rows "
                         "(requires --semgrep and/or --codeql)")
    ap.add_argument("--llm-sources-in", type=Path, default=None, metavar="PATH",
                    help="optional semgrep-style rule file from an LLM flow "
                         "to merge into --sources-out")
    ap.add_argument("--llm-sinks-in", type=Path, default=None, metavar="PATH",
                    help="optional semgrep-style rule file from an LLM flow "
                         "to merge into --sinks-out")
    ap.add_argument("--generic-out", type=Path, default=None, metavar="PATH",
                    help="write the user-facing generic CWE/OWASP starter pack "
                         "to PATH instead of requiring corpus clones")
    ap.add_argument("--llm-generic", action="store_true", default=False,
                    help="polish the generic starter pack with the low-cost "
                         "Haiku model before writing it")
    ap.add_argument("--llm-generic-via", default="sdk",
                    help="backend for --llm-generic (default: sdk)")
    ap.add_argument("--callgraph-langs", default=",".join(_CALLGRAPH_DEFAULT_LANGS),
                    help="comma-separated callgraph target languages for "
                        "sources/sinks outputs (default: python,java,"
                        "javascript,typescript,kotlin; use 'all' to disable "
                        "language filtering)")
    ap.add_argument("--strict-callgraph", action="store_true", default=True,
                    help="fail on invalid/missing callgraph metadata in "
                         "source/sink rule outputs (default: true)")
    ap.add_argument("--no-strict-callgraph", action="store_false",
                    dest="strict_callgraph",
                    help="drop invalid source/sink rules instead of failing")
    args = ap.parse_args(argv)
    callgraph_langs = _parse_lang_list(args.callgraph_langs)

    if args.generic_out is not None:
        out_p = write_generic_kb(
            args.generic_out,
            llm=args.llm_generic,
            via=args.llm_generic_via,
            model_id="claude-haiku-4-5",
        )
        print(f"  [build-kb] generic: wrote starter pack → {out_p}",
              file=sys.stderr)
        return 0

    ran = False
    for name, fn in EXTRACTORS.items():
        src = getattr(args, name)
        if not src:
            continue
        ran = True
        if not src.is_dir():
            print(f"  [build-kb] {name}: {src} is not a directory — skipped",
                  file=sys.stderr)
            continue
        entries = fn(src)
        if not entries:
            print(f"  [build-kb] {name}: 0 entries extracted from {src}",
                  file=sys.stderr)
            continue
        p = write_kb(name, entries, args.out)
        n_cwe = len({e["cwe"] for e in entries})
        print(f"  [build-kb] {name}: {len(entries)} raw → {n_cwe} CWEs → {p}",
              file=sys.stderr)
    # Optional secondary output: semgrep-format sources.yaml built from
    # (a) --semgrep taint-mode `pattern-sources:` blocks, and
    # (b) --codeql MaD `sourceModel` rows (import-scoped patterns).
    if args.sources_out is not None:
        src_rules: list[dict] = []
        if args.semgrep and args.semgrep.is_dir():
            src_rules.extend(extract_semgrep_source_rules(args.semgrep))
        elif args.semgrep:
            print(f"  [build-kb] sources: --semgrep {args.semgrep} is not a "
                  f"directory — semgrep block skipped", file=sys.stderr)
        if args.codeql and args.codeql.is_dir():
            src_rules.extend(extract_codeql_source_rules(args.codeql))
        elif args.codeql:
            print(f"  [build-kb] sources: --codeql {args.codeql} is not a "
                  f"directory — codeql block skipped", file=sys.stderr)
        if args.llm_sources_in and args.llm_sources_in.is_file():
            src_rules.extend(_load_rule_file(args.llm_sources_in))
        elif args.llm_sources_in:
            print(f"  [build-kb] sources: --llm-sources-in {args.llm_sources_in} "
                  f"is not a file — llm block skipped", file=sys.stderr)
        src_rules = _prepare_callgraph_rules(
            src_rules,
            role="source",
            callgraph_langs=callgraph_langs,
            strict=args.strict_callgraph,
        )
        if not src_rules:
            print("  [build-kb] sources: 0 rules extracted "
                  "(need --semgrep and/or --codeql pointing at a valid corpus)",
                  file=sys.stderr)
        else:
            src_prov = _artifact_provenance(
                artifact_type="sources",
                rules=src_rules,
                callgraph_langs=callgraph_langs,
                strict_callgraph=args.strict_callgraph,
                semgrep_dir=args.semgrep if args.semgrep and args.semgrep.is_dir() else None,
                codeql_dir=args.codeql if args.codeql and args.codeql.is_dir() else None,
                llm_sources_in=args.llm_sources_in if args.llm_sources_in and args.llm_sources_in.is_file() else None,
            )
            out_p = write_sources_yaml(src_rules, args.sources_out,
                                       provenance=src_prov)
            _print_rule_quality_summary(src_rules, "sources")
            langs = sorted({l for r in src_rules
                            for l in (r.get("languages") or [])})
            gen_from = []
            if args.semgrep and args.semgrep.is_dir():
                gen_from.append("semgrep")
            if args.codeql and args.codeql.is_dir():
                gen_from.append("codeql")
            print(f"  [build-kb] sources: {len(src_rules)} rules across "
                  f"{len(langs)} langs (from: {', '.join(gen_from) or 'none'}) "
                  f"→ {out_p}", file=sys.stderr)
    # Optional secondary output: semgrep-format sinks.yaml built from
    # (a) --semgrep taint-mode `pattern-sinks:` blocks, and
    # (b) --codeql MaD `sinkModel` rows (import-scoped patterns).
    if args.sinks_out is not None:
        sink_rules: list[dict] = []
        if args.semgrep and args.semgrep.is_dir():
            sink_rules.extend(extract_semgrep_sink_rules(args.semgrep))
        elif args.semgrep:
            print(f"  [build-kb] sinks: --semgrep {args.semgrep} is not a "
                  f"directory — semgrep block skipped", file=sys.stderr)
        if args.codeql and args.codeql.is_dir():
            sink_rules.extend(extract_codeql_sink_rules(args.codeql))
        elif args.codeql:
            print(f"  [build-kb] sinks: --codeql {args.codeql} is not a "
                  f"directory — codeql block skipped", file=sys.stderr)
        if args.findsecbugs and args.findsecbugs.is_dir():
            sink_rules.extend(extract_findsecbugs_sink_rules(args.findsecbugs))
        elif args.findsecbugs:
            print(f"  [build-kb] sinks: --findsecbugs {args.findsecbugs} is "
                  f"not a directory — findsecbugs block skipped",
                  file=sys.stderr)
        if args.llm_sinks_in and args.llm_sinks_in.is_file():
            sink_rules.extend(_load_rule_file(args.llm_sinks_in))
        elif args.llm_sinks_in:
            print(f"  [build-kb] sinks: --llm-sinks-in {args.llm_sinks_in} "
                  f"is not a file — llm block skipped", file=sys.stderr)
        sink_rules = _prepare_callgraph_rules(
            sink_rules,
            role="sink",
            callgraph_langs=callgraph_langs,
            strict=args.strict_callgraph,
        )
        if not sink_rules:
            print("  [build-kb] sinks: 0 rules extracted "
                  "(need --semgrep and/or --codeql pointing at a valid corpus)",
                  file=sys.stderr)
        else:
            sink_prov = _artifact_provenance(
                artifact_type="sinks",
                rules=sink_rules,
                callgraph_langs=callgraph_langs,
                strict_callgraph=args.strict_callgraph,
                semgrep_dir=args.semgrep if args.semgrep and args.semgrep.is_dir() else None,
                codeql_dir=args.codeql if args.codeql and args.codeql.is_dir() else None,
                findsecbugs_dir=(args.findsecbugs
                                 if args.findsecbugs and args.findsecbugs.is_dir()
                                 else None),
                llm_sinks_in=args.llm_sinks_in if args.llm_sinks_in and args.llm_sinks_in.is_file() else None,
            )
            out_p = write_sinks_yaml(sink_rules, args.sinks_out,
                                     provenance=sink_prov)
            _print_rule_quality_summary(sink_rules, "sinks")
            langs = sorted({l for r in sink_rules
                            for l in (r.get("languages") or [])})
            gen_from = []
            if args.semgrep and args.semgrep.is_dir():
                gen_from.append("semgrep")
            if args.codeql and args.codeql.is_dir():
                gen_from.append("codeql")
            if args.findsecbugs and args.findsecbugs.is_dir():
                gen_from.append("findsecbugs")
            print(f"  [build-kb] sinks: {len(sink_rules)} rules across "
                  f"{len(langs)} langs (from: {', '.join(gen_from) or 'none'}) "
                  f"→ {out_p}", file=sys.stderr)
    if not ran and args.sources_out is None and args.sinks_out is None:
        ap.error("provide at least one of: " +
                 " ".join(f"--{n}" for n in EXTRACTORS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
