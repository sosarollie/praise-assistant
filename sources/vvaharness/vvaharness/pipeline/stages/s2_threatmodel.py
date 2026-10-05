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
Step 2 — Application threat model.

Runs AFTER s1 and consumes its ContextPackage, so the threat model reasons
over the *actual mapped attack surface* (modules, entry points, config
representatives, API contracts) rather than a blind alphabetical file
sample. Builds an application-level threat model (assets, trust boundaries,
STRIDE-tagged threats) so every downstream step has context for *what this
system is and who attacks it*, not just *what the code looks like*.

Backend: single-shot `prompt()` (no tools) by default. Evidence is assembled
deterministically from ctx + on-disk docs/manifests and packed into one
prompt; representative config files are packed as redacted, length-capped
CONTENTS (first `step2.max_config_rep_bodies` files, `max_config_rep_chars`
each), path-only beyond that. With `step2.agentic: true` the stage calls
`agentic()` instead, giving the model a tool allowlist
(`step2.allowed_tools`, validated by the shared via-aware
`validate_detection_tools` guard) bounded by
`step2.max_turns` — output parsing is unchanged either way.

Output ThreatModel is attached to ContextPackage and read by:
  - the s3 strategist prompt (`ThreatModel.to_compact_prompt_block()`,
    called from `s3_decompose.py`'s `to_decompose_prompt_block`) — the
    ranked threat list itself, capped
  - s3 taint attribution (`_threat_for`, `s3_decompose.py:~1228`) — the full
    `threats[].surface` list, matched against each taint entry point to
    stamp a `threat_id` on taint chunks
  - s3's forced-on access-control lens (`_has_authz_surface`,
    `s3_decompose.py:~2350`) — `threats[].actor`, forcing the lens on when any
    threat names an authenticated/privileged actor
  - s3's threat-fallback chunking and coverage report
    (`_add_threat_surface_fallback_chunks`, `s3_decompose.py:~868`;
    `_report_threat_coverage`, `:~691`) — the full threat list, to guarantee
    every threat is covered by some chunk
  - s4's trust-context block (`_trust_context_block`, `s4_deepdive.py:~851`)
    — `system_context` and `trust_boundaries[:8]` only, NOT the threat list
  - s8's chain narrative and severity ranking (`s8_chain.py`) — full,
    uncapped
  - the report renderer — all fields

s6 verification does NOT read the threat model; it verifies findings produced
by the earlier analysis stages.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path, PurePosixPath

# Module import keeps the monkeypatch seam for tests.
from vvaharness.backends.llm import deepagents as _deepagents
from vvaharness.backends.llm.models import validate_detection_tools
from vvaharness.backends.llm.registry import resolve
from vvaharness.lang.hints import EXT_TO_LANG, LANG_DISPLAY
from vvaharness.models import (
    CVE,
    AppProfile,
    ContextPackage,
    Control,
    Threat,
    ThreatModel,
)
from vvaharness.pipeline.stages.s1_preprocess import _DEFAULT_EXCLUDE_DIRS
from vvaharness.pipeline.stages.s3_decompose import _SECURITY_CONFIG_NAMES
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.util.counters import COUNTERS
from vvaharness.util.json_extract import extract_json

log = logging.getLogger(__name__)

# Deterministic evidence gathering (no LLM)

# Ordered by relevance to threat modelling, not alphabetically: the first
# three are written *about* security properties, the README is written for
# users, and the changelog is the weakest signal per byte. A repo that has
# all of them competing for a shared character budget should lose the
# changelog first and the threat model doc last.
_DOC_CANDIDATES = (
    "THREAT_MODEL.md", "SECURITY.md", "ARCHITECTURE.md",
    "README.md", "README.rst", "README.txt", "README",
    "CHANGELOG.md", "CHANGELOG",
)

# Design/analysis docs that aren't named README/ARCHITECTURE but describe
# data flows the threat model needs (e.g. COBOL→Python migration write-ups).
# Matched case-insensitively against the basename of any .md/.rst in the tree.
_DOC_NAME_RX = re.compile(
    r"(analysis|architecture|design|migration|specification|spec|"
    r"threat|security|dataflow|data[_-]?flow|interface)",
    re.IGNORECASE,
)
_DOC_EXTRA_MAX = 8

_MANIFEST_CANDIDATES = (
    "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
    "setup.py", "pyproject.toml", "requirements.txt",
    "go.mod", "Cargo.toml", "Gemfile", "composer.json",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".csproj",
)

# Raw ceiling applied before structural (json/toml) parsing — generous
# enough that no realistic manifest is cut before its dependency section,
# while still bounding a pathological file. The USEFUL cap (step2's
# max_manifest_chars) is applied to the STRUCTURALLY EXTRACTED text, after
# parsing, not to this raw read.
_MANIFEST_RAW_CEILING = 500_000

# Raw ceiling for a config-rep body read (redact-before-cap — see
# `_config_rep_contents`, the canonical telling). 500k matches the manifest
# ceiling above and dwarfs the USEFUL cap (step2's max_config_rep_chars,
# 2000 by default); redaction can lengthen text — a 3-digit CVV becomes a
# 14-char `[REDACTED-CVV]` — but never by more than ~5x, so `_config_rep_
# contents` also floors the ceiling at 4x an operator-raised cap, and reads
# with `whole_or_nothing=True` so a file over THIS boundary goes path-only,
# never truncated pre-redaction — do not reintroduce a cut by dropping that flag.
_CONFIG_REP_RAW_CEILING = 500_000

_API_SURFACE_GLOBS = (
    "*openapi*.y*ml", "*openapi*.json",
    "*swagger*.y*ml", "*swagger*.json",
    "*.proto", "*.graphql", "*.graphqls",
    "*.avsc", "*.wsdl", "*.thrift",
    "*META-INF/*", "*AndroidManifest.xml",
)

_CONFIG_EXTS = {".yml", ".yaml", ".json", ".toml", ".ini",
                ".properties", ".conf", ".cfg", ".env"}

# Entry-point kind → STRIDE categories an attacker at that boundary can
# typically pursue. Used as a hint, not a constraint.
_STRIDE_BY_KIND = {
    "network":         "S T R I D E",
    "framework":       "S T R I D E",  # a framework-routed handler reachable
                                        # pre-auth (Spring @RequestMapping,
                                        # Django/Flask url-conf) faces the
                                        # same surface as "network", of which
                                        # it is a specialisation — it is not
                                        # a lesser "other" boundary.
    "ipc":             "T I E",
    "file":            "T I D",
    "cli":             "T E",
    "deserialization": "T E",
    "other":           "T I",
}

_LANG_BY_EXT = {ext: LANG_DISPLAY.get(key, key) for ext, key in EXT_TO_LANG.items()}


# Repo-kind classifier → minimum-baseline checklist (step2.baseline)

_WEB_FW_RX = re.compile(
    r"\b(spring|express|fastify|koa|hapi|nest|next|nuxt|django|flask|fastapi|"
    r"tornado|rails|sinatra|laravel|symfony|gin-gonic|echo|fiber|actix|axum|"
    r"asp\.net|ktor|micronaut|quarkus|vertx|play-framework)\b", re.IGNORECASE)

_NATIVE_LANGS = {"c", "cpp", "c++", "c-cpp", "c/c++", "rust", "objective-c", "objc"}

# Every baseline item carries a stable id (BL-<kind>-<suffix>) so a model's
# disposition of it — "I emitted a threat for this" or "I named it in
# open_questions" — is machine-checkable by matching the id, not by fuzzy
# string comparison against 60-120 character prose. See `_baseline_block`
# and `_baseline_audit`.
_BASELINES: dict[str, tuple[tuple[str, str], ...]] = {
    "web-api": (
        ("BL-WEB-A01", "OWASP A01 Broken Access Control (IDOR, path traversal, forced browsing, privilege escalation)"),
        ("BL-WEB-A02", "OWASP A02 Cryptographic Failures (weak/missing crypto, plaintext secrets/transport)"),
        ("BL-WEB-A03", "OWASP A03 Injection (SQL/NoSQL/OS/LDAP/template/header)"),
        ("BL-WEB-A04", "OWASP A04 Insecure Design (missing rate-limit, trust-boundary assumptions)"),
        ("BL-WEB-A05", "OWASP A05 Security Misconfiguration (default creds, debug on, permissive CORS)"),
        ("BL-WEB-A07", "OWASP A07 Identification & Authentication Failures (weak session, missing MFA, JWT flaws)"),
        ("BL-WEB-A08", "OWASP A08 Software & Data Integrity Failures (unsafe deserialization, unsigned updates)"),
        ("BL-WEB-A10", "OWASP A10 Server-Side Request Forgery"),
        ("BL-WEB-XSS", "XSS (reflected / stored / DOM)"),
        ("BL-WEB-CSRF", "CSRF / state-changing GET"),
    ),
    "mobile": (
        ("BL-MOB-M1", "OWASP M1 Improper Credential Usage (hardcoded keys, token leakage)"),
        ("BL-MOB-M3", "OWASP M3 Insecure Authentication/Authorization"),
        ("BL-MOB-M5", "OWASP M5 Insecure Communication (no cert pinning, cleartext traffic)"),
        ("BL-MOB-M8", "OWASP M8 Security Misconfiguration (exported components, debuggable build)"),
        ("BL-MOB-M9", "OWASP M9 Insecure Data Storage (world-readable prefs, unencrypted DB)"),
    ),
    "native": (
        ("BL-NAT-119", "CWE-119/787 Buffer overflow (stack/heap write OOB)"),
        ("BL-NAT-416", "CWE-416 Use-after-free / double-free"),
        ("BL-NAT-190", "CWE-190 Integer overflow leading to undersized allocation"),
        ("BL-NAT-134", "CWE-134 Format-string"),
        ("BL-NAT-362", "CWE-362 TOCTOU / race condition"),
        ("BL-NAT-78", "CWE-78 OS command injection via system()/exec()"),
    ),
    "iac": (
        ("BL-IAC-IAM", "Over-permissive IAM / RBAC (wildcard actions, cluster-admin bindings)"),
        ("BL-IAC-NET", "Public network exposure (0.0.0.0/0 ingress, hostNetwork, public S3/bucket)"),
        ("BL-IAC-SECRETS", "Secrets committed in plaintext / env"),
        ("BL-IAC-PRIV", "Privileged or root containers, missing securityContext"),
        ("BL-IAC-TLS", "Disabled TLS / unencrypted storage classes"),
    ),
    "library": (
        ("BL-LIB-INJ", "Injection via untrusted caller input (SQL/OS/path)"),
        ("BL-LIB-DESER", "Unsafe deserialization (pickle/yaml.load/XMLDecoder/ObjectInputStream)"),
        ("BL-LIB-PATH", "Path traversal in file-handling APIs"),
        ("BL-LIB-REDOS", "ReDoS / algorithmic-complexity DoS"),
    ),
}


def _cap_int(s2, key: str, default: int) -> int:
    """The single sanitizer every integer cap in this module reads through.

    `0` is a legitimate operator choice ("emit none of this block"), so it
    must survive rather than being treated as falsy-and-therefore-missing.
    A negative value or a non-numeric value is a config error, not an
    instruction to slice with a negative index — both fall back to
    `default` rather than propagating.
    """
    v = getattr(s2, key, None)
    if v is None:
        return default
    try:
        n = int(v)
    except (TypeError, ValueError, OverflowError):
        # OverflowError covers a YAML float infinity (`max_threats: .inf`),
        # which is a valid scalar and would otherwise crash the stage rather
        # than falling back the way a non-numeric value does.
        return default
    return n if n >= 0 else default


def _contained(root: Path, p: Path) -> Path | None:
    """Resolve `p` and confirm it stays inside `root`.

    `Path.is_relative_to` (stdlib, 3.9+) is used deliberately instead of a
    string `startswith` check: `"/repo-evil".startswith("/repo")` is True,
    so a sibling directory that merely shares a prefix with the repo root
    would pass a string check while being a completely different tree.

    Returns the resolved path (not just True/False) so a caller can log it
    without re-resolving, or None if `p` cannot be resolved at all (a
    dangling symlink) or resolves outside `root`.

    Out of scope, by design rather than by oversight: a hardlink cannot be
    detected by `resolve()`, but a hardlink cannot be committed to or cloned
    from a git repository (git stores blob content, not links) and cannot
    cross filesystems, so the untrusted-clone vector this function defends
    against cannot deliver one. A TOCTOU window between this resolve and the
    later `read_text` is likewise not addressed: this is a single local file
    read, not a multi-step privileged operation, and the race window is
    negligible.
    """
    try:
        rp = p.resolve(strict=True)
    except OSError:
        return None
    try:
        rroot = root.resolve(strict=True)
    except OSError:
        return None
    return rp if rp.is_relative_to(rroot) else None


def _cap_text(txt: str, cap_chars: int) -> str:
    if len(txt) > cap_chars:
        return txt[:cap_chars] + f"\n…(truncated, {len(txt)} chars total)"
    return txt


def _read_capped(root: Path, p: Path, cap_chars: int, *,
                 whole_or_nothing: bool = False) -> str:
    """The single chokepoint for every on-disk read this stage performs:
    containment-checked, then length-capped. A caller that wants the whole
    file for structural parsing (see `_structural_truncate`) passes a large
    ceiling here and applies its own, smarter cap afterward — it must not
    skip this function to do so, because containment is checked here and
    nowhere else.

    `whole_or_nothing=True` returns "" instead of a truncated prefix when the
    file exceeds `cap_chars`. Callers that redact the result need this
    (redact-before-cap — see `_config_rep_contents`): a read whose output is
    destined for a model must never take the truncating path.
    """
    rp = _contained(root, p)
    if rp is None:
        # recovered=True: the refusal is the containment guard working
        # exactly as designed, and the guard is UNCONDITIONAL — the same
        # default-secure, not-config-disableable host-file-disclosure policy
        # as s1's repo walk, which excludes the identical class (an in-repo
        # symlink whose target resolves off-root) from scan scope without a
        # degrading record. Off-root content is something this stage is
        # FORBIDDEN to deliver into an LLM prompt, so its absence from the
        # threat model is policy, not loss, and errlog's marking criterion is
        # satisfied without needing a backstop record. Be precise about what
        # actually reaches this branch (an earlier version of this comment
        # claimed "configs referencing an out-of-repo path", a trigger that
        # does not exist in this module): every caller feeds either s1-scoped
        # paths from ctx.all_files (escaping symlinks already excluded) or
        # `_find_manifests` hits pre-checked by `_contained`, EXCEPT the
        # fixed-name documents pass, which reads `root / name` gated only by
        # `is_file()` — so in practice this fires for a root-level document
        # (README/SECURITY/…) that is a symlink resolving outside the repo,
        # plus the negligible TOCTOU class (a scoped path deleted or
        # re-linked between s1 and this read — see `_contained`'s docstring).
        # The refused read is not invisible: the record stays in errors.jsonl
        # for diagnosis.
        _errlog.log("s2", "containment",
                    f"refused to read outside repo root: {p}",
                    reason="containment_refused", recovered=True)
        return ""
    try:
        txt = rp.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    if whole_or_nothing and len(txt) > cap_chars:
        return ""
    return _cap_text(txt, cap_chars)


def _structural_truncate(kind: str, raw: str, cap: int) -> str:
    """Keep the dependency/script section of a manifest instead of cutting a
    blind prefix, so the text that actually drives `_WEB_FW_RX` (usually a
    dependency list, not the metadata that precedes it) survives truncation.

    `pyproject.toml` is parsed with `tomllib` (stdlib), not `json.loads` — it
    is TOML, not JSON; a JSON parse raises immediately, the `except` below
    would swallow it, and `pyproject.toml` would silently get no structural
    truncation at all, which matters because it is the one format among
    these whose dependency table drives Python framework detection.

    Any parse failure, or a format this function does not recognise, falls
    back to the plain prefix cap on the raw text.
    """
    try:
        if kind in ("package.json", "composer.json"):
            data = json.loads(raw)
            if isinstance(data, dict):
                keep = {k: v for k, v in data.items()
                        if k in ("name", "version", "dependencies", "devDependencies",
                                 "peerDependencies", "require", "require-dev", "scripts")}
                if keep:
                    return _cap_text(json.dumps(keep, indent=2, sort_keys=True), cap)
        elif kind == "pyproject.toml":
            data = tomllib.loads(raw)
            keep: dict = {}
            project = data.get("project") if isinstance(data, dict) else None
            if isinstance(project, dict):
                sub = {k: v for k, v in project.items()
                       if k in ("name", "version", "dependencies", "optional-dependencies")}
                if sub:
                    keep["project"] = sub
            tool = data.get("tool") if isinstance(data, dict) else None
            poetry = tool.get("poetry") if isinstance(tool, dict) else None
            if isinstance(poetry, dict) and "dependencies" in poetry:
                keep.setdefault("tool", {}).setdefault("poetry", {})["dependencies"] = poetry["dependencies"]
            if keep:
                return _cap_text(json.dumps(keep, indent=2, sort_keys=True, default=str), cap)
    except Exception:
        pass
    return _cap_text(raw, cap)


def _apply_manifest_total_cap(manifests: list[tuple[str, str]],
                              total_cap: int) -> list[tuple[str, str]]:
    """Aggregate cap across every manifest, applied AFTER each file's own
    structural-truncation cap. Without this, a repo with ~17 manifests at
    the per-file cap (4,000 chars each) has no ceiling at all on the
    MANIFESTS block as a whole (~68,000 chars)."""
    out: list[tuple[str, str]] = []
    remaining = total_cap
    for name, text in manifests:
        if remaining <= 0:
            break
        if len(text) > remaining:
            text = _cap_text(text, remaining)
        out.append((name, text))
        remaining -= len(text)
    return out


def _find_manifests(root: Path, max_depth: int, max_total: int,
                    max_per_kind: int) -> list[tuple[str, Path]]:
    """Search for build/dependency manifests up to `max_depth` directories
    below the repo root — deep enough to cover `services/<n>/pom.xml` and
    `packages/<n>/package.json` — honouring the same directory exclusions
    s1's own repository walk uses, so a vendored dependency tree's manifest
    (`node_modules/some-pkg/package.json`) cannot masquerade as the
    project's own.

    Deduplicates by manifest KIND (the candidate name/extension) before
    path, keeping at most `max_per_kind` per kind, so many instances of one
    ecosystem's manifest (twelve `package.json` files) cannot crowd out the
    sole manifest that identifies a different ecosystem living in the same
    polyglot repo (one `pom.xml`). Selection is breadth-first across kinds
    (round-robin), capped at `max_total` overall, so kind diversity is
    preferred over depth within one kind.

    Every hit is containment-checked before being returned, and the walk
    never descends into a symlinked directory — both because this function
    itself must not become a new instance of the escape it is partly
    designed to close (the old `.csproj` search used an unbounded,
    exclusion-blind `rglob`).
    """
    hits_by_kind: dict[str, list[Path]] = {}

    def _walk(d: Path, depth: int) -> None:
        for name in _MANIFEST_CANDIDATES:
            if name.startswith("."):
                candidates = sorted(d.glob(f"*{name}"))
            else:
                candidates = [d / name]
            for p in candidates:
                if p.is_file() and _contained(root, p) is not None:
                    hits_by_kind.setdefault(name, []).append(p)
        if depth >= max_depth:
            return
        try:
            children = sorted(c for c in d.iterdir() if c.is_dir())
        except OSError:
            return
        for child in children:
            if child.name in _DEFAULT_EXCLUDE_DIRS or child.is_symlink():
                continue
            _walk(child, depth + 1)

    _walk(root, 0)

    for kind in hits_by_kind:
        hits_by_kind[kind] = hits_by_kind[kind][:max_per_kind]

    ordered_kinds = [k for k in _MANIFEST_CANDIDATES if k in hits_by_kind]
    selected: list[tuple[str, Path]] = []
    round_idx = 0
    while len(selected) < max_total:
        added = False
        for kind in ordered_kinds:
            paths = hits_by_kind[kind]
            if round_idx < len(paths):
                selected.append((kind, paths[round_idx]))
                added = True
                if len(selected) >= max_total:
                    break
        if not added:
            break
        round_idx += 1
    return selected


def _select_config_reps(full_files: list[str], max_reps: int) -> list[str]:
    """Representative configuration files, one candidate directory at a
    time, breadth-first.

    Deduplicating by TOP-LEVEL directory (the previous behaviour) collapses
    an entire monorepo to one representative, because every service under
    `services/<n>/config.yml` shares the same top-level dir ("services").
    Deduplicating by IMMEDIATE PARENT directory instead gives each service
    its own slot. Within a directory, a basename in `_SECURITY_CONFIG_NAMES`
    (imported from the s3 stage rather than duplicated) is preferred over
    an arbitrary config file, since it is far more likely to carry
    security-relevant settings. Once every directory has contributed one
    representative, a second pass lets directories with more than one
    config file contribute a second, and so on — breadth before depth,
    capped at `max_reps` overall.

    A basename in `_SECURITY_CONFIG_NAMES` is selectable even when its
    extension is absent from `_CONFIG_EXTS`. Without that clause the
    preference sort below is dead code for three quarters of the set:
    `web.xml`, `spring-security.xml`, `web.config`, `Info.plist` and the rest
    of the Java/.NET/mobile names end in `.xml`/`.config`/`.plist`, none of
    which `_CONFIG_EXTS` carries — so the canonical TLS-and-authz config of
    those stacks could never be selected at all, while the prompt header
    advertises this block as revealing TLS posture. Keying on the name set
    rather than widening `_CONFIG_EXTS` keeps the two in step by
    construction (a name added there is reachable here for free) and avoids
    pulling in unrelated `.config`/`.plist` build output.
    """
    by_dir: dict[str, list[str]] = {}
    for rel in full_files:
        p = PurePosixPath(rel)
        suffix = p.suffix.lower()
        name = p.name.lower()
        if suffix in _CONFIG_EXTS or name in _CONFIG_EXTS or name in _SECURITY_CONFIG_NAMES:
            parent = str(p.parent) if str(p.parent) != "." else ""
            by_dir.setdefault(parent, []).append(rel)

    for d in by_dir:
        by_dir[d].sort(key=lambda f: (PurePosixPath(f).name.lower() not in _SECURITY_CONFIG_NAMES, f))

    dirs = sorted(by_dir.keys())
    reps: list[str] = []
    round_idx = 0
    while len(reps) < max_reps:
        added = False
        for d in dirs:
            files = by_dir[d]
            if round_idx < len(files):
                reps.append(files[round_idx])
                added = True
                if len(reps) >= max_reps:
                    break
        if not added:
            break
        round_idx += 1
    return reps


def _config_rep_contents(root: Path, rel_paths: list[str], cap_chars: int,
                         max_bodies: int) -> list[tuple[str, str]]:
    """Pair each config representative with a redacted, length-capped body.

    The first `max_bodies` paths are read through `_read_capped` — the
    module's single containment-checked reader — with the generous
    `_CONFIG_REP_RAW_CEILING`, then passed through `report.redact`, and only
    THEN capped to `cap_chars`, because this block is the one place s2
    egresses raw config content (the very files most likely to carry
    credentials). The order is load-bearing: capping BEFORE redaction bisects
    any secret straddling the cap boundary, and the surviving prefix no
    longer matches any redaction pattern — a partial credential would egress
    under a prompt header advertising the content as redacted. Redacting the
    (near-)whole text first masks the complete secret; truncating inside a
    `[REDACTED-…]` placeholder afterward is harmless, and `_cap_text` still
    appends its truncation notice so the model knows content was cut. The
    remaining paths are kept with an empty body so the full breadth of the
    selection stays visible path-only.

    ponytail: bodies get a plain prefix cap (`max_config_rep_chars`), not the
    per-format structural extraction manifests get — upgrade path is a
    `_structural_truncate` variant for config formats if TLS/endpoint keys
    prove to be truncated away in practice.
    """
    reps: list[tuple[str, str]] = []
    # The 4x floor keeps the raw ceiling comfortably above an operator-raised
    # cap even though redaction can lengthen text (worst observed pattern,
    # CVV, lengthens ~5x on the masked span alone but far less over any
    # surrounding text).
    read_ceiling = max(_CONFIG_REP_RAW_CEILING, cap_chars * 4)
    # Which paths get a body is ranked, not positional. `rel_paths` arrives
    # breadth-first over alphabetically sorted directories, so a plain
    # `[:max_bodies]` slice hands every body slot to the directories that sort
    # first and leaves a `WEB-INF/web.xml` path-only — exactly the file the
    # prompt header promises TLS posture from. Sorting on the same key
    # `_select_config_reps` uses within a directory promotes the
    # security-relevant basenames repo-wide; the sort is stable, so breadth
    # order is preserved inside each group and the emitted order (below) is
    # still the caller's, keeping the path-only breadth view unchanged.
    with_bodies = frozenset(
        sorted(rel_paths, key=lambda r: PurePosixPath(r).name.lower() not in _SECURITY_CONFIG_NAMES)
        [: max(max_bodies, 0)]
    )
    for rel in rel_paths:
        # cap_chars == 0 means "no bodies at all" (the pre-Phase-9, path-only
        # block); without the guard `_cap_text` would emit a bare truncation
        # notice instead of an empty body.
        body = ""
        if cap_chars > 0 and rel in with_bodies:
            # redact-before-cap (see this function's docstring) is safe HERE
            # because whole_or_nothing returns the WHOLE file or "" — never a
            # truncated prefix — so redact() below always sees intact secrets.
            raw = _read_capped(root, root / rel, read_ceiling,
                               whole_or_nothing=True)
            if raw:
                body = _cap_text(redact(raw), cap_chars)
        reps.append((rel, body))
    return reps


def _repo_kind(ev: dict, ctx: ContextPackage | None) -> set[str]:
    kinds: set[str] = set()
    all_files = [f.lower() for f in (ctx.all_files if ctx else [])]
    manifest_text = "\n".join(body for _, body in ev["manifests"])

    if (any(k in ("network", "framework") for k, *_ in ev["entry_points"])
            or ev["api_artefacts"]
            or _WEB_FW_RX.search(manifest_text)):
        kinds.add("web-api")

    if (any(f.endswith(("androidmanifest.xml", "info.plist", "podfile"))
            for f in all_files)
            or re.search(r"\bcom\.android\b", manifest_text)):
        kinds.add("mobile")

    if any(f.endswith((".tf", ".hcl", "chart.yaml", "values.yaml",
                       "kustomization.yaml", "kustomization.yml"))
           for f in all_files):
        kinds.add("iac")

    langs = {(ev["primary_language"] or "").lower(),
             *(lang.lower() for lang, _ in ev["languages"])}
    if langs & _NATIVE_LANGS:
        kinds.add("native")

    return kinds or {"library"}


def _baseline_block(ev: dict, ctx: ContextPackage | None, mode: str) -> tuple[set[str], str]:
    if mode == "none":
        return set(), ""
    kinds = {"web-api"} if mode == "owasp" else _repo_kind(ev, ctx)
    seen: set[str] = set()
    items: list[tuple[str, str]] = []
    for k in sorted(kinds):
        for bid, text in _BASELINES.get(k, ()):
            if bid not in seen:
                seen.add(bid)
                items.append((bid, text))
    if not items:
        return kinds, ""
    body = "\n".join(f"  - [{bid}] {text}" for bid, text in items)
    return kinds, (
        f"\nMINIMUM BASELINE for repo kind {{{', '.join(sorted(kinds))}}} — this is "
        f"a coverage floor, not a checklist to tick. A disposition is REQUIRED for "
        f"EVERY item; silent omission is a contract violation. For each item, do "
        f"exactly one of:\n"
        f"  (a) emit a threat whose \"evidence\" starts with \"baseline: <ID>\", "
        f"setting likelihood to reflect how strongly this snapshot supports it "
        f"(\"rare\" is a perfectly good answer for a plausible-but-unconfirmed "
        f"surface). Continue the string after the id with the concrete evidence "
        f"for THIS repo — e.g. \"baseline: BL-WEB-A03; routes/search.ts builds "
        f"SQL by string concatenation\" — and give \"surface\" a real path when "
        f"one exists. Write the bare id alone only when this snapshot genuinely "
        f"offers nothing; a threat pinned to no file forfeits its guaranteed "
        f"review chunk in a later stage;\n"
        f"  (b) add an open_questions entry starting \"<ID>: \" with a one-clause "
        f"reason no matching surface exists in the evidence above.\n"
        f"You are looking at STRUCTURE, not source code, so you usually cannot rule "
        f"an item out — when in doubt, choose (a) with a low likelihood. A later "
        f"stage re-checks every threat against the real code.\n{body}\n")


_BASELINE_EVIDENCE_RX = re.compile(r"baseline:\s*(BL-[A-Z]+-\w+)")


def _baseline_audit(tm: ThreatModel, kinds: set[str]) -> set[str]:
    """Which required baseline items received neither disposition — not a
    threat with a `"baseline: <ID>"`-prefixed `evidence` string, nor an
    `open_questions` entry naming the id. Deterministic and model-free: it
    tests the checker, not the model's judgement about any one repo."""
    required = {bid for k in kinds for bid, _ in _BASELINES.get(k, ())}
    as_threat = {m.group(1) for t in tm.threats
                 if (m := _BASELINE_EVIDENCE_RX.match(t.evidence or ""))}
    as_question = {q.split(":", 1)[0].strip() for q in tm.open_questions
                   if q.startswith("BL-")}
    return required - as_threat - as_question


def _gather_evidence(repo_root: str, cfg,
                     ctx: ContextPackage | None) -> dict:
    """Assemble threat-model evidence. When `ctx` is supplied (normal path)
    the high-signal blocks come from s1's mapped surface; docs/manifests are
    still read from disk.

    Two different views of the repository feed this function, and they must
    not be confused: the AST FRONTIER (`ctx.ast_context_view(...)`, capped at
    `max_graph_files` — 220 by default) is a *sample* chosen for AST/call-
    graph relevance, while `ctx.all_files` is the FULL, s1-filtered file
    list. Blocks that are *about* the graph (MODULES, ENTRY POINTS, FUNCTION
    SITES, CALL EDGES) read the frontier — that is what makes them coherent
    with each other. Blocks that describe repo *shape* (LANGUAGE BREAKDOWN,
    COMPONENTS, config representatives, API artefacts, doc extras) read the
    full list — a monorepo with 800 files and a 220-file frontier must not
    report `top_dirs=['src']` and no config files just because the sample
    that happened to anchor the frontier lived under `src/`.
    """
    root = Path(repo_root)
    s2 = getattr(cfg, "step2", None)
    doc_cap = _cap_int(s2, "max_doc_chars", 20000)
    manifest_cap = _cap_int(s2, "max_manifest_chars", 4000)
    manifest_total_cap = _cap_int(s2, "max_manifest_total_chars", 24000)
    max_manifest_depth = _cap_int(s2, "max_manifest_depth", 3)
    max_manifests = _cap_int(s2, "max_manifests", 12)
    max_manifests_per_kind = max(1, _cap_int(s2, "max_manifests_per_kind", 2))

    max_graph_files = _cap_int(s2, "max_graph_files", 220)
    max_entry_points = _cap_int(s2, "max_entry_points", 80)
    max_graph_sinks = _cap_int(s2, "max_graph_sinks", 80)
    max_modules = _cap_int(s2, "max_modules", 40)
    max_graph_edges = _cap_int(s2, "max_graph_edges", 100)
    max_notes_chars = _cap_int(s2, "max_notes_chars", 2500)
    max_function_sites = _cap_int(s2, "max_function_sites", 80)
    max_config_reps = _cap_int(s2, "max_config_reps", 60)
    max_config_rep_chars = _cap_int(s2, "max_config_rep_chars", 2000)
    max_config_rep_bodies = _cap_int(s2, "max_config_rep_bodies", 12)
    max_api_artefacts = _cap_int(s2, "max_api_artefacts", 80)
    # Prompt caps use their OWN keys, distinct from the frontier caps
    # (max_modules / max_entry_points) read above.
    max_modules_prompt = _cap_int(s2, "max_prompt_modules", 100)
    max_entry_points_prompt = _cap_int(s2, "max_prompt_entry_points", 400)

    frontier = None
    if ctx:
        frontier = ctx.ast_context_view(
            max_files=max_graph_files,
            max_entry_points=max_entry_points,
            max_sinks=max_graph_sinks,
            max_modules=max_modules,
            max_edges=max_graph_edges,
            max_notes_chars=max_notes_chars,
        )
    active_ctx = frontier or ctx
    frontier_files = list(active_ctx.all_files) if active_ctx else []
    # Shape-derived blocks read the FULL file list, not the AST frontier
    # sample — see the docstring above.
    full_files = list(ctx.all_files) if ctx else frontier_files

    lang_counts: Counter[str] = Counter()
    for rel in full_files:
        lang = _LANG_BY_EXT.get(PurePosixPath(rel).suffix.lower())
        if lang:
            lang_counts[lang] += 1

    # ── Documents — fixed names, read straight off disk (present even in a
    #    ctx needed). Per-document sub-cap: a third of whatever budget
    #    remains, so three documents at a third each beats one document
    #    consuming the entire allowance and starving the other two — the
    #    exact failure mode of the old README-first ordering, which could
    #    exhaust `doc_cap` on the two least security-relevant documents and
    #    never even attempt to open THREAT_MODEL.md.
    docs: list[tuple[str, str]] = []
    budget = doc_cap
    found: list[tuple[str, Path]] = []
    for name in _DOC_CANDIDATES:
        p = root / name
        if p.is_file():
            found.append((name, p))

    # Pass one buys BREADTH: every document present gets a fair share, so no
    # single large file can starve the others.
    for name, p in found:
        if budget <= 0:
            break
        sub_cap = min(doc_cap, max(1000, budget // 3))
        body = _read_capped(root, p, sub_cap)
        if body:
            docs.append((name, body))
            budget -= len(body)

    # Pass two spends what pass one left over, in the same relevance order.
    # Without it a repository with a single README reads only a third of the
    # allowance and abandons the rest — so the budgeting intended to widen the
    # evidence would instead cut it by a third or more on the commonest repo
    # shape. Breadth is already secured above; this only ever grows a document
    # that was truncated, never displaces another.
    guard = 0
    while budget > 0 and guard < len(docs):
        grew = False
        for i, (name, body) in enumerate(list(docs)):
            if budget <= 0:
                break
            p = root / name
            if not p.is_file():
                continue          # an "extras" entry, handled in its own pass
            bigger = _read_capped(root, p, min(doc_cap, len(body) + budget))
            if len(bigger) > len(body):
                budget -= len(bigger) - len(body)
                docs[i] = (name, bigger)
                grew = True
        if not grew:
            break                 # every document is whole; stop re-reading
        guard += 1

    seen = {n for n, _ in docs}
    extras = sorted(
        rel for rel in full_files
        if PurePosixPath(rel).suffix.lower() in (".md", ".rst")
        and rel not in seen
        and _DOC_NAME_RX.search(PurePosixPath(rel).stem)
    )[:_DOC_EXTRA_MAX]
    if extras:
        per_cap = max(1000, budget // max(len(extras), 1)) if budget > 0 else 0
        for rel in extras:
            if budget <= 0:
                break
            body = _read_capped(root, root / rel, min(budget, per_cap))
            if body:
                docs.append((rel, body))
                budget -= len(body)

    # ── Manifests — bounded, exclusion-respecting, depth-limited walk
    #    (replaces the old root-only fixed-name checks plus an unbounded,
    #    exclusion-blind `.csproj` `rglob`), structurally truncated per
    #    format, then aggregate-capped across the whole block.
    manifests_struct: list[tuple[str, str]] = []
    for kind, p in _find_manifests(root, max_manifest_depth, max_manifests,
                                   max_manifests_per_kind):
        raw = _read_capped(root, p, _MANIFEST_RAW_CEILING)
        if not raw:
            continue
        try:
            relpath = str(p.relative_to(root)).replace("\\", "/")
        except ValueError:
            relpath = str(p)
        manifests_struct.append((relpath, _structural_truncate(kind, raw, manifest_cap)))
    manifests = _apply_manifest_total_cap(manifests_struct, manifest_total_cap)

    # Top-level component names — shape, full file list.
    top_dirs = sorted({rel.split("/", 1)[0] for rel in full_files if "/" in rel})

    # s1-mapped modules (asset candidates) and entry points (trust
    # boundaries) — these are *about the graph*, so they stay on the
    # frontier.
    modules = [(m.name, m.purpose, m.loc) for m in (active_ctx.modules if active_ctx else [])]
    eps = [(e.kind, e.reachable_from_unauth, e.file, e.function)
           for e in (active_ctx.entry_points if active_ctx else [])]
    eps.sort(key=lambda t: (t[0] != "network", not t[1], t[0], t[2]))

    function_sites: list[tuple[str, list[str], str]] = []
    if active_ctx:
        for fn, sites in list(active_ctx.call_graph_files.items())[:max_function_sites]:
            span = active_ctx.def_spans.get(fn)
            span_txt = f" lines {span[0]}-{span[1]}" if span and len(span) == 2 else ""
            function_sites.append((fn, sites[:2], span_txt))

    call_edges: list[tuple[str, str]] = []
    if active_ctx:
        for caller, callees in active_ctx.call_graph.items():
            for callee in list(dict.fromkeys(callees or [])):
                call_edges.append((caller, callee))

    # Representative config files — shape, full file list, dedup by
    # immediate parent directory (not top-level dir — see
    # `_select_config_reps`'s docstring for why that distinction matters).
    # The first `max_config_rep_bodies` carry redacted, capped CONTENTS
    # (containment-checked via `_read_capped`); the rest stay path-only.
    cfg_reps = _config_rep_contents(
        root, _select_config_reps(full_files, max_config_reps),
        max_config_rep_chars, max_config_rep_bodies)

    # API-contract artefacts (proto/openapi/graphql/…) — shape, full list.
    api_artefacts: list[str] = []
    for rel in full_files:
        for g in _API_SURFACE_GLOBS:
            if fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(rel.lower(), g):
                api_artefacts.append(rel)
                break
    api_artefacts = api_artefacts[:max_api_artefacts]

    return {
        "file_count": len(frontier_files),
        "original_file_count": len(ctx.all_files) if ctx else len(frontier_files),
        # Hot/cold/dropped-by-cap call-edge breakdown that `ast_context_view`
        # computes on every call, s2's included — surfaced here so run()'s
        # stderr diagnostic can print it under an `[s2]` label instead of the
        # method silently discarding it on this call path.
        "ast_frontier_stats": dict(frontier.ast_frontier_stats) if frontier else {},
        "primary_language": ctx.language if ctx else "",
        "languages": lang_counts.most_common(),
        "top_dirs": top_dirs,
        "modules": modules[:max_modules_prompt],
        "modules_truncated": len(modules) > max_modules_prompt,
        "entry_points": eps[:max_entry_points_prompt],
        "entry_points_truncated": len(eps) > max_entry_points_prompt,
        "function_sites": function_sites,
        "call_edges": call_edges,
        "config_reps": cfg_reps,
        "api_artefacts": api_artefacts,
        "docs": docs,
        "manifests": manifests,
        "s1_notes": getattr(ctx, "notes", "") if ctx else "",
    }


# Deterministic threat ranking (replaces positional truncation)

_IMPACT_RANK = {"existential": 5, "critical": 4, "high": 3, "medium": 2, "low": 1}
_LIKELIHOOD_RANK = {"almost_certain": 5, "likely": 4, "possible": 3, "rare": 2, "very_rare": 1}
_SENSITIVITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_ACTOR_RANK = {"remote_unauth": 6, "remote_auth": 5, "adjacent_network": 4,
              "local_admin": 3, "local_user": 2, "supply_chain": 1, "insider": 1}


def _sensitivity_of(t: Threat, tm: ThreatModel) -> int:
    key = t.asset.strip().lower()
    a = next((x for x in tm.assets if x.name.strip().lower() == key), None)
    return _SENSITIVITY_RANK.get(a.sensitivity, 0) if a else 0


def _rank_key(t: Threat, tm: ThreatModel):
    """Deterministic total order, most severe first.

    The sensitivity term is the one part of PASTA worth adopting here:
    risk-centric weighting by business impact, at zero prompt cost, using
    `Asset.sensitivity` data s2 already computes (and already forces to
    "critical" for PCI/PAN/PII app profiles). No `evidence != ""` term is
    included deliberately — the baseline disposition convention means the
    weakest, unconfirmed checklist threats also carry non-empty evidence, so
    rewarding non-empty evidence would boost them the same as a threat with
    real CVE backing.
    """
    return (-_IMPACT_RANK.get(t.impact, 0),
            -_sensitivity_of(t, tm),
            -_LIKELIHOOD_RANK.get(t.likelihood, 0),
            -_ACTOR_RANK.get(t.actor, 0),
            0 if (not t.controls or t.controls == "none") else 1,
            _id_ordinal(t.id),
            t.id)


def _id_ordinal(threat_id: str) -> int:
    """Numeric part of an id like `T7`, for a stable tiebreak.

    `str.isdigit()` is true for characters `int()` cannot parse — superscripts
    and other Unicode digit forms — so the conversion is guarded rather than
    predicated. This runs on every call, truncating or not, so an unparseable
    id must not be able to take the whole stage down: one odd character in one
    id would otherwise discard a fully parsed threat model.
    """
    try:
        return int(threat_id[1:])
    except (TypeError, ValueError):
        return 1_000_000


def _covered_boundaries(threats: list[Threat], pool: set[int],
                        boundaries: list) -> set[str]:
    """Which boundaries have at least one covering threat in `pool`.

    `pool` holds positions into `threats`, not ids. A model can emit several
    threats sharing one id, and keying this on id would make those threats
    indistinguishable — collapsing them into a single entry and discarding the
    rest.
    """
    covered: set[str] = set()
    for b in boundaries:
        bnorm = b.entry_point.strip().casefold()
        for i in pool:
            if threats[i].surface.strip().casefold() == bnorm:
                covered.add(b.entry_point)
                break
    return covered


def _cap_threats(tm: ThreatModel, max_threats: int) -> ThreatModel:
    """Sort deterministically (permuting only — `id` is never rewritten, so
    `T7` keeps meaning `T7` for coverage reporting and cross-version
    comparison), then truncate to `max_threats` while preserving every trust
    boundary's sole coverage: if truncation would drop the only threat
    covering some boundary, the best-ranked dropped threat that covers it is
    promoted back, evicting the lowest-ranked kept threat whose removal
    would not itself uncover a boundary.

    No deduplication of any kind is performed — measured across 121 real
    threats from five models, the dedup predicate this stage used to run
    produced zero merges; real near-duplicates diverge on `surface` (the
    STRIDE walk runs per trust boundary) and land far below any reasonable
    similarity threshold. The only input that ever tripped the predicate was
    one where merging was actively wrong: it erased the per-category
    coverage the prompt requires.
    """
    threats = sorted(tm.threats, key=lambda t: _rank_key(t, tm))
    COUNTERS.bump("s2_threats_raw", len(threats))
    if len(threats) <= max_threats:
        return tm.model_copy(update={"threats": threats})

    # Everything below addresses threats by POSITION in the ranked list, never
    # by `id`. Ids are model-supplied and are not guaranteed unique: a weaker
    # model emitting thirty threats all labelled "T1" is a routine failure, and
    # an id-keyed set would treat them as one threat and silently return a
    # single result from a cap of twenty.
    kept: set[int] = set(range(min(max_threats, len(threats))))
    evicted_idx = list(range(len(kept), len(threats)))  # rank-ordered, best first
    truncated_n = len(evicted_idx)

    all_boundary_names = {b.entry_point for b in tm.trust_boundaries}
    uncovered = all_boundary_names - _covered_boundaries(
        threats, kept, tm.trust_boundaries)

    kept_order = sorted(kept)  # rank order; worst-ranked is last
    promoted = 0
    progressed = True
    while uncovered and progressed:
        progressed = False
        for boundary in list(uncovered):
            bnorm = boundary.strip().casefold()
            candidate = next(
                (i for i in evicted_idx
                 if i not in kept and threats[i].surface.strip().casefold() == bnorm),
                None,
            )
            if candidate is None:
                continue
            current_coverage = _covered_boundaries(threats, kept, tm.trust_boundaries)
            evict_at = None
            for i in reversed(kept_order):  # worst-ranked survivor first
                trial_coverage = _covered_boundaries(
                    threats, kept - {i}, tm.trust_boundaries)
                if len(trial_coverage) >= len(current_coverage):
                    evict_at = i
                    break
            if evict_at is None:
                continue  # every survivor is a sole cover — cannot evict safely
            kept.discard(evict_at)
            kept_order.remove(evict_at)
            kept.add(candidate)
            kept_order.append(candidate)
            promoted += 1
            uncovered.discard(boundary)
            progressed = True

    COUNTERS.bump("s2_threats_truncated", truncated_n)
    COUNTERS.bump("s2_threats_promoted", promoted)
    final = [threats[i] for i in sorted(kept)]  # already rank-ordered
    return tm.model_copy(update={"threats": final})


def _cap_assets(tm: ThreatModel, max_assets: int) -> ThreatModel:
    if len(tm.assets) <= max_assets:
        return tm
    ranked = sorted(tm.assets,
                    key=lambda a: (-_SENSITIVITY_RANK.get(a.sensitivity, 0), a.name))
    return tm.model_copy(update={"assets": ranked[:max_assets]})


def _cap_boundaries(tm: ThreatModel, max_boundaries: int) -> ThreatModel:
    if len(tm.trust_boundaries) <= max_boundaries:
        return tm
    ranked = sorted(tm.trust_boundaries,
                    key=lambda b: (-len(b.reachable_assets), b.entry_point))
    return tm.model_copy(update={"trust_boundaries": ranked[:max_boundaries]})


# Prompt

SYSTEM = """\
You are an application-security threat modeler. You receive a STRUCTURAL
snapshot of a codebase — docs, manifests, the component list, the
agentically-mapped MODULES (purpose-tagged) and ENTRY POINTS (kind +
auth-reachability), representative CONFIG files, and API-contract artefacts —
NOT the source code bodies. From this you produce a threat model: what the
system IS, what it PROTECTS, where untrusted input ENTERS, and what an
attacker would TRY.

A threat survives a patch. "Heap overflow in parser.c:412" is a vulnerability;
"RCE via untrusted media parsing" is a threat. You produce threats.

Work through these stages:

1. SYSTEM CONTEXT — from docs/manifests/tree: what is this application, what
   does it do, who runs it, where (service / CLI / library / batch job)?

2. ASSETS — what does it protect or produce? Data (PII, payment data, secrets,
   credentials), process integrity, service availability, downstream consumers.
   Assign sensitivity: low|medium|high|critical.

3. TRUST BOUNDARIES — every place untrusted input enters or privilege changes.
   Derive from manifests, framework hints in the tree, and docs. Include
   supply-chain and infra/IAM surfaces. Name the crossing
   ("unauth network → application logic", "tenant A → shared DB").

4. THREATS — for EACH trust boundary, walk STRIDE (Spoofing, Tampering,
   Repudiation, Info-disclosure, DoS, Elevation) and emit the plausible ones.
   Use prior CVEs as EVIDENCE that raises likelihood; design controls LOWER it.
   Score impact (low|medium|high|critical|existential) and likelihood
   (very_rare|rare|possible|likely|almost_certain). Assign ids T1, T2, … in the
   order you emit them; ordering does not matter — the caller ranks
   deterministically. Do NOT drop a threat because you are unsure: a plausible
   threat with likelihood "rare" is useful, a missing threat is not. Downstream
   stages re-check every threat against the real source code and discard the ones
   that do not hold up.

5. OPEN QUESTIONS — things the snapshot can't tell you (deployment exposure,
   upstream WAF, who supplies inputs, risk appetite).

Respond with ONLY a JSON object — no prose, no markdown fences:
{
  "system_context": "1-3 paragraphs",
  "assets": [{"name":"str","description":"str","sensitivity":"low|medium|high|critical"}],
  "trust_boundaries": [{"entry_point":"str","crossing":"str","reachable_assets":["asset name"]}],
  "threats": [{"id":"T1","threat":"one sentence, names the outcome",
               "actor":"remote_unauth|remote_auth|adjacent_network|local_user|local_admin|supply_chain|insider",
               "surface":"entry_point name from trust_boundaries",
               "asset":"asset name",
               "impact":"low|medium|high|critical|existential",
               "likelihood":"very_rare|rare|possible|likely|almost_certain",
               "controls":"current mitigations or 'none'",
               "evidence":"CVE ids / commit hashes or ''"}],
  "open_questions": ["str"]
}

Every element of "assets", "trust_boundaries" and "threats" MUST be an object
carrying the keys shown above — never a bare string. A bare string where an
object is required fails schema validation and discards the ENTIRE response;
it is the one malformation observed to do so in production runs.

Coverage rules:
  - Every trust_boundary MUST appear as the surface of ≥1 threat.
  - Every MINIMUM BASELINE item, if any are supplied, MUST be either the basis of
    a threat (with "evidence" starting "baseline: <ID>") or named in
    open_questions with a one-clause reason. Never drop a baseline item without a
    written trace."""


def _build_user_prompt(repo_name: str, ev: dict,
                       cves: list[CVE], controls: list[Control],
                       app_profile: AppProfile | None = None,
                       baseline_block: str = "") -> str:
    lang_block = "\n".join(f"  - {lang}: {n} files" for lang, n in ev["languages"]) \
                 or "  (none detected)"
    comp_block = "\n".join(f"  - {d}/" for d in ev["top_dirs"]) \
                 or "  (flat repo)"

    mod_block = "\n".join(
        f"  - {name}  ({loc} LOC) — {purpose}"
        for name, purpose, loc in ev["modules"]
    ) or "  (s1 emitted no modules)"
    if ev["modules_truncated"]:
        mod_block += "\n  …(truncated)"

    ep_block = "\n".join(
        f"  - [{kind:<14}] {'UNAUTH' if unauth else 'auth  '}  "
        f"STRIDE:{_STRIDE_BY_KIND.get(kind, 'T I')}  "
        f"{file}::{func}"
        for kind, unauth, file, func in ev["entry_points"]
    ) or "  (s1 emitted no entry points)"
    if ev["entry_points_truncated"]:
        ep_block += "\n  …(truncated)"

    site_block = "\n".join(
        f"  - {fn} @ {', '.join(sites)}{span_txt}"
        for fn, sites, span_txt in ev["function_sites"]
    ) or "  (none)"

    edge_block = "\n".join(
        f"  - {caller} -> {callee}" for caller, callee in ev["call_edges"]
    ) or "  (none)"

    # A representative that was read gets a per-file header + redacted body;
    # one beyond `max_config_rep_bodies` (or that failed containment/read)
    # stays a bare path bullet.
    cfg_block = "\n".join(f"  === {rel} ===\n{body}" if body else f"  - {rel}"
                          for rel, body in ev["config_reps"]) \
                or "  (none)"
    api_block = "\n".join(f"  - {p}" for p in ev["api_artefacts"]) \
                or "  (none)"

    docs_block = "\n\n".join(
        f"=== {name} ===\n{body}" for name, body in ev["docs"]
    ) or "(no README / SECURITY / ARCHITECTURE docs found)"
    manifest_block = "\n\n".join(
        f"=== {name} ===\n{body}" for name, body in ev["manifests"]
    ) or "(no build/dependency manifests found)"
    cve_block = "\n".join(
        f"  - {c.id} (CVSS {c.cvss}, {'patched' if c.patched else 'UNPATCHED'}): {c.summary}"
        for c in cves
    ) or "  (none on file)"
    ctl_block = "\n".join(
        f"  - [{c.kind}] {c.name} → protects: {', '.join(c.protects) or 'global'}"
        + (f" — {c.notes}" if c.notes else "")
        for c in controls
    ) or "  (none on file)"

    cmdb_block = ""
    if app_profile:
        cmdb_block = (app_profile.to_prompt_block()
                      + "\n  → Use externally_facing to set default actor "
                        "(remote_unauth only if YES; otherwise adjacent_network/"
                        "remote_auth). Use PCI/PAN/PII flags to set asset "
                        "sensitivity = critical.\n\n")

    notes_block = ""
    if ev["s1_notes"]:
        notes_block = f"\nMAPPER OBSERVATIONS (s1 free-form):\n{ev['s1_notes']}\n"

    # Block order is non-increasing staticness across scan re-runs of the
    # SAME repo: the baseline/CMDB/shape blocks below
    # are the same for every run against this repo; the AST-frontier blocks
    # at the bottom are the most likely to shift between runs as the mapped
    # call graph changes. `repo_root` (an absolute host path) is deliberately
    # NOT rendered anywhere — it tells the model nothing `repo_name` does
    # not, and it was the single biggest obstacle to a stable cross-run
    # prefix.
    return f"""{baseline_block}{cmdb_block}LANGUAGE BREAKDOWN:
{lang_block}

COMPONENTS (top-level directories):
{comp_block}

REPRESENTATIVE CONFIGURATION (one per component, post-dedup — entries under a
"=== path ===" header carry redacted, length-capped file contents revealing
data stores, message buses, key/secret managers, TLS posture, external
endpoints; entries listed as "- path" are present by name only):
{cfg_block}

API CONTRACT ARTEFACTS (OpenAPI/Swagger/Protobuf/GraphQL/WSDL/META-INF — the
explicit external interface):
{api_block}

DOCUMENTATION:
{docs_block}

BUILD / DEPENDENCY MANIFESTS:
{manifest_block}

KNOWN PRIOR CVEs (use as evidence; raises likelihood):
{cve_block}

DESIGN CONTROLS (lower likelihood where they apply):
{ctl_block}

TARGET: {repo_name}
PRIMARY LANGUAGE: {ev['primary_language'] or 'unknown'}
FILES IN AST FRONTIER: {ev['file_count']} (from {ev['original_file_count']} total in-scope files)

MODULES (s1-mapped — treat as asset candidates):
{mod_block}

ENTRY POINTS (s1-mapped — these ARE the trust boundaries; STRIDE hint per kind):
{ep_block}

AST FUNCTION SITES (method-level anchors chosen from entry-point/sink/callgraph frontier):
{site_block}

AST CALL EDGES (bounded frontier, one edge per line):
{edge_block}
{notes_block}
Produce the threat model JSON now. Anchor each trust_boundary.entry_point to
one of the ENTRY POINTS above where possible; use the STRIDE hint to seed
threats per boundary."""


def _parse_threat_model(raw: str) -> ThreatModel:
    """Extraction and schema validation as ONE step, because a benchmarked
    failure population showed shape errors dominating syntax errors: in the
    observed parse failures the response was syntactically valid JSON whose
    `assets` items were bare strings, which sails through `extract_json` and
    dies in `model_validate`. A repair path that only guarded the JSON decode
    would have recovered the minority failure and missed the majority one."""
    data = extract_json(raw)
    # Envelope check between the two steps. Every ThreatModel field defaults,
    # so `model_validate` accepts ANY dict — and a truncated response whose
    # outer object never closes can still contain a smaller balanced object
    # (a single asset, say) that `extract_json` dutifully returns. Without
    # this check that sub-object "validates" into an all-empty ThreatModel:
    # the exact empty-but-present outcome the error handling below exists to
    # prevent. A literal `{}` (no keys at all) stays accepted — that is the
    # model's established way of reporting "nothing plausible here", pinned
    # by an existing test — but a non-empty dict sharing NO keys with the
    # schema is some other object entirely, not an empty threat model.
    if isinstance(data, dict) and data \
            and not (data.keys() & ThreatModel.model_fields.keys()):
        raise ValueError(
            "extracted JSON object has none of the threat-model fields "
            f"(got keys: {sorted(data.keys())[:8]}) — likely a sub-object "
            "of a truncated or malformed response")
    return ThreatModel.model_validate(data)


def _repair_json_prompt(raw: str, err: Exception) -> str:
    """One-shot repair prompt, modelled on s4's `_repair_json_prompt`
    (`s4_deepdive.py`), with two deliberate differences: the error may be a
    Pydantic ValidationError, not just a JSONDecodeError, so the instruction
    covers schema shape and not merely syntax; and it names the concretely
    observed malformation (a bare string where an object is required) because
    that is what production failures actually look like. The prompt forbids
    inventing content — repair converts what the model already said into the
    required shape, it must not become a second chance to hallucinate."""
    return f"""REPAIR TASK:
The previous threat-model response failed to parse against the required
schema. Return ONLY a corrected JSON object that (a) is syntactically valid
JSON and (b) matches the schema in the system prompt exactly — in particular,
every element of "assets", "trust_boundaries" and "threats" must be an object
with the keys shown there, never a bare string. Preserve the original content
faithfully: do not add, remove, or reword any asset, boundary, or threat
beyond what restructuring requires.

PARSE/VALIDATION ERROR:
{type(err).__name__}: {err}

BROKEN RESPONSE:
{raw}
"""


# Agentic dispatch (step2.agentic, default false — ships dark)

#: The ONE line added to SYSTEM when agentic is on: the model may now open
#: the config files the baseline evidence lists by name.
_AGENTIC_SYSTEM_LINE = (
    "\n\nYou have read-only tools (Read, Glob, Grep): you may open the "
    "configuration files listed by path in the evidence — and any other "
    "repository file — to confirm details before emitting the JSON."
)


def _threatmodel_call(user: str, cfg: object, repo_root: str) -> str:
    """Issue the primary threat-model completion.

    `step2.agentic: false` (the default) preserves today's single-shot
    `prompt()`-shaped call byte-for-byte — `dispatch_prompt` forwards a
    non-deepagents role to `registry.prompt` with these exact kwargs. When
    true, the stage swaps to the `agentic()` shape with a validated tool
    allowlist and a `max_turns` bound — deliberately NOT `max_tokens`: each
    route applies its own output ceiling (per-turn `AGENTIC_MAX_TOKENS`, 16k,
    on `via: sdk`/`openai` AND on `via: deepagents`, where the agentic()
    construction site pins the same constant through `CapOutputTokens`; the
    CLI's own default on `via: cli`), and a
    ≈6–9k-token threat model fits every one of them. NOT
    `temperature`/`thinking_budget` either (`registry.agentic()` discards
    extras). `max_budget_usd` is likewise not passed: it is a no-op on
    `sdk`/`openai`, so `max_turns` is the only real bound and the only one
    advertised.

    Both shapes route through the deepagents dispatch seam, which is the ONE
    place that branches on the resolved via: `deepagents` reaches the harness
    (whose `agentic()` is implemented — the old use-site guard rejecting
    `step2.agentic: true` on that route predates it and is gone), anything
    else reaches the registry exactly as before.
    """
    s2 = getattr(cfg, "step2", None)
    if getattr(s2, "agentic", False):
        return _deepagents.dispatch_agentic(
            user,
            model=cfg.models.threatmodel,
            cfg=cfg,
            system_prompt=SYSTEM + _AGENTIC_SYSTEM_LINE,
            # The shared detection-stage guard (`validate_detection_tools`,
            # beside `DEFAULT_READ_TOOLS`), threaded the resolved via exactly
            # as s1/s6 do: `via: cli` honours the allowlist verbatim (Bash
            # there is a shipped capability); every other via stays read-only.
            allowed_tools=validate_detection_tools(
                getattr(s2, "allowed_tools", None),
                config_key="step2.allowed_tools",
                via=resolve(cfg.models.threatmodel).via),
            cwd=repo_root,
            max_turns=_cap_int(s2, "max_turns", 12),
            tag="s2 threatmodel",
        )
    return _deepagents.dispatch_prompt(
        user,
        model=cfg.models.threatmodel,
        cfg=cfg,
        cwd=repo_root,
        system_prompt=SYSTEM,
        max_tokens=getattr(s2, "max_tokens", 16000),
        timeout=_cap_int(s2, "timeout", 1800),
        tag="s2 threatmodel",
    )


# Entry point

def run(repo_root: str, repo_name: str, cfg,
        known_cves: list[CVE], controls: list[Control],
        ctx: ContextPackage | None = None,
        app_profile: AppProfile | None = None) -> ThreatModel:
    s2 = getattr(cfg, "step2", None)
    tracker = getattr(cfg, "_scan_progress", None)
    log.info("s2/threatmodel: starting threat modeling for %s", repo_name)
    if ctx is not None:
        print(
            "  [s2] ctx: "
            f"type={type(ctx).__module__}.{type(ctx).__name__}, "
            f"has_ast_context_view={hasattr(ctx, 'ast_context_view')}, "
            f"all_files={len(getattr(ctx, 'all_files', []) or [])}",
            file=sys.stderr,
        )
        log.debug("s2/threatmodel: context has_ast_view=%s files=%d",
                  hasattr(ctx, 'ast_context_view'), len(getattr(ctx, 'all_files', []) or []))
    ev = _gather_evidence(repo_root, cfg, ctx)
    if tracker is not None:
        tracker.stage_note(
            "s2",
            (f"evidence files={ev['file_count']} modules={len(ev['modules'])} "
             f"eps={len(ev['entry_points'])} api={len(ev['api_artefacts'])}"),
        )
    print(f"  [s2] evidence: {ev['file_count']} files, "
          f"{len(ev['modules'])} modules, {len(ev['entry_points'])} entry points, "
          f"{len(ev['config_reps'])} config reps, "
          f"{len(ev['api_artefacts'])} api artefacts, "
          f"{len(ev['docs'])} docs, {len(ev['manifests'])} manifests",
          file=sys.stderr)
    print(f"  [s2] frontier: {ev['file_count']} / {ev['original_file_count']} files "
          f"(AST-focused evidence view)", file=sys.stderr)
    fs = ev["ast_frontier_stats"]
    if fs:
        print(f"  [s2] call-edge frontier: kept={fs.get('edges_kept', 0)}/"
              f"{fs.get('edges_total', 0)} hot={fs.get('hot', 0)} "
              f"cold={fs.get('cold', 0)} dropped_by_cap={fs.get('dropped_by_cap', 0)}",
              file=sys.stderr)

    baseline_mode = getattr(s2, "baseline", "auto")
    kinds, baseline = _baseline_block(ev, ctx, baseline_mode)
    COUNTERS.note("s2_repo_kinds", ",".join(sorted(kinds)))
    print(f"  [s2] baseline={baseline_mode} repo_kind={sorted(kinds) or '-'}",
          file=sys.stderr)

    user = _build_user_prompt(repo_name, ev, known_cves, controls,
                              app_profile=app_profile,
                              baseline_block=baseline)
    if tracker is not None:
        tracker.stage_note("s2", "threat-model LLM request started")

    try:
        raw = _threatmodel_call(user, cfg, repo_root)
    except Exception as e:
        # Record here for stage-level granularity, then re-raise. The
        # orchestrator already wraps this call, marks the stage failed and
        # continues with no threat model, and every later stage handles its
        # absence. Swallowing the error instead would report a failed provider
        # call as a successful stage that merely found nothing, and would hand
        # downstream an empty-but-present model — which renders as a hollow
        # threat-model block in later prompts rather than being skipped.
        print(f"  [s2] ERROR: threat-model call failed ({e})",
              file=sys.stderr)
        _errlog.log("s2", repo_name, e, reason="threat_model_call_failed")
        raise
    if tracker is not None:
        tracker.stage_note("s2", "threat-model LLM response received")

    try:
        tm = _parse_threat_model(raw)
    except Exception as parse_err:
        # ONE bounded repair retry, following s4's existing pattern. Benchmark
        # runs lose the entire threat model — and with it s3/s4 threat-derived
        # targeting — to a single malformed response, most often a schema-shape
        # slip (`assets` items emitted as bare strings) that the model itself
        # can trivially restructure. The retry reuses the operator's configured
        # step2 caps rather than its own: a repair must re-emit the full model,
        # so a smaller budget (s4 clamps to 12k for its per-chunk findings)
        # would turn a recoverable shape error into a real truncation.
        print(f"  [s2] threat-model response did not parse, retrying repair "
              f"— {parse_err}", file=sys.stderr)
        # Deliberately NOT errlogged here. `counts_by_stage()` feeds both
        # run_manifest.json's `errors_by_stage` and the report's, and any CI gate
        # or dashboard reading a non-zero s2 count treats the threat model as
        # degraded. A slip the retry recovers perfectly is a HEALTHY scan, so
        # logging the first attempt unconditionally would false-alarm on it — and
        # would also make every before/after comparison show a fabricated error
        # delta. The attempt stays visible through `s2_parse_repair_attempted`,
        # which the manifest now dumps in full; only a genuine, permanent failure
        # writes an errlog record, and it does so once, below.
        COUNTERS.bump("s2_parse_repair_attempted")
        repaired = None
        try:
            # The retry goes through the same dispatch seam as the primary
            # call: a deepagents role's repair must reach the harness too —
            # the registry has no deepagents backend, so falling back to
            # registry.prompt would raise `Unknown backend` instead of
            # repairing.
            repaired = _deepagents.dispatch_prompt(
                _repair_json_prompt(raw, parse_err),
                model=cfg.models.threatmodel,
                cfg=cfg,
                cwd=repo_root,
                system_prompt=SYSTEM,
                max_tokens=getattr(s2, "max_tokens", 16000),
                timeout=_cap_int(s2, "timeout", 1800),
                tag="s2 threatmodel json-repair",
            )
            tm = _parse_threat_model(repaired)
        except Exception as e:
            # Second failure gives up cleanly: an unparseable response means
            # there is no threat model, which is not the same thing as a model
            # that found nothing. The raise reaches the orchestrator, which
            # bumps `s2_degraded` (rendered as "Threat model: **degraded**" in
            # the report) and continues without threat context.
            print(f"  [s2] ERROR: threat-model response did not parse ({e})",
                  file=sys.stderr)
            # Head of whichever text the FINAL attempt tried to parse; when
            # the repair call itself failed (provider error) that is still the
            # original response, the only model output there is to show.
            # redact() the FULL text BEFORE the [:500] cut — errlog redacts
            # its string fields internally, but only after receiving them
            # (redact-before-cap — see `_config_rep_contents`).
            _errlog.log("s2", repo_name, e,
                        reason="threat_model_parse_failed",
                        raw_head=redact((repaired if repaired is not None
                                         else raw) or "")[:500],
                        note="s2 JSON extraction or model validation failed "
                             "after one repair retry; s3–s8 will receive no "
                             "threat context")
            raise
        COUNTERS.bump("s2_parse_repair_recovered")
        print("  [s2] repair retry recovered a valid threat model",
              file=sys.stderr)

    if not tm.threats:                    # success path, not inside an except —
        # DELIBERATELY UNMARKED (no recovered=True): this record flips s2 to
        # completed_with_errors even when the emptiness is legitimate, and
        # that is the intended trade. Zero threats is a real downstream
        # capability loss — the message below is a loss statement, not a
        # diagnostic — and this record is the only structural signal
        # separating a vacuous-but-parseable model reply from a healthy run.
        # Stamping it would close s2 plain "completed" on a model that
        # silently produced nothing: the silent-degradation defect
        # again. (An earlier comment here said an empty scan "must not be
        # treated as an error"; it justified not RAISING and predates the
        # outcome predicate — the stage still completes, it just does not
        # complete clean.)
        _errlog.log(
            "s2", "threatmodel",
            "zero threats — downstream attribution, threat-surface fallback "
            "and the access-control specialist force-on are all disabled",
        )

    # The baseline audit runs BEFORE the cap, against what the model actually
    # emitted. Baseline dispositions are deliberately low-likelihood, so they
    # rank last and are the first thing truncation removes — auditing after the
    # cap would report a fully compliant model as being in breach, and blame it
    # for the harness's own truncation.
    undisposed = _baseline_audit(tm, kinds)

    max_threats = _cap_int(s2, "max_threats", 20)
    tm = _cap_threats(tm, max_threats)
    tm = _cap_assets(tm, _cap_int(s2, "max_assets", 40))
    tm = _cap_boundaries(tm, _cap_int(s2, "max_trust_boundaries", 60))

    # A count tells an operator nothing actionable; the ids themselves do.
    COUNTERS.note("s2_baseline_undisposed", ",".join(sorted(undisposed)))
    if undisposed:
        # DELIBERATELY UNMARKED (no recovered=True): an undisposed baseline
        # item is a genuine deliverable gap, not an informational diagnostic —
        # s3 consumes baseline-disposition threats for chunk targeting, so
        # every mandated checklist category left undisposed loses its
        # threat-derived guidance downstream. The fail-safe default (unmarked
        # counts) therefore stands; revisit only if this fires routinely on
        # healthy scans.
        _errlog.log("s2", repo_name, "baseline items undisposed",
                    reason="baseline_items_undisposed",
                    baseline_ids=sorted(undisposed))
        print(f"  [s2] WARN: {len(undisposed)} baseline item(s) undisposed: "
              f"{sorted(undisposed)}", file=sys.stderr)

    print(f"  [s2] done: {len(tm.assets)} assets, "
          f"{len(tm.trust_boundaries)} trust boundaries, "
          f"{len(tm.threats)} threats", file=sys.stderr)
    log.info("s2/threatmodel: threat model complete - assets=%d boundaries=%d threats=%d",
             len(tm.assets), len(tm.trust_boundaries), len(tm.threats))
    return tm
