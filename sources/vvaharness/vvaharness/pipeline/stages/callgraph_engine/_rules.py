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

"""Convert `sources.generated.yaml` / `sinks.generated.yaml` (semgrep-format
rule files, but with rich `metadata.*` fields we can read directly) into
structured :class:`MatchSpec` records the tree-sitter scanner can use.

Two match categories per rule:
    * ``qualified`` — package + class + method-set   (CodeQL / FSB origins)
    * ``module_attr`` — best-effort parse of a semgrep call-shape pattern
      like ``pickle.loads(...)`` or ``os.system(...)``   (semgrep origin)

Rules whose patterns are too complex for this translator (regex-only bodies,
nested pattern-either trees, etc.) are omitted from the callgraph engine's
view; simplify or pre-compile those patterns before using them as S0 inputs.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from vvaharness.rules.families import (
    OWASP_2025_BY_SEMANTIC as _OWASP_2025_BY_SEMANTIC,
)
from vvaharness.rules.families import (
    resolve_semantic_family as _resolve_semantic_family,
)

# The YAML `languages:` field uses semgrep's language keys, which are 1:1 with
# vvaharness language keys for the six we support today. Kept as a table so
# any future divergence lives in exactly one place.
_SEMGREP_TO_VVAH: dict[str, str] = {
    "python":     "python",
    "java":       "java",
    "javascript": "javascript",
    "typescript": "typescript",
    "go":         "go",
    "csharp":     "csharp",
    "kotlin":     "kotlin",
    "scala":      "scala",
    "ruby":       "ruby",
    "php":        "php",
    "c":          "c-cpp",
    "cpp":        "c-cpp",
}


@dataclass(frozen=True)
class MatchSpec:
    """A single API pattern the scanner can look for."""
    rule_id: str
    role: str                              # "source" | "sink"
    origin: str                            # "semgrep" | "codeql" | "fsb"
    cwe: str
    kind: str                              # ep_kind (sources) / sink_kind (sinks)
    languages: frozenset[str]              # vvaharness language keys
    semantic_family: str = ""              # Iteration B semantic sink/source class
    owasp_top10_2025: frozenset[str] = field(default_factory=frozenset)

    # STRUCTURED match (codeql / fsb): match a call whose receiver's static
    # type is `class_name` (which is imported from `package`) AND whose
    # method is in `methods` (regex-alternation). Optional constructor form:
    # `is_constructor=True` matches `new <leaf_class>(...)`.
    package: str = ""
    class_name: str = ""                   # source-form (may contain '.')
    top_class: str = ""                    # top segment for import matching
    methods: frozenset[str] = field(default_factory=frozenset)
    is_constructor: bool = False

    # SEMGREP-LIFTED module-attribute match: a call of the form
    # `<module>.<attr>(...)` where `<module>` is one of these names (bare
    # first-segment). Attrs are the method-name set.
    module_attr_module: str = ""           # e.g. "os", "pickle"
    module_attr_names: frozenset[str] = field(default_factory=frozenset)

    # Translation metadata for auditability (Gap 2): when Semgrep patterns are
    # flattened into module-attribute call shapes, preserve what was parsed vs
    # dropped so downstream stages and tests can reason about fidelity.
    total_pattern_leaves: int = 0
    parsed_pattern_leaves: frozenset[str] = field(default_factory=frozenset)
    dropped_pattern_leaves: frozenset[str] = field(default_factory=frozenset)
    translation_flags: frozenset[str] = field(default_factory=frozenset)

    def has_qualified(self) -> bool:
        return bool(self.methods) and bool(self.class_name) and bool(self.package)

    def has_module_attr(self) -> bool:
        return bool(self.module_attr_module) and bool(self.module_attr_names)


# Semgrep pattern grep: `<name>.<name>[.<name>]*(...)` at the top level.
_MODULE_ATTR_RX = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*\("
)
# Regex alternation body inside metavariable-regex: `^(a|b|c)$` → ["a","b","c"]
_ALT_BODY_RX = re.compile(r"^\s*\^?\s*\(([^)]+)\)\s*\$?\s*$")


# _OWASP_2025_BY_SEMANTIC is imported from vvaharness.rules.families.


def _normalize_family(kind: str, cwe: str, rule_id: str, rule: dict) -> str:
    """Infer a stable semantic family from sink/source metadata.

    This is intentionally coarse and repo-agnostic so grouping can work across
    framework-specific APIs and wrapper layers.
    """
    k = (kind or "").lower().strip()
    rid = (rule_id or "").lower()
    c = (cwe or "").upper()
    leaf_patterns = "\n".join(_walk_pattern_leaves(rule)).lower()

    if ("79" in c or k in {"xss", "template"}
            or "raw-html-format" in rid
            or "response(" in leaf_patterns
            or "render_template" in leaf_patterns
            or "htmlresponse" in leaf_patterns):
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
    return k or "other"


def _owasp_2025_labels(semantic_family: str) -> frozenset[str]:
    return frozenset(_OWASP_2025_BY_SEMANTIC.get(semantic_family, ("A03:2025-Injection",)))


def _norm_langs(raw_langs) -> frozenset[str]:
    if not isinstance(raw_langs, list):
        return frozenset()
    out: set[str] = set()
    for l in raw_langs:
        v = _SEMGREP_TO_VVAH.get(str(l).lower())
        if v:
            out.add(v)
    return frozenset(out)


def _extract_methods_from_regex(regex: str) -> frozenset[str]:
    m = _ALT_BODY_RX.match(regex or "")
    if not m:
        return frozenset()
    body = m.group(1)
    parts = [p.strip() for p in body.split("|")]
    return frozenset(p for p in parts if p and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p))


def _metavar_methods(rule: dict, metavar_name: str) -> frozenset[str]:
    """Walk a rule's `patterns:` list looking for `{metavariable-regex: {
    metavariable: $NAME, regex: ...}}` and return the alternation set."""
    for pat in rule.get("patterns") or []:
        if not isinstance(pat, dict):
            continue
        mvr = pat.get("metavariable-regex")
        if not isinstance(mvr, dict):
            continue
        if mvr.get("metavariable") != metavar_name:
            continue
        return _extract_methods_from_regex(str(mvr.get("regex") or ""))
    return frozenset()


def _top_pattern_string(rule: dict) -> str:
    """Best-effort extraction of a semgrep rule's top-level match pattern
    for module-attribute-shape detection. Handles `pattern: ...` and
    `pattern-either: [{pattern: ...}, ...]`; returns "" for anything else."""
    p = rule.get("pattern")
    if isinstance(p, str):
        return p
    pe = rule.get("pattern-either")
    if isinstance(pe, list):
        for item in pe:
            if isinstance(item, dict):
                v = item.get("pattern")
                if isinstance(v, str):
                    return v
    return ""


def _walk_pattern_leaves(node):
    """Recursively yield every leaf `pattern: <str>` inside an arbitrarily
    nested semgrep patterns tree (patterns -> pattern-either -> patterns …)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                yield v
            elif isinstance(v, (dict, list)):
                yield from _walk_pattern_leaves(v)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_pattern_leaves(item)


def _walk_rule_keys(node):
    """Yield all dict keys in a nested Semgrep rule tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            if isinstance(v, (dict, list)):
                yield from _walk_rule_keys(v)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_rule_keys(item)


def _translation_flags(rule: dict, parsed_count: int, total_count: int) -> frozenset[str]:
    keys = set(_walk_rule_keys(rule))
    flags: set[str] = set()
    if "patterns" in keys or "pattern-either" in keys:
        flags.add("nested-patterns")
    if "pattern-not" in keys or "pattern-not-inside" in keys:
        flags.add("negative-patterns")
    if "pattern-regex" in keys or "pattern-not-regex" in keys:
        flags.add("regex-patterns")
    if "metavariable-regex" in keys:
        flags.add("metavariable-constraints")
    if total_count > 0 and parsed_count == 0:
        flags.add("no-parseable-module-attr")
    elif total_count > 0 and parsed_count < total_count:
        flags.add("partial-pattern-coverage")
    return frozenset(flags)


def _try_module_attr(rule_id: str, role: str, origin: str, cwe: str, kind: str,
                     langs: frozenset[str], rule: dict) -> list[MatchSpec]:
    """Parse every `<mod>.<attr>(...)` leaf in a semgrep-lifted rule. Emits
    ONE MatchSpec per unique module-root, with all seen method names merged
    into `module_attr_names`. Returns [] if no shapes are parseable."""
    by_module: dict[str, set[str]] = {}
    parsed_leaves: set[str] = set()
    all_leaves = [ptxt for ptxt in _walk_pattern_leaves(rule) if isinstance(ptxt, str)]
    # Walk the whole rule dict so patterns at any depth get picked up.
    for ptxt in all_leaves:
        m = _MODULE_ATTR_RX.match(ptxt or "")
        if not m:
            continue
        parsed_leaves.add(ptxt)
        parts = m.group(1).split(".")
        if len(parts) < 2:
            continue
        by_module.setdefault(parts[0], set()).add(parts[-1])
    specs: list[MatchSpec] = []
    meta = rule.get("metadata") or {}
    # Prefer the corpus-stored family; re-derive only if absent.
    semantic_family = _resolve_semantic_family(
        meta, fallback=_normalize_family(kind, cwe, rule_id, rule))
    owasp_tags = _owasp_2025_labels(semantic_family)
    dropped_leaves = set(all_leaves) - parsed_leaves
    flags = _translation_flags(rule, len(parsed_leaves), len(all_leaves))
    for module_root, names in by_module.items():
        specs.append(MatchSpec(
            rule_id=rule_id, role=role, origin=origin, cwe=cwe, kind=kind,
            semantic_family=semantic_family,
            owasp_top10_2025=owasp_tags,
            languages=langs,
            module_attr_module=module_root,
            module_attr_names=frozenset(names),
            total_pattern_leaves=len(all_leaves),
            parsed_pattern_leaves=frozenset(parsed_leaves),
            dropped_pattern_leaves=frozenset(dropped_leaves),
            translation_flags=flags,
        ))
    return specs


def _spec_from_rule(rule: dict, role: str) -> list[MatchSpec]:
    """Convert one semgrep rule dict into zero or more MatchSpec records."""
    rule_id = str(rule.get("id") or "").strip()
    if not rule_id:
        return []
    langs = _norm_langs(rule.get("languages"))
    if not langs:
        return []
    meta = rule.get("metadata") or {}
    cwe = str(meta.get("cwe") or "").strip() or "CWE-20"
    kind = str(meta.get("sink_kind") or meta.get("ep_kind") or "other")
    # The rule corpus is authoritative for the semantic family (build_kb writes
    # a clamped value); read it rather than re-deriving. Fall back to the local
    # classifier only for rules that carry no stored family.
    semantic_family = _resolve_semantic_family(
        meta, fallback=_normalize_family(kind, cwe, rule_id, rule))
    owasp_tags = _owasp_2025_labels(semantic_family)

    # Detect provenance from metadata fingerprints (rule-id prefixes vary).
    if meta.get("codeql_pkg"):
        origin = "codeql"
        package = str(meta.get("codeql_pkg") or "")
        class_name = str(meta.get("codeql_class") or "")
        methods = _metavar_methods(rule, "$METHOD")
        is_ctor = False
    elif meta.get("fsb_pkg"):
        origin = "fsb"
        package = str(meta.get("fsb_pkg") or "")
        class_name = str(meta.get("fsb_class") or "")
        methods = _metavar_methods(rule, "$METHOD")
        is_ctor = rule_id.endswith("-ctor")
    else:
        # Semgrep-lifted rule — try module-attribute parse only. Everything
        # more complex is omitted from this callgraph input.
        return _try_module_attr(rule_id, role, "semgrep", cwe, kind, langs, rule)

    if not package:
        return []
    top_class = class_name.split(".")[0] if class_name else ""
    if is_ctor and top_class:
        # Constructor rules apply to the class itself, not method-named calls.
        return [MatchSpec(
            rule_id=rule_id, role=role, origin=origin, cwe=cwe, kind=kind,
            semantic_family=semantic_family,
            owasp_top10_2025=owasp_tags,
            languages=langs, package=package, class_name=class_name,
            top_class=top_class, methods=frozenset({top_class}),
            is_constructor=True,
            total_pattern_leaves=0,
            parsed_pattern_leaves=frozenset(),
            dropped_pattern_leaves=frozenset(),
            translation_flags=frozenset(),
        )]
    if not methods:
        return []
    return [MatchSpec(
        rule_id=rule_id, role=role, origin=origin, cwe=cwe, kind=kind,
        semantic_family=semantic_family,
        owasp_top10_2025=owasp_tags,
        languages=langs, package=package, class_name=class_name,
        top_class=top_class, methods=methods, is_constructor=False,
        total_pattern_leaves=0,
        parsed_pattern_leaves=frozenset(),
        dropped_pattern_leaves=frozenset(),
        translation_flags=frozenset(),
    )]


def _load(path: Path | None) -> list[dict]:
    if not path or not path.is_file():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return list((doc or {}).get("rules") or [])


def load_rulepacks(sources_yaml: Path | None,
                   sinks_yaml:   Path | None,
                   active_langs: list[str]) -> tuple[
                       list[MatchSpec], list[MatchSpec], dict[str, list[str]]]:
    """Load both YAMLs, filter to `active_langs`, return
    (source_specs, sink_specs, rule_cwe)."""
    # Memory profiling is opt-in: gc.collect() + tracemalloc on the default
    # rule-load path cost ~3s/scan for a diagnostic nobody reads. Gate it behind
    # VVAHARNESS_DEBUG_MEM=1.
    _debug_mem = os.environ.get("VVAHARNESS_DEBUG_MEM") == "1"
    if _debug_mem:
        import gc
        import tracemalloc
        gc.collect()
        tracemalloc.start()

    lang_filter = frozenset(active_langs)
    source_specs: list[MatchSpec] = []
    sink_specs: list[MatchSpec] = []
    rule_cwe: dict[str, list[str]] = {}
    stats = {
        "source": {"rules": 0, "converted": 0, "dropped_unconvertible": 0,
                   "dropped_lang": 0},
        "sink": {"rules": 0, "converted": 0, "dropped_unconvertible": 0,
                 "dropped_lang": 0},
    }
    translation_flag_counts: dict[str, int] = {}
    for role, raw_rules in (("source", _load(sources_yaml)),
                            ("sink",   _load(sinks_yaml))):
        stats[role]["rules"] += len(raw_rules)
        for r in raw_rules:
            specs = _spec_from_rule(r, role)
            if not specs:
                stats[role]["dropped_unconvertible"] += 1
                continue
            for spec in specs:
                if not (spec.languages & lang_filter):
                    stats[role]["dropped_lang"] += 1
                    continue
                stats[role]["converted"] += 1
                rule_cwe[spec.rule_id] = [spec.cwe]
                for flag in spec.translation_flags:
                    translation_flag_counts[flag] = translation_flag_counts.get(flag, 0) + 1
                (source_specs if role == "source" else sink_specs).append(spec)
    if _debug_mem:
        _mem_current, _mem_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    print(
        "  [s0/callgraph] rulepack conversion: "
        f"sources rules={stats['source']['rules']} "
        f"kept={stats['source']['converted']} "
        f"dropped(unconvertible={stats['source']['dropped_unconvertible']},"
        f" lang_filtered={stats['source']['dropped_lang']}); "
        f"sinks rules={stats['sink']['rules']} "
        f"kept={stats['sink']['converted']} "
        f"dropped(unconvertible={stats['sink']['dropped_unconvertible']},"
        f" lang_filtered={stats['sink']['dropped_lang']})",
        file=sys.stderr,
    )
    if _debug_mem:
        print(
            f"  [s0/callgraph] rule memory: "
            f"peak_kb={_mem_peak // 1024} "
            f"current_kb={_mem_current // 1024} "
            f"n_sources={len(source_specs)} "
            f"n_sinks={len(sink_specs)}",
            file=sys.stderr,
        )
    if translation_flag_counts:
        flag_parts = ", ".join(
            f"{k}={translation_flag_counts[k]}" for k in sorted(translation_flag_counts)
        )
        print(
            f"  [s0/callgraph] translation flags: {flag_parts}",
            file=sys.stderr,
        )
    return source_specs, sink_specs, rule_cwe
