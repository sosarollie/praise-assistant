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

"""LLM-backed source/sink spec derivation for callgraph mode.

This module converts tree-sitter-observed call fingerprints into MatchSpec
records so s0 can run without sources/sinks YAML files when
`step0.callgraph_detection: llm` is selected.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Any

# Module import keeps the monkeypatch seam for tests.
from vvaharness.backends.llm import deepagents as _deepagents
from vvaharness.pipeline.stages.callgraph_engine._rules import MatchSpec
from vvaharness.pipeline.stages.callgraph_engine._scan import FileIndex
from vvaharness.rules.families import (
    OWASP_2025_BY_SEMANTIC as _FAMILIES_OWASP,
)
from vvaharness.rules.families import (
    norm_cwe as _families_norm_cwe,
)
from vvaharness.backends.harness.models import is_halt_error
from vvaharness.report.redact import redact
from vvaharness.util.counters import COUNTERS
from vvaharness.util.json_extract import extract_json
from vvaharness.util.response_quality import stage_floors

_SYSTEM = (
    "You are a taint-analysis classifier. Given API call fingerprints extracted "
    "from source code, classify each as source, sink, or none for static taint seeding.\n\n"
    "DEFINITIONS:\n"
    "- source: An API that reads UNTRUSTED data into the application from outside "
    "its trust boundary. Examples: HTTP request parameters, file reads, environment "
    "variables, CLI arguments, deserialized objects, database query results from "
    "user-controlled queries, IPC/socket receives.\n"
    "- sink: An API that performs a SECURITY-SENSITIVE operation where untrusted "
    "data could cause harm. Examples: OS command execution, SQL query execution, "
    "file writes to user-controlled paths, template rendering, deserialization of "
    "untrusted formats, dynamic code evaluation, LDAP queries, XML parsing.\n"
    "- none: Utility functions, logging, type conversions, pure computation, "
    "string formatting without injection risk, internal-only helpers. When "
    "uncertain, prefer none.\n\n"
    "COMMON FALSE POSITIVES TO AVOID:\n"
    "- Logging/printing functions (print, log, logger.*) are NOT sinks.\n"
    "- Collection operations (append, push, add, len, size) are NOT sinks.\n"
    "- Type conversions (str, int, float, toString) are NOT sinks.\n"
    "- Internal getters/setters with no external I/O are NOT sources.\n\n"
    "CONFIDENCE CALIBRATION:\n"
    "- 0.9-1.0: API name AND module unambiguously indicate taint relevance "
    "(e.g., subprocess.Popen, flask.request.args, os.system).\n"
    "- 0.7-0.9: Strong signal from either name or module, context confirms "
    "(e.g., cursor.execute with SQL module, yaml.load).\n"
    "- 0.5-0.7: Ambiguous name, module/context unclear "
    "(e.g., generic .get(), .read() without clear taint-relevant module).\n"
    "- Below 0.5: Lean toward role=none instead.\n\n"
    "LANGUAGE-SPECIFIC HINTS:\n"
    "- Python: flask/django/fastapi request.* = source; os/subprocess.* = sink; "
    "pickle/yaml.load = sink (CWE-502); sqlite3/psycopg2 .execute = sink (CWE-89).\n"
    "- Java: HttpServletRequest.get* = source; Runtime.exec = sink (CWE-78); "
    "Statement.execute* = sink (CWE-89); ObjectInputStream.readObject = sink (CWE-502).\n"
    "- JavaScript/TypeScript: req.query/req.body/req.params = source; eval/Function = sink; "
    "child_process.exec = sink (CWE-78); pg/mysql .query = sink (CWE-89).\n"
    "- Go: r.URL.Query/r.FormValue/r.Body = source; exec.Command = sink (CWE-78); "
    "db.Query with string concat = sink (CWE-89).\n"
    "- C/C++: recv/fgets/getenv/argv = source; system/popen/exec* = sink (CWE-78); "
    "strcpy/sprintf/strcat = sink (CWE-120); free after use = sink (CWE-416).\n"
    "- PHP: $_GET/$_POST/$_COOKIE/$_REQUEST/$_FILES/$_SERVER = source; "
    "exec/system/shell_exec/passthru/popen = sink (CWE-78); "
    "mysqli_query/pg_query with concat = sink (CWE-89); "
    "include/require with user input = sink (CWE-98); "
    "move_uploaded_file = sink (CWE-434); unserialize = sink (CWE-502).\n\n"
    "Return JSON only with key 'results': a list of objects with fields "
    "id, role, confidence, cwe, kind. "
    "role must be one of source, sink, none. "
    "confidence must be a number between 0 and 1. "
    "cwe should be like CWE-89. "
    "kind for source should be one of network, ipc, file, cli, "
    "deserialization, other. "
    "kind for sink can be a short snake_case label."
)

# VVAH-E003 floors sized for THIS stage's real output. The reply is compact
# JSON and the prompt says "when uncertain, prefer none", so a small final
# batch legitimately answers with a single all-none row:
#   {"results":[{"id":"c1","role":"none","confidence":0.9,"cwe":"CWE-20","kind":"other"}]}
# is 86 chars / ~31 output tokens (cl100k) — far under the global 150-char
# floor (sized for prose/report stages) and straddling the 30-token one.
# _parse_results is deliberately lenient (a bare list of rows also parses), so
# the leanest reply the stage actually accepts as a usable sample is
#   [{"id":"c1","role":"none"}]
# at 27 chars / ~12 tokens. A floor above THAT band flags a healthy short
# answer as degenerate; at 3 consecutive trips — easily reached here, because
# every batch and every self-consistency sample shares this one tag — the
# backend raises DegenerateResponseError, the per-sample handler below drops
# the sample, and seed coverage is silently lost on a correct reply.
#
# 25 chars / 10 tokens sit just below that leanest valid reply and still above
# every degenerate archetype (the catalogue in s1_autoexclude.py): empty body
# (0 chars / 0 tokens), one-word acknowledgement (~2 / ~1-2), empty fenced
# block (~7 / ~4), one-sentence refusal (~8-9 tokens). On the CHAR axis a
# refusal (~25-60 chars) overlaps the leanest valid reply, so 25 cannot
# separate them — the token floor does where the route reports output_tokens,
# and either way the stage's own structural check already catches what the
# floor cannot: extract_json/_parse_results discard any non-JSON or row-less
# reply as an unusable sample (counted as s0_annotate_sample_unusable), so a
# refusal can never become specs. Provider-reported output_tokens include
# thinking and multi-turn tokens, so they only over-count visible text — the
# margin above the 10-token floor is one-directional.
_MIN_RESPONSE_CHARS = 25
_MIN_RESPONSE_TOKENS = 10
_TAG = "s0 callgraph-annotate"

_SOURCE_METHOD_HINTS = {
    "get", "args", "query", "param", "params", "form", "json",
    "body", "headers", "header", "cookies", "cookie", "input",
    "read", "recv", "receive", "next", "fetch",
}
_SOURCE_MODULE_HINTS = {
    "flask", "fastapi", "django", "starlette", "aiohttp", "request",
    "requests", "sys", "os",
}

_SINK_METHOD_HINTS = {
    "execute", "executemany", "raw", "query", "run", "system",
    "popen", "spawn", "exec", "eval", "loads", "load",
    "deserialize", "unmarshal", "parse", "render", "template",
    "write", "send", "post", "put",
}
_SINK_MODULE_HINTS = {
    "os", "subprocess", "sqlite3", "psycopg2", "pymysql", "mysql",
    "sqlalchemy", "pickle", "yaml", "jinja2", "mako", "shlex",
}

_OWASP_2025_BY_SEMANTIC: dict[str, tuple[str, ...]] = _FAMILIES_OWASP


@dataclass
class _Candidate:
    cid: str
    language: str
    module: str
    method: str
    count: int
    sample_file: str
    sample_line: int
    sample_snippet: str


def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _cfg_get(obj: Any, name: str, default: Any) -> Any:
    try:
        return getattr(obj, name)
    except AttributeError:
        return default


def _norm_cwe(raw: Any, role: str) -> str:
    # Normalize via the shared canonical form so e.g. ``CWE-0089`` and
    # ``CWE-89`` resolve identically and agree with build_kb's normalized
    # corpus.
    norm = _families_norm_cwe(raw)
    if norm:
        return norm
    return "CWE-20" if role == "source" else "CWE-78"


def _semantic_family(kind: str, cwe: str) -> str:
    """Map a source/sink kind + CWE to the semantic family used downstream."""
    k = (kind or "").lower().strip()
    c = (cwe or "").upper()
    if "79" in c or k in {"xss", "template"}:
        return "html-response"
    if "78" in c or k in {"cmd", "dyn-eval"}:
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


def _owasp_labels(family: str) -> frozenset[str]:
    return frozenset(_OWASP_2025_BY_SEMANTIC.get(family, ("A03:2025-Injection",)))


def _collect_candidates(file_indices: list[FileIndex], active_langs: set[str],
                        max_candidates: int) -> list[_Candidate]:
    by_sig: dict[tuple[str, str, str], _Candidate] = {}
    for idx in file_indices:
        for oc in idx.observed_calls:
            if oc.language not in active_langs:
                continue
            module = ""
            if oc.resolved_receiver:
                module = oc.resolved_receiver.split(".")[0]
            elif oc.receiver:
                module = oc.receiver.split(".")[0]
            module = module.strip()
            method = (oc.method or "").strip()
            if not module or not method:
                continue
            sig = (oc.language, module, method)
            cur = by_sig.get(sig)
            if cur is None:
                by_sig[sig] = _Candidate(
                    cid=f"c{len(by_sig) + 1}",
                    language=oc.language,
                    module=module,
                    method=method,
                    count=1,
                    sample_file=oc.file,
                    sample_line=oc.line,
                    sample_snippet=oc.snippet,
                )
            else:
                cur.count += 1
    ordered = sorted(by_sig.values(),
                     key=lambda c: (-c.count, c.language, c.module, c.method))
    return ordered[:max_candidates]


def _build_prompt_batch(batch: list[_Candidate]) -> str:
    payload = [
        {
            "id": c.cid,
            "language": c.language,
            "module": c.module,
            "method": c.method,
            "count": c.count,
            "sample": f"{c.sample_file}:{c.sample_line}: {c.sample_snippet}",
        }
        for c in batch
    ]
    instr = {
        "task": "Classify each API as source, sink, or none for taint seeding.",
        "constraints": [
            "Use only provided IDs.",
            "Prefer role=none when uncertain.",
            "Confidence must be numeric in [0,1].",
        ],
        "output_schema": {
            "results": [
                {
                    "id": "c1",
                    "role": "source|sink|none",
                    "confidence": 0.0,
                    "cwe": "CWE-20",
                    "kind": "network|ipc|file|cli|deserialization|other|<sink_kind>",
                }
            ]
        },
        "calls": payload,
    }
    return json.dumps(instr, ensure_ascii=True, indent=2)


def _parse_results(raw: str) -> list[dict[str, Any]]:
    obj = extract_json(raw)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        rows = obj.get("results")
        if isinstance(rows, list):
            return [x for x in rows if isinstance(x, dict)]
    return []


def _tok(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _heuristic_source_kind(c: _Candidate) -> tuple[bool, str, str]:
    mt = _tok(c.method)
    md = _tok(c.module)
    sn = (c.sample_snippet or "").lower()
    if (mt in _SOURCE_METHOD_HINTS and
            (md in _SOURCE_MODULE_HINTS
             or "request" in sn
             or "header" in sn
             or "cookie" in sn)):
        return True, "network", "CWE-20"
    if mt in {"getenv", "environ"} or "os.environ" in sn:
        return True, "file", "CWE-73"
    if mt in {"argv", "next", "readline"} and ("sys" in md or "stdin" in sn):
        return True, "cli", "CWE-20"
    return False, "", ""


def _heuristic_sink_kind(c: _Candidate) -> tuple[bool, str, str]:
    mt = _tok(c.method)
    md = _tok(c.module)
    sn = (c.sample_snippet or "").lower()
    if mt in {"system", "popen", "spawn", "exec", "eval"} or md in {"os", "subprocess"}:
        return True, "command_injection", "CWE-78"
    if mt in {"execute", "executemany", "raw", "query"}:
        return True, "sql_injection", "CWE-89"
    if mt in {"loads", "load", "deserialize", "unmarshal"} or md in {"pickle", "yaml"}:
        return True, "unsafe_deserialization", "CWE-502"
    if mt in _SINK_METHOD_HINTS and (md in _SINK_MODULE_HINTS or "sql" in sn):
        return True, "unsafe", "CWE-20"
    return False, "", ""


def _append_spec(role: str, cand: _Candidate, kind: str, cwe: str,
                 source_specs: list[MatchSpec], sink_specs: list[MatchSpec],
                 rule_cwe: dict[str, list[str]],
                 seen_sig: set[tuple[str, str, str, str]],
                 suffix: str = "") -> None:
    sig = (role, cand.language, cand.module, cand.method)
    if sig in seen_sig:
        return
    seen_sig.add(sig)
    rule_id = f"llm-{role}:{cand.language}:{cand.module}.{cand.method}{suffix}"
    family = _semantic_family(kind, cwe)
    spec = MatchSpec(
        rule_id=rule_id,
        role=role,
        origin="llm",
        cwe=cwe,
        kind=kind,
        languages=frozenset({cand.language}),
        semantic_family=family,
        owasp_top10_2025=_owasp_labels(family),
        module_attr_module=cand.module,
        module_attr_names=frozenset({cand.method}),
    )
    rule_cwe[rule_id] = [cwe]
    if role == "source":
        source_specs.append(spec)
    else:
        sink_specs.append(spec)


def _seed_seen_sig(source_specs: list[MatchSpec],
                   sink_specs: list[MatchSpec]) -> set[tuple[str, str, str, str]]:
    seen: set[tuple[str, str, str, str]] = set()
    for role, specs in (("source", source_specs), ("sink", sink_specs)):
        for s in specs:
            if not s.has_module_attr():
                continue
            for m in s.module_attr_names:
                seen.add((role, next(iter(s.languages), ""),
                          s.module_attr_module, m))
    return seen


def supplement_with_heuristics(
    file_indices: list[FileIndex],
    active_langs: list[str],
    source_specs: list[MatchSpec],
    sink_specs: list[MatchSpec],
    rule_cwe: dict[str, list[str]],
    min_extra_sources: int = 1,
    min_extra_sinks: int = 0,
    max_extra_specs: int = 10,
) -> tuple[list[MatchSpec], list[MatchSpec], dict[str, list[str]]]:
    """Augment existing specs with deterministic tree-sitter heuristics."""
    if max_extra_specs <= 0:
        return source_specs, sink_specs, rule_cwe

    candidates = _collect_candidates(file_indices, set(active_langs), 400)
    if not candidates:
        return source_specs, sink_specs, rule_cwe

    seen_sig = _seed_seen_sig(source_specs, sink_specs)
    add_src = max(0, int(min_extra_sources))
    add_snk = max(0, int(min_extra_sinks))
    added = 0

    if add_src:
        for cand in candidates:
            ok, kind, cwe = _heuristic_source_kind(cand)
            if not ok:
                continue
            before = len(source_specs)
            _append_spec(
                "source", cand, kind, cwe,
                source_specs, sink_specs, rule_cwe, seen_sig,
                suffix=":h",
            )
            if len(source_specs) > before:
                add_src -= 1
                added += 1
            if add_src <= 0 or added >= max_extra_specs:
                break

    if add_snk and added < max_extra_specs:
        for cand in candidates:
            ok, kind, cwe = _heuristic_sink_kind(cand)
            if not ok:
                continue
            before = len(sink_specs)
            _append_spec(
                "sink", cand, kind, cwe,
                source_specs, sink_specs, rule_cwe, seen_sig,
                suffix=":h",
            )
            if len(sink_specs) > before:
                add_snk -= 1
                added += 1
            if add_snk <= 0 or added >= max_extra_specs:
                break

    return source_specs, sink_specs, rule_cwe


def detect_specs(file_indices: list[FileIndex], active_langs: list[str], cfg,
                 *, repo_root: str,
                 ) -> tuple[list[MatchSpec], list[MatchSpec], dict[str, list[str]]]:
    """Infer source/sink MatchSpecs from observed call fingerprints via LLM.

    ``repo_root`` is the scanned repository root, required (never defaulted
    to ``"."``) because it becomes the working directory of the deepagents
    route's model call; the legacy registry routes ignore it.
    """
    step0 = _cfg_get(cfg, "step0", None)
    cg = _cfg_get(step0, "callgraph", None)
    llm_cfg = _cfg_get(cg, "llm", None)

    max_candidates = int(_cfg_get(llm_cfg, "max_candidates", 400) or 400)
    max_batch_candidates = int(_cfg_get(llm_cfg, "max_batch_candidates", 150) or 150)
    min_source_conf = float(_cfg_get(llm_cfg, "min_source_confidence", 0.75) or 0.75)
    min_sink_conf = float(_cfg_get(llm_cfg, "min_sink_confidence", 0.75) or 0.75)
    max_tokens = int(_cfg_get(llm_cfg, "max_tokens", 16000) or 16000)
    failure_mode = str(_cfg_get(llm_cfg, "failure_mode", "empty") or "empty").lower()
    heuristic_enabled = bool(_cfg_get(llm_cfg, "heuristic_supplement", True))
    min_sources = int(_cfg_get(llm_cfg, "min_sources", 1) or 1)
    min_sinks = int(_cfg_get(llm_cfg, "min_sinks", 1) or 1)
    max_heuristic_specs = int(_cfg_get(llm_cfg, "max_heuristic_specs", 10) or 10)
    # Self-consistency voting (N>1, majority wins) damps documented seed
    # variance (identical replicates drew 4/6/7 source specs at N=1, each spec
    # swinging ~56 sink sites) at roughly N-1 extra annotate outputs per batch,
    # measured at ~6.8% of whole-scan completion tokens for N=3; the default is
    # single-pass and profiles opt in via self_consistency.
    self_consistency = max(1, int(_cfg_get(llm_cfg, "self_consistency", 1) or 1))

    models = _cfg_get(cfg, "models", None)
    model = _cfg_get(models, "graph_annotate", None)
    if model is None:
        model = _cfg_get(models, "preprocess", None)
    if model is None:
        model = _cfg_get(models, "callgraph_creation", None)
    if model is None:
        model = _cfg_get(models, "deepdive", None)

    if model is None:
        if failure_mode == "fail":
            raise ValueError("step0.callgraph.llm mode requires a configured model")
        print("  [s0/callgraph] llm detection has no model configured; returning empty specs",
              file=sys.stderr)
        return [], [], {}

    candidates = _collect_candidates(file_indices, set(active_langs), max_candidates)
    if not candidates:
        return [], [], {}

    by_id = {c.cid: c for c in candidates}
    source_specs: list[MatchSpec] = []
    sink_specs: list[MatchSpec] = []
    rule_cwe: dict[str, list[str]] = {}
    seen_sig: set[tuple[str, str, str, str]] = set()

    try:
        for i in range(0, len(candidates), max_batch_candidates):
            batch = candidates[i:i + max_batch_candidates]
            user = _build_prompt_batch(batch)
            # cid -> role -> list of (confidence, cwe, kind) across samples
            votes: dict[str, dict[str, list[tuple[float, str, str]]]] = {}
            samples_ok = 0
            for _s in range(self_consistency):
                # Each SAMPLE is contained: extract_json raises on an unparseable
                # response, and without this the first bad draw would abort the
                # whole detection through the outer handler and return no specs
                # at all — turning one provider hiccup into a lost seed. An
                # unusable sample is also excluded from `samples_ok`, so it
                # cannot silently raise the bar the good samples must clear.
                try:
                    # stage_floors keys the override by the same `stage` tag
                    # every backend hands check_response_quality(), so it
                    # applies on whichever route (deepagents / sdk / cli /
                    # openai) the model resolves to. This loop is serial, so
                    # the shared constant tag never has two overlapping
                    # scopes — the case stage_floors' save/restore cannot
                    # survive.
                    with stage_floors(_TAG, min_chars=_MIN_RESPONSE_CHARS,
                                      min_tokens=_MIN_RESPONSE_TOKENS):
                        raw = _deepagents.dispatch_prompt(
                            user,
                            model=model,
                            cfg=cfg,
                            cwd=repo_root,
                            system_prompt=_SYSTEM,
                            max_tokens=max_tokens,
                            tag=_TAG,
                        )
                    rows = _parse_results(raw)
                except Exception as e:  # noqa: BLE001 — drop the sample, not the batch
                    # A credential or proxy/TLS failure is NOT an unusable
                    # sample: it will hit every remaining sample identically,
                    # so swallowing it here drives samples_ok to 0, reports
                    # "llm detection produced 0 specs", silently degrades the
                    # scan to rules mode, and then burns S1-S9 against a dead
                    # credential. This handler sat UNDER the is_halt_error
                    # re-raise in run(), which made that guard unreachable in
                    # production even though it reads as protection.
                    if is_halt_error(e):
                        raise
                    COUNTERS.bump("s0_annotate_sample_unusable")
                    print(f"  [s0/callgraph] discarding one unusable "
                          f"classification sample: {redact(str(e))}",
                          file=sys.stderr)
                    continue
                if not rows:
                    COUNTERS.bump("s0_annotate_sample_unusable")
                    continue
                samples_ok += 1
                for row in rows:
                    cid = str(row.get("id") or "").strip()
                    if cid not in by_id:
                        continue
                    role = str(row.get("role") or "none").strip().lower()
                    if role not in ("source", "sink"):
                        role = "none"
                    votes.setdefault(cid, {}).setdefault(role, []).append((
                        _as_float(row.get("confidence"), 0.0),
                        _norm_cwe(row.get("cwe"), role),
                        str(row.get("kind")
                            or ("other" if role == "source" else "unsafe")
                            ).strip() or "other",
                    ))
            if not samples_ok:
                continue
            need = samples_ok // 2 + 1        # strict majority of usable samples
            for cid, by_role in votes.items():
                role, entries = max(by_role.items(), key=lambda kv: len(kv[1]))
                if role not in ("source", "sink") or len(entries) < need:
                    continue
                # Mean confidence of the WINNING role only. A candidate sitting
                # near the cutoff is the case voting exists for, and averaging
                # the winners is far steadier than any single draw.
                conf = sum(e[0] for e in entries) / len(entries)
                if role == "source" and conf < min_source_conf:
                    continue
                if role == "sink" and conf < min_sink_conf:
                    continue
                # Most common cwe/kind among the winning votes, so one odd
                # sample cannot relabel a spec the others agreed on.
                cwe = Counter(e[1] for e in entries).most_common(1)[0][0]
                kind = Counter(e[2] for e in entries).most_common(1)[0][0]
                _append_spec(
                    role, by_id[cid], kind, cwe,
                    source_specs, sink_specs, rule_cwe, seen_sig,
                )
        if self_consistency > 1:
            print(f"  [s0/callgraph] self-consistency={self_consistency}: "
                  f"{len(source_specs)} source, {len(sink_specs)} sink spec(s) "
                  f"held a majority", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        # failure_mode defaults to "empty", so without the halt check a
        # credential/TLS failure is swallowed here too and the caller's
        # is_halt_error guard never sees it — the same unreachable-protection
        # bug as the per-sample handler above, one frame out.
        if failure_mode == "fail" or is_halt_error(e):
            raise
        print(f"  [s0/callgraph] llm detection failed: {redact(str(e))}",
              file=sys.stderr)
        return [], [], {}

    if heuristic_enabled:
        need_src = max(0, min_sources - len(source_specs))
        need_snk = max(0, min_sinks - len(sink_specs))
        if need_src or need_snk:
            source_specs, sink_specs, rule_cwe = supplement_with_heuristics(
                file_indices,
                active_langs,
                source_specs,
                sink_specs,
                rule_cwe,
                min_extra_sources=need_src,
                min_extra_sinks=need_snk,
                max_extra_specs=max_heuristic_specs,
            )

    return source_specs, sink_specs, rule_cwe
