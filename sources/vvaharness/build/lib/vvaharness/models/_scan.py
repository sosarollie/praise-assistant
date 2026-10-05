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
Data contracts passed between pipeline steps.

Rule: every step receives and emits one of these. No raw dicts cross step
boundaries — that's how you keep the pipeline debuggable when a $50 run dies
at step 3.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vvaharness.lang.hints import is_source
from vvaharness.models.vocab import OFFENSIVE_LABELS, Severity, VulnClass

log = logging.getLogger(__name__)

_ATX_HEADING_RX = re.compile(r"^(\s{0,3})#{1,6}[ \t]+(.*)$")
_FENCE_RX = re.compile(r"^\s{0,3}(```|~~~)")

# Line/paragraph separators beyond \r\n -- VT, FF, FS/GS/RS, NEL, LS, PS.
# str.splitlines() (and some renderers/post-processors) treat every one of
# these as a line break, so an untrusted value carrying e.g. U+2028 could
# still forge a table row or heading after \r\n were neutralised. Folded to
# spaces, exactly like \r\n.
_MD_LINEBREAK_RX = re.compile(
    "[\r\n\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")
# Remaining C0 controls / DEL (tab excepted) plus zero-width and
# bidirectional format characters (Trojan-Source style): stripped so an
# untrusted value cannot hide, disguise, or visually reorder rendered report
# text (e.g. make a FAILED status read as something else).
_MD_INVISIBLE_RX = re.compile(
    "[\x00-\x08\x0e-\x1f\x7f"              # C0 minus \t and the breaks above
    "\u00ad\u061c"                         # soft hyphen, Arabic letter mark
    "\u200b-\u200f\u202a-\u202e"           # zero-width chars, bidi embeddings
    "\u2060-\u2064\u2066-\u2069\ufeff]")   # word joiner..isolates, BOM


def _demote_md_headings(text):
    if not text:
        return text
    out, in_fence = [], False
    for ln in str(text).splitlines():
        if _FENCE_RX.match(ln):
            in_fence = not in_fence
            out.append(ln)
            continue
        if not in_fence:
            ln = _ATX_HEADING_RX.sub(
                lambda m: f"{m.group(1)}**{m.group(2).rstrip()}**", ln)
        out.append(ln)
    return "\n".join(out)


def _md_cell(text) -> str:
    """Neutralise structure-forging characters in an untrusted value bound for report Markdown."""
    # Inline Markdown (backticks, emphasis, brackets, HTML) is deliberately NOT escaped: the
    # report-augmentation stages re-parse `### N. [SEV] <title>` headings and match them against
    # the raw DTO titles, so widening the alphabet would silently break that matching.
    # Once line breaks are folded, inline metacharacters cannot forge block structure anyway; a
    # caller wrapping the result in a code span must fold backticks itself (chr(96) -> chr(0x2CB)),
    # because a backslash escape is inert inside a span.
    if text is None:
        return ""
    s = _MD_LINEBREAK_RX.sub(" ", str(text))
    s = _MD_INVISIBLE_RX.sub("", s)
    # Backslash before pipe: escaping it afterwards would leave an attacker-supplied "\"
    # consuming the "\" this adds before "|", re-exposing the raw delimiter.
    return s.replace("\\", "\\\\").replace("|", "\\|").strip()


def _render_repro_block(detail: dict) -> list[str]:
    """Render an exploit-verification repro (curl + observed response).

    The renderer lives in ``exploit_verification.verify.repro`` and is imported
    lazily: this module is a leaf (stdlib + pydantic only), and importing an
    exploit_verification package at module scope would invert that. A failure
    here must never cost us the whole report, so it degrades to no block — the
    one-line ``**Repro:**`` field above it still carries the request.
    """
    try:
        from vvaharness.exploit_verification.verify.model import ReproDetail
        from vvaharness.exploit_verification.verify.repro import render_block
        return render_block(ReproDetail.model_validate(detail))
    except Exception:  # noqa: BLE001 — report generation is never worth crashing
        return []


# LLM-output coercion helpers
#
# Several fields below are strict Literal[...] / Enum / int types that get
# populated straight from model_validate(LLM-emitted JSON). A single
# off-schema value (e.g. kind="rpc", size="tiny", risk_rank="high") used to
# kill the whole run. Every such field now carries a `field_validator(
# mode="before")` that maps common synonyms to a valid member and falls back
# to a safe default — so the pipeline degrades instead of crashing,
# regardless of which backend (cli/sdk/openai) produced the JSON.

def _norm(v) -> str:
    return str(v or "").strip().lower().replace("-", "_").replace(" ", "_")


def _coerce_enum(v, valid: set[str], alias: dict[str, str], default: str) -> str:
    raw = str(v or "").strip()
    if raw in valid:                       # exact (case-preserving) hit
        return raw
    k = _norm(v)
    if k in valid:
        return k
    return alias.get(k, default)


def _coerce_int(v, default: int = 0) -> int:
    if isinstance(v, bool):                # bool ⊂ int in Python; reject
        return default
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        # NaN / ±Infinity are not convertible to int — int(float('nan'))
        # raises ValueError and int(float('inf')) raises OverflowError,
        # which would violate this helper's "never crash" contract.
        if v != v or v in (float("inf"), float("-inf")):
            return default
        return int(v)
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _coerce_confidence(v, default: float = 0.5) -> float:
    """
    Crash-proof float coercion for the strict Finding.confidence field
    (Field(ge=0.0, le=1.0)). An off-schema LLM value (e.g. "high", 95,
    NaN, null) used to fail validation and silently drop the whole
    finding at s4. Map common shapes to [0.0, 1.0] and clamp; fall back
    to `default` for anything uninterpretable — so the finding survives
    with a neutral confidence instead of vanishing.
    """
    if isinstance(v, bool):                # bool ⊂ int; treat as no signal
        return default
    if isinstance(v, (int, float)):
        f = float(v)
    else:
        s = str(v if v is not None else "").strip().rstrip("%").strip()
        try:
            f = float(s)
        except (TypeError, ValueError):
            return default
    if f != f or f in (float("inf"), float("-inf")):   # NaN / ±Inf
        return default
    if 2.0 <= f <= 10.0 and f == int(f):
        f = f / 10.0
    elif 2.0 <= f <= 100.0:
        f = f / 100.0
    return min(1.0, max(0.0, f))


def _coerce_scalar_str(v, default, label: str):
    """
    Shape coercion for a scalar-string field populated straight from
    model_validate(LLM-emitted JSON). Handles the recognisable off-schema
    shapes only:

    * list/tuple where one value belongs (a strategist told to cover every
      threat with few chunks reasonably emits `threat_id: ["T45","T46","T47"]`)
      → keep the first non-empty element. For `threat_id` the tail ids then
      read as uncovered and the s3 threat-surface fallback pass MAY backfill
      them — a partial mitigation only: it requires
      `step3.threat_surface_fallbacks` enabled, candidate files to exist for
      each tail threat, headroom under `max_threat_fallback_chunks`, and it
      exempts baseline threats; the model's file↔threat association for the
      tail ids is lost either way. The chunk (and with it the LLM ranking)
      survives, which is the point.
    * explicit null → the field default.
    * bare int/float → its string form (e.g. `id: 1`).

    Anything else (dict, bool, …) is returned unchanged so Pydantic still
    rejects it — the manifest is untrusted model output, and coercion must
    normalise a recognisable shape, never accept arbitrary data.
    """
    if isinstance(v, str):
        return v                              # on-schema; untouched
    if isinstance(v, (list, tuple)):
        first = next((x for x in v if x not in (None, "")), None)
        log.warning("LLM output coercion: %s was a %d-element list; "
                    "keeping the first element %r", label, len(v), first)
        return _coerce_scalar_str(first, default, label)
    if v is None:
        if default is None:
            return None                       # valid for Optional fields
        log.warning("LLM output coercion: %s was null; using default %r",
                    label, default)
        return default
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        log.warning("LLM output coercion: %s was a bare %s (%r); using its "
                    "string form", label, type(v).__name__, v)
        return str(v)
    return v                                  # unrecognisable — let Pydantic reject


def _coerce_str_list(v, label: str):
    """
    Shape coercion for a list-of-strings field populated straight from
    model_validate(LLM-emitted JSON) — the list-typed counterpart of
    :func:`_coerce_scalar_str`. A bare scalar where a list belongs
    (`files: "a.py"`, `related_cves: "CVE-2024-1234"`) is wrapped; an
    explicit null becomes the empty list. Element validation stays
    Pydantic's; unrecognisable shapes pass through unchanged and still fail.
    """
    if isinstance(v, list):
        return v                              # on-schema; untouched
    if v is None:
        log.warning("LLM output coercion: %s was null; using an empty list",
                    label)
        return []
    if isinstance(v, tuple):
        return list(v)
    if isinstance(v, (str, int, float)) and not isinstance(v, bool):
        log.warning("LLM output coercion: %s was a bare %s; wrapping it in "
                    "a list", label, type(v).__name__)
        s = str(v).strip()
        return [s] if s else []
    return v                                  # unrecognisable — let Pydantic reject


# ── Exploit-verification report vocabulary ──────────────────────────────────────
# The labels a person reads are deliberately NOT the internal ``ev_status`` values.
# "INCONCLUSIVE" and "NOT TESTED" read as verdicts on the FINDING, and a reader who takes
# them that way dismisses a static finding that nothing has argued against — exploit
# verification is additive and positive-only, so CONFIRMED is the only verdict it owns.
# The wire values are unchanged (state store, ``--resume``, the report/enrich.py
# round-trip); only the words change, and enrich.py maps them back.
_EV_VERDICT_LABEL = {
    "CONFIRMED": "CONFIRMED (beta)",
    "NOT_CONFIRMED": "NOT CONFIRMED (beta)",
    "INCONCLUSIVE": "REQUIRES REVIEW (beta)",
    "NOT_TESTED": "SAST-ONLY (beta; not live-testable)",
}
# Where the `Why:` reason came from. A deterministic routing fact and a model's reading
# render as identical prose and are not worth the same, so the reason names which it is.
_EV_REASON_TAG = {
    "rule": "[rule] ",
    "triage": "[triage] ",
    "judge": "[judge] ",
}
# Stated on every non-confirmed block, because the block is where the misreading happens
# and a one-word label cannot carry the point on its own.
_EV_NOT_A_FP_NOTE = ("_Not a false positive: exploit verification only ever adds a live "
                     "confirmation. This finding's verdict comes from static "
                     "verification._")
# The same point once more, next to the run-level tally.
_EV_POSITIVE_ONLY_NOTE = ("Exploit verification is additive and positive-only: a finding "
                          "it did not confirm live is not a false positive — the static "
                          "verifier owns that verdict.")


# Injected context (loaded once, threaded through every step)

class CVE(BaseModel):
    id: str                          # CVE-2024-1234
    summary: str
    affected_files: list[str] = []   # if known
    cvss: float | None = None
    patched: bool = False


_CONTROL_KINDS = {"auth", "sandbox", "input-validation", "aslr", "cfi", "other"}
_CONTROL_KIND_ALIAS = {
    "authn": "auth", "authentication": "auth", "authz": "auth",
    "authorization": "auth", "rbac": "auth", "iam": "auth", "sso": "auth",
    "waf": "input-validation", "validation": "input-validation",
    "input_validation": "input-validation", "sanitization": "input-validation",
    "sanitisation": "input-validation", "encoding": "input-validation",
    "seccomp": "sandbox", "container": "sandbox", "isolation": "sandbox",
    "chroot": "sandbox", "jail": "sandbox",
}


class Control(BaseModel):
    """Design-level mitigation. The strategist/chain LLM uses these to downrank exploitability."""
    name: str                        # "auth-gateway", "wasm-sandbox"
    kind: Literal["auth", "sandbox", "input-validation", "aslr", "cfi", "other"]
    protects: list[str] = []         # file globs or module names behind this control
    notes: str = ""

    @field_validator("kind", mode="before")
    @classmethod
    def _v_kind(cls, v):
        return _coerce_enum(v, _CONTROL_KINDS, _CONTROL_KIND_ALIAS, "other")


class AppProfile(BaseModel):
    """CMDB-derived deployment context for the application under scan.
    Built once from report.enrich.lookup_app() and threaded into s1/s2/s6 so
    threat-model actor selection and CVSS environmental scoring agree."""
    application_id: str
    name: str = ""
    externally_facing: bool = False
    pci_scoped: bool = False
    processes_pan: bool = False
    pii: bool = False
    source: str = ""                 # "application" | "component->parent NNN" | …

    def to_prompt_block(self) -> str:
        sens = []
        if self.pci_scoped:   sens.append("PCI-scoped")
        if self.processes_pan: sens.append("processes PAN")
        if self.pii:          sens.append("handles PII")
        return (
            "CMDB APPLICATION PROFILE:\n"
            f"  - Application ID: {self.application_id}\n"
            f"  - Name: {self.name or '(unnamed)'}\n"
            f"  - Externally facing: {'YES' if self.externally_facing else 'NO'}\n"
            f"  - Data sensitivity: {', '.join(sens) or 'standard'}\n"
            f"  - Source: {self.source}\n"
        )


# Step 2 output: ThreatModel  (application-level, code-independent)

_SENSITIVITY = {"low", "medium", "high", "critical"}
_SENSITIVITY_ALIAS = {
    "none": "low", "info": "low", "informational": "low", "minor": "low",
    "moderate": "medium", "med": "medium", "normal": "medium",
    "major": "high", "severe": "high", "important": "high",
    "crit": "critical", "blocker": "critical", "extreme": "critical",
}


class Asset(BaseModel):
    name: str
    description: str = ""
    sensitivity: Literal["low", "medium", "high", "critical"] = "medium"

    @field_validator("sensitivity", mode="before")
    @classmethod
    def _v_sensitivity(cls, v):
        return _coerce_enum(v, _SENSITIVITY, _SENSITIVITY_ALIAS, "medium")


class TrustBoundary(BaseModel):
    entry_point: str
    crossing: str                    # "unauth network → application logic"
    reachable_assets: list[str] = []


_ACTORS = {"remote_unauth", "remote_auth", "adjacent_network",
           "local_user", "local_admin", "supply_chain", "insider"}
_ACTOR_ALIAS = {
    "external": "remote_unauth", "anonymous": "remote_unauth",
    "unauthenticated": "remote_unauth", "internet": "remote_unauth",
    "public": "remote_unauth", "attacker": "remote_unauth",
    "authenticated": "remote_auth", "user": "remote_auth",
    "tenant": "remote_auth", "customer": "remote_auth",
    "internal": "adjacent_network", "network": "adjacent_network",
    "lan": "adjacent_network", "adjacent": "adjacent_network",
    "local": "local_user", "physical": "local_user",
    "admin": "local_admin", "root": "local_admin",
    "operator": "local_admin", "privileged": "local_admin",
    "supply": "supply_chain", "dependency": "supply_chain",
    "third_party": "supply_chain", "vendor": "supply_chain",
    "employee": "insider", "developer": "insider", "malicious_insider": "insider",
}
_IMPACTS = {"low", "medium", "high", "critical", "existential"}
_IMPACT_ALIAS = {**_SENSITIVITY_ALIAS,
                 "catastrophic": "existential", "fatal": "existential"}
_LIKELIHOODS = {"very_rare", "rare", "possible", "likely", "almost_certain"}
_LIKELIHOOD_ALIAS = {
    "very_unlikely": "very_rare", "negligible": "very_rare",
    "remote": "very_rare", "improbable": "very_rare",
    "unlikely": "rare", "low": "rare",
    "moderate": "possible", "medium": "possible", "occasional": "possible",
    "probable": "likely", "high": "likely", "frequent": "likely",
    "very_likely": "almost_certain", "certain": "almost_certain",
    "definite": "almost_certain", "inevitable": "almost_certain",
}


class Threat(BaseModel):
    id: str                          # T1, T2, …
    threat: str
    actor: Literal["remote_unauth", "remote_auth", "adjacent_network",
                   "local_user", "local_admin", "supply_chain", "insider"]
    surface: str                     # entry_point name from trust_boundaries
    asset: str
    impact: Literal["low", "medium", "high", "critical", "existential"]
    likelihood: Literal["very_rare", "rare", "possible", "likely", "almost_certain"]
    controls: str = ""
    evidence: str = ""

    @field_validator("actor", mode="before")
    @classmethod
    def _v_actor(cls, v):
        return _coerce_enum(v, _ACTORS, _ACTOR_ALIAS, "remote_auth")

    @field_validator("impact", mode="before")
    @classmethod
    def _v_impact(cls, v):
        return _coerce_enum(v, _IMPACTS, _IMPACT_ALIAS, "medium")

    @field_validator("likelihood", mode="before")
    @classmethod
    def _v_likelihood(cls, v):
        return _coerce_enum(v, _LIKELIHOODS, _LIKELIHOOD_ALIAS, "possible")


class ThreatModel(BaseModel):
    system_context: str = ""
    assets: list[Asset] = []
    trust_boundaries: list[TrustBoundary] = []
    threats: list[Threat] = []
    open_questions: list[str] = []

    def to_prompt_block(self) -> str:
        lines = ["THREAT MODEL:", "", "System context:", self.system_context, ""]
        if self.assets:
            lines.append(f"Assets ({len(self.assets)}):")
            for a in self.assets:
                lines.append(f"  - [{a.sensitivity}] {a.name} — {a.description}")
            lines.append("")
        if self.trust_boundaries:
            lines.append(f"Trust boundaries ({len(self.trust_boundaries)}):")
            for b in self.trust_boundaries:
                ra = ", ".join(b.reachable_assets) or "-"
                lines.append(f"  - {b.entry_point}: {b.crossing} → assets: {ra}")
            lines.append("")
        if self.threats:
            lines.append(f"Ranked threats ({len(self.threats)}):")
            for t in self.threats:
                lines.append(
                    f"  - {t.id} [{t.impact}/{t.likelihood}] {t.threat} "
                    f"(actor={t.actor}, surface={t.surface}, asset={t.asset}"
                    + (f", controls: {t.controls}" if t.controls and t.controls != "none" else "")
                    + ")"
                )
            lines.append("")
        return "\n".join(lines)

    def to_compact_prompt_block(self, *, max_assets: int = 8,
                                max_boundaries: int = 12,
                                max_threats: int = 12,
                                max_context_chars: int = 2500) -> str:
        lines = [
            "THREAT MODEL:",
            "",
            "System context:",
            self.system_context[:max_context_chars],
            "",
        ]
        if self.assets:
            assets = self.assets[:max_assets]
            lines.append(f"Assets ({len(assets)}/{len(self.assets)}):")
            for a in assets:
                lines.append(f"  - [{a.sensitivity}] {a.name} — {a.description}")
            if len(self.assets) > len(assets):
                lines.append("  …(truncated)")
            lines.append("")
        if self.trust_boundaries:
            bounds = self.trust_boundaries[:max_boundaries]
            lines.append(f"Trust boundaries ({len(bounds)}/{len(self.trust_boundaries)}):")
            for b in bounds:
                ra = ", ".join(b.reachable_assets) or "-"
                lines.append(f"  - {b.entry_point}: {b.crossing} → assets: {ra}")
            if len(self.trust_boundaries) > len(bounds):
                lines.append("  …(truncated)")
            lines.append("")
        if self.threats:
            threats = self.threats[:max_threats]
            lines.append(f"Ranked threats ({len(threats)}/{len(self.threats)}):")
            for t in threats:
                lines.append(
                    f"  - {t.id} [{t.impact}/{t.likelihood}] {t.threat} "
                    f"(actor={t.actor}, surface={t.surface}, asset={t.asset}"
                    + (f", controls: {t.controls}" if t.controls and t.controls != "none" else "")
                    + ")"
                )
            if len(self.threats) > len(threats):
                lines.append("  …(truncated)")
            lines.append("")
        return "\n".join(lines)


# Step 1 output: ContextPackage  (preprocess → strategist, NO raw source code)

_EP_KINDS = {"network", "ipc", "file", "cli", "deserialization", "framework", "other"}
_EP_KIND_ALIAS = {
    "rpc": "network", "grpc": "network", "http": "network",
    "https": "network", "rest": "network", "api": "network",
    "graphql": "network", "websocket": "network", "ws": "network",
    "soap": "network", "tcp": "network", "udp": "network",
    "socket": "network", "webhook": "network", "endpoint": "network",
    "queue": "ipc", "message": "ipc", "mq": "ipc", "kafka": "ipc",
    "amqp": "ipc", "jms": "ipc", "pubsub": "ipc", "event": "ipc",
    "signal": "ipc", "pipe": "ipc", "bus": "ipc",
    "stdin": "cli", "argv": "cli", "command": "cli", "arg": "cli",
    "config": "file", "env": "file", "filesystem": "file", "fs": "file",
    "deserialize": "deserialization", "serde": "deserialization",
    "unmarshal": "deserialization", "parse": "deserialization",
    "pickle": "deserialization", "json": "deserialization",
    "spring": "framework", "django": "framework", "aspnet": "framework",
}


class EntryPoint(BaseModel):
    file: str
    function: str
    kind: Literal["network", "ipc", "file", "cli", "deserialization", "framework", "other"]
    reachable_from_unauth: bool = False

    @field_validator("kind", mode="before")
    @classmethod
    def _v_kind(cls, v):
        return _coerce_enum(v, _EP_KINDS, _EP_KIND_ALIAS, "other")


class Sink(BaseModel):
    """Unsafe function call site flagged by static grep."""
    file: str
    line: int = 0
    function: str                    # strcat, memcpy, sprintf, system, ...
    snippet: str = ""                # the offending line, ~120 chars max
    # CWE ids from the s0 static-seed rule metadata (e.g. ["CWE-89"]).
    # Propagated to Chunk.sink_cwe in s3 so the s4 confirm/refute prompt can
    # splice per-CWE sanitizer/non-sanitizer guidance from rules/*.kb.yaml.
    # Empty for agent-discovered sinks — the KB block simply omits itself.
    cwe: list[str] = []

    @field_validator("line", mode="before")
    @classmethod
    def _v_line(cls, v):
        return _coerce_int(v, 0)


class ModuleInfo(BaseModel):
    name: str
    files: list[str] = []
    loc: int = 0                     # rough lines of code
    purpose: str = ""                # one-line summary from the mapper

    @field_validator("loc", mode="before")
    @classmethod
    def _v_loc(cls, v):
        return _coerce_int(v, 0)


class TaintSymbolRef(BaseModel):
    qnode: str
    symbol: str
    kind: Literal["param", "local", "return", "arg", "field", "container", "property"]


class TaintTransferEdge(BaseModel):
    file: str
    line: int
    function_qnode: str
    src: TaintSymbolRef
    dst: TaintSymbolRef
    transfer_kind: Literal[
        "source", "assign", "arg_to_param", "return_to_local", "return_to_sink", "local_to_sink",
        "field_write", "field_read", "container_put", "container_get", "sanitize",
    ]

    @field_validator("transfer_kind", mode="before")
    @classmethod
    def _coerce_unknown_kind(cls, v: object) -> object:
        _known = {
            "source", "assign", "arg_to_param", "return_to_local", "return_to_sink",
            "local_to_sink", "field_write", "field_read", "container_put",
            "container_get", "sanitize",
        }
        if isinstance(v, str) and v not in _known:
            return "assign"
        return v


class TaintEvidencePath(BaseModel):
    source_ref: str
    sink_ref: str
    path_funcs: list[str] = []
    edges: list[TaintTransferEdge] = []
    sink_cwe: list[str] = []
    sanitized: bool = False  # True if the final edge neutralized taint before the sink


# Control-flow graph and reflection/condition-gated taint edges

class CFGNode(BaseModel):
    """A single basic block in a control-flow graph.
    
    Represents a linear sequence of statements without branching.
    Successors point to block IDs reachable from this node.
    """
    block_id: str                    # e.g., "B0", "B1"
    stmts: list = []                 # tree-sitter nodes or instruction metadata
    successors: list[str] = []       # block IDs this block can reach
    condition: str | None = None     # condition text if branch, else None


class CFG(BaseModel):
    """Control-flow graph for a single function.
    
    Maps basic blocks and their successors to form the control flow.
    Entry and exit mark the start and end blocks.
    """
    blocks: dict[str, CFGNode] = {}   # mapping block_id to CFGNode
    entry: str = ""                   # starting block ID, typically "B0"
    exit: str = ""                    # final block ID
    function_name: str = ""           # for reference


class ConditionTaintEdge(TaintTransferEdge):
    """Taint transfer gated by a condition.
    
    Represents a taint flow where the transfer depends on a condition
    that may itself be tainted. Used to model conditional assignments
    and guarded data flows.
    """
    transfer_kind: Literal["condition"] = "condition"
    condition_text: str = ""           # e.g., "is_admin", "user.role == 'admin'"
    is_tainted_condition: bool = False # does the condition depend on taint source?
    confidence: Literal["high", "medium"] = "high"

    @field_validator("condition_text", mode="before")
    @classmethod
    def _v_condition_text(cls, v):
        return str(v or "").strip()


class ReflectionFact(BaseModel):
    """A reflective/dynamic dispatch call.
    
    Captures calls to dynamic resolution mechanisms like getMethod,
    invoke, getattr, construct, or delegate patterns. Used to model
    reflection and dependency injection in the taint graph.
    """
    function_qnode: str              # qualified node of the function
    line: int = 0                    # source line
    call_type: Literal["getmethod", "invoke", "getattr", "construct", "delegate"] = "invoke"
    target_symbols: list[str] = []   # symbols passed to getMethod/getattr/etc.
    receiver: str = ""               # object on which reflection is called
    # Exactly what a reflection extractor can EMIT, not the parser registry:
    # LANG_PLUGINS also has "go" (no reflection extractor exists) and
    # "typescript" (its key reuses the JS extractor, which hardcodes
    # "javascript"), so neither value is reachable. Kept too narrow once
    # already — missing "javascript" made every JS/TS fact fail validation, and
    # the per-file guard then evicted whole files, eval() sinks included.
    # test_extractor_registry_emits_only_schema_languages pins both directions.
    # Not coerce-to-default like call_type: language is provenance, so an
    # unknown value fails loudly and _scan.py contains it to the one fact.
    language: Literal["python", "java", "javascript", "csharp"] = "python"

    @field_validator("line", mode="before")
    @classmethod
    def _v_line(cls, v):
        return _coerce_int(v, 0)

    @field_validator("call_type", mode="before")
    @classmethod
    def _v_call_type(cls, v):
        _known = {"getmethod", "invoke", "getattr", "construct", "delegate"}
        if isinstance(v, str):
            norm = _norm(v)
            if norm in _known:
                return norm
        return "invoke"


class ReflectionTaintEdge(TaintTransferEdge):
    """Taint transfer via reflection.
    
    Represents a taint flow through dynamically resolved methods or
    functions. Confidence reflects how well the reflection target
    could be resolved statically.
    """
    transfer_kind: Literal["reflect"] = "reflect"
    reflected_targets: list[str] = []  # resolved target method/class QNames
    confidence: Literal["low", "medium", "high"] = "medium"
    is_speculative: bool = True        # this edge is inferred, not explicit

    @field_validator("confidence", mode="before")
    @classmethod
    def _v_confidence(cls, v):
        _known = {"low", "medium", "high"}
        return _coerce_enum(v, _known, {}, "medium")


class BridgeUncertaintyEdge(BaseModel):
    """Low-confidence cross-language handoff edge.

    This is intentionally lightweight and optional. Instances are serialized as
    plain dicts into ``ContextPackage.uncertainty_edges`` to keep wire
    compatibility with existing checkpoints/prompts.
    """

    src_qnode: str
    dst_qnode: str
    reason: str = "bridge_signal"
    confidence: float = Field(default=0.25, ge=0.0, le=1.0)
    edge_type: Literal["bridge"] = "bridge"
    bridge_kind: Literal["shell", "subprocess", "sql_builder", "template"] = "shell"
    language: str = ""
    file: str = ""
    line: int = 0
    snippet: str = ""

    @field_validator("line", mode="before")
    @classmethod
    def _v_line(cls, v):
        return _coerce_int(v, 0)

    @field_validator("confidence", mode="before")
    @classmethod
    def _v_confidence(cls, v):
        return _coerce_confidence(v, default=0.25)

    @field_validator("bridge_kind", mode="before")
    @classmethod
    def _v_bridge_kind(cls, v):
        known = {"shell", "subprocess", "sql_builder", "template"}
        alias = {
            "sql": "sql_builder",
            "sql_string": "sql_builder",
            "tmpl": "template",
            "render": "template",
            "cmd": "shell",
            "process": "subprocess",
        }
        return _coerce_enum(v, known, alias, "shell")


# Framework-level source detection and route/response dataflow

class FrameworkMarkerFact(BaseModel):
    """Framework-specific source or entry point marker.
    
    Captures framework annotations, decorators, and implicit type-based
    markers that indicate user-controlled input sources (e.g., @RequestParam,
    request.GET, @FromQuery). Used to identify sources from web framework
    entry points without explicit type tainting.
    """
    function_qnode: str
    line: int = 0
    marker_type: Literal[
        "spring_annotation", "django_view", "aspnet_annotation",
        "spring_implicit", "django_dict_access", "aspnet_implicit",
        "express_handler", "middleware"
    ] = "spring_annotation"
    marker_name: str                   # e.g., "@RequestParam", "request.GET", "@FromQuery"
    parameter_names: list[str] = []    # Which parameters are tainted by this marker
    framework: Literal["spring", "django", "aspnet", "express"] = "spring"
    confidence: Literal["high", "medium"] = "high"  # high for explicit, medium for implicit

    @field_validator("line", mode="before")
    @classmethod
    def _v_line(cls, v):
        return _coerce_int(v, 0)

    @field_validator("marker_type", mode="before")
    @classmethod
    def _v_marker_type(cls, v):
        _known = {"spring_annotation", "django_view", "aspnet_annotation",
                  "spring_implicit", "django_dict_access", "aspnet_implicit",
                  "express_handler", "middleware"}
        _alias = {
            "spring": "spring_annotation",
            "django": "django_view",
            "aspnet": "aspnet_annotation",
            "request.get": "django_dict_access",
            "request.post": "django_dict_access",
        }
        return _coerce_enum(v, _known, _alias, "spring_annotation")

    @field_validator("framework", mode="before")
    @classmethod
    def _v_framework(cls, v):
        _known = {"spring", "django", "aspnet", "express"}
        return _coerce_enum(v, _known, {}, "spring")

    @field_validator("confidence", mode="before")
    @classmethod
    def _v_confidence(cls, v):
        _known = {"high", "medium"}
        return _coerce_enum(v, _known, {"explicit": "high", "implicit": "medium"}, "high")


class RouteTaintFact(BaseModel):
    """Framework route parameter binding taint fact.
    
    Represents a framework route with path parameters that are bound to
    function arguments. Route parameters extracted from URL patterns are
    inherently tainted (user-controlled). Used to model route parameter
    sources in Spring, Django, and ASP.NET applications.
    """
    function_qnode: str
    line: int = 0
    route_pattern: str                 # e.g., "/user/{id}", "user/<int:id>/", "users/{userId}"
    parameter_name: str                # e.g., "id", "userId"
    is_tainted: bool = True            # URL parameters are always tainted
    framework: Literal["spring", "django", "aspnet", "express"] = "spring"

    @field_validator("line", mode="before")
    @classmethod
    def _v_line(cls, v):
        return _coerce_int(v, 0)

    @field_validator("framework", mode="before")
    @classmethod
    def _v_framework(cls, v):
        _known = {"spring", "django", "aspnet", "express"}
        return _coerce_enum(v, _known, {}, "spring")


class ResponseDataflowFact(BaseModel):
    """Data flow from computation to response output sink.
    
    Tracks flows from intermediate variables or return values to response
    output sinks (e.g., JsonResponse, HttpResponse, Ok, render). Used to
    identify where tainted data reaches response boundaries and may cause
    injection vulnerabilities (XSS, XXE, SSTI, etc.).
    """
    function_qnode: str
    line: int = 0
    from_symbol: str                   # Variable flowing into response
    to_sink: str                       # Response sink (e.g., "JsonResponse", "HttpResponse", "Ok")
    framework: Literal["spring", "django", "aspnet"] = "spring"
    response_type: Literal["json", "html", "text", "xml"] = "json"

    @field_validator("line", mode="before")
    @classmethod
    def _v_line(cls, v):
        return _coerce_int(v, 0)

    @field_validator("framework", mode="before")
    @classmethod
    def _v_framework(cls, v):
        _known = {"spring", "django", "aspnet"}
        return _coerce_enum(v, _known, {}, "spring")

    @field_validator("response_type", mode="before")
    @classmethod
    def _v_response_type(cls, v):
        _known = {"json", "html", "text", "xml"}
        _alias = {
            "response": "html",
            "jsonresponse": "json",
            "httpresponse": "html",
            "render": "html",
            "ok": "json",
            "content": "text",
        }
        return _coerce_enum(v, _known, _alias, "json")


class FrameworkTaintEdge(TaintTransferEdge):
    """Taint transfer via framework infrastructure.
    
    Represents a taint flow through framework-managed entry points,
    route bindings, or response construction. Extends TaintTransferEdge
    to capture transfers that occur within framework-provided mechanisms
    (e.g., Spring request binding, Django view decorators, ASP.NET model binding).
    """
    transfer_kind: Literal["framework"] = "framework"
    marker_type: Literal[
        "spring_annotation", "django_view", "aspnet_annotation",
        "spring_implicit", "django_dict_access", "aspnet_implicit"
    ] = "spring_annotation"
    framework: Literal["spring", "django", "aspnet"] = "spring"
    confidence: Literal["high", "medium"] = "high"

    @field_validator("marker_type", mode="before")
    @classmethod
    def _v_marker_type(cls, v):
        _known = {"spring_annotation", "django_view", "aspnet_annotation",
                  "spring_implicit", "django_dict_access", "aspnet_implicit"}
        _alias = {
            "spring": "spring_annotation",
            "django": "django_view",
            "aspnet": "aspnet_annotation",
        }
        return _coerce_enum(v, _known, _alias, "spring_annotation")

    @field_validator("framework", mode="before")
    @classmethod
    def _v_framework(cls, v):
        _known = {"spring", "django", "aspnet"}
        return _coerce_enum(v, _known, {}, "spring")

    @field_validator("confidence", mode="before")
    @classmethod
    def _v_confidence(cls, v):
        _known = {"high", "medium"}
        return _coerce_enum(v, _known, {"explicit": "high", "implicit": "medium"}, "high")


class ContextPackage(BaseModel):
    repo_root: str
    language: str                    # primary language detected
    call_graph: dict[str, list[str]] = {}     # caller_fqn -> [callee_fqn]
    call_graph_files: dict[str, list[str]] = {}   # fn -> ["file:line", …] (deterministic def-sites from s1 supplement)
    def_spans: dict[str, list[int]] = {}      # qnode -> [start_line, end_line]; tree-sitter only — feeds s3/s4 function slicing
    function_signatures: dict[str, dict[str, object]] = {}  # qnode -> signature metadata (params/class/scope)
    # Low-confidence/ambiguous edges not promoted to the primary call_graph.
    uncertainty_edges: list[dict] = []
    # s0 semgrep codeFlows: each path is ["rel/path:line", …] source→…→sink.
    # Consumed by s3._reachable_files so a file semgrep PROVED is on a taint
    # path can never be dropped by catchall_mode=reachable_only even when the
    # call-graph missed the edge (reflection/DI/dynamic dispatch).
    seed_taint_paths: list[list[str]] = []
    seed_taint_evidence: list[TaintEvidencePath] = []
    entry_points: list[EntryPoint] = []
    unsafe_sinks: list[Sink] = []
    modules: list[ModuleInfo] = []
    all_files: list[str] = []                 # injected: deterministic repo walk (rel paths)
    excluded: dict = {}                       # injected: {dirs:{path:n}, exts:{ext:n}, globs:{pat:n}, oversize:n}
    known_cves: list[CVE] = []                # injected
    design_controls: list[Control] = []       # injected
    app_profile: AppProfile | None = None     # injected (CMDB)
    threat_model: ThreatModel | None = None   # s2 output, attached to ctx after s2
    notes: str = ""                           # free-form Opus observations
    # Exploit-verification: reachability-annotated normalized API collection,
    # attached at S1 prep when EV_API_COLLECTION is set. Stored as a plain
    # dict (a dumped exploit_verification.collection.model.NormalizedCollection)
    # to keep core models free of an exploit_verification import. None = EV off.
    ev_collection: dict | None = None
    # Edge-selection diagnostics from the most recent ast_context_view() call
    # on this object (hot/cold/dropped-by-cap breakdown). Empty on an object
    # that was never passed through ast_context_view. Both s2 and s3 call that
    # method, so the breakdown travels on the returned object instead of being
    # printed with one stage's name baked in.
    ast_frontier_stats: dict = {}

    def ast_context_view(self, *, max_files: int = 250, max_entry_points: int = 120,
                         max_sinks: int = 160, max_modules: int = 40,
                         max_edges: int = 120, max_notes_chars: int = 4000) -> "ContextPackage":
        seed_files: list[str] = []
        _seen: set[str] = set()

        def _add_file(path: str) -> None:
            norm = path.replace("\\", "/")
            while norm.startswith("./"):
                norm = norm[2:]
            if norm and norm not in _seen:
                _seen.add(norm)
                seed_files.append(norm)

        for entry in self.entry_points[:max_entry_points]:
            _add_file(entry.file)
        for sink in self.unsafe_sinks[:max_sinks]:
            _add_file(sink.file)
        for path in self.seed_taint_paths:
            for node in path:
                _add_file(node.split(":", 1)[0])
        for sites in self.call_graph_files.values():
            for site in sites[:2]:
                _add_file(site.split(":", 1)[0])
        for module in self.modules[:max_modules]:
            for path in module.files[:5]:
                _add_file(path)

        all_files: list[str] = []
        all_files_set = set(self.all_files)
        seen_all: set[str] = set()
        for path in seed_files:
            if path in all_files_set and path not in seen_all:
                seen_all.add(path)
                all_files.append(path)
                if len(all_files) >= max_files:
                    break
        if len(all_files) < max_files:
            for path in self.all_files:
                if path not in seen_all:
                    seen_all.add(path)
                    all_files.append(path)
                    if len(all_files) >= max_files:
                        break

        allowed_files = set(all_files)
        entry_points = [e for e in self.entry_points if e.file in allowed_files][:max_entry_points]
        unsafe_sinks = [s for s in self.unsafe_sinks if s.file in allowed_files][:max_sinks]

        modules = []
        for module in self.modules:
            kept = [path for path in module.files if path in allowed_files][:10]
            if kept:
                modules.append(module.model_copy(update={"files": kept}))
            if len(modules) >= max_modules:
                break

        ep_fqns = {f"{e.file}::{e.function}" for e in entry_points}
        sink_fqns = {f"{s.file}::{s.function}" for s in unsafe_sinks}
        # Bare-name fallback for nodes whose file part is missing (agent-emitted
        # unqualified names survive as bare strings until s1 qualifies them).
        # Ambiguous bare names: if the same function name is an entry point (or
        # sink) in more than one file, promoting every edge that touches that
        # bare name crowds out edges on the real taint path.  Only allow the
        # bare-name fallback when the name resolves to exactly ONE entry/sink
        # file — i.e. it is globally unambiguous in this repo.
        from collections import Counter as _Counter
        _ep_bare_count = _Counter(e.function for e in entry_points)
        _sink_bare_count = _Counter(s.function for s in unsafe_sinks)
        ep_bare_uniq = {n for n, c in _ep_bare_count.items() if c == 1}
        sink_bare_uniq = {n for n, c in _sink_bare_count.items() if c == 1}

        def _bare(name: str) -> str:
            return name.rpartition("::")[2]

        def _is_hot(caller: str, callee: str) -> bool:
            # Prefer qualified match (file::function) — always unambiguous.
            if caller in ep_fqns or caller in sink_fqns:
                return True
            if callee in ep_fqns or callee in sink_fqns:
                return True
            # Bare-name fallback: only fire when the name uniquely identifies
            # one entry point / sink across the whole repo so common names like
            # run(), validate(), process() don't spuriously promote every edge.
            caller_bare = _bare(caller)
            callee_bare = _bare(callee)
            if "::" not in caller and (caller_bare in ep_bare_uniq or caller_bare in sink_bare_uniq):
                return True
            if "::" not in callee and (callee_bare in ep_bare_uniq or callee_bare in sink_bare_uniq):
                return True
            return False

        def _edges():
            for caller, callees in self.call_graph.items():
                for callee in dict.fromkeys(c for c in callees if c):
                    yield caller, callee

        trimmed_graph: dict[str, list[str]] = defaultdict(list)
        total_edges = 0
        n_hot = 0
        n_cold = 0
        n_dropped_cap = 0
        # Emit hot edges before cold edges (that order decides which survive the
        # max_edges cut), but classify lazily and stop at the cut instead of
        # materializing every edge into three lists first.
        for want_hot in (True, False):
            if total_edges >= max_edges:
                break
            for caller, callee in _edges():
                is_hot = _is_hot(caller, callee)
                if is_hot != want_hot:
                    if total_edges >= max_edges and not is_hot:
                        n_dropped_cap += 1
                    continue
                cf = caller.split("::", 1)[0] if "::" in caller else ""
                tf = callee.split("::", 1)[0] if "::" in callee else ""
                if cf and cf not in allowed_files and tf and tf not in allowed_files:
                    continue
                if total_edges >= max_edges:
                    n_dropped_cap += 1
                    continue
                trimmed_graph[caller].append(callee)
                total_edges += 1
                if is_hot:
                    n_hot += 1
                else:
                    n_cold += 1

        frontier_stats = {
            "edges_kept": total_edges,
            "edges_total": sum(len(v) for v in self.call_graph.values()),
            "hot": n_hot,
            "cold": n_cold,
            "dropped_by_cap": n_dropped_cap,
        }

        kept_functions = set(trimmed_graph)
        for callees in trimmed_graph.values():
            kept_functions.update(callees)

        trimmed_graph_files = {
            fn: [site for site in sites if site.split(":", 1)[0] in allowed_files][:3]
            for fn, sites in self.call_graph_files.items()
            if fn in kept_functions and any(site.split(":", 1)[0] in allowed_files for site in sites)
        }
        trimmed_def_spans = {
            fn: span for fn, span in self.def_spans.items() if fn in kept_functions
        }
        trimmed_function_signatures: dict[str, dict[str, object]] = {}
        for fn, sig in self.function_signatures.items():
            if fn not in kept_functions or not isinstance(sig, dict):
                continue
            sig_out = dict(sig)
            body_text = sig_out.get("body_text")
            if isinstance(body_text, str):
                if len(body_text) > 800:
                    sig_out["body_text"] = body_text[:800].rstrip() + "\n[truncated body snapshot]"
            trimmed_function_signatures[fn] = sig_out
        trimmed_paths = []
        for path in self.seed_taint_paths:
            kept = [node for node in path if node.split(":", 1)[0] in allowed_files]
            if kept:
                trimmed_paths.append(kept[:8])

        trimmed_evidence = []
        for evidence in self.seed_taint_evidence:
            source_file = evidence.source_ref.split(":", 1)[0]
            sink_file = evidence.sink_ref.split(":", 1)[0]
            if source_file not in allowed_files or sink_file not in allowed_files:
                continue
            trimmed_evidence.append(evidence.model_copy(update={
                "edges": evidence.edges[:24],
            }))
            if len(trimmed_evidence) >= 60:
                break

        def _ref_file(ref) -> str:
            if isinstance(ref, dict):
                qnode = ref.get("qnode")
                if isinstance(qnode, str) and "::" in qnode:
                    return qnode.split("::", 1)[0]
                file_val = ref.get("file")
                if isinstance(file_val, str):
                    return file_val.split(":", 1)[0]
                return ""
            if isinstance(ref, str):
                if "::" in ref:
                    return ref.split("::", 1)[0]
                if ":" in ref:
                    return ref.split(":", 1)[0]
                return ref
            return ""

        trimmed_uncertainty = []
        for edge in self.uncertainty_edges:
            if not isinstance(edge, dict):
                continue
            src_file = _ref_file(edge.get("src_qnode") or edge.get("src"))
            dst_file = _ref_file(edge.get("dst_qnode") or edge.get("dst"))
            if src_file and src_file not in allowed_files:
                continue
            edge_type = str(edge.get("edge_type") or "").strip().lower()
            dst_qnode = str(edge.get("dst_qnode") or edge.get("dst") or "")
            is_synthetic_bridge = edge_type == "bridge" and dst_qnode.startswith("bridge::")
            if dst_file and dst_file not in allowed_files and not is_synthetic_bridge:
                continue
            trimmed_uncertainty.append(edge)
            if len(trimmed_uncertainty) >= 200:
                break

        notes = self.notes[:max_notes_chars]
        if len(self.notes) > max_notes_chars:
            notes = notes.rstrip() + "\n[truncated for AST frontier prompt]"

        return self.model_copy(update={
            "all_files": all_files,
            "entry_points": entry_points,
            "unsafe_sinks": unsafe_sinks,
            "modules": modules,
            "call_graph": dict(trimmed_graph),
            "call_graph_files": trimmed_graph_files,
            "def_spans": trimmed_def_spans,
            "function_signatures": trimmed_function_signatures,
            "uncertainty_edges": trimmed_uncertainty,
            "seed_taint_paths": trimmed_paths,
            "seed_taint_evidence": trimmed_evidence,
            "notes": notes,
            "ast_frontier_stats": frontier_stats,
        })

    def id_inventory(self) -> dict[str, dict]:
        """Deterministic F/E/K id map -> {"files", "entry_points", "sinks"} keyed by F###/E###/K###."""
        # Ids come from SORTED order, not insertion order, so a prompt rendered from them is
        # byte-identical across runs -- prompt-prefix caching depends on that.
        # Call this on the SAME object the prompt was rendered from (e.g. the reduced view
        # ast_context_view() returns): sorted(view.all_files)[k] and sorted(full.all_files)[k] name
        # different files whenever the lists differ, so an id built against one and resolved
        # against the other silently addresses the wrong file.
        def _ids_for(n: int, prefix: str) -> list[str]:
            width = max(3, len(str(n)))
            return [f"{prefix}{i + 1:0{width}d}" for i in range(n)]

        # Deduplicate before numbering. A repeated path would otherwise take a
        # second id, and building the reverse map would drop the first — leaving
        # a gap in the sequence, so an id named in the rendered inventory could
        # resolve to nothing.
        files_sorted = sorted(set(self.all_files))
        file_id_of = dict(zip(files_sorted, _ids_for(len(files_sorted), "F")))
        files = {fid: path for path, fid in file_id_of.items()}

        eps_sorted = sorted(self.entry_points, key=lambda e: (e.file, e.function))
        entry_points = {
            eid: {
                "file_id": file_id_of.get(e.file, ""),
                "function": e.function,
                "kind": e.kind,
                "unauth": e.reachable_from_unauth,
            }
            for eid, e in zip(_ids_for(len(eps_sorted), "E"), eps_sorted)
        }

        sinks_sorted = sorted(self.unsafe_sinks, key=lambda s: (s.file, s.line, s.function))
        sinks = {
            kid: {
                "file_id": file_id_of.get(s.file, ""),
                "function": s.function,
                "line": s.line,
                "cwe": list(s.cwe),
            }
            for kid, s in zip(_ids_for(len(sinks_sorted), "K"), sinks_sorted)
        }

        return {"files": files, "entry_points": entry_points, "sinks": sinks}

    def _file_inventory_block(self) -> list[str]:
        """Render id_inventory() as the authoritative id -> path lookup for the prompt."""
        # The only block that binds an id to a real path. Every other block keeps readable paths
        # because directory and filename carry risk signal a bare id would strip out.
        from pathlib import Path
        inv = self.id_inventory()
        root = Path(self.repo_root)
        out = ["FILE INVENTORY (authoritative — the ONLY files that exist):"]
        for fid, path in inv["files"].items():
            try:
                loc = sum(1 for ln in (root / path).open(
                    "r", encoding="utf-8", errors="replace") if ln.strip())
            except OSError:
                loc = 0
            out.append(f"  {fid}  {path}  ({loc} LOC)")
        if inv["entry_points"]:
            out.append("ENTRY POINTS:")
            for eid, e in inv["entry_points"].items():
                unauth = ", UNAUTH" if e["unauth"] else ""
                out.append(f"  {eid}  {e['file_id']}::{e['function']}  [{e['kind']}{unauth}]")
        if inv["sinks"]:
            out.append("SINKS:")
            for kid, s in inv["sinks"].items():
                cwe = f"  [{', '.join(s['cwe'])}]" if s["cwe"] else ""
                out.append(f"  {kid}  {s['file_id']}::{s['function']}{cwe}")
        out.append(
            "Every chunk file reference MUST resolve to one of the F### ids "
            "above — this is the complete set; nothing outside it exists in "
            "this repository."
        )
        return out

    def to_decompose_prompt_block(self, *, max_assets: int = 8,
                                  max_boundaries: int = 12,
                                  max_threats: int = 12,
                                  max_context_chars: int = 2500) -> str:
        """Method-centric text representation for Step 3 strategist prompts."""
        # File inventory and threat model come FIRST: without an authoritative file list the model
        # invented paths that shared a basename with a real file elsewhere in the tree.
        # The four caps mirror ThreatModel.to_compact_prompt_block's own defaults, so a caller
        # passing none of them renders exactly what this method rendered before they existed.
        lines = list(self._file_inventory_block())
        lines.append("")
        if self.threat_model:
            lines.append(self.threat_model.to_compact_prompt_block(
                max_assets=max_assets, max_boundaries=max_boundaries,
                max_threats=max_threats, max_context_chars=max_context_chars,
            ))
            lines.append("")
        lines += [
            f"REPO: {self.repo_root}  LANG: {self.language}",
            "",
            f"MODULES ({len(self.modules)}):",
        ]
        for m in self.modules:
            lines.append(f"  - {m.name} ({m.loc} loc): {m.purpose}")
        lines.append("")
        lines.append(f"ENTRY POINTS ({len(self.entry_points)}):")
        for e in self.entry_points:
            unauth = " [UNAUTH-REACHABLE]" if e.reachable_from_unauth else ""
            lines.append(f"  - {e.kind}: {e.function} @ {e.file}{unauth}")
        lines.append("")
        lines.append(f"UNSAFE SINKS ({len(self.unsafe_sinks)}):")
        for s in self.unsafe_sinks:
            lines.append(f"  - {s.function} @ {s.file}:{s.line}")
        lines.append("")
        sites = self._function_sites_block()
        if sites:
            lines += sites
            lines.append("")
        sigs = self._signatures_block(body_lines=1, cap=40)
        if sigs:
            lines += sigs
            lines.append("")
        if self.call_graph:
            lines += self._call_graph_block_full()
            lines.append("")
        if self.known_cves:
            lines.append(f"KNOWN CVEs ({len(self.known_cves)}) — DO NOT REDISCOVER:")
            for c in self.known_cves:
                lines.append(f"  - {c.id}: {c.summary}")
            lines.append("")
        if self.design_controls:
            lines.append(f"DESIGN CONTROLS ({len(self.design_controls)}):")
            for c in self.design_controls[:40]:
                prot = ", ".join(c.protects) if c.protects else "global"
                lines.append(f"  - [{c.kind}] {c.name} → protects: {prot}")
            lines.append("")
        if self.app_profile:
            lines.append(self.app_profile.to_prompt_block())
            lines.append("")
        if self.notes:
            lines.append(f"OPUS NOTES:\n{self.notes[:3000]}")
        return "\n".join(lines)

    def _function_sites_block(self, cap: int = 120) -> list[str]:
        out = ["FUNCTION SITES (use these method/file anchors when grouping related files into one chunk):"]
        count = 0
        seen: set[tuple[str, str]] = set()
        for fn, sites in self.call_graph_files.items():
            uniq_sites = []
            for site in sites:
                file_part = site.split(":", 1)[0]
                marker = (fn, file_part)
                if marker in seen:
                    continue
                seen.add(marker)
                uniq_sites.append(site)
            if not uniq_sites:
                continue
            span = self.def_spans.get(fn)
            span_txt = f" lines {span[0]}-{span[1]}" if span and len(span) == 2 else ""
            out.append(f"  - {fn} @ {', '.join(uniq_sites[:3])}{span_txt}")
            count += 1
            if count >= cap:
                remaining = max(0, len(self.call_graph_files) - count)
                if remaining:
                    out.append(f"  … ({remaining} more function sites truncated)")
                break
        return out if count else []

    def _call_graph_block_full(self) -> list[str]:
        """Render the entire frontier call_graph without additional clipping."""
        ep_fqns = {f"{e.file}::{e.function}" for e in self.entry_points}
        sink_fqns = {f"{s.file}::{s.function}" for s in self.unsafe_sinks}
        ep_bare = {e.function for e in self.entry_points}
        sink_bare = {s.function for s in self.unsafe_sinks}
        bare = lambda qn: qn.rpartition("::")[2]

        def _hot(caller: str, callee: str) -> bool:
            return (
                caller in ep_fqns or caller in sink_fqns
                or callee in ep_fqns or callee in sink_fqns
                or ("::" not in caller and (bare(caller) in ep_bare or bare(caller) in sink_bare))
                or ("::" not in callee and (bare(callee) in ep_bare or bare(callee) in sink_bare))
            )

        hot, cold = [], []
        for caller, callees in self.call_graph.items():
            uniq = list(dict.fromkeys(c for c in callees if c))
            if not uniq:
                continue
            for callee in uniq:
                line = f"  - {caller} -> {callee}"
                if _hot(caller, callee):
                    hot.append(line)
                else:
                    cold.append(line)
        ordered = hot + cold
        n_total = len(ordered)
        out = [f"CALL GRAPH ({n_total} edges — group caller+callee files in the SAME chunk):"]
        out += ordered
        return out

    def _signatures_block(self, body_lines: int = 3, cap: int = 60) -> list[str]:
        """
        Real code excerpts for entry points and sinks so the s3 strategist can
        see parameter types / annotations / taint shape when deciding which
        files belong together — instead of grouping on filenames alone.
        """
        from pathlib import Path
        root = Path(self.repo_root)
        out = ["SIGNATURES (entry points + sinks — use param types to group "
               "related files into one chunk):"]
        seen: set[tuple[str, int]] = set()

        def _emit(tag: str, file: str, fn: str, hint_line: int) -> None:
            if len(seen) >= cap:
                return
            p = root / file
            try:
                src = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                return
            anchor = hint_line - 1 if 0 < hint_line <= len(src) else None
            if anchor is None:
                for i, ln in enumerate(src):
                    if fn and fn in ln and "(" in ln:
                        anchor = i
                        break
            if anchor is None or (file, anchor) in seen:
                return
            seen.add((file, anchor))
            hi = min(len(src), anchor + 1 + body_lines)
            out.append(f"  [{tag}] {file}:{anchor + 1} {fn}()")
            for ln in src[anchor:hi]:
                text = ln.rstrip()
                stripped = text.strip()
                if not stripped:
                    continue
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                if stripped in {'"""', "'''", '/**', '*/', '*'}:
                    continue
                out.append(f"      {text[:160]}")

        for e in self.entry_points:
            _emit("ENTRY", e.file, e.function, 0)
        for s in self.unsafe_sinks:
            _emit("SINK", s.file, s.function, s.line)
        if len(seen) >= cap:
            out.append(f"  … (capped at {cap})")
        return out if len(out) > 1 else []


# Step 3 output: TaskManifest  (the strategist's prioritized hunt list)

class ChunkSize(str, Enum):
    SMALL = "small"      # fits in one context, exhaustive
    MEDIUM = "medium"    # fits, but tight
    LARGE = "large"      # needs sliding window anchored to entry points


_CHUNK_SIZES = {"small", "medium", "large"}
_CHUNK_SIZE_ALIAS = {
    "xs": "small", "tiny": "small", "s": "small",
    "m": "medium", "med": "medium", "moderate": "medium",
    "normal": "medium", "default": "medium",
    "l": "large", "xl": "large", "xxl": "large",
    "big": "large", "huge": "large", "x_large": "large",
}


class Chunk(BaseModel):
    # `files` also accepts the JSON key "file_ids" (the id-based shape a
    # strategist prompt asks for once the prompt exposes F### ids instead of
    # paths). Without `populate_by_name=True`, a payload keyed "file_ids"
    # would validate successfully with `files` left at its empty default —
    # no error, so the fallback path that exists for exactly this situation
    # never fires and the manifest is quietly missing that chunk's contents.
    # `populate_by_name=True` keeps every existing `files=[...]` call site
    # (in this module and in tests) working unchanged alongside it.
    model_config = ConfigDict(populate_by_name=True)

    id: str                          # "chunk-01"
    size: ChunkSize = ChunkSize.MEDIUM
    risk_rank: int = 999             # 1 = highest risk, descending
    files: list[str] = Field(default=[], alias="file_ids")  # files the researcher should load for this chunk
    focus_entry_points: list[str] = []  # function names to anchor sliding window on
    hypothesis: str = ""             # strategist's reasoning: "likely heap overflow via..."
    related_cves: list[str] = []     # variant-hunt seeds
    threat_id: str | None = None     # ThreatModel.threats[].id this chunk tests (coverage metric)
    languages: list[str] = []        # detected from file extensions (s3)
    specialist: str | None = None    # "crypto" | "logic-bug" → repo-wide pass
    # Which shard this chunk belongs to when specialist chunks are grouped
    # shard-major (one shard's files, reused across every enabled lens) —
    # empty for chunk kinds that aren't shard-grouped.
    shard_id: str = ""
    # ── taint-chunk metadata (populated by s3 for entry→…→sink chunks; empty
    #    on risk/specialist/catch-all chunks). Drives s4 function-slice loading
    #    and the confirm/refute prompt under the taint.yaml profile.
    path_funcs: list[str] = []       # qnodes on the BFS path, entry → … → sink
    source_ref: str = ""             # "file::function" — the EntryPoint
    sink_ref: str = ""               # "file:line" — the Sink location
    sink_cwe: list[str] = []         # CWE tags from s0 rule metadata (confirm/refute focus)

    @field_validator("size", mode="before")
    @classmethod
    def _v_size(cls, v):
        return _coerce_enum(v, _CHUNK_SIZES, _CHUNK_SIZE_ALIAS, "medium")

    @field_validator("risk_rank", mode="before")
    @classmethod
    def _v_rank(cls, v):
        return _coerce_int(v, 999)

    # One shared shape-guard per declared shape, instead of a dozen per-field
    # validators: every scalar-string and string-list field on this model is
    # populated straight from model_validate(LLM JSON) at the s3 choke point
    # and carries the identical exposure — a single off-schema value used to
    # fail the WHOLE TaskManifest and discard the strategist's ranking (an
    # observed `threat_id: ["T45","T46","T47"]` did exactly that).

    @field_validator("id", "hypothesis", "threat_id", "specialist", "shard_id",
                     "source_ref", "sink_ref", mode="before")
    @classmethod
    def _v_scalar_str(cls, v, info):
        fld = cls.model_fields[info.field_name]
        default = None if fld.is_required() else fld.default
        return _coerce_scalar_str(v, default, f"Chunk.{info.field_name}")

    @field_validator("files", "focus_entry_points", "related_cves",
                     "languages", "path_funcs", "sink_cwe", mode="before")
    @classmethod
    def _v_str_list(cls, v, info):
        return _coerce_str_list(v, f"Chunk.{info.field_name}")


class TaskManifest(BaseModel):
    chunks: list[Chunk]
    # A model reply missing only "rationale" used to raise ValidationError and
    # discard the whole manifest even though every chunk was well-formed;
    # `chunks` is what actually distinguishes a malformed reply (it is always
    # missing or empty on one), so defaulting this loses no detection.
    rationale: str = ""              # strategist explains its ranking
    # Files dropped by step3.catchall_mode=reachable_only — listed in the
    # report appendix (output.emit_unreachable_appendix) so coverage is
    # auditable, never silently truncated. Empty under default.yaml.
    unreachable_files: list[str] = []

    # `chunks` deliberately gets NO shape coercion: a missing/null "chunks"
    # key is what actually distinguishes a genuinely malformed reply (see the
    # rationale comment above) and must keep raising. The two fields below
    # share Chunk's exposure — an explicit-null `rationale` or a bare-scalar
    # `unreachable_files` used to fail the whole manifest.

    @field_validator("rationale", mode="before")
    @classmethod
    def _v_rationale(cls, v):
        return _coerce_scalar_str(v, "", "TaskManifest.rationale")

    @field_validator("unreachable_files", mode="before")
    @classmethod
    def _v_unreachable_files(cls, v):
        return _coerce_str_list(v, "TaskManifest.unreachable_files")

    def sorted_chunks(self) -> list[Chunk]:
        return sorted(self.chunks, key=lambda c: c.risk_rank)


# Step 4 output: Finding  (Opus deep-dive results, post-intersection)
# VulnClass / Severity / OFFENSIVE_LABELS moved to models.vocab, which is now the single
# home for every vocabulary the contracts draw on. Re-exported below so the ~30 modules
# that import them from vvaharness.models are unaffected.


class DupLocation(BaseModel):
    """A finding that was collapsed into a canonical finding during dedup.
    Preserved on `Finding.duplicates` so per-call-site / per-endpoint detail
    isn't lost — the markdown report and SARIF `relatedLocations` surface
    every site that needs remediation, not just the canonical one."""
    file: str
    line_start: int
    line_end: int = 0
    vuln_class: VulnClass
    title: str = ""
    chunk_id: str = ""
    source_ref: str | None = None
    sink_ref: str | None = None
    reasoning: str = ""              # why dedup merged this into the canonical


class Finding(BaseModel):
    """One vulnerability, as every stage and both subsystems understand it.

    Four fields are required -- ``title``, ``file``, ``line_start``, ``vuln_class`` -- and
    that set is deliberate: it is everything a caller holding a third-party scanner's
    result can actually know. The rest is pipeline enrichment and defaults, so this stays
    constructible by hand::

        Finding(title="SQLi in login", file="app/auth.py", line_start=42,
                vuln_class="injection", severity=Severity.HIGH)

    ``chunk_id``, ``code_snippet`` and ``confidence`` used to be required. They are
    artefacts of how *this* pipeline finds things -- a chunk id means nothing to a caller
    who never ran s3 -- so requiring them made the type unusable as an input.
    """

    # ── required: what any caller can know ──
    title: str
    file: str
    line_start: int
    vuln_class: VulnClass
    # Severity lived only on the RankedFinding wrapper, so a caller without a wrapper had
    # nowhere to put it. Defaulted rather than required because ~45 existing construction
    # sites predate it; the ranking stage fills it from the wrapper at ingest. MEDIUM
    # matches the fallback the validation subsystem already used.
    severity: Severity = Severity.MEDIUM
    # ── location / classification ──
    line_end: int = 0
    cwe: str | None = None           # canonical "CWE-79"; set by s4, carried to MD + SARIF taxa
    vuln_class_label: str = ""       # the caller's own wording, when vuln_class folded to OTHER
    chunk_id: str = ""               # the s3 analysis unit this came from; empty for a
                                     # finding that did not originate in this pipeline
    # ── narrative ──
    impact: str = ""                 # 2-3 sentences, plain language, business-facing
    description: str = ""
    exploit_scenario: str = ""       # ≤5 sentences: concrete input → impact
    preconditions: list[str] = []    # what must be true for exploitation
    recommendation: str = ""         # security property + specific code change
    # ── evidence: carried through remediation and validation, not re-derived ──
    code_snippet: str = ""
    source_ref: str | None = None    # "file:line" where untrusted input enters (s4 evidence gate)
    sink_ref: str | None = None      # "file:line" where it is used unsafely
    # Defaulted, not optional: 0.5 is already this codebase's "no opinion" value (see
    # _coerce_confidence), and nine call sites across s4/s5/s8/enrich compare or format it
    # arithmetically, so None would be a TypeError waiting in a $50 scan.
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    votes: int = 1                   # set by intersection logic (1..N runs)
    duplicates: list[DupLocation] = []  # call sites collapsed into this canonical by s7_dedup;
                                        # these are the OTHER SITES a fix must also cover
    backfilled_refs: list[str] = []  # "source_ref"/"sink_ref" synthesized by s5 AST backfill, not derived by s4
    case_id: str = ""                # stable identity across attempts; minted at ingest when empty
    # s8 chain-pass commentary, incl. mitigations. Lives here as well as on RankedFinding
    # because it is rendered into the remediation prompt, and the wrapper is not reachable
    # from the contract -- an engine given only a Finding would silently lose it.
    exploitability_notes: str = ""

    @field_validator("confidence", mode="before")
    @classmethod
    def _v_confidence(cls, v):
        return _coerce_confidence(v, 0.5)

    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE"] | None = None
    verdict_confidence: int | None = None     # 0..10
    verdict_reason: str = ""
    cvss_vector: str | None = None            # CVSS:3.1/AV:_/AC:_/...
    cvss_score: float | None = None           # 0.0–10.0, computed from vector
    cvss_rating: str | None = None            # None/Low/Medium/High/Critical (cvss.rating(), CVSS 3.1 bands)
    verifier_reasoning: str = ""              # internal pre-verdict diagnostic text

    # ── Exploit verification (set by exploit_verification.verify.router; additive) ──
    # "CONFIRMED" | "NOT_CONFIRMED" | "INCONCLUSIVE" (EV probed it) | "NOT_TESTED" (EV
    # did not: not live-testable, no endpoint in the collection, or auth unusable —
    # ``ev_evidence`` carries the reason). None = EV did not run at all this scan.
    # These are wire values: the report renders them through ``_EV_VERDICT_LABEL``, which
    # deliberately words the two non-verdicts differently — see the note there.
    ev_status: str | None = None
    ev_evidence: str = ""                     # concrete tell + offending request (guard-verified)
    # Where ev_evidence came from: "rule" (a deterministic routing or oracle outcome),
    # "triage" (the classifier model's own one-clause reason), "judge" (the independent
    # judge's ruling). Rendered as a tag on the report's `Why:` line so a reader can see
    # whether the sentence is a routing fact or a model's reading. "" when EV set none.
    ev_reason_source: str = ""
    ev_repro: str = ""                        # redacted, replayable request line
    ev_method: str = ""                       # "deterministic-backed" (judge + oracle tell) | "agent-judged" (judge on reasoning)
    ev_confidence: str = ""                   # "high" | "medium" | "low" (proof tier)
    # EV's 0-10 confidence in its live result — the judge's certainty in the verdict it
    # made (like the static verifier's own N/10), falling back to the proof tier when no
    # judge number is available. Distinct axis from static's verdict_confidence: it scores
    # "is EV sure of the live outcome", not "is the finding a true positive". None when EV
    # did not live-test this finding (NOT_TESTED carries no score).
    ev_confidence_score: int | None = None
    # EV's own CVSS, scored by the confirming judge from the OBSERVED impact and
    # advisory only — static's cvss_score above remains the ranking authority (see
    # exploit_verification.verify.router). Shown next to it, "surfaced not reconciled".
    ev_cvss_vector: str = ""                  # CVSS 3.1 vector the judge emitted for the confirmed exploit
    ev_cvss_score: float | None = None        # 0.0–10.0, computed from ev_cvss_vector via report.cvss
    ev_cvss_rating: str | None = None         # None/Low/Medium/High/Critical
    # Confirming request/response, for a replayable curl/Postman repro. A plain
    # dict (an exploit_verification ReproDetail dumped) so this module stays a
    # leaf — see the lazy import in to_markdown below.
    ev_repro_detail: dict = Field(default_factory=dict)

    # ── Post-s7 environmental enrichment (set by pipeline._enrich_findings) ──
    vsvs_vector: str | None = None            # CVSS env vector w/ CR/IR/AR/MAV
    vsvs_score: float | None = None           # 0.0–10.0
    vsvs_rating: str | None = None            # None/Low/Medium/High
    offensive_priority: str | None = None       # P1..P4
    offensive_reason: str = ""

    def canonical_key(self, line_bucket: int = 10) -> tuple:
        """
        Identity for intersection. T=1 jitter means Opus might say line 142
        on run A and line 145 on run B — same bug. Bucket the line number.
        """
        return (self.file, self.line_start // line_bucket, self.vuln_class)


# Step 8 output: Final report


class Chain(BaseModel):
    """Multi-step exploit path that combines several findings."""
    title: str                       # "UAF → arb write → code exec"
    steps: list[int]                 # indices into FinalReport.findings
    severity: Severity
    blocked_by_controls: list[str] = []   # control names that genuinely stop this
    narrative: str


class RankedFinding(BaseModel):
    finding: Finding
    severity: Severity
    exploitability_notes: str        # chain-pass LLM commentary incl. mitigations


class DroppedFinding(BaseModel):
    """Audit-trail entry for a finding removed before the final report."""
    file: str
    line: int
    vuln_class: VulnClass
    title: str
    chunk_id: str
    reason: Literal["FALSE_POSITIVE", "VERIFY_ERROR", "DUPLICATE",
                    "UNCONFIRMED", "EXCLUDED", "GUARDRAIL_BLOCKED"]
    detail: str = ""                 # verdict_reason / error text / dedup reasoning
    canonical_idx: int | None = None # for DUPLICATE: index into FinalReport.findings


class ScopeEntry(BaseModel):
    """One analysis unit (chunk) in the scope appendix."""
    name: str
    kind: Literal["risk", "catchall", "specialist", "taint", "threat_fallback", "other"]
    files: list[str]


class ScanMetrics(BaseModel):
    """Coverage + verification stats rendered at the top of the report."""
    scan_id: str = ""
    module_name: str = ""
    start_ts: str = ""               # ISO 8601
    end_ts: str = ""
    duration_sec: float = 0.0
    total_files_in_scope: int = 0
    analyzed_files_unique: int = 0
    chunks_total: int = 0
    chunks_risk: int = 0
    chunks_catchall: int = 0
    chunks_specialist: int = 0
    # Per-chunk deep-dive outcome tally (default 0 keeps older reports valid).
    chunks_attempted: int = 0
    chunks_failed: int = 0           # failed / timed-out / guardrail-blocked
    errors_by_stage: dict[str, int] = {}   # coarse per-stage error-record counts
    errors_log_path: str = ""              # path to the per-run errors.jsonl
    loc_in_scope_by_language: dict[str, int] = {}
    loc_scanned_by_language: dict[str, int] = {}
    raw_findings_count: int = 0
    true_positive_count: int = 0
    false_positive_count: int = 0
    duplicate_count: int = 0
    # Token accounting (None → render "unavailable")
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    tokens_by_phase: dict[str, dict] | None = None
    # Scope appendix
    folders_scanned: list[str] = []
    scope: list[ScopeEntry] = []
    excluded: dict = {}

    # ── Process-wide counters (vvaharness.util.counters.COUNTERS), read once
    #    into these fields by the metrics builder. Declared here, all
    #    defaulted, so a payload serialized before these fields existed still
    #    validates. Stages bump/note the counters as the event happens; this
    #    class only names where the snapshot ends up. ──────────────────────
    s2_degraded: bool = False
    s2_threats_raw: int = 0
    s2_threats_truncated: int = 0
    s2_threats_promoted: int = 0
    s2_baseline_undisposed: list[str] = []
    s2_repo_kinds: list[str] = []
    s3_output_shape: str = ""              # "ids" | "paths" | "mixed" | ""
    s3_unknown_file_ids: int = 0
    s3_dropped_paths: int = 0
    s3_relocated_paths: int = 0
    s3_dropped_empty_chunks: int = 0
    s3_forced_coverage_files: int = 0
    s3_fallback_chunks_dropped: int = 0
    s3_cohesion_groups: int = 0
    s3_buckets: int = 0
    s4_findings_truncated: int = 0
    # VVAH-E004: deepagents-route calls refused pre-dispatch as over-ceiling.
    deepagents_oversize_prompts: int = 0
    # VVAH-E005: sdk/openai replies confirmed cut off by the output-token budget.
    llm_truncated_replies: int = 0
    # Per-kind chunk tally across the widened ScopeEntry.kind set (superset of
    # chunks_risk/chunks_catchall/chunks_specialist above, which stay for
    # back-compat with reports rendered before this field existed).
    chunks_by_kind: dict[str, int] = {}

    @property
    def coverage_pct(self) -> float:
        if not self.total_files_in_scope:
            return 0.0
        return self.analyzed_files_unique / self.total_files_in_scope * 100

    @property
    def verification_precision_pct(self) -> float:
        if not self.raw_findings_count:
            return 0.0
        return self.true_positive_count / self.raw_findings_count * 100


class FinalReport(BaseModel):
    repo_root: str
    repo_name: str | None = None     # repository_name from repos.txt/csv — used for the report title
    git_sha: str | None = None       # B9: HEAD at scan time; step 10 refuses on mismatch
    findings: list[RankedFinding]
    chains: list[Chain]
    dropped: list[DroppedFinding] = []
    raw_findings_count: int = 0      # pre-verification count
    metrics: ScanMetrics | None = None
    threat_model: ThreatModel | None = None
    app_profile: AppProfile | None = None
    # step3.catchall_mode=reachable_only — files NOT reviewed because they
    # weren't on any entry→…→sink call-graph path. Rendered as an appendix so
    # the report never silently truncates coverage.
    unreachable_files: list[str] = []
    summary: str
    degraded: bool = False
    degraded_reason: str = ""

    def to_markdown(self) -> str:
        tp = len(self.findings)
        fp = sum(1 for d in self.dropped if d.reason == "FALSE_POSITIVE")
        dup = sum(1 for d in self.dropped if d.reason == "DUPLICATE")
        # Undetermined verifications (unparseable reply / guardrail) are NOT
        # confirmed false positives — surface them so a degraded verification
        # pass is visible rather than silently folded into the FP count.
        verr = sum(1 for d in self.dropped
                   if d.reason in ("VERIFY_ERROR", "GUARDRAIL_BLOCKED"))
        precision = (tp / self.raw_findings_count * 100) if self.raw_findings_count else 0.0
        safe_title = re.sub(r"[<>`|\[\]]", "", str(self.repo_name or self.repo_root or ""))
        out = [
            f"# Agentic SAST — {safe_title}",
            "",
            "## Summary",
            _demote_md_headings(self.summary),
            "",
        ]
        if self.metrics:
            out.extend(self._render_metrics())
        out.extend(self._render_scan_health())
        if self.threat_model:
            out.extend(self._render_threat_model())
        out.extend([
            "## Verification",
            f"- Raw findings (pre-verification): {self.raw_findings_count}",
            f"- True positives (verified): {tp}",
            f"- False positives (dropped): {fp}",
            f"- Verifier errors (excluded — undetermined, not confirmed clean): {verr}",
            f"- Duplicates collapsed (all passes): {dup}",
            f"- Verification precision: {precision:.1f}%",
        ])
        # Exploit-verification tally, when EV live-tested at least one reported finding.
        # Counts findings IN THIS REPORT: a NOT_CONFIRMED finding the static verifier also
        # dropped is not here (only CONFIRMED is rescued from a static drop), so the
        # authoritative live-tested total is the S6 funnel log line, not this.
        _ev = [rf.finding.ev_status for rf in self.findings]
        ev_confirmed = _ev.count("CONFIRMED")
        ev_not = _ev.count("NOT_CONFIRMED")
        ev_inconc = _ev.count("INCONCLUSIVE")
        ev_tested = ev_confirmed + ev_not + ev_inconc
        if ev_tested:
            out.extend([
                f"- Exploit verification: {ev_confirmed} confirmed live, "
                f"{ev_not} not confirmed, {ev_inconc} requiring review "
                f"({ev_tested} live-tested)",
                f"  - {_EV_POSITIVE_ONLY_NOTE}",
            ])
        out.extend([
            "",
            f"## Findings ({len(self.findings)})",
            "",
        ])
        for i, rf in enumerate(self.findings, 1):
            f = rf.finding
            if f.cvss_score is not None:
                cvss = f"**{f.cvss_score:.1f}** ({f.cvss_rating}) — `{f.cvss_vector}`"
            elif f.cvss_vector:
                cvss = f"`{f.cvss_vector}`"
            else:
                cvss = "_not computed_"
            from vvaharness.report.cwe import cwe_for, cwe_name
            # Resolve a deterministic CWE: the finding's own token if present,
            # else the VulnClass→CWE fallback (None for unclassified "other").
            _cwe = cwe_for(f.cwe, f.vuln_class)
            _nm = cwe_name(_cwe) if _cwe else ""
            _cwe_label = (f"{_cwe}: {_nm}" if _nm else _cwe) if _cwe else ""
            out.extend([
                f"### {i}. [{rf.severity.value.upper()}] {_md_cell(f.title)}",
                f"**Class:** {_cwe_label or f.vuln_class.value}",
            ])
            if _cwe:
                _n = _cwe.split('-')[-1]
                out.append(
                    f"**CWE:** {_cwe_label} - "
                    f"https://cwe.mitre.org/data/definitions/{_n}.html")
            # Repo-controlled path: neutralise Markdown and fold backticks to
            # a U+02CB lookalike so a hostile filename cannot close this code
            # span (matching the Dropped-Findings / Unreachable-appendix
            # renderers). A backslash escape is inert inside a code span, so
            # folding is the only defence; the numeric :line-line suffix is
            # harness-controlled and stays outside the escaper so the report
            # parsers still read it.
            _file_span = _md_cell(f.file).replace(chr(96), chr(0x2CB))
            out.extend([
                f"**File:** `{_file_span}:{f.line_start}-{f.line_end}`",
                f"**CVSS 3.1:** {cvss}",
            ])
            if f.vsvs_score is not None:
                out.append(f"**VulContextSeverity:** `{f.vsvs_vector}` - "
                           f"**{f.vsvs_score:.1f} ({f.vsvs_rating})**")
            if f.offensive_priority:
                out.append(f"**OffensivePriority:** **{f.offensive_priority}** - "
                           f"{OFFENSIVE_LABELS.get(f.offensive_priority, '')} | "
                           f"*{f.offensive_reason}*")
            _vote_word = "run" if f.votes == 1 else "runs"
            out.append(f"**Confidence:** {f.confidence:.2f} "
                       f"({f.votes} {_vote_word} agreed)")
            if f.duplicates:
                # Duplicate paths are model-authored like f.file above — same
                # neutralisation, or a backtick could close the code span.
                refs = ", ".join(
                    f"`{_md_cell(d.file).replace(chr(96), chr(0x2CB))}:{d.line_start}"
                    + (f"-{d.line_end}`" if d.line_end and d.line_end != d.line_start
                       else "`")
                    for d in f.duplicates
                )
                out.append(f"**Also at:** {refs}")
            out.append("")
            if f.duplicates:
                out.extend([
                    f"*{len(f.duplicates)} additional call site(s) collapsed "
                    f"during dedup — same root cause; each location needs the "
                    f"same fix applied.*",
                    "",
                ])
            out.extend(["#### Description", _demote_md_headings(f.description), ""])
            if f.impact:
                out.extend(["#### Impact", _demote_md_headings(f.impact), ""])
            if f.exploit_scenario:
                out.extend(["#### Exploit scenario",
                            _demote_md_headings(f.exploit_scenario), ""])
            if f.preconditions:
                out.append("#### Preconditions")
                out.extend(f"- {_md_cell(p)}" for p in f.preconditions)
                out.append("")
            out.extend([
                "```",
                f.code_snippet,
                "```",
                "",
            ])
            if f.recommendation:
                out.extend(["#### How to fix",
                            _demote_md_headings(f.recommendation), ""])
            out.extend([f"**Exploitability:** "
                        f"{_demote_md_headings(rf.exploitability_notes)}", ""])
            if f.verdict:
                out.extend([
                    "#### Adversarial verification",
                    f"**Verdict:** {f.verdict} (confidence: "
                    f"{f.verdict_confidence}/10) — "
                    f"{_demote_md_headings(f.verdict_reason)}",
                    "",
                ])
            # Every finding EV live-tested gets a verdict block — CONFIRMED and the two
            # non-confirming outcomes alike — so the report shows what EV tried, not only
            # what it proved. Every finding EV touched gets a verdict — CONFIRMED,
            # NOT CONFIRMED, INCONCLUSIVE, or NOT TESTED (EV ran but never attacked this
            # one: unmapped / not observable — the reason is in ev_evidence). Only
            # ev_status None is skipped: that means EV did not run this scan at all, so a
            # verdict line would be noise. The "**Exploit Verification:**" inline line is
            # the SARIF-parseable carrier (report/enrich.py); its verdict word is the anchor.
            if f.ev_status in _EV_VERDICT_LABEL:
                verdict = _EV_VERDICT_LABEL[f.ev_status]
                reason = _demote_md_headings(f.ev_evidence) if f.ev_evidence else ""
                out.append("#### Exploit Verification")
                # EV's confidence in its live result: the judge's 0-10 (else tier-derived),
                # rendered on every outcome EV live-tested. Number only — for CONFIRMED the
                # method (deterministic-backed / agent-judged) is on the EV Method line just
                # below; the non-confirming outcomes have no "backing" to name. Labelled
                # "EV Confidence" (not bare "Confidence") for the same reason as EV Method /
                # EV CVSS: the finding already carries a static "**Confidence:**" line (a
                # 0-1 verdict confidence), and an unprefixed label would both read as that
                # and be swallowed by report.enrich's CONFIDENCE_LINE parser.
                conf_line = (f"**EV Confidence:** {f.ev_confidence_score}/10"
                             if f.ev_confidence_score is not None else None)
                if f.ev_status == "CONFIRMED":
                    # A confirmation's evidence IS the proof, so it stays on the verdict
                    # line where every reader and the SARIF parser already expect it.
                    out.extend([
                        f"**Exploit Verification:** {verdict}"
                        + (f" — {reason}" if reason else ""),
                        "",
                    ])
                    if conf_line:
                        out.extend([conf_line, ""])
                else:
                    # For the three non-confirming outcomes the reason is the whole
                    # message, so it gets its own labelled line rather than trailing an
                    # em dash after a word the reader has already misread. The tag says
                    # whether a rule or a model authored it.
                    out.extend([f"**Exploit Verification:** {verdict}", ""])
                    if conf_line:
                        out.extend([conf_line, ""])
                    if reason:
                        out.extend([
                            f"**Why:** {_EV_REASON_TAG.get(f.ev_reason_source, '')}{reason}",
                            "",
                        ])
                    out.extend([_EV_NOT_A_FP_NOTE, ""])
                # Method / CVSS / repro describe HOW something confirmed, so they exist only
                # for a CONFIRMED verdict; a non-confirming block is verdict + judge reason.
                if f.ev_status == "CONFIRMED":
                    if f.ev_method or f.ev_confidence:
                        out.extend([
                            f"**EV Method:** {f.ev_method or 'deterministic-backed'} "
                            f"({f.ev_confidence or 'medium'})",
                            "",
                        ])
                    if f.ev_cvss_score is not None:
                        # EV's own CVSS, scored by the judge from the observed impact —
                        # advisory (static's cvss_score owns ranking), shown for the reader.
                        # Labelled "EV CVSS" (not bare "CVSS") so report.enrich's static-CVSS
                        # line parser does not swallow it as the finding's ranking score.
                        out.extend([
                            f"**EV CVSS:** {f.ev_cvss_score}"
                            + (f" ({f.ev_cvss_rating})" if f.ev_cvss_rating else "")
                            + (f" `{f.ev_cvss_vector}`" if f.ev_cvss_vector else ""),
                            "",
                        ])
                    if f.ev_repro:
                        out.extend([f"**Repro:** `{_md_cell(f.ev_repro)}`", ""])
                    if f.ev_repro_detail:
                        out.extend(_render_repro_block(f.ev_repro_detail))
        if self.chains:
            out.extend(["## Exploit Chains", ""])
            for c in self.chains:
                steps_str = " → ".join(
                    f"#{idx+1} {_md_cell(self.findings[idx].finding.title)}"
                    for idx in c.steps
                )
                blocked = (
                    f"  \n**Blocked by:** "
                    f"{', '.join(_md_cell(x) for x in c.blocked_by_controls)}"
                    if c.blocked_by_controls else ""
                )
                out.extend([
                    # Chain titles are model-authored like finding titles —
                    # same neutralisation, or a title with a newline could
                    # terminate this heading and inject Markdown.
                    f"### [{c.severity.value.upper()}] {_md_cell(c.title)}",
                    f"**Path:** {steps_str}{blocked}",
                    "",
                    _demote_md_headings(c.narrative),
                    "",
                ])
        elif not self.degraded:
            out.extend([
                "## Exploit Chains",
                "",
                "No exploit chains were identified — the findings above are "
                "independent and do not combine into a multi-step path.",
                "",
            ])
        out.extend(["", "## Dropped Findings", ""])
        if self.dropped:
            _tag = {
                "FALSE_POSITIVE":    "FP",
                "UNCONFIRMED":       "UNCONFIRMED",
                "VERIFY_ERROR":      "VERIFY-ERR",
                "EXCLUDED":          "EXCLUDED",
                "GUARDRAIL_BLOCKED": "GUARDRAIL",
            }
            for d in self.dropped:
                if d.reason == "DUPLICATE":
                    tag = (f"DUP of #{d.canonical_idx + 1}"
                           if d.canonical_idx is not None
                           else "DUP (pre-verify)")
                else:
                    tag = _tag.get(d.reason, d.reason)
                out.append(f"- **[{tag}]** `{_md_cell(d.file).replace(chr(96), chr(0x2CB))}:{d.line}` "
                           f"{d.vuln_class.value} ({_md_cell(d.chunk_id)}) — "
                           f"{_md_cell(d.detail)}")
        else:
            out.append("_None._")
        out.append("")
        if self.metrics:
            out.extend(self._render_scope_appendix())
        if self.unreachable_files:
            out.extend(self._render_unreachable_appendix())
        return "\n".join(out)

    def _render_unreachable_appendix(self) -> list[str]:
        """Appendix listing files dropped by step3.catchall_mode=reachable_only."""
        # Split by coverage state rather than one blanket claim: the specialist lenses sweep source
        # files unconditionally, but ONLY source files -- a .env or Makefile here has no reviewer at
        # all, and an earlier version told the operator those "remain covered".
        # Each subsection is capped so a 10k-file monorepo doesn't bloat the report; the full list
        # lives in the s3 checkpoint.
        cap = 200
        covered = [f for f in self.unreachable_files if is_source(f)]
        not_reviewed = [f for f in self.unreachable_files if not is_source(f)]

        def _list(files: list[str]) -> list[str]:
            block = []
            for f in files[:cap]:
                # Repo-controlled file paths: neutralise Markdown the same way
                # the rest of this renderer does (_md_cell strips CR/LF and
                # escapes `|`), and additionally replace backticks so a
                # hostile filename cannot close this code span and inject
                # content into the coverage audit.
                block.append(f"- `{_md_cell(f).replace(chr(96), chr(0x2CB))}`")
            if len(files) > cap:
                block.append(f"- _… and {len(files) - cap} more (full list in "
                             f"the s3 checkpoint manifest)_")
            return block

        out = [
            "",
            "## Appendix — Files Not Sent for Catch-All Review (call-graph unreachable)",
            "",
            f"`step3.catchall_mode: reachable_only` dropped "
            f"**{len(self.unreachable_files)}** file(s) that were neither "
            f"forward-reachable from any entry point nor backward-reachable "
            f"from any sink on the call graph. They were **not** sent for "
            f"catch-all review. To include them, set "
            f"`step3.catchall_mode: all` in your config and re-scan — the "
            f"bundled `default.yaml` and `taint.yaml` both set "
            f"`reachable_only`, so pointing `--config` at either of them "
            f"will not change this.",
            "",
        ]
        if covered:
            out.append(f"### Still covered by specialist passes ({len(covered)})")
            out.append("")
            out.append("Source files — the logic-bug specialist (and any "
                       "other enabled lens) reviews them even though "
                       "catch-all did not.")
            out.append("")
            out.extend(_list(covered))
            out.append("")
        if not_reviewed:
            out.append(f"### Not reviewed by any pass ({len(not_reviewed)})")
            out.append("")
            out.append("Not source files by extension or name, so no "
                       "specialist lens sweeps them either — nobody reviewed "
                       "these.")
            out.append("")
            out.extend(_list(not_reviewed))
            out.append("")
        return out

    def _render_threat_model(self) -> list[str]:
        tm = self.threat_model
        out = ["## Threat Model", ""]
        if self.app_profile:
            ap = self.app_profile
            sens = ", ".join(s for s, ok in (
                ("PCI-scoped", ap.pci_scoped),
                ("processes PAN", ap.processes_pan),
                ("PII", ap.pii)) if ok) or "standard"
            out.extend([
                "### Application profile (CMDB)",
                # application_id (--application-id) / name / source are operator/CMDB
                # supplied, not tool-derived; escape them so a value with a newline or
                # `|` can't terminate this list/heading and inject Markdown into the
                # report (same neutralisation the rest of this renderer already uses).
                # The ID sits in a code span, so also fold backticks (as the
                # Dropped Findings renderer does) or the span could be closed.
                f"- ID: `{_md_cell(ap.application_id).replace(chr(96), chr(0x2CB))}`"
                f"  ({_md_cell(ap.name) or '-'})",
                f"- Externally facing: **{'YES' if ap.externally_facing else 'NO'}**",
                f"- Data sensitivity: {sens}",
                f"- Source: {_md_cell(ap.source)}",
                "",
            ])
        if tm.system_context:
            out.extend(["### System context", "",
                        _demote_md_headings(tm.system_context), ""])
        if tm.assets:
            out.extend(["### Assets", "",
                        "| Asset | Sensitivity | Description |",
                        "|---|---|---|"])
            for a in tm.assets:
                out.append(f"| {_md_cell(a.name)} | {_md_cell(a.sensitivity)} "
                           f"| {_md_cell(a.description)} |")
            out.append("")
        if tm.trust_boundaries:
            out.extend(["### Trust boundaries", ""])
            for b in tm.trust_boundaries:
                ra = ", ".join(_md_cell(x) for x in b.reachable_assets) or "-"
                out.append(f"- **{_md_cell(b.entry_point)}** — "
                           f"{_md_cell(b.crossing)} → {ra}")
            out.append("")
        if tm.threats:
            out.extend(["### Ranked threats", "",
                        "| ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Controls |",
                        "|---|---|---|---|---|---|---|---|"])
            for t in tm.threats:
                out.append(f"| {_md_cell(t.id)} | {_md_cell(t.threat)} | "
                           f"{_md_cell(t.actor)} | {_md_cell(t.surface)} | "
                           f"{_md_cell(t.asset)} | {_md_cell(t.impact)} | "
                           f"{_md_cell(t.likelihood)} | "
                           f"{_md_cell(t.controls) or '-'} |")
            out.append("")
        if tm.open_questions:
            out.extend(["### Open questions", ""])
            out.extend(f"- {_md_cell(q)}" for q in tm.open_questions)
            out.append("")
        return out

    # Fixed display order for the known chunk kinds; anything else present in
    # chunks_by_kind (a kind added after this list was written) is still
    # rendered, just appended after these.
    _CHUNK_KIND_LABELS = [
        ("risk", "risk"), ("catchall", "catch-all"), ("specialist", "specialist"),
        ("taint", "taint"), ("threat_fallback", "threat-fallback"), ("other", "other"),
    ]

    def _render_chunk_kind_line(self) -> str:
        m = self.metrics
        if m.chunks_by_kind:
            known = dict(self._CHUNK_KIND_LABELS)
            parts = [f"{label}={m.chunks_by_kind[key]}"
                     for key, label in self._CHUNK_KIND_LABELS if key in m.chunks_by_kind]
            parts += [f"{key}={v}" for key, v in m.chunks_by_kind.items()
                     if key not in known]
        else:
            # Legacy trio — populated on every report (including ones written
            # before chunks_by_kind existed), so a resumed old report still
            # renders a chunk breakdown.
            parts = [f"risk={m.chunks_risk}", f"catch-all={m.chunks_catchall}",
                     f"specialist={m.chunks_specialist}"]
        return f"- Chunks: {m.chunks_total} ({', '.join(parts)})"

    def _render_pipeline_diagnostics(self) -> list[str]:
        """Surfaces the stage counters read from the shared counter sink."""
        # Every counter defaults to zero both when its stage never ran and when it ran cleanly, and
        # the schema cannot tell those apart -- so a line is emitted only when its counter has
        # something to say, and this renders nothing at all when none of them do.
        m = self.metrics
        lines: list[str] = []

        if m.s2_degraded:
            lines.append(
                "- Threat model: **degraded** — the model call failed or "
                "returned no usable threats; ranking and baseline coverage "
                "for this scan fell back to the deterministic passes only."
            )
        if m.s3_output_shape:
            shape_label = {
                "ids": "id-based (file/entry-point/sink references)",
                "paths": "path-based",
                "mixed": "a mix of ids and paths",
            }.get(m.s3_output_shape, m.s3_output_shape)
            lines.append(f"- Chunk file references from the strategist: {shape_label}")

        if m.s2_threats_raw:
            lines.append(f"- Threats identified before ranking: {m.s2_threats_raw}")
        if m.s2_threats_truncated:
            lines.append(f"- Threats truncated by the prompt cap: {m.s2_threats_truncated}")
        if m.s2_threats_promoted:
            lines.append(
                "- Threats re-promoted after truncation to keep a trust "
                f"boundary covered: {m.s2_threats_promoted}"
            )
        if m.s2_baseline_undisposed:
            lines.append(
                "- Baseline checklist items with no threat or open question "
                f"disposing of them: {', '.join(m.s2_baseline_undisposed)}"
            )
        if m.s2_repo_kinds:
            lines.append(f"- Repository kind(s) detected: {', '.join(m.s2_repo_kinds)}")

        if m.s3_unknown_file_ids:
            lines.append(
                f"- Chunk file references that matched no known file id: "
                f"{m.s3_unknown_file_ids}"
            )
        if m.s3_dropped_paths:
            lines.append(f"- File references dropped (no matching file found): {m.s3_dropped_paths}")
        if m.s3_relocated_paths:
            lines.append(
                f"- **File references repaired by a suffix match: "
                f"{m.s3_relocated_paths}** — the strategist named a file that "
                "did not exist as given; verify these did not resolve onto "
                "the wrong file of the same name."
            )
        if m.s3_dropped_empty_chunks:
            lines.append(f"- Empty chunks dropped: {m.s3_dropped_empty_chunks}")
        if m.s3_forced_coverage_files:
            lines.append(
                # The backstop carries a skip list (_CATCHALL_SKIP_* in s3_decompose.py)
                # and catchall_mode: reachable_only prunes further, so files in those
                # classes can still reach zero reviewers. The docs retracted the
                # guarantee; this operator-facing label must not keep claiming it.
                f"- **Files added back by the coverage backstop: "
                f"{m.s3_forced_coverage_files}** — files no review pass would "
                "otherwise have reached."
            )
        if m.s3_fallback_chunks_dropped:
            lines.append(
                "- Fallback chunks skipped (already covered by a real "
                f"threat): {m.s3_fallback_chunks_dropped}"
            )
        if m.s3_cohesion_groups:
            lines.append(f"- Cohesion groups formed: {m.s3_cohesion_groups}")
        if m.s3_buckets:
            lines.append(f"- Chunks packed into: {m.s3_buckets} bucket(s)")

        if m.s4_findings_truncated:
            lines.append(
                f"- **Deep-dive findings discarded by the per-call cap: "
                f"{m.s4_findings_truncated}** — one or more calls produced "
                "more findings than step4.max_findings_per_run allows; only "
                "the highest-confidence findings from each call were kept."
            )

        if m.deepagents_oversize_prompts:
            lines.append(
                f"- **Calls refused as over-ceiling on the deepagents route: "
                f"{m.deepagents_oversize_prompts}** (VVAH-E004) — a prompt "
                "exceeded the route's context ceiling before dispatch, so the "
                "owning unit failed loudly instead of being silently "
                "truncated; its results are absent from this report."
            )

        if m.llm_truncated_replies:
            lines.append(
                f"- **LLM replies cut off by the output-token budget: "
                f"{m.llm_truncated_replies}** (VVAH-E005) — the reply and its "
                "one doubled-budget retry both hit the completion cap, so the "
                "owning unit failed loudly instead of a truncated reply "
                "passing as success; its results are absent from this report."
            )

        if not lines:
            return []
        return ["### Pipeline Diagnostics", ""] + lines + [""]

    def _render_metrics(self) -> list[str]:
        m = self.metrics
        lines = [
            "## Scan Metrics",
            "",
            f"- Scan ID: {m.scan_id}",
            f"- Module: {m.module_name}",
            f"- Start: {m.start_ts}",
            f"- End: {m.end_ts}",
            f"- Duration (sec): {m.duration_sec:.0f}",
            f"- Files in scope: {m.total_files_in_scope}",
            f"- Files analyzed (unique): {m.analyzed_files_unique}",
            f"- Coverage: {m.coverage_pct:.1f}%",
            self._render_chunk_kind_line(),
            f"- Tokens (prompt): {m.prompt_tokens if m.prompt_tokens is not None else 'unavailable'}",
            f"- Tokens (completion): {m.completion_tokens if m.completion_tokens is not None else 'unavailable'}",
            f"- Tokens (total): {m.total_tokens if m.total_tokens is not None else 'unavailable'}",
            "",
        ]
        if m.folders_scanned:
            lines.append(f"- Folders scanned: {len(m.folders_scanned)}")
        lines.extend(self._render_pipeline_diagnostics())
        if m.tokens_by_phase:
            lines.extend([
                "### Tokens by Phase",
                "",
                "_Prompt = fresh + cache-write (billable). Cache-read shown "
                "separately, NOT included in totals._",
                "",
                "| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) |",
                "|---|---:|---:|---:|---:|---:|---:|",
            ])
            grand = sum(b["prompt"] + b["completion"]
                        for b in m.tokens_by_phase.values()) or 1
            for ph, b in sorted(m.tokens_by_phase.items(),
                                key=lambda kv: -(kv[1]["prompt"] + kv[1]["completion"])):
                phase_label = "unscoped (outside stage wrapper)" if ph in {
                    "unlabeled", "unscoped"
                } else ph
                tot = b["prompt"] + b["completion"]
                lines.append(
                    f"| {phase_label} | {b['calls']} | {b['prompt']:,} | {b['completion']:,} "
                    f"| {tot:,} | {tot / grand * 100:.1f} | {b['cache_read']:,} |"
                )
            lines.append("")
        if m.loc_in_scope_by_language:
            lines.extend([
                "### Language LOC Coverage",
                "",
                "| Language | LOC in scope | LOC scanned | Coverage % |",
                "|---|---:|---:|---:|",
            ])
            for lang, loc_in in sorted(m.loc_in_scope_by_language.items()):
                loc_sc = m.loc_scanned_by_language.get(lang, 0)
                pct = (loc_sc / loc_in * 100) if loc_in else 0.0
                lines.append(f"| {lang} | {loc_in} | {loc_sc} | {pct:.1f} |")
            lines.append("")
        return lines

    def _render_scan_health(self) -> list[str]:
        """Surface deep-dive coverage loss and per-stage errors so a degraded
        run is not silently indistinguishable from a clean one. Renders nothing
        when the scan was healthy (no failed chunks, no logged errors) and the
        chain pass completed — so a clean report carries no noise.

        The chain-degraded banner (set when s8 falls back to the unranked
        report) is rendered here too via `self.degraded`."""
        from pathlib import Path
        m = self.metrics
        lines: list[str] = []
        degraded = getattr(self, "degraded", False)
        failed = m.chunks_failed if m else 0
        errs = (m.errors_by_stage if m else {}) or {}
        if not (degraded or failed or errs):
            return lines
        lines.extend(["## Scan Health", ""])
        if degraded:
            reason = getattr(self, "degraded_reason", "") or \
                "the exploit-chain pass could not be computed; findings are unranked"
            lines.append(f"- ⚠️ **DEGRADED** — {reason}")
        if failed:
            attempted = (m.chunks_attempted or m.chunks_total) if m else 0
            lines.append(f"- ⚠️ Degraded coverage: {failed}/{attempted} deep-dive "
                         "chunk(s) failed or timed out — their findings are "
                         "absent from this report.")
        if errs:
            brk = ", ".join(f"{s}={n}" for s, n in sorted(errs.items()))
            # "Non-fatal", not "unrecovered": `errs` is metrics.errors_by_stage,
            # built from errlog.counts_by_stage() at its include_recovered=True
            # default — EVERY errlog record, including transients the pipeline
            # already recovered from. The console ✓-line (util/status.py) says
            # "unrecovered" because it reports the include_recovered=False
            # subset; borrowing that word here would mislabel this larger
            # population, and the retired "Recoverable" wrongly promised the
            # errors could be recovered when this count includes ones that
            # were not.
            lines.append(f"- Non-fatal errors logged by stage: {brk}")
        if m and m.errors_log_path:
            lines.append(f"- Full error log: `{Path(m.errors_log_path).name}`")
        lines.append("")
        return lines

    def _render_scope_appendix(self) -> list[str]:
        m = self.metrics
        out = ["", "---", "", "## Appendix: Scan Scope", ""]

        if m.folders_scanned:
            out.append(f"### Folders scanned ({len(m.folders_scanned)})")
            out.append("")
            for d in m.folders_scanned:
                out.append(f"- `{d}/`")
            out.append("")

        ex = m.excluded or {}
        dd_dropped = (ex.get("config_dedup") or {}).get("dropped") or 0
        if dd_dropped or any(ex.get(k) for k in ("dirs", "exts", "globs",
                                                 "oversize", "symlinks")):
            n_total = (sum((ex.get("dirs") or {}).values())
                       + sum((ex.get("exts") or {}).values())
                       + sum((ex.get("globs") or {}).values())
                       + (ex.get("oversize") or 0)
                       + sum((ex.get("symlinks") or {}).values())
                       + dd_dropped)
            out.append(f"### Excluded from scan ({n_total} files)")
            out.append("")
            if ex.get("dirs"):
                out.append("**Folders** (matched `exclude_dirs`):")
                out.append("")
                for d, n in sorted(ex["dirs"].items(), key=lambda kv: -kv[1]):
                    out.append(f"- `{d}/` — {n} files")
                out.append("")
            if ex.get("exts"):
                out.append("**File types** (matched `exclude_exts`):")
                out.append("")
                for e, n in sorted(ex["exts"].items(), key=lambda kv: -kv[1]):
                    out.append(f"- `*{e}` — {n} files")
                out.append("")
            if ex.get("globs"):
                out.append("**Patterns** (matched `exclude_globs`):")
                out.append("")
                for g, n in sorted(ex["globs"].items(), key=lambda kv: -kv[1]):
                    out.append(f"- `{g}` — {n} files")
                out.append("")
            if ex.get("oversize"):
                out.append(f"**Oversize** (> `max_file_kb`): {ex['oversize']} files")
                out.append("")
                for path, sz in ex.get("oversize_files") or []:
                    out.append(f"- `{path}` — {sz / 1024:.0f} KB")
                if ex.get("oversize_files"):
                    out.append("")
            if ex.get("symlinks"):
                out.append("**Symlinks** (target resolves outside the repo — "
                           "not followed):")
                out.append("")
                for path, n in sorted(ex["symlinks"].items(),
                                      key=lambda kv: -kv[1]):
                    # Repo-controlled path in a code span: fold backticks too,
                    # or a hostile filename could close the span (same pattern
                    # as the unreachable-files appendix).
                    out.append(f"- `{_md_cell(path).replace(chr(96), chr(0x2CB))}`"
                               + (f" — {n} files" if n != 1 else ""))
                out.append("")
            dd = ex.get("config_dedup") or {}
            if dd.get("dropped"):
                out.append(
                    f"**Config dedup**: {dd['candidates']} config files -> "
                    f"{dd['clusters']} shape-clusters; kept {dd['kept_reps']} "
                    f"representatives + {dd['promoted']} promoted "
                    f"(suspicious value), dropped {dd['dropped']} "
                    f"near-duplicates.")
                out.append("")
                for c in dd.get("top_clusters") or []:
                    out.append(f"- `{c['sample']}` x{c['size']} "
                               f"(kept {len(c['reps'])}, dropped {c['dropped']})")
                if dd.get("promoted_files"):
                    out.append("")
                    out.append("Promoted (suspicious value not present in "
                               "cluster representative):")
                    out.append("")
                    for p, why in dd["promoted_files"]:
                        out.append(f"- `{p}` — `{why}`")
                out.append("")

        return out
