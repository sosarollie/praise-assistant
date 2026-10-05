#!/usr/bin/env python3
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
Reads a findings markdown that already contains CVSS 3.1 base vectors,
looks up the application in the CMDB CSV exports (application -> component
fallback with parent merge), then for each finding:

  1. appends the numeric CVSS 3.1 base score to the base-vector line
  2. inserts  **VulContextSeverity:** `<env-vector>` - **X.X (Rating)**
  3. inserts  **OffensivePriority:** **Pn** - <label> | *<reason>*

and finally emits a SARIF 2.1.0 file with cvss/vulContextSeverity/offensive properties.

Idempotent: re-running leaves the MD unchanged.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

from vvaharness import __version__ as _PKG_VERSION
from vvaharness.report.cvss import score as _cvss31_score
from vvaharness.report.cwe import cwe_for, cwe_label, cwe_name
from vvaharness.report.redact import redact_tree

csv.field_size_limit(2**31 - 1)

# Line regexes for parsing the findings markdown (finding header, location
# line, CWE/CVSS lines, etc.).
FINDING_HDR = re.compile(
    r"^[#\s\d.]*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)]\s+(.+)$"
)
LOCATION_LINE = re.compile(
    r"^`([^`]+?)(?::(\d+))?`\s+·\s+([^·]+?)\s+·\s+confidence\s+([0-9.]+)"
)
ALT_FILE_LINE = re.compile(
    r"^\*{0,2}File:\*{0,2}\s*`?([^`:\s][^`:]*?)(?::(\d+)(?:-\d+)?)?`?\s*$"
)
ALT_CLASS_LINE = re.compile(r"^\*{0,2}Class:\*{0,2}\s*`?([^`]+?)`?\s*$")
CWE_LINE = re.compile(r"^\*{0,2}CWE:\*{0,2}.*?\b(CWE-\d{1,5})\b", re.I)
CVSS_LINE = re.compile(r"^\*\*(?:CVSS|Base Vector).*?`([^`]+)`")
ALT_CVSS_LINE = re.compile(
    r"^CVSS\s*3\.[01].*?(CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH])"
)
# Detects a base score already appended to a CVSS line so re-enrichment is
# idempotent. The pipeline renderer (models.FinalReport.to_markdown) emits the
# score BEFORE the backticked vector as **X.X**, while the standalone CLI
# appends it AFTER the vector as `<vector>` - **X.X**. Match either position so
# we never double-append. The X.X inside the vector itself (CVSS:3.1) is never
# matched: it lives inside the backticks and is not bolded.
CVSS_SCORE_PRESENT = re.compile(
    r"(?:`[^`]+`.*?\b\d{1,2}\.\d\b)|(?:\*\*\d{1,2}\.\d\*\*)"
)
VSVS_LINE = re.compile(r"^\*?\*?VulContextSeverity:")
OFFENSIVE_LINE = re.compile(r"^\*?\*?(?:OffensivePriority|PentestPriority):")
OFFENSIVE_PARSE = re.compile(
    r"^\*?\*?(?:OffensivePriority|PentestPriority):\*?\*?\s*\*?\*?(P[1-4])\*?\*?\s*(?:[-—]\s*)?(.*)$"
)
CONFIDENCE_LINE = re.compile(
    r"^\*?\*?Confidence:\*?\*?\s*([0-9.]+)"
    r"(?:\s*\((\d+)\s+of\s+(?:N|\d+)\s+runs?\b[^)]*\))?",
    re.IGNORECASE,
)
# `**Also at:** \`file:line\`, \`file:line-line\`, ...` — emitted by
# models.FinalReport.to_markdown when a canonical absorbed other call sites
# during s7 dedup. Carried into SARIF as `relatedLocations`.
ALSO_AT_LINE = re.compile(r"^\*{0,2}Also at:\*{0,2}\s*(.+)$")
ALSO_AT_REF_RX = re.compile(r"`([^`]+):(\d+)(?:-(\d+))?`")
# `**Exploit Verification:** <VERDICT>` (+ `— <evidence>` inline for CONFIRMED, and
# `**Method:**`/`**CVSS:**`/`**Repro:**`) — emitted by models.FinalReport.to_markdown for
# every EV live-tested finding. Parsed here for two reasons only: to keep the block out of
# `description`, and to map the rendered labels back to the wire statuses. NO verdict —
# CONFIRMED included — reaches SARIF: results carry no verification output of any kind
# (see the note where `props` is built).
#
# The rendered labels are NOT the wire values: `models._scan._EV_VERDICT_LABEL` words the
# two non-verdicts so a reader does not take them for a judgement on the finding. Mapped
# back below so `ev_status` and the CONFIRMED gate keep the internal vocabulary, and the
# retired spellings stay accepted so an older report still parses.
EV_LABEL_TO_STATUS = {
    "CONFIRMED": "CONFIRMED",
    "NOT CONFIRMED": "NOT_CONFIRMED",
    "REQUIRES REVIEW": "INCONCLUSIVE",
    "INCONCLUSIVE": "INCONCLUSIVE",          # pre-rename reports
    "SAST-ONLY": "NOT_TESTED",
    "NOT TESTED": "NOT_TESTED",              # pre-rename reports
}
EV_LINE = re.compile(
    r"^\*{0,2}Exploit Verification:\*{0,2}\s*"
    r"(CONFIRMED|NOT CONFIRMED|INCONCLUSIVE|NOT TESTED|REQUIRES REVIEW|SAST-ONLY)\b"
    r"(?:\s*\([^)]*\))?"                     # the label's own beta/details parenthetical
    r"(?:\s*[-—]\s*(.*))?\s*$", re.I)
# `**Why:** [judge] <reason>` — the reason for a non-confirmed verdict, on its own line.
# The bracketed tag names what authored it: a deterministic rule, the classifier's triage
# pass, or the independent judge. Only consulted once an EV verdict line has been seen.
EV_WHY_LINE = re.compile(
    r"^\*{0,2}Why:\*{0,2}\s*(?:\[(rule|triage|judge)\]\s*)?(.*)$", re.I)
# The standing "not a false positive" note under a non-confirmed verdict. Recognised only
# so it stays out of `description` — it carries no per-finding data.
EV_NOTE_LINE = re.compile(r"^_Not a false positive: .*_\s*$")
# `**EV Confidence:** 9/10` — EV's 0-10 certainty in its live result, on every EV outcome
# (not just CONFIRMED). The "EV " prefix keeps it off the generic CONFIDENCE_LINE parser
# above (which matches a bare `**Confidence:**`, the finding's own static confidence) — the
# same guard EV Method / EV CVSS use. Parsed here so it stays out of `description`.
EV_CONFIDENCE_LINE = re.compile(r"^\*{0,2}EV Confidence:\*{0,2}\s*(\d{1,2})\s*/\s*10\b", re.I)
# Sub-lines of a CONFIRMED block, read only while `cur.ev_status == "CONFIRMED"` (below).
# The "EV " prefix keeps them off the generic CVSS_LINE parser above, which matches a bare
# `**CVSS:**` and would otherwise swallow EV's advisory score as the finding's ranking one.
EV_METHOD_LINE = re.compile(
    r"^\*{0,2}EV Method:\*{0,2}\s*([\w-]+)\s*\(([^)]*)\)\s*$", re.I)
# `**EV CVSS:** 9.8 (Critical) `CVSS:3.1/…`` — EV's advisory score (static's CVSS remains
# authoritative). Rating + vector are optional.
EV_CVSS_LINE = re.compile(
    r"^\*{0,2}EV CVSS:\*{0,2}\s*([0-9]+(?:\.[0-9]+)?)"
    r"(?:\s*\(([^)]*)\))?(?:\s*`([^`]+)`)?\s*$", re.I)
EV_REPRO_LINE = re.compile(r"^\*{0,2}Repro:\*{0,2}\s*`?([^`]+?)`?\s*$")
# `**Curl:** \`curl -i -X GET '...'\`` — the replayable form of the repro, emitted on
# its own line ahead of the collapsed `<details>` block. Matched here so the line is
# recognised and skipped rather than folded into `description`. Greedy so a payload
# containing a backtick still captures through to the closing one.
EV_CURL_LINE = re.compile(r"^\*{0,2}Curl:\*{0,2}\s*`(.+)`\s*$")
# The exact opening line of the EV repro block, matched WHOLE rather than as a substring.
# A substring test also fires on a rendered `code_snippet` that merely quotes a `<details>`
# element -- likely precisely on an XSS finding -- which opened a skip the producer's closer
# never ended and dropped every later finding from the SARIF. Kept as a literal, like the
# EV_* patterns above, so this module stays independent of exploit_verification; the pairing
# with the producer is pinned by a test instead of an import.
EV_REPRO_OPEN = "<details><summary>Replay this request</summary>"
EV_REPRO_CLOSE = "</details>"
DROPPED_BOUNDARY = re.compile(
    r"^#{0,3}\s*(?:Dropped Findings|Exploit Chains|Appendix)\b", re.IGNORECASE
)

# Temporal preset for AI-SAST findings: Exploit-code-maturity = Proof-of-Concept,
# Remediation-Level = Official-fix, Report-Confidence = Confirmed.
SAST_E, SAST_RL, SAST_RC = "P", "O", "C"

OFFENSIVE_LABELS = {
    "P1": "Externally Exploitable, No Auth",
    "P2": "Externally Exploitable, Obtainable Auth",
    "P3": "Internal Network / Privileged Position",
    "P4": "Code-Knowledge / Insider Dependent",
}

KW_CODE_KNOWLEDGE = (
    "source code is accessible", "access to the source", "access to the repo",
    "read access to the repo", "decompil", "reverse engineer",
    "if the attacker knows", "knowing the function", "knowledge of the source",
    "internal function name", "would need to know",
    "hardcoded credential", "hardcoded password", "hardcoded secret",
    "hardcoded token", "hard-coded credential", "hard-coded password",
    "hard-coded secret", "credential in source", "secret in source",
    "test credential", "qa credential", "qa password", "test password",
    "encryption key in source", "key hardcoded",
)
KW_INTERNAL = (
    "internal network", "intranet", "corporate network", "internal-only",
    "internal only", "back-office", "corporate sso", "enterprise sso",
    "enterprise idp", "behind sso", "behind the idp",
    "loopback", "127.0.0.1", "localhost", "local listener", "local user",
    "local access", "same host", "on the host",
    "service-to-service", "mtls", "behind api gateway", "behind the gateway",
    "vpn", "external partner", "third-party provisioned", 
    "log access", "db access", "database access",
    "mitm", "man-in-the-middle", "man in the middle",
    "compromised server", "compromise of", "control of the",
    "physical access", "adjacent network",
)
KW_HIGH_PRIV = (
    "super_admin", "super admin", "system_admin", "dist_admin",
    "with admin", "as an admin", "an admin user", "admin role",
    "privileged user", "privileged account",
    "requires admin", "admin-only", "admin privileges",
)
KW_OBTAINABLE_AUTH = (
    "self-registration", "self-registered", "self registration",
    "free signup", "sign up for", "any registered user",
    "any authenticated user", "any user account", "any valid user",
    "developer account", "portal user", "merchant account",
    "low-privilege user", "low privilege user", "lowest role",
)
KW_NO_AUTH = (
    "unauthenticated", "no authentication", "without authentication",
    "no auth required", "without auth", "pre-auth", "anonymous",
    "no credentials", "without credentials", "[allowanonymous]",
    "allowanonymous", "publicly accessible", "public endpoint",
)


# CMDB
@dataclass
class AppInfo:
    id: str = ""
    name: str = ""
    externally_facing: bool = False
    pci_scoped: bool = False
    processes_pan: bool = False
    pii: bool = False
    ext_raw: Optional[str] = None
    pci_raw: Optional[str] = None
    pan_raw: Optional[str] = None
    pii_raw: Optional[str] = None
    parent_app_id: Optional[str] = None
    source: str = "application"

    def cr(self) -> str:
        return "H" if (self.pci_scoped or self.processes_pan or self.pii) else "M"

    def ir(self) -> str:
        return "H" if (self.pci_scoped or self.processes_pan) else "M"

    def ar(self) -> str:
        return "M"

    def mav(self, base_av: str) -> str:
        return "A" if (not self.externally_facing and base_av == "N") else base_av

    def env_summary(self) -> str:
        return f"CR:{self.cr()}/IR:{self.ir()}/AR:{self.ar()} extFacing={self.externally_facing}"


def _yes(v: Optional[str]) -> bool:
    return v is not None and v.strip().lower() == "yes"


def _nz(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    v = v.strip()
    return v or None


def normalize_app_id(app_id: Optional[str]) -> Optional[str]:
    if app_id is None:
        return None
    s = re.sub(r"^0+", "", app_id.strip())
    return s or "0"


def _csv_col(hdr: dict, *names: str) -> int:
    for n in names:
        i = hdr.get(n.lower())
        if i is not None:
            return i
    return -1


def _cmdb_enrichment_differs(x: AppInfo, y: AppInfo) -> bool:
    """True when two CMDB rows that collide on ``normalize_app_id`` carry
    DIFFERENT enrichment signal — the fields that drive VulContextSeverity /
    exposure (the four decision bools, plus the parent they inherit from).
    Exact / benign duplicates (same key, same signal) return False so they stay
    silent; only a genuine conflict that would drift severity is worth a warning.
    Parents are compared normalised so '07' and '7' count as the same parent."""
    for f in ("externally_facing", "pci_scoped", "processes_pan", "pii"):
        if getattr(x, f) != getattr(y, f):
            return True
    return normalize_app_id(x.parent_app_id) != normalize_app_id(y.parent_app_id)


def load_cmdb_csv(path: str) -> dict[str, AppInfo]:
    out: dict[str, AppInfo] = {}
    if not path or not os.path.isfile(path):
        return out
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.reader(fh)
        # Skip license-header comment lines and blanks so the first DATA row
        # is treated as the CSV header (cmdb.csv carries an Apache-2.0 block).
        header = None
        for row in reader:
            if not row:
                continue
            first = (row[0] or "").lstrip()
            if first.startswith("#") or not any((c or "").strip() for c in row):
                continue
            header = row
            break
        if header is None:
            return out
        hdr = {h.strip().lower(): i for i, h in enumerate(header)}
        # Column lookup is by header NAME (case-insensitive). Canonical CMDB
        # header set: id, name, externally_facing, pci, pan, pii, parent_id.
        i_id = _csv_col(hdr, "id")
        i_name = _csv_col(hdr, "name")
        i_ext = _csv_col(hdr, "externally_facing")
        i_pci = _csv_col(hdr, "pci")
        i_pan = _csv_col(hdr, "pan")
        i_pii = _csv_col(hdr, "pii")
        i_par = _csv_col(hdr, "parent_id")
        if i_id < 0:
            raise ValueError(f"CMDB CSV missing 'id' column: {path}")

        def at(row, i):
            return row[i] if 0 <= i < len(row) else None

        for row in reader:
            rid = at(row, i_id)
            if not rid or not rid.strip():
                continue
            a = AppInfo()
            a.id = rid.strip()
            a.name = at(row, i_name) or ""
            # Decision fields are yes / no / empty. _nz() normalises blank →
            # None (so a child row can still inherit from parent_id via
            # _merge_with_parent); _yes() then maps yes→True, anything else
            # (no / blank / None) → False.
            a.ext_raw = _nz(at(row, i_ext))
            a.pci_raw = _nz(at(row, i_pci))
            a.pan_raw = _nz(at(row, i_pan))
            a.pii_raw = _nz(at(row, i_pii))
            a.externally_facing = _yes(a.ext_raw)
            a.pci_scoped = _yes(a.pci_raw)
            a.processes_pan = _yes(a.pan_raw)
            a.pii = _yes(a.pii_raw)
            a.parent_app_id = _nz(at(row, i_par))
            key = normalize_app_id(a.id)
            prior = out.get(key)
            if prior is not None and _cmdb_enrichment_differs(prior, a):
                # Two rows whose ids normalise to the same key (leading zeros /
                # surrounding whitespace, e.g. '042' vs '42') carry conflicting
                # enrichment. Silent last-wins would drift severity/exposure for
                # whichever app looks it up, so surface it loudly with BOTH raw
                # ids. Last-wins is preserved (behaviour unchanged) — the operator
                # must disambiguate the CMDB to resolve it.
                print(f"  [cmdb] WARN: id {a.id!r} normalises to the same key "
                      f"{key!r} as earlier id {prior.id!r}, but their "
                      f"exposure/sensitivity differ ({prior.env_summary()} vs "
                      f"{a.env_summary()}); last-wins — disambiguate the CMDB to "
                      f"avoid severity-enrichment drift", file=sys.stderr)
            out[key] = a
    return out


def _pick(own: Optional[AppInfo], parent: Optional[AppInfo],
          raw: str, val: str) -> bool:
    if own is not None and getattr(own, raw) is not None:
        return getattr(own, val)
    if parent is not None:
        return getattr(parent, val)
    return own is not None and getattr(own, val)


def _merge_with_parent(base: AppInfo, own: Optional[AppInfo],
                       parent: Optional[AppInfo], source: str) -> AppInfo:
    r = AppInfo()
    r.id = base.id
    r.name = base.name
    r.parent_app_id = own.parent_app_id if own else base.parent_app_id
    r.source = source
    r.externally_facing = _pick(own, parent, "ext_raw", "externally_facing")
    r.pci_scoped = _pick(own, parent, "pci_raw", "pci_scoped")
    r.processes_pan = _pick(own, parent, "pan_raw", "processes_pan")
    r.pii = _pick(own, parent, "pii_raw", "pii")
    return r


def lookup_app(app_id: str, cmdb: dict[str, AppInfo],
               cmdb_comp: dict[str, AppInfo]) -> Optional[AppInfo]:
    if not app_id:
        return None
    key = normalize_app_id(app_id)
    a = cmdb.get(key)
    c = cmdb_comp.get(key)

    if a is not None:
        any_blank = (a.pci_raw is None or a.pan_raw is None
                     or a.pii_raw is None or a.ext_raw is None)
        parent_id = a.parent_app_id or (c.parent_app_id if c else None)
        if any_blank and parent_id:
            p = cmdb.get(normalize_app_id(parent_id))
            if p and normalize_app_id(p.id) != key:
                return _merge_with_parent(a, a, p, f"application->parent {p.id}")
        a.source = "application"
        return a

    if c is None:
        return None
    p = cmdb.get(normalize_app_id(c.parent_app_id)) if c.parent_app_id else None
    return _merge_with_parent(
        c, c, p, f"component->parent {p.id}" if p else "component"
    )


# CVSS 3.1 base + environmental
def _cia(v: str) -> float:
    return {"H": 0.56, "L": 0.22, "N": 0.0}.get(v, -1.0)


def _req(v: str) -> float:
    return {"H": 1.5, "L": 0.5}.get(v, 1.0)


def _temporal_e(v: str) -> float:
    return {"U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}.get(v, 1.0)


def _temporal_rl(v: str) -> float:
    return {"O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}.get(v, 1.0)


def _temporal_rc(v: str) -> float:
    return {"U": 0.92, "R": 0.96, "C": 1.0}.get(v, 1.0)


def round_up1(x: float) -> float:
    n = int(round(x * 100000))
    if n % 10000 == 0:
        return n / 100000.0
    return (n // 10000 + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    m: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            m[k.strip().upper()] = v.strip().upper()
    return m


def cvss31_base_score(vector: Optional[str]) -> float:
    """Return the canonical CVSS 3.1 base score, or this module's -1 sentinel."""
    score = _cvss31_score(vector)
    return score if score is not None else -1.0


@dataclass
class VsvsResult:
    vector: str
    score: float
    rating: str


def qualitative(s: float) -> str:
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    if s >= 0.1:
        return "Low"
    return "None"


def _env_vector(base: str, mav: str, app: AppInfo) -> str:
    prefix = base if base.startswith("CVSS:") else f"CVSS:3.1/{base}"
    return (f"{prefix}/E:{SAST_E}/RL:{SAST_RL}/RC:{SAST_RC}"
            f"/CR:{app.cr()}/IR:{app.ir()}/AR:{app.ar()}/MAV:{mav}")


def vsvs_score(base_vector: Optional[str], app: Optional[AppInfo]) -> Optional[VsvsResult]:
    if not base_vector or app is None:
        return None
    m = parse_vector(base_vector)
    av, ac, pr, ui = m.get("AV"), m.get("AC"), m.get("PR"), m.get("UI")
    s, c, i, a = m.get("S"), m.get("C"), m.get("I"), m.get("A")
    if None in (av, ac, pr, ui, s, c, i, a):
        return None
    mav = app.mav(av)
    scope_changed = s == "C"
    mav_v = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(mav, -1.0)
    ac_v = {"L": 0.77, "H": 0.44}.get(ac, -1.0)
    pr_v = {"N": 0.85,
            "L": 0.68 if scope_changed else 0.62,
            "H": 0.50 if scope_changed else 0.27}.get(pr, -1.0)
    ui_v = {"N": 0.85, "R": 0.62}.get(ui, -1.0)
    c_v, i_v, a_v = _cia(c), _cia(i), _cia(a)
    cr_v, ir_v, ar_v = _req(app.cr()), _req(app.ir()), _req(app.ar())
    if min(mav_v, ac_v, pr_v, ui_v, c_v, i_v, a_v) < 0:
        return None
    e_v = _temporal_e(SAST_E)
    rl_v = _temporal_rl(SAST_RL)
    rc_v = _temporal_rc(SAST_RC)
    # CVSS 3.1 environmental scoring caps MISS at 0.915 before modified impact.
    miss = min(1 - (1 - cr_v * c_v) * (1 - ir_v * i_v) * (1 - ar_v * a_v), 0.915)
    m_impact = (7.52 * (miss - 0.029) - 3.25 * math.pow(miss * 0.9731 - 0.02, 13)
                if scope_changed else 6.42 * miss)
    if m_impact <= 0:
        return VsvsResult(_env_vector(base_vector, mav, app), 0.0, "None")
    m_exploit = 8.22 * mav_v * ac_v * pr_v * ui_v
    raw = 1.08 * (m_impact + m_exploit) if scope_changed else m_impact + m_exploit
    mod_base = round_up1(min(raw, 10.0))
    env = round_up1(mod_base * e_v * rl_v * rc_v)
    return VsvsResult(_env_vector(base_vector, mav, app), env, qualitative(env))


# OffensivePriority
def _contains_any(haystack: str, needles) -> bool:
    return any(n in haystack for n in needles)


@dataclass
class Finding:
    severity: str = ""
    title: str = ""
    file: Optional[str] = None
    line_no: int = 1
    category: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[str] = None
    cvss_score: float = -1.0
    description: str = ""
    vsvs_vector: Optional[str] = None
    vsvs_score: float = -1.0
    vsvs_rating: Optional[str] = None
    offensive_priority: Optional[str] = None
    offensive_reason: Optional[str] = None
    confidence: float = -1.0
    votes: int = 0
    # Exploit-verification stamp (parsed from the "**Exploit Verification:**" MD line).
    ev_status: Optional[str] = None
    ev_reason_source: str = ""      # "rule" | "triage" | "judge", from the `Why:` tag
    ev_confidence_score: Optional[int] = None   # EV's 0-10, from the `**EV Confidence:**` line
    ev_evidence: str = ""
    ev_repro: str = ""
    ev_curl: str = ""
    ev_method: str = ""
    ev_confidence: str = ""
    ev_cvss_score: Optional[float] = None
    ev_cvss_rating: str = ""
    ev_cvss_vector: str = ""
    # Additional call sites collapsed into this canonical by s7_dedup.
    # Emitted as SARIF `relatedLocations` and rendered in markdown as an "Also at:" list.

    also_at: list[tuple[str, int, int]] = field(default_factory=list)


def offensive_priority_for(title: str, category: Optional[str],
                         description: str, cvss_vector: Optional[str],
                         app: Optional[AppInfo]) -> tuple[str, str]:
    """Pure (priority, reason) — model-agnostic, called by
    pipeline._enrich_findings (post-s7) and by compute_offensive_priority()
    below for the standalone CLI path."""
    body = " ".join(x or "" for x in (title, category, description)).lower()
    v = parse_vector(cvss_vector) if cvss_vector else {}
    av = v.get("AV", "N")
    pr = v.get("PR", "L")
    pr_explicit = "PR" in v
    ac = v.get("AC", "L")

    cmdb_external = app is not None and app.externally_facing
    cmdb_internal = app is not None and not app.externally_facing

    code_knowledge = (_contains_any(body, KW_CODE_KNOWLEDGE)
                      or (category and "hardcoded" in category.lower()))
    internal_net = (cmdb_internal or av in ("A", "L", "P")
                    or _contains_any(body, KW_INTERNAL))
    high_priv = pr == "H" or _contains_any(body, KW_HIGH_PRIV)
    obtainable_auth = pr == "L" or _contains_any(body, KW_OBTAINABLE_AUTH)
    # An explicit PR:L/PR:H in the vector means auth IS required — it vetoes a
    # stray "unauthenticated"/"public" keyword in the prose (which usually
    # describes the endpoint class, not the privilege the verifier scored), so
    # a PR:L finding is never mislabeled as the top unauthenticated tier.
    pr_requires_auth = pr_explicit and pr in ("L", "H")
    no_auth = (not pr_requires_auth) and (
        _contains_any(body, KW_NO_AUTH)
        or (pr == "N" and not obtainable_auth and not high_priv))
    internet_reachable = (av == "N" and not internal_net and cmdb_external)
    exposure_unknown = app is None and av == "N" and not internal_net

    why: list[str] = []
    if code_knowledge:
        prio = "P4"
        why.append("requires source-code / insider knowledge")
        if cmdb_internal:
            why.append("app not externally facing (CMDB)")
        elif av != "N":
            why.append(f"AV:{av}")
    elif exposure_unknown and not high_priv:
        prio = "P3"
        why.append("exposure unverified — no CMDB context")
        why.append(f"AV:{av} (network-routable; internet exposure unconfirmed)")
    elif not internet_reachable or high_priv:
        prio = "P3"
        if cmdb_internal:
            why.append("app not externally facing (CMDB)")
        elif av != "N":
            why.append(f"AV:{av} (non-network)")
        elif internal_net:
            why.append("internal-network position required")
        if high_priv:
            why.append("PR:H - high-privilege auth required" if pr == "H"
                       else "admin/privileged role required")
        if not why:
            why.append("internal network / privileged position required")
    elif no_auth:
        prio = "P1"
        why.append("internet-facing" + (" (CMDB)" if cmdb_external else ""))
        why.append(f"AV:{av} - unauthenticated"
                   + (f" (PR:{pr})" if pr_explicit else ""))
    else:
        prio = "P2"
        why.append("internet-facing" + (" (CMDB)" if cmdb_external else ""))
        why.append(f"PR:{pr} - auth required but obtainable")

    if ac == "H" and prio in ("P1", "P2"):
        why.append("AC:H - complex preconditions")

    return prio, "; ".join(why)


def compute_offensive_priority(f: Finding, app: Optional[AppInfo]) -> None:
    f.offensive_priority, f.offensive_reason = offensive_priority_for(
        f.title, f.category, f.description, f.cvss, app)


# MD annotation (idempotent)
def annotate_md_cvss_vsvs(md_path: str, app: Optional[AppInfo]) -> bool:
    with open(md_path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    out: list[str] = []
    changed = False
    dropped = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if not dropped and DROPPED_BOUNDARY.search(line):
            dropped = True

        vector = None
        ccsec = False
        cv = CVSS_LINE.search(line)
        if cv and not VSVS_LINE.search(line):
            vector = cv.group(1)
            ccsec = True
        else:
            acv = ALT_CVSS_LINE.search(line)
            if acv:
                vector = acv.group(1)

        if vector is None or dropped:
            out.append(line)
            i += 1
            continue

        if ccsec:
            base = cvss31_base_score(vector)
            if base >= 0 and not CVSS_SCORE_PRESENT.search(line):
                line = f"{line} - **{base:.1f}**"
                changed = True
        out.append(line)

        j = i + 1
        while j < len(lines) and lines[j].strip() == "":
            j += 1
        next_is_vsvs = j < len(lines) and VSVS_LINE.search(lines[j])
        if app is not None:
            v = vsvs_score(vector, app)
            if v is not None:
                vsvs_line = (
                    f"**VulContextSeverity:** `{v.vector}` - **{v.score:.1f} ({v.rating})**"
                    if ccsec else
                    f"VulContextSeverity: {v.score:.1f} ({v.rating}) - {v.vector}"
                )
                out.append("")
                out.append(vsvs_line)
                if next_is_vsvs:
                    if lines[j] != vsvs_line:
                        changed = True
                    i = j
                else:
                    changed = True
        i += 1

    if changed:
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    return changed


def annotate_md_offensive(md_path: str, findings: list[Finding]) -> bool:
    if not findings:
        return False
    with open(md_path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    out: list[str] = []
    changed = False
    dropped = False
    f_idx = -1
    done = [False] * len(findings)

    for i, line in enumerate(lines):
        if not dropped and DROPPED_BOUNDARY.search(line):
            dropped = True
        if not dropped and FINDING_HDR.search(line):
            f_idx += 1
        out.append(line)
        if dropped or f_idx < 0 or f_idx >= len(findings) or done[f_idx]:
            continue

        is_vsvs = bool(VSVS_LINE.search(line))
        is_cvss = (not is_vsvs and not OFFENSIVE_LINE.search(line)
                   and (CVSS_LINE.search(line) or ALT_CVSS_LINE.search(line)))
        j = i + 1
        while j < len(lines) and lines[j].strip() == "":
            j += 1
        nxt = lines[j] if j < len(lines) else ""
        at_insert = is_vsvs or (is_cvss and not VSVS_LINE.search(nxt))
        if not at_insert:
            continue

        done[f_idx] = True
        if OFFENSIVE_LINE.search(nxt):
            continue

        f = findings[f_idx]
        if not f.offensive_priority:
            continue
        ccsec = line.startswith("**")
        label = OFFENSIVE_LABELS.get(f.offensive_priority, "")
        out.append("")
        out.append(
            f"**OffensivePriority:** **{f.offensive_priority}** - {label} | *{f.offensive_reason}*"
            if ccsec else
            f"OffensivePriority: {f.offensive_priority} - {label} ({f.offensive_reason})"
        )
        changed = True

    if changed:
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    return changed


# MD parse -> Findings
def parse_findings(md_path: str, app: Optional[AppInfo]) -> list[Finding]:
    with open(md_path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    findings: list[Finding] = []
    cur: Optional[Finding] = None
    desc: list[str] = []
    in_details = False

    def flush():
        nonlocal cur
        if cur is not None:
            cur.description = "\n".join(desc).strip()
            findings.append(cur)
        cur = None

    for line in lines:
        # `<details>` holds the EV repro (curl + captured response), whose body is
        # verbatim target output. Skip the whole block FIRST -- ahead of the boundary
        # and header checks below -- so a response-body line that happens to look like
        # a `Dropped Findings`/`Appendix` boundary or a `[INFO] ...` finding header
        # cannot truncate the report or inject a finding. The fallthrough at the bottom
        # of this loop would otherwise also fold the code fences and body into
        # `description`, and from there into every EV finding's SARIF description. The
        # machine-readable parts are lifted from the `**Curl:**`/`**Repro:**` lines
        # emitted above it. BOTH tags are matched as WHOLE lines, so a `code_snippet`
        # quoting a `<details>` element cannot open a block and an inline tag cannot close
        # one. A body line that IS the closing tag is stopped at the producer, which masks
        # the tags in target-authored text (`verify.repro._DETAILS_TAG_RX`) — both halves
        # are load-bearing.
        if in_details:
            if line.strip() == EV_REPRO_CLOSE:
                in_details = False
            continue
        if line.strip() == EV_REPRO_OPEN:
            in_details = True
            continue
        if DROPPED_BOUNDARY.search(line):
            flush()
            break
        h = FINDING_HDR.search(line)
        if h:
            flush()
            sev = h.group(1)
            cur = Finding(severity=sev, title=h.group(2).strip())
            desc = []
            continue
        if cur is None:
            continue

        if cur.file is None:
            loc = LOCATION_LINE.search(line)
            if loc:
                cur.file = loc.group(1)
                cur.line_no = int(loc.group(2)) if loc.group(2) else 1
                cur.category = loc.group(3).strip()
                continue
            floc = ALT_FILE_LINE.search(line)
            if floc:
                cur.file = floc.group(1).strip()
                cur.line_no = int(floc.group(2)) if floc.group(2) else 1
                continue
        if cur.category is None:
            cls = ALT_CLASS_LINE.search(line)
            if cls:
                cur.category = cls.group(1).strip()
                continue
        if cur.cwe is None:
            cw = CWE_LINE.search(line)
            if cw:
                cur.cwe = cw.group(1).upper()
                continue
        if cur.cvss is None:
            vec = None
            cv = CVSS_LINE.search(line)
            if cv and not VSVS_LINE.search(line):
                vec = cv.group(1)
            else:
                acv = ALT_CVSS_LINE.search(line)
                if acv:
                    vec = acv.group(1)
            if vec:
                cur.cvss = vec
                cur.cvss_score = cvss31_base_score(vec)
                if app is not None:
                    v = vsvs_score(vec, app)
                    if v:
                        cur.vsvs_vector = v.vector
                        cur.vsvs_score = v.score
                        cur.vsvs_rating = v.rating
                continue
        if VSVS_LINE.search(line):
            continue
        if OFFENSIVE_LINE.search(line):
            pm = OFFENSIVE_PARSE.search(line)
            if pm:
                cur.offensive_priority = pm.group(1)
                cur.offensive_reason = (pm.group(2) or line).strip()
            continue
        cm = CONFIDENCE_LINE.search(line)
        if cm:
            try:
                cur.confidence = float(cm.group(1))
            except ValueError:
                pass
            if cm.group(2):
                cur.votes = int(cm.group(2))
            continue
        aa = ALSO_AT_LINE.search(line)
        if aa:
            for m in ALSO_AT_REF_RX.finditer(aa.group(1)):
                lo = int(m.group(2))
                hi = int(m.group(3)) if m.group(3) else lo
                cur.also_at.append((m.group(1).strip(), lo, hi))
            continue
        ev = EV_LINE.search(line)
        if ev:
            # Normalise the rendered label back to the finding vocabulary so the CONFIRMED
            # gate below and any downstream comparison match. Only CONFIRMED goes on to
            # collect method/CVSS/repro; none of the verdicts reaches SARIF (see the note
            # where `props` is built). Every verdict is recognised here so the line is kept
            # out of `description`.
            label = ev.group(1).upper()
            cur.ev_status = EV_LABEL_TO_STATUS.get(label, label.replace(" ", "_"))
            cur.ev_evidence = (ev.group(2) or "").strip()
            continue
        if cur.ev_status:
            # The confidence line rides on every EV outcome, so it is matched here — ahead
            # of the CONFIRMED-only and non-confirmed-only branches below — and kept out of
            # `description` either way.
            ec = EV_CONFIDENCE_LINE.search(line)
            if ec:
                cur.ev_confidence_score = int(ec.group(1))
                continue
        if cur.ev_status and cur.ev_status != "CONFIRMED":
            # A non-confirming block is verdict + `Why:` + the standing note. Both extra
            # lines are recognised here or they land in `description`, which is how the
            # EV block polluted SARIF descriptions before it was parsed at all.
            why = EV_WHY_LINE.search(line)
            if why:
                cur.ev_reason_source = (why.group(1) or "").lower()
                cur.ev_evidence = (why.group(2) or "").strip()
                continue
            if EV_NOTE_LINE.search(line):
                continue
        if cur.ev_status == "CONFIRMED":
            evm = EV_METHOD_LINE.search(line)
            if evm:
                cur.ev_method = evm.group(1).strip().lower()
                cur.ev_confidence = evm.group(2).strip().lower()
                continue
            evc = EV_CVSS_LINE.search(line)
            if evc:
                try:
                    cur.ev_cvss_score = float(evc.group(1))
                except (TypeError, ValueError):
                    cur.ev_cvss_score = None
                cur.ev_cvss_rating = (evc.group(2) or "").strip()
                cur.ev_cvss_vector = (evc.group(3) or "").strip()
                continue
            if not cur.ev_curl:
                cl = EV_CURL_LINE.search(line)
                if cl:
                    cur.ev_curl = cl.group(1).strip()
                    continue
            if not cur.ev_repro:
                rp = EV_REPRO_LINE.search(line)
                if rp:
                    cur.ev_repro = rp.group(1).strip()
                    continue
        if line.startswith("---") or line.startswith("# "):
            flush()
            desc = []
            continue
        if not line.startswith("**Repo:") and not line.startswith("### "):
            desc.append(line)

    flush()
    return findings


# SARIF
# Stable identity for the CWE taxonomy component so result `taxa[].toolComponent`
# references resolve against `tool.driver.supportedTaxonomies`. Fixed literal
# (not derived) — it must stay constant across runs for consumers to correlate.
CWE_TAXONOMY_GUID = "b7c8d9e0-1f2a-3b4c-5d6e-7f8090a1b2c3"


def _driver_rules(findings: list["Finding"], rule_ids: list[str]) -> list[dict]:
    """One reportingDescriptor per distinct emitted ruleId, so every
    result.ruleId resolves against tool.driver.rules[]. Keyed on the SAME
    namespace the results use (category, else severity) — non-breaking; we do
    not change ruleId. shortDescription is borrowed from a representative CWE
    name when the rule's findings carry one."""
    # representative CWE name per rule_id (first finding that has one wins).
    rep_name: dict[str, str] = {}
    for f in findings:
        rid = f.category or f.severity.lower()
        eff = cwe_for(f.cwe, f.category)
        if rid and rid not in rep_name and eff:
            nm = cwe_name(eff)
            if nm:
                rep_name[rid] = nm
    rules = []
    for rid in rule_ids:
        desc: dict = {"id": rid, "name": rid}
        if rid in rep_name:
            desc["shortDescription"] = {"text": rep_name[rid]}
        rules.append(desc)
    return rules


def _cwe_taxonomy(findings: list["Finding"]) -> dict:
    ids = sorted({c for c in (cwe_for(f.cwe, f.category) for f in findings) if c},
                 key=lambda c: int(c.split("-")[-1]))
    taxa = []
    for cid in ids:
        nm = cwe_name(cid)
        n = cid.split("-")[-1]
        t: dict = {
            "id": cid,
            "helpUri": f"https://cwe.mitre.org/data/definitions/{n}.html",
        }
        if nm:
            t["name"] = nm
            t["shortDescription"] = {"text": nm}
        taxa.append(t)
    return {
        "guid": CWE_TAXONOMY_GUID,
        "name": "CWE",
        "organization": "MITRE",
        "shortDescription": {"text": "The MITRE Common Weakness Enumeration"},
        "informationUri": "https://cwe.mitre.org/",
        "taxa": taxa,
    }


def _sarif_level(sev: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error",
            "MEDIUM": "warning"}.get(sev, "note")


def _security_severity(f: Finding) -> str:
    if f.cvss_score >= 0:
        return f"{f.cvss_score:.1f}"
    return {"CRITICAL": "9.0", "HIGH": "7.0",
            "MEDIUM": "4.0", "LOW": "0.1"}.get(f.severity, "0.0")


def _cvss_rating(f: Finding) -> str:
    s = f.cvss_score if f.cvss_score >= 0 else float(_security_severity(f))
    return qualitative(s)


def generate_sarif(md_path: str, findings: list[Finding],
                   app_id: str, app: Optional[AppInfo], out_path: str,
                   scan_health: Optional[dict] = None) -> None:
    results = []
    rule_ids: list[str] = []          # distinct emitted ruleIds, in first-seen order
    for f in findings:
        rule_id = f.category or f.severity.lower()
        if rule_id and rule_id not in rule_ids:
            rule_ids.append(rule_id)
        score_txt = f" {f.cvss_score:.1f}" if f.cvss_score >= 0 else ""
        msg = f.title + (f"  [CVSS{score_txt}: {f.cvss}]" if f.cvss else "")
        full = f.description[:4000] + "…" if len(f.description) > 4000 else f.description
        props: dict = {
            "severity": f.severity.lower(),
            "security-severity": _security_severity(f),
            "cvssRating": _cvss_rating(f),
            "category": f.category,
            "cvssVector": f.cvss,
        }
        # Deterministic CWE: parsed token if present, else VulnClass fallback.
        eff_cwe = cwe_for(f.cwe, f.category)
        if eff_cwe:
            props["cwe"] = cwe_label(eff_cwe)
            props["cweId"] = eff_cwe
            nm = cwe_name(eff_cwe)
            if nm:
                props["cweName"] = nm
        if f.cvss_score >= 0:
            props["cvssScore"] = round(f.cvss_score, 1)
        if f.vsvs_score >= 0:
            props["vulContextSeverityVector"] = f.vsvs_vector
            props["vulContextSeverityScore"] = round(f.vsvs_score, 1)
            props["vulContextSeverityRating"] = f.vsvs_rating
        if f.offensive_priority:
            props["offensivePriority"] = f.offensive_priority
            props["offensivePriorityLabel"] = OFFENSIVE_LABELS.get(f.offensive_priority, "")
            props["offensivePriorityReason"] = f.offensive_reason
        # No exploit-verification entry here on purpose. SARIF results carry no
        # verification output of any kind: the static verifier's verdict has no key or
        # property either, so a dedicated EV block would make live confirmation look
        # like the more authoritative of the two — the reverse of how they rank. Both
        # verdicts live in the Markdown report, which is where a reader compares them.
        if f.confidence >= 0:
            props["confidence"] = round(f.confidence, 2)
            if f.votes:
                props["votes"] = f.votes
        props["description"] = full

        result: dict = {
            "ruleId": rule_id,
            "level": _sarif_level(f.severity),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file or "unknown"},
                    "region": {"startLine": f.line_no},
                }
            }],
            "properties": props,
        }
        if eff_cwe:
            result["taxa"] = [{
                "toolComponent": {"name": "CWE", "guid": CWE_TAXONOMY_GUID},
                "id": eff_cwe,
            }]
        if f.also_at:
            related = []
            for uri, lo, hi in f.also_at:
                region: dict = {"startLine": lo}
                if hi and hi != lo:
                    region["endLine"] = hi
                related.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": region,
                    },
                    "message": {
                        "text": "Additional call site — collapsed during "
                                "dedup; same root cause as the primary "
                                "location and needs the same fix.",
                    },
                })
            result["relatedLocations"] = related
            props["dedupRelatedLocationCount"] = len(related)
        if f.cvss_score >= 0:
            # SARIF result.rank is a 0.0–100.0 priority scale; the 0–10 CVSS
            # base score (exposed verbatim as properties.cvssScore /
            # security-severity) is scaled up to match the spec's range.
            result["rank"] = round(f.cvss_score * 10.0, 1)
        results.append(result)

    run_props = {"applicationId": app_id}
    if app:
        run_props["cmdbSource"] = app.source
        run_props["applicationName"] = app.name

    run: dict = {
        "tool": {"driver": {
            "name": "Agentic SAST",
            "version": _PKG_VERSION,
            # Catalog of the ruleIds the results reference, and the taxonomy
            # those results' taxa[] resolve against.
            "rules": _driver_rules(findings, rule_ids),
            "supportedTaxonomies": [{"guid": CWE_TAXONOMY_GUID}],
        }},
        "taxonomies": [_cwe_taxonomy(findings)],
        "properties": run_props,
        "results": results,
    }
    # When scan-health is supplied, make a degraded run observably distinct from
    # a clean one (a clean run still emits executionSuccessful=true + no notes).
    # Omitted entirely when scan_health is None → default output byte-identical.
    if scan_health is not None:
        notifications = []
        for stg, n in sorted((scan_health.get("errors_by_stage") or {}).items()):
            # "Non-fatal", not "unrecovered": these counts are the caller's
            # metrics.errors_by_stage (errlog.counts_by_stage() at its
            # include_recovered=True default), so they include transients the
            # pipeline already recovered from — the console's "unrecovered"
            # wording names the include_recovered=False subset and would
            # misdescribe this population. This string must agree with the
            # report's Scan Health line (models/_scan.py) since both render
            # the same counts.
            notifications.append({
                "level": "warning",
                "message": {"text": f"{stg}: {n} non-fatal error(s) logged"},
            })
        cf = int(scan_health.get("chunks_failed", 0) or 0)
        if cf:
            notifications.append({
                "level": "warning",
                "message": {"text": f"{cf} deep-dive chunk(s) failed or timed "
                                    "out; their findings are absent"},
            })
        if scan_health.get("degraded"):
            notifications.append({
                "level": "warning",
                "message": {"text": "Exploit-chain analysis could not be "
                                    "computed; findings are unranked"},
            })
        invocation: dict = {
            "executionSuccessful": bool(scan_health.get("executionSuccessful", True)),
        }
        if notifications:
            invocation["toolExecutionNotifications"] = notifications
        run["invocations"] = [invocation]
        run_props["scanDegraded"] = bool(scan_health.get("degraded"))
        run_props["unrankedFallback"] = bool(scan_health.get("degraded"))

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(redact_tree(sarif), indent=2))
        fh.write("\n")


# Programmatic entrypoint (called from orchestrator.scan_repo)
# Single CMDB export (app data). The pipeline supplies the path via
# config.yaml -> inject.cmdb_file; this constant is only the default location
# for the standalone `python -m vvaharness.report.enrich` CLI.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CMDB_CSV = os.path.join(_REPO_ROOT, "inputs", "cmdb.csv")


def md_to_sarif(md_path: str, app_id: Optional[str],
                app: Optional[AppInfo], sarif_out: str,
                scan_health: Optional[dict] = None) -> list[Finding]:
    """Pipeline s9: parse an already-enriched MD (s8 wrote CVSS/VulContextSeverity/Offensive
    natively) and emit SARIF. No CMDB load, no MD mutation.

    ``scan_health`` (optional) makes a degraded run observably distinct in the
    SARIF invocation; when None the output is unchanged."""
    findings = parse_findings(md_path, app)
    generate_sarif(md_path, findings, app_id or "", app, sarif_out,
                   scan_health=scan_health)
    print(f"  SARIF written: {sarif_out} ({len(findings)} results)", file=sys.stderr)
    return findings


def enrich(md_path: str, app_id: Optional[str],
           sarif_out: str) -> tuple[list[Finding], Optional[AppInfo]]:
    """CMDB lookup → annotate MD in place (CVSS/VulContextSeverity/OffensivePriority) → SARIF.

    Returns (findings, resolved AppInfo or None). Safe to call with
    app_id=None: CVSS base scores and OffensivePriority are still computed,
    only the VulContextSeverity environmental adjustment is skipped.
    """
    cmdb = load_cmdb_csv(DEFAULT_CMDB_CSV)
    print(f"  CMDB loaded: {len(cmdb)} records", file=sys.stderr)

    app = lookup_app(app_id, cmdb, {}) if app_id else None
    if app:
        print(f"  [{app_id}] CMDB({app.source}): {app.name} | "
              f"extFacing={app.externally_facing} pci={app.pci_scoped} "
              f"pan={app.processes_pan} pii={app.pii} -> {app.env_summary()}",
              file=sys.stderr)
    elif app_id and cmdb:
        print(f"  [{app_id}] WARN: applicationId not found in CMDB - "
              f"VulContextSeverity skipped (OffensivePriority still computed)", file=sys.stderr)
    elif not app_id:
        print("  WARN: no applicationId supplied - VulContextSeverity skipped", file=sys.stderr)

    annotate_md_cvss_vsvs(md_path, app)
    findings = parse_findings(md_path, app)
    for f in findings:
        if f.offensive_priority is None:
            compute_offensive_priority(f, app)
    annotate_md_offensive(md_path, findings)

    no_vsvs = sum(1 for f in findings if f.vsvs_score < 0)
    print(f"  Findings: {len(findings)} | VulContextSeverity computed: {len(findings) - no_vsvs} "
          f"| VulContextSeverity skipped: {no_vsvs}", file=sys.stderr)

    generate_sarif(md_path, findings, app_id or "", app, sarif_out)
    print(f"  SARIF written: {sarif_out} ({len(findings)} results)", file=sys.stderr)

    return findings, app


# CLI
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Enrich findings MD with CVSS base score, VulContextSeverity, "
                    "OffensivePriority; emit SARIF.")
    ap.add_argument("--md", required=True, help="findings markdown to enrich in place")
    ap.add_argument("--app-id", required=True, help="CMDB application id")
    ap.add_argument("--sarif-out",
                    help="SARIF output path (default: <md-stem>.sarif)")
    args = ap.parse_args()

    if not os.path.isfile(args.md):
        print(f"!! MD not found: {args.md}", file=sys.stderr)
        return 1

    sarif_out = args.sarif_out or re.sub(r"\.md$", "", args.md) + ".sarif"
    findings, app = enrich(args.md, args.app_id, sarif_out)

    for f in findings:
        vs = f"{f.vsvs_score:.1f} {f.vsvs_rating}" if f.vsvs_score >= 0 else "-"
        print(f"  [{f.severity:8}] {f.offensive_priority or '--'} "
              f"base={f.cvss_score:4.1f} vulContextSeverity={vs:14} {f.title[:60]}")

    return 0 if app or not os.path.isfile(DEFAULT_CMDB_CSV) else 2


if __name__ == "__main__":
    sys.exit(main())
