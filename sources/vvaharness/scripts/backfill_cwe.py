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
Backfill **CWE:** lines into an already-generated findings MD, then regenerate
SARIF via the (now CWE-aware) vcs_enrich.md_to_sarif.

Usage:
    python backfill_cwe.py <report.md> [--app-id APPID] [--sarif-out PATH]
                           [--dry-run]

Idempotent: a finding that already has a **CWE:** line is left alone.
The original MD is saved to <report>.md.bak before modification.
"""
from __future__ import annotations
import argparse
import re
import shutil
import sys
from pathlib import Path

from vvaharness.report import enrich as vcs_enrich
from vvaharness.report.cwe import cwe_name, VULNCLASS_CWE


FINDING_HDR = re.compile(r"^### \d+\. \[(CRITICAL|HIGH|MEDIUM|LOW|INFO)] (.+)$")
CLASS_LINE  = re.compile(r"^\*{0,2}Class:\*{0,2}\s*`?([^`]+?)`?\s*$")
CWE_ALREADY = re.compile(r"^\*{0,2}CWE:\*{0,2}.*?\b(CWE-\d{1,5})\b", re.I)

# ── Title/description keyword → CWE heuristics (most specific first) ──────
_KEYWORD_CWE: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.I), cwe) for p, cwe in [
        (r"\bsql\s*inject", "CWE-89"),
        (r"\bxss\b|cross[-\s]?site script", "CWE-79"),
        (r"\bssrf\b|server[-\s]?side request forgery", "CWE-918"),
        (r"\bxxe\b|xml external entity", "CWE-611"),
        (r"\bcommand inject|os command", "CWE-78"),
        (r"\bpath travers|directory travers|\.\./", "CWE-22"),
        (r"\bopen redirect", "CWE-601"),
        (r"\bcsrf\b|cross[-\s]?site request forgery", "CWE-352"),
        (r"\bdeserial", "CWE-502"),
        (r"\bldap inject", "CWE-90"),
        (r"\bidor\b|owner(?:ship)? check|"
         r"not b(?:ind|ound)\b.*\bauthenticated|"
         r"client[-\s]?supplied (?:user|card|order)?id|trusts client", "CWE-639"),
        (r"\bmass[-\s]?assign", "CWE-915"),
        (r"\bauthoriz(?:ation)? bypass|missing authoriz", "CWE-862"),
        (r"\bunauth(?:enticat)?ed (?:admin|endpoint)|missing authenticat|"
         r"no auth", "CWE-306"),
        (r"\bwebhook.*(?:sign|origin|verif)|signature verif", "CWE-347"),
        (r"\btrust[-\s]?all|badcertificate|disable[sd]? cert|"
         r"insecureskipverify|hostname verif|cert(?:ificate)? validation|"
         r"trust ?manager|accepts? (?:any )?cert", "CWE-295"),
        (r"\bcipher suite|tls_rsa|forward secrecy|sslv3|tls\s*1\.0",
         "CWE-327"),
        (r"\bhard[-\s]?coded.*(?:api[-\s]?key|secret|token|password|cred)|"
         r"api[-\s]?key.*(?:committed|hard[-\s]?coded|in repo|in source)|"
         r"keystore password|truststore password|shared[-\s]?secret.*commit|"
         r"sonarqube token", "CWE-798"),
        (r"\bplaintext|cleartext|unencrypted (?:storage|sharedpref)|"
         r"stored in plaintext", "CWE-312"),
        (r"\bdisable[sd]?\s+tls|jdbc.*(?:disable|usessl=false)|"
         r"cleartext transmission", "CWE-319"),
        (r"\b(?:log|logged|logging|logs)\b.*\b(?:pii|otp|hmac|secret|key|pan|"
         r"sensitive|email|phone|password)\b|"
         r"\b(?:pii|otp|hmac|secret|key|pan|sensitive|email|phone|password)\b"
         r".*\b(?:log|logged|logging|logs)\b|log mask", "CWE-532"),
        (r"\bactuator|env endpoint|health detail|stack ?trace.*expos|"
         r"verbose error", "CWE-200"),
        (r"\bh2 console|debug (?:mode|enabled)|admin console enabled",
         "CWE-489"),
        (r"\bidempoten|replay protect|double[-\s]?(?:charge|post|book|spend)",
         "CWE-294"),
        (r"\bmutable @main|workflow.*@(?:main|master)|untrusted pr code|"
         r"pull[-_\s]?request trigger.*secret", "CWE-829"),
        (r"\bcustom scheme|interceptable.*deep link|deep link.*intercept",
         "CWE-923"),
        (r"\bldap auth.*disabled|authenticat.*disabled", "CWE-287"),
        (r"\b(?:mock|hardcoded mock|stub) ident|returns hardcoded.*identity",
         "CWE-1390"),
        (r"\bwildcard access|grants.*all.*endpoints|over[-\s]?privileg",
         "CWE-269"),
        (r"\bmagic[-\s]?link", "CWE-640"),
    ]
]

def derive_cwe(title: str, category: str | None, desc: str = "") -> str | None:
    blob = " ".join(x or "" for x in (title, category, desc))
    for rx, cwe in _KEYWORD_CWE:
        if rx.search(blob):
            return cwe
    # Fallback: shared VulnClass→CWE map (single source of truth in
    # vvaharness.report.cwe). "other" maps to "" → no CWE.
    if category:
        return VULNCLASS_CWE.get(category.strip().lower()) or None
    return None


def _cwe_label(cwe: str) -> str:
    nm = cwe_name(cwe)
    return f"{cwe}: {nm}" if nm else cwe


def _cwe_md_line(cwe: str) -> str:
    n = cwe.split("-")[-1]
    return (f"**CWE:** {_cwe_label(cwe)} - "
            f"https://cwe.mitre.org/data/definitions/{n}.html")


def backfill(md_path: Path, *, dry_run: bool = False) -> tuple[int, int, int]:
    src = md_path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    i = 0
    n_findings = n_inserted = n_skipped = 0

    while i < len(src):
        line = src[i]
        out.append(line)
        h = FINDING_HDR.search(line)
        if h:
            n_findings += 1
            title = h.group(2).strip()
            category: str | None = None
            class_idx_in_out: int | None = None
            cwe_idx_in_out: int | None = None
            existing_cwe: str | None = None
            # Scan the contiguous **Field:** header block under this ### heading.
            j = i + 1
            while j < len(src):
                ln = src[j]
                if FINDING_HDR.search(ln) or ln.startswith("## ") \
                        or ln.startswith("#### ") or ln.startswith("---"):
                    break
                cw = CWE_ALREADY.search(ln)
                if cw and existing_cwe is None:
                    existing_cwe = cw.group(1).upper()
                    out.append(ln)
                    cwe_idx_in_out = len(out) - 1
                    j += 1
                    continue
                cm = CLASS_LINE.search(ln)
                if cm and category is None:
                    category = cm.group(1).strip()
                    out.append(ln)
                    class_idx_in_out = len(out) - 1
                    j += 1
                    continue
                out.append(ln)
                j += 1
                # Stop scanning header block at first blank after we've seen Class.
                if category is not None and ln == "":
                    break
            # Insertion anchor for the no-Class-line case: end of the header
            # block we just consumed into `out`.
            header_block_end_in_out = len(out)
            cwe = existing_cwe or derive_cwe(title, category)
            if cwe:
                if class_idx_in_out is not None:
                    out[class_idx_in_out] = f"**Class:** {_cwe_label(cwe)}"
                if cwe_idx_in_out is not None:
                    out[cwe_idx_in_out] = _cwe_md_line(cwe)
                    n_skipped += 1
                    print(f"  ~ #{n_findings:2d} {cwe:9s} (reformat) {title[:60]}",
                          file=sys.stderr)
                elif class_idx_in_out is not None:
                    out.insert(class_idx_in_out + 1, _cwe_md_line(cwe))
                    n_inserted += 1
                    print(f"  + #{n_findings:2d} {cwe:9s} {title[:60]}",
                          file=sys.stderr)
                else:
                    # A CWE was derived but the finding has neither an
                    # existing **CWE:** line nor a **Class:** line to anchor on.
                    # Insert the CWE line at the end of the header block rather
                    # than silently dropping it.
                    out.insert(header_block_end_in_out, _cwe_md_line(cwe))
                    n_inserted += 1
                    print(f"  + #{n_findings:2d} {cwe:9s} (no class) {title[:60]}",
                          file=sys.stderr)
            else:
                print(f"  - #{n_findings:2d} (no cwe)  {title[:60]}",
                      file=sys.stderr)
            i = j
            continue
        i += 1

    if dry_run:
        return n_findings, n_inserted, n_skipped

    bak = md_path.with_suffix(md_path.suffix + ".bak")
    if not bak.exists():
        shutil.copy2(md_path, bak)
        print(f"  [backup] {bak}", file=sys.stderr)
    md_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return n_findings, n_inserted, n_skipped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("md", help="findings markdown to backfill in place")
    ap.add_argument("--app-id", default=None,
                    help="CMDB application id for SARIF run.properties")
    ap.add_argument("--sarif-out", default=None,
                    help="SARIF output path (default: <md-stem>.sarif)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would change; do not write")
    args = ap.parse_args()

    md_path = Path(args.md)
    if not md_path.exists():
        print(f"error: {md_path} not found", file=sys.stderr)
        return 1

    n_f, n_ins, n_skip = backfill(md_path, dry_run=args.dry_run)
    print(f"\n  findings={n_f}  cwe-inserted={n_ins}  already-had-cwe={n_skip}",
          file=sys.stderr)

    if args.dry_run:
        print("  [dry-run] no files written", file=sys.stderr)
        return 0

    sarif_out = args.sarif_out or str(md_path.with_suffix(".sarif"))
    vcs_enrich.md_to_sarif(str(md_path), args.app_id, None, sarif_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
