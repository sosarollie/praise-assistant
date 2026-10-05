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

"""Minting the stable, content-addressed ``case_id`` every finding is tracked under, so a re-scan of the same bug at a slightly different line keeps the same case directory."""

from __future__ import annotations

import hashlib
import unicodedata
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:  # typing only -- keeps this module importable without the pipeline
    from vvaharness.models import FinalReport, Finding

__all__ = ["CASE_ID_PREFIX", "LINE_BUCKET", "mint_case_ids"]

#: Versioned prefix, so a future identity scheme is distinguishable rather than ambiguous.
CASE_ID_PREFIX: Final = "vvaf1_"

#: Line tolerance; bucketing is what lets the id survive T>0 sampling reporting the same bug at a slightly different line across runs.
LINE_BUCKET: Final = 10

#: 128 bits of the digest -- enough that an accidental clash is not a real failure mode, short enough to be a comfortable directory name.
_DIGEST_CHARS: Final = 32


def _rel_posix(repo_root: str, raw: str) -> str:
    """Fold *raw* to a repo-relative POSIX path in NFC, so an absolute-vs-relative path, a Windows separator, or macOS NFD filenames don't mint two ids for one file."""
    text = unicodedata.normalize("NFC", (raw or "").replace("\\", "/")).strip()
    root = unicodedata.normalize("NFC", (repo_root or "").replace("\\", "/")).rstrip("/")
    if root and text.startswith(f"{root}/"):
        text = text[len(root) + 1:]
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _material(repo_root: str, finding: Finding) -> str:
    """Return the content the id addresses for *finding*; CWE wins over ``vuln_class`` when present, falling back keeps the id mintable when s4 never assigned one."""
    path = _rel_posix(repo_root, finding.file)
    bucket = finding.line_start // LINE_BUCKET
    klass = finding.cwe or finding.vuln_class.value
    return f"{path}\n{bucket}\n{klass}"


def _digest(material: str, salt: int) -> str:
    """Hash *material* into a case id; ``salt`` > 0 disambiguates a bucket collision."""
    raw = material if salt == 0 else f"{material}\n#{salt}"
    return CASE_ID_PREFIX + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:_DIGEST_CHARS]


def _tiebreak_key(finding: Finding) -> tuple[int, int, str, str, str, str]:
    """Order findings that share one bucket, by content alone (not list index), so a reordered report doesn't re-mint every id and orphan its case directory."""
    return (
        finding.line_start,
        finding.line_end,
        finding.title,
        finding.chunk_id,
        finding.source_ref or "",
        finding.sink_ref or "",
    )


def _claim(material: str, taken: set[str]) -> tuple[str, int]:
    """Return the first unclaimed id for *material* and the salt that produced it."""
    salt = 0
    while _digest(material, salt) in taken:
        salt += 1
    return _digest(material, salt), salt


def _assert_unique(findings: list[Finding]) -> None:
    """Refuse to proceed unless every finding holds a distinct, non-empty id — the id names a directory, so a duplicate silently overwrites one case file with another."""
    seen: dict[str, Finding] = {}
    for finding in findings:
        if not finding.case_id:
            msg = f"finding {finding.file}:{finding.line_start} has no case_id after minting"
            raise ValueError(msg)
        clash = seen.get(finding.case_id)
        if clash is not None:
            msg = (
                f"case_id {finding.case_id!r} minted twice: "
                f"{clash.file}:{clash.line_start} and {finding.file}:{finding.line_start}. "
                "The id names the case directory, so writing both would lose one finding."
            )
            raise ValueError(msg)
        seen[finding.case_id] = finding


def mint_case_ids(report: FinalReport) -> dict[str, int]:
    """Give every finding in *report* a unique ``case_id``, in place; idempotent, so a ``--resume`` doesn't renumber cases that already exist on disk."""
    findings = [ranked.finding for ranked in report.findings]
    taken = {f.case_id for f in findings if f.case_id}
    pending: dict[str, list[Finding]] = {}
    for finding in findings:
        if not finding.case_id:
            pending.setdefault(_material(report.repo_root, finding), []).append(finding)
    minted = 0
    collisions = 0
    for material, group in pending.items():
        for finding in sorted(group, key=_tiebreak_key):
            case_id, salt = _claim(material, taken)
            finding.case_id = case_id
            taken.add(case_id)
            minted += 1
            collisions += 1 if salt else 0
    _assert_unique(findings)
    return {
        "minted": minted,
        "collisions": collisions,
        "preassigned": len(findings) - minted,
    }
