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

"""remediation_agent.report_augment.locate — locate + copy the scan report.

:func:`_locate_scan_report` finds the ``(*_report.sarif, *_report.md)`` pair to
augment — non-tamperable when the caller passes the explicit canonical report,
and refusing to guess among multiple glob candidates otherwise.
:func:`_ensure_combined` copies that pair into ``security-remediation/`` once."""
from __future__ import annotations

import logging
import shutil
from pathlib import Path

from vvaharness.remediation_agent.report_parser import (
    REMEDIATION_DIR_NAME,
    SCAN_DIR_NAME,
)

log = logging.getLogger(__name__)

# Newest scan SARIF (sibling .md shares the stem), mirrors validation.report.augment.
SCAN_REPORT_GLOB = "*_report.sarif"


def _locate_scan_report(repo: Path,
                        report_md: Path | None = None) -> tuple[Path, Path] | None:
    """Return ``(scan *_report.sarif, sibling *_report.md)`` to augment, or None.

    Selection is non-tamperable when *report_md* is given: the caller passes the
    EXACT canonical scan Markdown report this run processed, so a planted/stale
    sibling report cannot win. The SARIF is its same-stem sibling.

    Only when no explicit report is provided do we fall back to scanning
    ``security-scan/`` — and that fallback now refuses to silently pick a winner
    when MULTIPLE candidates exist (newest-wins was the tamperable behaviour):
    it proceeds only when exactly one report is present, else logs and bails."""
    if report_md is not None:
        md = Path(report_md)
        if not md.exists():
            log.warning("explicit scan report %s not found — skipping augmentation", md)
            return None
        sarif = md.with_suffix(".sarif")
        if not sarif.exists():
            log.warning("sibling SARIF for %s not found — skipping augmentation", md)
            return None
        return (sarif, md)

    sarifs = sorted((repo / SCAN_DIR_NAME).glob(SCAN_REPORT_GLOB))
    if not sarifs:
        return None
    if len(sarifs) > 1:
        log.warning(
            "%d scan SARIF reports under %s/%s and no explicit report was passed "
            "— refusing to guess which is canonical (pass the report path to "
            "avoid tamperable newest-wins selection)",
            len(sarifs), repo, SCAN_DIR_NAME)
        return None
    sarif = sarifs[0]
    md = sarif.with_suffix(".md")
    return (sarif, md) if md.exists() else None


def _ensure_combined(repo: Path, sarif_src: Path, md_src: Path) -> tuple[Path, Path]:
    """Copy the scan SARIF + MD into ``security-remediation/`` once; return the copies."""
    dst_dir = repo / REMEDIATION_DIR_NAME
    dst_dir.mkdir(parents=True, exist_ok=True)
    sarif_dst = dst_dir / sarif_src.name
    md_dst = dst_dir / md_src.name
    if not sarif_dst.exists():
        shutil.copy2(sarif_src, sarif_dst)
    if not md_dst.exists():
        shutil.copy2(md_src, md_dst)
    return sarif_dst, md_dst
