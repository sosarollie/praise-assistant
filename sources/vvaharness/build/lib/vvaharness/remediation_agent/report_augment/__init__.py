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

"""Augment the combined SARIF + MD report with remediation results."""
from __future__ import annotations

import logging
from pathlib import Path

from vvaharness.remediation_agent.report_augment.dto import _load_cases
from vvaharness.remediation_agent.report_augment.locate import (
    _ensure_combined,
    _locate_scan_report,
)
from vvaharness.remediation_agent.report_augment.markdown import _augment_md
from vvaharness.remediation_agent.report_augment.sarif import _augment_sarif
from vvaharness.remediation_agent.report_parser import (
    REMEDIATION_DIR_NAME,
    SCAN_DIR_NAME,
)

log = logging.getLogger(__name__)

__all__ = ["augment_reports"]


def augment_reports(repo: Path, report_md: Path | str | None = None) -> None:
    """Copy the scan report into ``security-remediation/`` and add remediation results; best-effort, never fails the run."""
    try:
        _augment(Path(repo), Path(report_md) if report_md else None)
    except Exception:  # report augmentation must never fail the remediation run
        log.exception("remediation report augmentation failed; results not written "
                      "to combined report")


def _augment(repo: Path, report_md: Path | None = None) -> None:
    """Locate + copy the scan report, then augment the SARIF and MD copies."""
    rem_dir = repo / REMEDIATION_DIR_NAME
    records = _load_cases(rem_dir) if rem_dir.is_dir() else []
    if not records:
        log.info("no remediation cases under %s — skipping report augmentation", rem_dir)
        return

    located = _locate_scan_report(repo, report_md)
    if located is None:
        log.warning("no scan report under %s/%s — skipping report augmentation",
                    repo, SCAN_DIR_NAME)
        return
    sarif_dst, md_dst = _ensure_combined(repo, *located)
    _augment_sarif(sarif_dst, records)
    _augment_md(md_dst, records)
    log.info("remediation results written to combined report under %s", sarif_dst.parent)
