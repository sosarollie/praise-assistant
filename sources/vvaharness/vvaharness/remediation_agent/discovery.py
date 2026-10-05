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

"""Locates the scan report and selects findings for the ``remediate`` command."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from vvaharness.orchestrator.checkpoints import run_id_for
from vvaharness.remediation_agent.report_parser import (
    REMEDIATION_DIR_NAME,
    SCAN_DIR_NAME,
    find_scan_dir,
    latest_report,
    parse_findings,
)
from vvaharness.remediation_agent.select import select_top_logged
from vvaharness.remediation_agent.target import RemediationTarget

__all__ = ["Findings", "Layout", "cvss_score_of", "load_findings", "locate_report",
           "prepare_layout"]

CHECKPOINTS_DIR_NAME = "checkpoints"


def locate_report(repo_path: Path) -> tuple[Path | None, int]:
    """Find the newest scan report under ``<repo>/security-scan/``, returning ``(None, exit_code)`` with the error already printed on failure."""
    scan_dir = find_scan_dir(repo_path)
    if scan_dir is None:
        print(f"  ✗ no '{SCAN_DIR_NAME}' folder found under {repo_path} — run "
              f"`vvaharness scan --repo {repo_path}` first.", file=sys.stderr)
        return None, 1

    report = latest_report(scan_dir)
    if report is None:
        print(f"  ✗ no scan report (*_report.md) found in {scan_dir} — run "
              f"`vvaharness scan --repo {repo_path}` first.", file=sys.stderr)
        return None, 1
    return report, 0


def cvss_score_of(target: RemediationTarget) -> float | None:
    """Numeric CVSS base score accessor for ``--top N`` selection, or ``None`` when the report carried only a vector / bare severity band."""
    return target.finding.cvss_score


@dataclass(frozen=True)
class Findings:
    """What a report yielded: the findings this run will work on (``selected``), and every one it had (``discovered``, still needed for checkpoint pruning)."""

    selected: list[RemediationTarget]
    discovered: list[RemediationTarget]


def load_findings(report: Path, top: int | None) -> Findings:
    """Parse findings from *report* and, when ``top`` is set, narrow to the N highest-CVSS findings via the shared :func:`select_top_logged` helper."""
    discovered = parse_findings(report.read_text(encoding="utf-8"))
    selected = select_top_logged(discovered, top, score_of=cvss_score_of,
                                 log_prefix="[Remediation Agent]")
    return Findings(selected=selected, discovered=discovered)


@dataclass(frozen=True)
class Layout:
    """Resolved per-repo output + checkpoint locations for one remediation run."""
    rem_dir: Path
    ckpt_dir: Path
    run_id: str


def prepare_layout(repo_path: Path) -> Layout:
    """Resolve (and create) the per-repo remediation output dir, reusing the scan pipeline's ``<repo>/checkpoints`` folder rather than a private one."""
    rem_dir = repo_path / REMEDIATION_DIR_NAME
    rem_dir.mkdir(parents=True, exist_ok=True)
    return Layout(
        rem_dir=rem_dir,
        ckpt_dir=repo_path / CHECKPOINTS_DIR_NAME,
        run_id=run_id_for(repo_path),
    )
