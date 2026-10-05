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

"""remediation_agent.report_parser.locate — artefact folder names and scan-report discovery.

Owns the single source of truth for the scan/remediation folder names (kept in
lock-step with ``orchestrator.scan``) and the helpers that find the scan dir and
its newest report under a target repo."""
from __future__ import annotations

from pathlib import Path

# ``out_dir = repo / "security-scan"`` in orchestrator.scan.scan_repo — keep the
# single source of truth for the folder name here so the two stay in lock-step.
SCAN_DIR_NAME = "security-scan"
# Sibling of the scan output: remediation artefacts land here, one folder/finding.
REMEDIATION_DIR_NAME = "security-remediation"
REPORT_GLOB = "*_report.md"


def find_scan_dir(repo: Path) -> Path | None:
    """Return ``<repo>/security-scan`` if it exists, else None."""
    scan_dir = Path(repo) / SCAN_DIR_NAME
    return scan_dir if scan_dir.is_dir() else None


def latest_report(scan_dir: Path) -> Path | None:
    """Return the newest ``*_report.md`` in *scan_dir*, or None if there are
    none. Report names embed a sortable UTC timestamp
    (``<module>_<YYYYMMDDTHHMMSSZ>_report.md``) so a lexical max picks the most
    recent; mtime is the tie-breaker for safety."""
    reports = sorted(
        Path(scan_dir).glob(REPORT_GLOB),
        key=lambda p: (p.name, p.stat().st_mtime),
    )
    return reports[-1] if reports else None
