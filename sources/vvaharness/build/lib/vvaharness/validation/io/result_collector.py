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

"""Collect fix-validation verdicts from agent output, recomputed host-side, never trusted as-is."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

from vvaharness.models import Provenance, ScoringPolicy, Severity, Verdict
from vvaharness.validation.constants.artifacts import (
    MANIFEST_FILENAME,
    VALIDATION_REPORT_FILENAME,
)
from vvaharness.validation.io._host_score import load_synthesized_gates, verdict_for
from vvaharness.validation.models import (
    Manifest,
    OutputFinding,
    ValidationReport,
    ValidationResult,
    gate_score_rows,
    render_row,
)
from vvaharness.validation.scoring import FIX_CONFIG

log = logging.getLogger(__name__)

__all__ = ["CollectedFinding", "collect_and_enrich"]

# Drop affected-file entries shorter than this (junk / placeholder fragments).
_MIN_AFFECTED_FILE_LEN = 3


class CollectedFinding(NamedTuple):
    """One finding's authoritative verdict and the report row rendered from it."""

    verdict: Verdict
    row: ValidationResult


def _collect(
    workspace_dir: Path,
    finding_number_start: int,
    *,
    provenance: Provenance,
    policy: ScoringPolicy | None,
) -> list[CollectedFinding]:
    """Parse validation_report.json into per-finding verdicts and rows."""
    report_path = workspace_dir / VALIDATION_REPORT_FILENAME
    try:
        report = ValidationReport.from_file(report_path)
    except (OSError, ValueError):
        log.warning("Could not read validation report at %s", report_path)
        return []
    gates_by_id = load_synthesized_gates(workspace_dir)
    return [
        _one(finding, gates_by_id.get(finding.tracking_id), finding_number_start + index,
             provenance=provenance, policy=policy)
        for index, finding in enumerate(report.findings)
    ]


def _one(
    finding: OutputFinding,
    gates: list[Mapping[str, object]] | None,
    finding_number: int,
    *,
    provenance: Provenance,
    policy: ScoringPolicy | None,
) -> CollectedFinding:
    """Score one finding host-side and render its row."""
    verdict = verdict_for(finding, gates, provenance=provenance, policy=policy)
    rows = gate_score_rows(verdict, FIX_CONFIG)
    return CollectedFinding(
        verdict=verdict,
        row=render_row(
            verdict,
            finding,
            finding_number=finding_number,
            gate_scores_json=json.dumps(rows) if rows else "",
            policy=policy,
        ),
    )


def _filter_affected_files(affected: list[str]) -> str:
    """Drop comment markers and sub-threshold fragments, then join."""
    kept = [
        name for name in affected
        if not name.startswith("//") and len(name) > _MIN_AFFECTED_FILE_LEN
    ]
    return ", ".join(kept)


def _load_manifest(workspace_dir: Path) -> Manifest | None:
    """Load Manifest from workspace; return None on any parse/IO failure."""
    try:
        return Manifest.from_file(workspace_dir / MANIFEST_FILENAME)
    except (OSError, ValueError):
        return None


def collect_and_enrich(
    workspace_dir: Path,
    finding_number_start: int = 0,
    *,
    provenance: Provenance | None = None,
    policy: ScoringPolicy | None = None,
) -> list[CollectedFinding]:
    """Collect verdicts and rows, filling blank row fields from manifest.json."""
    collected = _collect(
        workspace_dir,
        finding_number_start,
        provenance=provenance or Provenance(),
        policy=policy,
    )
    manifest = _load_manifest(workspace_dir)
    if not collected or manifest is None or manifest.finding is None:
        return collected
    return [
        CollectedFinding(item.verdict, _enrich(item.row, manifest))
        for item in collected
    ]


def _enrich(row: ValidationResult, manifest: Manifest) -> ValidationResult:
    """Return *row* with blanks filled from manifest.finding, copied since row is a checkpoint."""
    finding = manifest.finding
    if finding is None:
        return row
    # (row field, fill value, whether the row's current value counts as absent).
    fills: tuple[tuple[str, str, bool], ...] = (
        ("finding_title", finding.title, not row.finding_title),
        (
            "finding_description",
            finding.description.replace("\\n", " ").strip(),
            not row.finding_description,
        ),
        (
            "affected_files",
            _filter_affected_files(manifest.affected_files),
            not row.affected_files,
        ),
        (
            "tracking_id",
            finding.case_id or manifest.case_id,
            not row.tracking_id or row.tracking_id == manifest.case_id,
        ),
        # The agent left the schema default, so it offered no severity: defer to the finding's.
        (
            "severity",
            finding.severity.value,
            row.severity.casefold() == Severity.MEDIUM.value,
        ),
    )
    updates = {name: value for name, value, absent in fills if absent and value}
    return row.model_copy(update=updates) if updates else row
