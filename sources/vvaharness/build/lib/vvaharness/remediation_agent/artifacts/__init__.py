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

"""Renders and persists one remediation attempt to disk, re-exporting the focused layout/summary/diff/report/writer submodules."""
from __future__ import annotations

from vvaharness.remediation_agent.artifacts.diff import (  # noqa: F401
    _safe_repo_path,
    capture_git_diff,
    changed_files_whole_tree,
    changed_since_snapshot,
    derive_diff,
    snapshot_files,
    synth_unified_diff,
)
from vvaharness.remediation_agent.artifacts.layout import (  # noqa: F401
    DIFF_PATCH,
    EVIDENCE_DIR,
    FINDING_CASE_JSON,
    SUMMARY_MD,
    TRIAGE_JSON,
)
from vvaharness.remediation_agent.artifacts.report import build_report  # noqa: F401
from vvaharness.remediation_agent.artifacts.summary import render_summary  # noqa: F401
from vvaharness.remediation_agent.artifacts.writer import write_case  # noqa: F401

__all__ = [
    "EVIDENCE_DIR", "TRIAGE_JSON", "SUMMARY_MD", "DIFF_PATCH",
    "FINDING_CASE_JSON",
    "render_summary", "capture_git_diff", "synth_unified_diff",
    "snapshot_files", "derive_diff", "changed_files_whole_tree", "changed_since_snapshot", "_safe_repo_path",
    "build_report", "write_case",
]
