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

"""The per-finding artefact file names — single source of truth so the writer, case builder, and tests all agree."""
from __future__ import annotations

__all__ = [
    "DIFF_PATCH",
    "EVIDENCE_DIR",
    "FINDING_CASE_JSON",
    "SUMMARY_MD",
    "TRIAGE_JSON",
]

# Evidence artefacts live in a subfolder; the canonical case file sits at the root.
EVIDENCE_DIR = "evidence"
TRIAGE_JSON = "triage.json"
SUMMARY_MD = "summary.md"
# Shares the literal "diff.patch" with validation's DIFF_FILENAME by design — do not extract a shared constant, the subsystems are deliberately decoupled.
DIFF_PATCH = "diff.patch"
FINDING_CASE_JSON = "finding_case.json"
