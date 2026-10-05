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

"""The names of the directories a scan leaves inside a target checkout, kept here so what a stage writes and what ``cleanup._purge_clone`` refuses to delete never drift apart."""

from __future__ import annotations

from typing import Final

__all__ = [
    "CASE_DIR_NAME",
    "CASE_FILE_NAME",
    "FINDINGS_JSON_NAME",
    "SCAN_DIR_NAME",
]

#: Detection output: the Markdown report, the SARIF, the error log, and findings.json.
SCAN_DIR_NAME: Final = "security-scan"

#: Remediation output: one subdirectory per finding, each holding that case's record.
CASE_DIR_NAME: Final = "security-remediation"

#: The per-case record inside each ``<CASE_DIR_NAME>/<dir>/``; the subdirectory is named by the remediation agent's own slug, not by ``case_id``.
CASE_FILE_NAME: Final = "finding_case.json"

#: The typed scan result, so a later process reads findings instead of re-parsing Markdown.
FINDINGS_JSON_NAME: Final = "findings.json"
