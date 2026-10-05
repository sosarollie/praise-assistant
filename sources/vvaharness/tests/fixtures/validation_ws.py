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

"""Validation-workspace artifact writers shared by the validation tests.

These encode the on-disk contract a validation session leaves behind in its
workspace — ``validation_report.json`` and ``synthesized_gates.json``. Both
the result collector tests (tests/test_validate_collect.py) and the
finding-case verdict write-back tests (tests/test_validate_case_writeback.py)
import these writers and the canonical gate constants below, so a filename or
JSON-shape change here is the single place to make it.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from vvaharness.validation.constants.artifacts import (
    SYNTHESIZED_GATES_FILENAME,
    VALIDATION_REPORT_FILENAME,
)

# Canonical four-gate outcomes used across the validation tests.
ALL_PASS: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "pass"},
    {"gate_name": "instance_coverage", "status": "pass"},
    {"gate_name": "no_new_vulnerabilities", "status": "pass"},
    {"gate_name": "security_best_practices", "status": "pass"},
]
ALL_FAIL: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "fail"},
    {"gate_name": "instance_coverage", "status": "fail"},
    {"gate_name": "no_new_vulnerabilities", "status": "fail"},
    {"gate_name": "security_best_practices", "status": "fail"},
]


def write_gates(ws: Path, tracking_id: str, gates: list[Mapping[str, object]]) -> None:
    (ws / SYNTHESIZED_GATES_FILENAME).write_text(
        json.dumps([{"tracking_id": tracking_id, "gates": gates}])
    )


def write_report(ws: Path, findings: list[dict]) -> None:
    (ws / VALIDATION_REPORT_FILENAME).write_text(json.dumps({"findings": findings}))
