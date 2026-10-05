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

"""Exit code when validation selects no validatable findings.

An idempotent re-run after every finding is already validated must succeed (0),
not report failure; only a repo with no finding cases at all is an error (1).
"""

from pathlib import Path

from vvaharness.models import (
    Decision,
    Finding,
    FindingCase,
    Remediation,
    RemediationKind,
    Verdict,
)
from vvaharness.validation.cli._run import _empty_selection_rc


def _validated_case(repo: Path, slug: str = "01_finding", case_id: str = "F-1") -> None:
    """Write a case whose DERIVED state is `validated`, i.e. closed and not validatable."""
    finding = Finding(
        title="t", file="app/x.py", line_start=3, vuln_class="injection",
        severity="high", case_id=case_id, cvss_score=7.5,
    )
    case = FindingCase(case_id=case_id, finding=finding).with_attempt(
        Remediation(kind=RemediationKind.EDITS_APPLIED, summary="s", files_touched=("app/x.py",))
    ).with_verdict(Verdict(decision=Decision.FIXED, rationale="fix verified", score=1.0))
    d = repo / "security-remediation" / slug
    d.mkdir(parents=True)
    case.write(d / "finding_case.json")


def test_zero_when_cases_exist_but_none_validatable(tmp_path: Path) -> None:
    # Cases are present but all terminal (a FIXED verdict derives `validated`) -> nothing to do.
    _validated_case(tmp_path)
    assert _empty_selection_rc(tmp_path) == 0


def test_one_when_no_finding_cases_at_all(tmp_path: Path) -> None:
    assert _empty_selection_rc(tmp_path) == 1
