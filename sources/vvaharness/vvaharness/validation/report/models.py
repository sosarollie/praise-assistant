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

"""Data shapes for combined-report augmentation."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, TypedDict

if TYPE_CHECKING:
    from vvaharness.models import Finding
    from vvaharness.validation.models import ValidationResult

__all__ = [
    "CombinedReportPaths",
    "SarifResult",
    "SarifValidationBlock",
    "ValidatedFinding",
]


class CombinedReportPaths(NamedTuple):
    """The SARIF and Markdown twins of one combined report under security-remediation/."""

    sarif: Path
    md: Path


class ValidatedFinding(NamedTuple):
    """One validated finding and its render row; the finding carries SARIF fields the row lacks."""

    finding: Finding
    row: ValidationResult


# A raw SARIF ``result`` object; kept loosely typed since we only read a few known fields.
SarifResult = dict[str, object]


class SarifValidationBlock(TypedDict):
    """The SARIF ``validation`` object this package attaches to a matched result."""

    validationStatus: str
    validationReason: str
    weightedScore: float
    mergeReadiness: str
    gateScores: dict[str, object]
