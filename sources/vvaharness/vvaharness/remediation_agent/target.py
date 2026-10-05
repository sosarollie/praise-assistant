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

"""One finding queued for remediation: a thin wrapper around :class:`vvaharness.models.Finding` carrying only this run's state."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from vvaharness.models import Finding

__all__ = ["RemediationTarget"]


@dataclass
class RemediationTarget:
    """One finding to remediate, plus its position in this run; not frozen because ``done`` is flipped by the interactive picker."""

    finding: Finding
    index: int
    done: bool = False

    @property
    def case_id(self) -> str:
        """Stable identity across attempts: deferred to the finding when minted, else derived from its location."""
        return self.finding.case_id or _derive_case_id(self.finding)

    @property
    def severity(self) -> str:
        """The severity band, upper-cased the way the report and the label render it."""
        return self.finding.severity.value.upper()

    @property
    def title(self) -> str:
        """The finding's title, for display."""
        return self.finding.title

    @property
    def file(self) -> str:
        """The clean repo-relative path, with no line suffix."""
        return self.finding.file

    @property
    def label(self) -> str:
        """One-line display label for the progress renderer."""
        loc = f" ({self.finding.file})" if self.finding.file else ""
        return f"[{self.severity}] {self.finding.title}{loc}"

    @property
    def slug(self) -> str:
        """Stable, filesystem-safe, index-prefixed artefact folder name, e.g. ``01_stored-jql-injection`` (``case_id`` is not in it — it contains path separators)."""
        base = re.sub(r"[^a-z0-9]+", "-", self.finding.title.lower()).strip("-")
        base = base[:60].rstrip("-") or "finding"
        return f"{self.index:02d}_{base}"


def _derive_case_id(finding: Finding) -> str:
    """Mint a stable ``<hash6>-<class>-<file>-<line>`` id for a finding that has none, seeded only on title and location so it stays reproducible."""
    seed = f"{finding.title}|{finding.file}|{finding.line_start}".encode()
    digest = hashlib.sha1(seed).hexdigest()[:6]
    return f"{digest}-{finding.vuln_class.value}-{finding.file or 'unknown'}-{finding.line_start}"
