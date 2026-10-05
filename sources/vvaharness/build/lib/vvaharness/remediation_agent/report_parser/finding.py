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

"""remediation_agent.report_parser.finding — the ``Finding`` dataclass.

A single parsed finding header — enough to drive the remediation loop and
render a meaningful per-step label. Kept in its own module so the parsing,
location, and field-extraction helpers can all import it without cycles."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Finding:
    """A single parsed finding header — enough to drive the remediation loop
    and render a meaningful per-step label."""

    index: int
    severity: str
    title: str
    file: str | None = None
    body: str = ""  # full markdown block (header → next "### "), for the agent prompt
    done: bool = False  # remediated already (DONE_MARKER present on the header)

    @property
    def label(self) -> str:
        loc = f" ({self.file})" if self.file else ""
        return f"[{self.severity}] {self.title}{loc}"

    @property
    def slug(self) -> str:
        """Stable, filesystem-safe folder name, e.g. ``01_stored-jql-injection``.

        Index is zero-padded for lexical ordering; the title is lower-cased,
        non-alphanumerics collapse to single hyphens, and the whole thing is
        length-capped so deep paths stay sane."""
        base = re.sub(r"[^a-z0-9]+", "-", self.title.lower()).strip("-")
        base = base[:60].rstrip("-") or "finding"
        return f"{self.index:02d}_{base}"
