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

"""Per-finding workspace manifest for the agent session; carries a Finding, not a flattened copy."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from vvaharness.models import Finding

__all__ = ["Manifest"]


class Manifest(BaseModel):
    """What one validation session needs about the finding; history lives in finding_case.json."""

    model_config = ConfigDict(extra="ignore")

    case_id: str = ""
    session_id: str = ""
    finding: Finding | None = None
    # The remediation's touched files: what the patch claims to have changed.
    affected_files: list[str] = Field(default_factory=list)
    post_results: bool = False

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain JSON-compatible dict."""
        return self.model_dump(mode="json")

    def write(self, path: Path) -> None:
        """Persist the manifest as pretty JSON."""
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def from_file(cls, path: Path) -> Manifest:
        """Load a manifest from disk, tolerating extra keys."""
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))
