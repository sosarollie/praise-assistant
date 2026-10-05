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

"""The per-finding record both subsystems write; ``state`` is computed, never stored."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from vvaharness.models._scan import Finding
from vvaharness.models.derive import state_of
from vvaharness.models.remediation import Remediation
from vvaharness.models.verdict import Verdict
from vvaharness.models.vocab import CaseState

__all__ = ["Attempt", "FindingCase"]

#: Bumped when the persisted shape changes in a way a reader must notice.
SCHEMA_VERSION = "2.0"


class Attempt(BaseModel):
    """One remediation and, once it has been judged, its verdict."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    ordinal: int = Field(description="1-based position in the sequence")
    remediation: Remediation = Field(description="what was attempted")
    verdict: Verdict | None = Field(default=None, description="None until validated")
    reverted_paths: tuple[str, ...] = Field(
        default=(), description="paths the harness rolled back after a policy breach"
    )


class FindingCase(BaseModel):
    """One finding tracked across every attempt to fix it."""

    # extra="ignore", not "forbid": rejecting an unknown key would drop the persisted case.
    model_config = ConfigDict(frozen=True, extra="ignore")

    schema_version: str = Field(default=SCHEMA_VERSION, description="persisted shape version")
    case_id: str = Field(description="stable identity, assigned once per (repo, finding)")
    finding: Finding = Field(description="what was found")
    attempts: tuple[Attempt, ...] = Field(default=(), description="ordered, possibly multi-engine")
    superseded_ids: tuple[str, ...] = Field(
        default=(), description="earlier ids reconciled into this case"
    )

    @computed_field
    @property
    def state(self) -> CaseState:
        """Lifecycle position, derived from the attempt sequence."""
        return state_of(self.attempts)

    @model_validator(mode="before")
    @classmethod
    def _drop_derived(cls, data: object) -> object:
        """Discard derived fields on input, so no caller can assert an unsupported state."""
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if k != "state"}
        return data

    def with_attempt(
        self,
        remediation: Remediation,
        *,
        reverted_paths: tuple[str, ...] = (),
    ) -> FindingCase:
        """Return a copy with one more attempt appended; *reverted_paths* records the rollback."""
        attempt = Attempt(
            ordinal=len(self.attempts) + 1,
            remediation=remediation,
            reverted_paths=reverted_paths,
        )
        return self.model_copy(update={"attempts": (*self.attempts, attempt)})

    def with_verdict(self, verdict: Verdict) -> FindingCase:
        """Return a copy with *verdict* attached to the most recent attempt."""
        if not self.attempts:
            msg = f"case {self.case_id!r} has no attempt to attach a verdict to"
            raise ValueError(msg)
        judged = self.attempts[-1].model_copy(update={"verdict": verdict})
        return self.model_copy(update={"attempts": (*self.attempts[:-1], judged)})

    @classmethod
    def read(cls, path: Path) -> FindingCase:
        """Load a case from disk, naming the file on malformed JSON."""
        return cls.model_validate(_read_json(path))

    def write(self, path: Path) -> None:
        """Persist the case atomically, so a concurrent reader never sees a partial file."""
        payload = json.dumps(self.model_dump(mode="json"), indent=2) + "\n"
        tmp = path.with_suffix(f"{path.suffix}.tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(path)


def _read_json(path: Path) -> object:
    """Read and parse *path*, raising a path-qualified error on malformed JSON."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"malformed JSON in finding case {path}: {exc}"
        raise ValueError(msg) from exc
