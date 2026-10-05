# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Structured result returned by the S10 file-editor subagent."""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, Field, model_validator

FixerStatus = Literal["applied", "already_applied", "not_applied", "tool_error"]


class FixerResult(BaseModel):
    """Machine-readable outcome of one isolated fixer invocation."""

    status: FixerStatus
    files_changed: list[str] = Field(default_factory=list)
    summary: str
    error: str = ""
    retryable: bool = False

    @model_validator(mode="after")
    def _status_has_evidence(self) -> FixerResult:
        """Keep success and retry claims tied to concrete evidence."""
        if self.status == "applied" and not self.files_changed:
            raise ValueError("status=applied requires at least one changed file")
        if self.status != "applied" and self.files_changed:
            raise ValueError("only status=applied may report changed files")
        if self.retryable and self.status != "tool_error":
            raise ValueError("retryable=true is valid only for status=tool_error")
        if self.status == "tool_error" and not self.error.strip():
            raise ValueError("status=tool_error requires an error description")
        return self

    @classmethod
    def schema_json_compact(cls) -> str:
        """Compact schema for embedding in the fixer system prompt."""
        return json.dumps(cls.model_json_schema(), separators=(",", ":"))


__all__ = ["FixerResult", "FixerStatus"]
