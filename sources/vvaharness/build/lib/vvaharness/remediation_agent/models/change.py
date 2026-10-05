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

"""remediation_agent.models.change — one edited-file record in a remediation verdict."""
from __future__ import annotations

from pydantic import BaseModel, Field


class Change(BaseModel):
    file: str = Field(default="", description="repo-relative path that was edited")
    summary: str = Field(default="", description="what changed and why (≤ 2 sentences)")
