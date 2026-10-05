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

"""Data shapes for parsed subagent YAML frontmatter."""

from __future__ import annotations

from typing import NamedTuple

from typing_extensions import TypedDict


class SubagentFrontmatterMeta(TypedDict, total=False):
    """Typed representation of parsed subagent YAML frontmatter."""

    name: str
    model: str
    description: str
    allowedTools: list[str]
    deniedTools: list[str]
    skills: list[str]


class ParsedFrontmatter(NamedTuple):
    """A subagent .md file's parsed frontmatter and its stripped body text."""

    meta: SubagentFrontmatterMeta
    body: str
