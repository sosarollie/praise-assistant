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

"""Parse YAML frontmatter from subagent .md authoring files without a pyyaml dependency."""

from __future__ import annotations

import re
from typing import cast

from vvaharness.validation.subagents.models import ParsedFrontmatter, SubagentFrontmatterMeta

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)
_SCALAR_KEYS = frozenset({"name", "model", "description"})
_LIST_KEYS = frozenset({"allowedTools", "deniedTools", "skills"})


def _append_list_item(
    meta: dict[str, object],
    current_list_key: str | None,
    raw_line: str,
) -> None:
    """Append a YAML block-list item to its parent bucket in meta."""
    if current_list_key is None:
        raise ValueError(f"list item without parent key: {raw_line!r}")
    value = raw_line.rstrip().split("- ", 1)[1].strip()
    bucket = meta[current_list_key]
    if not isinstance(bucket, list):
        raise TypeError(f"expected list for key {current_list_key!r}, got {type(bucket)!r}")
    bucket.append(value)


def _apply_key_line(meta: dict[str, object], raw_line: str) -> str | None:
    """Apply a ``key: value`` line to meta; return the new list-context key or None."""
    field_key, separator, value = raw_line.rstrip().partition(":")
    if not separator:
        raise ValueError(f"malformed frontmatter line: {raw_line!r}")
    field_key, value = field_key.strip(), value.strip()
    if field_key in _SCALAR_KEYS:
        meta[field_key] = value
        return None
    if field_key in _LIST_KEYS:
        if value:
            raise ValueError(f"{field_key} must be a block list, got inline value")
        meta[field_key] = []
        return field_key
    raise ValueError(f"unknown frontmatter key: {field_key}")


def _classify_line(
    meta: dict[str, object], current_list_key: str | None, raw_line: str,
) -> str | None:
    """Process one frontmatter line; return the updated list-context key."""
    line = raw_line.rstrip()
    if not line.strip():
        return None
    if line.startswith(("  - ", "\t- ")):
        _append_list_item(meta, current_list_key, raw_line)
        return current_list_key
    return _apply_key_line(meta, raw_line)


def parse_frontmatter(text: str) -> ParsedFrontmatter:
    """Parse YAML frontmatter and return the meta dict and stripped body text."""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        raise ValueError("subagent file missing YAML frontmatter")
    head, body = match.group(1), match.group(2)
    meta: dict[str, object] = {}  # bounded to _SCALAR_KEYS/_LIST_KEYS; cast to TypedDict below
    current_list_key: str | None = None
    for raw_line in head.splitlines():
        current_list_key = _classify_line(meta, current_list_key, raw_line)
    return ParsedFrontmatter(cast(SubagentFrontmatterMeta, meta), body.strip())
