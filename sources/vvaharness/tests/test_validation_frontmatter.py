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

"""Characterization tests for the subagent frontmatter parser."""

from __future__ import annotations

import pytest

from vvaharness.validation.subagents._frontmatter import parse_frontmatter

_FULL = """\
---
name: my-agent
model: claude-sonnet-4-6
description: Does security review
allowedTools:
  - Read
  - Bash
deniedTools:
  - Write
---
Body text here.
"""

_SCALAR_ONLY = """\
---
name: minimal
model: claude-opus-4-8
description: Simple
---
Simple body.
"""


class TestParseFrontmatter:
    def test_parses_scalar_fields(self) -> None:
        meta, _ = parse_frontmatter(_FULL)
        assert meta["name"] == "my-agent"
        assert meta["model"] == "claude-sonnet-4-6"
        assert meta["description"] == "Does security review"

    def test_parses_list_fields(self) -> None:
        meta, _ = parse_frontmatter(_FULL)
        assert meta["allowedTools"] == ["Read", "Bash"]
        assert meta["deniedTools"] == ["Write"]

    def test_returns_stripped_body(self) -> None:
        _, body = parse_frontmatter(_FULL)
        assert body == "Body text here."

    def test_scalar_only_no_list_keys(self) -> None:
        meta, body = parse_frontmatter(_SCALAR_ONLY)
        assert meta["name"] == "minimal"
        assert "allowedTools" not in meta
        assert body == "Simple body."

    def test_missing_frontmatter_raises(self) -> None:
        with pytest.raises(ValueError, match="frontmatter"):
            parse_frontmatter("No delimiters here.")

    def test_inline_list_value_raises(self) -> None:
        bad = "---\nallowedTools: Read\n---\nbody\n"
        with pytest.raises(ValueError, match="block list"):
            parse_frontmatter(bad)

    def test_unknown_key_raises(self) -> None:
        bad = "---\nunknownKey: value\n---\nbody\n"
        with pytest.raises(ValueError, match="unknown frontmatter key"):
            parse_frontmatter(bad)

    def test_blank_line_resets_list_context(self) -> None:
        text = (
            "---\n"
            "allowedTools:\n"
            "  - Read\n"
            "\n"
            "name: agent\n"
            "---\n"
            "body\n"
        )
        meta, _ = parse_frontmatter(text)
        assert meta["allowedTools"] == ["Read"]
        assert meta["name"] == "agent"
