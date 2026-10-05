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

"""Validation's DeepAgents tool-builder: generic readers + deterministic fact tools.

Injected via ``StreamingOptions.tool_builder``; builds the generic readers, then appends
the five read-only fact tools that operate on ``diff.patch`` and the staged workspace.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from langchain_core.tools import BaseTool, tool

from vvaharness.backends.harness import StreamingOptions
from vvaharness.backends.harness.deepagents.tools import build_tools as build_reader_tools
from vvaharness.validation.tools.diff_facts import (
    build_diff_impact_map,
    changed_lines,
    diff_touched,
)
from vvaharness.validation.tools.pattern_scanner import pattern_scan
from vvaharness.validation.tools.test_inventory import test_inventory

if TYPE_CHECKING:
    from collections.abc import Sequence


def _fact_tools(options: StreamingOptions, allowed: set[str]) -> list[BaseTool]:
    """Build the deterministic fact tools whose names appear in *allowed*."""
    workspace = options.cwd
    tools: list[BaseTool] = []

    if "DiffTouched" in allowed:
        @tool
        def DiffTouched(file_path: str) -> dict:
            """Return whether *file_path* is in diff.patch and its changed line ranges."""
            return diff_touched(workspace, file_path)

        tools.append(DiffTouched)

    if "ChangedLines" in allowed:
        @tool
        def ChangedLines(file_path: str) -> list[tuple[int, int]]:
            """Return added line ranges for *file_path* from diff.patch."""
            return changed_lines(workspace, file_path)

        tools.append(ChangedLines)

    if "DiffImpactMap" in allowed:
        @tool
        def DiffImpactMap() -> dict:
            """Return files changed by diff.patch and whether a trust boundary was touched."""
            impact = build_diff_impact_map(workspace)
            return {
                "files_changed": impact.files_changed,
                "trust_boundary_touched": impact.trust_boundary_touched,
            }

        tools.append(DiffImpactMap)

    if "PatternScan" in allowed:
        @tool
        def PatternScan(pattern_set: str) -> list[dict]:
            """Return bounded, secret-free match metadata and a scan summary.

            Builtin sets: "secret_exposure", "insecure_value". The final item
            reports counts, limits, and whether results were truncated.
            """
            return pattern_scan(workspace, pattern_set)

        tools.append(PatternScan)

    if "TestInventory" in allowed:
        @tool
        def TestInventory() -> dict:
            """Inventory test files and detect negative/adversarial test markers."""
            return test_inventory(workspace)

        tools.append(TestInventory)

    return tools


def build_validation_tools(
    options: StreamingOptions,
    *,
    allowed_tools: Sequence[str] | None,
) -> list[BaseTool]:
    """Build validation's tool set: generic readers plus the fact tools in the allow-list."""
    reader_tools = build_reader_tools(options, allowed_tools=allowed_tools)
    allowed = set(allowed_tools if allowed_tools is not None else ())
    return reader_tools + _fact_tools(options, allowed)


__all__ = ["build_validation_tools"]
