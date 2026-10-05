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

"""Constant tool-name vocabularies for the validation agent."""

from __future__ import annotations

from typing import Final

from vvaharness.backends.harness import READ_TOOLS

#: Deterministic fact tools implemented in ``validation/tools/``.
FACT_TOOLS: Final[tuple[str, ...]] = (
    "DiffTouched",
    "ChangedLines",
    "DiffImpactMap",
    "PatternScan",
    "TestInventory",
)

#: What DeepAgents grants a validation subagent; Claude CLI/SDK personas use their own readers.
DEFAULT_FACT_TOOLS: Final[tuple[str, ...]] = (*sorted(READ_TOOLS), *FACT_TOOLS)
