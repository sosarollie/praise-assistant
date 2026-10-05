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

"""Validation-specific harness policy values (read-only tool allow-list + write gate).

The shared harness contract deliberately doesn't own these: the read-only tool policy and
the workspace artifact names retained in the defence-in-depth permission gate.
"""

from __future__ import annotations

from vvaharness.backends.harness import ToolPolicy
from vvaharness.validation.constants.artifacts import (
    SYNTHESIZED_GATES_FILENAME,
    VALIDATION_REPORT_FILENAME,
)

# No Write: the agent returns structured output; the host persists artifacts and scores them.
VALIDATION_POLICY = ToolPolicy(
    allowed_tools=("Read", "Grep", "Glob", "Agent"),
    disallowed_tools=("Write", "Edit", "NotebookEdit", "Bash"),
)

# Defence in depth: if a future adapter exposes Write, these are the only files it could target.
DEFAULT_ALLOWED_OUTPUT_FILES: frozenset[str] = frozenset({
    VALIDATION_REPORT_FILENAME,
    SYNTHESIZED_GATES_FILENAME,
})

__all__ = ["DEFAULT_ALLOWED_OUTPUT_FILES", "VALIDATION_POLICY"]
