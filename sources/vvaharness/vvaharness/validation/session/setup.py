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

"""Assemble the validation-specific values injected into the shared harness.

The shared harness is domain-neutral; this is the single place validation's semantics live —
tool policy, write gate, structured-output model, fact-tool builder, and skill package root.
"""

from __future__ import annotations

from pathlib import Path

from vvaharness.backends.harness import PermissionsPolicy
from vvaharness.validation.constants.policy import (
    DEFAULT_ALLOWED_OUTPUT_FILES,
    VALIDATION_POLICY,
)
from vvaharness.validation.constants.tools import DEFAULT_FACT_TOOLS
from vvaharness.validation.models.output import ValidationOutput
from vvaharness.validation.tools.deep_tools import build_validation_tools

# Cosmetic name for validation's compiled agent graph.
VALIDATION_GRAPH_NAME = "validation"


def validation_skill_root(workspace: Path) -> Path:
    """Return the skill-package root for validation agents, inside *workspace*.

    The injected copy, not the packaged source: harness backends resolve skill paths
    relative to the session cwd, so ``inject_claude_config`` copies ``skills/`` here first.
    """
    # Imported lazily: the session package pulls in the launcher, which imports this module.
    from vvaharness.validation.constants.artifacts import CLAUDE_DIRNAME

    return workspace / CLAUDE_DIRNAME / "skills"


def validation_write_gate(workspace: Path) -> PermissionsPolicy:
    """Return the defence-in-depth write gate scoped to two host-owned artifacts."""
    return PermissionsPolicy(
        target_dir=workspace,
        allowed_output_files=DEFAULT_ALLOWED_OUTPUT_FILES,
    )


__all__ = [
    "DEFAULT_FACT_TOOLS",
    "VALIDATION_GRAPH_NAME",
    "VALIDATION_POLICY",
    "ValidationOutput",
    "build_validation_tools",
    "validation_skill_root",
    "validation_write_gate",
]
