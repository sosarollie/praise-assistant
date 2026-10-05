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

"""Agent config for the fix-validation path: a module constant, since only one path exists."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from vvaharness.validation.constants.artifacts import SYSTEM_PROMPT_FILENAME

__all__ = ["FIX_VALIDATION", "PathConfig"]


@dataclass(frozen=True)
class PathConfig:
    """Immutable agent configuration for the fix-validation path."""

    agent_names: tuple[str, ...]
    system_prompt_file: str


FIX_VALIDATION: Final[PathConfig] = PathConfig(
    agent_names=("security-architect", "penetration-tester", "cross-repo-analyzer"),
    system_prompt_file=SYSTEM_PROMPT_FILENAME,
)
