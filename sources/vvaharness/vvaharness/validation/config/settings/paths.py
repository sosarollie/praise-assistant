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

"""Filesystem layout for a validation run."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from vvaharness.validation.constants.artifacts import (
    OUTPUTS_DIRNAME,
    PROMPTS_DIRNAME,
    TARGETS_DIRNAME,
)

_ASSETS_ROOT = Path(__file__).resolve().parent.parent.parent


class PathsConfig(BaseModel):
    """Filesystem layout for a run."""

    model_config = ConfigDict(extra="forbid")

    project_root: Path
    targets_dir: Path
    outputs_dir: Path
    prompts_dir: Path


def _build_paths(project_root: Path) -> PathsConfig:
    """Build PathsConfig for *project_root*, resolving asset dirs from the package."""
    return PathsConfig(
        project_root=project_root,
        targets_dir=project_root / TARGETS_DIRNAME,
        outputs_dir=project_root / OUTPUTS_DIRNAME,
        prompts_dir=_ASSETS_ROOT / PROMPTS_DIRNAME,
    )
