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

"""The composed configuration tree, and the loader that builds it from the environment."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from vvaharness.validation.config.overrides import ValidateOverrides
from vvaharness.validation.config.settings.agent import AgentConfig
from vvaharness.validation.config.settings.env import _EnvScalars
from vvaharness.validation.config.settings.ghe import GheConfig
from vvaharness.validation.config.settings.paths import PathsConfig, _build_paths
from vvaharness.validation.constants.artifacts import (
    DEFAULT_EFFORT,
    DEFAULT_MAX_BUDGET_USD,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_TURNS,
    DEFAULT_MODEL,
    DEFAULT_VALIDATION_VIA,
)


class Config(BaseModel):
    """The composed configuration tree consumed across the package."""

    model_config = ConfigDict(extra="forbid")

    paths: PathsConfig
    agent: AgentConfig = Field(default_factory=AgentConfig)
    ghe: GheConfig = Field(default_factory=GheConfig)
    max_findings: int | None = DEFAULT_MAX_FINDINGS
    live: bool = False
    verbose: bool = False
    dry_run: bool = False


def _parse_tools(raw: str) -> tuple[str, ...] | None:
    """Parse a comma-separated tool list into a tuple; empty/blank → None (inherit .md default)."""
    tools = tuple(tool.strip() for tool in raw.split(",") if tool.strip())
    return tools or None


def load_config(
    project_root: Path | None = None,
    *,
    live: bool = False,
    overrides: ValidateOverrides | None = None,
) -> Config:
    """Build the config tree: tunables from *overrides* or a hardcoded default, never env."""
    ov: ValidateOverrides = overrides or {}
    env = _EnvScalars()
    root = project_root if project_root is not None else Path.cwd()
    cfg = Config(
        paths=_build_paths(root),
        agent=AgentConfig(
            binary=env.binary,
            model=ov.get("model", DEFAULT_MODEL),
            max_turns=ov.get("max_turns", DEFAULT_MAX_TURNS),
            max_budget_usd=ov.get("max_budget_usd", DEFAULT_MAX_BUDGET_USD),
            effort=ov.get("effort", DEFAULT_EFFORT),
            max_retries=env.max_retries,
            via=ov.get("via", DEFAULT_VALIDATION_VIA),
            provider=ov.get("provider", None),
            use_responses_api=ov.get("use_responses_api", None),
            security_architect_model=ov.get("security_architect_model", None),
            penetration_tester_model=ov.get("penetration_tester_model", None),
            cross_repo_analyzer_model=ov.get("cross_repo_analyzer_model", None),
            validate_tools=_parse_tools(ov.get("validate_tools", "")),
            cache_markers=ov.get("cache_markers", True),
        ),
        ghe=GheConfig(token=env.ghe_token, archived_token=env.ghe_archived_token),
        max_findings=ov.get("max_findings", DEFAULT_MAX_FINDINGS),
        live=live,
    )
    # No mkdir: root defaults to Path.cwd(), so building a config used to create ./targets and
    # ./outputs in whatever directory an embedder called from. Neither path has a reader.
    return cfg
