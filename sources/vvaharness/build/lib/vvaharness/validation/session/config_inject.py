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

"""Inject Claude runtime config files into a validation workspace."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from vvaharness.validation.constants.artifacts import (
    CLAUDE_DIRNAME,
    LOGGING_DIRNAME,
    ORCHESTRATOR_LOG_DIRNAME,
    SUBAGENTS_LOG_DIRNAME,
)

log = logging.getLogger(__name__)

_PKG_ROOT = Path(__file__).resolve().parent.parent
CLAUDE_CONFIG_SOURCE = _PKG_ROOT / "claude_config"


def _inject_hooks(dest_claude: Path) -> None:
    """Copy transcript-capture hook into dest_claude/hooks/."""
    hooks_logging = dest_claude / "hooks" / LOGGING_DIRNAME
    hooks_logging.mkdir(parents=True)
    src_transcript = CLAUDE_CONFIG_SOURCE / "hooks" / LOGGING_DIRNAME / "capture_transcript.sh"
    if src_transcript.exists():
        dest_transcript = hooks_logging / "capture_transcript.sh"
        shutil.copy2(src_transcript, dest_transcript)
        dest_transcript.chmod(0o755)


def _inject_tools(dest_claude: Path) -> None:
    """Copy bundled in-sandbox tools into dest_claude/tools/."""
    tools_src = CLAUDE_CONFIG_SOURCE / "tools"
    if tools_src.exists():
        shutil.copytree(tools_src, dest_claude / "tools")


def inject_claude_config(workspace_dir: Path) -> None:
    """Inject the .claude/ config subtree into the workspace.

    Scoring is computed host-side (the agent has no shell and never runs the scoring CLI),
    so the scoring package is deliberately NOT copied into the workspace.
    """
    try:
        dest_claude = workspace_dir / CLAUDE_DIRNAME
        if dest_claude.exists():
            shutil.rmtree(dest_claude)
        dest_claude.mkdir(parents=True)
        # rules/ carries the scoring rubric and MUST be injected; skills/ is optional.
        rules_src = CLAUDE_CONFIG_SOURCE / "rules"
        if not rules_src.exists():
            raise FileNotFoundError(f"required claude_config rules/ missing at {rules_src}")
        shutil.copytree(rules_src, dest_claude / "rules")
        skills_src = CLAUDE_CONFIG_SOURCE / "skills"
        if skills_src.exists():
            shutil.copytree(skills_src, dest_claude / "skills")
        _inject_hooks(dest_claude)
        shutil.copy2(
            CLAUDE_CONFIG_SOURCE / "settings.json",
            dest_claude / "settings.json",
        )
        _inject_tools(dest_claude)
        log_dir = workspace_dir / LOGGING_DIRNAME
        (log_dir / ORCHESTRATOR_LOG_DIRNAME).mkdir(parents=True, exist_ok=True)
        (log_dir / SUBAGENTS_LOG_DIRNAME).mkdir(parents=True, exist_ok=True)
    except OSError:
        log.exception("Failed to inject claude config into %s", workspace_dir)
        raise
