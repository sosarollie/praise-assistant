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

"""remediation_agent.plugin_runner.helpers — tool list, prompt build, verdict coerce."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.remediation_agent.prompts import build_user
from vvaharness.remediation_agent.target import RemediationTarget
from vvaharness.util.json_extract import extract_json

# Read/search tools every backend supports; CLI additionally provides Bash + edit tools that fix mode uses.
_DEFAULT_TOOLS = ["Read", "Glob", "Grep"]


def _tools(cfg) -> list[str]:
    sr = getattr(cfg, "step_remediate", None)
    tools = getattr(sr, "allowed_tools", None)
    return list(tools) if tools else list(_DEFAULT_TOOLS)


def _build_user(target: RemediationTarget, repo: Path, mode: str, *,
                pre=None, ctx=None) -> str:
    """Build the per-finding user prompt, injecting the playbook strategy on the ALLOW path."""
    if pre is not None and ctx is not None and pre.strategy is not None:
        return build_user(
            target, str(repo), mode=mode,
            strategy_block=pre.strategy.as_prompt_block(),
            deny_paths=ctx.gate.deny_paths,
            forbid_paths=ctx.gate.forbid_patch_paths)
    return build_user(target, str(repo), mode=mode)


def _coerce_verdict(raw: Any, target: RemediationTarget) -> RemediationVerdict:
    """Validate the agent's response into a :class:`RemediationVerdict`, salvaging a near-complete response rather than discarding it."""
    if isinstance(raw, RemediationVerdict):
        raw.finding_index = target.index
        return raw
    if isinstance(raw, dict):
        return RemediationVerdict.coerce(raw, finding_index=target.index)
    try:
        data = extract_json(raw)
    except Exception as e:  # noqa: BLE001 — no JSON at all in the response
        return RemediationVerdict(
            finding_index=target.index,
            verdict="Needs Review",
            summary=f"could not parse agent response as JSON: {e}",
        )
    return RemediationVerdict.coerce(data, finding_index=target.index)
