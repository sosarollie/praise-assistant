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

"""The embeddable surface: remediate a finding, validate a remediation."""

from __future__ import annotations

from pathlib import Path

from vvaharness.models import (
    Finding,
    MergeReadiness,
    Remediation,
    ScoringPolicy,
    Verdict,
    merge_readiness_for,
    state_of,
)

__all__ = [
    "Finding",
    "MergeReadiness",
    "Remediation",
    "ScoringPolicy",
    "Verdict",
    "merge_readiness_for",
    "remediate",
    "state_of",
    "validate",
]


def remediate(finding: Finding, *, repo: Path, mode: str = "fix",
              config: Path | None = None, verbose: bool = False) -> Remediation:
    """Attempt a fix for *finding* in *repo* and return what the harness can prove was done."""
    from vvaharness.remediation_agent.discovery import prepare_layout
    from vvaharness.remediation_agent.plugin_runner import apply_plugin
    from vvaharness.remediation_agent.target import RemediationTarget

    repo = Path(repo)
    layout = prepare_layout(repo)
    target = RemediationTarget(finding=finding, index=1)
    return apply_plugin(target, layout.rem_dir / target.slug, cfg=_config(config),
                        repo=repo, mode=mode, verbose=verbose)


def validate(finding: Finding, remediation: Remediation, *, repo: Path,
             config: Path | None = None) -> Verdict:
    """Judge whether *remediation* actually fixes *finding* in *repo*."""
    raise NotImplementedError(
        "vvaharness.api.validate is not wired yet: validation ingests by globbing "
        "security-remediation/*/finding_case.json and stages a workspace, so a public entry "
        "point needs validate_case() promoted out of validation.cli._run first. "
        "Use `vvaharness validate --repo <path>` meanwhile."
    )


def _config(config: Path | None) -> object:
    """Load *config*, or the packaged default profile when none is given."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import _default_config

    return config_mod.load(str(config if config is not None else _default_config()))
