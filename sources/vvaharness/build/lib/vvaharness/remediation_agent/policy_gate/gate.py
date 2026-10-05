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

"""remediation_agent.policy_gate.gate — the deterministic eligibility gate.

:class:`RemediationGate` loads the shipped ``remediation_policy.yaml`` (via
:mod:`…policy_gate.loader`) and is the ONLY place that decides whether a finding
may be sent to the LLM patch agent (:meth:`RemediationGate.decide`) and which
on-disk changed files must be reverted after the agent runs
(:meth:`forbidden_files` / :meth:`patch_touches_forbidden` /
:meth:`changed_paths_hit_deny`)."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from vvaharness.remediation_agent.policy_gate.action import (
    _FAIL_CLOSED,
    Action,
    Decision,
)
from vvaharness.remediation_agent.policy_gate.loader import _norm_cwe, parse_policy
from vvaharness.remediation_agent.policy_gate.matching import _first_match, _glob_match
from vvaharness.remediation_agent.rule_paths import locate_rule

log = logging.getLogger(__name__)

def _default_policy_path() -> Path:
    """Locate the policy in a source checkout or an installed wheel."""
    return locate_rule("remediation_policy.yaml", __file__)


DEFAULT_POLICY_PATH = _default_policy_path()
RULES_DIR = DEFAULT_POLICY_PATH.parent

_TRUE = ("1", "true", "yes", "on")


class RemediationGate:

    def __init__(self, policy_path: Path | str | None = None):
        data = parse_policy(Path(policy_path) if policy_path else DEFAULT_POLICY_PATH)
        self._data = data
        self._loaded = data is not None

    @property
    def deny_paths(self) -> list[str]:
        return list(self._data.deny_paths) if self._data else []

    @property
    def forbid_patch_paths(self) -> list[str]:
        return list(self._data.forbid_patch_paths) if self._data else []

    # ---------------------------------------------------------------- decide
    def decide(self, cwe_id: str | None, file_path: str) -> Decision:
        """Return the maximum action permitted for this finding.

        The caller MUST NOT invoke the patch agent unless
        ``decision.may_generate_patch`` is True.
        """
        d = self._data
        if not self._loaded or d is None:
            return _FAIL_CLOSED

        # 0. kill-switch — checked on EVERY call.
        if d.kill_env and os.environ.get(d.kill_env, "").strip().lower() in _TRUE:
            return Decision(Action.GUIDANCE_ONLY, "kill_switch_env")
        if d.kill_file and d.kill_file.exists():
            return Decision(Action.GUIDANCE_ONLY, "kill_switch_file")

        cwe = _norm_cwe(cwe_id)
        if not cwe:
            return Decision(Action.GUIDANCE_ONLY, "unmapped_cwe")

        # 1. deny-list (incl. descendants) — absolute, wins over everything.
        if cwe in d.deny:
            return Decision(Action.GUIDANCE_ONLY, d.deny[cwe],
                            matched_rule=f"deny:{cwe}")

        # 2. sensitive-path guard — blocks even allowed CWEs.
        norm_path = (file_path or "").replace("\\", "/")
        for pat in d.deny_paths:
            if _glob_match(norm_path, pat):
                return Decision(Action.GUIDANCE_ONLY,
                                f"sensitive_path:{pat}",
                                matched_rule=f"deny_path:{pat}")

        # 3. allow-list — explicit patch eligibility.
        if cwe in d.allow:
            return Decision(Action.PATCH, "allow_list",
                            matched_rule=f"allow:{cwe}")

        # 4. default.
        return Decision(d.default, "default_action")

    # ----------------------------------------------------------- patch gates
    def patch_touches_forbidden(self, changed_files: list[str]) -> str | None:
        """Return the matching glob if any file in the diff hits
        ``forbid_patch_paths`` (build/test/CI infra). The caller MUST reject the
        candidate — running build/test against an LLM-modified build script is
        arbitrary code execution on the scanner host."""
        return _first_match(changed_files, self.forbid_patch_paths)

    def changed_paths_hit_deny(self, changed_files: list[str]) -> str | None:
        """Return the matching glob if any file in the diff hits ``deny_paths``
        (sensitive subsystem). The caller should revert that file and downgrade
        the verdict to guidance."""
        return _first_match(changed_files, self.deny_paths)

    def forbidden_files(self, changed_files: list[str]) -> list[str]:
        """The subset of *changed_files* that hit forbid_patch_paths OR
        deny_paths — i.e. every file that must be reverted from disk."""
        bad: list[str] = []
        for f in changed_files or []:
            nf = (f or "").replace("\\", "/")
            if not nf:
                continue
            if (_first_match([nf], self.forbid_patch_paths)
                    or _first_match([nf], self.deny_paths)):
                bad.append(f)
        return bad
