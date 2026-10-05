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

"""remediation_agent.policy_gate — deterministic eligibility gate.

The ONLY place that decides whether a finding may be sent to the LLM patch
agent. The runner MUST call :meth:`RemediationGate.decide` first and MUST
honour a non-PATCH decision (a denied CWE/path is short-circuited to
guidance-only output; the agent is never invoked, so no tokens are spent).

After the agent runs, the same gate inspects the generated diff's changed-file
set (:func:`inspect_diff` / :meth:`RemediationGate.forbidden_files`) so a patch
that touched a ``forbid_patch_paths`` (build/CI infra) or ``deny_paths``
(sensitive subsystem) file is caught and reverted regardless of what the model
did.

Design rules (mirrors the shipped inputs/remediation_policy.yaml semantics):
  * The decision is BINARY: a finding is either PATCHED or routed to
    GUIDANCE_ONLY. There is no "auto" vs "suggest" autonomy mode.
  * Fail-closed: any error loading/parsing policy ⇒ DENY everything.
  * Deny-list wins over allow-list.
  * default_action is ``allow`` or ``deny`` and applies only when neither the
    deny-list nor the allow-list matches.
  * Kill-switch (env var or sentinel file) is checked on EVERY decide() call so
    flipping it stops a long batch mid-flight without restart.
  * No LLM involvement — pure deterministic code.

Split into focused modules, re-exported here so callers keep using
``from vvaharness.remediation_agent.policy_gate import …`` unchanged:

  - :mod:`vvaharness.remediation_agent.policy_gate.action`   — Action / Decision value types
  - :mod:`vvaharness.remediation_agent.policy_gate.matching` — glob matching helpers
  - :mod:`vvaharness.remediation_agent.policy_gate.gate`     — the RemediationGate
  - :mod:`vvaharness.remediation_agent.policy_gate.diffscan` — diff inspection + verdict capping
"""
from __future__ import annotations

from vvaharness.remediation_agent.policy_gate.action import (  # noqa: F401
    Action,
    Decision,
)
from vvaharness.remediation_agent.policy_gate.diffscan import (  # noqa: F401
    cap_verdict,
    inspect_diff,
)
from vvaharness.remediation_agent.policy_gate.gate import (  # noqa: F401
    DEFAULT_POLICY_PATH,
    RULES_DIR,
    RemediationGate,
)
from vvaharness.remediation_agent.policy_gate.matching import (  # noqa: F401
    _first_match,
    _glob_match,
)

__all__ = [
    "Action", "Decision",
    "RemediationGate", "DEFAULT_POLICY_PATH", "RULES_DIR",
    "inspect_diff", "cap_verdict",
]
