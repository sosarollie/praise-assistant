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

"""remediation_agent.policy — wire the deterministic gate + playbook into the agent.

This is the glue between :mod:`vvaharness.remediation_agent.policy_gate` (hard
enforcement), :mod:`vvaharness.remediation_agent.playbook` (fix strategy), and
the per-finding loop in :mod:`vvaharness.remediation_agent.plugin_runner`.

Two enforcement points:

  * **Pre-gate** (:func:`pre_decision`) — before any LLM call. A policy-denied
    CWE/path short-circuits to a guidance-only verdict (built by
    :func:`guidance_verdict`); the patch agent is never invoked, so no tokens
    are spent.
  * **Post-gate** (:func:`enforce_post`) — after the agent edits files. The
    generated diff's changed-file set is inspected; forbidden paths and unsafe
    reusable-workflow refs are **reverted on disk**, dropped from the verdict's
    ``changes``, and downgraded.

All policy enforcement is deterministic. Split into focused modules, re-exported
here so callers keep using ``from vvaharness.remediation_agent import policy``
(or ``from …policy import …``) unchanged:

  - :mod:`vvaharness.remediation_agent.policy.context`  — load gate + playbook once
  - :mod:`vvaharness.remediation_agent.policy.decide`   — pre-gate decision + guidance verdict
  - :mod:`vvaharness.remediation_agent.policy.postgate` — post-gate path enforcement
  - :mod:`vvaharness.remediation_agent.policy.revert`   — on-disk revert of forbidden edits
"""
from __future__ import annotations

from vvaharness.remediation_agent.policy.context import (  # noqa: F401
    PolicyContext,
    _resolve_input,
    _sr,
    build_context,
    policy_enabled,
)
from vvaharness.remediation_agent.policy.decide import (  # noqa: F401
    PreResult,
    guidance_verdict,
    pre_decision,
)
from vvaharness.remediation_agent.policy.postgate import (  # noqa: F401
    PostResult,
    enforce_post,
    worktree_forbidden_matches,
)
from vvaharness.remediation_agent.policy.revert import revert_files  # noqa: F401
from vvaharness.remediation_agent.policy.workflow_refs import (
    introduced_unsafe_workflow_refs,
    workflow_snapshot_paths,
)

__all__ = [
    "PolicyContext", "build_context", "policy_enabled",
    "PreResult", "pre_decision", "guidance_verdict",
    "PostResult", "enforce_post", "worktree_forbidden_matches",
    "revert_files", "introduced_unsafe_workflow_refs", "workflow_snapshot_paths",
]
