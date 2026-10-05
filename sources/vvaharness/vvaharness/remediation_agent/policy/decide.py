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

"""remediation_agent.policy.decide — the pre-gate (before any LLM call)."""
from __future__ import annotations

from dataclasses import dataclass

from vvaharness.remediation_agent.frameworks import language_for
from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.remediation_agent.playbook import Strategy
from vvaharness.remediation_agent.policy.context import PolicyContext
from vvaharness.remediation_agent.policy_gate import Decision
from vvaharness.remediation_agent.target import RemediationTarget


@dataclass
class PreResult:
    """Outcome of the pre-gate for one finding."""
    decision: Decision
    cwe: str | None
    strategy: Strategy | None
    # Convenience: the agent may run iff this is True.
    @property
    def allowed(self) -> bool:
        return self.decision.may_generate_patch


def pre_decision(ctx: PolicyContext, target: RemediationTarget) -> PreResult:
    """Decide whether *target* may be patched and, if so, resolve its strategy, from the finding's typed CWE and path."""
    cwe = target.finding.cwe
    file_path = target.finding.file
    decision = ctx.gate.decide(cwe, file_path)
    strategy = None
    if decision.may_generate_patch:
        lang = language_for(file_path)
        # The playbook is SUPPLEMENTARY context, not a second gate — the policy gate alone owns allow/deny.
        strategy = ctx.playbook.resolve(cwe, lang, ctx.frameworks)
    return PreResult(decision=decision, cwe=cwe, strategy=strategy)


def guidance_verdict(ctx: PolicyContext, target: RemediationTarget,
                     pre: PreResult) -> RemediationVerdict:
    """Build a plain DENIED verdict for a policy-denied finding, carrying only the deny reason."""
    reason = pre.decision.reason
    return RemediationVerdict(
        finding_index=target.index,
        verdict="Denied",
        root_cause="",
        changes=[],
        recommendations=[],
        summary=f"Denied by policy ({reason}). No patch generated.",
    )
