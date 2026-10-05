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

"""Plan execution pipeline: launch a fix-validation session and collect its verdicts."""

from __future__ import annotations

import logging
from typing import NamedTuple

from vvaharness.models import Decision, Provenance, Verdict
from vvaharness.validation.config import Config
from vvaharness.validation.constants.artifacts import MANIFEST_FILENAME
from vvaharness.validation.io.result_collector import CollectedFinding, collect_and_enrich
from vvaharness.validation.models import RunMetadata, unverifiable_row
from vvaharness.validation.models.plans import FixValidationPlan
from vvaharness.validation.session.errors import ValidationSessionError
from vvaharness.validation.session.launcher import launch_session

log = logging.getLogger(__name__)

__all__ = ["PlanOutcome", "execute_plan"]


class PlanOutcome(NamedTuple):
    """What one plan produced; session_failed distinguishes a crash from an honest INCONCLUSIVE."""

    findings: list[CollectedFinding]
    session_failed: bool = False


def _unverifiable(
    plan: FixValidationPlan, reason: str, provenance: Provenance
) -> PlanOutcome:
    """Build a single fail-closed result for *plan*, with no score rather than a zero."""
    verdict = Verdict(
        decision=Decision.INCONCLUSIVE,
        rationale=reason,
        score=None,
        recommendations=(f"Manual review required: {reason}",),
        produced_by=provenance,
    )
    return PlanOutcome(
        findings=[
            CollectedFinding(
                verdict=verdict,
                row=unverifiable_row(
                    tracking_id=plan.case_id, title=plan.case_id, reason=reason
                ),
            )
        ],
        session_failed=True,
    )


async def execute_plan(
    plan: FixValidationPlan,
    config: Config,
    *,
    post_results: bool,
    meta: RunMetadata,
) -> PlanOutcome:
    """Execute a fix-validation plan and return one verdict + row per finding."""
    stamp = plan.provenance
    workspace_dir = plan.workspace_dir
    workspace_dir.mkdir(parents=True, exist_ok=True)
    manifest = plan.manifest.model_copy(update={"post_results": post_results})
    manifest.write(workspace_dir / MANIFEST_FILENAME)
    log.info("Launching validation session %s for %s", plan.session_id, plan.case_id)
    try:
        await launch_session(config, manifest, workspace_dir, plan.output_dir)
    except ValidationSessionError as exc:
        log.exception("Validation session failed for %s", plan.case_id)
        meta.errors.append(f"Validation session failed: {plan.case_id}")
        return _unverifiable(plan, exc.reason_string(), stamp)
    collected = collect_and_enrich(workspace_dir, provenance=stamp, policy=plan.policy)
    if not collected:
        return _unverifiable(plan, "Validation session produced no results", stamp)
    return PlanOutcome(findings=collected)
