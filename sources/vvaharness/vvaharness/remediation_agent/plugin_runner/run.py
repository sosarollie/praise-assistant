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

"""remediation_agent.plugin_runner.run — the harness guards, and the engine they wrap."""
from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vvaharness.models import (
    LLM_REGISTRY,
    Provenance,
    Remediation,
    RemediationEvidence,
    RemediationKind,
    finalize,
)
from vvaharness.remediation_agent import artifacts
from vvaharness.remediation_agent import policy as _policy
from vvaharness.remediation_agent.models import RemediationVerdict, to_evidence
from vvaharness.remediation_agent.target import RemediationTarget
from vvaharness.util.tokens import TOKENS, Spend, reported_between

__all__ = [
    "Amended",
    "EngineRequest",
    "GuardedCall",
    "apply_plugin",
    "call_with_guards",
    "checkpoint_record",
    "engine_model",
    "harness_amend",
]

#: Engine identity stamped on every attempt this module produces.
ENGINE_ID = "vvaharness.remediation_agent"


@dataclass(frozen=True)
class EngineRequest:
    """One finding handed to a remediation engine, with the run context it needs."""

    target: RemediationTarget
    repo: Path
    mode: str
    cfg: Any
    verbose: bool = False
    policy_ctx: Any = None

    @property
    def enforce(self) -> bool:
        """True when a policy context is present AND switched on."""
        return self.policy_ctx is not None and getattr(self.policy_ctx, "enabled", False)


@dataclass(frozen=True)
class GuardedCall:
    """What the guards observed around one engine call; ``pre`` is ``None`` on the denied path."""

    verdict: RemediationVerdict
    snapshot: dict[str, str | None] = field(default_factory=dict)
    pre: Any = None
    meta: dict = field(default_factory=dict)
    denied: bool = False
    started: datetime | None = None
    spend_before: Spend = Spend()


@dataclass(frozen=True)
class Amended:
    """The harness's own account of an attempt, overriding the engine's self-report."""

    remediation: Remediation
    reverted_paths: tuple[str, ...] = ()
    meta: dict = field(default_factory=dict)


def call_with_guards(fn: Callable[..., Any], request: EngineRequest) -> GuardedCall:
    """Run *fn* behind the harness's pre-call guards (policy gate, then snapshot) and return what they saw."""
    from vvaharness.remediation_agent import plugin_runner as _pr

    started = datetime.now(timezone.utc)
    spend_before = TOKENS.spend()
    meta = _base_meta(request, started)
    pre = _policy.pre_decision(request.policy_ctx, request.target) if request.enforce else None
    if request.verbose:
        _trace_policy(request, pre)
    if pre is not None and not pre.allowed:
        return _denied(request, pre, meta, started, spend_before)
    snapshot = artifacts.snapshot_files(request.repo, _snapshot_targets(request))
    raw = _call_engine(fn, request, pre)
    return GuardedCall(verdict=_pr._coerce_verdict(raw, request.target),
                       snapshot=snapshot, pre=pre, meta=meta, started=started,
                       spend_before=spend_before)


def harness_amend(remediation: RemediationVerdict, snapshot: dict[str, str | None], *,
                  request: EngineRequest, pre: Any = None, denied: bool = False,
                  started: datetime | None = None,
                  spend_before: Spend = Spend()) -> Amended:
    """Replace the engine's self-report with what the harness can prove, reading the whole working tree rather than the reported ``changes``."""
    reverted: tuple[str, ...] = ()
    meta: dict = {}
    if pre is not None:
        post = _policy.enforce_post(request.policy_ctx, request.target, remediation, pre,
                                    repo=request.repo, before_snapshot=snapshot)
        reverted = tuple(post.reverted)
        meta = _post_meta(pre, post)
    diff = artifacts.derive_diff(request.repo, snapshot,
                                 [c.file for c in remediation.changes if c.file])
    evidence = to_evidence(remediation, provenance=_provenance(
        request, denied=denied, started=started, spend_before=spend_before))
    # The harness supplies mode, diff and file list; the engine couldn't know the first two and is unreliable on the third.
    contract = finalize(evidence, mode=request.mode, diff=diff,
                        files_touched=_files_touched(request.repo, evidence, snapshot))
    meta = _reconcile_post_meta(meta, contract)
    return Amended(remediation=contract, reverted_paths=reverted, meta=meta)


def _reconcile_post_meta(meta: dict, remediation: Remediation) -> dict:
    """Prevent the policy audit label from contradicting persisted evidence.

    The post-gate necessarily runs before the canonical remediation contract is
    finalized.  In a multi-finding run it can observe an earlier finding's
    still-dirty worktree patch, so its provisional ACCEPT is not proof that the
    current finding produced a diff.  The finalized, per-attempt diff is the
    authority used by ``diff_captured`` and must also bound ``final_verdict``.
    """
    # Pre-gate denials and post-gate reverts already carry their own stronger
    # rejection reason.  This reconciliation is for an otherwise permitted
    # patch attempt only.
    if meta.get("policy_action") != "patch" or meta.get("policy_reverted"):
        return meta
    no_action = remediation.kind in (
        RemediationKind.NO_ACTION, RemediationKind.ALREADY_RESOLVED)
    if remediation.diff and not no_action:
        return meta
    reason = "no_diff_captured" if not remediation.diff else "remediation_not_applied"
    reconciled = {
        **meta,
        "policy_reason": reason,
        "final_verdict": "REJECT",
    }
    if meta.get("policy_reason") != reason:
        reconciled["policy_pre_reason"] = meta.get("policy_reason", "")
    return reconciled


def apply_plugin(target: RemediationTarget, out_dir: Path, *, cfg, repo: Path,
                 mode: str = "fix", verbose: bool = False,
                 policy_ctx=None) -> Remediation:
    """Remediate one *target* through the guards and persist its artefacts."""
    from vvaharness.remediation_agent import plugin_runner as _pr

    request = EngineRequest(target=target, repo=Path(repo), mode=mode, cfg=cfg,
                            verbose=verbose, policy_ctx=policy_ctx)
    guarded = call_with_guards(_pr._invoke, request)
    amended = harness_amend(guarded.verdict, guarded.snapshot,
                            request=request, pre=guarded.pre, denied=guarded.denied,
                            started=guarded.started, spend_before=guarded.spend_before)
    artifacts.write_case(out_dir, guarded.verdict, amended.remediation,
                         meta={**guarded.meta, **amended.meta}, target=target,
                         reverted_paths=amended.reverted_paths)
    return amended.remediation


def checkpoint_record(target: RemediationTarget, out_dir: Path,
                      remediation: Remediation) -> dict:
    """The small JSON record ``--resume`` stores for one processed finding; deliberately not the whole ``Remediation``."""
    disposition = remediation.disposition
    return {
        "finding_index": target.index,
        "artifact_dir": str(out_dir),
        "kind": remediation.kind.value,
        "disposition": disposition.value if disposition is not None else None,
        "diff_captured": bool(remediation.diff),
    }


def _files_touched(repo: Path, evidence: RemediationEvidence,
                   snapshot: dict[str, str | None]) -> tuple[str, ...]:
    """What actually changed under *repo* — proven where possible (git status, then snapshot), never merely claimed by the engine."""
    proven = artifacts.changed_files_whole_tree(repo)
    if proven:
        return tuple(proven)
    from_snapshot = artifacts.changed_since_snapshot(repo, snapshot)
    claimed = [c.file for c in evidence.changes if _resolves(repo, c.file)]
    return tuple(dict.fromkeys([*from_snapshot, *claimed]))


def _resolves(repo: Path, ref: str) -> bool:
    """True when *ref* names a real file confined to *repo*."""
    if not ref:
        return False
    resolved = artifacts._safe_repo_path(repo, ref)
    return resolved is not None and resolved.is_file()


def _base_meta(request: EngineRequest, started: datetime) -> dict:
    """Display-only context the summary renderer and the audit sidecar carry."""
    return {
        "severity": request.target.severity,
        "title": request.target.title,
        "file": request.target.file,
        "mode": request.mode,
        "generated": started.isoformat(),
    }


def _post_meta(pre: Any, post: Any) -> dict:
    """The audit trail of one post-gate pass, for the evidence sidecar."""
    reason = post.reason or pre.decision.reason
    meta = {
        "policy_action": pre.decision.action.value,
        "policy_reason": reason,
        "final_verdict": post.final_verdict,
    }
    if post.reason:
        meta["policy_pre_reason"] = pre.decision.reason
    if post.reverted:
        meta["policy_reverted"] = post.reverted
        meta["policy_matched_globs"] = post.matched_globs
    return meta


def _trace_policy(request: EngineRequest, pre: Any) -> None:
    """Surface the policy decision + resolved playbook strategy under --verbose."""
    from vvaharness.remediation_agent import plugin_runner as _pr

    if pre is not None:
        _pr._dump_policy(request.target, pre)
        return
    print(f"    [policy] enforcement disabled "
          f"(step_remediate.enforce_policy=false) — no policy gate or "
          f"playbook strategy injected for finding {request.target.index}",
          file=sys.stderr)


def _denied(request: EngineRequest, pre: Any, meta: dict, started: datetime,
            spend_before: Spend) -> GuardedCall:
    """Short-circuit a policy-denied finding to guidance: no model call, no tokens."""
    verdict = _policy.guidance_verdict(request.policy_ctx, request.target, pre)
    print(f"    [policy] pre-gate guidance-only for finding "
          f"{request.target.index} ({pre.decision.reason}) — agent skipped",
          file=sys.stderr)
    return GuardedCall(
        verdict=verdict,
        meta={**meta, "policy_action": pre.decision.action.value,
              "policy_reason": pre.decision.reason, "final_verdict": "REJECT"},
        denied=True,
        started=started,
        spend_before=spend_before,
    )


def _snapshot_targets(request: EngineRequest) -> list[str]:
    """Return files needed to prove and, when necessary, revert S10 edits."""
    targets = [request.target.file] if request.target.file else []
    # Workflow reference integrity is enforced from the pre-edit repository:
    # known pins are reusable evidence, and every workflow needs a rollback
    # baseline even when the model omits it from ``changes``.
    targets.extend(_policy.workflow_snapshot_paths(request.repo))
    if not request.enforce:
        return targets
    gate = getattr(request.policy_ctx, "gate", None)
    patterns = ([*getattr(gate, "forbid_patch_paths", []),
                 *getattr(gate, "deny_paths", [])] if gate else [])
    return list(dict.fromkeys(
        [*targets, *_policy.worktree_forbidden_matches(request.repo, patterns)]))


def _call_engine(fn: Callable[..., Any], request: EngineRequest, pre: Any) -> Any:
    """Invoke the engine seam, passing the policy context only on the enforced path."""
    if pre is not None:
        return fn(request.target, request.cfg, request.repo, request.mode,
                  request.verbose, pre=pre, ctx=request.policy_ctx)
    return fn(request.target, request.cfg, request.repo, request.mode, request.verbose)


def _provenance(request: EngineRequest, *, denied: bool = False,
                started: datetime | None = None,
                spend_before: Spend = Spend()) -> Provenance:
    """Stamp who produced this attempt; ``engine_version`` is load-bearing since it's hashed into the resume checkpoint key."""
    from vvaharness import __version__

    # Denied = refused before any token was spent, so naming a model would assert a call that never happened.
    model, backend = ("", "") if denied else engine_model(request.cfg)
    # Denied spent nothing by construction; otherwise take whatever the backend reported.
    usd, turns = (0.0, 0) if denied else reported_between(spend_before, TOKENS.spend())
    return Provenance(engine=ENGINE_ID, engine_version=__version__,
                      model=model, backend=backend, started=started,
                      ended=datetime.now(timezone.utc) if started else None,
                      usd=usd, turns=turns)


def engine_model(cfg) -> tuple[str, str]:
    """Resolve (model id, backend) for the remediate role; public because ``runner.step_key_of`` hashes the same pair into the resume key."""
    from vvaharness.backends.llm.registry import resolve as resolve_model

    try:
        mid, via, _ = resolve_model(cfg.models.remediate)
    except Exception:  # noqa: BLE001 — provenance is attribution, never a hard failure
        return "", ""
    # Registry-qualified: bare "cli" is a subprocess here and an in-process SDK in validation.
    return str(mid), f"{LLM_REGISTRY}:{via}"
