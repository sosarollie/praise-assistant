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

"""The per-finding processing loop: :func:`process_targets` walks each finding through ``plugin_runner.apply_plugin`` and checkpoints the result."""
from __future__ import annotations

import sys
from collections.abc import MutableMapping
from enum import Enum
from pathlib import Path

from vvaharness.backends.llm.registry import resolve as resolve_model
from vvaharness.models import RemediationKind
from vvaharness.orchestrator.checkpoints import (
    REMEDIATE_PREFIX,
    load_ckpt,
    save_ckpt,
    step_key_for,
)
from vvaharness.remediation_agent import policy as _policy
from vvaharness.remediation_agent.discovery import Layout
from vvaharness.remediation_agent.options import RemediateOptions
from vvaharness.remediation_agent.plugin_runner import (
    ENGINE_ID,
    apply_plugin,
    checkpoint_record,
    engine_model,
)
from vvaharness.remediation_agent.target import RemediationTarget
from vvaharness.report.redact import redact
from vvaharness.util.status import stage

__all__ = ["model_banner", "process_targets", "remediate_one", "step_key_of"]


class _Result(Enum):
    FIXED = "fixed"
    NOT_FIXED = "not fixed"
    FAILED = "failed"


def _result_for_kind(kind: RemediationKind | str | None, *,
                     diff_captured: bool | None = None) -> _Result:
    """Classify a completed attempt by what the harness proved it did."""
    value = kind.value if isinstance(kind, RemediationKind) else kind
    # New checkpoints carry finding-scoped diff proof. Preserve legacy resume
    # behavior when that field is absent, but never call a proven no-diff
    # attempt fixed.
    if diff_captured is False:
        return _Result.NOT_FIXED
    return (_Result.FIXED
            if value in (RemediationKind.EDITS_APPLIED.value,
                         RemediationKind.PULL_REQUEST.value)
            else _Result.NOT_FIXED)


def model_banner(cfg) -> str:
    """One-line description of the model/backend doing remediation."""
    try:
        mid, via, _ = resolve_model(cfg.models.remediate)
        return f"{mid} [{via}]"
    except Exception:  # noqa: BLE001 — banner is best-effort only
        return "unknown"


def step_key_of(target: RemediationTarget, cfg) -> str:
    """The resume-checkpoint step key for *target*, computable before the engine runs so nothing comes from the attempt being skipped."""
    # Read at call time rather than bound at import, so a late-stamped version is still keyed on.
    from vvaharness import __version__

    model, backend = engine_model(cfg)
    return step_key_for(REMEDIATE_PREFIX, engine_id=ENGINE_ID,
                        engine_version=__version__, case_id=target.case_id,
                        model=model, backend=backend)


def _finding_identity(target: RemediationTarget) -> str:
    """The identity recorded IN the checkpoint (the ``case_id``), so a hit can be checked against it before a skip proves WHICH finding it covers."""
    return target.case_id


def remediate_one(target: RemediationTarget, *, idx: int, total: int, layout: Layout,
                  cfg, repo_path: Path, opts: RemediateOptions,
                  policy_ctx=None, _results: list[_Result] | None = None) -> bool:
    """Process a single finding: skip-if-cached (resume), otherwise run the agent and checkpoint the result; one bad finding never aborts the run."""
    label = redact(target.label)
    out_dir = layout.rem_dir / target.slug
    step = step_key_of(target, cfg)
    fid = _finding_identity(target)

    # Skip only when a checkpoint exists AND its finding identity matches — existence alone isn't proof of completion.
    if opts.resume:
        cached = load_ckpt(layout.ckpt_dir, layout.run_id, step)
        if isinstance(cached, dict) and cached.get("finding_id") == fid:
            cached_result = _result_for_kind(
                cached.get("kind"), diff_captured=cached.get("diff_captured"))
            with stage(f"{label} — cached", n=idx, total=total) as progress:
                if cached_result is _Result.NOT_FIXED:
                    progress.mark_incomplete("not fixed")
            if _results is not None:
                _results.append(cached_result)
            return True

    try:
        # Verbose output must stay plain; otherwise defer to stage()'s TTY gate so
        # redirected S10 logs never receive spinner frames or cursor escapes.
        animate = False if opts.verbose else None
        with stage(label, n=idx, total=total, animate=animate) as progress:
            remediation = apply_plugin(target, out_dir, cfg=cfg, repo=repo_path,
                                       mode=opts.mode, verbose=opts.verbose,
                                       policy_ctx=policy_ctx)
            # Bind the finding identity into the checkpoint so a later --resume can authenticate it.
            record = {**checkpoint_record(target, out_dir, remediation),
                      "finding_id": fid}
            save_ckpt(layout.ckpt_dir, layout.run_id, step, record)
            result = _result_for_kind(
                remediation.kind, diff_captured=bool(remediation.diff))
            if result is _Result.NOT_FIXED:
                progress.mark_incomplete("not fixed")
        if _results is not None:
            _results.append(result)
        return True
    except Exception as e:  # noqa: BLE001 — one bad finding shouldn't abort
        print(f"    WARN: remediation failed for finding {target.index} "
              f"({redact(str(e))}); continuing.", file=sys.stderr)
        if _results is not None:
            _results.append(_Result.FAILED)
        return False


def process_targets(targets: list[RemediationTarget], *, layout: Layout, cfg,
                    repo_path: Path, opts: RemediateOptions,
                    report: Path | None = None,
                    progress: MutableMapping[str, int] | None = None) -> int:
    """Walk *targets* sequentially, remediating each; returns exit code 0 when all were processed."""
    total = len(targets)

    # No-op unless step_remediate.enforce_policy is true.
    policy_ctx = _policy.build_context(cfg, repo_path)
    if policy_ctx.enabled:
        print("  [Remediation Agent] policy gate ENABLED "
              "(deny-list + playbook + diff post-gate)", file=sys.stderr)
    results: list[_Result] = []
    processed_ok = [
        remediate_one(target, idx=i, total=total, layout=layout, cfg=cfg,
                      repo_path=repo_path, opts=opts, policy_ctx=policy_ctx,
                      _results=results)
        for i, target in enumerate(targets, start=1)
    ]
    fixed = results.count(_Result.FIXED)
    not_fixed = results.count(_Result.NOT_FIXED)
    failed = results.count(_Result.FAILED)
    processed = sum(processed_ok)
    if progress is not None:
        # ``not_fixed`` is the true outcome count: an infrastructure failure did
        # not fix the finding either.  Keep the three public fields exhaustive so
        # log consumers can rely on attempted == fixed + not_fixed.
        progress.update(
            attempted=total,
            fixed=fixed,
            not_fixed=total - fixed,
        )
    failure_note = f", {failed} failed" if failed else ""
    marker = "✗" if failed else ("○" if not_fixed else "✓")
    print(f"\n  {marker} {processed}/{total} findings processed — "
          f"{fixed}/{total} fixed, {not_fixed} not fixed{failure_note}",
          file=sys.stderr)
    # Best-effort — never fails the run.
    from vvaharness.remediation_agent.report_augment import augment_reports
    augment_reports(repo_path, report)
    return 0 if failed == 0 else 1
