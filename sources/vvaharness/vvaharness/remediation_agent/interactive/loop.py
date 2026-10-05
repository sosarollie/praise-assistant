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

"""The interactive remediation loops: :func:`run_interactive` picks the arrow-key TUI or numbered-prompt fallback, both funneling through :func:`_remediate_one`."""
from __future__ import annotations

import sys

from vvaharness.orchestrator.checkpoints import save_ckpt
from vvaharness.remediation_agent import policy as _policy
from vvaharness.remediation_agent import report_parser
from vvaharness.remediation_agent.interactive.keys import (
    DOWN,
    ENTER,
    QUIT,
    UP,
    _read_key,
)
from vvaharness.remediation_agent.interactive.render import (
    _clear_and_draw,
    parse_selection,
    render_rows,
)
from vvaharness.remediation_agent.plugin_runner import apply_plugin, checkpoint_record
from vvaharness.remediation_agent.runner import step_key_of
from vvaharness.report.redact import redact
from vvaharness.util.status import stage


def _remediate_one(target, *, report_path, rem_dir, ckpt_dir, run_id,
                   cfg, mode, verbose=False, policy_ctx=None) -> bool:
    """Run the agent for one finding, checkpoint it, and mark it done; never raises, returns False on failure so the menu keeps running."""
    out_dir = rem_dir / target.slug
    step = step_key_of(target, cfg)
    label = redact(target.label)
    try:
        # Verbose output must stay plain; otherwise defer to stage()'s TTY gate so
        # the numbered non-TTY fallback never emits spinner frames or cursor escapes.
        animate = False if verbose else None
        with stage(label, n=target.index, total=None, animate=animate):
            remediation = apply_plugin(target, out_dir, cfg=cfg, repo=rem_dir.parent,
                                       mode=mode, verbose=verbose,
                                       policy_ctx=policy_ctx)
            save_ckpt(ckpt_dir, run_id, step,
                      checkpoint_record(target, out_dir, remediation))

        report_parser.mark_done(report_path, target)
        target.done = True
        print(f"    → {out_dir}", file=sys.stderr)
        return True
    except Exception as e:  # noqa: BLE001
        print(f"    WARN: remediation failed for finding {target.index} "
              f"({redact(str(e))}); continuing.", file=sys.stderr)
        return False


def run_interactive(findings, *, report_path, rem_dir, ckpt_dir, run_id,
                    cfg, mode, out=None, verbose=False) -> int:
    """Interactive loop: arrow-key TUI on a real terminal, else the numbered-prompt fallback; always returns exit code 0."""
    out = out or sys.stderr
    session = 0
    # Build the policy context once (no-op unless step_remediate.enforce_policy).
    policy_ctx = _policy.build_context(cfg, rem_dir.parent)
    if policy_ctx.enabled:
        print("  [Remediation Agent] policy gate ENABLED "
              "(deny-list + playbook + diff post-gate)", file=sys.stderr)
    try:
        interactive_tty = sys.stdin.isatty() and out.isatty()
    except Exception:  # noqa: BLE001
        interactive_tty = False

    if interactive_tty:
        session = _loop_tty(findings, report_path=report_path, rem_dir=rem_dir,
                            ckpt_dir=ckpt_dir, run_id=run_id, cfg=cfg, mode=mode,
                            out=out, verbose=verbose, policy_ctx=policy_ctx)
    else:
        session = _loop_prompt(findings, report_path=report_path, rem_dir=rem_dir,
                               ckpt_dir=ckpt_dir, run_id=run_id, cfg=cfg, mode=mode,
                               verbose=verbose, policy_ctx=policy_ctx)

    total_done = sum(1 for f in findings if f.done)
    print(f"\n  ✓ exited — {session} remediated this session "
          f"({total_done}/{len(findings)} total complete)", file=sys.stderr)
    return 0


def _loop_tty(findings, *, report_path, rem_dir, ckpt_dir, run_id, cfg, mode,
              out, verbose=False, policy_ctx=None) -> int:
    cursor = 0
    session = 0
    while True:
        _clear_and_draw(findings, cursor, out)
        try:
            key = _read_key()
        except RuntimeError:
            # Lost the raw TTY mid-loop — degrade to the prompt path.
            return session + _loop_prompt(
                findings, report_path=report_path, rem_dir=rem_dir,
                ckpt_dir=ckpt_dir, run_id=run_id, cfg=cfg, mode=mode,
                verbose=verbose, policy_ctx=policy_ctx)
        if key == QUIT:
            return session
        if key == UP:
            cursor = (cursor - 1) % len(findings)
        elif key == DOWN:
            cursor = (cursor + 1) % len(findings)
        elif key == ENTER:
            out.write("\033[2J\033[H")
            out.flush()
            if _remediate_one(findings[cursor], report_path=report_path,
                              rem_dir=rem_dir, ckpt_dir=ckpt_dir, run_id=run_id,
                              cfg=cfg, mode=mode, verbose=verbose,
                              policy_ctx=policy_ctx):
                session += 1


def _loop_prompt(findings, *, report_path, rem_dir, ckpt_dir, run_id, cfg,
                 mode, verbose=False, policy_ctx=None) -> int:
    session = 0
    while True:
        for row in render_rows(findings):
            print(row, file=sys.stderr)
        try:
            raw = input("  Select issues (e.g. 1,3-5 | all | pending | q): ")
        except (EOFError, KeyboardInterrupt):
            return session
        picks = parse_selection(raw, findings)
        if picks is None:
            return session
        for i in picks:
            if _remediate_one(findings[i], report_path=report_path,
                              rem_dir=rem_dir, ckpt_dir=ckpt_dir, run_id=run_id,
                              cfg=cfg, mode=mode, verbose=verbose,
                              policy_ctx=policy_ctx):
                session += 1
