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

"""Drives remediation from an existing scan report: parses findings and walks them one-by-one via the per-finding loop."""

from __future__ import annotations

import sys
from pathlib import Path

from vvaharness.orchestrator.checkpoints import REMEDIATE_PREFIX, prune_stale_steps
from vvaharness.remediation_agent.discovery import (
    load_findings,
    locate_report,
    prepare_layout,
)
from vvaharness.remediation_agent.options import parse_options
from vvaharness.remediation_agent.runner import (
    model_banner,
    process_targets,
    step_key_of,
)
from vvaharness.remediation_agent.select import resolve_top


def remediate(repo: str | None, args=None, cfg=None) -> int:
    """Entry point for the ``remediate`` command; returns a process exit code (0 on success)."""
    if not repo:
        print("usage: vvaharness remediate --repo <path>", file=sys.stderr)
        return 2
    if cfg is None:
        print("  ✗ no config loaded — internal error: remediate() requires cfg.",
              file=sys.stderr)
        return 2

    try:
        opts = parse_options(args or [])
    except ValueError as e:
        print(f"  ✗ {e}", file=sys.stderr)
        return 2

    repo_path = Path(repo)
    if not repo_path.exists():
        print(f"  ✗ no such path: {repo}", file=sys.stderr)
        return 1

    report, rc = locate_report(repo_path)
    if report is None:
        return rc

    # Interactive mode is a manual picker, so a profile cap must not silently pre-truncate the list; an explicit --top N still applies.
    if opts.interactive and opts.top is None:
        top = None
    else:
        top = resolve_top(opts.top, cfg)
    print(f"  [Remediation Agent] report: {report}", file=sys.stderr)
    found = load_findings(report, top)
    findings = found.selected

    n = len(findings)
    if n == 0:
        print("  ✓ identified 0 SAST issue(s) — nothing to remediate.",
              file=sys.stderr)
        return 0

    layout = prepare_layout(repo_path)
    # Drop checkpoint rows no finding in the current report claims; uses discovered, not the --top N subset, so unselected findings still resume correctly.
    prune_stale_steps(layout.run_id, REMEDIATE_PREFIX,
                      [step_key_of(t, cfg) for t in found.discovered])
    print(f"  identified {n} SAST issue(s) to remediate", file=sys.stderr)
    print(f"  [Remediation Agent] model: {model_banner(cfg)}  mode={opts.mode}",
          file=sys.stderr)
    print(f"  [Remediation Agent] artefacts → {layout.rem_dir}", file=sys.stderr)
    if opts.verbose:
        print("  [Remediation Agent] verbose: printing prompt + raw LLM response "
              "per finding", file=sys.stderr)

    # Interactive: let the user pick which issues to remediate.
    if opts.interactive:
        from vvaharness.remediation_agent.interactive import run_interactive
        return run_interactive(findings, report_path=report,
                               rem_dir=layout.rem_dir, ckpt_dir=layout.ckpt_dir,
                               run_id=layout.run_id, cfg=cfg, mode=opts.mode,
                               verbose=opts.verbose)

    # The report's own ordinals are kept; after a --top N selection they are no longer 1..N.
    return process_targets(findings, layout=layout, cfg=cfg,
                           repo_path=repo_path, opts=opts, report=report)

