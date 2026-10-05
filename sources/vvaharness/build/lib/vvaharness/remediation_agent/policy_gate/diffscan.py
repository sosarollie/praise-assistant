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

"""remediation_agent.policy_gate.diffscan — diff inspection + verdict capping.

:func:`inspect_diff` extracts the changed-file set from a unified diff (git or
the harness's synthesized non-git diffs) so the post-gate can enforce path
policy on what actually changed. :func:`cap_verdict` maps the binary policy
decision + gate status to a clean ACCEPT/REJECT verdict."""
from __future__ import annotations

import re

from vvaharness.remediation_agent.policy_gate.action import Action

# Match both git diffs (``diff --git a/x b/x`` / ``+++ b/x``) and the
# synthesized non-git diffs the artifacts writer emits (same headers).
_DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)\s*$")
_PLUS_RE = re.compile(r"^\+\+\+ (?:b/)?(.+?)\s*$")
_MINUS_RE = re.compile(r"^--- (?:a/)?(.+?)\s*$")


def inspect_diff(diff_text: str | None) -> list[str]:
    """Extract the changed-file set (repo-relative paths) from a unified diff.

    Works for git diffs and the harness's synthesized non-git diffs. ``/dev/null``
    (added/deleted side) is ignored. Returns a de-duplicated, order-preserving
    list."""
    if not diff_text:
        return []
    out: list[str] = []
    seen: set[str] = set()

    def _add(p: str) -> None:
        p = (p or "").strip()
        if not p or p == "/dev/null":
            return
        if p not in seen:
            seen.add(p)
            out.append(p)

    for line in diff_text.splitlines():
        m = _DIFF_GIT_RE.match(line)
        if m:
            _add(m.group(2) or m.group(1))
            continue
        m = _PLUS_RE.match(line)
        if m:
            _add(m.group(1))
            continue
        m = _MINUS_RE.match(line)
        if m:
            _add(m.group(1))
    return out


def cap_verdict(action: Action, all_gates_passed: bool) -> str:
    """Map the binary policy decision + gate status to a clean ACCEPT/REJECT
    verdict. PATCH with all gates passed → ACCEPT; anything else (a denied
    finding routed to guidance, or a patch with a failed/skipped gate) →
    REJECT."""
    if action == Action.GUIDANCE_ONLY:
        return "REJECT"
    return "ACCEPT" if all_gates_passed else "REJECT"
