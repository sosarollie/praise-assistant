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

"""The one function that picks between ``git diff`` and the synthesized fallback, so the diff is the harness's account, not the engine's."""
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff.gitcapture import capture_git_diff
from vvaharness.remediation_agent.artifacts.diff.synth import synth_unified_diff

__all__ = ["derive_diff"]


def derive_diff(repo: Path, snapshot: dict[str, str | None] | None,
                changed: Sequence[str]) -> str:
    """Return the unified diff for *changed* under *repo* (real ``git diff`` preferred, else synthesized from *snapshot*), or "" when nothing changed."""
    diff = capture_git_diff(Path(repo), list(changed))
    if not diff and snapshot is not None:
        diff = synth_unified_diff(Path(repo), snapshot, extra_files=list(changed))
    return diff or ""
