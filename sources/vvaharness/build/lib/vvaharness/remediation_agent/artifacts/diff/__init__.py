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

"""Captures a scoped diff of the edited files: a real ``git diff`` when possible, else a synthesized unified diff from a pre-edit snapshot."""
from __future__ import annotations

from vvaharness.remediation_agent.artifacts.diff.derive import derive_diff  # noqa: F401
from vvaharness.remediation_agent.artifacts.diff.gitcapture import (  # noqa: F401
    capture_git_diff,
    changed_files_whole_tree,
)
from vvaharness.remediation_agent.artifacts.diff.paths import (  # noqa: F401
    _norm_path,
    _safe_repo_path,
)
from vvaharness.remediation_agent.artifacts.diff.snapshot import (  # noqa: F401
    changed_since_snapshot,
    snapshot_files,
)
from vvaharness.remediation_agent.artifacts.diff.synth import (  # noqa: F401
    SYNTH_HEADER,
    synth_unified_diff,
)

__all__ = [
    "_norm_path", "_safe_repo_path",
    "changed_since_snapshot", "snapshot_files",
    "SYNTH_HEADER", "synth_unified_diff",
    "capture_git_diff", "changed_files_whole_tree",
    "derive_diff",
]
