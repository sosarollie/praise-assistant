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

"""Permission evaluation predicates used by PermissionsPolicy.

Write is gated to the session's permitted output files directly under the target dir.
Bash is denied outright by PermissionsPolicy (no shell execution in a validation session),
so no command-parsing predicates live here.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from vvaharness.backends.harness.models import PermissionDecision

if TYPE_CHECKING:
    from collections.abc import Mapping


def _resolve_write_path(
    input_data: Mapping[str, object], resolved_target: Path
) -> Path | None:
    """Resolve Write's file_path, anchoring a relative path under the target dir."""
    raw_path = input_data.get("file_path", "")
    if not isinstance(raw_path, str) or not raw_path:
        return None
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = resolved_target / candidate
    try:
        return candidate.resolve()
    except (ValueError, OSError):
        return None


def _under_target(resolved: Path, resolved_target: Path) -> bool:
    """True when ``resolved`` sits directly in ``resolved_target`` (case-insensitive)."""
    return os.path.normcase(str(resolved.parent)) == os.path.normcase(str(resolved_target))


def evaluate_write(
    input_data: Mapping[str, object],
    resolved_target: Path,
    allowed_output_files: frozenset[str],
) -> PermissionDecision:
    """Allow Write only to a permitted output file directly under the target dir."""
    resolved = _resolve_write_path(input_data, resolved_target)
    if os.environ.get("VVAHARNESS_DEBUG"):
        print(
            f"  [s11-writegate] raw={input_data.get('file_path')!r} "
            f"resolved={resolved} target={resolved_target}",
            file=sys.stderr,
        )
    if resolved is None:
        return PermissionDecision(False, "Write path missing or unresolvable", True)
    if not _under_target(resolved, resolved_target) or resolved.name not in allowed_output_files:
        return PermissionDecision(False, f"Write to disallowed path: {resolved}", True)
    return PermissionDecision(True)


__all__ = ["evaluate_write"]
