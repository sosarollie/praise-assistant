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

"""Build the agent-facing validation manifest for one finding case."""

from __future__ import annotations

from vvaharness.models import FindingCase
from vvaharness.validation.models import Manifest

__all__ = ["build_manifest"]


def build_manifest(case: FindingCase, session_id: str) -> Manifest:
    """Build a single-finding manifest from a case, carrying the finding whole, nothing lost."""
    latest = case.attempts[-1] if case.attempts else None
    return Manifest(
        case_id=case.case_id,
        session_id=session_id,
        finding=case.finding,
        affected_files=list(latest.remediation.files_touched) if latest else [],
        post_results=False,
    )
