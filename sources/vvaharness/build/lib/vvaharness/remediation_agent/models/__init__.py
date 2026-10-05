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

"""remediation_agent.models — the structured-output contract for one remediation."""
from __future__ import annotations

from vvaharness.remediation_agent.models.change import Change  # noqa: F401
from vvaharness.remediation_agent.models.fixer import FixerResult, FixerStatus
from vvaharness.remediation_agent.models.gates import (  # noqa: F401
    EvidenceGateStatus,
    Gates,
    GateStatus,
)
from vvaharness.remediation_agent.models.verdict import (  # noqa: F401
    RemediationVerdict,
    Verdict,
    to_evidence,
)

__all__ = ["Gates", "GateStatus", "EvidenceGateStatus", "Change",
           "FixerResult", "FixerStatus", "RemediationVerdict", "Verdict",
           "to_evidence"]
