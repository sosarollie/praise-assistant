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

"""The fix-validation ScoringConfig, derived from this engine's ScoringPolicy."""

from __future__ import annotations

from typing import Final

from vvaharness.validation.constants.scoring import (
    CRITERION_NAME_FIELD,
    FIX_POLICY,
    STATUS_MULTIPLIER,
)
from vvaharness.validation.models.scoring import ScoringConfig

from ._justify import build_fix_justification

__all__ = ["FIX_CONFIG"]

#: Built from the policy, so gate set, weights, critical gates, and thresholds have one definition.
FIX_CONFIG: Final[ScoringConfig] = ScoringConfig.from_policy(
    FIX_POLICY,
    name="fix",
    criterion_name_field=CRITERION_NAME_FIELD,
    status_multiplier=STATUS_MULTIPLIER,
    justify=build_fix_justification,
)
