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

"""Profile-sourced values that seed the settings layer, bypassing the environment."""

from __future__ import annotations

from typing import TypedDict

from vvaharness.validation.enums import EffortLevel

__all__ = ["ValidateOverrides"]


class ValidateOverrides(TypedDict, total=False):
    """Profile-sourced tunables consumed by ``load_config()``.

    ``total=False`` because a profile sets only what it declares; every absent key falls back
    directly to the shipped default — the ``VVAHARNESS_*`` environment is never consulted for
    these (``_EnvScalars`` reads only its four credential/host-local scalars).
    """

    model: str
    via: str
    provider: str | None
    use_responses_api: bool | None
    effort: EffortLevel
    max_turns: int
    max_budget_usd: float | None
    max_findings: int | None
    security_architect_model: str
    penetration_tester_model: str
    cross_repo_analyzer_model: str
    validate_tools: str
    cache_markers: bool
