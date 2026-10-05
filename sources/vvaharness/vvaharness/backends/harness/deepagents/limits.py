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

"""Loop-budget constants for the DeepAgents backend, free of ``deepagents`` imports."""

from __future__ import annotations

#: Extra supersteps beyond max_turns, so a long tool loop isn't truncated mid-flight.
RECURSION_HEADROOM: int = 900

#: Per-request timeout (seconds) for every model call; a hang-stop, not a spend budget.
MODEL_TIMEOUT_SECONDS: float = 1800.0

#: Output-token ceiling; explicit, since langchain's 128000 default 400s on lower-cap models.
MODEL_MAX_OUTPUT_TOKENS: int = 64000

__all__ = ["MODEL_MAX_OUTPUT_TOKENS", "MODEL_TIMEOUT_SECONDS", "RECURSION_HEADROOM"]
