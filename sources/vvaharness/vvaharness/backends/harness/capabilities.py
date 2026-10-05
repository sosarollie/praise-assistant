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

"""What a harness backend does differently, for hosts that must shape input before running it.

Keyed by ``via`` rather than declared on :class:`Harness` because callers ask while building a
prompt, before any harness exists -- and instantiating one would import an optional dependency.

**Scope: the harness agent-graph route (S10 remediate / S11 validate) ONLY.** A ``via`` value
is no longer enough to identify a transport: ``via: deepagents`` on a detection role (S0-S9)
selects the detection seam (``backends.llm.deepagents`` — its ``dispatch_prompt`` /
``dispatch_agentic`` wrappers), which returns raw text -- NOT the harness graph whose native
subagents carry an output schema. This table answers "what does the harness built by
``get_harness(via)`` do"; it must never be consulted about a detection-path ``prompt()``
call, where e.g. ``returns_schema_validated_reports=True`` would be false.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, NamedTuple

__all__ = ["HarnessCapabilities", "capabilities_for"]


class HarnessCapabilities(NamedTuple):
    """Backend traits a host must know before it can build the right prompt.

    Harness agent-graph route only — see the module docstring.
    """

    reads_injected_claude_config: bool
    returns_schema_validated_reports: bool


#: Unknown selectors get every trait off, so a new backend opts in rather than inheriting.
_NONE: Final = HarnessCapabilities(
    reads_injected_claude_config=False,
    returns_schema_validated_reports=False,
)

_BY_VIA: Final[Mapping[str, HarnessCapabilities]] = {
    # Claude Agent SDK convention: the session auto-loads `.claude/`, so rules need no inlining.
    "cli": HarnessCapabilities(
        reads_injected_claude_config=True,
        returns_schema_validated_reports=False,
    ),
    "sdk": HarnessCapabilities(
        reads_injected_claude_config=True,
        returns_schema_validated_reports=False,
    ),
    # Native subagents carry an output schema, so the host can synthesize gates
    # deterministically — on the harness graph only (module docstring).
    "deepagents": HarnessCapabilities(
        reads_injected_claude_config=False,
        returns_schema_validated_reports=True,
    ),
}


def capabilities_for(via: str | None) -> HarnessCapabilities:
    """Return the traits of the HARNESS *via* selects, all off for an unrecognised value."""
    return _BY_VIA.get(via or "", _NONE)
