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

"""remediation_agent.interactive — arrow-key issue picker for `vvaharness remediate -i`.

A dependency-free terminal menu: ↑/↓ move the highlight, Enter remediates the
highlighted finding, q/Esc exits anytime. Each row shows a ✅ once the finding
is remediated (the source of truth is the DONE_MARKER written into the report
markdown by ``report_parser.mark_done``), so completed state is visible and
persists across sessions.

On a non-interactive stream (CI, pipes, tests) the raw-key reader is
unavailable, so we fall back to a numbered prompt that accepts
``1,3-5 | all | pending | q``. Both paths funnel selected findings through the
SAME per-finding runner + checkpoint + mark-done logic.

Split into focused modules, re-exported here so callers keep using
``from vvaharness.remediation_agent.interactive import …`` unchanged:

  - :mod:`vvaharness.remediation_agent.interactive.keys`   — raw key input + decoding
  - :mod:`vvaharness.remediation_agent.interactive.render` — menu rendering + selection parsing
  - :mod:`vvaharness.remediation_agent.interactive.loop`   — the interactive remediation loops
"""
from __future__ import annotations

from vvaharness.remediation_agent.interactive.keys import (  # noqa: F401
    DOWN,
    ENTER,
    OTHER,
    QUIT,
    UP,
    decode_key,
)
from vvaharness.remediation_agent.interactive.loop import run_interactive  # noqa: F401
from vvaharness.remediation_agent.interactive.render import (  # noqa: F401
    parse_selection,
    render_rows,
)

__all__ = [
    "run_interactive", "parse_selection", "decode_key", "render_rows",
    "UP", "DOWN", "ENTER", "QUIT", "OTHER",
]
