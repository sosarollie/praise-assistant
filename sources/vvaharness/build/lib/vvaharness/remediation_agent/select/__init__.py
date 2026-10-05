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

"""remediation_agent.select — shared "top N by CVSS" finding selection.

A single home for the ``--top N`` selection used by BOTH remediation entry
points so the logic is never duplicated:

  * the standalone ``vvaharness remediate --repo <path> --top N`` command
    (:mod:`vvaharness.remediation_agent.remediate`), and
  * the in-pipeline ``vvaharness scan --remediate --top N`` step
    (:func:`vvaharness.orchestrator.scan._run_remediation`).

``--top N`` means *limit and reorder*: keep the N findings with the highest
CVSS base score, ordered highest→lowest, and skip the rest. Selection is built
on a priority queue (:mod:`heapq`) keyed by score; ties fall back to the item's
original position so the result is stable and reproducible.

Split into focused modules, re-exported here so callers keep using
``from vvaharness.remediation_agent.select import …`` unchanged:

  - :mod:`vvaharness.remediation_agent.select.topspec` — ``--top`` parsing + cap resolution
  - :mod:`vvaharness.remediation_agent.select.pq`      — the priority-queue selector
"""
from __future__ import annotations

from vvaharness.remediation_agent.select.pq import (  # noqa: F401
    band_score,
    select_top_by_cvss,
    select_top_logged,
)
from vvaharness.remediation_agent.select.topspec import (  # noqa: F401
    ALL_FINDINGS,
    _coerce_top_value,
    cfg_top_n_findings,
    parse_top_arg,
    resolve_top,
)

__all__ = [
    "ALL_FINDINGS", "_coerce_top_value", "cfg_top_n_findings", "parse_top_arg",
    "resolve_top",
    "band_score", "select_top_by_cvss", "select_top_logged",
]
