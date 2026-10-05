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

"""remediation_agent.policy_gate.matching — glob matching helpers.

The deterministic path-glob primitives the gate and diff inspection share:
:func:`_glob_match` (fnmatch with a ``**/`` zero-dir fallback) and
:func:`_first_match` (first changed file hitting any pattern)."""
from __future__ import annotations

import fnmatch


def _glob_match(path: str, pat: str) -> bool:
    """fnmatch with a ``**/`` suffix fallback so a bare root-level file (e.g.
    ``setup.py``) still matches a ``**/setup.py`` glob (fnmatch's ``*`` does not
    cross ``/``, and ``**/`` does not match zero leading dirs)."""
    if fnmatch.fnmatch(path, pat):
        return True
    if pat.startswith("**/") and fnmatch.fnmatch(path, pat[3:]):
        return True
    return False


def _first_match(files: list[str] | None, patterns: list[str]) -> str | None:
    for f in files or []:
        nf = (f or "").replace("\\", "/")
        if not nf:
            continue
        for pat in patterns:
            if _glob_match(nf, pat):
                return pat
    return None
