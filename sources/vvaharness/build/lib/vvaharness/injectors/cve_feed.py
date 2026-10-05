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

"""Load known CVEs from a JSON file. Format is intentionally simple — adapt
to your tracker (NVD export, internal DB dump, etc.)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from vvaharness.models import CVE
from vvaharness.util import errlog as _errlog


def load_cves(path: str | Path) -> list[CVE]:
    p = Path(path)
    if not p.exists():
        return []
    # A present-but-malformed / hand-edited feed must DEGRADE rather than abort
    # the whole scan with a raw traceback. The STRUCTURAL load (read + JSON parse
    # + top-level shape) is all-or-nothing: if we can't even read the file or it
    # isn't a list / {"cves": [...]}, return [] and log.
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        # Accept either a bare list or {"cves": [...]}. Only treat a dict as a
        # wrapper when it actually carries a "cves" key — otherwise iterating
        # the dict yields its string keys, which then fail validation. A dict
        # without "cves" is malformed input, not a single CVE.
        if isinstance(data, dict):
            items = data.get("cves")
            if items is None:
                raise ValueError(
                    "CVE feed is a JSON object without a 'cves' key — expected "
                    "a list or {\"cves\": [...]}")
        else:
            items = data
        # Reject a non-list payload explicitly (e.g. {"cves": 123} or a bare
        # scalar) rather than iterating a string char-by-char or failing deep in
        # the loop.
        if not isinstance(items, list):
            raise TypeError(
                f"CVE feed payload must be a list, got {type(items).__name__}")
    except (OSError, ValueError, TypeError) as e:
        print(f"  [inject] WARN: could not load CVE feed {p} ({type(e).__name__}: "
              f"{e}); continuing with no injected CVEs.", file=sys.stderr)
        _errlog.log("inject.cves", str(p), e)
        return []

    # Per-ITEM validation is isolated: one malformed record only drops itself,
    # so a single bad entry in a shared/hand-edited feed cannot suppress the rest
    # of the known-CVE prioritization context. Each skip is logged individually.
    out: list[CVE] = []
    skipped = 0
    for idx, item in enumerate(items):
        try:
            out.append(CVE.model_validate(item))
        except (ValidationError, TypeError, ValueError) as e:
            skipped += 1
            cid = item.get("id") if isinstance(item, dict) else None
            unit = f"{p}#{idx}" + (f" ({cid})" if cid else "")
            _errlog.log("inject.cves.item", unit, e)
    if skipped:
        print(f"  [inject] WARN: skipped {skipped} malformed CVE record(s) in "
              f"{p}; loaded {len(out)} valid record(s).", file=sys.stderr)
    return out
