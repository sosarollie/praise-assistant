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

"""Stamping each SARIF result's ``partialFingerprints`` with the case id the harness minted for it, as a post-pass since the SARIF emitter never holds a typed ``Finding``."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from vvaharness.models import FinalReport

__all__ = ["FINGERPRINT_KEY", "stamp_case_ids"]

#: Versioned with the id scheme it carries, per the SARIF convention for this property.
FINGERPRINT_KEY = "vvaFindingId/v1"


def _result_location(result: object) -> tuple[str, int] | None:
    """Return a result's ``(uri, startLine)``, or ``None`` when it has no physical location."""
    try:
        physical = result["locations"][0]["physicalLocation"]  # type: ignore[index]
        uri = str(physical["artifactLocation"]["uri"]).replace("\\", "/")
        return uri, int(physical["region"]["startLine"])
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def _matches(result: object, file: str, line: int) -> bool:
    """Whether *result* sits at the finding's location, comparing on the path tail since the SARIF uri may carry a prefix the typed finding does not."""
    located = _result_location(result)
    if located is None:
        return False
    uri, start_line = located
    wanted = file.replace("\\", "/")
    return start_line == line and (uri.endswith(wanted) or wanted.endswith(uri))


def _stamped(results: list[object], report: FinalReport) -> int:
    """Attach a fingerprint to each verified positional match; return how many were stamped."""
    stamped = 0
    for result, ranked in zip(results, report.findings, strict=False):
        finding = ranked.finding
        if not isinstance(result, dict) or not _matches(result, finding.file, finding.line_start):
            continue
        fingerprints = result.setdefault("partialFingerprints", {})
        if isinstance(fingerprints, dict):
            fingerprints[FINGERPRINT_KEY] = finding.case_id
            stamped += 1
    return stamped


def stamp_case_ids(sarif_path: Path, report: FinalReport) -> int:
    """Add ``partialFingerprints`` to the SARIF at *sarif_path* and return results stamped; best-effort, since the SARIF is already a valid, complete artefact."""
    try:
        document = json.loads(sarif_path.read_text(encoding="utf-8"))
        runs = document.get("runs") or []
        results = runs[0].get("results") or [] if runs else []
        stamped = _stamped(results, report)
        sarif_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, AttributeError, IndexError) as exc:
        print(f"  [s9] WARN: could not stamp case ids into {sarif_path} ({exc})",
              file=sys.stderr)
        return 0
    if stamped != len(report.findings):
        print(f"  [s9] WARN: stamped {stamped}/{len(report.findings)} case id(s) into "
              f"{sarif_path.name}; the rest did not match a SARIF result location",
              file=sys.stderr)
    return stamped
