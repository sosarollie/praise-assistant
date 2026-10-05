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

"""The typed scan result on disk, beside the rendered Markdown one, so a later process reads it instead of re-parsing Markdown and losing fields."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from vvaharness.models import FinalReport
from vvaharness.orchestrator.artifacts import FINDINGS_JSON_NAME, SCAN_DIR_NAME
from vvaharness.report.redact import redact_tree

__all__ = ["findings_json_path", "read_findings_json", "write_findings_json"]


def findings_json_path(repo: Path | str) -> Path:
    """Where the typed result lives for a given checkout."""
    return Path(repo) / SCAN_DIR_NAME / FINDINGS_JSON_NAME


def write_findings_json(report: FinalReport, repo: Path | str) -> Path:
    """Persist *report* as JSON under ``<repo>/security-scan/`` and return the path, atomically so a reader in another process never sees a half-written document."""
    path = findings_json_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(redact_tree(report.model_dump(mode="json")), indent=2) + "\n"
    tmp = path.with_suffix(f"{path.suffix}.tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(path)
    return path


def read_findings_json(repo: Path | str) -> FinalReport | None:
    """Load the typed result for *repo*, or ``None`` (a routine answer, not an error) when a checkout scanned by an older build has no such file."""
    path = findings_json_path(repo)
    if not path.is_file():
        return None
    return _validated(path)


def _validated(path: Path) -> FinalReport | None:
    """Parse and validate *path*, degrading to ``None`` with a notice on a bad document rather than partially trusting it."""
    try:
        return FinalReport.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        print(
            f"  [findings] WARN: {path} is not a readable scan result ({exc}); "
            "ignoring it",
            file=sys.stderr,
        )
        return None
