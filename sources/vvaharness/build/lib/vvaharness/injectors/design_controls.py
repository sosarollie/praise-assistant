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

"""Load design controls (auth boundaries, sandboxes, mitigations) from YAML."""
from __future__ import annotations

import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from vvaharness.models import Control
from vvaharness.util import errlog as _errlog


def load_controls(path: str | Path) -> list[Control]:
    p = Path(path)
    if not p.exists():
        return []
    # A present-but-malformed / hand-edited controls file must DEGRADE (empty
    # list) rather than abort the scan with a raw YAMLError / validation
    # traceback. Parse and per-item validation are guarded; the failure is
    # recorded to the structured error log next to the report.
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict):
            items = data.get("controls")
            if items is None:
                raise ValueError(
                    "controls file is a YAML mapping without a 'controls' key — "
                    "expected a list or {controls: [...]}")
        else:
            items = data
        return [Control.model_validate(item) for item in items]
    except (OSError, ValueError, TypeError, yaml.YAMLError, ValidationError) as e:
        print(f"  [inject] WARN: could not load controls file {p} "
              f"({type(e).__name__}: {e}); continuing with no injected controls.",
              file=sys.stderr)
        _errlog.log("inject.controls", str(p), e)
        return []
