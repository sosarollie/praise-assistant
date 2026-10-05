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

"""Load per-CWE adversarial bypass hints from the operator-supplied ``inputs/`` file.

Sole source is ``./inputs/validator_hints.yaml``; no bundled fallback — an absent file
means no hints, and a malformed one is ignored with a warning rather than aborting.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from vvaharness.validation.constants.artifacts import (
    INPUTS_DIRNAME,
    VALIDATOR_HINTS_FILENAME,
)


def _hints_path() -> Path:
    """The sole hints source: ``./inputs/validator_hints.yaml`` (cwd-relative)."""
    return Path.cwd() / INPUTS_DIRNAME / VALIDATOR_HINTS_FILENAME


def _parse_hints(path: Path) -> dict[str, object] | None:
    """Parse a hints YAML mapping, or None when the file is unreadable / malformed."""
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return loaded if isinstance(loaded, dict) else {}


def _resolve_raw() -> dict[str, object]:
    """Return the raw hints mapping from ``inputs/``; empty when absent or malformed."""
    path = _hints_path()
    if not path.exists():
        return {}  # optional operator input — run without per-CWE bypass hints
    raw = _parse_hints(path)
    if raw is None:
        print(
            f"validate: ignoring malformed hints file {path}; "
            f"proceeding without per-CWE bypass hints"
        )
        return {}
    return raw


class CweHints(BaseModel):
    """Map of CWE identifier to a list of adversarial bypass hints."""

    model_config = ConfigDict(extra="ignore")

    hints: dict[str, list[str]]

    @classmethod
    def load(cls) -> CweHints:
        """Load hints from ``./inputs/validator_hints.yaml``; empty when absent or malformed."""
        raw = _resolve_raw()
        cleaned: dict[str, list[str]] = {}
        for key, val in raw.items():
            if isinstance(key, str) and isinstance(val, list):
                cleaned[key.strip()] = [str(h) for h in val]
        return cls(hints=cleaned)


_REGISTRY: CweHints | None = None


def _registry() -> CweHints:
    """Return the singleton loaded registry (lazy)."""
    global _REGISTRY  # singleton registry — intentional module-level state
    if _REGISTRY is None:
        _REGISTRY = CweHints.load()
    return _REGISTRY


def hints_for(category: str) -> list[str]:
    """Return bypass hints for a CWE category string, or [] if unknown."""
    reg = _registry()
    direct = reg.hints.get(category.strip())
    if direct is not None:
        return direct
    # Try prefix match for "CWE-89: SQL Injection" style category strings
    prefix = category.split(":")[0].strip()
    return reg.hints.get(prefix, [])
