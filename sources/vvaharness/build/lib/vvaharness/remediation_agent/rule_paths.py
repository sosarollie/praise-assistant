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

"""Locate remediation rules across source, wheel, and user installs."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

RULE_FILES = ("remediation_policy.yaml", "remediation_playbook.yaml")


def settings_path() -> Path:
    override = os.environ.get("VVAHARNESS_SETTINGS_FILE")
    if override:
        return Path(override).expanduser()
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "vvaharness" / "settings.json"


def configured_inputs_dir() -> Path | None:
    try:
        raw = json.loads(settings_path().read_text(encoding="utf-8"))
        value = raw.get("inputs_dir") if isinstance(raw, dict) else None
        return Path(value).expanduser() if value else None
    except (OSError, ValueError, TypeError):
        return None


def save_inputs_dir(path: str | Path) -> Path:
    directory = Path(path).expanduser().resolve()
    target = settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, object] = {}
    try:
        existing = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(existing, dict):
            data.update(existing)
    except (OSError, ValueError, TypeError):
        pass
    data["inputs_dir"] = str(directory)
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return target


def candidate_inputs_dirs(package_file: str | Path) -> tuple[Path, ...]:
    del package_file  # retained for a stable, easily monkeypatched call surface
    source_inputs = Path(__file__).resolve().parents[2] / "inputs"
    shared_inputs = Path(sys.prefix) / "share" / "vvaharness" / "rules"
    configured = configured_inputs_dir()
    ordered = (source_inputs, shared_inputs, configured)
    return tuple(path for i, path in enumerate(ordered)
                 if path is not None and path not in ordered[:i])


def locate_rule(filename: str, package_file: str | Path) -> Path:
    candidates = tuple(path / filename for path in candidate_inputs_dirs(package_file))
    return next((path for path in candidates if path.is_file()), candidates[0])


def missing_rules(package_file: str | Path) -> list[str]:
    return [name for name in RULE_FILES if not locate_rule(name, package_file).is_file()]


def validate_inputs_dir(path: str | Path) -> tuple[Path, list[str]]:
    directory = Path(path).expanduser()
    missing = [name for name in RULE_FILES if not (directory / name).is_file()]
    return directory, missing
