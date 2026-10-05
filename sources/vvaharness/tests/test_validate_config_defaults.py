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

"""The step_validate tunable defaults must agree across all three sources, and load_config
overrides must seed typed values directly without laundering through os.environ.

Sources pinned together: the orchestrator _STEP_DEFAULTS["step_validate"], the validation
DEFAULT_* constants, and every shipped YAML profile. A drift in any one fails here.
"""
import os
from pathlib import Path

import pytest
import yaml

from vvaharness.config import _STEP_DEFAULTS
from vvaharness.validation.config import load_config
from vvaharness.validation.constants.artifacts import (
    DEFAULT_EFFORT,
    DEFAULT_MAX_BUDGET_USD,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_TURNS,
    ENV_EFFORT,
    ENV_MAX_BUDGET_USD,
    ENV_MAX_FINDINGS,
    ENV_MAX_TURNS,
)
from vvaharness.validation.enums import EffortLevel

_PROFILE_DIR = Path(__file__).resolve().parent.parent / "vvaharness" / "config" / "profiles"
# Derive the guarded set from the shipped profiles on disk so a rename/add can
# never silently drop a profile from the drift guard (the regression that broke
# this test when cli.yaml was renamed to sdk.yaml). The assert keeps an empty
# glob from collapsing to zero parametrized cases (a vacuous pass).
_PROFILES = sorted(p.stem for p in _PROFILE_DIR.glob("*.yaml"))
assert _PROFILES, f"no shipped profiles discovered under {_PROFILE_DIR}"
# Non-default override values, kept as named constants so the asserts compare against the
# same source (and avoid bare magic literals in comparisons).
_OVR_TURNS = 7
_OVR_BUDGET = 1.5
_OVR_FINDINGS = 3
_ENV_TURNS = 11
# (validation DEFAULT_* constant, step_validate key) for the four tuning scalars.
_TUNABLES: tuple[tuple[object, str], ...] = (
    (DEFAULT_EFFORT, "effort"),
    (DEFAULT_MAX_TURNS, "max_turns"),
    (DEFAULT_MAX_BUDGET_USD, "max_budget_usd"),
    (DEFAULT_MAX_FINDINGS, "max_findings"),
)


def test_orchestrator_defaults_match_validation_constants() -> None:
    block = _STEP_DEFAULTS["step_validate"]
    for default, key in _TUNABLES:
        assert block[key] == default, f"step_validate.{key} drifted from DEFAULT_*"


@pytest.mark.parametrize("profile", _PROFILES)
def test_shipped_profiles_match_validation_constants(profile: str) -> None:
    raw = yaml.safe_load((_PROFILE_DIR / f"{profile}.yaml").read_text(encoding="utf-8"))
    block = raw["step_validate"]
    for default, key in _TUNABLES:
        assert block[key] == default, f"{profile}.yaml step_validate.{key} drifted from DEFAULT_*"


def test_overrides_apply_without_mutating_environ(tmp_path: Path, monkeypatch) -> None:
    for env_key in (ENV_EFFORT, ENV_MAX_TURNS, ENV_MAX_BUDGET_USD, ENV_MAX_FINDINGS):
        monkeypatch.delenv(env_key, raising=False)
    cfg = load_config(
        tmp_path,
        overrides={"max_turns": _OVR_TURNS, "effort": EffortLevel.LOW,
                   "max_budget_usd": _OVR_BUDGET, "max_findings": _OVR_FINDINGS},
    )
    assert cfg.agent.max_turns == _OVR_TURNS
    assert cfg.agent.effort == EffortLevel.LOW
    assert cfg.agent.max_budget_usd == _OVR_BUDGET
    assert cfg.max_findings == _OVR_FINDINGS
    # The laundering is gone: nothing was written to the process environment.
    for env_key in (ENV_EFFORT, ENV_MAX_TURNS, ENV_MAX_BUDGET_USD, ENV_MAX_FINDINGS):
        assert env_key not in os.environ


def test_string_effort_override_coerces_to_enum(tmp_path: Path, monkeypatch) -> None:
    # A profile supplies effort as a bare string; it must coerce to the typed enum.
    monkeypatch.delenv(ENV_EFFORT, raising=False)
    cfg = load_config(tmp_path, overrides={"effort": "medium"})
    assert cfg.agent.effort == EffortLevel.MEDIUM


def test_env_var_no_longer_influences_tunables(tmp_path: Path, monkeypatch) -> None:
    # Tunables are override-or-default only now; a VVAHARNESS_* env value must be ignored.
    monkeypatch.setenv(ENV_MAX_TURNS, str(_ENV_TURNS))
    assert load_config(tmp_path).agent.max_turns == DEFAULT_MAX_TURNS
