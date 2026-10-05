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

"""Every shipped profile (cli / default / full) must resolve a usable s11 validator model.

The validator runs only on an Anthropic-compatible endpoint, so models.validate (and any
persona overrides) must resolve via sdk/cli — never openai. _apply_model_env returns 0 on
success and 2 when it would refuse, so a green run here means the profile is launch-ready."""
import os
from pathlib import Path

import pytest

from vvaharness.validation.cli._model import _apply_model_env

_PROFILE_DIR = Path(__file__).resolve().parent.parent / "vvaharness" / "config" / "profiles"
# Derive the guarded set from the shipped profiles on disk so a rename/add can
# never silently drop a profile from this launch-readiness guard (the regression
# that broke this test when cli.yaml was renamed to sdk.yaml). The assert keeps
# an empty glob from collapsing to zero parametrized cases (a vacuous pass).
_PROFILES = sorted(p.stem for p in _PROFILE_DIR.glob("*.yaml"))
assert _PROFILES, f"no shipped profiles discovered under {_PROFILE_DIR}"


@pytest.mark.parametrize("profile", _PROFILES)
def test_shipped_profile_validate_model_resolves(profile: str, monkeypatch) -> None:
    monkeypatch.delenv("VVAHARNESS_MODEL", raising=False)
    monkeypatch.delenv("VVAHARNESS_VIA", raising=False)
    path = _PROFILE_DIR / f"{profile}.yaml"
    assert path.exists(), f"missing shipped profile {path}"

    rc, overrides = _apply_model_env(str(path))

    assert rc == 0, f"{profile}.yaml: validate role not on an Anthropic-compatible endpoint"
    assert overrides.get("model"), f"{profile}.yaml: no validate model in overrides"
