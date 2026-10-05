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

"""Every shipped profile's inject.* paths must resolve into repo-root inputs/.

Regression test: inject.cve_file/controls_file/cmdb_file in the shipped
profiles were "./inputs/...", which _resolve_against joins against the
profile's own directory (vvaharness/config/profiles/) rather than the repo
root -- landing in a vvaharness/config/profiles/inputs/ directory that has
never existed. On a default run this made VulContextSeverity's "no CMDB
file" warning name a path no operator following docs/SETUP_GUIDE.md would
ever populate. Fixed by pointing the values at "../../../inputs/..." so they
climb back up to the real repo-root inputs/ directory; this test pins that
resolution so a future edit to any shipped profile can't reintroduce the
mismatch."""
from pathlib import Path

import pytest

from vvaharness.config import load
from vvaharness.orchestrator.config_paths import _resolve_against

_PROFILE_DIR = Path(__file__).resolve().parent.parent / "vvaharness" / "config" / "profiles"
# Derive from the shipped profiles on disk (not a hardcoded tuple) so adding a
# new profile can't silently skip this guard.
_PROFILES = sorted(p.stem for p in _PROFILE_DIR.glob("*.yaml"))
assert _PROFILES, f"no shipped profiles discovered under {_PROFILE_DIR}"

_REPO_ROOT_INPUTS = _PROFILE_DIR.parent.parent.parent / "inputs"


def test_repo_root_inputs_dir_exists():
    # Sanity check on the assertion's own premise -- if this ever moves, the
    # per-profile assertions below would otherwise pass/fail for the wrong
    # reason.
    assert _REPO_ROOT_INPUTS.is_dir(), (
        f"expected the shipped inputs/ directory at {_REPO_ROOT_INPUTS}; "
        "docs/SETUP_GUIDE.md documents this as where operators place "
        "cmdb.csv/known_cves.json/design_controls.yaml")


@pytest.mark.parametrize("profile", _PROFILES)
@pytest.mark.parametrize("field", ["cve_file", "controls_file", "cmdb_file"])
def test_shipped_profile_inject_path_resolves_to_repo_root_inputs(profile: str, field: str):
    path = _PROFILE_DIR / f"{profile}.yaml"
    cfg = load(path)
    value = getattr(cfg.inject, field, None)
    assert value, f"{profile}.yaml: inject.{field} is unset -- expected a value pointing at inputs/"

    # _resolve_against joins but does not normalize -- resolve() to collapse
    # any ".." segments before comparing directories.
    resolved = Path(_resolve_against(path.resolve().parent, value)).resolve()

    assert resolved.parent == _REPO_ROOT_INPUTS, (
        f"{profile}.yaml: inject.{field} = {value!r} resolves to {resolved}, "
        f"not into the documented repo-root inputs/ directory ({_REPO_ROOT_INPUTS}). "
        "Relative inject paths resolve against the profile's own directory "
        f"({path.resolve().parent}), so this likely needs to climb back up to "
        "repo root the same way the other inject.* fields do.")
