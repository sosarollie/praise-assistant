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

"""Regression tests for the UNC/network-path guard.

A Windows UNC path (``\\\\host\\share\\x``) supplied via ``--step1-config`` or
any injected input path (inject.cve/controls/cmdb, step_remediate
policy/playbook, TLS certs) would, the moment the loader calls is_file()/read,
open an SMB connection and leak the user's NTLMv2 hash to the host. The guard
refuses such paths before any filesystem touch. These tests assert the guard at
each layer; they are OS-independent because rejection is pure string
classification via PureWindowsPath (no SMB is ever attempted)."""
from pathlib import Path

import pytest

from vvaharness.config import Config, apply_step1_overlay, is_network_path
from vvaharness.orchestrator.config_paths import _resolve_against
from vvaharness.remediation_agent.policy.context import _resolve_input

# Every spelling of "go off-box" that Windows would dial over SMB.
NETWORK_PATHS = [
    r"\\attacker\share\x.yaml",      # classic backslash UNC
    "//attacker/share/x.yaml",       # forward-slash UNC (Windows accepts it)
    r"\\?\UNC\attacker\share\x",     # extended-length UNC device path
    r"\\127.0.0.1\c$\x.yaml",        # admin share by IP
]

# Paths that must keep working — local overlays/inputs.
LOCAL_PATHS = [
    r"C:\Users\me\step1.yaml",
    "step1.yaml",
    "./inputs/known_cves.json",
    "/home/me/step1.yaml",
]


# is_network_path classifier
@pytest.mark.parametrize("p", NETWORK_PATHS)
def test_is_network_path_true_for_unc(p):
    assert is_network_path(p) is True


@pytest.mark.parametrize("p", LOCAL_PATHS)
def test_is_network_path_false_for_local(p):
    assert is_network_path(p) is False


# apply_step1_overlay  (--step1-config — the originally reported vector)
@pytest.mark.parametrize("p", NETWORK_PATHS)
def test_apply_step1_overlay_rejects_network_path(p):
    c = Config({"step1": {"exclude_dirs": ["a"]}})
    with pytest.raises(ValueError, match="network/UNC"):
        apply_step1_overlay(c, p)
    # config left untouched — the guard fired before any merge.
    assert c._data["step1"]["exclude_dirs"] == ["a"]


def test_apply_step1_overlay_guard_precedes_filesystem_touch():
    # A *missing local* file returns (cfg, False); a UNC path must instead
    # RAISE — proving the guard runs before is_file() rather than treating the
    # UNC location as "just not found" (which would still have triggered SMB).
    c = Config({"step1": {}})
    with pytest.raises(ValueError, match="network/UNC"):
        apply_step1_overlay(c, r"\\attacker\share\does-not-exist.yaml")


# _resolve_against  (inject.cve/controls/cmdb + TLS ca_cert/client_cert)
@pytest.mark.parametrize("p", NETWORK_PATHS)
def test_resolve_against_rejects_network_value(p):
    with pytest.raises(ValueError, match="network/UNC"):
        _resolve_against(Path("/local/cfg/dir"), p)


def test_resolve_against_rejects_network_base():
    # A relative input is safe on its own, but a UNC *base* (cfg_dir) would
    # taint it once joined — reject the joined result too.
    with pytest.raises(ValueError, match="network/UNC"):
        _resolve_against(Path("//attacker/share"), "inputs/known_cves.json")


def test_resolve_against_allows_local():
    out = _resolve_against(Path("/cfg/dir"), "./inputs/known_cves.json")
    assert "network" not in out  # sanity: returns a path, no raise
    assert out  # non-empty


# _resolve_input  (step_remediate policy_file / playbook_file)
@pytest.mark.parametrize("p", NETWORK_PATHS)
def test_resolve_input_rejects_network_path_without_cfg_dir(p):
    # cfg=None -> cfg_dir is None -> the value would otherwise pass through
    # unresolved. The explicit guard must still reject it.
    with pytest.raises(ValueError, match="network/UNC"):
        _resolve_input(None, p)


def test_resolve_input_none_and_empty_pass_through():
    assert _resolve_input(None, None) is None
    assert _resolve_input(None, "") is None
