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

"""Static guard against missing imports / undefined names across the package.

This catches the class of bug that unit tests miss: a name used in a branch the
tests don't execute (e.g. `_resolve_against` used only in configure_backends'
ca_cert path after the orchestrator split). pyflakes flags every undefined name
(F821) regardless of coverage, so a missing import can never ship.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parent.parent / "vvaharness"


def test_package_has_no_undefined_names():
    pytest.importorskip("pyflakes", reason="pyflakes not installed (dev extra)")
    r = subprocess.run([sys.executable, "-m", "pyflakes", str(PKG)],
                       capture_output=True, text=True)
    undefined = [ln for ln in r.stdout.splitlines() if "undefined name" in ln]
    assert not undefined, (
        "undefined names (missing imports) — these are runtime NameErrors "
        "waiting in untested branches:\n  " + "\n  ".join(undefined))
