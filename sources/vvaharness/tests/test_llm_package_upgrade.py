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

"""Regression coverage for the v1.2 module to v1.3 package promotion."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_llm_package_wins_over_stale_legacy_module(tmp_path):
    """A leftover ``llm.py`` must not shadow the current ``llm`` package."""
    source_init = (Path(__file__).resolve().parents[1] / "vvaharness" /
                   "backends" / "llm" / "__init__.py")
    package_root = tmp_path / "site-packages"
    backends = package_root / "vvaharness" / "backends"
    llm_package = backends / "llm"
    llm_package.mkdir(parents=True)

    (package_root / "vvaharness" / "__init__.py").write_text("", encoding="utf-8")
    (backends / "__init__.py").write_text("", encoding="utf-8")
    (backends / "llm.py").write_text(
        'raise RuntimeError("stale llm.py was imported")\n', encoding="utf-8")
    (llm_package / "__init__.py").write_text(
        source_init.read_text(encoding="utf-8"), encoding="utf-8")
    (llm_package / "registry.py").write_text(
        'SENTINEL = "current package"\n', encoding="utf-8")

    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from vvaharness.backends.llm.registry import SENTINEL; "
            "print(SENTINEL)",
            str(package_root),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "current package"
