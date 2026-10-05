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

"""Smoke test: every package module must import cleanly."""
import importlib
import pkgutil

import vvaharness


def test_all_modules_import():
    failed = []
    for mod in pkgutil.walk_packages(vvaharness.__path__, "vvaharness."):
        try:
            importlib.import_module(mod.name)
        except Exception as e:  # noqa: BLE001
            failed.append(f"{mod.name}: {e}")
    assert not failed, "import failures:\n" + "\n".join(failed)
