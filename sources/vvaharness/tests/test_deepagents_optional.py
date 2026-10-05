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

"""The package must import without the ``deepagents`` distribution.

The project floor is Python 3.11 (``pyproject.toml`` ``requires-python``), and
the ``deepagents`` dependency carries a matching ``python_version >= '3.11'``
marker to stay aligned with DeepAgents' own floor. The distribution can still
be absent at runtime (a partial or hand-rolled install, or an environment
built before the floor moved), and the cli/sdk/openai backends must still
work: nothing outside the deepagents backend may import it at module scope.

Run in a subprocess so blocking the import cannot leak into other tests.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

# Importable without deepagents; the last four regressed previously via an eager re-export.
MUST_IMPORT = (
    "vvaharness.cli",
    "vvaharness.backends.harness",
    "vvaharness.backends.harness.deepagents.limits",
    "vvaharness.backends.harness.deepagents.tools",
    "vvaharness.validation.tools.deep_tools",
    "vvaharness.validation.session.setup",
    "vvaharness.remediation_agent",
)

_SCRIPT = textwrap.dedent(
    """
    import importlib, sys
    from importlib.abc import MetaPathFinder

    class Blocker(MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "deepagents" or fullname.startswith("deepagents."):
                raise ImportError("simulated: deepagents not installed")
            return None

    sys.meta_path.insert(0, Blocker())
    try:
        importlib.import_module("deepagents")
    except ImportError:
        pass
    else:
        print("BLOCKER_INEFFECTIVE")
        raise SystemExit(2)

    for name in sys.argv[1:]:
        try:
            importlib.import_module(name)
        except ImportError as exc:
            print(f"IMPORT_FAILED {name}: {exc}")
            raise SystemExit(1) from exc

    from vvaharness.backends.harness.registry import get_harness
    try:
        get_harness("deepagents")
    except RuntimeError as exc:
        print(f"GUARDED {exc}")
    except ImportError as exc:
        print(f"UNGUARDED_IMPORTERROR {exc}")
        raise SystemExit(3) from exc
    else:
        print("NOT_GUARDED")
        raise SystemExit(4)

    print("ALL_OK")
    """
)


def _run_without_deepagents() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _SCRIPT, *MUST_IMPORT],
        capture_output=True,
        text=True,
        check=False,
    )


def test_package_imports_without_deepagents_installed() -> None:
    result = _run_without_deepagents()
    assert "ALL_OK" in result.stdout, result.stdout + result.stderr
    assert result.returncode == 0, result.stdout + result.stderr


def test_selecting_deepagents_backend_reports_the_python_floor() -> None:
    """A user without deepagents picking ``via: deepagents`` needs a message naming the 3.11 floor."""
    result = _run_without_deepagents()
    guarded = [ln for ln in result.stdout.splitlines() if ln.startswith("GUARDED ")]
    assert guarded, result.stdout + result.stderr
    message = guarded[0]
    assert "3.11" in message
    assert "deepagents" in message
