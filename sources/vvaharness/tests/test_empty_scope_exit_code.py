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

"""An empty scan scope is refused with exit 2, never reported as clean."""
import ast
import inspect

from vvaharness.orchestrator import entry
from vvaharness.pipeline.stages.s1_preprocess import EmptyScopeError


def _handlers():
    """The (exception-name, returned-int) pairs of main()'s outer except chain."""
    src = inspect.getsource(entry.main)
    tree = ast.parse("if 1:\n" + "\n".join("  " + ln
                                           for ln in src.splitlines()))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for h in node.handlers:
            name = getattr(h.type, "id", None) or getattr(
                getattr(h.type, "attr", None), "__str__", lambda: None)()
            rets = [n.value.value for n in ast.walk(h)
                    if isinstance(n, ast.Return)
                    and isinstance(n.value, ast.Constant)]
            out.append((name, rets))
    return out


def test_empty_scope_is_mapped_to_exit_two():
    pairs = dict((n, r) for n, r in _handlers() if n)
    assert "EmptyScopeError" in pairs, (
        "main() has no EmptyScopeError handler; an empty scope would fall "
        "through to `except Exception` and report exit 1 (a crash) instead "
        "of 2 (a refusal)")
    assert pairs["EmptyScopeError"] == [2]


def test_empty_scope_handler_precedes_the_catch_all():
    names = [n for n, _ in _handlers()]
    assert "EmptyScopeError" in names and "Exception" in names
    assert names.index("EmptyScopeError") < names.index("Exception"), (
        "`except Exception` would shadow the EmptyScopeError handler and "
        "return 1")


def test_empty_scope_error_is_not_a_harness_error():
    # Must not inherit HarnessError: is_halt_error and the VVAH-Exxx taxonomy
    # are the LLM-backend contract, and an empty scope is a scan-input refusal.
    from vvaharness.backends.harness.models import HarnessError, is_halt_error
    assert not issubclass(EmptyScopeError, HarnessError)
    assert not is_halt_error(EmptyScopeError("x"))
