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

"""Constants for the deterministic test-inventory fact tool."""

from __future__ import annotations

PY_TEST_EXACT_NAMES: frozenset[str] = frozenset({"conftest.py", "tests.py", "test.py"})
PY_TEST_NAME_PREFIX = "test_"
PY_TEST_NAME_SUFFIX = "_test.py"
JS_TEST_SUFFIXES: tuple[str, ...] = (
    ".test.js", ".test.jsx", ".test.ts", ".test.tsx",
    ".spec.js", ".spec.jsx", ".spec.ts", ".spec.tsx",
)

# Matched case-insensitively on word boundaries, so "mock" does not match inside "MagicMock".
NEGATIVE_TEST_MARKERS: tuple[str, ...] = (
    "pytest.raises", "assertRaises", "with raises", "expect_exception",
    "toThrow", "rejects", "should fail", "assert.throws",
    "malformed", "invalid", "fake", "mock", "exploit", "payload",
)
