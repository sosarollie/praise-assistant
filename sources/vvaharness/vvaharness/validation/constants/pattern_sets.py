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

"""Constants for deterministic pattern-scanning fact tools."""

from __future__ import annotations

import re

from vvaharness.pipeline.stages.s1_preprocess import _INSECURE_RX, _SECRET_RX
from vvaharness.validation.constants.diff import DIFF_PATCH_FILENAME

DEFAULT_PATTERN_SETS: dict[str, tuple[str, re.Pattern[str]]] = {
    "secret_exposure": ("hardcoded secret or credential", _SECRET_RX),
    "insecure_value": ("insecure configuration value", _INSECURE_RX),
}

SKIP_IN_SCAN: frozenset[str] = frozenset({DIFF_PATCH_FILENAME})

# A file containing this byte is treated as binary and skipped by the scanner.
NUL_BYTE: bytes = b"\x00"
# Rule tag emitted for matches from the builtin pattern sets above.
BUILTIN_RULE: str = "__builtin__"
