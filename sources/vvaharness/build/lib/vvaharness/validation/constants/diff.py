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

"""Constants for deterministic diff-based fact tools."""

from __future__ import annotations

import re

DIFF_PATCH_FILENAME: str = "diff.patch"

TRUST_BOUNDARY_RE: re.Pattern[str] = re.compile(
    r"(?i)(auth|session|login|logout|password|crypto|cipher|tls|ssl|token|"
    r"secret|credential|permission|role|config|settings)\b"
)

HUNK_HEADER_RE: re.Pattern[str] = re.compile(
    r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@"
)
# The regex group that holds the hunk's new-side start line number.
HUNK_NEW_START_GROUP: int = 1

# Unified-diff line markers.
GIT_HEADER_PREFIX: str = "diff --git "
# A well-formed "diff --git" header splits into 4+ tokens; fewer means it is truncated.
GIT_HEADER_MIN_TOKENS: int = 4
OLD_FILE_MARKER: str = "--- "
NEW_FILE_MARKER: str = "+++ "
# Byte offset past "+++ " / "--- " where the file path begins.
MARKER_PATH_START: int = len(NEW_FILE_MARKER)
DEV_NULL_PATH: str = "/dev/null"
GIT_PATH_PREFIXES: tuple[str, ...] = ("a/", "b/")
ADDED_LINE: str = "+"
REMOVED_LINE: str = "-"
NO_NEWLINE_NOTE: str = "\\"
