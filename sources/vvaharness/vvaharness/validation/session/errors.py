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

"""Domain exception hierarchy for harness-backed validation sessions."""

from vvaharness.backends.harness import HarnessError, HarnessProcessError
from vvaharness.validation.constants.artifacts import STDERR_TAIL_LINES


class ValidationSessionError(Exception):
    """Per-session failure driving the case INCONCLUSIVE; wraps the harness error, cause exposed."""

    def __init__(
        self,
        message: str,
        cause: Exception | None = None,
        exit_code: int | None = None,
    ) -> None:
        """Initialize with message, optional cause exception, and optional exit code."""
        super().__init__(message)
        self.cause = cause
        self.exit_code = exit_code

    def reason_string(self) -> str:
        """Build a concise diagnostic string joining message, exit_code, and cause."""
        parts = [str(self)]
        if self.exit_code is not None:
            parts.append(f"exit_code={self.exit_code}")
        if isinstance(self.cause, HarnessProcessError) and self.cause.stderr:
            tail = self.cause.stderr.splitlines()[-STDERR_TAIL_LINES:]
            parts.append("stderr: " + " | ".join(tail))
        elif isinstance(self.cause, HarnessError) or self.cause is not None:
            parts.append(f"cause={type(self.cause).__name__}: {self.cause}")
        return " -- ".join(parts)
