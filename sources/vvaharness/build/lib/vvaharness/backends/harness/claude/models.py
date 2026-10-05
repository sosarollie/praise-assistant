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

"""The Claude backend's own data contract: the SDK-to-harness error mapping.

Separate from ``harness.models`` because this table names Claude Agent SDK exception
classes, and the neutral contract must not import an SDK. ``client.py`` translates by
consulting this table; the table itself declares nothing else.

Deliberately thin. It exists as the seam for Claude-specific contract values, so the
next one has an obvious home rather than accreting at the top of ``client.py``.
"""

from __future__ import annotations

from claude_agent_sdk import (
    CLIConnectionError,
    CLIJSONDecodeError,
    CLINotFoundError,
)
from claude_agent_sdk._errors import MessageParseError

from vvaharness.backends.harness.models import (
    HarnessCLINotFoundError,
    HarnessConnectionError,
    HarnessJSONDecodeError,
    HarnessMessageParseError,
)

#: SDK exception to harness exception, for failures that need no payload translation.
#: ``ProcessError`` is absent on purpose: it carries an exit code and stderr tail that
#: ``client._wrap_sdk_error`` has to copy across, so it cannot be a plain pair.
SDK_ERROR_MAP: tuple[tuple[type[Exception], type[Exception]], ...] = (
    (CLINotFoundError, HarnessCLINotFoundError),
    (CLIConnectionError, HarnessConnectionError),
    (CLIJSONDecodeError, HarnessJSONDecodeError),
    (MessageParseError, HarnessMessageParseError),
)

__all__ = ["SDK_ERROR_MAP"]
