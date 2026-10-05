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

"""Abstract Harness contract every agent runtime must implement."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from vvaharness.backends.harness.models import (
    HarnessMessage,
    OneShotOptions,
    OneShotResult,
    StreamingOptions,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class Harness(ABC):
    """Abstract contract every agent runtime must implement."""

    @abstractmethod
    async def run_oneshot(
        self, prompt: str, options: OneShotOptions
    ) -> OneShotResult:
        """Run a single-turn parser-only invocation; raises HarnessError on failure."""

    @abstractmethod
    def run_streaming(
        self, prompt: str, options: StreamingOptions
    ) -> AsyncIterator[HarnessMessage]:
        """Return an async iterator of typed messages for a full streaming session."""
