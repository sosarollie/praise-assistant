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

"""LangGraph invoke-config construction and a recursion-limit counter."""

from __future__ import annotations

import os

from vvaharness.backends.harness.deepagents.models import GraphInvokeConfig
from vvaharness.backends.harness.models import OneShotOptions, StreamingOptions


def _make_config(options: OneShotOptions | StreamingOptions, buffer: int) -> GraphInvokeConfig:
    """Build a LangGraph invoke config with an optional recursion limit buffer."""
    config: GraphInvokeConfig = {"configurable": {"thread_id": os.urandom(8).hex()}}
    if options.max_turns is not None:
        config["recursion_limit"] = options.max_turns + buffer
    return config


class _RecursionCounter:
    """Stateful counter to avoid ever-decreasing `recursion_limit` for cached configs."""

    def __init__(self) -> None:
        self._value = 0

    def next(self, base: int) -> int:
        """Return *base* plus an ever-increasing offset."""
        self._value += 1
        return base + self._value


_recursion_counter = _RecursionCounter()
