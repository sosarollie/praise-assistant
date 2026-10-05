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

"""Backend registry: maps ``via`` strings to lazy Harness factory callables.

Each factory imports its own SDK inside the function body, so selecting one
backend never imports another's dependencies.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from vvaharness.backends.harness.harness import Harness

if TYPE_CHECKING:
    from collections.abc import Callable


def _make_claude() -> Harness:
    from vvaharness.backends.harness.claude.client import (  # noqa: PLC0415 — lazy: selecting one backend must not import another's SDK
        ClaudeHarness,
    )

    return ClaudeHarness()


def _make_deepagents() -> Harness:
    try:
        from vvaharness.backends.harness.deepagents.client import (  # noqa: PLC0415 — lazy: deepagents is optional and needs 3.11+
            DeepAgentHarness,
        )
    except ImportError as exc:  # deepagents requires Python 3.11+
        msg = (
            "the deepagents backend needs the 'deepagents' package, which requires "
            f"Python 3.11+ (running {sys.version_info.major}.{sys.version_info.minor}). "
            "Use via: cli or sdk, or upgrade Python."
        )
        raise RuntimeError(msg) from exc

    return DeepAgentHarness()


_BACKENDS: dict[str, Callable[[], Harness]] = {
    "cli": _make_claude,
    "sdk": _make_claude,
    "deepagents": _make_deepagents,
}


def get_harness(via: str | None = None) -> Harness:
    """Return a fresh Harness instance for the given *via* selector.

    Args:
        via: Backend selector string — one of ``"cli"``, ``"sdk"``, or
            ``"deepagents"``.  ``None`` (or any falsy value) defaults to the
            Claude backend (``"sdk"``); ``"cli"`` is an alias for ``"sdk"``
            (both select the Claude backend). Note: detection-role
            ``via: deepagents`` dispatches via
            ``backends.llm.deepagents.dispatch_prompt``/``dispatch_agentic``,
            not this registry.

    Returns:
        A concrete ``Harness`` instance for the requested provider.

    Raises:
        ValueError: If *via* is not a registered backend key.
    """
    key = via or "sdk"
    factory = _BACKENDS.get(key)
    if factory is None:
        valid = ", ".join(f'"{k}"' for k in _BACKENDS)
        raise ValueError(f"unknown backend {key!r}; valid values are: {valid}")
    return factory()


__all__ = ["get_harness"]
