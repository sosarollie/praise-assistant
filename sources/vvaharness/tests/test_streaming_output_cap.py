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

"""Per-turn output cap threading on the streaming builder.

``CapOutputTokens`` was one-shot-only; ``SessionOptions.max_output_tokens``
now reaches the streaming builder too. Only the detection ``agentic()`` site
opts in, pinning ``AGENTIC_MAX_TOKENS`` (asserted in
tests/test_backend_deepagents.py) for parity with the sdk/openai routes.
The frozen S10/S11 option builders never set the field, so their options
default to ``None`` — no middleware, the model's own ceiling — pinned below.
"""

from __future__ import annotations

from pathlib import Path

from vvaharness.backends.harness.deepagents.options import streaming as streaming_mod
from vvaharness.backends.harness.deepagents.options.streaming import (
    _build_streaming_graph,
)
from vvaharness.backends.harness.models import StreamingOptions


def _capture_create_agent(monkeypatch) -> dict:
    captured: dict = {}

    def fake_create_agent(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(streaming_mod, "_create_agent", fake_create_agent)
    return captured


def _options(tmp_path: Path, **extra) -> StreamingOptions:
    return StreamingOptions(model="claude-test", cwd=tmp_path, **extra)


def test_streaming_builder_threads_the_cap(monkeypatch, tmp_path: Path):
    captured = _capture_create_agent(monkeypatch)
    _build_streaming_graph(_options(tmp_path, max_output_tokens=12_345))
    assert captured["max_output_tokens"] == 12_345


def test_streaming_default_none_keeps_the_model_ceiling(monkeypatch, tmp_path: Path):
    """S10/S11 pass no cap by default; None must reach the builder unchanged."""
    captured = _capture_create_agent(monkeypatch)
    _build_streaming_graph(_options(tmp_path))
    assert captured["max_output_tokens"] is None
