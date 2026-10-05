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

"""Pre-dispatch prompt-size guardrail (VVAH-E004) on the deepagents route.

The fail-closed detection backend makes upstream eviction unreachable
(tests/test_detection_backend_no_writes.py), so a genuinely over-context
prompt would now fail at the provider after being paid for. This guardrail
refuses it BEFORE dispatch instead: one shared ceiling
(``DEEPAGENTS_MAX_PROMPT_TOKENS``) on both dispatch seams (``prompt()`` /
``agentic()``), raising ``OversizePromptError`` so the owning unit fails
loudly at stage level — no auto-split, no silent mutation, and NOT a halt
(stage handlers record it and the scan continues). sdk/openai routes are
unchanged by design.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vvaharness.backends.harness import OneShotResult
from vvaharness.backends.harness.models import OversizePromptError, is_halt_error
from vvaharness.backends.llm import deepagents as deep
from vvaharness.backends.llm.models import DEEPAGENTS_MAX_PROMPT_TOKENS
from vvaharness.util import errlog as _errlog
from vvaharness.util.counters import COUNTERS

# All-alpha text estimates at prose density (~4.4 chars/token), so 700k chars
# is ~159k estimated tokens — safely past the 150k ceiling.
_OVERSIZE = "a" * 700_000
_HEALTHY_TEXT = "finding: " + "x" * 160

_COUNTER = "deepagents_oversize_prompts"


class _OneShotHarness:
    """Fake harness recording run_oneshot invocations."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    async def run_oneshot(self, prompt, options):
        self.calls.append((prompt, options))
        return self.result


class _StreamHarness:
    """Fake harness whose run_streaming yields a fixed message sequence."""

    def __init__(self, messages):
        self.messages = messages
        self.calls = []

    def run_streaming(self, prompt, options):
        self.calls.append((prompt, options))

        async def gen():
            for message in self.messages:
                yield message

        return gen()


def _model_node():
    return SimpleNamespace(id="claude-test", via="deepagents")


# ── prompt(): the one-shot dispatch seam ─────────────────────────────────────


def test_prompt_refuses_oversized_before_any_dispatch(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text=_HEALTHY_TEXT))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(OversizePromptError) as excinfo:
        deep.prompt(_OVERSIZE, model=_model_node(), cwd=str(tmp_path), tag="s4 chunk-01")

    assert fake.calls == [], "the harness was dispatched despite the refusal."
    err = excinfo.value
    assert err.error_code == "VVAH-E004"
    assert err.stage == "s4 chunk-01"
    assert err.limit == DEEPAGENTS_MAX_PROMPT_TOKENS
    assert err.estimated_tokens > DEEPAGENTS_MAX_PROMPT_TOKENS


def test_prompt_ceiling_counts_the_cache_prefix(monkeypatch, tmp_path):
    """An S4 specialist shard carries most of its content in cache_prefix."""
    fake = _OneShotHarness(OneShotResult(result_text=_HEALTHY_TEXT))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(OversizePromptError):
        deep.prompt(
            "short question",
            model=_model_node(),
            cwd=str(tmp_path),
            cache_prefix=_OVERSIZE,
        )
    assert fake.calls == []


def test_prompt_under_ceiling_dispatches_normally(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text=_HEALTHY_TEXT))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    out = deep.prompt("short prompt", model=_model_node(), cwd=str(tmp_path))

    assert out == _HEALTHY_TEXT
    assert len(fake.calls) == 1
    assert COUNTERS.get(_COUNTER) == 0


# ── agentic(): the streaming dispatch seam, same shared ceiling ──────────────


def test_agentic_refuses_oversized_before_any_dispatch(monkeypatch, tmp_path):
    fake = _StreamHarness([])
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    with pytest.raises(OversizePromptError) as excinfo:
        deep.agentic(_OVERSIZE, model=_model_node(), cwd=str(tmp_path), tag="s1")

    assert fake.calls == []
    assert excinfo.value.limit == DEEPAGENTS_MAX_PROMPT_TOKENS


# ── failure taxonomy: recoverable unit failure, never a halt ─────────────────


def test_oversize_is_not_a_halt_error():
    err = OversizePromptError("x", stage="s4", estimated_tokens=1, limit=1)
    assert not is_halt_error(err)


def test_refusal_bumps_the_scanmetrics_counter(monkeypatch, tmp_path):
    fake = _OneShotHarness(OneShotResult(result_text=_HEALTHY_TEXT))
    monkeypatch.setattr(deep, "get_harness", lambda _via: fake)

    for _ in range(2):
        with pytest.raises(OversizePromptError):
            deep.prompt(_OVERSIZE, model=_model_node(), cwd=str(tmp_path))

    assert COUNTERS.get(_COUNTER) == 2


def test_errlog_stamps_the_e004_code(monkeypatch, tmp_path):
    """Stage handlers log the raised error generically; the code self-stamps."""
    monkeypatch.setattr(_errlog, "_path", tmp_path / "errors.jsonl")
    err = OversizePromptError("x", stage="s4 chunk-01", estimated_tokens=2, limit=1)
    _errlog.log("s4", "chunk-01", err, scope="chunk")

    record = json.loads((tmp_path / "errors.jsonl").read_text(encoding="utf-8"))
    assert record["error_code"] == "VVAH-E004"
