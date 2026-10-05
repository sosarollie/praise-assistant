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

"""Token-economics contracts of the one-shot detection path, and their S10/S11 freeze.

Two measured fixes are pinned here, both through the REAL graph builders with a
spy chat model (no network, no LLM):

1. Skills block suppression. ``_skill_sources`` returns ``[]`` (a list, not
   None) when no ``skill_root`` is configured — always the case on detection —
   and deepagents attaches SkillsMiddleware whenever ``skills is not None``,
   injecting a ~1.9k-char "## Skills System" block ("No skills available yet",
   ~430 est. tokens) into the system prompt of EVERY one-shot model call. The
   one-shot builder now omits the kwarg via ``or None``.

2. Per-call output cap. ``OneShotOptions.max_output_tokens`` rides a
   ``model_settings`` override middleware into every model request; ``None``
   inherits the model's own ceiling (64k Anthropic / uncapped OpenAI).

THE FREEZE — the asymmetry is deliberate: S10/S11 reach the harness only
through ``run_streaming``/``options/streaming.py``, which still passes the
skill list unchanged and never sets ``max_output_tokens``. The streaming tests
below are the permanent S10/S11-neutrality proof; if one fails, a "tidy-up"
has changed a frozen stage's prompts or output cap.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fixtures.deepagents_scaffolding import patch_models
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage

from vvaharness.backends.harness import (
    OneShotOptions,
    StreamingOptions,
    ToolPolicy,
)
from vvaharness.backends.harness.deepagents.options import (
    graph_builder as _da_graph_builder,
)
from vvaharness.backends.harness.deepagents.options.oneshot import (
    build_oneshot_options,
)
from vvaharness.backends.harness.deepagents.options.streaming import (
    build_streaming_agent,
)

_SKILLS_HEADER = "## Skills System"
_NO_SKILLS_TEXT = "No skills available yet"


def _spy_model(captured: dict):
    """A fake chat model recording the exact messages and bound kwargs it is called with.

    ``bind_tools`` returns self (kwargs recorded), so the ``model_settings``
    capture covers both factory binding paths; generation is a terminal text
    reply that ends the agent loop without a tool call.
    """

    class _Spy(GenericFakeChatModel):
        def bind_tools(self, tools, **kwargs):  # noqa: ANN001, ANN003
            captured.setdefault("bind_tools_kwargs", []).append(kwargs)
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):  # noqa: ANN001, ANN003
            captured.setdefault("messages", []).append(messages)
            captured.setdefault("gen_kwargs", []).append(kwargs)
            return super()._generate(messages, stop=stop, run_manager=run_manager)

    return _Spy(messages=iter([AIMessage(content="ok")] * 8))


def _system_text(captured: dict) -> str:
    """Flatten the SystemMessage of the first captured model call to one string."""
    system = captured["messages"][0][0]
    content = system.content
    if isinstance(content, str):
        return content
    return "".join(
        block.get("text", "") if isinstance(block, dict) else str(block)
        for block in content
    )


def _run_oneshot_graph(monkeypatch, tmp_path, **option_overrides) -> dict:
    """Compile the REAL one-shot graph over a spy model and invoke it once."""
    captured: dict = {}
    spy = _spy_model(captured)
    patch_models(monkeypatch, spy)
    options = OneShotOptions(
        model="claude-sonnet-4-6",
        cwd=tmp_path,
        tool_policy=ToolPolicy(),
        system_prompt="SYS",
        **option_overrides,
    )
    graph, config = build_oneshot_options(options)
    asyncio.run(
        graph.ainvoke({"messages": [HumanMessage(content="hi")]}, config=config)
    )
    return captured


def _run_streaming_graph(monkeypatch, tmp_path) -> dict:
    """Compile the REAL streaming graph (the S10 shape: no skill_root) and invoke it."""
    captured: dict = {}
    spy = _spy_model(captured)
    patch_models(monkeypatch, spy)
    options = StreamingOptions(
        model="claude-sonnet-4-6",
        cwd=tmp_path,
        tool_policy=ToolPolicy(allowed_tools=("Read",)),
        system_prompt="SYS",
    )
    graph, config = build_streaming_agent(options)
    asyncio.run(
        graph.ainvoke({"messages": [HumanMessage(content="hi")]}, config=config)
    )
    return captured


# ── Task 1: the dead skills block stays off the one-shot system prompt ───────


def test_oneshot_system_prompt_carries_no_skills_block(monkeypatch, tmp_path) -> None:
    """No skill_root (every detection call) => the ~430-token block must be gone."""
    captured = _run_oneshot_graph(monkeypatch, tmp_path)
    text = _system_text(captured)
    assert _SKILLS_HEADER not in text
    assert _NO_SKILLS_TEXT not in text
    # The caller's own system prompt is all that remains.
    assert text == "SYS"


def test_streaming_system_prompt_keeps_skills_block(monkeypatch, tmp_path) -> None:
    """S10/S11-NEUTRALITY PROOF for Task 1 — this asymmetry is deliberate.

    S10/S11 reach the harness only through ``run_streaming`` /
    ``options/streaming.py``, which still passes ``_skill_sources``'s list
    unchanged: S10 gets ``[]`` (and therefore today's dead block, verbatim),
    S11 gets a real ``skill_root``. If this fails, someone "tidied" the
    ``or None`` fix into the streaming path and changed a frozen stage's
    system prompt.
    """
    captured = _run_streaming_graph(monkeypatch, tmp_path)
    text = _system_text(captured)
    assert _SKILLS_HEADER in text
    assert _NO_SKILLS_TEXT in text


# ── Task 2: per-call max_tokens on the one-shot seam ─────────────────────────


def test_oneshot_max_output_tokens_binds_model_settings(monkeypatch, tmp_path) -> None:
    """A set cap must reach the model call as an invocation-level ``max_tokens``."""
    captured = _run_oneshot_graph(monkeypatch, tmp_path, max_output_tokens=8000)
    bound = captured["gen_kwargs"][0]
    assert bound.get("max_tokens") == 8000


def test_oneshot_without_cap_binds_no_max_tokens(monkeypatch, tmp_path) -> None:
    """``None`` (the default) inherits today's behaviour: no per-request override."""
    captured = _run_oneshot_graph(monkeypatch, tmp_path)
    assert captured["gen_kwargs"][0] == {}


def test_streaming_binds_no_max_tokens(monkeypatch, tmp_path) -> None:
    """S10/S11-NEUTRALITY PROOF for Task 2: streaming never gains an output cap.

    ``max_output_tokens`` lives on ``OneShotOptions`` only; a streaming model
    call must keep the model's own ceiling (64k Anthropic / uncapped OpenAI).
    """
    captured = _run_streaming_graph(monkeypatch, tmp_path)
    for bound in captured["gen_kwargs"]:
        assert "max_tokens" not in bound
    for bound in captured.get("bind_tools_kwargs", []):
        assert "max_tokens" not in bound


def test_cap_middleware_preserves_existing_model_settings() -> None:
    """The override merges into ``model_settings``; it never replaces the dict."""
    from langchain.agents.middleware.types import ModelRequest

    middleware = _da_graph_builder.CapOutputTokens(8000)
    request = ModelRequest(
        model=object(),  # never invoked; the handler below only reads settings
        messages=[],
        model_settings={"stop": ["END"]},
    )
    seen: list[dict] = []
    middleware.wrap_model_call(request, lambda req: seen.append(req.model_settings))
    assert seen == [{"stop": ["END"], "max_tokens": 8000}]
