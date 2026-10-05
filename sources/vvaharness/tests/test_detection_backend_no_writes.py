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

"""Fail-closed write surface of the detection deepagents backends.

DeepAgents 0.7.x middleware writes BELOW the model-facing permission layers
(READ_ONLY_PERMISSIONS and the PermitTools gate act on TOOL CALLS; the
middleware calls ``backend.write`` directly): FilesystemMiddleware persists
any >200k-char trailing HumanMessage to ``conversation_history/<uuid>.md``
inside the session root — the SCANNED REPO — and replaces it with a read_file
stub; oversized ToolMessages are offloaded to ``large_tool_results/<id>``;
SummarizationMiddleware offloads history the same way. On the tool-less
detection one-shot the stub is unrecoverable (the model has no read_file), so
an oversized S4 shard prompt degraded to a parse failure or a SILENT empty
findings list. The detection backends now fail every write closed; upstream's
own documented failure handling then keeps the ORIGINAL content in flight:

* human-message eviction tags/truncates only on a SUCCESSFUL write
  (``_apply_eviction_and_truncate``) — the full prompt reaches the model;
* a failed tool-result offload returns None and the caller keeps the original
  ToolMessage (``_offload_tool_message_content``);
* a failed summarization offload is documented non-fatal.

The tripwires below drive the REAL graphs through the REAL production entry
points with fake chat models (no network, no LLM); if a deepagents upgrade
changes the write-failure semantics this file fails loudly. The frozen
S10/S11 streaming shape keeps the stock, WRITABLE backend — pinned here too,
because S10 fix mode needs writes by contract.
"""

from __future__ import annotations

import asyncio

from deepagents.backends import FilesystemBackend
from deepagents.middleware.filesystem import TOO_LARGE_HUMAN_MSG, TOO_LARGE_TOOL_MSG
from deepagents.middleware.summarization import SummarizationMiddleware
from fixtures.deepagents_scaffolding import (
    HEALTHY_TEXT,
    collect_tool_messages,
    fake_model,
    oneshot_options,
    patch_models,
)
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool

from vvaharness.backends.harness import StreamingOptions, ToolPolicy
from vvaharness.backends.harness.deepagents.options import build_oneshot_options
from vvaharness.backends.harness.deepagents.options.filesystem import (
    _NoWriteBackend,
    _ScopedReadBackend,
    _session_backend,
)
from vvaharness.backends.harness.deepagents.options.streaming import (
    build_streaming_agent,
)

# Head phrases of the two upstream replacement stubs; their presence in any
# message the model receives means an eviction fired despite the fix.
_HUMAN_STUB_MARKER = TOO_LARGE_HUMAN_MSG.split("{", 1)[0].strip()
_TOOL_STUB_MARKER = TOO_LARGE_TOOL_MSG.split("{", 1)[0].strip()

# Comfortably past the 200k-char human-eviction threshold (50k tokens x 4).
_EVICTION_THRESHOLD_CHARS = 200_000
_TAIL_SENTINEL = "TAIL-SENTINEL-4462"


# ── the backend unit contract ────────────────────────────────────────────────


def test_write_edit_delete_fail_closed_without_touching_disk(tmp_path):
    (tmp_path / "f.txt").write_text("original", encoding="utf-8")
    backend = _NoWriteBackend(root_dir=tmp_path, virtual_mode=True)

    w = backend.write("/new.txt", "data")
    assert w.error and not (tmp_path / "new.txt").exists()

    e = backend.edit("/f.txt", "original", "patched")
    assert e.error and (tmp_path / "f.txt").read_text(encoding="utf-8") == "original"

    d = backend.delete("/f.txt")
    assert d.error and (tmp_path / "f.txt").exists()


def test_async_wrappers_fail_closed_too(tmp_path):
    """The a* protocol wrappers delegate to the overridden sync methods."""
    (tmp_path / "f.txt").write_text("original", encoding="utf-8")
    backend = _NoWriteBackend(root_dir=tmp_path, virtual_mode=True)

    async def drive():
        return (
            await backend.awrite("/new.txt", "data"),
            await backend.aedit("/f.txt", "original", "patched"),
            await backend.adelete("/f.txt"),
        )

    w, e, d = asyncio.run(drive())
    assert w.error and e.error and d.error
    assert not (tmp_path / "new.txt").exists()
    assert (tmp_path / "f.txt").read_text(encoding="utf-8") == "original"


def test_reads_still_work_on_the_no_write_backend(tmp_path):
    (tmp_path / "f.txt").write_text("readable", encoding="utf-8")
    backend = _NoWriteBackend(root_dir=tmp_path, virtual_mode=True)
    result = backend.read("/f.txt")
    assert not result.error
    assert result.file_data is not None and "readable" in str(result.file_data)


# ── construction-site selection: detection fail-closed, S10/S11 untouched ────


def test_oneshot_construction_gets_the_no_write_backend(tmp_path):
    backend = _session_backend(oneshot_options(tmp_path))
    assert isinstance(backend, _NoWriteBackend)


def test_detection_agentic_construction_gets_scoped_and_no_write(tmp_path):
    options = StreamingOptions(
        model="claude-test",
        cwd=tmp_path,
        tool_policy=ToolPolicy(allowed_tools=("Read",)),
        permitted_tool_calls=frozenset({"read_file"}),
    )
    backend = _session_backend(options)
    assert isinstance(backend, _ScopedReadBackend)
    assert isinstance(backend, _NoWriteBackend)


def test_frozen_streaming_keeps_the_stock_writable_backend(tmp_path):
    """The S10/S11 shape (no permitted_tool_calls): stock backend, writes WORK."""
    options = StreamingOptions(model="claude-test", cwd=tmp_path)
    backend = _session_backend(options)
    assert type(backend) is FilesystemBackend
    result = backend.write("/fix.txt", "patched")
    assert not result.error and (tmp_path / "fix.txt").exists()


# ── tripwire 1: oversized one-shot prompt reaches the model intact ───────────


def _spy_model(captured: dict) -> GenericFakeChatModel:
    """Fake chat model recording the exact messages of every model request."""

    class _Spy(GenericFakeChatModel):
        def bind_tools(self, tools, **_kwargs):  # noqa: ARG002
            return self

        def _generate(self, messages, stop=None, run_manager=None, **_kwargs):
            captured.setdefault("messages", []).append(list(messages))
            return super()._generate(messages, stop=stop, run_manager=run_manager)

    return _Spy(messages=iter([AIMessage(content="ok")] * 4))


def test_oversized_oneshot_prompt_is_not_evicted(tmp_path, monkeypatch):
    """THE regression: a >200k-char parser prompt must arrive byte-identical.

    Pre-fix, FilesystemMiddleware wrote it to ``conversation_history/`` in the
    scanned repo and the tool-less model received a read_file stub it could
    not follow — a parse failure or a silent empty findings list.
    """
    captured: dict = {}
    patch_models(monkeypatch, _spy_model(captured))
    big = "analyze this code\n" + "a" * _EVICTION_THRESHOLD_CHARS + _TAIL_SENTINEL

    graph, config = build_oneshot_options(oneshot_options(tmp_path))
    asyncio.run(
        graph.ainvoke({"messages": [HumanMessage(content=big)]}, config=config)
    )

    humans = [
        m
        for call in captured["messages"]
        for m in call
        if isinstance(m, HumanMessage)
    ]
    assert humans, "the spy model saw no HumanMessage — re-derive the harness shape."
    received = [str(m.content) for m in humans]
    assert any(text == big for text in received), (
        "the oversized prompt did not reach the model byte-identical — "
        "upstream eviction fired despite the fail-closed backend. Regression."
    )
    assert all(_HUMAN_STUB_MARKER not in text for text in received)
    assert not (tmp_path / "conversation_history").exists(), (
        "eviction wrote conversation_history/ into the scanned repo."
    )


# ── tripwire 2: oversized agentic tool result stays inline ───────────────────


def test_oversized_tool_result_kept_inline_on_detection_agentic(tmp_path, monkeypatch):
    """A session-tool result past the 80k-char offload threshold stays inline.

    Built through the REAL streaming builder in the detection-agentic shape
    (``permitted_tool_calls`` set), with an injected session tool returning a
    synthetic oversized payload — the built-in readers cannot trigger this
    path because they paginate their own output below the threshold, but a
    custom session tool (and any future unbounded native) goes straight to
    the offload seam.
    """
    # Clears the 20k-token x 4-chars offload threshold with margin.
    big = "b" * 90_000 + _TAIL_SENTINEL

    def _builder(options, allowed_tools=()):  # noqa: ARG001
        @tool
        def dump_data() -> str:
            """Return the synthetic oversized payload."""
            return big

        return [dump_data]

    script = [
        AIMessage(
            content="",
            tool_calls=[{
                "name": "dump_data",
                "args": {},
                "id": "call-big-dump",
                "type": "tool_call",
            }],
        ),
        AIMessage(content=HEALTHY_TEXT),
    ]
    patch_models(monkeypatch, fake_model(script))

    graph, config = build_streaming_agent(
        StreamingOptions(
            model="claude-test",
            cwd=tmp_path,
            tool_policy=ToolPolicy(),
            tool_builder=_builder,
            permitted_tool_calls=frozenset(),
            max_turns=12,
        )
    )
    collected = collect_tool_messages(graph, config)

    dumps = [m for _ns, m in collected if m.tool_call_id == "call-big-dump"]
    assert dumps, "the session tool produced no observable ToolMessage."
    content = str(dumps[-1].content)
    assert _TAIL_SENTINEL in content, (
        "the oversized tool result was clipped — the offload replaced it "
        "despite the fail-closed backend. Regression."
    )
    assert _TOOL_STUB_MARKER not in content
    assert not (tmp_path / "large_tool_results").exists(), (
        "tool-result eviction wrote large_tool_results/ into the scanned repo."
    )


# ── tripwire 3: summarization offload failure is non-fatal ───────────────────


def test_summarization_offload_fails_nonfatally_and_writes_nothing(tmp_path):
    """The offload seam returns None (documented non-fatal) instead of raising."""
    backend = _NoWriteBackend(root_dir=tmp_path, virtual_mode=True)
    middleware = SummarizationMiddleware(
        model=fake_model([AIMessage(content="summary")]), backend=backend
    )
    out = middleware._offload_to_backend(
        backend, [HumanMessage(content="history")], "session-1"
    )
    assert out is None
    assert not (tmp_path / "conversation_history").exists()
    assert not any(tmp_path.iterdir()), (
        "the failed summarization offload still created files in the repo."
    )
