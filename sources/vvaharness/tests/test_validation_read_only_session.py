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

"""A read-only session must not be able to write, and must not leak file content.

The filesystem deny rules cannot carry this alone: the matcher runs without DOTGLOB
and unmatched paths fail open, so hidden paths stayed writable. `.git/config` is the
sharp case -- the harness itself runs git in that tree, so a write there is remote
code execution. The write tools are therefore withheld from the model as well.

DeepAgents applies ``create_deep_agent(middleware=...)`` to the parent stack only, so
subagents need their own copy or they read unredacted -- and the personas are what do
almost all of the reading.

Offline and deterministic: no network, no LLM, no subprocess.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from vvaharness.backends.harness import (
    NATIVE_WRITE_TOOLS,
    StreamingOptions,
    SubagentDefinition,
)
from vvaharness.backends.harness.deepagents.exclude_tools import ExcludeTools
from vvaharness.backends.harness.deepagents.models import DELETE_TOOL_NAME
from vvaharness.backends.harness.deepagents.options import subagents as _da_subagents
from vvaharness.backends.harness.deepagents.options.subagents import get_subagent_specs
from vvaharness.backends.harness.deepagents.redaction import read_only_middleware


@pytest.fixture(autouse=True)
def _stub_model_factory(monkeypatch):
    """Keep this module honest about its "no network, no LLM" docstring.

    ``get_subagent_specs`` resolves each subagent's chat model eagerly, so
    without a stub it constructs a real ``ChatOpenAI`` -- which raises unless
    the machine happens to export ``OPENAI_API_KEY``. Patch the name
    ``subagents`` actually holds (it imports the symbol directly, so patching
    the package attribute would not take effect). The spec only stores the
    object, so any sentinel works.
    """
    monkeypatch.setattr(
        _da_subagents, "build_model_cached", lambda *a, **kw: object()
    )


def _options(
    *, allow_writes: bool, agents: dict[str, SubagentDefinition] | None = None
) -> StreamingOptions:
    if agents is None:
        agents = {
            "security-architect": SubagentDefinition(
                name="security-architect", description="d", prompt="p"
            )
        }
    return StreamingOptions(
        model="test",
        cwd=Path("/tmp"),
        allow_writes=allow_writes,
        agents=agents,
    )


def test_read_only_middleware_redacts_and_withholds_write_tools() -> None:
    kinds = [type(m).__name__ for m in read_only_middleware()]
    assert "RedactToolResults" in kinds
    assert "ExcludeTools" in kinds


def test_read_only_middleware_excludes_delete() -> None:
    """NATIVE_WRITE_TOOLS does not carry ``delete``; the read-only gate must."""
    exclude = next(m for m in read_only_middleware() if isinstance(m, ExcludeTools))
    assert DELETE_TOOL_NAME in exclude._excluded
    assert NATIVE_WRITE_TOOLS <= exclude._excluded


def test_write_tools_are_removed_from_the_model_request() -> None:
    """FilesystemMiddleware always offers write_file/edit_file; strip them."""
    tools = [SimpleNamespace(name=n) for n in ("read_file", "grep", "write_file", "edit_file")]
    captured: dict[str, object] = {}

    request = SimpleNamespace(
        tools=tools,
        override=lambda **kw: SimpleNamespace(tools=kw["tools"], override=None),
    )
    ExcludeTools(NATIVE_WRITE_TOOLS).wrap_model_call(
        request, lambda req: captured.setdefault("tools", req.tools)
    )
    names = {getattr(t, "name", None) for t in captured["tools"]}
    assert names == {"read_file", "grep"}


def test_subagents_get_their_own_read_only_middleware() -> None:
    """Parent-only middleware left the personas reading unredacted."""
    specs = get_subagent_specs(_options(allow_writes=False))
    assert specs, "expected a persona spec"
    for spec in specs:
        kinds = [type(m).__name__ for m in spec["middleware"]]
        assert "RedactToolResults" in kinds, spec["name"]
        assert "ExcludeTools" in kinds, spec["name"]


def test_write_sessions_keep_their_edit_tools_but_withhold_delete() -> None:
    """Writer subagents edit files (masking reads would break edit_file's old_string)
    but never delete; read-only personas stay fully gated even in a write session."""
    agents = {
        "fixer": SubagentDefinition(
            name="fixer", description="d", prompt="p",
            tools=("Read", "Grep", "Glob", "Edit"),
        ),
        "security-architect": SubagentDefinition(
            name="security-architect", description="d", prompt="p"
        ),
    }
    specs = {
        spec["name"]: spec
        for spec in get_subagent_specs(_options(allow_writes=True, agents=agents))
    }
    fixer_kinds = [type(m).__name__ for m in specs["fixer"]["middleware"]]
    # No RedactToolResults for a writer; caching middleware is gate-neutral.
    assert fixer_kinds == ["ExcludeTools", "BlockMarkerPromptCaching"]
    excluded = next(iter(specs["fixer"]["middleware"]))._excluded
    assert excluded == frozenset({DELETE_TOOL_NAME})
    reader_kinds = [type(m).__name__ for m in specs["security-architect"]["middleware"]]
    assert "RedactToolResults" in reader_kinds
    assert "ExcludeTools" in reader_kinds


def test_every_dispatchable_spec_carries_gate_middleware() -> None:
    """The builtin general-purpose subagent had neither RedactToolResults nor a
    delete exclusion; the shadow spec must flow through the same gates."""
    for allow_writes in (False, True):
        specs = get_subagent_specs(_options(allow_writes=allow_writes))
        assert {s["name"] for s in specs} == {"security-architect", "general-purpose"}
        for spec in specs:
            kinds = [type(m).__name__ for m in spec["middleware"]]
            assert "ExcludeTools" in kinds, (spec["name"], allow_writes)


def test_general_purpose_shadow_is_read_only_even_in_write_sessions() -> None:
    specs = {
        spec["name"]: spec
        for spec in get_subagent_specs(_options(allow_writes=True))
    }
    kinds = [type(m).__name__ for m in specs["general-purpose"]["middleware"]]
    assert "RedactToolResults" in kinds
    assert "ExcludeTools" in kinds


# NOTE: this file used to also carry a one-shot advertised-tool-set test
# (`test_oneshot_graph_advertises_no_tools_not_even_task`, with a private
# `_recording_model` helper). The canonical, strictly stronger pin now lives
# in tests/test_deepagents_tool_exposure.py (the `oneshot-detection(a)` row
# of its _SHAPES table plus test_oneshot_graph_never_offers_task_to_the_model),
# driven through the real production entry point
# (backends/llm/deepagents.py::prompt). Its old docstring's claim that a
# forged `task` call "would still execute" is false on this branch:
# execution-side refusal is pinned by tests/test_oneshot_task_executor_gate.py
# ::test_forged_task_call_is_refused_before_any_subagent_dispatch (PermitTools
# at wrap_tool_call).
