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

"""Contract and translation tests for the additive DeepAgents validation backend.

These tests do not hit real endpoints; they use stubbed LangGraph/LangChain
models to verify option translation, tool gating, message translation, and that
the harness emits the same HarnessMessage sequence as the Claude backend for a
synthetic scenario.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from langchain.agents.structured_output import ToolStrategy
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from pydantic import BaseModel

from vvaharness.backends.harness import (
    HarnessAssistantText,
    HarnessResult,
    HarnessSessionInit,
    HarnessToolResult,
    HarnessToolUse,
    PermissionsPolicy,
    StreamingOptions,
    SubagentDefinition,
)
from vvaharness.backends.harness.deepagents.client import DeepAgentHarness
from vvaharness.backends.harness.deepagents.options import build_model, get_subagent_specs
from vvaharness.backends.harness.deepagents.options.filesystem import (
    _filesystem_permissions,
    _session_backend,
    _skill_sources,
)
from vvaharness.backends.harness.deepagents.options.response_format import (
    _pydantic_response_format,
)
from vvaharness.backends.harness.deepagents.options.subagents import _subagent_tools
from vvaharness.backends.harness.deepagents.tools import build_tools
from vvaharness.backends.harness.deepagents.translate import (
    make_terminal_result,
    translate_final_state,
    translate_stream_events,
)
from vvaharness.models import Decision, GateStatus
from vvaharness.validation.constants.artifacts import (
    SYNTHESIZED_GATES_FILENAME,
    VALIDATION_REPORT_FILENAME,
)
from vvaharness.validation.constants.policy import VALIDATION_POLICY
from vvaharness.validation.constants.tools import DEFAULT_FACT_TOOLS
from vvaharness.validation.io.persona_report_stash import extract_subagent_reports
from vvaharness.validation.models.persona_report import PersonaGateEntry, PersonaReport
from vvaharness.validation.session.launcher import (
    _DEFAULT_VALIDATE_ENV_VARS,
    _build_env,
    _write_host_synthesized_gates,
    _write_validation_outputs,
)
from vvaharness.validation.synthesis._consensus import (
    synthesize_gates_for_finding,
)
from vvaharness.validation.tools.deep_tools import build_validation_tools
from vvaharness.validation.tools.diff_facts import (
    build_diff_impact_map,
    diff_touched,
    parse_diff_patch,
)


class _FakeChatModel:
    """Minimal LangChain-compatible chat model for exercising create_agent graphs."""

    def __init__(self, responses: list[AIMessage]) -> None:
        self._responses = list(responses)
        self._index = 0

    def bind(self, **kwargs: object) -> _FakeChatModel:
        return self

    def bind_tools(self, tools: Any, **kwargs: object) -> _FakeChatModel:
        return self

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        response = self._responses[self._index]
        self._index = min(self._index + 1, len(self._responses) - 1)
        return response

    @property
    def _llm_type(self) -> str:
        return "fake"


# Model resolution


def test_build_model_resolves_openai_provider() -> None:
    env = {"OPENAI_API_KEY": "sk-test", "OPENAI_BASE_URL": "http://openai"}
    model = build_model("gpt-4o", env, provider="openai")
    assert model._llm_type == "openai-chat"
    assert str(model.openai_api_key.get_secret_value()) == "sk-test"  # type: ignore[attr-defined]
    assert str(model.openai_api_base) == "http://openai"  # type: ignore[attr-defined]


def test_build_model_resolves_anthropic_provider() -> None:
    env = {
        "ANTHROPIC_API_KEY": "sk-ant-test",
        "ANTHROPIC_BASE_URL": "http://anthropic",
    }
    model = build_model("claude-sonnet-4-6", env, provider="anthropic")
    assert model._llm_type == "anthropic-chat"


def test_build_model_infers_openai_from_gpt_name() -> None:
    env = {"OPENAI_API_KEY": "sk-test"}
    model = build_model("gpt-5.5", env)
    assert model._llm_type == "openai-chat"


def test_openai_model_accepts_node_ca_bundle(monkeypatch: Any, tmp_path: Path) -> None:
    from vvaharness.backends.harness.deepagents.options import model_building as deep_options

    ca = tmp_path / "ca.pem"
    ca.write_text("certificate placeholder", encoding="utf-8")
    sentinel = object()
    monkeypatch.setattr(deep_options.httpx, "create_ssl_context", lambda **kwargs: sentinel)
    assert deep_options._ssl_context({"NODE_EXTRA_CA_CERTS": str(ca)}) is sentinel


def test_build_model_anthropic_no_base_url_when_unset() -> None:
    env = {"ANTHROPIC_API_KEY": "sk-ant"}
    model = build_model("claude-sonnet-4-6", env)
    assert model._llm_type == "anthropic-chat"


def test_build_model_infers_openai_from_nongpt_name() -> None:
    """A bare non-gpt, non-claude name (glm, kimi) routes to OpenAI-compatible."""
    model = build_model("glm-5.2", {"OPENAI_API_KEY": "sk-test"})
    assert model._llm_type == "openai-chat"


def test_build_model_explicit_provider_openai_wins_over_claude_name() -> None:
    model = build_model("claude-ish-model", {"OPENAI_API_KEY": "sk"}, provider="openai")
    assert model._llm_type == "openai-chat"


def test_build_model_explicit_provider_anthropic_wins_over_nonclaude_name() -> None:
    model = build_model("some-model", {"ANTHROPIC_API_KEY": "sk-ant"}, provider="anthropic")
    assert model._llm_type == "anthropic-chat"


# Permissioning and tool building


def _fresh_options(tmp_path: Path, **kwargs: Any) -> StreamingOptions:
    merged = {
        "model": "gpt-test",
        "cwd": tmp_path,
        "env": {},
        "tool_policy": VALIDATION_POLICY,
        "permissions": PermissionsPolicy(target_dir=tmp_path),
    }
    merged.update(kwargs)
    return StreamingOptions(**merged)  # type: ignore[arg-type]


def test_read_only_permissions_deny_write_everywhere() -> None:
    """Assert the DECISION, not the pattern list.

    The matcher runs without DOTGLOB and unmatched paths fail open, so a rule set
    that looks total can still leave `.git/config` writable -- which is RCE once the
    harness runs git in that tree. Only evaluating real paths catches that.
    """
    from deepagents.middleware.filesystem import _check_fs_permission

    perms = _filesystem_permissions(_fresh_options(Path("/tmp")))
    assert all(p.operations == ["write"] and p.mode == "deny" for p in perms)
    for path in (
        "/src/app.py",
        "/validation_report.json",
        "/.git/config",
        "/.git/hooks/pre-commit",
        "/.github/workflows/ci.yml",
        "/.env",
        "/.claude/settings.json",
        "/nested/.hidden/secret",
        "/a/.git/config",
    ):
        assert _check_fs_permission(perms, "write", path) == "deny", path


def test_build_tools_exposes_read_grep_glob_fact_tools_and_no_write() -> None:
    """Readers map to native middleware tools; only fact tools are built here."""
    from vvaharness.backends.harness.deepagents.tools import native_tool_names

    options = _fresh_options(Path("/tmp"))
    allowed = (
        "Read", "Grep", "Glob", "Write", "DiffTouched", "ChangedLines",
        "DiffImpactMap", "PatternScan", "TestInventory",
    )
    names = {t.name for t in build_validation_tools(options, allowed_tools=allowed)}
    assert {"DiffTouched", "ChangedLines", "DiffImpactMap", "PatternScan",
            "TestInventory"}.issubset(names)
    # Readers are NOT rebuilt - they resolve to the native middleware names.
    assert not ({"Read", "Grep", "Glob"} & names)
    assert native_tool_names(options, allowed) == (
        "read_file", "grep", "glob", "write_file",
    )


def test_build_tools_denies_bash_edit_notebook() -> None:
    """Unmapped logical names (Bash/NotebookEdit) resolve to no native tool."""
    from vvaharness.backends.harness.deepagents.tools import native_tool_names

    options = _fresh_options(Path("/tmp"))
    allowed = ("Bash", "Edit", "NotebookEdit", "Read")
    assert native_tool_names(options, allowed) == ("read_file", "edit_file")
    assert build_tools(options, allowed_tools=allowed) == []


def test_read_tool_confined_to_cwd(tmp_path: Path) -> None:
    """Path confinement for the DeepAgents backend now comes from FilesystemBackend.

    The repo no longer builds its own Read tool (see LOGICAL_TO_NATIVE); the
    native read_file is confined by FilesystemBackend(virtual_mode=True), which
    rejects traversal. localtools' own jail is covered by tests/test_localtools.py.
    """
    backend = _session_backend(_fresh_options(tmp_path, allow_writes=True))
    assert backend is not None
    assert Path(backend.cwd).resolve() == tmp_path.resolve()


# Inventory scoping: the root jail alone still exposes .git/, the scanner's own
# output, and operator-excluded directories. A DETECTION construction — the only
# site that sets StreamingOptions.permitted_tool_calls (backends/llm/deepagents.py
# agentic()) — gets a backend additionally confined to the file inventory
# s1_preprocess registers (backends.llm.tools.set_scope). The frozen S10/S11
# option builders never set the field, so their constructions keep the stock
# FilesystemBackend and their full read/write reach — asserted below, because
# those post-scan stages legitimately read and write across the whole target.

_DETECTION_NATIVES = frozenset({"read_file", "grep", "glob"})


@pytest.fixture
def scoped_repo(tmp_path: Path):
    """A target with in-scope files, an operator-excluded answer key, VCS
    metadata and scanner output; registers the inventory, always deregisters."""
    from vvaharness.backends.llm import tools as lt

    (tmp_path / "sub").mkdir()
    (tmp_path / "a.txt").write_text("alpha\nneedle here\n", encoding="utf-8")
    (tmp_path / "sub" / "b.java").write_text("needle in java\n", encoding="utf-8")
    (tmp_path / "answer-key").mkdir()
    (tmp_path / "answer-key" / "answers.md").write_text(
        "needle planted-vuln payload\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(
        "url = https://user:tok@host/r.git\n", encoding="utf-8")
    (tmp_path / "security-scan").mkdir()
    (tmp_path / "security-scan" / "report.md").write_text(
        "needle prior findings\n", encoding="utf-8")
    lt.set_scope(tmp_path, ["a.txt", "sub/b.java"])
    try:
        yield tmp_path
    finally:
        lt._SCOPE.pop(str(tmp_path.resolve()), None)


def _detection_backend(root: Path) -> Any:
    return _session_backend(
        _fresh_options(root, permitted_tool_calls=_DETECTION_NATIVES)
    )


def test_detection_read_outside_inventory_refused(scoped_repo: Path) -> None:
    """The excluded-directory case: a real file the operator excluded from the
    scan is refused, and none of its content leaves the backend."""
    res = _detection_backend(scoped_repo).read("/answer-key/answers.md")
    assert res.file_data is None
    assert res.error is not None and "excluded from the scan scope" in res.error


def test_detection_scope_refusal_before_existence(scoped_repo: Path) -> None:
    """An excluded-but-missing path gets the scope error, not "not found" —
    the refusal must not double as an existence oracle."""
    res = _detection_backend(scoped_repo).read("/answer-key/nope.md")
    assert res.error is not None and "excluded from the scan scope" in res.error
    assert "not found" not in res.error


def test_detection_in_scope_read_succeeds(scoped_repo: Path) -> None:
    res = _detection_backend(scoped_repo).read("/a.txt")
    assert res.error is None
    assert res.file_data is not None and "alpha" in res.file_data["content"]


def test_detection_grep_confined_to_inventory(scoped_repo: Path) -> None:
    backend = _detection_backend(scoped_repo)
    hits = backend.grep("needle")
    assert {m["path"] for m in hits.matches} == {"/a.txt", "/sub/b.java"}
    direct = backend.grep("needle", path="/answer-key/answers.md")
    assert direct.matches == []
    assert direct.error is not None and "excluded from the scan scope" in direct.error


def test_detection_glob_and_ls_confined_to_inventory(scoped_repo: Path) -> None:
    backend = _detection_backend(scoped_repo)
    # "*.md" matches basenames at any depth; both hits are out of scope.
    assert backend.glob("*.md").matches == []
    listed = {e["path"] for e in backend.ls("/").entries}
    assert listed == {"/a.txt", "/sub/"}


def test_detection_vcs_and_scan_output_refused_without_scope(tmp_path: Path) -> None:
    """No registered inventory (a stage before s1): version-control metadata and
    the scanner's own output directory are still refused unconditionally."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("url = x\n", encoding="utf-8")
    (tmp_path / "security-scan").mkdir()
    (tmp_path / "security-scan" / "report.md").write_text("prior\n", encoding="utf-8")
    (tmp_path / "a.txt").write_text("alpha\n", encoding="utf-8")
    backend = _detection_backend(tmp_path)
    for path in ("/.git/config", "/security-scan/report.md"):
        res = backend.read(path)
        assert res.error is not None and "excluded from the scan scope" in res.error
    assert backend.grep("prior").matches == []
    assert backend.read("/a.txt").error is None  # unscoped reads stay legal


def test_frozen_construction_retains_full_reach(scoped_repo: Path) -> None:
    """The constraint this whole seam protects: the frozen S10/S11 option
    builders never set permitted_tool_calls, so — even with a scope registered
    for the very same root, as happens in-process after s1 — their backend is
    the stock FilesystemBackend and reads the operator-excluded directory,
    VCS metadata and scanner output exactly as before."""
    from deepagents.backends import FilesystemBackend

    for kwargs in (
        {"allow_writes": True, "writable_paths": (str(scoped_repo),)},  # S10 fix mode
        {},  # S10 detect-only / S11 validation: read-only, no opt-in
    ):
        backend = _session_backend(_fresh_options(scoped_repo, **kwargs))
        assert type(backend) is FilesystemBackend
        res = backend.read("/answer-key/answers.md")
        assert res.error is None
        assert "planted-vuln" in res.file_data["content"]
        assert backend.read("/.git/config").error is None
        assert "/security-scan/report.md" in {
            m["path"] for m in backend.grep("prior findings").matches
        }


# Subagent tool filtering


def test_subagent_tools_inherit_policy_and_strip_writes() -> None:
    subagent = SubagentDefinition(
        name="security-architect",
        description="d",
        prompt="p",
        tools=None,
        disallowed_tools=None,
    )
    options = _fresh_options(Path("/tmp"))
    # VALIDATION_POLICY no longer grants Write at all -- the agent returns structured
    # output and the host persists it -- so a persona inherits the policy verbatim.
    assert set(_subagent_tools(subagent, options)) == set(VALIDATION_POLICY.allowed_tools)
    assert "Write" not in _subagent_tools(subagent, options)


def test_subagent_tools_apply_frontmatter_denylist(tmp_path: Path) -> None:
    subagent = SubagentDefinition(
        name="security-architect",
        description="d",
        prompt="p",
        tools=("Read", "Grep", "Glob", "Bash"),
        disallowed_tools=("Bash",),
    )
    options = _fresh_options(tmp_path)
    assert set(_subagent_tools(subagent, options)) == {"Read", "Grep", "Glob"}


def test_get_subagent_specs_reader_gets_middleware_in_fix_mode(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Non-writer subagents must have RedactToolResults even when allow_writes=True (v3_37)."""
    import vvaharness.backends.harness.deepagents.options.subagents as da_subagents
    from vvaharness.backends.harness.deepagents.redaction import RedactToolResults
    from vvaharness.backends.harness.models import ToolPolicy

    monkeypatch.setattr(da_subagents, "build_model_cached", lambda *a, **kw: _FakeChatModel([]))
    options = StreamingOptions(
        model="gpt-test",
        cwd=tmp_path,
        env={},
        allow_writes=True,
        writable_paths=(str(tmp_path),),
        tool_policy=ToolPolicy(allowed_tools=("Read", "Grep", "Glob")),
        agents={
            "analyzer": SubagentDefinition(
                name="analyzer",
                description="reads only",
                prompt="p",
            ),
        },
    )
    specs = get_subagent_specs(options)
    spec = next(s for s in specs if s["name"] == "analyzer")
    middleware = spec.get("middleware", [])
    assert any(isinstance(m, RedactToolResults) for m in middleware)


def test_get_subagent_specs_writer_subagent_skips_middleware_in_fix_mode(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Writer subagents (with Edit) must NOT get RedactToolResults: edit_file needs unredacted reads."""
    import vvaharness.backends.harness.deepagents.options.subagents as da_subagents
    from vvaharness.backends.harness.deepagents.redaction import RedactToolResults
    from vvaharness.backends.harness.models import ToolPolicy

    monkeypatch.setattr(da_subagents, "build_model_cached", lambda *a, **kw: _FakeChatModel([]))
    options = StreamingOptions(
        model="gpt-test",
        cwd=tmp_path,
        env={},
        allow_writes=True,
        writable_paths=(str(tmp_path),),
        tool_policy=ToolPolicy(allowed_tools=("Read", "Grep", "Glob", "Edit")),
        agents={
            "fixer": SubagentDefinition(
                name="fixer",
                description="applies edits",
                prompt="p",
                tools=("Read", "Grep", "Glob", "Edit"),
            ),
        },
    )
    specs = get_subagent_specs(options)
    spec = next(s for s in specs if s["name"] == "fixer")
    middleware = spec.get("middleware", [])
    assert not any(isinstance(m, RedactToolResults) for m in middleware)


def test_get_subagent_specs_use_native_deepagents_response_format(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # get_subagent_specs resolves each subagent's chat model eagerly; stub the
    # factory (as the sibling spec tests do) so no provider credential is needed.
    # Patch the name subagents.py imported into ITS namespace — patching the
    # options package attribute would leave the real factory in place.
    import vvaharness.backends.harness.deepagents.options.subagents as da_subagents

    monkeypatch.setattr(da_subagents, "build_model_cached", lambda *a, **kw: _FakeChatModel([]))
    options = _fresh_options(
        tmp_path,
        tool_builder=build_validation_tools,
        fact_tools=DEFAULT_FACT_TOOLS,
        agents={
            "security-architect": SubagentDefinition(
                name="security-architect",
                description="d",
                prompt="p",
                response_model=PersonaReport,
            ),
        },
    )
    specs = get_subagent_specs(options)
    # The configured persona plus the always-present general-purpose shadow.
    assert {s["name"] for s in specs} == {"security-architect", "general-purpose"}
    spec = next(s for s in specs if s["name"] == "security-architect")
    # Subagents use the same per-provider strategy as the parent (see
    # test_response_format_selects_strategy_per_provider). No provider set here, so
    # the bare schema is passed through for LangChain's auto-detection.
    assert spec["response_format"] is PersonaReport
    # Fact tools are appended to the default parent tool list.
    tool_names = {t.name for t in spec["tools"]}
    assert {"DiffTouched", "PatternScan", "TestInventory"}.issubset(tool_names)
    assert "Bash" not in tool_names
    assert "Agent" not in tool_names


# Structured output / response format


def test_response_format_overrides_anthropic_only() -> None:
    """anthropic -> tool-calling; everything else defers to LangChain auto-detection.

    Forcing native output on models whose profile does not vouch for simultaneous
    tools + structured output suppresses tool calling entirely, so only the
    Anthropic gateway quirk is overridden here.
    """
    from vvaharness.backends.harness.deepagents.options.response_format import _response_format

    assert isinstance(_response_format(PersonaReport, "gpt-test", "anthropic"), ToolStrategy)
    assert _response_format(PersonaReport, "gpt-test", "openai") is PersonaReport
    assert _response_format(PersonaReport, "gpt-test", None) is PersonaReport
    assert _response_format(None, "gpt-test", "openai") is None


def test_response_format_overrides_a_claude_model_with_no_explicit_provider() -> None:
    """The route decides, not `provider` alone.

    A claude-* id with no provider builds a ChatAnthropic, so it needs the same override an
    explicit `provider: anthropic` gets. Testing provider alone skipped it and left that pair
    on the gateway's native structured output, which returns invalid JSON.
    """
    from vvaharness.backends.harness.deepagents.options.response_format import _response_format

    assert isinstance(_response_format(PersonaReport, "claude-opus-5", None), ToolStrategy)
    assert _response_format(PersonaReport, "claude-opus-5", "openai") is PersonaReport


def test_pydantic_response_format_builds_required_fields() -> None:
    schema = {
        "type": "object",
        "properties": {
            "verdict": {"type": "string"},
            "score": {"type": "integer"},
        },
        "required": ["verdict", "score"],
    }
    model = _pydantic_response_format(schema)
    instance = model(verdict="pass", score=8)
    assert instance.verdict == "pass"  # type: ignore[attr-defined]
    assert instance.score == 8  # type: ignore[attr-defined]


# Translation


def test_translate_final_state_prefers_structured_output() -> None:
    class Output(BaseModel):
        verdict: str

    state = {
        "messages": [AIMessage(content=" textual fallback")],
        "structured_response": Output(verdict="pass"),
    }
    result = translate_final_state(state, oneshot=True)
    assert result.structured is not None
    assert "pass" in str(result.structured)
    assert result.result_text is None


def test_translate_final_state_falls_back_to_last_ai_text() -> None:
    state = {
        "messages": [
            AIMessage(content="", tool_calls=[]),
            AIMessage(content="  final answer "),
        ],
    }
    result = translate_final_state(state, oneshot=True)
    assert result.result_text == "final answer"
    assert result.structured is None


def _run_sync(coro: Any) -> Any:
    return asyncio.run(coro)


def test_translate_stream_events_yields_text_tool_use_and_result() -> None:
    event = {
        "model": {
            "messages": [
                AIMessage(
                    content="think",
                    tool_calls=[{"id": "tc1", "name": "Read", "args": {"path": "x.py"}}],
                ),
            ],
        },
    }
    seen: set[str] = set()

    async def _collect() -> list[Any]:
        return [m async for m in translate_stream_events(event, seen)]

    messages = _run_sync(_collect())
    assert len(messages) == 2
    assert isinstance(messages[0], HarnessAssistantText)
    assert messages[0].text == "think"
    assert isinstance(messages[1], HarnessToolUse)
    assert messages[1].tool_id == "tc1"
    assert messages[1].name == "Read"
    assert messages[1].input == {"path": "x.py"}


def test_translate_stream_events_emits_tool_result() -> None:
    event = {
        "tools": {
            "messages": [ToolMessage(content="file body", tool_call_id="tc1")],
        },
    }

    async def _collect() -> list[Any]:
        return [m async for m in translate_stream_events(event, set())]

    messages = _run_sync(_collect())
    assert len(messages) == 1
    assert isinstance(messages[0], HarnessToolResult)
    assert messages[0].content == "file body"
    assert messages[0].is_error is False


def test_translate_stream_events_tags_subagent_by_persona() -> None:
    # subgraphs=True events are (namespace, payload) tuples; () is the parent.
    parent = ((), {"model": {"messages": [AIMessage(content="dispatch", name="validation")]}})
    ns = ("task:abc",)
    persona_ai = (
        ns,
        {"model": {"messages": [AIMessage(
            content="looking",
            name="security-architect",
            tool_calls=[{"id": "s1", "name": "Read", "args": {"path": "a.py"}}],
        )]}},
    )
    persona_tr = (ns, {"tools": {"messages": [ToolMessage(content="body", tool_call_id="s1")]}})
    seen: set[str] = set()
    ns_to_agent: dict[tuple, str] = {}

    async def _collect(ev: Any) -> list[Any]:
        return [m async for m in translate_stream_events(ev, seen, ns_to_agent)]

    parent_msgs = _run_sync(_collect(parent))
    assert parent_msgs[0].agent == "validation"
    assert parent_msgs[0].namespace is None  # empty namespace -> None

    ai_msgs = _run_sync(_collect(persona_ai))
    tool_use = next(m for m in ai_msgs if isinstance(m, HarnessToolUse))
    assert tool_use.agent == "security-architect"
    assert tool_use.namespace == ns

    tr_msgs = _run_sync(_collect(persona_tr))
    # A tool result carries only the tool name; it inherits the persona via ns.
    assert tr_msgs[0].agent == "security-architect"
    assert tr_msgs[0].namespace == ns


def test_read_only_harness_profile_excludes_write_tools() -> None:
    from vvaharness.backends.harness.deepagents.models import READ_ONLY_HARNESS_PROFILE

    assert READ_ONLY_HARNESS_PROFILE.excluded_tools == frozenset({"write_file", "edit_file"})


def test_write_permissions_are_scoped_to_workspace(tmp_path: Path) -> None:
    from vvaharness.backends.harness.deepagents.models import GIT_INTERNALS_DENY

    writable = StreamingOptions(
        model="test", cwd=tmp_path, allow_writes=True,
        writable_paths=(str(tmp_path),),
    )
    assert _filesystem_permissions(writable) == GIT_INTERNALS_DENY

    escaping = StreamingOptions(
        model="test", cwd=tmp_path, allow_writes=True,
        writable_paths=(str(tmp_path.parent),),
    )
    with pytest.raises(ValueError, match="escapes harness cwd"):
        _filesystem_permissions(escaping)


def test_fix_mode_still_denies_writes_into_git_internals(tmp_path: Path) -> None:
    """S10 fix mode is opted into writes generally, but `.git/config` stays denied.

    The harness itself later runs git in this tree, so a write there (e.g.
    core.fsmonitor/core.sshCommand, a [url] rewrite) is remote code execution --
    the same sharp case the read-only session test calls out, except here the
    write tools are legitimately live, so path-level denial is the only guard.
    """
    from deepagents.middleware.filesystem import _check_fs_permission

    options = StreamingOptions(
        model="test", cwd=tmp_path, allow_writes=True,
        writable_paths=(str(tmp_path),),
    )
    perms = _filesystem_permissions(options)
    for path in ("/.git/config", "/.git/hooks/pre-commit", "/a/.git/config"):
        assert _check_fs_permission(perms, "write", path) == "deny", path
    for path in ("/src/app.py", "/fixed.py", "/.env"):
        assert _check_fs_permission(perms, "write", path) == "allow", path


def test_fix_mode_backend_writes_to_disk_and_confines_paths(tmp_path: Path) -> None:
    options = StreamingOptions(
        model="test", cwd=tmp_path, allow_writes=True,
        writable_paths=(str(tmp_path),),
    )
    backend = _session_backend(options)
    assert backend is not None
    assert backend.virtual_mode is True

    backend.write("/fixed.py", "safe = True\n")
    assert (tmp_path / "fixed.py").read_text() == "safe = True\n"
    with pytest.raises(ValueError, match="traversal"):
        backend.write("../escaped.py", "unsafe = True\n")
    assert not (tmp_path.parent / "escaped.py").exists()


def test_read_only_backend_is_disk_backed_and_write_denied(tmp_path: Path) -> None:
    """Read-only sessions still need a real filesystem: the native read tools are
    the only read path, so StateBackend would show an empty workspace. Writes are
    denied by the permission rules instead."""
    from deepagents.middleware.filesystem import _check_fs_permission

    options = StreamingOptions(model="test", cwd=tmp_path, allow_writes=False)
    backend = _session_backend(options)
    assert backend is not None
    assert Path(backend.cwd).resolve() == tmp_path.resolve()
    perms = _filesystem_permissions(options)
    assert _check_fs_permission(perms, "write", "/fixed.py") == "deny"
    assert _check_fs_permission(perms, "write", "/.git/config") == "deny"


def test_skill_sources_are_virtual_paths_to_the_package_root(tmp_path: Path) -> None:
    """DeepAgents lists skill sources through the virtual-rooted backend, so a
    source must be a '/'-relative path to the directory CONTAINING packages."""
    root = tmp_path / ".claude" / "skills"
    (root / "validation-scoring").mkdir(parents=True)
    (root / "validation-scoring" / "SKILL.md").write_text("---\nname: x\n---\n")

    assert _skill_sources(root, tmp_path) == ["/.claude/skills"]
    assert _skill_sources(None, tmp_path) == []
    assert _skill_sources(tmp_path / "absent", tmp_path) == []


def test_skill_sources_reject_root_outside_cwd(tmp_path: Path) -> None:
    """A packaged-source path cannot be reached through the virtual backend: it
    would resolve to <cwd>/<host path> and silently load zero skills."""
    outside = tmp_path.parent / "installed-package-skills"
    outside.mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="must live under the session cwd"):
        _skill_sources(outside, tmp_path)


def test_make_terminal_result_extracts_last_ai_text_and_structured() -> None:
    state = {
        "messages": [
            HumanMessage(content="hi"),
            AIMessage(content="answer"),
        ],
        "structured_response": {"verdict": "pass"},
    }
    terminal = make_terminal_result(state)
    assert isinstance(terminal, HarnessResult)
    assert terminal.subtype == "success"
    assert terminal.result_text == "answer"
    assert terminal.structured == {"verdict": "pass"}
    assert terminal.total_cost_usd is None


def test_make_terminal_result_converts_pydantic_model_to_dict() -> None:
    class Output(BaseModel):
        target_jira_status: str
        findings: list[int]

    state = {
        "messages": [AIMessage(content="done")],
        "structured_response": Output(target_jira_status="In Progress", findings=[1]),
    }
    terminal = make_terminal_result(state)
    assert terminal.structured == {"target_jira_status": "In Progress", "findings": [1]}


# Host-side report / gates writer


def test_write_validation_outputs_writes_report_and_gates(tmp_path: Path) -> None:
    structured = {
        "target_jira_status": "In Progress",
        "findings": [
            {
                "tracking_id": "t1",
                "finding_title": "XSS",
                "finding_description": "desc",
                "affected_files": "a.py",
                "fix_status": "Fixed",
                "raw_score": 0.9,
                "justification": "ok",
            },
        ],
        "synthesized_gates": [
            {"tracking_id": "t1", "gates": [{"gate_name": "root_cause", "status": "pass", "summary": "s"}]},
        ],
    }
    _write_validation_outputs(tmp_path, structured)

    report_path = tmp_path / VALIDATION_REPORT_FILENAME
    gates_path = tmp_path / SYNTHESIZED_GATES_FILENAME
    assert report_path.exists()
    assert gates_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["target_jira_status"] == "In Progress"
    assert report["findings"][0]["tracking_id"] == "t1"

    gates = json.loads(gates_path.read_text(encoding="utf-8"))
    assert gates[0]["tracking_id"] == "t1"


def test_write_validation_outputs_is_noop_for_missing_keys(tmp_path: Path) -> None:
    _write_validation_outputs(tmp_path, {"findings": []})
    assert not (tmp_path / SYNTHESIZED_GATES_FILENAME).exists()


# Env propagation


def test_build_env_propagates_configurable_env_vars(tmp_path: Path, monkeypatch: Any) -> None:
    from vvaharness.validation.constants.artifacts import ANTHROPIC_API_KEY

    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.example.com/v1")
    cfg = SimpleNamespace(ghe=SimpleNamespace(token=None, archived_token=None))
    manifest = SimpleNamespace(case_id="CASE-1", session_id="s1")
    env = _build_env(cfg, manifest, tmp_path, tmp_path / "out")  # type: ignore[arg-type]
    assert env["OPENAI_API_KEY"] == "openai-secret"
    assert env["OPENAI_BASE_URL"] == "https://api.example.com/v1"
    assert ANTHROPIC_API_KEY in env


def test_default_validate_env_vars_is_the_propagated_set() -> None:
    """The default list is the whole contract: Anthropic + OpenAI-compatible endpoints."""
    assert list(_DEFAULT_VALIDATE_ENV_VARS) == [
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "OPENAI_API_KEY", "OPENAI_BASE_URL",
    ]


def test_validation_config_cannot_carry_a_step_validate_override() -> None:
    """Guards the removal of the always-None ``step_validate.env`` override.

    The launcher used to read ``getattr(config, "step_validate", None)`` off this
    pydantic Config. It has no such field and forbids extras, so the branch was
    unreachable and the default list always won. Re-adding an env override here
    would need a real typed field, not a getattr.
    """
    from vvaharness.validation.config import Config

    assert "step_validate" not in Config.model_fields
    assert Config.model_config.get("extra") == "forbid"


# Launcher: terminal result capture reaches host-side writer


def test_run_and_check_writes_outputs_from_terminal_result(tmp_path: Path) -> None:
    """Regression for the bug where terminal.structured never reached the host writer."""
    import anyio

    from vvaharness.validation.session.launcher import _run_and_check

    class _Harness:
        async def run_streaming(self, prompt: str, options: object) -> Any:
            yield HarnessAssistantText(text="thinking")
            yield HarnessResult(
                subtype="success",
                result_text="done",
                structured={
                    "target_jira_status": "In Progress",
                    "findings": [
                        {
                            "tracking_id": "t1",
                            "finding_title": "XSS",
                            "finding_description": "desc",
                            "affected_files": "a.py",
                            "fix_status": "Fixed",
                            "raw_score": 0.9,
                            "justification": "ok",
                        },
                    ],
                    "synthesized_gates": [
                        {"tracking_id": "t1", "gates": [{"gate_name": "root_cause", "status": "pass", "summary": "s"}]},
                    ],
                },
            )

    async def _run() -> int:
        return await _run_and_check(
            harness=_Harness(),  # type: ignore[arg-type]
            prompt="validate",
            options=object(),  # type: ignore[arg-type]
            session_id="s1",
            log_dir=tmp_path / "logs",
            workspace=tmp_path,
            tracking_ids=["t1"],
        )

    exit_code = anyio.run(_run)
    assert exit_code == 0
    assert (tmp_path / VALIDATION_REPORT_FILENAME).exists()
    assert (tmp_path / SYNTHESIZED_GATES_FILENAME).exists()
    # When no native subagent terminal state is provided, only the orchestrator's
    # synthesized gates are written.
    gates = json.loads((tmp_path / SYNTHESIZED_GATES_FILENAME).read_text())
    assert gates[0]["tracking_id"] == "t1"


def test_run_and_check_writes_no_outputs_when_session_fails(tmp_path: Path) -> None:
    """A failed session must leave no verdict artifacts for the DTO write-back to read.

    Persisting them before the exit-code check let a run that printed FAILED and exited 1
    still fold a terminal ``validated`` status into the DTO.
    """
    import anyio

    from vvaharness.validation.session.errors import ValidationSessionError
    from vvaharness.validation.session.launcher import _run_and_check

    class _Harness:
        # _run_and_check calls run_streaming positionally; the args are unused here.
        async def run_streaming(self, _prompt: str, _options: object) -> Any:
            yield HarnessAssistantText(text="thinking")
            # Non-success subtype -> exit code 1, but a partial verdict is still attached.
            yield HarnessResult(
                subtype="error_max_turns",
                result_text="turn limit hit",
                structured={
                    "target_jira_status": "In Progress",
                    "findings": [
                        {
                            "tracking_id": "t1",
                            "finding_title": "XSS",
                            "finding_description": "desc",
                            "affected_files": "a.py",
                            "fix_status": "Fixed",
                            "raw_score": 0.9,
                            "justification": "ok",
                        },
                    ],
                    "synthesized_gates": [
                        {
                            "tracking_id": "t1",
                            "gates": [
                                {"gate_name": "root_cause", "status": "pass", "summary": "s"},
                            ],
                        },
                    ],
                },
            )

    async def _run() -> int:
        return await _run_and_check(
            harness=_Harness(),  # type: ignore[arg-type]
            prompt="validate",
            options=object(),  # type: ignore[arg-type]
            session_id="s1",
            log_dir=tmp_path / "logs",
            workspace=tmp_path,
            tracking_ids=["t1"],
        )

    with pytest.raises(ValidationSessionError):
        anyio.run(_run)
    assert not (tmp_path / VALIDATION_REPORT_FILENAME).exists()
    assert not (tmp_path / SYNTHESIZED_GATES_FILENAME).exists()


# CLI parity: registry accepts deepagents and it is an allowed validator backend


def test_get_harness_supports_deepagents() -> None:
    from vvaharness.backends.harness.registry import get_harness

    harness = get_harness("deepagents")
    assert isinstance(harness, DeepAgentHarness)


# CLI model env application


def test_apply_model_env_accepts_deepagents_backend(monkeypatch: Any, tmp_path: Path) -> None:
    from vvaharness.validation.cli._model import _apply_model_env

    cfg_path = tmp_path / "deepagents.yaml"
    cfg_path.write_text(
        "models:\n  validate:\n    orchestrator: {id: gpt-5.5, via: deepagents}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )

    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    assert overrides["model"] == "gpt-5.5"
    assert overrides["via"] == "deepagents"


def test_apply_model_env_routes_openai_backend_to_deepagents(monkeypatch: Any, tmp_path: Path) -> None:
    """A `via: openai` validate role is routed onto DeepAgents with the OpenAI provider.

    See tests/test_validate_backend_routing.py for the full routing contract; this
    asserts the DeepAgents-facing half — the pair the harness and model builder see.
    """
    from vvaharness.validation.cli._model import _apply_model_env

    cfg_path = tmp_path / "openai.yaml"
    cfg_path.write_text(
        "models:\n  validate:\n    orchestrator: {id: gpt-5.5, via: openai}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )

    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    assert overrides["model"] == "gpt-5.5"
    assert overrides["via"] == "deepagents"
    assert overrides["provider"] == "openai"


def test_apply_model_env_exports_persona_models_without_openai_rejection(tmp_path: Path) -> None:
    from vvaharness.validation.cli._model import _apply_model_env

    cfg_path = tmp_path / "personas.yaml"
    cfg_path.write_text(
        "models:\n"
        "  validate:\n"
        "    orchestrator: {id: gpt-5.5, via: deepagents}\n"
        "    security_architect: {id: gpt-mini, via: openai}\n"
        "    penetration_tester: {id: gpt-mini}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )

    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    # persona models now travel through overrides, not os.environ
    assert overrides["security_architect_model"] == "gpt-mini"
    assert overrides["penetration_tester_model"] == "gpt-mini"


# WS-2: session_id propagation


def test_make_terminal_result_propagates_session_id() -> None:
    state = {
        "messages": [AIMessage(content="done")],
        "structured_response": {"verdict": "pass"},
    }
    terminal = make_terminal_result(state, session_id="abc123")
    assert terminal.session_id == "abc123"


def test_make_terminal_result_defaults_session_id_to_none() -> None:
    state = {"messages": [AIMessage(content="done")]}
    terminal = make_terminal_result(state)
    assert terminal.session_id is None


def test_run_and_check_receives_harness_session_init(tmp_path: Path) -> None:
    """HarnessSessionInit emitted by a backend is collected without error."""
    import anyio

    from vvaharness.validation.session.launcher import _run_and_check

    class _Harness:
        async def run_streaming(self, prompt: str, options: object) -> Any:
            yield HarnessSessionInit(session_id="sid-xyz")
            yield HarnessResult(
                subtype="success",
                session_id="sid-xyz",
                result_text="done",
                structured={"target_jira_status": "Done", "findings": [], "synthesized_gates": []},
            )

    async def _run() -> int:
        return await _run_and_check(
            harness=_Harness(),  # type: ignore[arg-type]
            prompt="validate",
            options=object(),  # type: ignore[arg-type]
            session_id="sid-xyz",
            log_dir=tmp_path / "logs",
            workspace=tmp_path,
            tracking_ids=[],
        )

    exit_code = anyio.run(_run)
    assert exit_code == 0


# WS-3: error wrapping


def test_translate_stream_events_error_tool_message(tmp_path: Path) -> None:
    event = {
        "tools": {
            "messages": [ToolMessage(content="oops", tool_call_id="tc1", status="error")],
        },
    }

    async def _collect() -> list[Any]:
        return [m async for m in translate_stream_events(event, set())]

    messages = _run_sync(_collect())
    assert len(messages) == 1
    assert isinstance(messages[0], HarnessToolResult)
    assert messages[0].is_error is True


def test_translate_stream_events_deduplicates_tool_call_ids() -> None:
    seen: set[str] = {"tc1"}  # pre-seed tc1 as already seen
    event = {
        "model": {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{"id": "tc1", "name": "Read", "args": {}}],
                ),
            ],
        },
    }

    async def _collect() -> list[Any]:
        return [m async for m in translate_stream_events(event, seen)]

    messages = _run_sync(_collect())
    tool_uses = [m for m in messages if isinstance(m, HarnessToolUse)]
    assert len(tool_uses) == 0


def test_translate_stream_events_list_content_ai_message() -> None:
    event = {
        "model": {
            "messages": [
                AIMessage(content=[{"type": "text", "text": "from list"}]),
            ],
        },
    }

    async def _collect() -> list[Any]:
        return [m async for m in translate_stream_events(event, set())]

    messages = _run_sync(_collect())
    texts = [m for m in messages if isinstance(m, HarnessAssistantText)]
    assert len(texts) == 1
    assert texts[0].text == "from list"


# WS-6: extract_subagent_reports

def _make_persona_json(persona: str, tracking_id: str, gate_status: str = "pass") -> str:
    return json.dumps({
        "persona": persona,
        "tracking_id": tracking_id,
        "gates": [{"gate_name": "root_cause", "status": gate_status, "summary": "ok"}],
    })


def test_extract_subagent_reports_happy_path() -> None:
    state = {
        "messages": [
            ToolMessage(content=_make_persona_json("security-architect", "t1"), tool_call_id="tc1"),
        ],
    }
    reports = extract_subagent_reports(state)
    assert len(reports) == 1
    assert reports[0].persona == "security-architect"
    assert reports[0].tracking_id == "t1"


def test_extract_subagent_reports_drops_malformed_json() -> None:
    state = {
        "messages": [
            ToolMessage(content="not-json", tool_call_id="tc1"),
            ToolMessage(content=_make_persona_json("pen-tester", "t1"), tool_call_id="tc2"),
        ],
    }
    reports = extract_subagent_reports(state)
    assert len(reports) == 1
    assert reports[0].persona == "pen-tester"


def test_extract_subagent_reports_drops_missing_keys() -> None:
    bad = json.dumps({"persona": "security-architect"})  # missing "gates"
    state = {
        "messages": [
            ToolMessage(content=bad, tool_call_id="tc1"),
        ],
    }
    reports = extract_subagent_reports(state)
    assert reports == []


def test_extract_subagent_reports_deduplicates_by_persona_and_tracking_id() -> None:
    msg = _make_persona_json("security-architect", "t1")
    state = {
        "messages": [
            ToolMessage(content=msg, tool_call_id="tc1"),
            ToolMessage(content=msg, tool_call_id="tc2"),  # duplicate
        ],
    }
    reports = extract_subagent_reports(state)
    assert len(reports) == 1


def test_extract_subagent_reports_list_content_uses_first_element() -> None:
    msg = _make_persona_json("security-architect", "t1")
    state = {
        "messages": [
            ToolMessage(content=[msg, "ignored"], tool_call_id="tc1"),
        ],
    }
    reports = extract_subagent_reports(state)
    assert len(reports) == 1


def test_extract_subagent_reports_drops_pydantic_validation_error() -> None:
    # A gate entry with no ``gate_name`` cannot be attributed to any gate, so the whole
    # persona report is unusable and pydantic rejects it. (An out-of-vocabulary *status*
    # no longer reaches this path -- GateStatus folds it to INVALID; see the test below.)
    bad = json.dumps({
        "persona": "security-architect",
        "tracking_id": "t1",
        "gates": [{"status": "pass", "summary": "x"}],
    })
    state = {
        "messages": [ToolMessage(content=bad, tool_call_id="tc1")],
    }
    reports = extract_subagent_reports(state)
    assert reports == []


def test_extract_subagent_reports_folds_unknown_status_to_invalid() -> None:
    """The status vocabulary fails closed instead of discarding the persona's whole report.

    INVALID scores 0.0 and stays in the scoring denominator, so keeping the report is
    strictly more conservative than dropping it (a dropped gate would be weight-neutral).
    """
    bad_status = json.dumps({
        "persona": "security-architect",
        "tracking_id": "t1",
        "gates": [{"gate_name": "root_cause", "status": "INVALID_STATUS", "summary": "x"}],
    })
    state = {
        "messages": [ToolMessage(content=bad_status, tool_call_id="tc1")],
    }
    reports = extract_subagent_reports(state)
    assert len(reports) == 1
    assert reports[0].gates[0].status is GateStatus.INVALID


# WS-6: synthesize_gates_for_finding

def _make_report(persona: str, tracking_id: str, gate_name: str, status: str) -> PersonaReport:
    return PersonaReport(
        persona=persona,
        tracking_id=tracking_id,
        gates=[PersonaGateEntry(gate_name=gate_name, status=status, summary=f"{persona} says {status}")],
    )


def test_synthesize_gates_majority_agreement_gives_high_confidence() -> None:
    reports = [
        _make_report("security-architect", "t1", "root_cause", "pass"),
        _make_report("pen-tester", "t1", "root_cause", "pass"),
        _make_report("cross-repo-analyzer", "t1", "root_cause", "fail"),
    ]
    gates = synthesize_gates_for_finding(reports, "t1")
    assert len(gates) == 1
    assert gates[0].status == "pass"
    assert gates[0].confidence == "HIGH"


def test_synthesize_gates_single_voter_gives_flagged_confidence() -> None:
    reports = [_make_report("security-architect", "t1", "root_cause", "pass")]
    gates = synthesize_gates_for_finding(reports, "t1")
    assert len(gates) == 1
    assert gates[0].confidence == "FLAGGED"


def test_synthesize_gates_disagreement_picks_lowest_status() -> None:
    reports = [
        _make_report("security-architect", "t1", "root_cause", "pass"),
        _make_report("pen-tester", "t1", "root_cause", "fail"),
    ]
    gates = synthesize_gates_for_finding(reports, "t1")
    assert gates[0].status == "fail"
    assert gates[0].confidence == "FLAGGED"


def test_synthesize_gates_even_split_is_conservative_and_flagged() -> None:
    # 2 pass / 2 fail resolves to the conservative status (fail) at FLAGGED --
    # never an insertion-order winner at HIGH confidence.
    reports = [
        _make_report("a", "t1", "root_cause", "pass"),
        _make_report("b", "t1", "root_cause", "pass"),
        _make_report("c", "t1", "root_cause", "fail"),
        _make_report("d", "t1", "root_cause", "fail"),
    ]
    gates = synthesize_gates_for_finding(reports, "t1")
    assert gates[0].status == "fail"
    assert gates[0].confidence == "FLAGGED"


def test_score_fix_tolerates_unknown_gate_name() -> None:
    """An unrecognised gate name must neither raise nor be silently swallowed.

    Gate names are an OPEN vocabulary, so the name cannot be rejected at parse time; the
    engine's shape check refuses the criteria set instead (INCONCLUSIVE, unscored). The
    unknown gate is still carried on the result -- dropping it would hide the evidence for
    that refusal, and would let a hallucinated gate look like a gate that was never emitted.
    """
    from vvaharness.validation.scoring import score_fix

    gates = [
        {"gate_name": "root_cause", "status": "pass", "summary": "s"},
        {"gate_name": "instance_coverage", "status": "pass", "summary": "s"},
        {"gate_name": "no_new_vulnerabilities", "status": "pass", "summary": "s"},
        {"gate_name": "security_best_practices", "status": "pass", "summary": "s"},
        {"gate_name": "hallucinated_gate", "status": "pass", "summary": "s"},
    ]
    result = score_fix(gates)  # must not raise on the unknown name
    assert {g.name for g in result.gates} == {
        "root_cause",
        "instance_coverage",
        "no_new_vulnerabilities",
        "security_best_practices",
        "hallucinated_gate",
    }
    # Four perfect passes must not score Fixed when a fifth, unknown gate came with them.
    assert result.decision is Decision.INCONCLUSIVE
    assert result.raw_score == 0.0


def test_synthesize_gates_merges_evidence_from_multiple_personas() -> None:
    r1 = PersonaReport(
        persona="security-architect",
        tracking_id="t1",
        gates=[PersonaGateEntry(
            gate_name="root_cause",
            status="pass",
            summary="ok",
            evidence=[{"file": "a.py", "line": 1, "snippet": "x"}],
        )],
    )
    r2 = PersonaReport(
        persona="pen-tester",
        tracking_id="t1",
        gates=[PersonaGateEntry(
            gate_name="root_cause",
            status="pass",
            summary="good",
            evidence=[{"file": "b.py", "line": 2, "snippet": "y"}],
        )],
    )
    gates = synthesize_gates_for_finding([r1, r2], "t1")
    evidence_files = {e.file for e in gates[0].evidence}
    assert evidence_files == {"a.py", "b.py"}


def test_synthesize_gates_empty_reports_returns_empty() -> None:
    assert synthesize_gates_for_finding([], "t1") == []


def test_synthesize_gates_ignores_non_matching_tracking_id() -> None:
    reports = [_make_report("security-architect", "t2", "root_cause", "pass")]
    gates = synthesize_gates_for_finding(reports, "t1")
    assert gates == []


# WS-6: _write_host_synthesized_gates


def test_write_host_synthesized_gates_non_dict_state_is_noop(
    tmp_path: Path, caplog: Any
) -> None:
    import logging
    with caplog.at_level(logging.WARNING):
        _write_host_synthesized_gates(tmp_path, "not-a-dict", ["t1"])
    assert not (tmp_path / "synthesized_gates.json").exists()


def test_write_host_synthesized_gates_empty_reports_is_noop(tmp_path: Path) -> None:
    state = {"messages": []}  # no ToolMessages → extract returns []
    _write_host_synthesized_gates(tmp_path, state, ["t1"])
    assert not (tmp_path / "synthesized_gates.json").exists()


def test_write_host_synthesized_gates_multiple_tracking_ids(tmp_path: Path) -> None:
    state = {
        "messages": [
            ToolMessage(content=_make_persona_json("security-architect", "t1"), tool_call_id="tc1"),
            ToolMessage(content=_make_persona_json("security-architect", "t2"), tool_call_id="tc2"),
        ],
    }
    _write_host_synthesized_gates(tmp_path, state, ["t1", "t2"])
    gates_path = tmp_path / "synthesized_gates.json"
    assert gates_path.exists()
    gates = json.loads(gates_path.read_text())
    tracking_ids = {g["tracking_id"] for g in gates}
    assert tracking_ids == {"t1", "t2"}


def test_write_host_synthesized_gates_writes_synthesized_gates_json(tmp_path: Path) -> None:
    state = {
        "messages": [
            ToolMessage(
                content=_make_persona_json("security-architect", "t1", "pass"),
                tool_call_id="tc1",
            ),
            ToolMessage(
                content=_make_persona_json("pen-tester", "t1", "pass"),
                tool_call_id="tc2",
            ),
        ],
    }
    _write_host_synthesized_gates(tmp_path, state, ["t1"])
    gates_path = tmp_path / "synthesized_gates.json"
    assert gates_path.exists()
    gates = json.loads(gates_path.read_text())
    assert gates[0]["tracking_id"] == "t1"
    assert gates[0]["gates"][0]["confidence"] == "HIGH"


# WS-7: diff_facts

_SIMPLE_DIFF = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,3 +10,4 @@
 context line
+new_line_1
+new_line_2
 another context
"""


def test_parse_diff_patch_returns_empty_when_no_file(tmp_path: Path) -> None:
    assert parse_diff_patch(tmp_path) == []


def test_parse_diff_patch_parses_added_ranges(tmp_path: Path) -> None:
    (tmp_path / "diff.patch").write_text(_SIMPLE_DIFF, encoding="utf-8")
    changes = parse_diff_patch(tmp_path)
    assert any(c.path == "src/auth.py" and c.added_ranges for c in changes)


def test_diff_touched_returns_true_for_changed_file(tmp_path: Path) -> None:
    (tmp_path / "diff.patch").write_text(_SIMPLE_DIFF, encoding="utf-8")
    result = diff_touched(tmp_path, "src/auth.py")
    assert result["touched"] is True


def test_diff_touched_returns_false_for_unchanged_file(tmp_path: Path) -> None:
    (tmp_path / "diff.patch").write_text(_SIMPLE_DIFF, encoding="utf-8")
    result = diff_touched(tmp_path, "src/unrelated.py")
    assert result["touched"] is False
    assert result["added_ranges"] == []


def test_build_diff_impact_map_detects_trust_boundary(tmp_path: Path) -> None:
    (tmp_path / "diff.patch").write_text(_SIMPLE_DIFF, encoding="utf-8")
    impact = build_diff_impact_map(tmp_path)
    assert impact.trust_boundary_touched is True  # "auth" in path


def test_build_diff_impact_map_no_trust_boundary(tmp_path: Path) -> None:
    diff = "--- a/src/utils.py\n+++ b/src/utils.py\n@@ -1,1 +1,2 @@\n context\n+added\n"
    (tmp_path / "diff.patch").write_text(diff, encoding="utf-8")
    impact = build_diff_impact_map(tmp_path)
    assert impact.trust_boundary_touched is False
    assert "src/utils.py" in impact.files_changed
