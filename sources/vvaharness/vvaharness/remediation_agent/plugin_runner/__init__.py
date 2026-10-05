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

"""remediation_agent.plugin_runner — run the remediation method for one finding."""
from __future__ import annotations

import asyncio
import os
import threading
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, TypeVar

from vvaharness.backends.harness import (
    HarnessAssistantText,
    HarnessResult,
    HarnessToolResult,
    HarnessToolUse,
    StreamingOptions,
    SubagentDefinition,
    ToolPolicy,
    get_harness,
)
from vvaharness.backends.harness.deepagents.limits import RECURSION_HEADROOM
from vvaharness.backends.harness.provider_routing import credential_env_overrides
from vvaharness.backends.llm.cli import stream_trace
from vvaharness.backends.llm.deepagents import markers_on
from vvaharness.backends.llm.registry import agentic, use_responses_api_of
from vvaharness.backends.llm.registry import resolve as resolve_model
from vvaharness.remediation_agent.models import FixerResult, RemediationVerdict
from vvaharness.remediation_agent.plugin_runner.handoff import FixerDispatchGuard
from vvaharness.remediation_agent.plugin_runner.helpers import (  # noqa: F401
    _build_user,
    _coerce_verdict,
    _tools,
)
from vvaharness.remediation_agent.plugin_runner.run import (  # noqa: F401
    ENGINE_ID,
    Amended,
    EngineRequest,
    GuardedCall,
    apply_plugin,
    call_with_guards,
    checkpoint_record,
    engine_model,
    harness_amend,
)
from vvaharness.remediation_agent.plugin_runner.trace import dump as _dump  # noqa: F401
from vvaharness.remediation_agent.plugin_runner.trace import dump_policy as _dump_policy
from vvaharness.remediation_agent.prompts import (
    FIXER_SYSTEM,
    ORCHESTRATOR_SYSTEM,
    SYSTEM,
)
from vvaharness.remediation_agent.target import RemediationTarget
from vvaharness.util.json_extract import extract_json
from vvaharness.util.tokens import TOKENS

__all__ = [
    "ENGINE_ID", "Amended", "EngineRequest", "GuardedCall",
    "apply_plugin", "call_with_guards", "checkpoint_record", "engine_model",
    "harness_amend",
]

_T = TypeVar("_T")

def _run_sync(awaitable: Coroutine[Any, Any, _T]) -> _T:
    """Run a coroutine from synchronous code, including inside a live loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)

    result: list[_T] = []
    error: list[BaseException] = []

    def worker() -> None:
        try:
            result.append(asyncio.run(awaitable))
        except BaseException as exc:  # propagate the original harness failure
            error.append(exc)

    thread = threading.Thread(target=worker, name="vvaharness-remediation", daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]


def _debug_log(event: str, detail: str = "") -> None:
    """Append a debug line to VVAHARNESS_DEBUG_LOG (no-op when unset)."""
    path = os.environ.get("VVAHARNESS_DEBUG_LOG")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{event}: {detail}\n")


def _terminal_stats(terminal: HarnessResult) -> tuple[int, int, str]:
    """Return (message count, tool-call count, trailing-message shape) for diagnostics."""
    messages = (getattr(terminal, "state", None) or {}).get("messages", [])
    tool_calls = sum(len(getattr(m, "tool_calls", None) or []) for m in messages)
    last = messages[-1] if messages else None
    pending = bool(getattr(last, "tool_calls", None)) and type(last).__name__ == "AIMessage"
    shape = "pending_tool_call(loop_truncated)" if pending else type(last).__name__ if last else "empty"
    return len(messages), tool_calls, shape


def _debug_terminal(terminal: HarnessResult) -> None:
    """Dump why a terminal lacks structured output (tool-call trail + state)."""
    if not os.environ.get("VVAHARNESS_DEBUG_LOG"):
        return
    n_msgs, n_calls, shape = _terminal_stats(terminal)
    _debug_log("TERMINAL.structured_is_none", str(terminal.structured is None))
    _debug_log("TERMINAL.structured", repr(terminal.structured)[:600])
    _debug_log("TERMINAL.result_text", repr(terminal.result_text)[:600])
    _debug_log("TERMINAL.stats", f"messages={n_msgs} tool_calls={n_calls} last={shape}")
    for msg in (getattr(terminal, "state", None) or {}).get("messages", [])[-8:]:
        tool_calls = getattr(msg, "tool_calls", None) or []
        _debug_log(
            f"STATE_MSG.{type(msg).__name__}",
            f"tool_calls={[c.get('name') for c in tool_calls]} "
            f"content={str(getattr(msg, 'content', ''))[:200]}",
        )


def _report_recursion_limit(terminal: HarnessResult, options: StreamingOptions) -> None:
    """Surface a swallowed recursion-limit truncation with actionable advice."""
    import sys
    n_msgs, n_calls, shape = _terminal_stats(terminal)
    limit = (options.max_turns or 50) + RECURSION_HEADROOM
    msg = (
        f"  [deepagents] {options.model} HIT THE LANGGRAPH RECURSION LIMIT "
        f"(recursion_limit={limit} = step_remediate.max_turns({options.max_turns}) + "
        f"{RECURSION_HEADROOM}). The tool loop was truncated mid-flight after {n_calls} tool "
        f"call(s) / {n_msgs} message(s) (last={shape}), so the agent never reached a final turn "
        f"and produced NO structured verdict. ACTION: raise step_remediate.max_turns in the "
        f"profile (e.g. 40 -> 100)."
    )
    print(msg, file=sys.stderr)
    _debug_log("RECURSION_LIMIT_HIT", f"limit={limit} tool_calls={n_calls} messages={n_msgs} last={shape}")


def _verdict_extraction_prompt() -> str:
    import json
    schema = json.dumps(RemediationVerdict.model_json_schema(), separators=(",", ":"))
    return (
        "You completed remediation work above but did not emit a structured verdict. "
        "Based solely on the work you did, return ONLY a JSON object — no prose, no "
        f"markdown fences — matching exactly this JSON Schema:\n{schema}"
    )


def _extract_verdict_from_history(
    terminal: HarnessResult, options: StreamingOptions
) -> dict | None:
    """Ask the same model to emit its verdict as raw JSON from its own work log."""
    from langchain_core.messages import HumanMessage

    from vvaharness.backends.harness.deepagents.options import build_model_cached
    messages = (getattr(terminal, "state", None) or {}).get("messages", [])
    if not messages:
        return None
    model = build_model_cached(
        options.model,
        options.env,
        options.model_provider,
        use_responses_api=options.use_responses_api,
    )
    try:
        response = model.invoke([*messages, HumanMessage(content=_verdict_extraction_prompt())])
        data = extract_json(getattr(response, "content", "") or "")
        if isinstance(data, dict):
            return data
        _debug_log("EXTRACTION_NOT_A_DICT", repr(data)[:200])
        return None
    except Exception as exc:
        _debug_log("EXTRACTION_FAILED", f"{type(exc).__name__}: {exc}")
        return None


def _attempt_extraction(terminal: HarnessResult, options: StreamingOptions) -> Any:
    """Try post-hoc verdict extraction; print diagnostics; return result or None."""
    n_tool_calls = sum(
        len(getattr(m, "tool_calls", None) or [])
        for m in (getattr(terminal, "state", None) or {}).get("messages", [])
    )
    import sys
    print(
        f"  [deepagents] {options.model} made {n_tool_calls} tool call(s) but did not "
        f"emit a structured verdict — attempting post-hoc extraction from message history",
        file=sys.stderr,
    )
    extracted = _extract_verdict_from_history(terminal, options)
    if extracted is not None:
        _debug_log("EXTRACTION_RESULT", repr(extracted)[:400])
        return extracted
    print(
        f"  [deepagents] post-hoc extraction failed for {options.model} — "
        f"recording as Needs Review. Check endpoint tool-call-parser config.",
        file=sys.stderr,
    )
    return terminal.result_text or ""


async def _consume_deepagents(prompt: str, options: StreamingOptions,
                              *, verbose: bool) -> Any:
    """Consume one DeepAgents stream and return its structured terminal value."""
    from vvaharness.backends.harness import HarnessProcessError
    terminal: HarnessResult | None = None
    recursion_error: BaseException | None = None
    try:
        async for message in get_harness("deepagents").run_streaming(prompt, options):
            if isinstance(message, HarnessResult):
                terminal = message
            elif isinstance(message, HarnessAssistantText):
                _debug_log("ASSISTANT_TEXT", message.text[:200])
                if verbose:
                    _dump("ASSISTANT", message.text)
            elif isinstance(message, HarnessToolUse):
                _debug_log("TOOL_USE", f"{message.name} {str(message.input)[:200]}")
                if verbose:
                    _dump(f"TOOL → {message.name}", str(message.input))
            elif verbose and isinstance(message, HarnessToolResult):
                _dump("TOOL RESULT", str(message.content))
    except HarnessProcessError as exc:
        if "GraphRecursionError" not in str(exc) and terminal is None:
            raise
        recursion_error = exc
    if terminal is None:
        raise RuntimeError("DeepAgents remediation ended without a terminal result")
    _debug_terminal(terminal)
    if terminal.is_error and recursion_error is None:
        raise RuntimeError(
            f"DeepAgents remediation failed: {terminal.subtype or 'unknown error'}")
    if terminal.structured is not None:
        return terminal.structured
    if recursion_error is not None:
        _report_recursion_limit(terminal, options)
    result = _attempt_extraction(terminal, options)
    if result is not None or recursion_error is None:
        return result
    raise recursion_error  # extraction failed and it was a recursion crash


def _virtualize_deepagents_prompt(user: str) -> str:
    """Present the repo using DeepAgents' virtual filesystem namespace so tools don't look for the host path inside the virtual root."""
    lines = user.splitlines()
    if lines and lines[0].startswith("REPOSITORY ROOT:"):
        lines[0] = "REPOSITORY ROOT: / (DeepAgents virtual workspace root)"
    return "\n".join(lines)


def _invoke_deepagents(user: str, *, model_id: str, repo: Path, mode: str,
                       sr: Any, cfg: Any, verbose: bool,
                       provider: str | None = None,
                       use_responses_api: bool | None = None,
                       primary_file: str = "") -> Any:
    tools = tuple(t for t in _tools(cfg) if t != "Bash")
    fix_mode = mode == "fix"
    env = {
        **os.environ,
        **credential_env_overrides(
            model_id, provider,
            sdk_cfg=getattr(cfg, "sdk", None),
            openai_cfg=getattr(cfg, "openai", None),
        ),
    }
    # In fix mode, split into orchestrator (reads redacted context, plans the fix)
    # and a fixer subagent (reads unredacted, applies the minimal edit). "Edit" in
    # the fixer's tool list signals get_subagent_specs to skip RedactToolResults on
    # it, while the orchestrator parent gets middleware via bool(subagent_specs).
    agents: dict[str, SubagentDefinition] = {}
    if fix_mode:
        fixer_tools = tuple(dict.fromkeys((*tools, "Edit")))
        agents = {
            "fixer": SubagentDefinition(
                name="fixer",
                description="Applies the security fix to the target file(s).",
                prompt=FIXER_SYSTEM,
                tools=fixer_tools,
                response_model=FixerResult,
            ),
        }
    options = StreamingOptions(
        model=model_id,
        model_provider=provider,
        use_responses_api=use_responses_api,
        cwd=repo,
        env=env,
        max_turns=getattr(sr, "max_turns", 40),
        max_budget_usd=getattr(sr, "max_budget_usd", 10.0),
        system_prompt=ORCHESTRATOR_SYSTEM if fix_mode else SYSTEM,
        tool_policy=ToolPolicy(
            allowed_tools=tools,
            disallowed_tools=("Bash",),
        ),
        response_model=RemediationVerdict,
        allow_writes=fix_mode,
        writable_paths=(str(repo.resolve()),) if fix_mode else (),
        graph_name="remediation",
        agents=agents,
        parent_middleware=(FixerDispatchGuard(
            finding_context=user, primary_file=primary_file),) if fix_mode else (),
        cache_markers=markers_on(getattr(cfg, "sdk", None)),
    )
    return _run_sync(_consume_deepagents(user, options, verbose=verbose))


def _invoke(target: RemediationTarget, cfg, repo: Path, mode: str,
            verbose: bool = False, *, pre=None, ctx=None) -> Any:
    """Single model call through the configured backend, isolated so tests can monkeypatch one seam."""
    sr = getattr(cfg, "step_remediate", None)
    user = _build_user(target, repo, mode, pre=pre, ctx=ctx)
    model_id, via, _ = resolve_model(cfg.models.remediate)
    provider = getattr(cfg.models.remediate, "provider", None)
    if via == "deepagents":
        user = _virtualize_deepagents_prompt(user)
    if verbose:
        _dump(f"PROMPT → finding {target.index} ({mode})", user)
    with TOKENS.phase("remediation-agent-remediate"):
        if via == "deepagents":
            raw = _invoke_deepagents(
                user, model_id=model_id, repo=repo, mode=mode,
                sr=sr, cfg=cfg, verbose=verbose, provider=provider,
                use_responses_api=use_responses_api_of(cfg.models.remediate),
                primary_file=target.file)
        else:
            raw = agentic(
                user,
                model=cfg.models.remediate,
                system_prompt=SYSTEM,
                allowed_tools=_tools(cfg),
                cwd=str(repo),
                max_budget_usd=getattr(sr, "max_budget_usd", 10.0),
                max_turns=getattr(sr, "max_turns", 40),
                tag=f"Remediation Agent remediate #{target.index}",
                stream_cb=(stream_trace if verbose else None),
            )
    if verbose:
        body = raw.model_dump_json() if isinstance(raw, RemediationVerdict) else str(raw)
        _dump(f"FINAL VERDICT ← finding {target.index}", body)
    return raw
