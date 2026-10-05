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

"""Execute a single fix-validation session via the harness."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

from vvaharness.backends.harness import (
    Harness,
    HarnessCLINotFoundError,
    HarnessError,
    HarnessMessage,
    HarnessResult,
    StreamingOptions,
    get_harness,
)
from vvaharness.backends.harness.capabilities import capabilities_for
from vvaharness.report.redact import redact_tree
from vvaharness.validation.config import Config
from vvaharness.validation.constants.artifacts import (
    ANTHROPIC_API_KEY,
    ANTHROPIC_AUTH_TOKEN,
    LOGGING_DIRNAME,
    MANIFEST_FILENAME,
    ORCHESTRATOR_LOG_DIRNAME,
    SESSION_ENV_FLAG,
    SESSION_ENV_GH_ARCHIVED_TOKEN,
    SESSION_ENV_GH_TOKEN,
    SESSION_ENV_JIRA_KEY,
    SESSION_ENV_LOG_DIR,
    SESSION_ENV_MANIFEST,
    SESSION_ENV_OUTPUT_DIR,
    SESSION_ENV_PROJECT_DIR,
    SESSION_ENV_SESSION_ID,
    SESSION_ENV_TARGET_DIR,
    SYNTHESIZED_GATES_FILENAME,
    VALIDATION_REPORT_FILENAME,
)
from vvaharness.validation.constants.paths import FIX_VALIDATION
from vvaharness.validation.io.message_logger import stream_and_log
from vvaharness.validation.io.persona_report_stash import extract_subagent_reports
from vvaharness.validation.models import HarnessTerminalState, Manifest
from vvaharness.validation.session.config_inject import inject_claude_config
from vvaharness.validation.session.errors import ValidationSessionError
from vvaharness.validation.session.launch_prompt import build_launch_prompt
from vvaharness.validation.session.rules import (
    orchestrator_rules_text,
    persona_rules_text,
)
from vvaharness.validation.session.setup import (
    DEFAULT_FACT_TOOLS,
    VALIDATION_GRAPH_NAME,
    VALIDATION_POLICY,
    ValidationOutput,
    build_validation_tools,
    validation_skill_root,
    validation_write_gate,
)
from vvaharness.validation.subagents import load_agents
from vvaharness.validation.synthesis._consensus import synthesize_gates_for_finding

log = logging.getLogger(__name__)

# Environment variables propagated into validation sessions when the profile does not override them.
_DEFAULT_VALIDATE_ENV_VARS: tuple[str, ...] = (
    ANTHROPIC_API_KEY,
    ANTHROPIC_AUTH_TOKEN,
    "ANTHROPIC_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
)


def _build_env(
    config: Config,
    manifest: Manifest,
    workspace: Path,
    output_dir: Path,
) -> dict[str, str]:
    """Build the subprocess environment dict for the validation session."""
    # Propagate the API auth token so auth works inside Claude Code and standalone.
    effective_api_key = (
        os.environ.get(ANTHROPIC_AUTH_TOKEN) or os.environ.get(ANTHROPIC_API_KEY, "")
    )
    env: dict[str, str] = {
        ANTHROPIC_API_KEY: effective_api_key,
        SESSION_ENV_FLAG: "true",
        SESSION_ENV_TARGET_DIR: str(workspace),
        SESSION_ENV_OUTPUT_DIR: str(output_dir),
        SESSION_ENV_MANIFEST: str(workspace / MANIFEST_FILENAME),
        SESSION_ENV_LOG_DIR: str(workspace / LOGGING_DIRNAME),
        SESSION_ENV_JIRA_KEY: manifest.case_id,
        SESSION_ENV_SESSION_ID: manifest.session_id,
        SESSION_ENV_PROJECT_DIR: str(workspace),
    }
    for name in _DEFAULT_VALIDATE_ENV_VARS:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    if config.ghe.token:
        env[SESSION_ENV_GH_TOKEN] = config.ghe.token
    if config.ghe.archived_token:
        env[SESSION_ENV_GH_ARCHIVED_TOKEN] = config.ghe.archived_token
    return env


def _persona_overrides(config: Config) -> dict[str, str]:
    """Map persona name → configured model id (omitting personas left to inherit validate)."""
    return {
        name: model
        for name, model in (
            ("security-architect", config.agent.security_architect_model),
            ("penetration-tester", config.agent.penetration_tester_model),
            ("cross-repo-analyzer", config.agent.cross_repo_analyzer_model),
        )
        if model
    }


def _resolve_binary(binary: str) -> str:
    """Resolve agent binary to an absolute, pinned path; else SDK resolves a bare name via PATH."""
    if Path(binary).is_file():
        return str(binary)
    found = shutil.which(binary)
    if found:
        return found
    log.warning("claude binary %r not found on PATH; SDK will resolve it", binary)
    return binary


def _write_workspace_json(workspace: Path, filename: str, payload: Any) -> None:
    """Write *payload* to *workspace/filename* atomically, redacted; warn, not raise, on failure."""
    dest = workspace / filename
    tmp = dest.with_suffix(f"{dest.suffix}.tmp")
    try:
        text = json.dumps(redact_tree(payload), indent=2) + "\n"
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(dest)
    except (OSError, TypeError, ValueError):
        log.exception("cannot write %s", dest)
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)


def _write_validation_outputs(workspace: Path, structured: Any) -> None:
    """Persist structured validation output to the workspace JSON artifacts."""
    if not isinstance(structured, dict):
        log.warning("structured validation output is not a dict; skipping host write")
        return
    findings = structured.get("findings")
    gates = structured.get("synthesized_gates")
    target_status = structured.get("target_jira_status")
    if findings is not None:
        _write_workspace_json(
            workspace,
            VALIDATION_REPORT_FILENAME,
            {"target_jira_status": target_status, "findings": findings},
        )
    if gates is not None:
        _write_workspace_json(workspace, SYNTHESIZED_GATES_FILENAME, gates)


def _write_host_synthesized_gates(
    workspace: Path,
    terminal_state: HarnessTerminalState,
    tracking_ids: list[str],
) -> None:
    """Synthesize persona reports, write synthesized_gates.json; failure leaves prior output."""
    if not isinstance(terminal_state, dict):
        log.warning("terminal harness state is not a dict; skipping host synthesis")
        return
    reports = extract_subagent_reports(terminal_state)
    if not reports:
        log.warning("no valid persona reports extracted; skipping host synthesis")
        return

    synthesized: list[dict] = []
    for tracking_id in tracking_ids:
        gates = synthesize_gates_for_finding(reports, tracking_id)
        if gates:
            synthesized.append({
                "tracking_id": tracking_id,
                "gates": [gate.model_dump() for gate in gates],
            })

    if synthesized:
        _write_workspace_json(workspace, SYNTHESIZED_GATES_FILENAME, synthesized)


def build_validation_options(
    config: Config,
    manifest: Manifest,
    workspace: Path,
    output_dir: Path,
    system_prompt: str | None,
) -> StreamingOptions:
    """Compose a StreamingOptions instance for the validation session."""
    path_cfg = FIX_VALIDATION
    injects_claude = _injects_claude_config(config)
    return StreamingOptions(
        model=config.agent.model,
        model_provider=config.agent.provider,
        use_responses_api=config.agent.use_responses_api,
        cwd=workspace,
        env=_build_env(config, manifest, workspace, output_dir),
        effort=config.agent.effort,
        max_turns=config.agent.max_turns,
        max_budget_usd=config.agent.max_budget_usd,
        system_prompt=system_prompt,
        setting_sources=("project",),
        cli_path=_resolve_binary(config.agent.binary),
        tool_policy=VALIDATION_POLICY,
        permissions=validation_write_gate(workspace),
        response_model=ValidationOutput,
        tool_builder=build_validation_tools,
        fact_tools=DEFAULT_FACT_TOOLS,
        skill_root=validation_skill_root(workspace) if injects_claude else None,
        graph_name=VALIDATION_GRAPH_NAME,
        agents=load_agents(
            path_cfg.agent_names,
            model_overrides=_persona_overrides(config),
            tools_override=config.agent.validate_tools,
            prompt_suffix=None if injects_claude else persona_rules_text(),
        ),
        cache_markers=config.agent.cache_markers,
    )


def _injects_claude_config(config: Config) -> bool:
    """Whether this backend receives the injected ``.claude/`` directory."""
    return capabilities_for(config.agent.via).reads_injected_claude_config


def _rules_section(config: Config) -> str:
    """Build the prompt's Rules section, inlining rules for backends skipping ``.claude/``."""
    if _injects_claude_config(config):
        return (
            "## Rules\n\n"
            "Follow the rules auto-loaded from `.claude/rules/`. They define persona\n"
            "isolation, anti-manipulation safeguards, evidence requirements, gate\n"
            "definitions, weights, and decision thresholds."
        )
    return (
        "## Rules\n\n"
        "These are the validation rules referred to above. Follow them as written.\n\n"
        f"{orchestrator_rules_text()}"
    )


def _synthesizes_gates_on_host(config: Config) -> bool:
    """Whether the host synthesizes gates from this backend's subagent reports."""
    return capabilities_for(config.agent.via).returns_schema_validated_reports


def _synthesis_section(config: Config) -> str:
    """Build the prompt's gate-synthesis section, stating whether host or agent owns synthesis."""
    if _synthesizes_gates_on_host(config):
        return (
            "## Synthesis boundary\n\n"
            "Do NOT synthesize across personas, compute scores, or fill "
            "`synthesized_gates` —\nthe host performs deterministic synthesis and "
            "scoring from the structured persona\nreports after you finish. Always "
            "emit `synthesized_gates` as an empty list `[]`."
        )
    return (
        "## Synthesis boundary\n\n"
        "Fill `synthesized_gates` with one entry per finding, each carrying all four\n"
        "gates, applying the synthesis rules from the validation rules above: where two\n"
        "or more personas agree on a gate use that status; where only one evaluated it\n"
        "use that status; where they disagree take the LOWEST (most conservative) status\n"
        "and show both perspectives in your justification.\n\n"
        "Do NOT compute scores. `raw_score`, `fix_status` and `merge_readiness` are\n"
        "recomputed on the host from the gate statuses you report, and the values you\n"
        "put in those fields are ignored."
    )


def _load_system_prompt(config: Config, path_cfg: object) -> str | None:
    """Read the system prompt file if present, else return None."""
    prompt_file = getattr(path_cfg, "system_prompt_file", None)
    if not prompt_file:
        return None
    path = config.paths.prompts_dir / prompt_file
    if not path.exists():
        return None
    return (
        f"{path.read_text().rstrip()}\n\n"
        f"{_synthesis_section(config)}\n\n"
        f"{_rules_section(config)}\n"
    )


_STRUCTURED_RETRY_SUBTYPE = "error_max_structured_output_retries"


def _failure_reason(terminal: HarnessResult | None, exit_code: int) -> str:
    """Build an operator-actionable reason from the terminal result."""
    if terminal is None:
        return f"validation session produced no terminal result (exit={exit_code})"
    parts = [f"validation session ended with subtype={terminal.subtype!r}"]
    if terminal.subtype == _STRUCTURED_RETRY_SUBTYPE:
        parts.append(
            "the model never returned a response matching the validation schema -- "
            "either schema-validation retries were exhausted, or a model fallback "
            "retracted the response and no retry replaced it"
        )
    if terminal.errors:
        parts.append("errors: " + " | ".join(str(e) for e in terminal.errors))
    return " -- ".join(parts)


async def _run_and_check(
    harness: Harness,
    prompt: str,
    options: StreamingOptions,
    session_id: str,
    log_dir: Path,
    workspace: Path,
    tracking_ids: list[str],
    host_gate_synthesis: bool = True,
) -> int:
    """Stream the session, log it, and raise ValidationSessionError on failure."""
    # Collect every message alongside the flushed live log to recover the terminal HarnessResult.
    messages: list[HarnessMessage] = []
    try:
        exit_code, observed_sid = await stream_and_log(
            _log_stream(harness.run_streaming(prompt, options), messages),
            log_dir=log_dir / ORCHESTRATOR_LOG_DIRNAME,
            session_id=session_id,
            live=False,
        )
    except HarnessCLINotFoundError:
        raise
    except HarnessError as e:
        raise ValidationSessionError(
            f"Harness error: {type(e).__name__}",
            cause=e,
            exit_code=getattr(e, "exit_code", None),
        ) from e
    terminal = next(
        (m for m in reversed(messages) if isinstance(m, HarnessResult)), None
    )
    # The exit-code check precedes both writes: a failed session must leave no verdict in workspace.
    if exit_code != 0:
        log.error("Session %s exited with code %d", session_id, exit_code)
        raise ValidationSessionError(
            _failure_reason(terminal, exit_code),
            exit_code=exit_code,
        )
    if terminal is not None and terminal.structured is not None:
        _write_validation_outputs(workspace, terminal.structured)
    # Backends whose subagents return schema-validated reports get deterministic host synthesis.
    if host_gate_synthesis and terminal is not None and terminal.state is not None:
        _write_host_synthesized_gates(
            workspace, cast(HarnessTerminalState, terminal.state), tracking_ids
        )
    # A "success" result can persist nothing; state counts only if synthesis wrote it.
    if (
        terminal is not None
        and terminal.structured is None
        and (not host_gate_synthesis or terminal.state is None)
    ):
        raise ValidationSessionError(
            "validation session reported success but returned no structured output "
            "and no terminal state; no validation_report.json could be written",
            exit_code=exit_code,
        )
    log.debug("Session %s completed (observed_sid=%s)", session_id, observed_sid)
    return exit_code


async def _log_stream(
    source: AsyncIterator[HarnessMessage],
    collected: list[HarnessMessage],
) -> AsyncIterator[HarnessMessage]:
    """Yield each streamed message, appending to *collected* so caller recovers the final result."""
    async for msg in source:
        collected.append(msg)
        yield msg


async def launch_session(
    config: Config,
    manifest: Manifest,
    workspace_dir: Path,
    output_dir: Path,
    harness: Harness | None = None,
) -> int:
    """Run a fix-validation session and return the exit code (0 on success)."""
    if _injects_claude_config(config):
        inject_claude_config(workspace_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path_cfg = FIX_VALIDATION
    options = build_validation_options(
        config=config,
        manifest=manifest,
        workspace=workspace_dir,
        output_dir=output_dir,
        system_prompt=_load_system_prompt(config, path_cfg),
    )
    log.info(
        "Launching validation session %s for %s in %s",
        manifest.session_id, manifest.case_id, workspace_dir,
    )
    # One case per session, so its id is the only tracking id the personas can report under.
    tracking_ids = [manifest.case_id] if manifest.case_id else []
    return await _run_and_check(
        harness=harness if harness is not None else get_harness(config.agent.via),
        prompt=build_launch_prompt(manifest),
        options=options,
        session_id=manifest.session_id,
        log_dir=workspace_dir / LOGGING_DIRNAME,
        workspace=workspace_dir,
        tracking_ids=tracking_ids,
        host_gate_synthesis=_synthesizes_gates_on_host(config),
    )
