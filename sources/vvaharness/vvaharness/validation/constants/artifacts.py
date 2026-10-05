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

"""Single source of truth for artifact names, DTO layout, and runtime environment keys."""

from __future__ import annotations

from typing import Final

from vvaharness.models import CaseState
from vvaharness.validation.enums import EffortLevel, Provider

# Workspace artifacts (written to / read from the staged workspace root).
MANIFEST_FILENAME: Final = "manifest.json"
# Shares "diff.patch" with remediation_agent's DIFF_PATCH by design; deliberately decoupled.
DIFF_FILENAME: Final = "diff.patch"
VALIDATION_REPORT_FILENAME: Final = "validation_report.json"
SYNTHESIZED_GATES_FILENAME: Final = "synthesized_gates.json"

# Case-file layout inside the target repository: one directory per case, holding its record.
APP_DIRNAME: Final = "app"
REMEDIATION_DIRNAME: Final = "security-remediation"
FINDING_CASE_FILENAME: Final = "finding_case.json"
FINDING_CASE_GLOB: Final = f"{REMEDIATION_DIRNAME}/*/{FINDING_CASE_FILENAME}"

# Case states s11 will attempt, derived from CaseState so the lifecycle stays owned by state_of.
VALIDATABLE_STATES: Final[frozenset[CaseState]] = frozenset({
    CaseState.OPEN,
    CaseState.REMEDIATED,
    CaseState.FAILED,
})

# Scan output dir: validator only READS the report here; artifacts go under REMEDIATION_DIRNAME.
SCAN_DIRNAME: Final = "security-scan"
# Ephemeral staged-workspace dir, joined under <repo>/security-remediation/validation.
WORKSPACE_DIRNAME: Final = "validation"
# Scan report artifacts under <repo>/security-scan/ (SARIF + sibling .md, timestamped).
SCAN_REPORT_GLOB: Final = "*_report.sarif"

# Injected agent-config layout inside the workspace.
CLAUDE_DIRNAME: Final = ".claude"
LOGGING_DIRNAME: Final = "logging"
ORCHESTRATOR_LOG_DIRNAME: Final = "orchestrator"
SUBAGENTS_LOG_DIRNAME: Final = "subagents"

# VVAHARNESS_* environment names. Only ENV_MAX_RETRIES, ENV_CLAUDE_BINARY, ENV_GHE_TOKEN, and
# ENV_GHE_ARCHIVED_TOKEN are read (by config.settings._EnvScalars); the rest are inert names
# kept for back-compat, read by no production code. Tunables flow YAML → overrides dict in
# cli._model — no os.environ involved.
ENV_MODEL: Final = "VVAHARNESS_MODEL"
ENV_EFFORT: Final = "VVAHARNESS_EFFORT"
ENV_MAX_TURNS: Final = "VVAHARNESS_MAX_TURNS"
ENV_MAX_RETRIES: Final = "VVAHARNESS_MAX_RETRIES"
ENV_CLAUDE_BINARY: Final = "VVAHARNESS_CLAUDE_BINARY"
ENV_GHE_TOKEN: Final = "VVAHARNESS_GHE_TOKEN"  # noqa: S105
ENV_GHE_ARCHIVED_TOKEN: Final = "VVAHARNESS_GHE_ARCHIVED_TOKEN"  # noqa: S105
ENV_VIA: Final = "VVAHARNESS_VIA"
ENV_MODEL_PROVIDER: Final = "VVAHARNESS_MODEL_PROVIDER"  # deepagents: openai|anthropic
ENV_MAX_BUDGET_USD: Final = "VVAHARNESS_MAX_BUDGET_USD"
ENV_MAX_FINDINGS: Final = "VVAHARNESS_MAX_FINDINGS"
# Comma-separated reviewer-persona tool allow-list (step_validate.allowed_tools); unset → default.
ENV_VALIDATE_TOOLS: Final = "VVAHARNESS_VALIDATE_TOOLS"
# Inert per-persona model env names: read by no production code; the overrides dict is the only
# path (pinned by test_validate_persona_models.py::test_env_vars_no_longer_set_persona_models).
ENV_SECURITY_ARCHITECT_MODEL: Final = "VVAHARNESS_SECURITY_ARCHITECT_MODEL"
ENV_PENETRATION_TESTER_MODEL: Final = "VVAHARNESS_PENETRATION_TESTER_MODEL"
ENV_CROSS_REPO_ANALYZER_MODEL: Final = "VVAHARNESS_CROSS_REPO_ANALYZER_MODEL"

# Agent-session environment contract (set on the launched validation session).
SESSION_ENV_FLAG: Final = "VALIDATION_SESSION"
SESSION_ENV_TARGET_DIR: Final = "VALIDATION_TARGET_DIR"
SESSION_ENV_OUTPUT_DIR: Final = "VALIDATION_OUTPUT_DIR"
SESSION_ENV_MANIFEST: Final = "VALIDATION_MANIFEST"
SESSION_ENV_LOG_DIR: Final = "VALIDATION_LOG_DIR"
# Legacy env name for the finding id; never used to fetch, comment on, or transition tickets.
SESSION_ENV_JIRA_KEY: Final = "JIRA_KEY"
SESSION_ENV_SESSION_ID: Final = "SESSION_ID"
SESSION_ENV_PROJECT_DIR: Final = "CLAUDE_PROJECT_DIR"
SESSION_ENV_GH_TOKEN: Final = "GH_ENTERPRISE_TOKEN"  # noqa: S105
SESSION_ENV_GH_ARCHIVED_TOKEN: Final = "GH_ARCHIVED_TOKEN"  # noqa: S105

# Legacy routing value with no agentic Harness; routes to DeepAgents+OpenAI. See cli._model.
BACKEND_OPENAI: Final = "openai"
BACKEND_DEEPAGENTS: Final = "deepagents"

# Re-exported from the backend that owns the routing, so the vocabulary has one definition.
PROVIDER_OPENAI: Final = Provider.OPENAI.value
PROVIDER_ANTHROPIC: Final = Provider.ANTHROPIC.value

# vvaharness CLI command token for the validation subcommand.
VALIDATE_COMMAND: Final = "validate"
# `s11` is a CLI alias for `validate`: the agentic validation agent is the s11 pipeline stage.
VALIDATE_ALIAS_S11: Final = "s11"
VALIDATE_COMMANDS: Final = (VALIDATE_COMMAND, VALIDATE_ALIAS_S11)

# Anthropic API environment keys propagated into the SDK subprocess.
ANTHROPIC_API_KEY: Final = "ANTHROPIC_API_KEY"
ANTHROPIC_AUTH_TOKEN: Final = "ANTHROPIC_AUTH_TOKEN"  # noqa: S105

# Session log filename written to the orchestrator log dir.
SESSION_LOG_FILENAME: Final = "session.jsonl"

# Redacted session transcript filename prefix: <prefix><safe_finding_id>.jsonl.
VALIDATION_SESSION_LOG_PREFIX: Final = "validation_session_"

# Bash command preview and stderr tail lengths for diagnostic messages.
CMD_PREVIEW_LEN: Final = 80
STDERR_TAIL_LINES: Final = 3

# Default agent runtime values (mirror AgentConfig defaults in config.settings).
DEFAULT_CLAUDE_BINARY: Final = "claude"
DEFAULT_MODEL: Final = "claude-opus-4-8[1m]"
DEFAULT_MAX_TURNS: Final = 50
DEFAULT_MAX_RETRIES: Final = 2
DEFAULT_VALIDATION_VIA: Final = "deepagents"
DEFAULT_MAX_BUDGET_USD: Final = 15.0
DEFAULT_MAX_FINDINGS: Final = 20
DEFAULT_EFFORT: Final = EffortLevel.HIGH

# Default workspace sub-directory names under the project root.
TARGETS_DIRNAME: Final = "targets"
OUTPUTS_DIRNAME: Final = "outputs"
PROMPTS_DIRNAME: Final = "prompts"

# Operator-supplied context inputs live here (cwd-relative), e.g. inputs/validator_hints.yaml.
INPUTS_DIRNAME: Final = "inputs"
VALIDATOR_HINTS_FILENAME: Final = "validator_hints.yaml"

# Subagent system-prompt filename (resolved from the prompts dir per validation path).
SYSTEM_PROMPT_FILENAME: Final = "system.md"

# Placeholder used when a manifest/finding field is absent or unset.
MISSING_FIELD_PLACEHOLDER: Final = "N/A"
