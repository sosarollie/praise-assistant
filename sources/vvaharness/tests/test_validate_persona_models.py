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

"""Tests for per-persona configurable models in the s11 validator.

Covers the full chain: profile models role -> _apply_model_env (ValidateOverrides) ->
load_config (AgentConfig) -> _persona_overrides -> load_agents override ->
SubagentDefinition.model -> SDK AgentDefinition.model. Unset persona -> inherit.
"""
import os
from types import SimpleNamespace

from vvaharness.backends.harness import SubagentDefinition
from vvaharness.backends.harness.claude.options import _to_agent_definition
from vvaharness.validation.config import load_config
from vvaharness.validation.constants.artifacts import (
    ENV_CROSS_REPO_ANALYZER_MODEL,
    ENV_PENETRATION_TESTER_MODEL,
    ENV_SECURITY_ARCHITECT_MODEL,
)
from vvaharness.validation.session.launcher import _persona_overrides
from vvaharness.validation.subagents import load_agents

# load_agents override / inherit


def test_override_sets_model_inherit_leaves_none() -> None:
    ag = load_agents(
        ["security-architect", "penetration-tester"],
        model_overrides={"security-architect": "claude-opus-4-8"},
    )
    assert ag["security-architect"].model == "claude-opus-4-8"   # overridden
    assert ag["penetration-tester"].model is None                # inherit


def test_no_overrides_all_inherit() -> None:
    ag = load_agents(["security-architect", "penetration-tester", "cross-repo-analyzer"])
    assert all(a.model is None for a in ag.values())


# env vars must not set persona models -> AgentConfig


def test_env_vars_no_longer_set_persona_models(monkeypatch) -> None:
    # Persona-model overrides are override-or-default only now; env vars must be ignored.
    monkeypatch.setenv(ENV_SECURITY_ARCHITECT_MODEL, "claude-opus-4-8")
    monkeypatch.delenv(ENV_PENETRATION_TESTER_MODEL, raising=False)
    monkeypatch.setenv(ENV_CROSS_REPO_ANALYZER_MODEL, "claude-sonnet-4-6")
    cfg = load_config()
    assert cfg.agent.security_architect_model is None
    assert cfg.agent.penetration_tester_model is None
    assert cfg.agent.cross_repo_analyzer_model is None


# _persona_overrides (config -> name->model map)


def test_persona_overrides_omits_unset() -> None:
    cfg = SimpleNamespace(agent=SimpleNamespace(
        security_architect_model="claude-opus-4-8",
        penetration_tester_model=None,
        cross_repo_analyzer_model="claude-sonnet-4-6",
    ))
    assert _persona_overrides(cfg) == {
        "security-architect": "claude-opus-4-8",
        "cross-repo-analyzer": "claude-sonnet-4-6",
    }


# _apply_model_env -> overrides (persona models go through overrides, not env)


def test_persona_model_in_overrides(tmp_path) -> None:
    from vvaharness.validation.cli._model import _apply_model_env
    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(
        "models:\n"
        "  validate:\n"
        "    orchestrator: {id: gpt-5.5, via: deepagents}\n"
        "    security_architect: {id: claude-opus-4-8}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )
    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    assert overrides["security_architect_model"] == "claude-opus-4-8"


def test_absent_persona_role_not_in_overrides(tmp_path) -> None:
    from vvaharness.validation.cli._model import _apply_model_env
    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(
        "models:\n  validate:\n    orchestrator: {id: gpt-5.5, via: deepagents}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )
    rc, overrides = _apply_model_env(str(cfg_path))
    assert rc == 0
    assert "security_architect_model" not in overrides
    assert "penetration_tester_model" not in overrides


# model carried through to the SDK shape


def test_agent_definition_carries_model() -> None:
    sub = SubagentDefinition(name="security-architect", description="d", prompt="p",
                             model="claude-opus-4-8")
    assert _to_agent_definition(sub).model == "claude-opus-4-8"
