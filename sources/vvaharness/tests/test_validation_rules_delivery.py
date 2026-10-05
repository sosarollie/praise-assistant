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

"""The validation rules must reach every backend, by one route or the other.

``.claude/rules/`` is injected only for the cli/sdk backends, so a prompt that
tells the model to read those files leaves deepagents/openai with dangling
references and no rules. Those backends get the same files inlined instead.
Offline and deterministic -- no network, no LLM, no subprocess.
"""

from __future__ import annotations

from types import SimpleNamespace

from vvaharness.validation.config.settings import _ASSETS_ROOT
from vvaharness.validation.session.launcher import (
    _injects_claude_config,
    _load_system_prompt,
)
from vvaharness.validation.session.rules import (
    orchestrator_rules_text,
    persona_rules_text,
)
from vvaharness.validation.subagents import load_agents

# Resolved from the package, so the tests do not depend on the working directory.
_PROMPTS_DIR = _ASSETS_ROOT / "prompts"

# Sections with no host-side equivalent -- the reason inlining is needed at all.
SCORING_ONLY_MARKER = "Code-level signals only"
PERSONA_MARKER = "Persona Isolation"
SECRET_PERSONA_MARKER = "Secret-Exposure Evidence"
CLAUDE_RULES_PATH = ".claude/rules"


def _config(via: str) -> SimpleNamespace:
    return SimpleNamespace(
        agent=SimpleNamespace(via=via),
        paths=SimpleNamespace(prompts_dir=_PROMPTS_DIR),
    )


_PATH_CFG = SimpleNamespace(system_prompt_file="system.md")


def test_injects_claude_config_only_for_cli_and_sdk() -> None:
    assert _injects_claude_config(_config("cli")) is True
    assert _injects_claude_config(_config("sdk")) is True
    assert _injects_claude_config(_config("deepagents")) is False
    assert _injects_claude_config(_config("openai")) is False


def test_orchestrator_rules_carry_both_files_without_the_licence_header() -> None:
    text = orchestrator_rules_text()
    assert SCORING_ONLY_MARKER in text
    assert "Rotation attestation" in text
    assert PERSONA_MARKER in text
    assert "Copyright 2026 Visa" not in text
    assert text == text.strip()


def test_secret_validation_contract_never_requires_plaintext_reconstruction() -> None:
    text = orchestrator_rules_text()
    assert 'PatternScan("secret_exposure")' in text
    assert "excludes the redacted `diff.patch`" in text
    assert "never reconstruct, persist, or place a removed plaintext credential" in text
    assert "exact-value `grep -F` verification is intentionally unavailable" in text
    assert "Identify the secret token(s)" not in text
    assert "Record the command and its output verbatim" not in text


def test_persona_rules_include_backend_aware_secret_verification() -> None:
    text = persona_rules_text()
    assert PERSONA_MARKER in text
    assert SECRET_PERSONA_MARKER in text
    assert "If `PatternScan` is present in your granted tools" in text
    assert "If `PatternScan` is not present" in text
    assert "never with the removed plaintext value" in text
    assert SCORING_ONLY_MARKER not in text
    assert "Copyright 2026 Visa" not in text


def test_bundled_personas_receive_tool_aware_secret_instructions() -> None:
    for name, agent in load_agents().items():
        assert "when they are present in your granted toolset" in agent.prompt, name
        assert "When a fact tool is unavailable" in agent.prompt, name
        assert "never reconstruct or report a plaintext candidate" in agent.prompt, name


def test_cli_sdk_prompt_points_at_the_injected_rules_and_does_not_inline() -> None:
    for via in ("cli", "sdk"):
        prompt = _load_system_prompt(_config(via), _PATH_CFG)
        assert prompt is not None
        assert "auto-loaded from `.claude/rules/`" in prompt, via
        assert "must be requested only when present" in prompt, via
        assert SCORING_ONLY_MARKER not in prompt, via


def test_other_backends_inline_the_rules_with_no_dangling_path_reference() -> None:
    """A `.claude/rules/...` mention would send the model after a file it never got."""
    for via in ("deepagents", "openai"):
        prompt = _load_system_prompt(_config(via), _PATH_CFG)
        assert prompt is not None
        assert SCORING_ONLY_MARKER in prompt, via
        assert PERSONA_MARKER in prompt, via
        assert CLAUDE_RULES_PATH not in prompt, via


def test_every_backend_gets_a_single_rules_section() -> None:
    for via in ("cli", "sdk", "deepagents", "openai"):
        prompt = _load_system_prompt(_config(via), _PATH_CFG)
        assert prompt is not None
        assert prompt.count("## Rules") == 1, via


def test_prompt_suffix_appends_to_every_persona() -> None:
    base = load_agents()
    suffixed = load_agents(prompt_suffix=persona_rules_text())
    assert set(base) == set(suffixed)
    for name, agent in suffixed.items():
        assert PERSONA_MARKER in agent.prompt, name
        assert SECRET_PERSONA_MARKER in agent.prompt, name
        assert "If `PatternScan` is present in your granted tools" in agent.prompt, name
        assert agent.prompt.startswith(base[name].prompt.rstrip()), name
        # Only the prompt changes; the rest of the definition is untouched.
        assert agent.name == base[name].name
        assert agent.tools == base[name].tools
        assert agent.response_model is base[name].response_model


def test_prompt_suffix_omitted_leaves_persona_prompts_untouched() -> None:
    base = load_agents()
    for name, agent in load_agents(prompt_suffix=None).items():
        assert agent.prompt == base[name].prompt, name
