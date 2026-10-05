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

"""The legacy via:openai validate role is routed to DeepAgents, not refused.

`via: openai` is a live selector for detection (S1-S9) and report-only remediation,
both served by the `backends/llm/openai.py` dispatcher. That dispatcher has no agentic
Harness implementation, so the validation panel cannot run on it directly. Rather
than aborting with exit 2 — which made one profile spelling mean "supported" at some
stages and "fatal" at others — the validate role maps it onto DeepAgents with the
OpenAI provider, the same `{via: deepagents, provider: <vendor>}` shape the shipped
profiles write explicitly (`default.yaml` ships the Anthropic pair).

These tests lock in that routing, that an explicit provider still wins, and that no
other backend selector is disturbed.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from vvaharness.backends.harness.provider_routing import (
    credential_env_overrides,
    routes_to_anthropic,
)
from vvaharness.validation.cli import main
from vvaharness.validation.cli._model import _apply_model_env, _check_persona_vendors
from vvaharness.validation.config.validate_role import normalize_validate_backend
from vvaharness.validation.constants.artifacts import (
    BACKEND_DEEPAGENTS,
    PROVIDER_OPENAI,
    REMEDIATION_DIRNAME,
    WORKSPACE_DIRNAME,
)


def _profile(
    tmp_path: Path,
    via: str,
    *,
    provider: str | None = None,
    personas: dict[str, str] | None = None,
) -> Path:
    spec = f"id: gpt-5.5, via: {via}"
    if provider is not None:
        spec += f", provider: {provider}"
    body = f"models:\n  validate:\n    orchestrator: {{{spec}}}\n"
    for name, persona_spec in (personas or {}).items():
        body += f"    {name}: {{{persona_spec}}}\n"
    body += "step_validate:\n  enabled: true\n"
    path = tmp_path / f"{via}-{provider or 'noprovider'}.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_openai_routes_to_deepagents_with_openai_provider() -> None:
    assert normalize_validate_backend("openai", None) == (
        BACKEND_DEEPAGENTS, PROVIDER_OPENAI,
    )


def test_explicit_provider_wins_over_the_routed_default() -> None:
    # Matches _backend_credential_ok precedence: explicit provider beats inference.
    assert normalize_validate_backend("openai", "anthropic") == (
        BACKEND_DEEPAGENTS, "anthropic",
    )


@pytest.mark.parametrize("via", ["cli", "sdk", "deepagents"])
def test_other_backends_pass_through_untouched(via: str) -> None:
    assert normalize_validate_backend(via, None) == (via, None)
    assert normalize_validate_backend(via, "openai") == (via, "openai")


def test_blank_via_is_left_to_the_config_layer() -> None:
    # Not this function's job — the config layer reports it with field context.
    assert normalize_validate_backend("", None) == ("", None)


def test_openai_profile_yields_deepagents_overrides(tmp_path: Path) -> None:
    rc, overrides = _apply_model_env(str(_profile(tmp_path, "openai")))

    assert rc == 0
    assert overrides["via"] == BACKEND_DEEPAGENTS
    assert overrides["provider"] == PROVIDER_OPENAI
    assert overrides["model"] == "gpt-5.5"


def test_deepagents_profile_overrides_are_unchanged(tmp_path: Path) -> None:
    rc, overrides = _apply_model_env(
        str(_profile(tmp_path, "deepagents", provider="openai"))
    )

    assert rc == 0
    assert overrides["via"] == BACKEND_DEEPAGENTS
    assert overrides["provider"] == PROVIDER_OPENAI


def test_persona_declared_route_warns_once_and_is_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Persona-level via/provider is not honoured; one aggregated warning names
    every declaring persona, and the overrides carry the orchestrator route."""
    cfg = _profile(
        tmp_path, "deepagents", provider="anthropic",
        personas={
            "security_architect": "id: claude-sonnet-4-6, via: cli",
            "penetration_tester": "id: claude-opus-4-8, provider: anthropic",
        },
    )

    rc, overrides = _apply_model_env(str(cfg))

    err = capsys.readouterr().err
    assert rc == 0
    assert err.count("declare via/provider") == 1
    assert "security_architect" in err and "penetration_tester" in err
    assert "deepagents/anthropic" in err
    assert overrides["via"] == BACKEND_DEEPAGENTS
    assert overrides["provider"] == "anthropic"
    assert overrides["security_architect_model"] == "claude-sonnet-4-6"
    assert overrides["penetration_tester_model"] == "claude-opus-4-8"


def test_bare_id_personas_emit_no_route_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The shipped-profile shape (persona ids only) is the documented contract.
    cfg = _profile(tmp_path, "deepagents", provider="anthropic",
                   personas={"security_architect": "id: claude-sonnet-4-6"})

    rc, overrides = _apply_model_env(str(cfg))

    assert rc == 0
    assert "declare via/provider" not in capsys.readouterr().err
    assert overrides["security_architect_model"] == "claude-sonnet-4-6"


def test_openai_profile_is_no_longer_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The old contract was exit 2 with "openai is not supported"; it is gone.

    The run may still fail for unrelated reasons (an empty repo has nothing to
    validate), but it must not fail because of the backend selector.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    main(["--repo", str(repo), "--config", str(_profile(tmp_path, "openai"))])

    err = capsys.readouterr().err
    assert "is not supported" not in err
    assert "legacy OpenAI harness" not in err


def test_openai_profile_stages_no_workspace_on_an_empty_repo(tmp_path: Path) -> None:
    # Routing must not make the CLI stage a workspace before it has work to do.
    repo = tmp_path / "repo"
    repo.mkdir()
    main(["--repo", str(repo), "--config", str(_profile(tmp_path, "openai"))])

    assert not (repo / REMEDIATION_DIRNAME / WORKSPACE_DIRNAME).exists()


# One definition in backends/harness/provider_routing.py: builder, credential probe, persona check.

@pytest.mark.parametrize(
    ("model_id", "provider", "expected"),
    [
        ("claude-opus-4-8", None, True),
        ("gpt-5.5", None, False),
        ("claude-opus-4-8", "openai", False),      # explicit provider overrides the name
        ("gpt-5.5", "anthropic", True),
        ("some-gateway-alias", None, False),       # unknown => OpenAI-compatible, not "unknown"
        ("anthropic/claude-opus", None, True),     # substring match, not prefix
        ("gpt-5.5", "azure", False),               # any non-anthropic provider
    ],
)
def test_routes_to_anthropic(model_id: str, provider: str | None, expected: bool) -> None:
    assert routes_to_anthropic(model_id, provider) is expected


def test_credential_env_overrides_reads_the_block_the_routing_resolved_to() -> None:
    sdk_cfg = SimpleNamespace(api_key="sk-ant-profile", base_url="https://anthropic.internal")
    openai_cfg = SimpleNamespace(api_key="sk-oai-profile", base_url="https://openai.internal")
    anthropic_route = credential_env_overrides(
        "claude-opus-4-8", None, sdk_cfg=sdk_cfg, openai_cfg=openai_cfg
    )
    assert anthropic_route == {
        "ANTHROPIC_API_KEY": "sk-ant-profile",
        "ANTHROPIC_BASE_URL": "https://anthropic.internal",
    }
    openai_route = credential_env_overrides(
        "gpt-5.5", None, sdk_cfg=sdk_cfg, openai_cfg=openai_cfg
    )
    assert openai_route == {
        "OPENAI_API_KEY": "sk-oai-profile",
        "OPENAI_BASE_URL": "https://openai.internal",
    }


def test_credential_env_overrides_empty_when_profile_block_absent() -> None:
    assert credential_env_overrides(
        "claude-opus-4-8", None, sdk_cfg=None, openai_cfg=None
    ) == {}


def _ov(model: str, provider: str | None, **personas: str) -> dict[str, object]:
    out: dict[str, object] = {"model": model, "provider": provider}
    out.update(personas)
    return out


def test_anthropic_panel_rejects_an_openai_persona() -> None:
    err = _check_persona_vendors(
        _ov("claude-opus-4-8", "anthropic", security_architect_model="gpt-5.5")
    )
    assert err is not None
    assert "security_architect" in err and "gpt-5.5" in err


def test_openai_panel_rejects_an_anthropic_persona() -> None:
    err = _check_persona_vendors(
        _ov("gpt-5.5", "openai", penetration_tester_model="claude-opus-4-8")
    )
    assert err is not None
    assert "penetration_tester" in err and "claude-opus-4-8" in err


@pytest.mark.parametrize(
    ("model", "provider", "persona"),
    [
        ("gpt-5.5", "openai", "gpt-5.5-mini"),               # OpenAI-route shape
        ("claude-opus-4-8", "anthropic", "claude-sonnet-4-6"),  # default.yaml / sdk.yaml shape
    ],
)
def test_same_route_personas_are_accepted(model: str, provider: str, persona: str) -> None:
    # Differing model ids within one route are the supported way to vary personas.
    assert _check_persona_vendors(
        _ov(model, provider, security_architect_model=persona)
    ) is None


def test_unset_personas_are_accepted() -> None:
    # Personas inheriting models.validate cannot mismatch it.
    assert _check_persona_vendors(_ov("gpt-5.5", "openai")) is None


def test_route_is_inferred_from_the_orchestrator_when_no_provider_is_set() -> None:
    # via: cli / via: sdk profiles set no provider; the orchestrator name decides.
    err = _check_persona_vendors(
        _ov("claude-opus-4-8", None, cross_repo_analyzer_model="gpt-5.5")
    )
    assert err is not None and "cross_repo_analyzer" in err


def test_every_persona_key_is_checked() -> None:
    for field in ("security_architect_model", "penetration_tester_model",
                  "cross_repo_analyzer_model"):
        err = _check_persona_vendors(_ov("claude-opus-4-8", "anthropic", **{field: "gpt-5.5"}))
        assert err is not None, field


def test_mismatched_panel_exits_two_and_stages_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A cross-route panel is refused before a workspace is staged or a token spent."""
    repo = tmp_path / "repo"
    repo.mkdir()
    cfg = tmp_path / "mixed.yaml"
    cfg.write_text(
        "models:\n  validate:\n"
        "    orchestrator:       {id: claude-opus-4-8, via: deepagents, provider: anthropic}\n"
        "    security_architect: {id: gpt-5.5}\n"
        "step_validate:\n  enabled: true\n",
        encoding="utf-8",
    )

    rc = main(["--repo", str(repo), "--config", str(cfg)])

    assert rc == 2
    assert "security_architect" in capsys.readouterr().err
    assert not (repo / REMEDIATION_DIRNAME / WORKSPACE_DIRNAME).exists()
