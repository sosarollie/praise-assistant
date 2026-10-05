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

"""Model-resolution logic for the ``vvaharness validate`` command."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import NamedTuple

from vvaharness import config as harness_config
from vvaharness.backends.harness.provider_routing import routes_to_anthropic
from vvaharness.backends.llm import registry as llm
from vvaharness.backends.llm.deepagents import markers_on
from vvaharness.config import Config as HarnessConfig
from vvaharness.validation.cli._parser import _tunable_overrides
from vvaharness.validation.config.overrides import ValidateOverrides
from vvaharness.validation.config.validate_role import (
    normalize_validate_backend,
    validate_model_spec,
)

_PERSONA_FIELDS: dict[str, str] = {
    "security_architect": "security_architect_model",
    "penetration_tester": "penetration_tester_model",
    "cross_repo_analyzer": "cross_repo_analyzer_model",
}


class LoadedValidateSpec(NamedTuple):
    """A loaded harness config paired with its resolved ``models.validate`` orchestrator spec."""

    config: HarnessConfig
    spec: object


class PersonaModelResolution(NamedTuple):
    """A persona's resolved model id and backend selector (``via``)."""

    model_id: str
    via: str


class ModelEnvResult(NamedTuple):
    """The exit code and settings overrides produced by resolving the validate model."""

    exit_code: int
    overrides: ValidateOverrides


def _check_persona_vendors(overrides: ValidateOverrides) -> str | None:
    """Return an error when a persona model routes elsewhere than the panel does.

    The orchestrator's provider applies to the whole panel — a persona's own via/provider
    is not honoured — so a mismatch would stage a workspace and fail mid-run untraceably.
    """
    provider = overrides.get("provider")
    panel_anthropic = routes_to_anthropic(
        str(overrides.get("model") or ""),
        provider if isinstance(provider, str) and provider else None,
    )
    for short_name, field in _PERSONA_FIELDS.items():
        model = overrides.get(field)
        if not isinstance(model, str) or not model:
            continue
        # A persona spec contributes only its model id, so the name alone decides.
        if routes_to_anthropic(model, None) == panel_anthropic:
            continue
        panel, wanted = (
            ("Anthropic", "an Anthropic") if panel_anthropic
            else ("an OpenAI-compatible endpoint", "an OpenAI-compatible")
        )
        return (
            f"validate: models.validate.{short_name} is {model!r}, which routes to "
            f"{'an OpenAI-compatible endpoint' if panel_anthropic else 'Anthropic'}, "
            f"but the panel runs on {panel} (from models.validate.orchestrator). "
            f"Every persona shares the orchestrator's provider — a persona's own "
            f"via/provider is not honoured. Set {short_name} to {wanted} model, or "
            f"change models.validate.orchestrator."
        )
    return None


def _load_validated_spec(config_path: str) -> LoadedValidateSpec | None:
    """Load config and its spec, or None on missing path or absent models.validate."""
    if not Path(config_path).exists():
        print(f"validate: config not found: {config_path}", file=sys.stderr)
        return None
    try:
        cfg = harness_config.load(config_path)
    except harness_config.ConfigPolicyError as e:
        print(f"validate: {e}", file=sys.stderr)
        return None
    spec = validate_model_spec(cfg)
    if spec is None:
        print("validate: config defines no models.validate role", file=sys.stderr)
        return None
    return LoadedValidateSpec(cfg, spec)


def _declares_route(spec: object) -> bool:
    """Return True when a persona spec declares the route keys the panel does not honour."""
    return bool(getattr(spec, "via", None) or getattr(spec, "provider", None))


def _warn_ignored_persona_routes(declared: list[str], via: str, provider: str | None) -> None:
    """Emit one aggregated advisory naming every persona whose declared route is ignored."""
    if not declared:
        return
    route = f"{via}/{provider}" if provider else via
    print(
        f"validate: models.validate.{{{', '.join(declared)}}} declare "
        f"via/provider — ignored; the panel runs on the orchestrator's "
        f"route ({route})",
        file=sys.stderr,
    )


def _persona_spec_resolved(spec: object) -> PersonaModelResolution | None:
    """Resolve a persona model spec to its model id and via, or None when absent/invalid."""
    if spec is None:
        return None
    try:
        model_id, via, _ = llm.resolve(spec)
    except (ValueError, AttributeError, KeyError, TypeError):
        return None  # malformed spec — fall back to inheriting models.validate
    return PersonaModelResolution(model_id, via or "") if model_id else None


def _apply_model_env(config_path: str) -> ModelEnvResult:
    """Read the profile and return a fully-populated overrides dict for load_config().

    Returns exit code 0 with overrides on success, 2 with empty overrides if the profile is
    missing or defines no models.validate role; all YAML-sourced, no os.environ involved.
    """
    loaded = _load_validated_spec(config_path)
    if loaded is None:
        return ModelEnvResult(2, ValidateOverrides())
    cfg, spec = loaded
    model_id, via, _ = llm.resolve(spec)
    # Legacy `via: openai` is routed to DeepAgents so every downstream consumer sees one backend.
    via, provider = normalize_validate_backend(via or "", getattr(spec, "provider", None))
    overrides: ValidateOverrides = _tunable_overrides(cfg)
    overrides["model"] = model_id
    overrides["via"] = via
    overrides["provider"] = provider
    overrides["use_responses_api"] = llm.use_responses_api_of(spec)

    # Persona model overrides — read from models.validate.{security_architect, …}
    models = getattr(cfg, "models", None)
    validate = getattr(models, "validate", None) if models is not None else None
    if validate is not None:
        for short_name, field in _PERSONA_FIELDS.items():
            resolved = _persona_spec_resolved(getattr(validate, short_name, None))
            if resolved is not None:
                overrides[field] = resolved.model_id
        # Raw-spec check, not the resolved result, so a malformed spec still warns.
        declared = [name for name in _PERSONA_FIELDS
                    if _declares_route(getattr(validate, name, None))]
        _warn_ignored_persona_routes(declared, via, provider)

    # validate_tools — read from step_validate.allowed_tools.
    block = getattr(cfg, "step_validate", None)
    tools = getattr(block, "allowed_tools", None) if block is not None else None
    if isinstance(tools, list) and tools:
        overrides["validate_tools"] = ",".join(str(t) for t in tools)

    # cache_markers — the sdk block's kill switch gates the deepagents markers too.
    overrides["cache_markers"] = markers_on(getattr(cfg, "sdk", None))

    return ModelEnvResult(0, overrides)
