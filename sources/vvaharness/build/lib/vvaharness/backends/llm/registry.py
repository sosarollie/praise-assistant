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

"""Backend dispatcher: step files import prompt()/agentic() from HERE, never a backend directly.

Routing comes from the model config's `.via` (bare string ⇒ cli); backends never know each other.
`via: deepagents` is deliberately NOT registered here — see DEEPAGENTS_ROLES below.
"""
from __future__ import annotations

from collections.abc import Mapping
from importlib import import_module
from typing import Any, Final

from vvaharness.backends.llm.cli import parse_json_response  # noqa: F401 — re-exported
from vvaharness.backends.llm.models import (
    LlmBackend,
    ModelExtras,
    ModulePath,
    ResolvedModel,
)
from vvaharness.util.scan_progress import get_active_tracker
from vvaharness.util.tokens import TOKENS  # also re-exported

# Roles allowed to select via:deepagents. This registry dispatches NONE of them —
# `deepagents` is deliberately absent from _BACKENDS, so a stray registry.prompt()/agentic()
# call with a via:deepagents model fails loudly in get_backend(). Every role listed here
# reaches the harness through an explicit in-stage branch on the resolved via, calling
# backends.llm.deepagents (the harness primitives) — the S10/S11 pattern. This set is the
# gate preflight.py and environment.py enforce: via:deepagents on any role NOT listed here
# is rejected before a scan starts. Every shipped role is now admitted; the gate remains
# for roles added in the future, and it also drives preflight probe routing.
DEEPAGENTS_ROLES = frozenset({
    "remediate", "validate",          # S10/S11 — harness graph, in-stage branch
    "preprocess",                     # S1 — harness graph (agentic), in-stage branch
    "autoexclude",                    # pre-S1 — harness graph, in-stage branch
    "threatmodel", "decompose",       # S2/S3 — in-stage branch
    "deepdive",                       # S4 — dispatch_prompt seam
    "verify",                         # S6 — dispatch_agentic seam
    "dedup", "chain",                 # S7/S8 (and S5-b via dedup) — in-stage branch
    "graph_annotate",                 # S0 — in-stage branch
    "exploit_verification.classify", "exploit_verification.mapper",
    "exploit_verification.judge", "exploit_verification.attacker",
})

# Roles that run after detection (S10/S11): a preflight probe failure here WARNs rather
# than aborts, because findings are already complete — only the fix/validation is lost.
# Detection roles stay fatal; an unreachable model there means a silently incomplete scan.
POST_SCAN_ROLES = frozenset({"remediate", "validate"})


def provider_of(model_cfg: object) -> str | None:
    """Provider selector from a model config node, when it declares one."""
    provider = getattr(model_cfg, "provider", None)
    return provider if isinstance(provider, str) else None


def use_responses_api_of(model_cfg: object) -> bool | None:
    """Transport override from a model config node, when it declares a boolean one."""
    value = getattr(model_cfg, "use_responses_api", None)
    return value if isinstance(value, bool) else None


#: Every key a consumer reads off a model config node; preflight/doctor warn on the rest.
KNOWN_MODEL_NODE_KEYS: Final[frozenset[str]] = frozenset(
    {"id", "via", "provider", "temperature", "thinking_budget", "betas",
     "use_responses_api"}
)


def unrecognized_model_keys(model_cfg: object) -> tuple[str, ...]:
    """Raw keys on a dict-backed model config node that no consumer reads."""
    data = getattr(model_cfg, "_data", None)
    if not isinstance(data, dict):
        return ()
    return tuple(sorted(str(k) for k in data if str(k) not in KNOWN_MODEL_NODE_KEYS))


def resolve(model_cfg: Any) -> ResolvedModel:
    """Normalize a model config; a bare str ⇒ the default via, else its .id/.via win.

    ``getattr`` throughout because a profile node is a dynamic YAML wrapper whose keys are
    all optional.
    """
    if isinstance(model_cfg, str):
        return ResolvedModel(model_cfg, DEFAULT_LLM_VIA, ModelExtras())

    model_id = getattr(model_cfg, "id", None)
    if model_id is None:
        raise ValueError(
            f"Model config must be a string or have an `id` field: got {model_cfg!r}"
        )
    via = getattr(model_cfg, "via", None) or DEFAULT_LLM_VIA
    extras = ModelExtras()
    temperature = getattr(model_cfg, "temperature", None)
    if temperature is not None:
        extras["temperature"] = float(temperature)
    thinking_budget = getattr(model_cfg, "thinking_budget", None)
    if thinking_budget:
        extras["thinking_budget"] = int(thinking_budget)
    betas = getattr(model_cfg, "betas", None)
    if betas:
        extras["betas"] = list(betas)
    return ResolvedModel(model_id, via, extras)


# Backends are named by import path and resolved on selection, so picking one never imports its SDK.
_BACKENDS: Final[Mapping[str, ModulePath]] = {
    "cli": ModulePath("vvaharness.backends.llm.cli"),
    "sdk": ModulePath("vvaharness.backends.llm.sdk"),
    "openai": ModulePath("vvaharness.backends.llm.openai"),
}

#: Selected when a model config names no backend.
DEFAULT_LLM_VIA: Final = "cli"


def available() -> list[str]:
    """Return the registered ``via`` names."""
    return sorted(_BACKENDS)


def targets() -> Mapping[str, ModulePath]:
    """Return the shipped module paths, so a test can assert every one still resolves."""
    return _BACKENDS


def get_backend(via: str, model_id: str) -> LlmBackend:
    """Resolve *via* to its backend module, naming the model if unknown; imported lazily here."""
    path = _BACKENDS.get(via)
    if path is None:
        raise ValueError(f"Unknown backend `via: {via}` for model {model_id}")
    module = import_module(path)
    if not isinstance(module, LlmBackend):
        msg = f"backend module {path!r} does not provide prompt() and agentic()"
        raise TypeError(msg)
    return module


def _flatten_blocks(user_prompt: str | list[dict]) -> str:
    """Render a prompt as one string, joining the text blocks of a content-block list."""
    if isinstance(user_prompt, str):
        return user_prompt
    return "\n\n".join(
        str(b.get("text", "")) for b in user_prompt
        if isinstance(b, dict) and b.get("type") == "text"
    )


def _fold_for_cli(user_prompt: str | list[dict], kw: dict[str, Any]) -> str | list[dict]:
    """Adapt *kw* in place for the CLI route, returning the (possibly prefixed) prompt.

    The CLI backend has no temperature/thinking flags, so SDK-only kwargs are silently
    dropped. Its only cacheable surface is ``--system-prompt``, so ``cache_prefix`` is
    folded back into the user turn rather than forwarded as a kwarg it cannot accept.
    """
    kw.pop("temperature", None)
    kw.pop("thinking_budget", None)
    kw.pop("betas", None)
    cache_prefix = kw.pop("cache_prefix", None)
    if not cache_prefix:
        return user_prompt
    if isinstance(user_prompt, list):
        return [{"type": "text", "text": cache_prefix}, *user_prompt]
    return cache_prefix + user_prompt


def prompt(user_prompt: str | list[dict], *, model: Any, **kw: Any) -> str:
    """Route a single-turn completion to the backend the model config selects."""
    model_id, via, extras = resolve(model)
    backend = get_backend(via, model_id)
    tracker = get_active_tracker()
    if tracker is not None:
        # Log the prefix too: for a specialist shard `cache_prefix` carries most of the
        # request, so logging user_prompt alone would omit the bulk of what was sent.
        _prefix = kw.get("cache_prefix") or ""
        _body = _flatten_blocks(user_prompt)
        tracker.llm_payload(
            phase=TOKENS.current_phase(),
            backend=via,
            model_id=model_id,
            tag=str(kw.get("tag", "") or ""),
            user_prompt=(_prefix + _body) if _prefix else _body,
            system_prompt=str(kw.get("system_prompt", "") or ""),
        )
    if via == DEFAULT_LLM_VIA:
        user_prompt = _fold_for_cli(user_prompt, kw)
    else:
        # extras (e.g. temperature) win unless the caller passed one explicitly.
        for k, v in extras.items():
            kw.setdefault(k, v)
    return backend.prompt(user_prompt, model=model_id, **kw)


def agentic(user_prompt: str, *, model: Any, **kw) -> str:
    """Route a tool-using loop to the backend the model config selects."""
    model_id, via, _ = resolve(model)
    backend = get_backend(via, model_id)
    # `stream_cb` (live trace) is CLI-only; dropped for sdk/openai to dodge a TypeError.
    if via != DEFAULT_LLM_VIA:
        kw.pop("stream_cb", None)
    return backend.agentic(user_prompt, model=model_id, **kw)
