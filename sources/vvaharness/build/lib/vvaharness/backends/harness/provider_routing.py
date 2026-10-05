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

"""Which vendor a (model, provider) pair resolves to.

Not stdlib-only — importing it executes the harness package ``__init__`` and pulls
``harness.models`` and ``util.tokens`` — but its transitive import closure contains no
langchain, deepagents, anthropic or openai module. That is the guarantee preflight,
``manifest._models()`` and the detection llm adapter rely on; ``deepagents.options``
would drag in langchain.
"""

from __future__ import annotations

from typing import Final

from vvaharness.backends.harness.models import Provider

__all__ = [
    "TRANSPORT_CHAT_COMPLETIONS",
    "TRANSPORT_RESPONSES",
    "credential_env_overrides",
    "routes_to_anthropic",
]

#: Manifest/telemetry names for the OpenAI-branch transport a model resolves to.
TRANSPORT_RESPONSES: Final = "responses"
TRANSPORT_CHAT_COMPLETIONS: Final = "chat_completions"


def routes_to_anthropic(model_id: str, provider: str | None) -> bool:
    """True for the Anthropic route, else OpenAI-compatible.

    An explicit *provider* decides, otherwise the model name does; anything not
    ``Provider.ANTHROPIC`` is OpenAI-compatible, including an unrecognised value.
    """
    if provider:
        return provider == Provider.ANTHROPIC
    return "claude" in model_id.lower()


def credential_env_overrides(
    model_id: str, provider: str | None, *, sdk_cfg: object, openai_cfg: object
) -> dict[str, str]:
    """ANTHROPIC_*/OPENAI_* env overrides read off whichever of sdk_cfg/openai_cfg is resolved."""
    is_anthropic = routes_to_anthropic(model_id, provider)
    block = sdk_cfg if is_anthropic else openai_cfg
    prefix = "ANTHROPIC" if is_anthropic else "OPENAI"
    overrides: dict[str, str] = {}
    api_key = getattr(block, "api_key", None)
    base_url = getattr(block, "base_url", None)
    if api_key:
        overrides[f"{prefix}_API_KEY"] = api_key
    if base_url:
        overrides[f"{prefix}_BASE_URL"] = base_url
    return overrides
