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

"""Resolving the ``models.validate`` role out of a harness profile.

Not CLI code: the orchestrator and preflight need the same answers as ``validation.cli``.
"""

from __future__ import annotations

from typing import NamedTuple

from vvaharness.config import Config as HarnessConfig
from vvaharness.validation.constants.artifacts import (
    BACKEND_DEEPAGENTS,
    BACKEND_OPENAI,
    PROVIDER_OPENAI,
)

__all__ = ["BackendRoute", "normalize_validate_backend", "validate_model_spec"]


class BackendRoute(NamedTuple):
    """The backend selector and DeepAgents provider a validate role should run on."""

    via: str
    provider: str | None


def validate_model_spec(cfg: HarnessConfig) -> object | None:
    """Return ``cfg.models.validate.orchestrator``, or None when any level is undefined.

    ``getattr`` because ``HarnessConfig`` resolves YAML keys dynamically and raises for an
    absent section; a missing ``models:`` block is normal, not an error.
    """
    models = getattr(cfg, "models", None)
    if models is None:
        return None
    validate = getattr(models, "validate", None)
    if validate is None:
        return None
    return getattr(validate, "orchestrator", None)


def normalize_validate_backend(via: str, provider: str | None) -> BackendRoute:
    """Route a legacy ``via: openai`` validate role onto DeepAgents with the OpenAI provider.

    ``via: openai`` is live for detection and report-only remediation but has no agentic
    Harness, so mapping it beats refusing a spelling that works at other stages. An explicit
    *provider* wins; every other *via* passes through untouched.
    """
    if via != BACKEND_OPENAI:
        return BackendRoute(via, provider)
    return BackendRoute(BACKEND_DEEPAGENTS, provider or PROVIDER_OPENAI)
