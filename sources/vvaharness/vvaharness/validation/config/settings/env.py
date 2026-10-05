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

"""The flat VVAHARNESS_* environment surface for credential/host-local settings."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from vvaharness.validation.constants.artifacts import (
    DEFAULT_CLAUDE_BINARY,
    DEFAULT_MAX_RETRIES,
    ENV_CLAUDE_BINARY,
    ENV_GHE_ARCHIVED_TOKEN,
    ENV_GHE_TOKEN,
    ENV_MAX_RETRIES,
)


class _EnvScalars(BaseSettings):
    """The flat ``VVAHARNESS_*`` environment surface for credential/host-local settings.

    Tunables (model, effort, turns, budget, provider, etc.) come from ``--config`` or a
    hardcoded default instead — see ``load_config()``.
    """

    model_config = SettingsConfigDict(extra="ignore", populate_by_name=True)

    max_retries: int = Field(default=DEFAULT_MAX_RETRIES, alias=ENV_MAX_RETRIES)
    binary: str = Field(default=DEFAULT_CLAUDE_BINARY, alias=ENV_CLAUDE_BINARY)
    ghe_token: str = Field(default="", alias=ENV_GHE_TOKEN)
    ghe_archived_token: str = Field(default="", alias=ENV_GHE_ARCHIVED_TOKEN)
