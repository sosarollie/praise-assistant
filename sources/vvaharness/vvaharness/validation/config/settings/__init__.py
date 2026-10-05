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

"""Typed configuration tree; all VVAHARNESS_* env access funnelled through _EnvScalars."""

from __future__ import annotations

from vvaharness.validation.config.settings.agent import AgentConfig
from vvaharness.validation.config.settings.config import Config, _parse_tools, load_config
from vvaharness.validation.config.settings.ghe import GheConfig
from vvaharness.validation.config.settings.paths import _ASSETS_ROOT, PathsConfig

__all__ = [
    "_ASSETS_ROOT",
    "AgentConfig",
    "Config",
    "GheConfig",
    "PathsConfig",
    "_parse_tools",
    "load_config",
]
