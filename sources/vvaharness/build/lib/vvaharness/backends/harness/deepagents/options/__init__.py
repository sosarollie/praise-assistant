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

"""Public surface of the options package: model, graph, and subagent-spec builders."""

from __future__ import annotations

from deepagents import register_provider_profile
from deepagents.profiles.provider.provider_profiles import ProviderProfile

from vvaharness.backends.harness.deepagents.limits import MODEL_TIMEOUT_SECONDS
from vvaharness.backends.harness.deepagents.options.model_building import (
    RESPONSES_INCLUDE_ENCRYPTED_REASONING,
    build_model,
    build_model_cached,
)
from vvaharness.backends.harness.deepagents.options.oneshot import build_oneshot_options
from vvaharness.backends.harness.deepagents.options.streaming import build_streaming_agent
from vvaharness.backends.harness.deepagents.options.subagents import get_subagent_specs

# Mirrors build_model's default, so a bare-string model that skips resolution matches it.
register_provider_profile(
    "openai",
    ProviderProfile(
        init_kwargs={
            "use_responses_api": True,
            "store": False,
            "include": list(RESPONSES_INCLUDE_ENCRYPTED_REASONING),
            "timeout": MODEL_TIMEOUT_SECONDS,
        }
    ),
)

__all__ = [
    "build_model",
    "build_model_cached",
    "build_oneshot_options",
    "build_streaming_agent",
    "get_subagent_specs",
]
