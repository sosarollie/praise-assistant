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

"""Validation session package — launch and error hierarchy."""

from vvaharness.validation.session.config_inject import inject_claude_config
from vvaharness.validation.session.errors import ValidationSessionError
from vvaharness.validation.session.launch_prompt import build_launch_prompt
from vvaharness.validation.session.launcher import (
    build_validation_options,
    launch_session,
)

__all__ = [
    "ValidationSessionError",
    "build_launch_prompt",
    "build_validation_options",
    "inject_claude_config",
    "launch_session",
]
