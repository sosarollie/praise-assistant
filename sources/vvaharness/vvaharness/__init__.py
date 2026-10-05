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

"""vvaharness — agentic SAST pipeline."""
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    # Single source of truth: pyproject `version`, so the CLI banner can't drift from it.
    __version__ = _pkg_version("vvaharness")
except PackageNotFoundError:  # running from a source tree that isn't pip-installed
    __version__ = "1.4.0"


def __getattr__(name: str):
    """Expose the embeddable surface (e.g. ``remediate``) lazily, without importing backends."""
    if name in ("remediate", "validate"):
        from vvaharness import api
        return getattr(api, name)
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
