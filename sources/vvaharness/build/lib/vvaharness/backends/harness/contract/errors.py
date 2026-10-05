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

"""Re-export of the harness exception hierarchy, which is defined in ``models``.

This module deliberately holds no class of its own. It briefly did: a merge
landed a second, byte-similar copy of the hierarchy here, and because Python
compares exception classes by identity the copies did not interoperate —
``is_halt_error(models.AuthenticationError(...))`` returned ``False``, so the
one caller's halt guard (``callgraph_engine``, which re-raises VVAH-E001/E002
instead of degrading to rules mode) silently became a no-op that still read as
protection. Anything importing from here therefore gets the same objects the
backends actually raise.

New code should import from ``vvaharness.backends.harness.models`` directly;
this shim exists so the existing import site keeps working.
"""

from vvaharness.backends.harness.models import (
    AuthenticationError,
    DegenerateResponseError,
    HarnessCLINotFoundError,
    HarnessConnectionError,
    HarnessError,
    HarnessJSONDecodeError,
    HarnessMessageParseError,
    HarnessProcessError,
    ProxyError,
    is_halt_error,
    is_token_error,
)

__all__ = [
    "AuthenticationError",
    "DegenerateResponseError",
    "HarnessCLINotFoundError",
    "HarnessConnectionError",
    "HarnessError",
    "HarnessJSONDecodeError",
    "HarnessMessageParseError",
    "HarnessProcessError",
    "ProxyError",
    "is_halt_error",
    "is_token_error",
]
