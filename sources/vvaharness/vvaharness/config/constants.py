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

"""Env-interpolation policy and overlay-visibility constants for the config loader."""

from __future__ import annotations

from typing import Final

LOCAL_OVERLAY_NAME: Final[str] = "config.local.yaml"

NO_LOCAL_CONFIG_ENV: Final[str] = "VVAHARNESS_NO_LOCAL_CONFIG"

# Uppercase substrings that mark an env-var name as secret-bearing.
SECRET_NAME_PATTERNS: Final[frozenset[str]] = frozenset(
    {
        "API_KEY",
        "APIKEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "PRIVATE_KEY",
    }
)

# Matched as a suffix of an underscore-delimited segment: OAUTH and _AUTH_ count, AUTHOR does not.
SECRET_SEGMENT_PATTERNS: Final[frozenset[str]] = frozenset({"AUTH"})

# The only key paths a secret-patterned env var may interpolate into.
# tests/test_profile_no_hardcoded_secrets.py::_CREDENTIAL_FIELDS asserts a different
# property (no literal fallbacks) and deliberately stays separate.
CREDENTIAL_DESTINATIONS: Final[frozenset[str]] = frozenset(
    {
        "sdk.api_key",
        "openai.api_key",
        "batch.git_token",
        "output.ingest_token",
    }
)

# Overlay banner: endpoint keys print the resolved host only.
ENDPOINT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "sdk.base_url",
        "openai.base_url",
        "output.ingest_url",
        "batch.git_base_url",
    }
)

# Overlay banner: leaf names (plus the full path cache_route) whose resolved value is printed.
TLS_ROUTING_KEYS: Final[frozenset[str]] = frozenset(
    {
        "verify_ssl",
        "ca_cert",
        "client_cert",
        "no_proxy",
        "cache_route",
    }
)


def is_secret_var_name(name: str) -> bool:
    """True when the env-var name matches a secret substring or segment pattern."""
    upper = name.upper()
    if any(pat in upper for pat in SECRET_NAME_PATTERNS):
        return True
    return any(seg.endswith(pat) for seg in upper.split("_") for pat in SECRET_SEGMENT_PATTERNS)


__all__ = [
    "CREDENTIAL_DESTINATIONS",
    "ENDPOINT_KEYS",
    "LOCAL_OVERLAY_NAME",
    "NO_LOCAL_CONFIG_ENV",
    "SECRET_NAME_PATTERNS",
    "SECRET_SEGMENT_PATTERNS",
    "TLS_ROUTING_KEYS",
    "is_secret_var_name",
]
