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

"""Regression guard against committed secrets in the shipped profiles.

Every credential-bearing field must be a pure ``${VAR}`` / ``${VAR:-default}``
placeholder (read from the environment at load time) — never a literal token.
Reads the raw YAML (no env expansion) so a real value would be caught even if
the matching env var happened to be set."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_PROFILE_DIR = Path(__file__).resolve().parent.parent / "vvaharness" / "config" / "profiles"
# Derive the guarded set from the shipped profiles on disk so a rename/add can
# never silently drop a profile from the guard (the exact regression that broke
# this test when cli.yaml was renamed to sdk.yaml). The assert keeps an empty
# glob from collapsing to zero parametrized cases (a vacuous pass).
_PROFILES = sorted(p.stem for p in _PROFILE_DIR.glob("*.yaml"))
assert _PROFILES, f"no shipped profiles discovered under {_PROFILE_DIR}"


# The ENTIRE value must be a single ${VAR} or ${VAR:-<fallback>} placeholder — nothing else.
# The optional ``:-`` fallback may ONLY be empty or another ${VAR} reference; a literal
# fallback is rejected because that is the exact channel a real secret leaked through before
# (commit 5285132: ${VAR:-eyJ...}).
_PLACEHOLDER_RE = re.compile(
    r"^\$\{[A-Z_][A-Z0-9_]*(?::-(?:\$\{[A-Z_][A-Z0-9_]*\})?)?\}$"
)

# (section, key) pairs that carry credentials / tokens / certs / internal endpoints.
_CREDENTIAL_FIELDS = [
    ("sdk", "api_key"),
    ("sdk", "base_url"),
    ("sdk", "ca_cert"),
    ("sdk", "client_cert"),
    ("openai", "api_key"),
    ("openai", "base_url"),
    ("openai", "ca_cert"),
    ("cli", "ca_cert"),
    ("batch", "git_token"),
    ("batch", "git_base_url"),
]


def _is_safe(value: object) -> bool:
    """Safe = absent, empty, or a pure ${VAR}/${VAR:-} placeholder (never a literal secret)."""
    if value is None or value == "":
        return True
    return bool(_PLACEHOLDER_RE.match(str(value)))


@pytest.mark.parametrize("profile", _PROFILES)
@pytest.mark.parametrize(("section", "key"), _CREDENTIAL_FIELDS)
def test_credential_field_is_placeholder(profile: str, section: str, key: str) -> None:
    data = yaml.safe_load((_PROFILE_DIR / f"{profile}.yaml").read_text(encoding="utf-8")) or {}
    value = (data.get(section) or {}).get(key)
    assert _is_safe(value), (
        f"{profile}.yaml [{section}.{key}] = {value!r} — must be a ${{VAR}} placeholder, "
        f"not a literal secret"
    )
