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

"""One-shot stderr warnings: print a message at most once per key.

The single check-membership / record / print mechanism behind every
"warn once per <thing> per process" site (legacy kwargs and zero-usage tags in
``backends.llm.deepagents``, unknown tool names in
``backends.harness.deepagents.tools``, usage-contract violations in
``backends.harness.deepagents.usage``, permission problems in
``orchestrator.store``, the markers-withheld-on-unrecognised-route note in
``backends.llm.sdk``). Each caller owns its ``seen`` set, keeping warn-once
scopes independent, tests free to clear or replace one site's registry without
touching the others, and a batch driver able to reset a specific scope between
repos by clearing its set — or all of them at once via
:func:`reset_warn_once_registries`, which ``orchestrator.batch`` calls between
repos and between app-groups.
"""

from __future__ import annotations

import sys

__all__ = ["warn_once", "reset_warn_once_registries"]


def warn_once(seen: set[str], key: str, message: str) -> None:
    """Print *message* to stderr the first time *key* appears in *seen*.

    *seen* is the caller's registry: subsequent calls with the same key are
    silent until the caller clears it. Never raises — a diagnostic must not
    abort a scan.
    """
    if key in seen:
        return
    seen.add(key)
    print(message, file=sys.stderr)


# Every warn-once registry in the process, by owning module and attribute
# name. The sets deliberately KEEP living in their owning modules — tests pin
# them by name (``store._PERM_WARNED``, ``da_tools._WARNED_UNKNOWN_TOOLS``) —
# so this table only records where they live; it never re-homes them. The
# ``sys.modules`` lookup (instead of an import) keeps this module import-light:
# a module that was never imported has never warned, so there is nothing to
# clear — and importing ``backends.llm.deepagents`` here would drag the
# langchain/deepagents stack into every ``vvaharness.cli`` start-up.
_REGISTRY_SITES: tuple[tuple[str, str], ...] = (
    ("vvaharness.backends.llm.deepagents", "_NO_USAGE_WARNED_TAGS"),
    ("vvaharness.backends.llm.deepagents", "_WARNED_LEGACY_KW"),
    ("vvaharness.backends.llm.sdk", "_CACHE_ROUTE_NOTED"),
    ("vvaharness.backends.harness.deepagents.tools", "_WARNED_UNKNOWN_TOOLS"),
    ("vvaharness.backends.harness.deepagents.usage", "_EXCLUSIVE_USAGE_WARNED"),
    ("vvaharness.backends.harness.deepagents.client", "_EFFORT_UNSUPPORTED_WARNED"),
    ("vvaharness.backends.harness.deepagents.client", "_TRANSPORT_FALLBACK_WARNED"),
    ("vvaharness.orchestrator.store", "_PERM_WARNED"),
)


def reset_warn_once_registries() -> None:
    """Clear every warn-once registry in place (set identity preserved).

    Called by the batch driver between repos and between app-groups so repo
    N>1 gets the same one-shot diagnostics as repo 1 — most importantly the
    deepagents "no token usage recorded" WARN, which is the only signal that
    a stage's usage went unrecorded on that route. Clearing in place keeps
    every per-module name valid for the tests that pin them.
    """
    for mod_name, attr in _REGISTRY_SITES:
        mod = sys.modules.get(mod_name)
        if mod is None:
            continue  # never imported → never warned → nothing to clear
        reg = getattr(mod, attr, None)
        if isinstance(reg, set):
            reg.clear()
