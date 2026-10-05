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

"""Prompt-cache policy shared by the cli/sdk/openai backends, so no two can disagree about it."""
from __future__ import annotations

import sys
from collections.abc import Mapping

from vvaharness.backends.harness.provider_routing import routes_to_anthropic
from vvaharness.report.redact import redact
from vvaharness.util.tokens import TOKENS, unparsed_cache_keys

# Boundary margin applied to the ESTIMATE, not the floor: the content-aware estimator
# under-counts by up to ~1.35x against the real tokenizer, and the error is asymmetric in both
# providers' favour. On Anthropic an inert marker wastes one of 4 breakpoint slots (~nil) while
# refusing a cacheable block re-sends its whole prefix at full price on every later call (~7% of
# a measured s4 scan); on the OpenAI route a mis-estimate only picks a routing shard and changes
# no request field at all. So mark when the estimate is within its own error of the floor; well
# below it (estimate * margin < floor) the block is still refused.
CACHE_EST_MARGIN = 1.35

# Falsey YAML spellings of the kill switch. PyYAML parses an unquoted `off` as the boolean
# False, so the documented `cache_markers: off` arrives as False rather than the string.
_DISABLED_SPELLINGS = ("off", "false", "no", "0", "none")


PREFIX_CACHE_BREAKPOINT = "breakpoint"
PREFIX_CACHE_IMPLICIT = "implicit"
PREFIX_CACHE_NONE = "none"


def prefix_cache_class(via: str, *, model_id: str = "",
                       provider: str | None = None) -> str:
    """The prompt-prefix caching mechanism a route's requests can use.

    ``sdk`` places explicit cache_control breakpoints; ``openai`` rides the
    provider's implicit prefix cache; ``cli`` folds ``cache_prefix`` into the
    user turn with no mechanism behind it. ``deepagents`` follows its model
    routing (the same ``routes_to_anthropic`` the transport uses): breakpoints
    on the Anthropic branch, the gateway's implicit cache on OpenAI-compatible
    ones. Callers deciding whether to serialize shard siblings (S4's gate) key
    on this rather than on ``via`` literals, so the encoding lives in one
    place.
    """
    if via == "sdk":
        return PREFIX_CACHE_BREAKPOINT
    if via == "openai":
        return PREFIX_CACHE_IMPLICIT
    if via == "deepagents":
        if routes_to_anthropic(model_id, provider):
            return PREFIX_CACHE_BREAKPOINT
        return PREFIX_CACHE_IMPLICIT
    return PREFIX_CACHE_NONE


def markers_enabled(cfg: Mapping) -> bool:
    """Whether `cfg`'s `cache_markers` switch permits this route to emit cache markers/hints."""
    v = cfg.get("cache_markers", "on")
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() not in _DISABLED_SPELLINGS


def report_unparsed_cache_keys(usage: dict | None, parsed, *,
                               via: str, label: str) -> None:
    """Flag cache accounting `usage` reports under key names `parsed` does not cover.

    Without this a working cache reads as 0/0 in every artifact kept, because util/tokens.py
    coerces the names it knows with `or 0` — indistinguishable from an unhonoured marker. Key
    names only; values never print, since the gateway authors this payload.
    """
    keys = unparsed_cache_keys(usage, parsed)
    # Tolerate a TOKENS stand-in that only implements add() (test doubles patch exactly that).
    note = getattr(TOKENS, "note_cache_unparsed", None)
    if note is not None and note(keys, via=via):
        print(f"    [{label}] note: usage reports cache accounting under "
              f"unparsed key(s): {redact(', '.join(keys))} — not included in "
              f"cache_read/cache_write totals; counted in the cache_unparsed "
              f"bucket", file=sys.stderr)
