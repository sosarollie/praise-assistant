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

"""Operator-supplied model price table used to cost a run's token counts.

vvaharness bundles no price list: rates differ per account, per gateway and
over time, so a shipped table would go stale and quietly misreport spend. An
operator points the tool at their own YAML table with the
``VVAHARNESS_PRICING_FILE`` environment variable or the ``pricing.file`` config
key (env wins); with neither set the run manifest reports token counts and
leaves every ``cost_usd`` null.

Table schema — rates are US dollars per million tokens, keyed by the exact
model id the run resolves::

    models:
      claude-sonnet-4-6:
        input_per_mtok: 3.0
        output_per_mtok: 15.0
        cache_read_per_mtok: 0.30
        cache_creation_per_mtok: 3.75

``cache_read_per_mtok`` and ``cache_creation_per_mtok`` are optional; a missing
rate is derived from ``input_per_mtok`` and a stderr note records it. Setting
them explicitly is strongly preferred, because cache multipliers are
PROVIDER- and MODEL-specific and no single derivation is right for all of them.
An explicit ``0`` is honored, for providers that charge no cache-write fee.

When a table omits them, the derivation multipliers themselves are declarable,
so no provider's economics are baked into this module::

    cache_rate_defaults:      # optional; applies to every model in the table
      read_fraction: 0.10     # cache read as a fraction of input_per_mtok
      write_multiplier: 1.25  # cache write as a multiple of input_per_mtok
    models:
      ...

Published multipliers at the time of writing, for operators filling a table in
(verify against your own provider's current pricing — these move):

===================================  ==========  =============
model family                         cache read  cache write
===================================  ==========  =============
Anthropic Claude                     0.10x       1.25x (5-min TTL), 2.0x (1-hour)
OpenAI gpt-5.x                       0.10x       no write fee -> 0
OpenAI gpt-4.1 / o3 / o4-mini        0.25x       no write fee -> 0
OpenAI gpt-4o / o1 / o3-mini         0.50x       no write fee -> 0
OpenAI GPT-5.6 family                0.10x       1.25x (writes ARE billed)
===================================  ==========  =============

Two traps worth naming. A single global ``read_fraction`` cannot be right for a
table mixing gpt-4o (0.50x) with gpt-5.x (0.10x) — per-model
``cache_read_per_mtok`` is the only correct answer there. And most OpenAI models
charge nothing to create a cache entry, so a derived write rate invents a cost
that does not exist; set ``cache_creation_per_mtok: 0`` for them.

Pricing is best-effort reporting and must never fail a scan: an unreadable or
malformed table degrades to ``None`` with a stderr warning.
"""
from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

import yaml

PRICING_FILE_ENV = "VVAHARNESS_PRICING_FILE"
_PER_MTOK = 1_000_000.0

# Last-resort derivation multipliers, used only when the table declares neither
# a per-model rate nor `cache_rate_defaults`. SOME number is unavoidable here:
# costing cached tokens at zero silently under-reports every cached run, and
# refusing to cost would null out tables that are valid under the documented
# schema. These particular values are Anthropic's 5-minute-TTL economics, which
# is a real limitation rather than a neutral choice — they are wrong for most
# OpenAI models, where reads range 0.10x-0.50x by family and writes are usually
# free. That is why `cache_rate_defaults` exists and why the load path warns per
# model when it falls back this far.
FALLBACK_CACHE_READ_FRACTION = 0.10
FALLBACK_CACHE_WRITE_MULTIPLIER = 1.25


@dataclass(frozen=True)
class CacheRateDefaults:
    """Table-declared multipliers for deriving absent cache rates."""

    read_fraction: float = FALLBACK_CACHE_READ_FRACTION
    write_multiplier: float = FALLBACK_CACHE_WRITE_MULTIPLIER
    #: True when both values came from this module rather than the table, so
    #: the load path can say so and the operator can see the assumption.
    is_fallback: bool = True


class TokenBucket(TypedDict, total=False):
    """One ``util.tokens`` per-phase bucket — the unit of costing."""

    prompt: int
    completion: int
    cache_read: int
    cache_write: int
    calls: int


@dataclass(frozen=True)
class ModelPricing:
    """Dollar rates per million tokens for one exact model id."""

    input_per_mtok: float
    output_per_mtok: float
    cache_read_per_mtok: float | None = None
    cache_creation_per_mtok: float | None = None


@dataclass(frozen=True)
class PricingTable:
    """A loaded price table plus the provenance recorded in the manifest."""

    models: dict[str, ModelPricing]
    path: str
    sha256: str
    source: str
    cache_defaults: CacheRateDefaults = CacheRateDefaults()


def _rate(raw: Mapping[str, object], key: str) -> float | None:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _model_pricing(raw: object) -> ModelPricing | None:
    if not isinstance(raw, Mapping):
        return None
    inp = _rate(raw, "input_per_mtok")
    out = _rate(raw, "output_per_mtok")
    if inp is None or out is None:
        return None
    return ModelPricing(
        input_per_mtok=inp,
        output_per_mtok=out,
        cache_read_per_mtok=_rate(raw, "cache_read_per_mtok"),
        cache_creation_per_mtok=_rate(raw, "cache_creation_per_mtok"),
    )


def _parse_cache_defaults(data: object) -> CacheRateDefaults:
    """Read optional table-level ``cache_rate_defaults``.

    A partially-specified block is honored field by field: declaring only
    ``write_multiplier: 0`` is a legitimate way to say "this provider charges
    nothing for cache writes" without also having to restate the read fraction.
    """
    if not isinstance(data, Mapping):
        return CacheRateDefaults()
    raw = data.get("cache_rate_defaults")
    if not isinstance(raw, Mapping):
        return CacheRateDefaults()
    read = _rate(raw, "read_fraction")
    write = _rate(raw, "write_multiplier")
    if read is None and write is None:
        return CacheRateDefaults()
    return CacheRateDefaults(
        read_fraction=(FALLBACK_CACHE_READ_FRACTION if read is None else read),
        write_multiplier=(FALLBACK_CACHE_WRITE_MULTIPLIER
                          if write is None else write),
        is_fallback=False,
    )


def _parse_models(data: object) -> dict[str, ModelPricing]:
    if not isinstance(data, Mapping):
        return {}
    raw_models = data.get("models")
    if not isinstance(raw_models, Mapping):
        return {}
    out: dict[str, ModelPricing] = {}
    for name, spec in raw_models.items():
        priced = _model_pricing(spec)
        if isinstance(name, str) and priced is not None:
            out[name] = priced
    return out


def _table_from_file(path: Path, source: str) -> PricingTable | None:
    try:
        blob = path.read_bytes()
        data: object = yaml.safe_load(blob.decode("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        print(f"  [pricing] WARNING: ignoring price table {path}: {e}",
              file=sys.stderr)
        return None
    models = _parse_models(data)
    if not models:
        print(f"  [pricing] WARNING: no usable model rates in {path}; "
              f"costs will be reported as null", file=sys.stderr)
        return None
    defaults = _parse_cache_defaults(data)
    # The manifest records only the table's provenance, not per-model rates, so
    # this stderr note is the operator's one chance to see that cache tokens
    # will be costed at derived rates. The multipliers are named explicitly, and
    # a fallback to this module's values says so — those are Anthropic-shaped
    # and wrong for most OpenAI models, which is worth surfacing rather than
    # burying.
    for name, priced in models.items():
        omitted = [field for field, rate in
                   (("cache_read_per_mtok", priced.cache_read_per_mtok),
                    ("cache_creation_per_mtok", priced.cache_creation_per_mtok))
                   if rate is None]
        if not omitted:
            continue
        origin = ("built-in fallback — Anthropic-shaped, verify it suits this "
                  "model's provider" if defaults.is_fallback
                  else "from cache_rate_defaults")
        print(f"  [pricing] NOTE: {name} omits {', '.join(omitted)}; deriving "
              f"from input_per_mtok at reads x{defaults.read_fraction:g}, "
              f"writes x{defaults.write_multiplier:g} ({origin})",
              file=sys.stderr)
    return PricingTable(models=models, path=str(path),
                        sha256=hashlib.sha256(blob).hexdigest(), source=source,
                        cache_defaults=defaults)


def _selected_source(cfg_pricing_file: str | None) -> tuple[str, str] | None:
    env_path = os.environ.get(PRICING_FILE_ENV, "").strip()
    if env_path:
        return env_path, "env"
    if cfg_pricing_file:
        return str(cfg_pricing_file), "config"
    return None


def load_pricing(cfg_pricing_file: str | None) -> PricingTable | None:
    """Load the active price table, or ``None`` when costing is unavailable.

    Args:
        cfg_pricing_file: The ``pricing.file`` config value, if any. The
            ``VVAHARNESS_PRICING_FILE`` environment variable overrides it.

    Returns:
        The parsed table, or ``None`` when no table is configured, the file
        cannot be read/parsed, or it declares no usable model rates.
    """
    selected = _selected_source(cfg_pricing_file)
    if selected is None:
        return None
    raw_path, source = selected
    return _table_from_file(Path(raw_path).expanduser(), source)


def bucket_cost_usd(bucket: TokenBucket, pricing: ModelPricing,
                    cache_defaults: CacheRateDefaults | None = None) -> float:
    """Cost one token bucket at *pricing*'s rates.

    ``prompt`` is billable input — fresh plus cache-write, per
    :mod:`vvaharness.util.tokens` — so the fresh share is
    ``prompt - cache_write``.

    Args:
        bucket: A ``util.tokens`` bucket (``prompt``/``completion``/
            ``cache_read``/``cache_write``).
        pricing: Rates for the model that produced the bucket. An explicit
            cache rate always wins, including an explicit ``0``.
        cache_defaults: Multipliers for deriving cache rates the model omits —
            normally ``PricingTable.cache_defaults``, so the operator's table
            decides. Omit only when costing a standalone ``ModelPricing``; the
            module fallback then applies, which is Anthropic-shaped and wrong
            for most OpenAI models.

    Returns:
        The bucket's cost in US dollars.
    """
    d = cache_defaults or CacheRateDefaults()
    cache_write = bucket.get("cache_write", 0)
    fresh = max(bucket.get("prompt", 0) - cache_write, 0)
    write_rate = (pricing.input_per_mtok * d.write_multiplier
                  if pricing.cache_creation_per_mtok is None
                  else pricing.cache_creation_per_mtok)
    read_rate = (pricing.input_per_mtok * d.read_fraction
                 if pricing.cache_read_per_mtok is None
                 else pricing.cache_read_per_mtok)
    total = (fresh * pricing.input_per_mtok
             + cache_write * write_rate
             + bucket.get("cache_read", 0) * read_rate
             + bucket.get("completion", 0) * pricing.output_per_mtok)
    return total / _PER_MTOK
