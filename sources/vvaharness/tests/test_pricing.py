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

"""Unit tests for vvaharness.util.pricing — price-table loading + arithmetic.

Offline and deterministic: tables are written to tmp_path, and the
VVAHARNESS_PRICING_FILE environment variable is set via monkeypatch only.
"""
from __future__ import annotations

import hashlib

import pytest

from vvaharness.util import pricing as pr

_TABLE = """
models:
  model-a:
    input_per_mtok: 3.0
    output_per_mtok: 15.0
    cache_read_per_mtok: 0.3
    cache_creation_per_mtok: 3.75
  model-b:
    input_per_mtok: 1.0
    output_per_mtok: 2.0
"""


def _write(tmp_path, name="pricing.yaml", body=_TABLE):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# load_pricing — precedence and provenance
# ---------------------------------------------------------------------------

def test_no_table_configured_returns_none(monkeypatch):
    monkeypatch.delenv(pr.PRICING_FILE_ENV, raising=False)
    assert pr.load_pricing(None) is None


def test_config_key_is_used_when_env_unset(tmp_path, monkeypatch):
    monkeypatch.delenv(pr.PRICING_FILE_ENV, raising=False)
    table = pr.load_pricing(str(_write(tmp_path)))
    assert table is not None
    assert table.source == "config"
    assert set(table.models) == {"model-a", "model-b"}


def test_env_overrides_config_key(tmp_path, monkeypatch):
    env_file = _write(tmp_path, "env.yaml",
                      "models:\n  only-env:\n    input_per_mtok: 1\n"
                      "    output_per_mtok: 2\n")
    cfg_file = _write(tmp_path, "cfg.yaml")
    monkeypatch.setenv(pr.PRICING_FILE_ENV, str(env_file))

    table = pr.load_pricing(str(cfg_file))

    assert table is not None
    assert table.source == "env"
    assert table.path == str(env_file)
    assert set(table.models) == {"only-env"}


def test_blank_env_value_falls_back_to_config(tmp_path, monkeypatch):
    monkeypatch.setenv(pr.PRICING_FILE_ENV, "   ")
    table = pr.load_pricing(str(_write(tmp_path)))
    assert table is not None and table.source == "config"


def test_sha256_matches_file_bytes(tmp_path, monkeypatch):
    monkeypatch.delenv(pr.PRICING_FILE_ENV, raising=False)
    path = _write(tmp_path)
    table = pr.load_pricing(str(path))
    assert table is not None
    assert table.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# load_pricing — degradation (a bad table must never fail a scan)
# ---------------------------------------------------------------------------

def test_missing_file_warns_and_returns_none(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(pr.PRICING_FILE_ENV, raising=False)
    assert pr.load_pricing(str(tmp_path / "absent.yaml")) is None
    assert "[pricing] WARNING" in capsys.readouterr().err


def test_malformed_yaml_warns_and_returns_none(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(pr.PRICING_FILE_ENV, raising=False)
    bad = _write(tmp_path, "bad.yaml", "models: [unclosed\n")
    assert pr.load_pricing(str(bad)) is None
    assert "[pricing] WARNING" in capsys.readouterr().err


def test_table_without_models_mapping_returns_none(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(pr.PRICING_FILE_ENV, raising=False)
    empty = _write(tmp_path, "empty.yaml", "other_key: 1\n")
    assert pr.load_pricing(str(empty)) is None
    assert "no usable model rates" in capsys.readouterr().err


def test_entries_missing_required_rates_are_dropped(tmp_path, monkeypatch):
    monkeypatch.delenv(pr.PRICING_FILE_ENV, raising=False)
    partial = _write(
        tmp_path, "partial.yaml",
        "models:\n"
        "  good:\n    input_per_mtok: 1\n    output_per_mtok: 2\n"
        "  no-output:\n    input_per_mtok: 1\n"
        "  not-a-mapping: 7\n"
        "  bool-rate:\n    input_per_mtok: true\n    output_per_mtok: 2\n")
    table = pr.load_pricing(str(partial))
    assert table is not None
    assert set(table.models) == {"good"}


# ---------------------------------------------------------------------------
# bucket_cost_usd
# ---------------------------------------------------------------------------

def test_bucket_cost_splits_fresh_input_from_cache_write():
    # prompt is fresh+cache_write, so 1_000_000 prompt with 400_000 cache_write
    # is 600_000 fresh at 3.00 and 400_000 writes at 3.75.
    p = pr.ModelPricing(input_per_mtok=3.0, output_per_mtok=15.0,
                        cache_read_per_mtok=0.3, cache_creation_per_mtok=3.75)
    bucket = pr.TokenBucket(prompt=1_000_000, completion=200_000,
                            cache_read=500_000, cache_write=400_000, calls=3)

    cost = pr.bucket_cost_usd(bucket, p)

    expected = 0.6 * 3.0 + 0.4 * 3.75 + 0.5 * 0.3 + 0.2 * 15.0
    assert cost == pytest.approx(expected)


def test_bucket_cost_missing_cache_write_rate_derives_125pct_of_input():
    # cache_creation_per_mtok omitted: writes bill at 125% of the input rate,
    # not the plain input rate (which would silently under-report by 20%).
    p = pr.ModelPricing(input_per_mtok=2.0, output_per_mtok=4.0)
    bucket = pr.TokenBucket(prompt=1_000_000, cache_write=1_000_000,
                            completion=0, cache_read=0)
    assert pr.bucket_cost_usd(bucket, p) == pytest.approx(2.0 * 1.25)


def test_bucket_cost_missing_cache_read_rate_derives_10pct_of_input():
    # Regression: cache_read_per_mtok omitted used to cost reads at zero,
    # making cached runs look free in the manifest. Reads must bill at 10%
    # of the input rate.
    p = pr.ModelPricing(input_per_mtok=2.0, output_per_mtok=4.0)
    bucket = pr.TokenBucket(prompt=0, cache_write=0, completion=0,
                            cache_read=5_000_000)
    cost = pr.bucket_cost_usd(bucket, p)
    assert cost > 0.0
    assert cost == pytest.approx(5.0 * 2.0 * 0.10)


def test_bucket_cost_explicit_cache_rates_win_over_derived_defaults():
    # Rates that differ from the derived 10%/125% defaults must be used
    # verbatim — the derivation only fills gaps.
    p = pr.ModelPricing(input_per_mtok=2.0, output_per_mtok=4.0,
                        cache_read_per_mtok=0.5, cache_creation_per_mtok=3.0)
    bucket = pr.TokenBucket(prompt=1_000_000, cache_write=1_000_000,
                            completion=0, cache_read=1_000_000)
    assert pr.bucket_cost_usd(bucket, p) == pytest.approx(3.0 + 0.5)


def test_bucket_cost_explicit_zero_cache_write_rate_is_honored():
    # Some providers charge no cache-write fee; an explicit 0 must be used
    # verbatim, not treated as absent and replaced by the derived 125%.
    p = pr.ModelPricing(input_per_mtok=2.0, output_per_mtok=4.0,
                        cache_read_per_mtok=0.2, cache_creation_per_mtok=0.0)
    bucket = pr.TokenBucket(prompt=1_000_000, cache_write=1_000_000,
                            completion=0, cache_read=0)
    assert pr.bucket_cost_usd(bucket, p) == 0.0


def test_table_omitting_cache_rates_notes_derivation(tmp_path, monkeypatch,
                                                     capsys):
    # The manifest never records per-model rates, so the load-time stderr
    # note is the only surface where the operator learns rates were derived.
    monkeypatch.delenv(pr.PRICING_FILE_ENV, raising=False)
    table = pr.load_pricing(str(_write(tmp_path)))
    assert table is not None
    err = capsys.readouterr().err
    assert "model-b omits cache_read_per_mtok, cache_creation_per_mtok" in err
    assert "model-a omits" not in err  # fully specified: no note


def test_bucket_cost_zero_tokens_is_zero():
    p = pr.ModelPricing(input_per_mtok=3.0, output_per_mtok=15.0)
    assert pr.bucket_cost_usd(pr.TokenBucket(), p) == 0.0


def test_bucket_cost_never_negative_when_cache_write_exceeds_prompt():
    p = pr.ModelPricing(input_per_mtok=3.0, output_per_mtok=15.0,
                        cache_creation_per_mtok=3.0)
    bucket = pr.TokenBucket(prompt=100, cache_write=900, completion=0,
                            cache_read=0)
    assert pr.bucket_cost_usd(bucket, p) == 900 * 3.0 / 1_000_000


# ---------------------------------------------------------------------------
# config default
# ---------------------------------------------------------------------------

def test_config_exposes_pricing_file_default(tmp_path):
    from vvaharness import config as config_mod

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("models: {}\n", encoding="utf-8")
    cfg = config_mod.load(cfg_path)
    assert cfg.pricing.file is None


# ── table-declared cache derivation multipliers ─────────────────────────────
# The module-level fallbacks are Anthropic's 5-minute-TTL economics (reads at
# 0.10x input, writes at 1.25x). Applying those to OpenAI is wrong twice over:
# most OpenAI models bill NOTHING to create a cache entry, so a derived write
# rate invents a cost; and the read discount is 0.10x on gpt-5.x but 0.25x on
# gpt-4.1/o3 and 0.50x on gpt-4o, so one global fraction cannot serve a mixed
# table. `cache_rate_defaults` lets the table decide instead of this module.

def _write_table(tmp_path, body: str):
    p = tmp_path / "prices.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_cache_rate_defaults_are_read_from_the_table(tmp_path, monkeypatch):
    monkeypatch.setenv(pr.PRICING_FILE_ENV, str(_write_table(tmp_path, """
cache_rate_defaults:
  read_fraction: 0.5
  write_multiplier: 0
models:
  gpt-4o:
    input_per_mtok: 2.5
    output_per_mtok: 10.0
""")))
    table = pr.load_pricing(None)
    assert table is not None
    assert table.cache_defaults.read_fraction == 0.5
    assert table.cache_defaults.write_multiplier == 0
    assert table.cache_defaults.is_fallback is False


def test_declared_defaults_change_the_cost(tmp_path, monkeypatch):
    """gpt-4o: reads bill at 0.50x input and writes are free. Costing it with
    the Anthropic-shaped fallback would understate reads 5x and invent a write
    charge that does not exist."""
    monkeypatch.setenv(pr.PRICING_FILE_ENV, str(_write_table(tmp_path, """
cache_rate_defaults:
  read_fraction: 0.5
  write_multiplier: 0
models:
  gpt-4o:
    input_per_mtok: 2.5
    output_per_mtok: 10.0
""")))
    table = pr.load_pricing(None)
    rate = table.models["gpt-4o"]
    bucket = pr.TokenBucket(prompt=1_000_000, cache_write=1_000_000,
                            cache_read=1_000_000, completion=0)
    # fresh = prompt - cache_write = 0; write at 0; read at 0.50 * 2.5 = 1.25
    assert pr.bucket_cost_usd(bucket, rate, table.cache_defaults) \
        == pytest.approx(1.25)
    # Without the table's defaults the module fallback applies: write at
    # 1.25 * 2.5 = 3.125, read at 0.10 * 2.5 = 0.25 -> 3.375. Far off.
    assert pr.bucket_cost_usd(bucket, rate) == pytest.approx(3.375)


def test_partial_defaults_block_keeps_the_other_fallback(tmp_path, monkeypatch):
    # Declaring only "writes are free" must not force restating the read rate.
    monkeypatch.setenv(pr.PRICING_FILE_ENV, str(_write_table(tmp_path, """
cache_rate_defaults:
  write_multiplier: 0
models:
  gpt-5.5:
    input_per_mtok: 5.0
    output_per_mtok: 15.0
""")))
    table = pr.load_pricing(None)
    assert table.cache_defaults.write_multiplier == 0
    assert table.cache_defaults.read_fraction == pr.FALLBACK_CACHE_READ_FRACTION
    assert table.cache_defaults.is_fallback is False


def test_absent_defaults_block_falls_back_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv(pr.PRICING_FILE_ENV, str(_write_table(tmp_path, """
models:
  claude-sonnet-4-6:
    input_per_mtok: 3.0
    output_per_mtok: 15.0
""")))
    table = pr.load_pricing(None)
    assert table.cache_defaults.is_fallback is True
    assert table.cache_defaults.read_fraction == pr.FALLBACK_CACHE_READ_FRACTION
    assert table.cache_defaults.write_multiplier == pr.FALLBACK_CACHE_WRITE_MULTIPLIER


def test_explicit_per_model_rate_still_beats_any_default(tmp_path, monkeypatch):
    # Per-model rates are the only correct answer for a table mixing families.
    monkeypatch.setenv(pr.PRICING_FILE_ENV, str(_write_table(tmp_path, """
cache_rate_defaults:
  read_fraction: 0.10
models:
  gpt-4o:
    input_per_mtok: 2.5
    output_per_mtok: 10.0
    cache_read_per_mtok: 1.25
    cache_creation_per_mtok: 0
""")))
    table = pr.load_pricing(None)
    rate = table.models["gpt-4o"]
    bucket = pr.TokenBucket(prompt=0, cache_read=1_000_000)
    assert pr.bucket_cost_usd(bucket, rate, table.cache_defaults) \
        == pytest.approx(1.25)


def test_derivation_note_names_the_multipliers_and_their_origin(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(pr.PRICING_FILE_ENV, str(_write_table(tmp_path, """
models:
  claude-sonnet-4-6:
    input_per_mtok: 3.0
    output_per_mtok: 15.0
""")))
    pr.load_pricing(None)
    err = capsys.readouterr().err
    assert "reads x0.1" in err and "writes x1.25" in err
    # The operator must be told the assumption is provider-shaped, not neutral.
    assert "Anthropic-shaped" in err
