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

"""The EV config block: its defaults layer, its structure, and the shipped profiles —
plus the helpers other EV test files use to build one.

EV reads its knobs bare (``ev.parallel``, ``ev_module(cfg, "attacker").max_turns``) with
no inline fallback, because ``config._STEP_DEFAULTS["step6_exploit_verification"]`` is
merged UNDER whatever profile loads. That makes two silent failures possible, and this
file exists to make both loud:

  * a key a profile declares that the code never reads — a typo, or a knob renamed on one
    side only. It would sit in the YAML looking effective and do nothing.
  * a key the code reads that the defaults layer does not define — an ``AttributeError``
    mid-scan, on whichever profile omitted it.

Unlike ``test_validate_config_defaults.py``, this cannot compare VALUES across profiles:
``step_validate``'s are identical everywhere, whereas EV profiles deliberately differ
(``sdk.yaml`` runs a much larger request budget). So the assertions are structural.
"""
from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from vvaharness.config import Config, _deep_merge, _STEP_DEFAULTS, load
from vvaharness.exploit_verification.settings import (EV_MODULES, EVConfigError,
                                                      ev_module, ev_section)

_EV = "step6_exploit_verification"
#: Sentinel: a knob's value may legitimately be False or 0, so "absent" cannot be None.
_ABSENT = object()
_PROFILE_DIR = Path(__file__).resolve().parent.parent / "vvaharness" / "config" / "profiles"
# Derived from disk so adding or renaming a profile cannot silently drop it from the
# guard; the assert stops an empty glob from collapsing to a vacuous pass.
_PROFILES = sorted(p.stem for p in _PROFILE_DIR.glob("*.yaml"))
assert _PROFILES, f"no shipped profiles discovered under {_PROFILE_DIR}"

#: Names that moved into a module sub-block. A profile still carrying one at the top
#: level would be read as nothing at all, which is exactly the silent failure above.
_MOVED = {"adaptive_loop": "attacker.enabled", "max_turns": "attacker.max_turns"}


def _profile(name: str) -> dict:
    raw = yaml.safe_load((_PROFILE_DIR / f"{name}.yaml").read_text(encoding="utf-8"))
    return raw.get(_EV) or {}


def _leaves(block: dict, prefix: str = "") -> set[str]:
    """Dotted key paths for every scalar leaf, e.g. ``mapper.finding_map.chunk``."""
    out: set[str] = set()
    for key, value in block.items():
        path = f"{prefix}{key}"
        out |= _leaves(value, f"{path}.") if isinstance(value, dict) else {path}
    return out


# ── build an EV config block for a test, from the SAME defaults a real run gets ─────
#
# A test that hand-writes a partial block raises ``AttributeError`` on the first knob it
# forgot (bare reads, no inline fallback); a test that hand-writes a COMPLETE one silently
# rots the day a knob is added. Both are avoided by deriving the block from the defaults
# here, then merging the test's overrides over it.
#
# The block is nested (``classify``, ``mapper.finding_map``, ``attacker``, ``judge``), so
# overrides take dotted keys::
#
#     cfg = SimpleNamespace(models=..., step6_exploit_verification=ev_block(
#         parallel=1, **{"attacker.max_turns": 3}))
#
# Two shapes, because EV is read two ways: :func:`ev_block` returns a ``SimpleNamespace``
# tree (what most tests pass as a fake ``cfg``), and :func:`ev_config` returns a real
# :class:`~vvaharness.config.Config` (what ``load_options`` tests pass, matching the
# loader's own wrapper). Used across the EV test suite, not just in this file.

def _nest(overrides: dict) -> dict:
    """``{"attacker.max_turns": 3}`` -> ``{"attacker": {"max_turns": 3}}``."""
    out: dict = {}
    for dotted, value in overrides.items():
        node = out
        *parents, leaf = dotted.split(".")
        for part in parents:
            node = node.setdefault(part, {})
        node[leaf] = value
    return out


def ev_dict(**overrides) -> dict:
    """The full default EV block as a plain dict, with ``overrides`` merged over it."""
    return _deep_merge(copy.deepcopy(_STEP_DEFAULTS[_EV]), _nest(overrides))


def _ns(value):
    if isinstance(value, dict):
        return SimpleNamespace(**{k: _ns(v) for k, v in value.items()})
    return value


def ev_block(**overrides) -> SimpleNamespace:
    """The EV block as a ``SimpleNamespace`` tree — a stand-in for a loaded profile."""
    return _ns(ev_dict(**overrides))


def ev_config(_top: dict | None = None, **overrides) -> Config:
    """A :class:`Config` carrying the EV block, plus any other top-level keys.

    ``_top`` is merged at the ROOT (e.g. ``{"models": {...}}``), while ``**overrides``
    apply inside the EV block — the split keeps the common case, tweaking one EV knob,
    free of nesting boilerplate.
    """
    return Config(_deep_merge({_EV: ev_dict(**overrides)}, dict(_top or {})))


# ── the defaults layer ────────────────────────────────────────────────────────

def test_the_defaults_layer_defines_the_ev_block() -> None:
    assert _EV in _STEP_DEFAULTS, (
        "EV must register its defaults like every other step, or its bare reads "
        "(ev.parallel, …) break on a profile that omits a knob")


def test_the_module_sub_blocks_are_exactly_the_four_purposes() -> None:
    block = _STEP_DEFAULTS[_EV]
    nested = {k for k, v in block.items() if isinstance(v, dict)}
    assert nested == set(EV_MODULES), (
        "the behaviour sub-blocks and models.exploit_verification's roles must use the "
        "same four names — that pairing is the whole point of the split")


def test_no_moved_name_survives_at_the_top_level() -> None:
    for old in _MOVED:
        assert old not in _STEP_DEFAULTS[_EV]


# ── the shipped profiles ──────────────────────────────────────────────────────

@pytest.mark.parametrize("profile", _PROFILES)
def test_every_declared_key_is_one_the_code_defines(profile: str) -> None:
    """A key in a profile that the defaults layer does not know is dead config."""
    known = _leaves(_STEP_DEFAULTS[_EV])
    declared = _leaves(_profile(profile))
    unknown = {k for k in declared if k not in known}
    assert not unknown, (
        f"{profile}.yaml sets {sorted(unknown)} under {_EV}, which nothing reads — "
        f"either wire it up or delete it")


@pytest.mark.parametrize("profile", _PROFILES)
def test_no_profile_still_uses_a_moved_name(profile: str) -> None:
    block = _profile(profile)
    for old, new in _MOVED.items():
        assert old not in block, f"{profile}.yaml: {old} moved to {new}"


@pytest.mark.parametrize("profile", _PROFILES)
def test_a_loaded_profile_answers_every_knob_the_code_reads(profile: str) -> None:
    """The end-to-end guarantee: load the profile, then reach every leaf bare.

    ``taint.yaml`` declares only ``enabled`` on purpose, so this is also the test that
    the defaults layer really does fill a near-empty block.
    """
    ev = ev_section(load(str(_PROFILE_DIR / f"{profile}.yaml")))
    missing = []
    for dotted in sorted(_leaves(_STEP_DEFAULTS[_EV])):
        node = ev
        for part in dotted.split("."):
            node = getattr(node, part, _ABSENT)
            if node is _ABSENT:
                missing.append(dotted)
                break
    assert not missing, f"{profile}.yaml: unreadable after load — {missing}"


# ── the accessors ─────────────────────────────────────────────────────────────

def test_a_missing_block_raises_instead_of_defaulting() -> None:
    from vvaharness.config import Config
    with pytest.raises(EVConfigError, match="--config"):
        ev_section(Config({}))


def test_a_missing_sub_block_names_itself() -> None:
    from vvaharness.config import Config
    with pytest.raises(EVConfigError, match=r"attacker"):
        ev_module(Config({_EV: {"parallel": 1}}), "attacker")


def test_a_nested_stage_is_reachable_by_a_dotted_name() -> None:
    cfg = load(str(_PROFILE_DIR / "sdk.yaml"))
    assert ev_module(cfg, "mapper.finding_map").chunk == \
        _STEP_DEFAULTS[_EV]["mapper"]["finding_map"]["chunk"]


def test_the_master_switch_still_reads_without_a_block() -> None:
    """``enabled`` is deliberately tolerant: it is consulted at preflight on every scan,
    including ones that never reach EV and callers that never loaded a profile."""
    from vvaharness.exploit_verification import options
    assert options.profile_disabled(SimpleNamespace()) is False
    assert options.may_run(SimpleNamespace(), {}) is False
