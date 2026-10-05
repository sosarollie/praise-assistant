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

"""Documented config values in the shipped profiles match what load() resolves.

The shipped profiles are documentation as much as configuration: their
comments state numeric values, cross-profile relations ("default.yaml raises
it to 25"), and inheritance claims ("these keys are deliberately NOT set
here"). A comment-cleanup audit found seven profile/defaults comments whose
stated values or facts were false at HEAD — every one written against a value
that later changed in the same or a sibling file, with no test linking them.

This file pins each number and relation those (now rewritten) comments state,
so the next value change fails a test instead of silently stranding prose.
It asserts three kinds of claim:

1. Registered defaults in ``_STEP_DEFAULTS`` equal the values the profile
   comments cite as "the registered default".
2. Each shipped profile, resolved through ``load()``, yields exactly the
   effective values its comments document — including keys the profile omits
   and inherits (default.yaml's step3 files/modules).
3. The inheritance claims themselves: a profile documented as omitting a key
   really omits it in raw YAML (otherwise "inherits the registered default"
   silently becomes a lie the loaded value cannot expose) — and the inherited
   value equals the registered one, which with (1) pins sdk/full/taint's
   effective frontier caps without restating them row by row.

It deliberately does NOT pin values no comment cites — that is
``test_config_stage_key_defaults.py``'s job — and it never touches the
cache-regime invariant pinned there (all four shipped profiles pre-declare
``cache_route: anthropic`` — the sibling test encodes exactly that).
"""
from pathlib import Path

import pytest
import yaml

from vvaharness.config import _STEP_DEFAULTS, load

_PROFILES_DIR = Path(__file__).resolve().parent.parent / "vvaharness" / "config" / "profiles"
_PROFILES = ("default", "sdk", "full", "taint")


def _load(profile: str):
    return load(_PROFILES_DIR / f"{profile}.yaml")


def _raw(profile: str) -> dict:
    return yaml.safe_load(
        (_PROFILES_DIR / f"{profile}.yaml").read_text(encoding="utf-8"))


# ── 1. Registered defaults the profile comments cite ────────────────────────
# "restates the registered default" (sdk/full taint_max_chunks,
# max_findings_per_run), "the registered default and sdk/full ship 3"
# (default.yaml step7), and the _STEP_DEFAULTS step3/step4 comments' own
# numbers. If one of these moves, the citing comments move with it.
_DOCUMENTED_REGISTERED = {
    ("step3", "taint_max_chunks"): 60,
    ("step3", "max_prompt_files"): 180,
    ("step3", "max_prompt_entry_points"): 60,
    ("step3", "max_prompt_sinks"): 80,
    ("step3", "max_prompt_modules"): 24,
    ("step3", "max_prompt_call_edges"): 80,
    ("step3", "max_prompt_notes_chars"): 2500,
    ("step4", "max_findings_per_run"): 10,
    # The _STEP_DEFAULTS step4 comment claims default.yaml no longer inherits
    # these two; the registered values are the legacy path it opts out of.
    ("step4", "taint_prompt_mode"): "discover",
    ("step4", "taint_runs"): None,
    ("step7_dedup", "line_tolerance"): 3,
}


@pytest.mark.parametrize("section,key,documented", [
    (s, k, v) for (s, k), v in _DOCUMENTED_REGISTERED.items()
])
def test_registered_default_matches_documented_value(section, key, documented):
    assert _STEP_DEFAULTS[section][key] == documented, (
        f"_STEP_DEFAULTS[{section!r}][{key!r}] no longer equals the value the "
        f"profile comments cite as 'the registered default' — update every "
        f"comment naming it (grep the profiles) alongside this table"
    )


# ── 2. Effective per-profile values the comments document ───────────────────
# One row per (profile, section, key, documented effective value). Rows for
# keys a profile OMITS pin the inherited value — the whole point of the
# frontier-cap documentation is that sdk/full/taint run 60/80/80 while
# default.yaml shows 200/200/200.
_DOCUMENTED_EFFECTIVE = [
    # taint_max_chunks: "120 under default/taint/full, registered 60 under sdk"
    ("default", "step3", "taint_max_chunks", 120),
    ("taint",   "step3", "taint_max_chunks", 120),
    ("sdk",     "step3", "taint_max_chunks", 60),
    ("full",    "step3", "taint_max_chunks", 120),
    # max_findings_per_run: registered default 10; all four shipped profiles raise it to 25
    ("default", "step4", "max_findings_per_run", 25),
    ("sdk",     "step4", "max_findings_per_run", 25),
    ("full",    "step4", "max_findings_per_run", 25),
    ("taint",   "step4", "max_findings_per_run", 25),
    # step3 prompt-frontier caps: default.yaml raises entry points/sinks/edges
    # to 200/200/200 and notes to 5000; files/modules agree across layers
    # (180/24, inherited — default.yaml sets neither).
    # ponytail: NO sdk/full/taint rows here. Their effective frontier values
    # are already pinned transitively: section 1 fixes the registered numbers
    # and test_frontier_keys_are_omitted_where_documented_as_inherited asserts
    # loaded == registered for the same 3 profiles × 6 keys, so 18 rows
    # repeating 60/80/80/180/24/2500 asserted nothing a failure could add.
    ("default", "step3", "max_prompt_entry_points", 200),
    ("default", "step3", "max_prompt_sinks", 200),
    ("default", "step3", "max_prompt_call_edges", 200),
    ("default", "step3", "max_prompt_notes_chars", 5000),
    ("default", "step3", "max_prompt_files", 180),
    ("default", "step3", "max_prompt_modules", 24),
    # line tolerances: default.yaml's step5 comment now says S5 EQUALS S7 (5);
    # full.yaml ships 5 as well, and only sdk.yaml still ships the registered 3.
    ("default", "step5_prefilter", "line_tolerance", 5),
    ("default", "step7_dedup", "line_tolerance", 5),
    ("sdk",     "step7_dedup", "line_tolerance", 3),
    ("full",    "step7_dedup", "line_tolerance", 5),
    # step4.runs relations cited by the step5_prefilter headers: voting is on
    # in full (runs 3) and off in default/sdk/taint (runs 1).
    ("default", "step4", "runs", 1),
    ("taint",   "step4", "runs", 1),
    ("sdk",     "step4", "runs", 1),
    ("full",    "step4", "runs", 3),
    # The rewritten _STEP_DEFAULTS step4 comment: default.yaml (and taint.yaml)
    # explicitly opt out of the legacy discover taint path.
    ("default", "step4", "taint_prompt_mode", "confirm_refute"),
    ("default", "step4", "taint_runs", 1),
    ("taint",   "step4", "taint_prompt_mode", "confirm_refute"),
    ("taint",   "step4", "taint_runs", 1),
]


@pytest.mark.parametrize("profile,section,key,documented", _DOCUMENTED_EFFECTIVE)
def test_loaded_profile_matches_documented_effective_value(
        profile, section, key, documented):
    cfg = _load(profile)
    got = getattr(getattr(cfg, section), key)
    assert got == documented, (
        f"{profile}.yaml resolves {section}.{key} to {got!r}, but its (or a "
        f"sibling profile's) comment documents {documented!r} — fix the "
        f"comment(s) and this row together, never one without the other"
    )


# ── 3. The inheritance claims themselves ─────────────────────────────────────

_FRONTIER_KEYS = (
    "max_prompt_files", "max_prompt_entry_points", "max_prompt_sinks",
    "max_prompt_modules", "max_prompt_call_edges", "max_prompt_notes_chars",
)


@pytest.mark.parametrize("profile", ("sdk", "taint"))
def test_frontier_keys_are_omitted_where_documented_as_inherited(profile):
    """sdk/taint step3 comments say the prompt-frontier caps are
    'deliberately NOT set in this profile' and inherited from _STEP_DEFAULTS.
    If someone adds one of the keys, the inheritance prose (and the
    _STEP_DEFAULTS step3 comment naming these profiles) goes stale — update
    both alongside the profile change.

    full.yaml is deliberately NOT in this list: it now sets all six frontier
    caps explicitly, so it inherits nothing to assert. Its own step3 comment
    documents the explicit values instead.
    """
    raw_step3 = _raw(profile).get("step3") or {}
    for key in _FRONTIER_KEYS:
        assert key not in raw_step3, (
            f"{profile}.yaml now sets step3.{key} explicitly — its step3 "
            f"frontier-caps comment (and the _STEP_DEFAULTS one) still claim "
            f"the key is omitted and inherited"
        )
        # …and the inherited value really is the registered one.
        assert getattr(_load(profile).step3, key) == _STEP_DEFAULTS["step3"][key]


def test_default_yaml_detection_is_deepagents_routed():
    """default.yaml's step5 comment attributes runs:1 to deliberate choice, NOT
    to a CLI temperature limitation, because the deepdive role is not via:cli.
    The flagship's detection roles now all route via:deepagents (provider
    anthropic) rather than via:sdk. If that route changes, those comments —
    and the credential guidance in README/docs, which names the deepagents
    credential for S1-S9 — must change with this pin.
    """
    raw = _raw("default")
    assert raw["models"]["deepdive"]["via"] == "deepagents"
    assert raw["models"]["deepdive"]["provider"] == "anthropic"
    # The point of the original pin: whatever the route, it must not be via:cli,
    # or the step5 comment's reasoning about temperature/voting breaks.
    assert raw["models"]["deepdive"]["via"] != "cli"


def test_default_and_taint_opt_out_of_legacy_taint_path_in_yaml():
    """The _STEP_DEFAULTS step4 comment claims default.yaml and taint.yaml set
    taint_prompt_mode/taint_runs explicitly rather than inheriting the legacy
    discover path. Assert against raw YAML, not the loaded config, because the
    loaded value cannot distinguish 'set explicitly' from 'inherited'."""
    for profile in ("default", "taint"):
        raw_step4 = _raw(profile).get("step4") or {}
        assert raw_step4.get("taint_prompt_mode") == "confirm_refute", profile
        assert raw_step4.get("taint_runs") == 1, profile
