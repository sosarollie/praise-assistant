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

"""Stage configuration keys are registered with their defaults.

``Config`` is not a permissive attribute bag: ``Config.__getattr__`` raises
``AttributeError`` for any key absent from the loaded mapping
(config/__init__.py:56-67). So the silence this file guards against does not
come from ``Config`` swallowing typos. It comes from the pipeline's call
convention, ``getattr(cfg.stepN, key, default)``, which substitutes ``default``
for any unknown key — typo or otherwise — with no error at all.

Registering a key in ``_STEP_DEFAULTS`` does not change that convention. What it
buys is that the key flows through ``_deep_merge(_STEP_DEFAULTS, raw)``
(in ``load``, `~config/__init__.py:272`) as the base for *every* profile, including
user-authored ones that never mention it, rather than only the shipped profiles
that happen to set it. An unregistered key is therefore undiscoverable and
un-overridable for anyone not editing a bundled profile.

Scope is deliberately limited to the keys registered alongside this test. A
blanket "every ``getattr`` must have a ``_STEP_DEFAULTS`` entry" scan would fail
on the many intentional inline-default scalars elsewhere in the pipeline, for
reasons unrelated to what this file is checking.
"""
from pathlib import Path

import pytest

from vvaharness.config import Config, _STEP_DEFAULTS, load

_PROFILES_DIR = Path(__file__).resolve().parent.parent / "vvaharness" / "config" / "profiles"

# The keys registered alongside this test, grouped by _STEP_DEFAULTS section.
_NEW_KEYS: dict[str, dict[str, object]] = {
    "step2": {
        "timeout": 1800,
        "max_assets": 40,
        "max_trust_boundaries": 60,
        "max_manifest_depth": 3,
        "max_manifests": 12,
        "max_manifests_per_kind": 2,
        "max_manifest_total_chars": 24000,
        # Config-representative CONTENTS (Phase 9): redacted bodies for the
        # first max_config_rep_bodies reps, capped per file.
        "max_config_rep_chars": 2000,
        "max_config_rep_bodies": 12,
        # Agentic s2 ships dark: prompt() unless an operator flips this on.
        # allowed_tools is replace-merged (step2 has no append semantics) and
        # re-validated in the stage against {Read, Glob, Grep}.
        "agentic": False,
        # A tuple, deliberately: _STEP_DEFAULTS values are assigned by object
        # into every load()'d config, so a mutable default would be shared
        # process-wide and one in-place mutation would poison later loads.
        "allowed_tools": ("Read", "Glob", "Grep"),
        "max_turns": 12,
    },
    "step3": {
        "max_prompt_threats": 50,
        "max_prompt_assets": 20,
        "max_prompt_boundaries": 30,
        "max_prompt_threat_context_chars": 2500,
        "max_cohesion_groups": 64,
        # On by default: coalescing adjacent under-filled _pack buckets is the
        # intended packing behaviour; `false` is the per-target escape hatch
        # that restores one-bucket-per-cohesion-group byte-for-byte.
        "pack_merge_underfilled": True,
        # Matches `max_prompt_threats`: the threat-coverage guarantee has to
        # hold for every threat that can reach s3, so this cap only binds when
        # an operator lowers it deliberately.
        "max_threat_fallback_chunks": 50,
        # Read with an inline default by the threat-fallback pass, never
        # registered until now, so an operator could not discover them.
        "threat_surface_fallbacks": True,
        "threat_fallback_max_files": 12,
    },
}

# Top-level (not per-step) new keys. `cache_min_block_tokens` defaults to
# None — "use the published per-model minimum" — because a single global
# number is wrong in both directions across the model range (512 to 4096);
# a configured integer is an operator override for a gateway that enforces
# its own floor. `cache_route` defaults to "auto" so behaviour without the
# key is exactly the pre-existing host detection, fail-closed included.
_NEW_TOP_LEVEL_KEYS: dict[str, object] = {
    "cache_min_block_tokens": None,
    "cache_markers": "on",
    "cache_route": "auto",
}

# Pre-existing keys that are easy to confuse with the new ones and must not be
# perturbed by registering them. `step3.timeout` in particular is 3600 because
# decompose can exceed ten minutes on a large repository; 1800 is `step4`'s
# separate deadline, and conflating the two halves a limit that is needed.
_MUST_NOT_CHANGE = {
    ("step2", "max_config_reps"): 80,
    ("step3", "timeout"): 3600,
    ("step2", "max_threats"): 50,
}


@pytest.mark.parametrize("section,key,default", [
    (section, key, default)
    for section, keys in _NEW_KEYS.items()
    for key, default in keys.items()
])
def test_new_key_registered_in_step_defaults(section, key, default):
    """Each new key has a _STEP_DEFAULTS entry with the stated default, which
    is what makes it reachable from a user-authored profile that never mentions
    it (see the module docstring)."""
    assert section in _STEP_DEFAULTS, f"missing section {section!r} in _STEP_DEFAULTS"
    assert key in _STEP_DEFAULTS[section], (
        f"{section}.{key} not registered in _STEP_DEFAULTS — a user profile "
        f"that omits it would silently fall back to whatever default the "
        f"call site's getattr(...) happens to hard-code, not this one"
    )
    assert _STEP_DEFAULTS[section][key] == default


@pytest.mark.parametrize("key,default", list(_NEW_TOP_LEVEL_KEYS.items()))
def test_new_top_level_key_registered_in_step_defaults(key, default):
    assert key in _STEP_DEFAULTS, f"missing top-level key {key!r} in _STEP_DEFAULTS"
    assert _STEP_DEFAULTS[key] == default


@pytest.mark.parametrize("section,key,expected", [
    (section, key, expected) for (section, key), expected in _MUST_NOT_CHANGE.items()
])
def test_preexisting_keys_unchanged(section, key, expected):
    """Adding the new keys must leave these pre-existing values untouched."""
    assert _STEP_DEFAULTS[section][key] == expected


def test_config_getattr_raises_on_unknown_key():
    """Config is NOT a permissive attribute bag: an unregistered key raises
    AttributeError rather than silently returning None. This is why the
    silence this test file guards against lives at pipeline call sites
    (getattr(cfg.stepN, key, default)), not in Config itself."""
    cfg = Config({"step3": {"known": 1}})
    with pytest.raises(AttributeError):
        cfg.step3.this_key_does_not_exist_anywhere


def test_load_each_shipped_profile_succeeds():
    """Smoke: every shipped profile still loads through load(), including
    with the new _STEP_DEFAULTS keys merged underneath it."""
    for profile in ("default", "taint", "full", "sdk"):
        path = _PROFILES_DIR / f"{profile}.yaml"
        assert path.is_file(), f"expected shipped profile at {path}"
        cfg = load(path)
        # New keys are reachable through the loaded Config for every profile,
        # even ones (taint/full/sdk) that never mention them in YAML.
        assert cfg.step2.max_assets == 40
        assert cfg.step3.max_cohesion_groups == 64
        # None -> the sdk backend's published per-model minimum applies.
        assert cfg.cache_min_block_tokens is None
        # Cache regime, per profile. Only the `via: sdk` transport reads this key:
        # via:cli places no markers, via:openai has no marker regime to declare,
        # and via:deepagents never consults it. `auto` classifies the endpoint by
        # hostname and withholds markers when it cannot recognise one —
        # fail-closed, and the built-in default.
        #
        # `sdk.yaml` and `default.yaml` pre-declare `anthropic` instead. Note what
        # that does: with `sdk.base_url` unset, `auto` already resolves to the
        # Anthropic regime, so the declaration only bites against a gateway `auto`
        # cannot classify, where it forces the regime rather than forfeiting
        # caching. `full.yaml` ships via:deepagents Claude roles on the same
        # operator-supplied endpoint yet leaves the key unset, so this is a
        # deliberate per-profile choice and NOT derivable from which models a
        # profile runs — which is why it is pinned here as a literal. Changing any
        # entry means updating that profile's comment block and
        # docs/configuration.md alongside.
        expected_route = "anthropic"   # all four shipped profiles pre-declare it
        assert cfg.cache_route == expected_route, (
            f"{profile}.yaml resolves cache_route to {cfg.cache_route!r}, "
            f"expected {expected_route!r}"
        )


def test_every_shipped_profile_enables_all_eleven_specialist_lenses():
    """All four shipped profiles enable the full eleven-lens specialist set.

    The five later lenses (deserialization, csrf, sensitive-data,
    hardcoded-creds, log-injection) each ship hint text plus a surface gate
    evaluated in s3 BEFORE any model call, so a repository without the matching
    surface pays nothing for the ones that gate narrowly. Note the gates are not
    uniformly narrow — csrf keys off any authz surface and
    sensitive-data/log-injection off `bool(entry_points)` — so this list is a
    real cost commitment, not a free one; README/docs/configuration.md state the
    same lens set for every profile. Adding or dropping a lens in any profile
    means updating those docs alongside this assertion.

    `injection` (11th lens) sweeps SQLi/NoSQLi/cmd/LDAP/XPath/XXE/SSRF/path/XSS-
    server-emit/SSTI/open-redirect/CRLF/ReDoS classes on every source file, in
    addition to - not instead of - the generic catch-all pass: under
    step3.catchall_deduct_lens_coverage a specialist's claim does not suppress
    catch-all, so a file this lens covers still gets an unscoped review too.
    See `SPECIALIST_HINTS["injection"]` and `_gate_specialists` in
    s3_decompose.py.
    """
    expected = {
        "crypto", "logic-bug", "access-control", "batch-etl", "iac",
        "deserialization", "csrf", "sensitive-data", "hardcoded-creds",
        "log-injection", "injection",
    }
    for profile in ("default", "taint", "full", "sdk"):
        cfg = load(_PROFILES_DIR / f"{profile}.yaml")
        got = list(cfg.step3.specialists)
        assert set(got) == expected, (
            f"{profile}.yaml specialists {got!r} no longer match the documented "
            f"eleven-lens set — update README/docs/configuration.md alongside"
        )


def test_step1_call_graph_default_pin_is_deliberate():
    """step1.call_graph is DELIBERATELY pinned to "regex" in _STEP_DEFAULTS.

    The pin overrides the in-code getattr fallback in s1_preprocess (which
    names "tree_sitter"), so any profile that omits the key — sdk.yaml
    documents relying on exactly that — runs the regex supplement, while
    shipped default.yaml/taint.yaml/full.yaml opt into tree_sitter explicitly.
    Flipping this value is a shipped-behaviour change for every key-omitting
    profile: do it only deliberately (large-repo benchmark, profile-comment
    updates) and update this pin alongside.
    """
    import yaml

    assert _STEP_DEFAULTS["step1"]["call_graph"] == "regex"

    # The constellation the pin's comment describes must keep holding, or the
    # comment (and this test) is stale: explicit tree_sitter opt-ins…
    for name in ("default.yaml", "taint.yaml", "full.yaml"):
        raw = yaml.safe_load((_PROFILES_DIR / name).read_text(encoding="utf-8"))
        assert (raw.get("step1") or {}).get("call_graph") == "tree_sitter", (
            f"{name} no longer opts into tree_sitter — revisit the "
            f"_STEP_DEFAULTS call_graph pin and its comment")
    # …and the profile that deliberately inherits the regex pin by omission.
    for name in ("sdk.yaml",):
        raw = yaml.safe_load((_PROFILES_DIR / name).read_text(encoding="utf-8"))
        assert "call_graph" not in (raw.get("step1") or {}), (
            f"{name} now sets step1.call_graph explicitly — revisit the "
            f"_STEP_DEFAULTS call_graph pin and its comment")
