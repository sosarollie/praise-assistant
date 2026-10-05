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

"""Harness-profile suffix stripping on the detection one-shot path.

deepagents' ``create_deep_agent`` appends a model-keyed system-prompt suffix
("harness profile") with no public opt-out. On the tool-less one-shot path
that agentic guidance measured +23.5% output tokens on sonnet-class models
(a prose preamble that breaks the respond-only-with-JSON contract) and ~530
uncached input tokens per call on every model, so ``_create_agent`` blanks
every profile's suffix — and only the suffix — around one-shot builds.
Streaming builds (S10 fix mode, S11 validation) are unstripped and their
prompts stay byte-identical; ``_BUILD_LOCK`` keeps a concurrent streaming
build out of the strip window.

The strip mutates a PRIVATE deepagents registry, so the tripwires below pin
the upstream seam: if a deepagents upgrade renames the registry or stops
shipping suffixed profiles, these fail loudly instead of the strip silently
becoming a no-op.
"""

from __future__ import annotations

import dataclasses
import inspect
from pathlib import Path

import pytest
from deepagents.profiles.harness.harness_profiles import (
    _HARNESS_PROFILES,
    _ensure_harness_profiles_loaded,
)
from fixtures.deepagents_scaffolding import oneshot_options

from vvaharness.backends.harness.deepagents.options import graph_builder as gb
from vvaharness.backends.harness.deepagents.options import oneshot as oneshot_mod
from vvaharness.backends.harness.deepagents.options import streaming
from vvaharness.backends.harness.deepagents.options.graph_builder import (
    _suffixless_harness_profiles,
)
from vvaharness.backends.harness.deepagents.options.oneshot import (
    _build_oneshot_graph,
)

# ── upstream-seam tripwires ───────────────────────────────────────────────────


def test_upstream_registry_still_ships_suffixed_profiles():
    """If this fails after a deepagents upgrade, re-validate the strip seam."""
    _ensure_harness_profiles_loaded()
    suffixed = [k for k, p in _HARNESS_PROFILES.items() if p.system_prompt_suffix]
    assert suffixed, "no registered profile carries a suffix; the strip is dead code"


def test_upstream_profiles_are_replaceable_dataclasses():
    _ensure_harness_profiles_loaded()
    profile = next(iter(_HARNESS_PROFILES.values()))
    assert dataclasses.is_dataclass(profile)
    assert dataclasses.replace(profile, system_prompt_suffix="").system_prompt_suffix == ""


# ── the context manager ───────────────────────────────────────────────────────


def test_strip_blanks_every_suffix_and_restores_originals():
    _ensure_harness_profiles_loaded()
    originals = dict(_HARNESS_PROFILES)
    with _suffixless_harness_profiles():
        assert _HARNESS_PROFILES.keys() == originals.keys()
        assert all(not p.system_prompt_suffix for p in _HARNESS_PROFILES.values())
        # Only the suffix is blanked; every other field survives the swap.
        for key, original in originals.items():
            swapped = _HARNESS_PROFILES[key]
            assert swapped.tool_description_overrides == original.tool_description_overrides
            assert swapped.excluded_middleware == original.excluded_middleware
    for key, original in originals.items():
        assert _HARNESS_PROFILES[key] is original


def test_strip_restores_originals_when_the_build_raises():
    _ensure_harness_profiles_loaded()
    originals = dict(_HARNESS_PROFILES)
    with pytest.raises(RuntimeError, match="build blew up"), _suffixless_harness_profiles():
        raise RuntimeError("build blew up")
    for key, original in originals.items():
        assert _HARNESS_PROFILES[key] is original


# ── the builder seam ──────────────────────────────────────────────────────────


def _spy_create(monkeypatch, sink: dict) -> None:
    """Record the registry's suffix state at the moment create_deep_agent runs."""

    def spy(**kwargs):
        sink["suffixes"] = [p.system_prompt_suffix for p in _HARNESS_PROFILES.values()]
        sink["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(gb, "create_deep_agent", spy)
    monkeypatch.setattr(gb, "build_model_cached", lambda *a, **k: object())  # noqa: ARG005


def _build(strip: bool) -> object:
    return gb._create_agent(
        model_id="claude-test",
        env={},
        system_prompt="sys",
        tools=[],
        name="t",
        skills=None,
        permissions=[],
        strip_harness_suffix=strip,
    )


def test_builder_strips_suffixes_during_the_build_when_asked(monkeypatch):
    _ensure_harness_profiles_loaded()
    sink: dict = {}
    _spy_create(monkeypatch, sink)
    _build(strip=True)
    assert sink["suffixes"], "spy never observed the registry"
    assert all(s == "" for s in sink["suffixes"])
    assert any(p.system_prompt_suffix for p in _HARNESS_PROFILES.values()), (
        "originals were not restored after the build"
    )


def test_builder_default_leaves_suffixes_intact(monkeypatch):
    _ensure_harness_profiles_loaded()
    sink: dict = {}
    _spy_create(monkeypatch, sink)
    _build(strip=False)
    assert any(s for s in sink["suffixes"]), (
        "the default build must see upstream suffixes untouched"
    )


# ── call-site pins ────────────────────────────────────────────────────────────


def test_oneshot_call_site_opts_in(monkeypatch, tmp_path: Path):
    captured: dict = {}

    def fake_create_agent(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(oneshot_mod, "_create_agent", fake_create_agent)
    _build_oneshot_graph(oneshot_options(tmp_path))
    assert captured["strip_harness_suffix"] is True


def test_streaming_call_site_stays_unstripped():
    """S10/S11 prompts are frozen: the streaming builder must not opt in."""
    source = inspect.getsource(streaming)
    assert "strip_harness_suffix" not in source
    sig = inspect.signature(gb._create_agent)
    assert sig.parameters["strip_harness_suffix"].default is False
