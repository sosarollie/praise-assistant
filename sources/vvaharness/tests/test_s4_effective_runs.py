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

"""Run/vote normalisation for the deep-dive stage (`_effective_runs`).

This function had no test at all, so the behaviour change it carries — SDK
models that reject `temperature` are no longer collapsed to a single run —
passed the suite identically before and after. That is the gap these tests
close: each one fails if the collapse is reintroduced, or if the collapse that
IS still correct (`via: cli`) is removed.

Why honouring the config is right for a temperature-rejecting SDK model:
rejecting the parameter is not determinism. The API exposes no seed, and those
models reject `temperature`/`top_p`/`top_k` outright, so the provider samples at
its own non-zero policy and repeated runs genuinely diverge. Voting therefore
filters something real; only the *tunability* of the diversity is lost, which is
what the stderr NOTE says. The old collapse overrode an operator who had asked
for voting while the stage banner still announced it was on.

No model call and no filesystem access is involved.
"""
from __future__ import annotations

from types import SimpleNamespace as NS

from vvaharness.pipeline.stages import s4_deepdive as s4


def _cfg(model_id, via, runs, threshold, temperature=None):
    node = NS(id=model_id, via=via, temperature=temperature,
              thinking_budget=None, betas=None)
    return NS(step4=NS(runs=runs, vote_threshold=threshold),
              models=NS(deepdive=node))


def test_sdk_temp_rejecting_model_honours_configured_runs(capsys):
    """The regression guard: opus-4-8 rejects `temperature` but still votes."""
    assert s4._effective_runs(_cfg("claude-opus-4-8", "sdk", 3, 2)) == (3, 2)
    # The NOTE is the whole warning surface for a non-tunable sampling route,
    # so its absence is as much a regression as a wrong return value.
    assert "NOTE" in capsys.readouterr().err


def test_cli_still_collapses_to_a_single_run():
    """`via: cli` has no temperature flag at all — this collapse is correct."""
    assert s4._effective_runs(_cfg("claude-opus-4-7", "cli", 3, 2)) == (1, 1)


def test_temp_capable_sdk_model_passes_through_silently(capsys):
    """sonnet-4-6 accepts `temperature`; nothing to warn about."""
    cfg = _cfg("claude-sonnet-4-6", "sdk", 3, 2, temperature=0.4)
    assert s4._effective_runs(cfg) == (3, 2)
    assert "NOTE" not in capsys.readouterr().err


def test_unreachable_vote_threshold_is_clamped_down_to_runs():
    """A threshold above runs can never be met, which would silently zero out
    every finding rather than fail loudly."""
    runs, threshold = s4._effective_runs(_cfg("claude-opus-4-8", "sdk", 2, 5))
    assert (runs, threshold) == (2, 2)


def test_invalid_runs_falls_back_to_single_pass(capsys):
    assert s4._effective_runs(_cfg("claude-opus-4-8", "sdk", 0, 1)) == (1, 1)
    assert "WARN" in capsys.readouterr().err
