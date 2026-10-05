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

"""S4 via:deepagents route tests — dispatch branching, `_effective_runs`'
deepagents arm, and route-aware shard gating.

The stage calls ``_deepagents.dispatch_prompt``; the via branch lives in that
dispatcher, so these tests patch its two legs — the module-level deepagents
wrapper (``_deepagents.prompt``) and the legacy registry
(``_deepagents.registry.prompt``) — arming whichever leg must NOT fire to
fail, so a routing regression cannot pass silently (the
test_s1_deepagents_route pattern).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.backends.llm.cache import (
    PREFIX_CACHE_BREAKPOINT,
    PREFIX_CACHE_IMPLICIT,
    PREFIX_CACHE_NONE,
    prefix_cache_class,
)
from vvaharness.models import Chunk, ChunkSize, ContextPackage
from vvaharness.pipeline.stages import s4_deepdive as s4


def _ctx() -> ContextPackage:
    return ContextPackage(repo_root="/nonexistent-repo", language="python",
                          all_files=[], entry_points=[], unsafe_sinks=[],
                          call_graph={})


def _cfg(node):
    return SimpleNamespace(
        step4=SimpleNamespace(taint_prompt_mode="discover", taint_model=None,
                              max_tokens=64000, timeout=1800),
        models=SimpleNamespace(deepdive=node),
        sdk=SimpleNamespace(api_key="sk-test"),
    )


def _chunk(cid: str = "chunk-01") -> Chunk:
    return Chunk(id=cid, size=ChunkSize.MEDIUM, file_ids=["a.py"], hypothesis="x")


def _fail_registry(monkeypatch):
    monkeypatch.setattr(
        s4._deepagents.registry, "prompt",
        lambda *_a, **_k: pytest.fail("legacy dispatcher was called"),
    )


def _fail_wrapper(monkeypatch):
    monkeypatch.setattr(
        s4._deepagents, "prompt",
        lambda *_a, **_k: pytest.fail("deepagents wrapper was called"),
    )


# ── dispatch branching ────────────────────────────────────────────────────────

def test_deepagents_via_routes_through_wrapper_only(monkeypatch):
    _fail_registry(monkeypatch)
    node = SimpleNamespace(id="claude-test", via="deepagents")
    cfg = _cfg(node)
    captured = {}

    def fake_prompt(user_prompt, **kw):
        captured["user_prompt"] = user_prompt
        captured.update(kw)
        return '{"findings": []}'

    monkeypatch.setattr(s4._deepagents, "prompt", fake_prompt)

    out = s4._single_run(_chunk(), _ctx(), "code", cfg)

    assert out == []
    assert captured["model"] is node
    assert captured["system_prompt"] is s4.SYSTEM
    assert captured["cwd"] == "/nonexistent-repo"
    assert captured["graph_name"] == "s4-deepdive"
    assert captured["sdk_cfg"] is cfg.sdk
    assert captured["openai_cfg"] is None
    assert captured["tag"] == "s4 chunk-01"
    assert captured["max_tokens"] == 64000


def test_legacy_via_keeps_exact_registry_kwargs(monkeypatch):
    _fail_wrapper(monkeypatch)
    node = SimpleNamespace(id="claude-test", via="sdk")
    cfg = _cfg(node)
    captured = {}

    def fake_prompt(user_prompt, **kw):
        captured["user_prompt"] = user_prompt
        captured["kw"] = kw
        return '{"findings": []}'

    monkeypatch.setattr(s4._deepagents.registry, "prompt", fake_prompt)

    out = s4._single_run(_chunk(), _ctx(), "code", cfg)

    assert out == []
    # The legacy leg keeps the registry signature: no deepagents-only kwargs
    # (cfg/cwd/graph_name) leak in, and every pre-migration kwarg survives.
    assert set(captured["kw"]) == {"model", "system_prompt", "max_tokens",
                                   "tag", "timeout", "output_format",
                                   "cache_prefix"}
    assert captured["kw"]["model"] is node


def test_repair_retry_stays_on_the_deepagents_route(stub_prompt, monkeypatch):
    """The JSON-repair retry goes through the same dispatch seam as the
    primary call: the registry has no deepagents backend, so a retry falling
    back to `registry.prompt` would raise `Unknown backend` instead of
    repairing the response."""
    responses = ['{"findings": [broken', '{"findings": []}']
    prompts = []

    def fake_run_oneshot(user_prompt, options):
        prompts.append(user_prompt)
        return SimpleNamespace(result_text=responses[len(prompts) - 1])

    monkeypatch.setattr(s4._deepagents, "run_oneshot", fake_run_oneshot)
    cfg = _cfg(SimpleNamespace(id="claude-test", via="deepagents"))

    out = s4._single_run(_chunk(), _ctx(), "code", cfg)

    assert out == []
    assert len(prompts) == 2, "original call plus exactly one repair"
    assert prompts[1].startswith("REPAIR TASK:")
    assert stub_prompt.calls == [], \
        "neither the original call nor the retry may reach registry.prompt"


# ── _effective_runs: the deepagents arm ──────────────────────────────────────

def _runs_cfg(runs, threshold, node):
    return SimpleNamespace(
        step4=SimpleNamespace(runs=runs, vote_threshold=threshold),
        models=SimpleNamespace(deepdive=node),
    )


@pytest.fixture(autouse=True)
def _fresh_temp_note():
    s4._DEEPAGENTS_TEMP_NOTED = False
    yield
    s4._DEEPAGENTS_TEMP_NOTED = False


def test_effective_runs_deepagents_honours_runs_with_note(capsys):
    node = SimpleNamespace(id="claude-test", via="deepagents")
    runs, threshold = s4._effective_runs(_runs_cfg(3, 2, node))

    assert (runs, threshold) == (3, 2), "never collapse to 1/1 on this route"
    err = capsys.readouterr().err
    assert "via: deepagents sends no `temperature`" in err
    assert "voting still works" in err


def test_effective_runs_deepagents_single_run_stays_quiet(capsys):
    node = SimpleNamespace(id="claude-test", via="deepagents")
    assert s4._effective_runs(_runs_cfg(1, 1, node)) == (1, 1)
    assert "NOTE" not in capsys.readouterr().err


def test_effective_runs_notes_ignored_temperature_pin_once(capsys):
    node = SimpleNamespace(id="claude-test", via="deepagents", temperature=0.4)
    s4._effective_runs(_runs_cfg(1, 1, node))
    err = capsys.readouterr().err
    assert "pins temperature=0.4" in err
    assert "never sends it" in err

    s4._effective_runs(_runs_cfg(1, 1, node))
    assert "pins temperature" not in capsys.readouterr().err


def test_effective_runs_deepagents_temperature_zero_not_warned(capsys):
    """The temperature=0 identical-runs WARN is an sdk/openai concern: on the
    deepagents route the pin is never sent, so runs stay divergent."""
    node = SimpleNamespace(id="claude-test", via="deepagents", temperature=0)
    runs, threshold = s4._effective_runs(_runs_cfg(3, 2, node))

    assert (runs, threshold) == (3, 2)
    assert "runs will be identical" not in capsys.readouterr().err


def test_effective_runs_sdk_temperature_zero_still_warned(capsys):
    node = SimpleNamespace(id="claude-sonnet-4-6", via="sdk", temperature=0)
    s4._effective_runs(_runs_cfg(3, 2, node))
    assert "runs will be identical" in capsys.readouterr().err


# ── route-aware shard gating ─────────────────────────────────────────────────

def test_prefix_cache_class_by_via():
    assert prefix_cache_class("sdk") == PREFIX_CACHE_BREAKPOINT
    assert prefix_cache_class("openai") == PREFIX_CACHE_IMPLICIT
    assert prefix_cache_class("cli") == PREFIX_CACHE_NONE


def test_prefix_cache_class_deepagents_follows_model_routing():
    assert prefix_cache_class(
        "deepagents", model_id="claude-opus-4-7") == PREFIX_CACHE_BREAKPOINT
    assert prefix_cache_class(
        "deepagents", model_id="claude-x", provider="anthropic",
    ) == PREFIX_CACHE_BREAKPOINT
    assert prefix_cache_class(
        "deepagents", model_id="gpt-5.5", provider="openai",
    ) == PREFIX_CACHE_IMPLICIT
    assert prefix_cache_class(
        "deepagents", model_id="glm-5.2") == PREFIX_CACHE_IMPLICIT


def _gating_cfg(via: str, model_id: str = "claude-test"):
    return SimpleNamespace(
        step4=SimpleNamespace(parallel=2, line_bucket=10, runs=1,
                              vote_threshold=1, specialist_runs=1,
                              max_tokens=64000, timeout=1800,
                              taint_prompt_mode="discover", taint_runs=1,
                              taint_model=None),
        models=SimpleNamespace(
            deepdive=SimpleNamespace(id=model_id, via=via)),
    )


def _shard_chunks():
    return [
        Chunk(id="chunk-01", size=ChunkSize.MEDIUM, file_ids=["a.py"],
              hypothesis="x", shard_id="shard-0", specialist="crypto"),
        Chunk(id="chunk-02", size=ChunkSize.MEDIUM, file_ids=["a.py"],
              hypothesis="x", shard_id="shard-0", specialist="injection"),
    ]


def test_run_builds_no_gates_on_uncached_routes(monkeypatch, capsys):
    built = []
    monkeypatch.setattr(
        s4, "_shard_gates",
        lambda chunks: built.append(1) or {},
    )
    monkeypatch.setattr(s4, "_deepdive_chunk",
                        lambda *_a, **_k: [])

    s4.run(_shard_chunks(), _ctx(), _gating_cfg("cli"))

    assert built == [], "gateless route must not even build a gate plan"
    assert "shard-gate scheduling off" in capsys.readouterr().err


def test_gateless_note_stays_quiet_without_shard_chunks(monkeypatch, capsys):
    """The scheduling-off note explains a behavior change only shard groups
    would have seen; a scan with no shards must not emit it."""
    monkeypatch.setattr(s4, "_deepdive_chunk", lambda *_a, **_k: [])

    s4.run([_chunk()], _ctx(), _gating_cfg("cli"))

    assert "shard-gate scheduling off" not in capsys.readouterr().err


@pytest.mark.parametrize(("via", "model_id"), [
    ("sdk", "claude-test"),
    ("openai", "gpt-5.5"),
    ("deepagents", "claude-test"),
    ("deepagents", "gpt-5.5"),
])
def test_run_builds_gates_on_prefix_cached_routes(via, model_id, monkeypatch, capsys):
    built = []
    real_shard_gates = s4._shard_gates
    monkeypatch.setattr(
        s4, "_shard_gates",
        lambda chunks: built.append(1) or real_shard_gates(chunks),
    )
    monkeypatch.setattr(s4, "_deepdive_chunk",
                        lambda *_a, **_k: [])

    s4.run(_shard_chunks(), _ctx(), _gating_cfg(via, model_id))

    assert built == [1]
    assert "shard-gate scheduling off" not in capsys.readouterr().err
