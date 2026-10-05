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

"""Self-check for every shared fixture defined in conftest.py /
tests/fixtures/**. Each test below instantiates one fixture and asserts the
single property it exists to guarantee, plus (at the end) a real,
end-to-end, offline pipeline run through the prompt stub and the network
guard.
"""
from __future__ import annotations

import socket
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from conftest import _NetworkBlocked


# ─────────────────────────────────────────────────────────────────────────────
# On-disk file-tree fixtures.
# ─────────────────────────────────────────────────────────────────────────────

def test_repo_deep_exceeds_the_frontier_cap_with_a_config_per_service(repo_deep):
    files = [p for p in repo_deep.rglob("*") if p.is_file()]
    assert len(files) > 220

    top_dirs = sorted({p.relative_to(repo_deep).parts[0] for p in files})
    assert len(top_dirs) >= 12

    for d in top_dirs:
        configs = list((repo_deep / d).glob("*.yaml"))
        assert len(configs) == 1, f"{d} must have exactly one config file"


def test_repo_nested_manifests_has_a_depth_two_pom_and_a_vendored_package_json(
    repo_nested_manifests,
):
    pom = repo_nested_manifests / "services" / "api" / "pom.xml"
    assert pom.is_file()
    assert len(pom.relative_to(repo_nested_manifests).parts) == 3  # 2 dirs + file

    vendored = repo_nested_manifests / "node_modules" / "lodash" / "package.json"
    assert vendored.is_file()

    # Neither manifest sits at the repo root.
    assert not (repo_nested_manifests / "pom.xml").exists()
    assert not (repo_nested_manifests / "package.json").exists()


def test_repo_symlink_escape_blocks_the_escape_but_not_the_in_repo_link(
    repo_symlink_escape,
):
    fx = repo_symlink_escape
    assert fx.escape_link.is_symlink()
    escape_real = fx.escape_link.resolve()
    assert not escape_real.is_relative_to(fx.root.resolve())
    assert escape_real == fx.escape_target.resolve()
    assert fx.escape_target.read_text(encoding="utf-8").strip() == fx.escape_marker

    assert fx.in_repo_link.is_symlink()
    in_repo_real = fx.in_repo_link.resolve()
    assert in_repo_real.is_relative_to(fx.root.resolve())
    assert fx.in_repo_link.read_text(encoding="utf-8").strip() == fx.in_repo_marker


def test_repo_extensionless_has_three_non_source_files(repo_extensionless):
    from vvaharness.pipeline.stages.s3_decompose import _is_source

    candidates = [
        repo_extensionless / "Makefile",
        repo_extensionless / "config" / "service.conf",
        repo_extensionless / "bin" / "deploy",
    ]
    for p in candidates:
        assert p.is_file(), p
        rel = str(p.relative_to(repo_extensionless))
        assert _is_source(rel) is False, f"{rel} must classify as non-source"


# ─────────────────────────────────────────────────────────────────────────────
# In-memory ContextPackage builder fixtures.
# ─────────────────────────────────────────────────────────────────────────────

def test_ctx_framework_eps_is_300_unauth_reachable_framework_entries(ctx_framework_eps):
    assert len(ctx_framework_eps.entry_points) == 300
    assert all(e.kind == "framework" for e in ctx_framework_eps.entry_points)
    assert all(e.reachable_from_unauth for e in ctx_framework_eps.entry_points)
    # None of them look like the deterministic "network" signal a classifier
    # keys on, by construction.
    assert not any(e.kind == "network" for e in ctx_framework_eps.entry_points)


def test_ctx_taint_multi_has_one_file_and_three_seeded_functions(ctx_taint_multi):
    ep_files = {e.file for e in ctx_taint_multi.entry_points}
    assert ep_files == {"app/handlers.py"}
    assert len(ctx_taint_multi.entry_points) == 3
    functions = {e.function for e in ctx_taint_multi.entry_points}
    assert len(functions) == 3
    assert len(ctx_taint_multi.seed_taint_evidence) == 3
    assert {e.source_ref.rsplit("::", 1)[1] for e in ctx_taint_multi.seed_taint_evidence} == functions


def test_ctx_frontier_ne_full_diverges_from_the_full_sorted_list(ctx_frontier_ne_full):
    ctx = ctx_frontier_ne_full
    assert len(ctx.all_files) == 50

    frontier = ctx.ast_context_view(max_files=5).all_files
    assert len(frontier) == 5

    full_sorted = sorted(ctx.all_files)
    frontier_sorted = sorted(frontier)
    assert frontier_sorted[1] != full_sorted[1]
    # The whole point: an index into the frontier does not address the same
    # file as the same index into the full list, anywhere in this fixture.
    assert set(frontier_sorted).isdisjoint(full_sorted[:45])


# ─────────────────────────────────────────────────────────────────────────────
# The prompt() stub.
# ─────────────────────────────────────────────────────────────────────────────

def test_stub_prompt_returns_canned_json_per_stage_and_records_calls(stub_prompt):
    from vvaharness.backends.llm import registry
    from vvaharness.pipeline.stages import s2_threatmodel, s3_decompose, s4_deepdive

    # s2/s3/s4 no longer bind the name `prompt`: they call
    # `_deepagents.dispatch_prompt`, whose legacy branch resolves
    # `registry.prompt` at call time — the origin patch below covers them.
    assert not hasattr(s2_threatmodel, "prompt")
    assert not hasattr(s3_decompose, "prompt")
    assert not hasattr(s4_deepdive, "prompt")
    # The dispatcher lives in `llm.registry`, not on `llm` itself.  The
    # package initializer intentionally re-exports nothing, so `llm.prompt`
    # does not exist and `registry` remains the patch origin.
    assert registry.prompt is stub_prompt

    out = stub_prompt("hello", model="stub-model", tag="s3 decompose", timeout=1800)
    assert '"chunks"' in out and '"rationale"' in out

    assert len(stub_prompt.calls) == 1
    call = stub_prompt.calls[0]
    assert call["stage"] == "s3"
    assert call["prompt"] == "hello"
    assert call["kw"]["timeout"] == 1800


def test_stub_prompt_response_is_overridable_per_stage(stub_prompt):
    stub_prompt.set_response("s4", '{"findings": [{"probe": true}]}')
    out = stub_prompt("body", model="m", tag="s4 chunk-01")
    assert out == '{"findings": [{"probe": true}]}'


def test_stub_prompt_can_be_made_to_raise(stub_prompt):
    stub_prompt.set_raise("s2", TimeoutError("simulated provider timeout"))
    with pytest.raises(TimeoutError):
        stub_prompt("body", model="m", tag="s2 threatmodel")


# ─────────────────────────────────────────────────────────────────────────────
# The network guard.
# ─────────────────────────────────────────────────────────────────────────────

def test_a_real_socket_connection_is_blocked():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(_NetworkBlocked):
            s.connect(("example.invalid", 80))
    finally:
        s.close()


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end: a real pipeline stage, run entirely offline.
# ─────────────────────────────────────────────────────────────────────────────

def test_decompose_stage_runs_end_to_end_with_no_network_access(
    stub_prompt, ctx_taint_multi
):
    from vvaharness.pipeline.stages import s3_decompose

    cfg = SimpleNamespace(
        step3=SimpleNamespace(),
        models=SimpleNamespace(decompose="stub-model"),
    )
    manifest = s3_decompose.run(ctx_taint_multi, cfg)

    assert manifest.chunks
    assert stub_prompt.calls
    assert stub_prompt.calls[0]["stage"] == "s3"
    assert stub_prompt.calls[0]["kw"]["timeout"] == 1800


def test_threatmodel_stage_runs_end_to_end_with_no_network_access(
    stub_prompt, ctx_framework_eps, repo_nested_manifests
):
    from vvaharness.pipeline.stages import s2_threatmodel

    cfg = SimpleNamespace(
        step2=SimpleNamespace(),
        models=SimpleNamespace(threatmodel="stub-model"),
    )
    tm = s2_threatmodel.run(
        str(repo_nested_manifests), "fixture-repo", cfg,
        known_cves=[], controls=[], ctx=ctx_framework_eps,
    )

    assert tm is not None
    assert stub_prompt.calls
    assert stub_prompt.calls[0]["stage"] == "s2"
