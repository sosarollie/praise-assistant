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

"""The EV dispatch seam (:mod:`vvaharness.exploit_verification._route`).

Mirrors the shared adapter's ``dispatch_prompt`` / ``dispatch_agentic``: a node naming
``via: deepagents`` reaches the DeepAgents adapter with the profile ``cfg`` node's
credential blocks read off it here; every other ``via`` stays on the legacy dispatcher.
The routes are stubbed, so these are hermetic and touch no model.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vvaharness.exploit_verification import _route


def _node(via: str):
    return SimpleNamespace(id="m", via=via)


def _cfg(sdk="SDK", openai="OAI", config_dir="/profiles"):
    # A profile node carries `sdk`/`openai` blocks and, via `_data`, its config dir.
    return SimpleNamespace(sdk=sdk, openai=openai, _data={"_config_dir": config_dir})


@pytest.fixture
def spies(monkeypatch):
    """Record which route a call took and with what kwargs."""
    calls: dict[str, dict] = {}

    def _record(name):
        def fake(user, **kw):
            calls[name] = {"user": user, **kw}
            return f"{name}-reply"
        return fake

    monkeypatch.setattr(_route._da, "prompt", _record("da_prompt"))
    monkeypatch.setattr(_route._da, "agentic", _record("da_agentic"))
    # Patch the registry module attrs (not a from-import), matching how the rest of
    # the suite stubs the legacy dispatcher — the seam resolves them at call time.
    monkeypatch.setattr(_route._registry, "prompt", _record("legacy_prompt"))
    monkeypatch.setattr(_route._registry, "agentic", _record("legacy_agentic"))
    return calls


def test_is_deepagents_reads_the_resolved_via():
    assert _route.is_deepagents(_node("deepagents")) is True
    assert _route.is_deepagents(_node("sdk")) is False
    assert _route.is_deepagents("bare-id-string") is False  # bare str => via: cli


def test_is_deepagents_treats_an_unusable_node_as_non_deepagents():
    # A node with no `id` cannot resolve; that is not a deepagents node.
    assert _route.is_deepagents(SimpleNamespace(via="deepagents")) is False


def test_cfg_blocks_extracts_sdk_openai_and_config_dir():
    sdk, openai, cfg_dir = _route._cfg_blocks(_cfg("S", "O", "/prof"))
    assert (sdk, openai, cfg_dir) == ("S", "O", "/prof")
    # A node without `_data` still yields the blocks and a None dir.
    assert _route._cfg_blocks(SimpleNamespace(sdk="S", openai="O")) == ("S", "O", None)
    assert _route._cfg_blocks(None) == (None, None, None)


def test_dispatch_prompt_deepagents_reads_creds_off_cfg(spies):
    out = _route.dispatch_prompt(
        "u", model=_node("deepagents"), cfg=_cfg("SDK", "OAI"),
        cwd="/repo", system_prompt="sys", graph_name="s6-ev-classify")
    assert out == "da_prompt-reply"
    assert "legacy_prompt" not in spies
    sent = spies["da_prompt"]
    assert sent["system_prompt"] == "sys" and sent["cwd"] == "/repo"
    assert sent["graph_name"] == "s6-ev-classify"
    assert (sent["sdk_cfg"], sent["openai_cfg"]) == ("SDK", "OAI")


def test_dispatch_prompt_legacy_ignores_cfg_and_forwards_max_tokens(spies):
    out = _route.dispatch_prompt(
        "u", model=_node("sdk"), cfg=_cfg(), system_prompt="sys", max_tokens=1500)
    assert out == "legacy_prompt-reply"
    assert "da_prompt" not in spies
    sent = spies["legacy_prompt"]
    assert sent["system_prompt"] == "sys" and sent["max_tokens"] == 1500
    # The legacy dispatcher never sees the deepagents-only credential blocks.
    assert "sdk_cfg" not in sent and "openai_cfg" not in sent


def test_dispatch_prompt_legacy_omits_max_tokens_when_unset(spies):
    _route.dispatch_prompt("u", model=_node("cli"), cfg=None, system_prompt="sys")
    assert "max_tokens" not in spies["legacy_prompt"]


def test_dispatch_agentic_deepagents_carries_tools_and_creds(spies):
    out = _route.dispatch_agentic(
        "u", model=_node("deepagents"), cfg=_cfg("SDK", "OAI"), system_prompt="sys",
        allowed_tools=("Read", "Glob", "Grep"), cwd="/repo", max_turns=20,
        graph_name="s6-ev-map")
    assert out == "da_agentic-reply"
    assert "legacy_agentic" not in spies
    sent = spies["da_agentic"]
    assert sent["allowed_tools"] == ["Read", "Glob", "Grep"]
    assert sent["cwd"] == "/repo" and sent["max_turns"] == 20
    assert (sent["sdk_cfg"], sent["openai_cfg"]) == ("SDK", "OAI")


def test_dispatch_agentic_legacy_matches_the_mapper_call_shape(spies):
    _route.dispatch_agentic(
        "u", model=_node("sdk"), cfg=_cfg(), system_prompt="sys",
        allowed_tools=("Read", "Glob", "Grep"), cwd="/repo", max_turns=20,
        tag="s6-ev map")
    sent = spies["legacy_agentic"]
    assert sent["allowed_tools"] == ["Read", "Glob", "Grep"]
    assert sent["cwd"] == "/repo" and sent["max_turns"] == 20 and sent["tag"] == "s6-ev map"
    assert "sdk_cfg" not in sent and "openai_cfg" not in sent
