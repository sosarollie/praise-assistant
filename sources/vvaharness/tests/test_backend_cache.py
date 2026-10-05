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

"""Offline tests for the cache_prefix / capability-gate / kill-switch work
shared by backends/llm/sdk.py, backends/llm/openai.py, and the
backends/llm/registry.py dispatcher.

No real network, no live model. `anthropic`/`openai` client construction is
never exercised here — every test that calls prompt() installs a fake client
whose `messages.stream()` / `chat.completions.create()` just records the
kwargs it was given.

These tests deliberately check ABSENCES as well as presences: a route that
should get no marker must be shown to get none, not merely "a marker was
observed on the routes that were checked". A suite that only asserts markers
appear would pass while shipping a request shape that gets rejected
elsewhere.
"""
from __future__ import annotations

import inspect
import json
import re
import types

import pytest

from vvaharness.backends.llm import openai as oai
from vvaharness.backends.llm import registry as llm
from vvaharness.backends.llm import sdk
from vvaharness.util.tokens import TOKENS

# ─────────────────────────────────────────────────────────────────────────────
# Shared filler helpers — deterministic, no clock/randomness, so token
# estimates are stable across runs. _filler sizes its output by the chars/4
# nominal convention (a construction rule for the test fixtures); the
# minimum-block guard under test rates the result with the shared
# content-aware estimator (util/tokens.estimate_tokens, imported by both
# backends and orchestrator.preflight alike).
# ─────────────────────────────────────────────────────────────────────────────

def _filler(estimated_tokens: int) -> str:
    """`estimated_tokens` under the chars/4 rule (len(text) // 4)."""
    chars_needed = estimated_tokens * 4
    return ("word " * ((chars_needed // 5) + 1))[:chars_needed]


_BELOW_MIN_PREFIX = _filler(100)          # well under every per-model minimum
# The guard estimates real tokens from the content's character mix and marks
# when that estimate (with a small boundary margin — see sdk._CACHE_EST_MARGIN)
# reaches the model's published minimum. Tests here mostly use opus-4-6, whose
# published minimum (4096) is the largest — this filler clears it comfortably.
_ABOVE_MIN_PREFIX = _filler(7000)
# A system prompt comfortably above the same effective floor, for tests where
# the system-block marker itself is the subject.
_ABOVE_MIN_SYSTEM = _filler(7000)


def _system_like_block() -> str:
    """A block shaped like s4's real SYSTEM constant: ~8 KB of narrative prose
    plus a JSON output schema — the mixed prose/schema content the old
    floor*1.25 gate refused for claude-opus-4-7 (its chars/4 estimate sat under
    the inflated floor). Whether the real token count clears the model's 2,048
    minimum is borderline and unknowable offline: every offline estimate lands
    just under it, and Anthropic's tokenizer (not tiktoken) commonly counts
    somewhat higher. The current gate resolves that doubt toward marking —
    estimate * margin clears the floor (see sdk._CACHE_EST_MARGIN)."""
    prose = (
        "You are a security researcher performing deep code analysis. Treat "
        "the slice as hostile and assume at least one exploitable defect is "
        "present; do not stop until every line and data flow has been "
        "examined. Report only findings you can trace to a concrete sink, "
        "with a precondition, a data-flow path, and an impact statement. "
    ) * 21
    schema = (
        '{"findings": [{"title": "string", "severity": "low|medium|high", '
        '"file": "string", "line": 0, "cwe": "string", "description": '
        '"string", "data_flow": ["string"], "recommendation": "string"}]}\n'
    ) * 6
    return prose + "\n\n" + schema


def _numbered_source_block(lines: int = 300) -> str:
    """Dense numbered source, like the shard body s4 puts in the USER turn:
    line-number digits, indentation and operators fragment far heavier than
    chars/4 assumes (~2.45 vs 4 chars/token)."""
    src = [
        "def authenticate(user, password):",
        "    token = hashlib.sha256(password.encode()).hexdigest()",
        '    if db.query("SELECT * FROM users WHERE name=%s" % user):',
        '        return {"ok": True, "tok": token[:16], "n": len(user)}',
        "    return None  # rate-limit missing; see advisory 2021-1234",
    ]
    return "\n".join(f"{i:4d}\t{src[i % len(src)]}" for i in range(1, lines + 1))


# ─────────────────────────────────────────────────────────────────────────────
# sdk.py fakes
# ─────────────────────────────────────────────────────────────────────────────

class _FakeBlock:
    def __init__(self, type, text=None):
        self.type = type
        if text is not None:
            self.text = text


class _FakeMessage:
    def __init__(self, content, usage=None, stop_reason="end_turn"):
        self.content = content
        self.usage = usage
        self.stop_reason = stop_reason


class _FakeStream:
    def __init__(self, msg):
        self._msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self._msg


class _FakeMessages:
    def __init__(self, recorder, msg):
        self._recorder = recorder
        self._msg = msg

    def stream(self, **kw):
        self._recorder.append(kw)
        return _FakeStream(self._msg)


class _FakeSdkClient:
    """Unlike the plain client double used elsewhere, this one carries a
    configurable `base_url` — the exact attribute the capability gate reads
    to tell Anthropic direct, Vertex, and Bedrock apart."""

    def __init__(self, recorder, msg, base_url=None):
        self.messages = _FakeMessages(recorder, msg)
        self.base_url = base_url

    def with_options(self, **kw):
        return self


def _install_sdk_client(monkeypatch, *, base_url=None, content=None):
    recorder: list = []
    if content is None:
        content = [_FakeBlock("text", "hello")]
    msg = _FakeMessage(content, usage=None)
    client = _FakeSdkClient(recorder, msg, base_url=base_url)
    monkeypatch.setattr(sdk, "_get_client", lambda: client)
    return recorder


@pytest.fixture(autouse=True)
def _isolate_sdk(monkeypatch):
    monkeypatch.setattr(sdk, "_client", None)
    monkeypatch.setattr(sdk, "_cfg", {
        "api_key": None, "base_url": None, "verify_ssl": True,
        "ca_cert": None, "client_cert": None,
        "allow_api_key_fallback": False,
        "cache_min_block_tokens": None,   # None -> per-model published minimum
        "cache_markers": "on",
        "cache_route": "auto",
    })
    # anthropic.APIStatusError / APIConnectionError must exist as importable
    # names for prompt()'s except clauses even though nothing raises them.
    fake_anthropic = types.SimpleNamespace(
        APIStatusError=type("APIStatusError", (Exception,), {}),
        APIConnectionError=type("APIConnectionError", (Exception,), {}),
    )
    monkeypatch.setattr(sdk, "anthropic", fake_anthropic)
    yield


@pytest.fixture(autouse=True)
def _isolate_oai(monkeypatch):
    monkeypatch.setattr(oai, "_client", None, raising=False)
    monkeypatch.setattr(oai, "_cfg", {
        "api_key": None, "base_url": None, "verify_ssl": True,
        "ca_cert": None, "organization": None, "cache_markers": "on",
    }, raising=False)
    yield


# ─────────────────────────────────────────────────────────────────────────────
# cache_prefix parameter shape and the byte-identical-when-omitted guarantee.
# ─────────────────────────────────────────────────────────────────────────────

def test_sdk_prompt_signature_has_cache_prefix_keyword_only():
    params = inspect.signature(sdk.prompt).parameters
    assert "cache_prefix" in params
    assert params["cache_prefix"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["cache_prefix"].default is None


def test_oai_prompt_signature_has_cache_prefix_keyword_only():
    params = inspect.signature(oai.prompt).parameters
    assert "cache_prefix" in params
    assert params["cache_prefix"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["cache_prefix"].default is None


def test_sdk_prompt_omitting_cache_prefix_is_byte_identical(monkeypatch):
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("hi", model="opus-4-6")
    # Exactly what today's code (no cache_prefix parameter at all) sends.
    assert rec[0]["messages"] == [{"role": "user", "content": "hi"}]


def test_sdk_prompt_omitting_cache_prefix_matches_with_system_prompt(monkeypatch):
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("hi", model="opus-4-6", system_prompt="be helpful")
    assert rec[0]["messages"] == [{"role": "user", "content": "hi"}]
    # A sub-minimum system prompt gets NO marker (below the model's published
    # minimum the API caches nothing while the marker still spends a slot),
    # so the system arrives as the plain string.
    assert rec[0]["system"] == "be helpful"


def test_oai_prompt_omitting_cache_prefix_is_byte_identical(monkeypatch):
    calls = {"n": 0}

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            calls["kw"] = kw
            return [types.SimpleNamespace(choices=[], usage=None)]

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    oai.prompt("hi", model="gpt-x")
    msgs = calls["kw"]["messages"]
    assert msgs[-1] == {"role": "user", "content": "hi"}


# ─────────────────────────────────────────────────────────────────────────────
# Capability gate: route classification from the resolved client's base_url,
# never from the model id.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("base_url,expected", [
    (None, sdk._ROUTE_ANTHROPIC),
    ("https://api.anthropic.com", sdk._ROUTE_ANTHROPIC),
    ("https://api.anthropic.com/v1", sdk._ROUTE_ANTHROPIC),
    ("https://us-central1-aiplatform.googleapis.com/v1", sdk._ROUTE_VERTEX),
    # A corporate hostname merely containing "vertex" is NOT a Vertex endpoint.
    # Matching it as one sent Anthropic markers to an unrecognised gateway,
    # which risks a rejected request; unrecognised must fall through to no
    # markers at all.
    ("https://my-vertex-gateway.example.com/v1", sdk._ROUTE_UNKNOWN),
    ("https://us-central1-aiplatform.googleapis.com", sdk._ROUTE_VERTEX),
    ("https://bedrock-runtime.us-east-1.amazonaws.com", sdk._ROUTE_BEDROCK),
    # Likewise for "bedrock" as a substring of an unrelated corporate host.
    ("https://my-bedrock-gateway.example.com", sdk._ROUTE_UNKNOWN),
    ("https://gateway.mycorp.internal/", sdk._ROUTE_UNKNOWN),
    ("https://claude-code-gateway.example.net/", sdk._ROUTE_UNKNOWN),
])
def test_cache_route_classification(base_url, expected):
    client = types.SimpleNamespace(base_url=base_url)
    assert sdk._cache_route(client) == expected


def test_cache_route_never_keyed_on_model_id():
    # The gate takes no model argument at all -- Bedrock/Vertex/Anthropic are
    # indistinguishable at the `via: sdk` transport level and can only be
    # told apart from the client, never from the model id.
    assert "model" not in inspect.signature(sdk._cache_route).parameters


def test_unknown_route_gets_neither_marker(monkeypatch):
    rec = _install_sdk_client(monkeypatch, base_url="https://gateway.mycorp.internal/")
    sdk.prompt("rest", model="opus-4-6", cache_prefix=_ABOVE_MIN_PREFIX)
    content = rec[0]["messages"][0]["content"]
    # Folded into one string -- no block list, no cache_control, no cachePoint.
    assert isinstance(content, str)
    assert content == _ABOVE_MIN_PREFIX + "rest"
    assert "cache_control" not in content
    assert "cachePoint" not in content


def test_anthropic_route_gets_cache_control_breakpoint(monkeypatch):
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("rest", model="opus-4-6", cache_prefix=_ABOVE_MIN_PREFIX)
    content = rec[0]["messages"][0]["content"]
    assert content == [
        {"type": "text", "text": _ABOVE_MIN_PREFIX,
         "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "rest"},
    ]


def test_vertex_route_gets_cache_control_breakpoint(monkeypatch):
    rec = _install_sdk_client(
        monkeypatch, base_url="https://us-central1-aiplatform.googleapis.com")
    sdk.prompt("rest", model="opus-4-6", cache_prefix=_ABOVE_MIN_PREFIX)
    content = rec[0]["messages"][0]["content"]
    assert content[0]["cache_control"] == {"type": "ephemeral"}


def test_bedrock_route_gets_no_marker_but_keeps_the_stable_prefix(monkeypatch):
    """A Bedrock-shaped endpoint deliberately receives no cache marker.

    The documented `cachePoint` block belongs to the Converse API, but this
    package only ever builds an Anthropic-Messages-shaped client, so the only
    thing such a base_url can be reached through here speaks Messages — where
    an untyped `cachePoint` sibling block is a foreign construct whose likeliest
    outcome is a rejected request. Emitting a marker whose wire shape has never
    been observed on the only client that can be constructed is the opposite of
    failing closed.

    The prefix must still be delivered, first and intact, so the route keeps
    whatever benefit a provider-managed cache gives a stable prefix.
    """
    rec = _install_sdk_client(
        monkeypatch, base_url="https://bedrock-runtime.us-east-1.amazonaws.com")
    sdk.prompt("rest", model="opus-4-6", cache_prefix=_ABOVE_MIN_PREFIX)
    content = rec[0]["messages"][0]["content"]
    assert isinstance(content, str), "expected a single concatenated turn"
    assert content == _ABOVE_MIN_PREFIX + "rest"
    assert "cachePoint" not in json.dumps(rec[0], default=str)


# ─────────────────────────────────────────────────────────────────────────────
# cache_route: the operator's declaration of the endpoint's marker regime.
# Host detection can only fail CLOSED on a corporate gateway, so a gateway
# that genuinely honours cache_control needs a way to say so.
# ─────────────────────────────────────────────────────────────────────────────

def test_cache_route_override_promotes_an_unknown_gateway(monkeypatch):
    # (a) The override changes the classification of a non-Anthropic host.
    client = types.SimpleNamespace(base_url="https://gateway.mycorp.internal/")
    assert sdk._cache_route(client) == sdk._ROUTE_UNKNOWN
    sdk.configure(cache_route="anthropic")
    assert sdk._cache_route(client) == sdk._ROUTE_ANTHROPIC


def test_cache_route_auto_preserves_host_detection(monkeypatch):
    # (b) Explicit "auto" is byte-for-byte today's behaviour: recognised
    # hosts classify as themselves, unrecognised ones stay unknown.
    sdk.configure(cache_route="auto")
    for base_url, expected in [
        ("https://api.anthropic.com", sdk._ROUTE_ANTHROPIC),
        ("https://us-central1-aiplatform.googleapis.com", sdk._ROUTE_VERTEX),
        ("https://bedrock-runtime.us-east-1.amazonaws.com", sdk._ROUTE_BEDROCK),
        ("https://gateway.mycorp.internal/", sdk._ROUTE_UNKNOWN),
    ]:
        client = types.SimpleNamespace(base_url=base_url)
        assert sdk._cache_route(client) == expected


def test_cache_route_none_forces_no_markers_even_on_anthropic(monkeypatch):
    sdk.configure(cache_route="none")
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("rest", model="opus-4-6", system_prompt=_ABOVE_MIN_SYSTEM,
               cache_prefix=_ABOVE_MIN_PREFIX)
    assert rec[0]["system"] == _ABOVE_MIN_SYSTEM
    content = rec[0]["messages"][0]["content"]
    assert isinstance(content, str)
    assert content == _ABOVE_MIN_PREFIX + "rest"


def test_cache_route_override_enables_markers_on_a_corporate_gateway(monkeypatch):
    # End-to-end: the exact customer configuration the knob exists for — a
    # corporate gateway that honours cache_control but can never be
    # recognised by hostname. Both markers engage once the operator opts in.
    sdk.configure(cache_route="anthropic")
    rec = _install_sdk_client(monkeypatch,
                              base_url="https://gateway.mycorp.internal/")
    sdk.prompt("rest", model="opus-4-6", system_prompt=_ABOVE_MIN_SYSTEM,
               cache_prefix=_ABOVE_MIN_PREFIX)
    assert rec[0]["system"][0]["cache_control"] == {"type": "ephemeral"}
    content = rec[0]["messages"][0]["content"]
    assert content[0]["cache_control"] == {"type": "ephemeral"}
    assert content[1] == {"type": "text", "text": "rest"}


def test_cache_route_forced_bedrock_still_places_no_markers(monkeypatch):
    # "bedrock" is an accepted declaration but the bedrock regime currently
    # places no markers (see _build_cache_prefix_content for the reasons), so
    # forcing it is a classification, not a marker grant.
    sdk.configure(cache_route="bedrock")
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("rest", model="opus-4-6", cache_prefix=_ABOVE_MIN_PREFIX)
    content = rec[0]["messages"][0]["content"]
    assert isinstance(content, str)
    assert content == _ABOVE_MIN_PREFIX + "rest"


def test_cache_route_is_case_insensitive(monkeypatch):
    sdk.configure(cache_route="Anthropic")
    client = types.SimpleNamespace(base_url="https://gateway.mycorp.internal/")
    assert sdk._cache_route(client) == sdk._ROUTE_ANTHROPIC


def test_cache_route_yaml_false_means_none(monkeypatch):
    # PyYAML parses an unquoted `no`/`off` as boolean False — the same
    # footgun the cache_markers switch already tolerates.
    sdk.configure(cache_route=False)
    client = types.SimpleNamespace(base_url="https://api.anthropic.com")
    assert sdk._cache_route(client) == sdk._ROUTE_UNKNOWN


def test_cache_route_unrecognised_value_falls_back_to_auto(monkeypatch, capsys):
    sdk.configure(cache_route="openai")
    client = types.SimpleNamespace(base_url="https://api.anthropic.com")
    assert sdk._cache_route(client) == sdk._ROUTE_ANTHROPIC
    assert "cache_route" in capsys.readouterr().err


def test_agentic_history_marker_respects_the_route_gate(monkeypatch):
    # The last-block marker the agentic loop places each turn obeys the same
    # single policy as the system and prefix markers.
    msgs = [{"role": "user", "content": [{"type": "text", "text": "go"}]}]
    unknown = types.SimpleNamespace(base_url="https://gateway.mycorp.internal/")
    out = sdk._with_cache_marker(unknown, msgs)
    assert "cache_control" not in out[0]["content"][-1]
    anthropic_direct = types.SimpleNamespace(base_url="https://api.anthropic.com")
    out = sdk._with_cache_marker(anthropic_direct, msgs)
    assert out[0]["content"][-1]["cache_control"] == {"type": "ephemeral"}


# ─────────────────────────────────────────────────────────────────────────────
# Minimum-block guard.
# ─────────────────────────────────────────────────────────────────────────────

def test_below_minimum_prefix_yields_no_breakpoint(monkeypatch):
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("rest", model="opus-4-6", cache_prefix=_BELOW_MIN_PREFIX)
    content = rec[0]["messages"][0]["content"]
    # A 100-token-ish prefix must NOT get a breakpoint, even on a fully
    # capable route -- it would fail silently and still spend one of the
    # four available marker slots.
    assert isinstance(content, str)
    assert content == _BELOW_MIN_PREFIX + "rest"


def test_system_sized_prose_and_schema_block_is_marked_for_opus_4_7(monkeypatch):
    # Requirement (a): a block shaped like s4's real SYSTEM (~8 KB of mixed
    # prose and JSON schema) MUST be marked for claude-opus-4-7. Everything
    # asserted here is a fact about OUR gate: the content-aware estimate
    # times the boundary margin clears the model's 2,048 floor, so the marker
    # is placed. Whether the provider's real tokenizer puts the block over
    # 2,048 — i.e. whether the marker actually caches — is borderline and
    # unknowable offline (offline estimates land just under; real counts run
    # somewhat higher), and is deliberately NOT asserted. The margin spends
    # the near-free marker rather than forgo a possible cache hit.
    block = _system_like_block()
    assert 7000 <= len(block) <= 10000
    # The old gate refused it: chars/4 was under the inflated 2048*1.25 floor.
    assert len(block) // 4 < 2048 * 1.25
    # The content-aware estimate alone is under the floor — the block
    # straddles it — and it is the margin that carries the gate's decision.
    est = sdk.estimate_tokens(block)
    assert est < 2048
    assert est * sdk._CACHE_EST_MARGIN >= 2048
    # Therefore the gate decides to mark it.
    assert sdk._cache_prefix_meets_minimum(block, "claude-opus-4-7") is True
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("hi", model="claude-opus-4-7", system_prompt=block)
    assert rec[0]["system"] == [{
        "type": "text", "text": block,
        "cache_control": {"type": "ephemeral"}}]


def test_prose_block_below_the_minimum_is_not_marked(monkeypatch):
    # Requirement (b): a genuinely small prose block — well under the floor
    # even after the boundary margin — must NOT be marked. Marking it would
    # spend one of the four breakpoint slots while the API silently caches
    # nothing.
    small = _filler(900)   # ~900 estimated tokens; *1.35 is still < 2048
    assert sdk._cache_prefix_meets_minimum(small, "claude-opus-4-7") is False
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("hi", model="claude-opus-4-7", system_prompt=small)
    assert rec[0]["system"] == small


def test_dense_numbered_source_is_estimated_above_chars_over_four():
    # The fix in the OTHER direction: dense numbered source tokenizes far
    # heavier than chars/4 assumes, so the content-aware estimate must exceed
    # the flat chars/4 count for it. Under-counting it is what wrongly refused
    # dense shard prefixes at the old gate.
    dense = _numbered_source_block()
    assert sdk.estimate_tokens(dense) > len(dense) // 4
    # ...while a pure-prose block of the same length is NOT inflated the same
    # way (chars/4 is already about right for prose).
    prose = _filler(len(dense) // 4)
    assert sdk.estimate_tokens(prose) <= len(prose) // 4 + 1


def test_minimum_block_guard_is_configurable(monkeypatch):
    # An operator-forced global floor overrides the per-model table and lets
    # the same prefix clear it.
    sdk.configure(cache_min_block_tokens=50)
    assert sdk._cache_prefix_meets_minimum(_BELOW_MIN_PREFIX, "opus-4-6") is True


@pytest.mark.parametrize("model,floor", [
    # Published per-model minimums. Deliberately NON-MONOTONIC across
    # releases (4-5/4-6 need more than 4-7, which needs more than 4-8), so a
    # version-ordering heuristic can never substitute for the table.
    ("claude-opus-5", 512),
    ("claude-fable-5", 512),
    ("claude-opus-4-8", 1024),
    ("claude-opus-4-1", 1024),
    ("claude-sonnet-5", 1024),
    ("claude-sonnet-4-6", 1024),
    ("claude-sonnet-4-5", 1024),
    ("claude-opus-4-7", 2048),
    ("claude-haiku-3-5", 2048),
    ("claude-opus-4-6", 4096),
    ("claude-opus-4-5", 4096),
    ("claude-haiku-4-5", 4096),
])
def test_per_model_minimum_lookup(model, floor):
    assert sdk._cache_min_tokens_for(model) == floor


def test_unknown_model_gets_the_largest_published_minimum():
    # Below the minimum the API silently caches nothing, so an unrecognised
    # model must be held to the strictest published floor, not a guess.
    assert sdk._cache_min_tokens_for("some-future-model") == 4096


def test_operator_floor_override_beats_the_table():
    sdk.configure(cache_min_block_tokens=512)
    assert sdk._cache_min_tokens_for("claude-opus-4-6") == 512


def test_shipped_default_floor_is_the_per_model_table():
    """Assert the SHIPPED default, not the test fixture's copy of it.

    The autouse isolation fixture installs its own `_cfg`, so reading
    `sdk._cfg` here would assert the fixture and stay green even when the
    real default in the module was changed.
    """
    src = inspect.getsource(sdk)
    assert '"cache_min_block_tokens": None' in src, (
        "the shipped default must stay None (use the published per-model "
        "minimum) — a global number is wrong in both directions: too strict "
        "for the 512/1024-minimum models, and silently inert below the "
        "4096-minimum ones"
    )


def test_minimum_is_cumulative_across_system_and_prefix(monkeypatch):
    """The provider evaluates the minimum against the CUMULATIVE prefix
    (tools -> system -> messages up to the marker), not the marked block
    alone. A shard prefix that is too small by itself must still get its
    breakpoint when the system prompt ahead of it carries it over the floor —
    on s4 this is exactly the case that matters."""
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    system = _filler(900)    # below opus-4-7's floor on its own
    prefix = _filler(1100)   # also below it alone; combined they clear it
    sdk.prompt("rest", model="claude-opus-4-7", system_prompt=system,
               cache_prefix=prefix)
    content = rec[0]["messages"][0]["content"]
    assert content == [
        {"type": "text", "text": prefix,
         "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "rest"},
    ]
    # The system block does NOT ride along: ITS cumulative prefix is only
    # itself (nothing renders before it here), and that is below the floor.
    assert rec[0]["system"] == system


def test_per_model_floor_changes_what_qualifies(monkeypatch):
    # The same 1500-estimated-token prefix (no system prompt to carry it):
    # below opus-4-7's floor (2048*1.25), above claude-opus-5's (512*1.25).
    prefix = _filler(1500)
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("rest", model="claude-opus-4-7", cache_prefix=prefix)
    assert isinstance(rec[0]["messages"][0]["content"], str)
    rec2 = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("rest", model="claude-opus-5", cache_prefix=prefix)
    assert rec2[0]["messages"][0]["content"][0]["cache_control"] == {
        "type": "ephemeral"}


# ─────────────────────────────────────────────────────────────────────────────
# The system-block marker: same gate as every other marker (route + kill
# switch + cumulative minimum), no longer unconditional.
# ─────────────────────────────────────────────────────────────────────────────

def test_sub_minimum_system_prompt_gets_no_cache_control(monkeypatch):
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("hi", model="opus-4-6", system_prompt="be helpful")
    # Provably inert at this size (the API caches nothing below the model
    # minimum and reports no error) — the marker must not spend a slot.
    assert rec[0]["system"] == "be helpful"


def test_above_minimum_system_prompt_gets_cache_control(monkeypatch):
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("hi", model="opus-4-6", system_prompt=_ABOVE_MIN_SYSTEM)
    assert rec[0]["system"] == [{
        "type": "text", "text": _ABOVE_MIN_SYSTEM,
        "cache_control": {"type": "ephemeral"},
    }]


def test_system_marker_respects_the_route_gate(monkeypatch):
    # One coherent policy: an endpoint the gate would not trust with the
    # user-prefix marker is not trusted with the system marker either — a
    # gateway strict enough to 400 would otherwise reject on the system block
    # first and the fail-closed protection would never engage.
    rec = _install_sdk_client(monkeypatch,
                              base_url="https://gateway.mycorp.internal/")
    sdk.prompt("hi", model="opus-4-6", system_prompt=_ABOVE_MIN_SYSTEM)
    assert rec[0]["system"] == _ABOVE_MIN_SYSTEM


def test_kill_switch_shipped_default_is_on():
    """Same reasoning: the fixture supplies "on", so this reads the source."""
    src = inspect.getsource(sdk)
    assert '"cache_markers": "on"' in src


# ─────────────────────────────────────────────────────────────────────────────
# Never exceed Anthropic's 4-breakpoint cap.
# ─────────────────────────────────────────────────────────────────────────────

def _count_markers(obj) -> int:
    n = 0
    if isinstance(obj, dict):
        if "cache_control" in obj or "cachePoint" in obj:
            n += 1
        for v in obj.values():
            n += _count_markers(v)
    elif isinstance(obj, list):
        for v in obj:
            n += _count_markers(v)
    return n


def test_anthropic_route_never_exceeds_four_markers(monkeypatch):
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    # Both the system prompt and the prefix are above-minimum, so both
    # markers are placed — the worst case prompt() can produce.
    sdk.prompt("rest", model="opus-4-6", system_prompt=_ABOVE_MIN_SYSTEM,
               cache_prefix=_ABOVE_MIN_PREFIX)
    total = _count_markers(rec[0])
    assert total == 2          # system block + cache_prefix boundary
    assert total <= 4


# ─────────────────────────────────────────────────────────────────────────────
# Runtime kill switch: cache_markers: off suppresses everything, on every
# route, including the pre-existing system_prompt marker.
# ─────────────────────────────────────────────────────────────────────────────

def test_kill_switch_suppresses_system_prompt_marker(monkeypatch):
    sdk.configure(cache_markers="off")
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    # Above-minimum on a capable route, so the kill switch is the ONLY thing
    # that can be suppressing the marker here.
    sdk.prompt("hi", model="opus-4-6", system_prompt=_ABOVE_MIN_SYSTEM)
    assert rec[0]["system"] == _ABOVE_MIN_SYSTEM   # plain string, no marker


def test_kill_switch_suppresses_cache_prefix_breakpoint_even_when_capable(monkeypatch):
    sdk.configure(cache_markers="off")
    rec = _install_sdk_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("rest", model="opus-4-6", cache_prefix=_ABOVE_MIN_PREFIX)
    content = rec[0]["messages"][0]["content"]
    assert isinstance(content, str)
    assert content == _ABOVE_MIN_PREFIX + "rest"


def test_kill_switch_is_case_insensitive():
    assert sdk._cache_markers_enabled() is True
    sdk.configure(cache_markers="OFF")
    assert sdk._cache_markers_enabled() is False
    sdk.configure(cache_markers="on")
    assert sdk._cache_markers_enabled() is True


def test_kill_switch_suppresses_oai_prompt_cache_key(monkeypatch):
    oai.configure(cache_markers="off")
    calls = {}

    class _Completions:
        def create(self, **kw):
            calls["kw"] = kw
            return [types.SimpleNamespace(choices=[], usage=None)]

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    oai.prompt("hi", model="gpt-x")
    assert "prompt_cache_key" not in calls["kw"]


def test_kill_switch_suppresses_agentic_system_marker(monkeypatch):
    sdk.configure(cache_markers="off")

    class _Msg:
        content = [_FakeBlock("text", "done")]
        usage = None
        stop_reason = "end_turn"

    class _Stream:
        def __init__(self, msg):
            self._msg = msg

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            return self._msg

    captured = {}

    class _Messages:
        def stream(self, **kw):
            captured.update(kw)
            return _Stream(_Msg())

    class _Client:
        messages = _Messages()

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    monkeypatch.setattr(sdk._localtools, "supported", lambda tools: (tools, []))
    monkeypatch.setattr(sdk._localtools, "anthropic_schemas_for", lambda tools: [])
    # Above-minimum so the kill switch, not the size gate, is what's tested.
    sdk.agentic("go", model="opus-4-6", system_prompt=_ABOVE_MIN_SYSTEM,
                cwd="/tmp", allowed_tools=["Read"])
    assert captured["system"] == _ABOVE_MIN_SYSTEM


# ─────────────────────────────────────────────────────────────────────────────
# prompt_cache_key on the OpenAI-compatible path.
# ─────────────────────────────────────────────────────────────────────────────

def _capture_oai_kw(monkeypatch, **prompt_kwargs):
    calls = {}

    class _Completions:
        def create(self, **kw):
            calls["kw"] = kw
            return [types.SimpleNamespace(choices=[], usage=None)]

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    oai.prompt("hi", model="gpt-x", **prompt_kwargs)
    return calls["kw"]


def test_openai_route_gets_prompt_cache_key_and_no_cache_control_markers(monkeypatch):
    kw = _capture_oai_kw(monkeypatch, tag="s4 chunk-01",
                         cache_prefix=_ABOVE_MIN_PREFIX)
    assert "prompt_cache_key" in kw
    assert isinstance(kw["prompt_cache_key"], str)
    # No explicit breakpoint exists on this route -- content stays a single
    # string, never a block list, and never carries cache_control/cachePoint.
    content = kw["messages"][-1]["content"]
    assert isinstance(content, str)
    assert content == _ABOVE_MIN_PREFIX + "hi"
    assert "cache_control" not in str(kw)
    assert "cachePoint" not in str(kw)


def test_prompt_cache_key_deterministic_per_stage_repo_model(monkeypatch):
    tracker = types.SimpleNamespace(repo_name="my-app")
    monkeypatch.setattr(oai, "get_active_tracker", lambda: tracker)
    k1 = oai._prompt_cache_key("s4 chunk-01", "gpt-5")
    k2 = oai._prompt_cache_key("s4 chunk-02", "gpt-5")  # same stage (first word)
    assert k1 == k2
    k3 = oai._prompt_cache_key("s3 decompose", "gpt-5")  # different stage
    assert k3 != k1


def test_prompt_cache_key_changes_with_repo_name(monkeypatch):
    monkeypatch.setattr(oai, "get_active_tracker",
                        lambda: types.SimpleNamespace(repo_name="repo-a"))
    k_a = oai._prompt_cache_key("s4 chunk-01", "gpt-5")
    monkeypatch.setattr(oai, "get_active_tracker",
                        lambda: types.SimpleNamespace(repo_name="repo-b"))
    k_b = oai._prompt_cache_key("s4 chunk-01", "gpt-5")
    assert k_a != k_b


def test_prompt_cache_key_never_contains_repo_root_or_path_separator(monkeypatch):
    tracker = types.SimpleNamespace(repo_name="my-app")
    monkeypatch.setattr(oai, "get_active_tracker", lambda: tracker)
    repo_root = "/Users/alice/Projects/super-secret-internal-codename"
    key = oai._prompt_cache_key(f"s4 chunk-01 root={repo_root}", "gpt-5")
    assert "/" not in key
    assert "\\" not in key
    assert repo_root not in key
    assert "super-secret-internal-codename" not in key
    assert len(key) == 32
    # Structurally impossible to leak: the function has no repo_root param.
    assert "repo_root" not in inspect.signature(oai._prompt_cache_key).parameters


def test_prompt_cache_key_handles_no_active_tracker(monkeypatch):
    monkeypatch.setattr(oai, "get_active_tracker", lambda: None)
    key = oai._prompt_cache_key("s2 threatmodel", "gpt-5")
    assert len(key) == 32


def test_prompt_cache_key_handles_missing_tag(monkeypatch):
    monkeypatch.setattr(oai, "get_active_tracker", lambda: None)
    key = oai._prompt_cache_key(None, "gpt-5")
    assert len(key) == 32


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher (backends/llm/registry.py): cache_prefix must never reach llm/cli.py,
# which has no such parameter and no catch-all **kwargs. registry.prompt() pops it and
# folds it into the user prompt instead.
# ─────────────────────────────────────────────────────────────────────────────

def _make_recording_backend():
    calls = []
    backend = types.SimpleNamespace()

    def _prompt(user_prompt, *, model, **kw):
        calls.append((user_prompt, model, kw))
        return "OK"

    backend.prompt = _prompt
    return backend, calls


def _install_backend(monkeypatch, via: str, backend):
    """Substitute *backend* for the *via* route at ``get_backend``, the dispatcher's single
    resolution point. ``_BACKENDS`` holds import PATHS resolved on selection, so there is no
    module object in that mapping to patch — same seam tests/test_backend_llm.py uses.
    """
    def _get_backend(requested_via, model_id):
        if requested_via != via:
            raise ValueError(f"Unknown backend `via: {requested_via}` for model {model_id}")
        return backend

    monkeypatch.setattr(llm, "get_backend", _get_backend)


def test_dispatcher_folds_cache_prefix_for_cli_route(monkeypatch):
    cli_backend, cli_calls = _make_recording_backend()
    _install_backend(monkeypatch, "cli", cli_backend)

    llm.prompt("rest", model="bare-model", cache_prefix="PREFIX-")

    assert len(cli_calls) == 1
    user_prompt, _model, kw = cli_calls[0]
    # Folded into the single positional argument cli.prompt() actually has —
    # never forwarded as a kwarg it doesn't accept.
    assert user_prompt == "PREFIX-rest"
    assert "cache_prefix" not in kw


def test_dispatcher_forwards_cache_prefix_unmodified_for_sdk_route(monkeypatch):
    sdk_backend, sdk_calls = _make_recording_backend()
    _install_backend(monkeypatch, "sdk", sdk_backend)
    cfg = types.SimpleNamespace(id="m", via="sdk")

    llm.prompt("rest", model=cfg, cache_prefix="PREFIX-")

    user_prompt, _model, kw = sdk_calls[0]
    assert user_prompt == "rest"
    assert kw["cache_prefix"] == "PREFIX-"


def test_dispatcher_forwards_cache_prefix_unmodified_for_openai_route(monkeypatch):
    oai_backend, oai_calls = _make_recording_backend()
    _install_backend(monkeypatch, "openai", oai_backend)
    cfg = types.SimpleNamespace(id="m", via="openai")

    llm.prompt("rest", model=cfg, cache_prefix="PREFIX-")

    user_prompt, _model, kw = oai_calls[0]
    assert user_prompt == "rest"
    assert kw["cache_prefix"] == "PREFIX-"


def test_dispatcher_cli_route_without_cache_prefix_is_unaffected(monkeypatch):
    # No cache_prefix passed at all -> nothing folded, nothing popped that
    # wasn't already being popped.
    cli_backend, cli_calls = _make_recording_backend()
    _install_backend(monkeypatch, "cli", cli_backend)

    llm.prompt("just this", model="bare-model")

    user_prompt, _model, kw = cli_calls[0]
    assert user_prompt == "just this"
    assert "cache_prefix" not in kw


# ─────────────────────────────────────────────────────────────────────────────
# The prompt-cache hint self-heals on a rejecting endpoint.
#
# This field is sent to every OpenAI-compatible endpoint, not only OpenAI's own,
# and a strict gateway may reject an unrecognised parameter outright. Without the
# drop-and-retry branch that is a fatal error on every call of every scan, for a
# field that is never more than an optimisation. Nothing covered this before.
# ─────────────────────────────────────────────────────────────────────────────

def test_a_rejected_prompt_cache_key_is_dropped_and_the_call_retried(monkeypatch):
    oai._NO_CACHE_KEY_MODELS.discard("gw-model")
    seen: list[dict] = []

    class _Err(Exception):
        status_code = 400

        def __str__(self):
            return ("Unrecognized request argument supplied: prompt_cache_key")

    class _Completions:
        def create(self, **kw):
            seen.append(dict(kw))
            if "prompt_cache_key" in kw:
                raise _Err()
            return [types.SimpleNamespace(choices=[], usage=None)]

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "openai",
                        types.SimpleNamespace(BadRequestError=_Err), raising=False)
    monkeypatch.setattr(oai, "_get_client", lambda: _Client())

    oai.prompt("hi", model="gw-model", tag="s4 chunk-01")

    assert len(seen) == 2, "expected one rejected attempt then one retry"
    assert "prompt_cache_key" in seen[0]
    assert "prompt_cache_key" not in seen[1], "the retry must omit the field"
    assert "gw-model" in oai._NO_CACHE_KEY_MODELS, (
        "the rejection must be remembered so the rest of the run stops sending it"
    )
    oai._NO_CACHE_KEY_MODELS.discard("gw-model")


def test_a_remembered_rejection_stops_the_field_being_sent_again(monkeypatch):
    oai._NO_CACHE_KEY_MODELS.add("known-bad")
    seen: list[dict] = []

    class _Completions:
        def create(self, **kw):
            seen.append(dict(kw))
            return [types.SimpleNamespace(choices=[], usage=None)]

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    oai.prompt("hi", model="known-bad", tag="s4 chunk-02")
    assert "prompt_cache_key" not in seen[0]
    oai._NO_CACHE_KEY_MODELS.discard("known-bad")


# ─────────────────────────────────────────────────────────────────────────────
# The kill switch must reach the backends from a LOADED CONFIG, not merely be
# readable by a helper. This is the whole point of the escape hatch, and the
# wiring — as opposed to the backend-internal behaviour — had no test.
# ─────────────────────────────────────────────────────────────────────────────

def test_kill_switch_reaches_both_backends_from_a_loaded_config(monkeypatch):
    from pathlib import Path
    from vvaharness.config import Config
    from vvaharness.orchestrator.preflight import configure_backends

    # Deliberately no `sdk:`/`openai:` section: these settings are top-level and
    # must not be gated on the presence of an unrelated credential block.
    cfg = Config({"models": {"deepdive": {"id": "m", "via": "sdk"}},
                  "cache_markers": False,          # unquoted YAML `off`
                  "cache_min_block_tokens": 512})
    configure_backends(cfg, Path("."))

    assert sdk._cache_markers_enabled() is False
    assert oai._cache_markers_enabled() is False
    assert sdk._cfg["cache_min_block_tokens"] == 512


def test_markers_stay_enabled_when_the_config_says_nothing(monkeypatch):
    from pathlib import Path
    from vvaharness.config import Config
    from vvaharness.orchestrator.preflight import configure_backends

    cfg = Config({"models": {"deepdive": {"id": "m", "via": "sdk"}}})
    configure_backends(cfg, Path("."))
    assert sdk._cache_markers_enabled() is True
    assert oai._cache_markers_enabled() is True


# ─────────────────────────────────────────────────────────────────────────────
# Unparsed cache accounting. util/tokens.py coerces missing cache fields with
# `or 0`, so a provider reporting cache usage under names this codebase does
# not parse (e.g. Bedrock's camelCase cacheReadInputTokens) was
# indistinguishable from a real zero in every artifact kept — a working cache
# read as "the marker is not honoured". Backends now flag such keys (NAMES
# ONLY, never values) on stderr once per distinct key-set and count each
# affected call in the `cache_unparsed` bucket entry.
#
# TOKENS is process-global; the suite-wide autouse fixture in conftest.py
# resets it (including the noted-key-set dedupe) around every test.
# ─────────────────────────────────────────────────────────────────────────────

def _cache_unparsed_total() -> int:
    return sum(b.get("cache_unparsed", 0)
               for b in TOKENS.snapshot()["by_phase"].values())


def _install_sdk_client_with_usage(monkeypatch, usage_dict):
    usage = types.SimpleNamespace(model_dump=lambda: dict(usage_dict))
    msg = _FakeMessage([_FakeBlock("text", "hello")], usage=usage)
    client = _FakeSdkClient([], msg, base_url="https://api.anthropic.com")
    monkeypatch.setattr(sdk, "_get_client", lambda: client)


def test_sdk_unparsed_camelcase_cache_key_is_counted_and_named(monkeypatch, capsys):
    _install_sdk_client_with_usage(
        monkeypatch, {"input_tokens": 50, "output_tokens": 3,
                      "cacheReadInputTokens": 9000})
    sdk.prompt("hi", model="opus-4-6")
    err = capsys.readouterr().err
    assert "cacheReadInputTokens" in err     # the key NAME is reported...
    assert "9000" not in err                 # ...its VALUE never is
    assert _cache_unparsed_total() == 1


def test_sdk_parsed_only_usage_produces_no_note_and_no_bump(monkeypatch, capsys):
    _install_sdk_client_with_usage(
        monkeypatch, {"input_tokens": 50, "output_tokens": 3,
                      "cache_read_input_tokens": 12,
                      "cache_creation_input_tokens": 34})
    sdk.prompt("hi", model="opus-4-6")
    assert "unparsed" not in capsys.readouterr().err
    assert _cache_unparsed_total() == 0


def test_present_as_zero_parsed_field_is_a_real_zero_not_unparsed(capsys):
    # A parsed name at 0 is a genuine zero; and the None a typed model_dump()
    # fabricates for fields the wire never sent is "absent", not a report.
    sdk._note_unparsed_cache_keys({"input_tokens": 50,
                                   "cache_read_input_tokens": 0,
                                   "cache_creation_input_tokens": None,
                                   "cache_creation": None})
    assert capsys.readouterr().err == ""
    assert _cache_unparsed_total() == 0


def test_present_as_zero_under_an_unparsed_name_is_still_reported(capsys):
    # The converse: 0 under a name nothing parses IS information — it proves
    # the provider reports cache accounting somewhere this build never looks.
    sdk._note_unparsed_cache_keys({"input_tokens": 50,
                                   "cacheReadInputTokens": 0})
    assert "cacheReadInputTokens" in capsys.readouterr().err
    assert _cache_unparsed_total() == 1


def test_note_emitted_once_per_distinct_key_set_counter_bumped_per_call(capsys):
    u = {"cacheReadInputTokens": 1}
    sdk._note_unparsed_cache_keys(u)
    sdk._note_unparsed_cache_keys(u)
    assert capsys.readouterr().err.count("cacheReadInputTokens") == 1
    # A DIFFERENT key-set earns its own (single) note...
    u2 = {"cacheReadInputTokens": 2, "cacheWriteInputTokens": 3}
    sdk._note_unparsed_cache_keys(u2)
    sdk._note_unparsed_cache_keys(u2)
    assert capsys.readouterr().err.count("cacheWriteInputTokens") == 1
    # ...while the bucket counts every affected call.
    assert _cache_unparsed_total() == 4


def test_cache_unparsed_lands_in_the_current_phase_bucket():
    with TOKENS.phase("s4-deepdive"):
        sdk._note_unparsed_cache_keys({"cacheReadInputTokens": 5})
    snap = TOKENS.snapshot()
    assert snap["by_phase"]["s4-deepdive"]["cache_unparsed"] == 1


def test_hostile_key_names_are_filtered_not_echoed(capsys):
    # A gateway controls its own usage payload, so a key name is attacker
    # input. Names that don't look like identifiers must be dropped, not
    # echoed: paths, credential-looking strings, URLs, oversized blobs.
    hostile = {
        "cache /etc/passwd": 1,                  # embedded path + space
        "cache:sk-abc123def456ghi789jkl": 1,     # credential-shaped, has ':'
        "cache" + "x" * 200: 1,                  # far over the 64-char cap
        "https://cache.gateway.example/v1": 1,   # URL-shaped
    }
    sdk._note_unparsed_cache_keys(hostile)
    err = capsys.readouterr().err
    assert err == ""                # nothing reportable survived the filter
    assert "passwd" not in err
    assert "sk-abc" not in err
    assert _cache_unparsed_total() == 0


def test_reported_key_names_are_sorted_deduped_and_capped(capsys):
    u = {f"cache_extra_{i:02d}": 1 for i in range(12)}
    sdk._note_unparsed_cache_keys(u)
    err = capsys.readouterr().err
    named = re.findall(r"cache_extra_\d\d", err)
    assert named == sorted(named)
    assert len(named) == 8          # capped, so a hostile flood can't spam


def test_oai_flags_unparsed_keys_from_the_raw_usage_dict(monkeypatch, capsys):
    # The check must run on the RAW Chat Completions usage BEFORE
    # _normalise_usage() (which fabricates the parsed Anthropic names), and
    # must look inside the prompt_tokens_details sub-dict too.
    raw = {"prompt_tokens": 50, "completion_tokens": 2,
           "prompt_tokens_details": {"cached_tokens": 0,
                                     "cache_hit_tokens": 7},
           "cacheReadInputTokens": 9000}
    usage_obj = types.SimpleNamespace(model_dump=lambda: dict(raw))

    class _Completions:
        def create(self, **kw):
            return [types.SimpleNamespace(choices=[], usage=usage_obj)]

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    oai.prompt("hi", model="gpt-x")
    err = capsys.readouterr().err
    assert "cacheReadInputTokens" in err
    assert "prompt_tokens_details.cache_hit_tokens" in err
    assert "9000" not in err
    assert _cache_unparsed_total() == 1


def test_oai_parsed_only_usage_is_not_flagged(monkeypatch, capsys):
    raw = {"prompt_tokens": 50, "completion_tokens": 2,
           "prompt_tokens_details": {"cached_tokens": 0,
                                     "cache_write_tokens": 0}}
    usage_obj = types.SimpleNamespace(model_dump=lambda: dict(raw))

    class _Completions:
        def create(self, **kw):
            return [types.SimpleNamespace(choices=[], usage=usage_obj)]

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    oai.prompt("hi", model="gpt-x")
    assert "unparsed" not in capsys.readouterr().err
    assert _cache_unparsed_total() == 0


def test_cli_route_flags_unparsed_envelope_keys(capsys):
    # Structurally limited route (the true wire response lives inside the
    # `claude` subprocess), but a foreign name the CLI passes through in its
    # envelope must still be flagged, key name only.
    from vvaharness.backends.llm import cli
    cli._note_unparsed_cache_keys({"input_tokens": 50,
                                   "cacheReadInputTokens": 9000})
    err = capsys.readouterr().err
    assert "[cli] note" in err
    assert "cacheReadInputTokens" in err
    assert "9000" not in err
    assert _cache_unparsed_total() == 1


def test_enabling_fact_usage_extras_survive_the_streaming_accumulator():
    """Codify the fact the sdk-route detection stands on: the installed
    anthropic SDK's usage model is extra='allow', and its streaming
    accumulator seeds the message snapshot from message_start.message
    .to_dict() while message_delta only overwrites TYPED fields — so a
    usage envelope carrying foreign camelCase cache names survives into
    msg.usage.model_dump() alongside the None-valued typed fields. If this
    fails, the sdk backend's unparsed-cache detection has lost its data
    source, not merely a test."""
    pytest.importorskip("anthropic")
    streaming = pytest.importorskip("anthropic.lib.streaming._messages")

    start = {
        "type": "message_start",
        "message": {
            "id": "msg_1", "type": "message", "role": "assistant",
            "model": "m", "content": [],
            "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 50, "output_tokens": 0,
                      "cacheReadInputTokens": 9000,
                      "cacheWriteInputTokens": 123},
        },
    }
    delta = {
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
        "usage": {"output_tokens": 7},
    }
    snap = streaming.accumulate_event(event=start, current_snapshot=None)
    snap = streaming.accumulate_event(event=delta, current_snapshot=snap)
    dumped = snap.usage.model_dump()
    assert dumped.get("cacheReadInputTokens") == 9000
    assert dumped.get("cacheWriteInputTokens") == 123
    assert dumped["input_tokens"] == 50    # message_start value survives
    assert dumped["output_tokens"] == 7    # delta's typed overwrite applied
