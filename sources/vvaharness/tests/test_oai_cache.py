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

"""Offline tests for backends/llm/openai.py's prompt-cache behaviour: the sharded
`prompt_cache_key`, the cache-write token accounting, and the explicit
minimum-cacheable-size guard.

No real network, no live OpenAI client — every prompt() call installs a fake
client whose `chat.completions.create()` just records the kwargs it was
given. The mapping tests deliberately assert DETERMINISM (same inputs, same
key, wall clock irrelevant): the whole value of `prompt_cache_key` sharding
is that repeat calls for the same prefix land on the same key across runs.
"""
from __future__ import annotations

import hashlib
import inspect
import types
from collections import Counter

import pytest

from vvaharness.backends.llm import openai as oai


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate_oai(monkeypatch):
    monkeypatch.setattr(oai, "_client", None, raising=False)
    monkeypatch.setattr(oai, "_cfg", {
        "api_key": None, "base_url": None, "verify_ssl": True,
        "ca_cert": None, "organization": None, "cache_markers": "on",
    }, raising=False)
    monkeypatch.setattr(oai, "_NO_CACHE_KEY_MODELS", set())
    monkeypatch.setattr(oai, "get_active_tracker",
                        lambda: types.SimpleNamespace(repo_name="my-app"))
    yield


def _filler(estimated_tokens: int) -> str:
    """`estimated_tokens` under the chars/4 rule the estimator uses —
    deterministic, no clock/randomness."""
    chars_needed = estimated_tokens * 4
    return ("word " * ((chars_needed // 5) + 1))[:chars_needed]


# Comfortably clears the 1,024-token floor plus the estimator margin.
_ABOVE_MIN_PREFIX = _filler(4000)
# Well below it — cannot be cached on its own.
_BELOW_MIN_PREFIX = _filler(100)


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


# ─────────────────────────────────────────────────────────────────────────────
# Minimum-cacheable-size guard.
# ─────────────────────────────────────────────────────────────────────────────

def test_minimum_is_explicit_and_is_1024():
    # The provider's documented floor, defined ONCE at module level — not
    # re-hardcoded at each decision point.
    assert oai._CACHE_MIN_PROMPT_TOKENS == 1024


def test_prefix_meets_minimum_true_above_false_below():
    assert oai._prefix_meets_cache_minimum(_ABOVE_MIN_PREFIX) is True
    assert oai._prefix_meets_cache_minimum(_BELOW_MIN_PREFIX) is False


def test_prefix_meets_minimum_handles_empty_and_none():
    assert oai._prefix_meets_cache_minimum("") is False
    assert oai._prefix_meets_cache_minimum(None) is False
    # No prefix means nothing to cache-key on — a large system prompt ahead
    # of an EMPTY prefix must not turn it "cacheable".
    assert oai._prefix_meets_cache_minimum(
        "", preceding=_ABOVE_MIN_PREFIX) is False
    assert oai._prefix_meets_cache_minimum(
        None, preceding=_ABOVE_MIN_PREFIX) is False


def test_minimum_is_cumulative_with_preceding_text():
    # The provider measures its floor against the CUMULATIVE rendered prefix
    # (system message + user-turn prefix), so a prefix too small on its own
    # clears the gate once the text ahead of it makes up the difference —
    # and still fails when the combination remains under the floor.
    assert oai._prefix_meets_cache_minimum(_BELOW_MIN_PREFIX) is False
    assert oai._prefix_meets_cache_minimum(
        _BELOW_MIN_PREFIX, preceding=_ABOVE_MIN_PREFIX) is True
    assert oai._prefix_meets_cache_minimum(
        _BELOW_MIN_PREFIX, preceding=_BELOW_MIN_PREFIX) is False


def test_minimum_is_single_source_of_truth(monkeypatch):
    # Lowering the one constant must move the guard — proving every
    # minimum-size decision reads it rather than a copied literal.
    monkeypatch.setattr(oai, "_CACHE_MIN_PROMPT_TOKENS", 10)
    assert oai._prefix_meets_cache_minimum(_BELOW_MIN_PREFIX) is True


def test_sub_minimum_prefix_is_not_treated_as_cacheable_in_the_key():
    # A prefix below the floor cannot be cached on its own, so it must NOT
    # select the prefix-affinity bucket: two different sub-minimum prefixes
    # on the same chunk yield the SAME key (ring on chunk identity), whereas
    # two different above-minimum prefixes yield DIFFERENT keys.
    small_a = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                    cache_prefix=_BELOW_MIN_PREFIX)
    small_b = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                    cache_prefix=_BELOW_MIN_PREFIX + "x")
    assert small_a == small_b
    big_a = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                  cache_prefix=_ABOVE_MIN_PREFIX)
    big_b = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                  cache_prefix=_ABOVE_MIN_PREFIX + "x")
    assert big_a != big_b


def test_preceding_text_promotes_a_small_prefix_to_the_affinity_bucket():
    # Cumulative gate, observed at the key level: the same sub-minimum
    # prefix pair that collapses onto one ring key in isolation gets
    # per-prefix affinity keys once a system prompt ahead of it carries the
    # combination over the floor — those calls genuinely cache, so rejecting
    # them was the drift being fixed.
    alone_a = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                    cache_prefix=_BELOW_MIN_PREFIX)
    alone_b = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                    cache_prefix=_BELOW_MIN_PREFIX + "x")
    assert alone_a == alone_b
    with_a = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                   cache_prefix=_BELOW_MIN_PREFIX,
                                   preceding=_ABOVE_MIN_PREFIX)
    with_b = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                   cache_prefix=_BELOW_MIN_PREFIX + "x",
                                   preceding=_ABOVE_MIN_PREFIX)
    assert with_a != with_b


# ─────────────────────────────────────────────────────────────────────────────
# Key sharding: deterministic across runs, prefixes land together, and no
# single key carries a whole fan-out stage's volume.
# ─────────────────────────────────────────────────────────────────────────────

def test_same_prefix_lands_on_the_same_key_across_chunks():
    # Calls sharing a byte-identical cacheable prefix are the only calls that
    # can hit each other's cache — they must share a routing key even though
    # their chunk tags differ.
    keys = {oai._prompt_cache_key(f"s4 chunk-{i:03d}", "gpt-5",
                                  cache_prefix=_ABOVE_MIN_PREFIX)
            for i in range(20)}
    assert len(keys) == 1


def test_distinct_shard_prefixes_get_distinct_keys():
    # Each s4 shard carries its own source block; distinct prefixes cannot
    # hit each other, so pinning them to one key would only pile volume up.
    keys = {oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                  cache_prefix=_ABOVE_MIN_PREFIX + f"shard{i}")
            for i in range(10)}
    assert len(keys) == 10


def test_sub_minimum_prefix_fanout_is_spread_and_bounded():
    # 510 chunk calls sharing only a sub-minimum prefix (the s4 problem
    # scale): the ring must spread them over multiple keys, with no key
    # taking more than a bounded share, so per-key traffic stays under the
    # provider's ~15 req/min routing guidance.
    tags = [f"s4 chunk-{i:03d}" for i in range(510)]
    keys = [oai._prompt_cache_key(t, "gpt-5", cache_prefix=_BELOW_MIN_PREFIX)
            for t in tags]
    counts = Counter(keys)
    assert 2 <= len(counts) <= oai._CACHE_KEY_SHARDS
    # A uniform-ish spread: no bucket hoards the stage. Generous bound so the
    # test pins the property, not the hash function's exact distribution.
    assert max(counts.values()) <= (510 // 2)


def test_mapping_is_deterministic_and_ignores_the_clock(monkeypatch):
    k1 = oai._prompt_cache_key("s4 chunk-042", "gpt-5",
                               cache_prefix=_BELOW_MIN_PREFIX)
    # A second "run": same inputs after the wall clock moves must produce the
    # same key — the mapping may depend on nothing but (tag, repo, model,
    # prefix), or re-runs would stop landing on their warm caches.
    monkeypatch.setattr(oai.time, "time", lambda: 4102444800.0)
    k2 = oai._prompt_cache_key("s4 chunk-042", "gpt-5",
                               cache_prefix=_BELOW_MIN_PREFIX)
    assert k1 == k2
    k3 = oai._prompt_cache_key("s4 chunk-042", "gpt-5",
                               cache_prefix=_ABOVE_MIN_PREFIX)
    k4 = oai._prompt_cache_key("s4 chunk-042", "gpt-5",
                               cache_prefix=_ABOVE_MIN_PREFIX)
    assert k3 == k4


def test_no_prefix_keeps_the_legacy_per_stage_key():
    # Call sites that pass no cache_prefix are the single-shot stage calls;
    # their key stays per (stage, repo, model) exactly as before the shard
    # work, so nothing downstream observes a change it didn't need.
    k1 = oai._prompt_cache_key("s4 chunk-01", "gpt-5")
    k2 = oai._prompt_cache_key("s4 chunk-02", "gpt-5")
    assert k1 == k2
    assert k1 != oai._prompt_cache_key("s3 decompose", "gpt-5")


def test_prompt_sends_the_prefix_derived_key(monkeypatch):
    # End to end through prompt(): the request field must reflect the prefix
    # bucket, i.e. two chunks sharing a shard prefix send the same key and a
    # different shard sends a different one.
    kw_a1 = _capture_oai_kw(monkeypatch, tag="s4 chunk-01",
                            cache_prefix=_ABOVE_MIN_PREFIX)
    kw_a2 = _capture_oai_kw(monkeypatch, tag="s4 chunk-02",
                            cache_prefix=_ABOVE_MIN_PREFIX)
    kw_b = _capture_oai_kw(monkeypatch, tag="s4 chunk-03",
                           cache_prefix=_ABOVE_MIN_PREFIX + "other-shard")
    assert kw_a1["prompt_cache_key"] == kw_a2["prompt_cache_key"]
    assert kw_b["prompt_cache_key"] != kw_a1["prompt_cache_key"]
    # The prefix itself still arrives folded first into a single string.
    assert kw_a1["messages"][-1]["content"] == _ABOVE_MIN_PREFIX + "hi"


def test_prompt_counts_the_system_message_toward_the_minimum(monkeypatch):
    # End to end through prompt(): the system message renders ahead of the
    # user turn, so it participates in the provider's cumulative floor. The
    # same sub-minimum prefix that rides the ring on its own must switch to
    # its prefix-affinity key when a large system prompt precedes it.
    kw_bare = _capture_oai_kw(monkeypatch, tag="s4 chunk-01",
                              cache_prefix=_BELOW_MIN_PREFIX)
    kw_sys = _capture_oai_kw(monkeypatch, tag="s4 chunk-01",
                             cache_prefix=_BELOW_MIN_PREFIX,
                             system_prompt=_ABOVE_MIN_PREFIX)
    digest = hashlib.sha256(_BELOW_MIN_PREFIX.encode("utf-8")).hexdigest()
    expected = hashlib.sha256(
        f"s4:my-app:gpt-x:{digest[:12]}".encode("utf-8")).hexdigest()[:32]
    assert kw_sys["prompt_cache_key"] == expected
    assert kw_bare["prompt_cache_key"] != expected


# ─────────────────────────────────────────────────────────────────────────────
# agentic() sends a prompt_cache_key too — built ONCE from the stable leading
# content and reused unchanged every turn, so the growing tail never churns it.
# ─────────────────────────────────────────────────────────────────────────────

class _TC:
    def __init__(self, id, name, args):
        self.id = id
        self.function = types.SimpleNamespace(name=name, arguments=args)

    def model_dump(self):
        return {"id": self.id,
                "function": {"name": self.function.name,
                             "arguments": self.function.arguments}}


def _resp(content=None, tool_calls=None):
    msg = types.SimpleNamespace(content=content, tool_calls=tool_calls)
    return types.SimpleNamespace(
        choices=[types.SimpleNamespace(message=msg)], usage=None)


def _make_agentic_client(monkeypatch, responses):
    seen: list[dict] = []

    class _Completions:
        def __init__(self):
            self._i = 0

        def create(self, **kw):
            seen.append(dict(kw))
            r = responses[min(self._i, len(responses) - 1)]
            self._i += 1
            return r

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    monkeypatch.setattr(oai._localtools, "supported", lambda t: (list(t), []))
    monkeypatch.setattr(oai._localtools, "schemas_for", lambda t: [])
    monkeypatch.setattr(oai._localtools, "execute", lambda *a, **k: "tool output")
    return seen


def test_agentic_sends_a_prompt_cache_key(monkeypatch):
    seen = _make_agentic_client(monkeypatch, [_resp(content="done")])
    out = oai.agentic("investigate F-1", model="gpt-x", cwd="/tmp",
                      system_prompt="you verify findings", tag="s6 verify F-1",
                      allowed_tools=["Read"])
    assert out == "done"
    assert "prompt_cache_key" in seen[0]
    assert isinstance(seen[0]["prompt_cache_key"], str)


def test_agentic_prompt_cache_key_is_stable_across_turns(monkeypatch):
    # A tool call on turn 1, a final answer on turn 2. The messages list grows
    # between the two create() calls, but the routing key must be identical —
    # keyed on the stable lead, never the turn-varying tail.
    responses = [
        _resp(tool_calls=[_TC("c1", "Read", '{"path": "a.py"}')]),
        _resp(content="done"),
    ]
    seen = _make_agentic_client(monkeypatch, responses)
    oai.agentic("investigate F-1", model="gpt-x", cwd="/tmp",
                system_prompt="you verify findings", tag="s6 verify F-1",
                allowed_tools=["Read"])
    # Two turns really happened (a tool call, then the final answer), and the
    # routing key was byte-identical on both despite the tail growing between.
    assert len(seen) == 2
    assert seen[0]["prompt_cache_key"] == seen[1]["prompt_cache_key"]


def test_agentic_kill_switch_suppresses_the_prompt_cache_key(monkeypatch):
    oai.configure(cache_markers="off")
    seen = _make_agentic_client(monkeypatch, [_resp(content="done")])
    oai.agentic("go", model="gpt-x", cwd="/tmp", tag="s6 verify F-1",
                allowed_tools=["Read"])
    assert "prompt_cache_key" not in seen[0]


def test_agentic_self_heals_when_the_gateway_rejects_the_key(monkeypatch):
    class _Err(Exception):
        def __str__(self):
            return "Unrecognized request argument supplied: prompt_cache_key"

    seen: list[dict] = []

    class _Completions:
        def create(self, **kw):
            seen.append(dict(kw))
            if "prompt_cache_key" in kw:
                raise _Err()
            return _resp(content="done")

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "openai",
                        types.SimpleNamespace(BadRequestError=_Err,
                                              APIStatusError=type("A", (Exception,), {}),
                                              APIConnectionError=type("C", (Exception,), {})),
                        raising=False)
    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    monkeypatch.setattr(oai._localtools, "supported", lambda t: (list(t), []))
    monkeypatch.setattr(oai._localtools, "schemas_for", lambda t: [])

    out = oai.agentic("go", model="gw-model", cwd="/tmp", tag="s6 verify F-1",
                      allowed_tools=["Read"])
    assert out == "done"
    assert len(seen) == 2
    assert "prompt_cache_key" in seen[0]
    assert "prompt_cache_key" not in seen[1]
    assert "gw-model" in oai._NO_CACHE_KEY_MODELS


# ─────────────────────────────────────────────────────────────────────────────
# The key must stay leak-free: hashed identifiers only, even now that prompt
# content (the cache_prefix) feeds the bucket.
# ─────────────────────────────────────────────────────────────────────────────

def test_key_contains_no_repo_root_path_separator_or_credential():
    repo_root = "/Users/alice/Projects/super-secret-internal-codename"
    secret = "sk-EXAMPLEsecret1234567890"
    prefix = (_ABOVE_MIN_PREFIX
              + f"\nsource at {repo_root}/app.py uses key {secret}\n")
    key = oai._prompt_cache_key(f"s4 chunk-01 root={repo_root}", "gpt-5",
                                cache_prefix=prefix)
    assert len(key) == 32
    assert set(key) <= set("0123456789abcdef"), "key must be a bare hex digest"
    assert "/" not in key and "\\" not in key
    assert repo_root not in key
    assert "super-secret-internal-codename" not in key
    assert secret not in key and "sk-" not in key
    # Structurally impossible to leak a root path: no such parameter exists.
    assert "repo_root" not in inspect.signature(
        oai._prompt_cache_key).parameters


def test_prefix_only_enters_the_key_as_a_digest():
    # The bucket contribution must be a SHA-256 digest of the prefix, never
    # any substring of it.
    key = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                cache_prefix=_ABOVE_MIN_PREFIX)
    digest = hashlib.sha256(_ABOVE_MIN_PREFIX.encode("utf-8")).hexdigest()
    expected = hashlib.sha256(
        f"s4:my-app:gpt-5:{digest[:12]}".encode("utf-8")).hexdigest()[:32]
    assert key == expected


def test_preceding_feeds_the_size_gate_but_never_the_key_bytes():
    # `preceding` (the system prompt) only decides WHETHER the prefix is
    # cacheable — its content must contribute nothing to the key, so a
    # system prompt carrying a path or credential cannot perturb (let alone
    # leak into) the routing key. Two different gate-clearing precedings,
    # one of them hostile, must yield the identical, digest-only key.
    hostile = (_ABOVE_MIN_PREFIX
               + "\n/Users/alice/Projects/super-secret-internal-codename"
               + "\nsk-EXAMPLEsecret1234567890\n")
    k_hostile = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                      cache_prefix=_BELOW_MIN_PREFIX,
                                      preceding=hostile)
    k_benign = oai._prompt_cache_key("s4 chunk-01", "gpt-5",
                                     cache_prefix=_BELOW_MIN_PREFIX,
                                     preceding=_ABOVE_MIN_PREFIX)
    assert k_hostile == k_benign
    digest = hashlib.sha256(_BELOW_MIN_PREFIX.encode("utf-8")).hexdigest()
    expected = hashlib.sha256(
        f"s4:my-app:gpt-5:{digest[:12]}".encode("utf-8")).hexdigest()[:32]
    assert k_hostile == expected
    assert set(k_hostile) <= set("0123456789abcdef")
    assert "super-secret-internal-codename" not in k_hostile
    assert "sk-" not in k_hostile and "/" not in k_hostile


def test_key_handles_missing_tag_and_tracker(monkeypatch):
    monkeypatch.setattr(oai, "get_active_tracker", lambda: None)
    assert len(oai._prompt_cache_key(None, "gpt-5")) == 32
    assert len(oai._prompt_cache_key("   ", "gpt-5",
                                     cache_prefix=_BELOW_MIN_PREFIX)) == 32


# ─────────────────────────────────────────────────────────────────────────────
# cache_write_tokens: parsed when the provider reports it, and NEVER invented
# when it doesn't — absent is "unmeasured on this model", not a confident 0.
# ─────────────────────────────────────────────────────────────────────────────

def test_normalise_usage_parses_cache_write_tokens_when_present():
    norm = oai._normalise_usage({
        "prompt_tokens": 10000,
        "completion_tokens": 500,
        "prompt_tokens_details": {"cached_tokens": 4000,
                                  "cache_write_tokens": 3000},
    })
    assert norm == {
        # fresh + read + write must add back up to prompt_tokens: the read
        # and write slices are carved OUT of the fresh count, matching the
        # Anthropic backends' accounting so pricing can rate each slice.
        "input_tokens": 3000,
        "output_tokens": 500,
        "cache_read_input_tokens": 4000,
        "cache_creation_input_tokens": 3000,
    }


def test_normalise_usage_reported_zero_write_is_a_real_zero():
    # The field being present with value 0 IS a measurement: no write.
    norm = oai._normalise_usage({
        "prompt_tokens": 100, "completion_tokens": 5,
        "prompt_tokens_details": {"cached_tokens": 0,
                                  "cache_write_tokens": 0},
    })
    assert norm["cache_creation_input_tokens"] == 0
    assert norm["input_tokens"] == 100


def test_normalise_usage_absent_write_field_is_not_recorded_as_zero():
    # Older models never report cache_write_tokens; the normalised dict must
    # omit the field entirely rather than assert a write count of 0.
    norm = oai._normalise_usage({
        "prompt_tokens": 100, "completion_tokens": 5,
        "prompt_tokens_details": {"cached_tokens": 40},
    })
    assert "cache_creation_input_tokens" not in norm
    assert norm["cache_read_input_tokens"] == 40
    assert norm["input_tokens"] == 60


def test_normalise_usage_tolerates_missing_or_malformed_details():
    assert oai._normalise_usage({"prompt_tokens": 7, "completion_tokens": 2}) \
        == {"input_tokens": 7, "output_tokens": 2,
            "cache_read_input_tokens": 0}
    # A gateway returning a non-dict details blob must not crash accounting.
    norm = oai._normalise_usage({"prompt_tokens": 7, "completion_tokens": 2,
                                 "prompt_tokens_details": "n/a"})
    assert norm["input_tokens"] == 7
    assert "cache_creation_input_tokens" not in norm


def test_normalise_usage_never_goes_negative():
    # Defensive: a gateway double-reporting subsets larger than the total
    # must clamp at zero fresh tokens, not report negative input.
    norm = oai._normalise_usage({
        "prompt_tokens": 100, "completion_tokens": 1,
        "prompt_tokens_details": {"cached_tokens": 80,
                                  "cache_write_tokens": 80},
    })
    assert norm["input_tokens"] == 0


def test_prompt_records_cache_write_through_tokens(monkeypatch):
    # End to end through prompt()'s streamed-usage path: what reaches
    # TOKENS.add carries the write slice when the provider reported one.
    recorded = []
    monkeypatch.setattr(oai, "TOKENS",
                        types.SimpleNamespace(add=recorded.append))

    usage = {"prompt_tokens": 2000, "completion_tokens": 10,
             "prompt_tokens_details": {"cached_tokens": 500,
                                       "cache_write_tokens": 1200}}

    class _Delta:
        content = "ok"

    class _Ev:
        def __init__(self, content=False, u=None):
            self.choices = ([types.SimpleNamespace(delta=_Delta())]
                            if content else [])
            self.usage = u

    class _Completions:
        def create(self, **kw):
            return [_Ev(content=True), _Ev(u=usage)]

    class _Client:
        chat = types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    out = oai.prompt("hi", model="gpt-x", tag="s4 chunk-01")
    assert out == "ok"
    assert recorded == [{
        "input_tokens": 300,
        "output_tokens": 10,
        "cache_read_input_tokens": 500,
        "cache_creation_input_tokens": 1200,
    }]


def test_agentic_usage_path_uses_the_same_normalisation(monkeypatch):
    recorded = []
    monkeypatch.setattr(oai, "TOKENS",
                        types.SimpleNamespace(add=recorded.append))
    usage = {"prompt_tokens": 50, "completion_tokens": 3,
             "prompt_tokens_details": {"cached_tokens": 20}}
    oai._record_usage(usage)
    assert recorded == [{"input_tokens": 30, "output_tokens": 3,
                         "cache_read_input_tokens": 20}]
    oai._record_usage(None)
    assert recorded[-1] is None
