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

"""Offline tests for the one-time "cache markers withheld" operator note.

A live run through an unrecognised gateway sent millions of prompt tokens
uncached (cache_read=0/cache_write=0 at every stage) and nothing at scan time
said why, even though one config line (`cache_route: anthropic`) would have
restored caching. The note under test is emitted by sdk._cache_route()'s
auto-detection fallthrough — the single point every marker withhold site
passes through — and must:

* fire exactly ONCE per process no matter how many calls, or which withhold
  site (prefix breakpoint, system block, agentic history marker) triggers it;
* stay SILENT when the route is recognised, when the operator disabled
  markers or forced `cache_route: none` (deliberate choices, not missed
  ones), and when a marker is withheld only by the per-model minimum;
* name the remedy config key without echoing any hostname/base_url — this
  code ships open source and the note must not train logs to carry gateway
  hosts;
* be registered in warn_once._REGISTRY_SITES so batch runs re-arm it between
  repos — an unregistered set means repo N>1 silently loses the note.

No real network: prompt() runs against a fake client whose messages.stream()
records kwargs, same as tests/test_backend_cache.py.
"""
from __future__ import annotations

import types

import pytest

from vvaharness.backends.llm import sdk
from vvaharness.util.warn_once import reset_warn_once_registries

# The load-bearing fragments of the note. NOTE_MARK identifies the note (and
# nothing else sdk.py prints); NOTE_REMEDY is the config line the operator is
# being pointed at.
NOTE_MARK = "markers are withheld"
NOTE_REMEDY = "cache_route: anthropic"

# An unrecognised gateway host, deliberately example-flavoured (open source:
# never a real internal hostname). Its distinctive label lets the tests assert
# the note carries no part of the endpoint.
_UNKNOWN_URL = "https://llm-gateway.hostname-must-not-print.example"


def _filler(estimated_tokens: int) -> str:
    """`estimated_tokens` under the chars/4 rule (len(text) // 4) — the same
    deterministic construction test_backend_cache.py uses."""
    chars_needed = estimated_tokens * 4
    return ("word " * ((chars_needed // 5) + 1))[:chars_needed]


# opus-4-6 carries the largest published minimum (4096 real tokens): 7000
# estimated clears it even under the content-aware estimator; 100 estimated is
# under every per-model minimum.
_MODEL = "opus-4-6"
_ABOVE_MIN_PREFIX = _filler(7000)
_BELOW_MIN_PREFIX = _filler(100)

# Long enough (chars and tokens) that the VVAH-E003 response-quality gate
# never warns — its stderr output would pollute the exact-count assertions.
_HEALTHY_REPLY = "All clear. " * 30
_HEALTHY_USAGE = {"input_tokens": 500, "output_tokens": 200}


class _FakeBlock:
    def __init__(self, type, text=None):
        self.type = type
        if text is not None:
            self.text = text


class _FakeUsage:
    def __init__(self, data):
        self._data = data

    def model_dump(self):
        return dict(self._data)


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
    """Carries the `base_url` attribute _cache_route() classifies from."""

    def __init__(self, recorder, msg, base_url=None):
        self.messages = _FakeMessages(recorder, msg)
        self.base_url = base_url

    def with_options(self, **kw):
        return self


def _install_client(monkeypatch, *, base_url=None):
    recorder: list = []
    msg = _FakeMessage([_FakeBlock("text", _HEALTHY_REPLY)],
                       usage=_FakeUsage(_HEALTHY_USAGE))
    client = _FakeSdkClient(recorder, msg, base_url=base_url)
    monkeypatch.setattr(sdk, "_get_client", lambda: client)
    return client, recorder


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Reset every sdk module singleton the note's behaviour depends on —
    most importantly _CACHE_ROUTE_NOTED, which other test files may have
    already consumed by classifying an unknown host."""
    monkeypatch.setattr(sdk, "_client", None)
    # raising=False so a build without the fix fails on the ASSERTIONS (no
    # note observed) rather than erroring here — the red-proof must show the
    # tests watch stderr, not that an attribute exists.
    monkeypatch.setattr(sdk, "_CACHE_ROUTE_NOTED", set(), raising=False)
    monkeypatch.setattr(sdk, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(sdk, "_NO_THINK_MODELS", set())
    monkeypatch.setattr(sdk, "_cfg", {
        "api_key": None, "base_url": None, "verify_ssl": True,
        "ca_cert": None, "client_cert": None, "no_proxy": None,
        "allow_api_key_fallback": False,
        "cache_min_block_tokens": None,
        "cache_markers": "on",
        "cache_route": "auto",
    })
    # prompt()'s except clauses need these importable names even though the
    # fake stream never raises.
    fake_anthropic = types.SimpleNamespace(
        APIStatusError=type("APIStatusError", (Exception,), {}),
        APIConnectionError=type("APIConnectionError", (Exception,), {}),
    )
    monkeypatch.setattr(sdk, "anthropic", fake_anthropic)
    yield


# ── the note fires, once, and says the right things ─────────────────────────

def test_note_fires_once_across_many_calls_and_all_withhold_sites(
        monkeypatch, capsys):
    client, _rec = _install_client(monkeypatch, base_url=_UNKNOWN_URL)
    # Site 1+2: prefix breakpoint and system block, twice each.
    for _ in range(2):
        sdk.prompt("rest", model=_MODEL, cache_prefix=_ABOVE_MIN_PREFIX,
                   system_prompt=_ABOVE_MIN_PREFIX)
    # Site 3: the agentic history marker, several turns' worth.
    msgs = [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
    for _ in range(3):
        sdk._with_cache_marker(client, msgs)
    err = capsys.readouterr().err
    assert err.count(NOTE_MARK) == 1
    assert NOTE_REMEDY in err


def test_note_names_the_classification_not_the_hostname(monkeypatch, capsys):
    client, _rec = _install_client(monkeypatch, base_url=_UNKNOWN_URL)
    sdk.prompt("rest", model=_MODEL, cache_prefix=_ABOVE_MIN_PREFIX)
    err = capsys.readouterr().err
    assert NOTE_MARK in err
    assert "unknown" in err                      # the classification, by name
    # No fragment of the endpoint may print — the note must be safe to paste
    # into a public bug report.
    assert "hostname-must-not-print" not in err
    assert _UNKNOWN_URL not in err


def test_note_fires_from_the_agentic_marker_site_alone(monkeypatch, capsys):
    """The coverage the single-choke-point placement buys: a profile that
    never passes a cache_prefix or system prompt (agentic-only) still gets
    the note, because _with_cache_marker also routes through _cache_route."""
    client, _rec = _install_client(monkeypatch, base_url=_UNKNOWN_URL)
    out = sdk._with_cache_marker(
        client, [{"role": "user", "content": [{"type": "text", "text": "x"}]}])
    err = capsys.readouterr().err
    assert NOTE_MARK in err
    # And the withhold itself still holds: no marker went onto the history.
    assert "cache_control" not in out[0]["content"][0]


# ── silence in every deliberate / non-route scenario ─────────────────────────

def test_no_note_when_route_is_recognised(monkeypatch, capsys):
    _install_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("rest", model=_MODEL, cache_prefix=_ABOVE_MIN_PREFIX,
               system_prompt=_ABOVE_MIN_PREFIX)
    assert NOTE_MARK not in capsys.readouterr().err


def test_no_note_when_markers_are_off(monkeypatch, capsys):
    sdk._cfg["cache_markers"] = "off"
    _install_client(monkeypatch, base_url=_UNKNOWN_URL)
    sdk.prompt("rest", model=_MODEL, cache_prefix=_ABOVE_MIN_PREFIX,
               system_prompt=_ABOVE_MIN_PREFIX)
    assert NOTE_MARK not in capsys.readouterr().err


def test_no_note_when_route_is_forced_none(monkeypatch, capsys):
    # `cache_route: none` is an explicit operator decision — nagging about a
    # remedy the operator already declined would train them to ignore notes.
    #
    # The base_url MUST be the unrecognised one. Pairing `cache_route: none`
    # with a recognised host made this test vacuous: _cache_route returned
    # ANTHROPIC on host detection and never reached the forced-none branch, so
    # deleting that branch left the test green. With the unknown host, the note
    # is suppressed only by the mechanism this test names.
    sdk._cfg["cache_route"] = "none"
    _install_client(monkeypatch, base_url=_UNKNOWN_URL)
    sdk.prompt("rest", model=_MODEL, cache_prefix=_ABOVE_MIN_PREFIX)
    assert NOTE_MARK not in capsys.readouterr().err


def test_no_note_when_prefix_is_under_the_model_minimum(monkeypatch, capsys):
    # Recognised route, marker withheld only by the per-model minimum: that
    # withhold is the provider's published behaviour, not a misconfiguration,
    # and no config line would change it — so no note.
    # Recognised host on purpose here — the scenario IS "route is fine, only the
    # size gate withheld". Asserting the note is absent would be vacuous (the
    # note lives on the unknown-route path and could never fire), so this test
    # asserts the size-gate behaviour instead and leaves note-absence to the
    # unknown-host tests above.
    _, rec = _install_client(monkeypatch, base_url="https://api.anthropic.com")
    sdk.prompt("rest", model=_MODEL, cache_prefix=_BELOW_MIN_PREFIX)
    # The prefix was folded into one block with no cache_control breakpoint.
    assert rec[0]["messages"][0]["content"] == _BELOW_MIN_PREFIX + "rest"
    assert "cache_control" not in str(rec[0]["messages"][0])


# ── batch-run re-arming via the warn_once registry ───────────────────────────

def test_reset_warn_once_registries_rearms_the_note(monkeypatch, capsys):
    """Pins the _REGISTRY_SITES registration. Without it, the batch driver's
    between-repo reset would not clear _CACHE_ROUTE_NOTED and repo N>1 would
    silently lose the note — the exact regression this test exists to catch."""
    client, _rec = _install_client(monkeypatch, base_url=_UNKNOWN_URL)
    msgs = [{"role": "user", "content": [{"type": "text", "text": "x"}]}]
    sdk._with_cache_marker(client, msgs)
    sdk._with_cache_marker(client, msgs)          # second repo-1 call: silent
    assert capsys.readouterr().err.count(NOTE_MARK) == 1
    reset_warn_once_registries()                  # batch driver, between repos
    sdk._with_cache_marker(client, msgs)
    assert capsys.readouterr().err.count(NOTE_MARK) == 1
