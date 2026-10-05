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

"""Unit tests for vvaharness.backends.oai.

Offline & deterministic: no real network, no live OpenAI client. A fake
`openai` module is injected via monkeypatch where the client construction
path is exercised. The module singleton `oai._client` is reset by an
autouse fixture so test order never matters.
"""
import json
import os
import subprocess
import sys

import pytest

from vvaharness.backends.harness.models import TruncatedResponseError
from vvaharness.backends.llm import openai as oai
from vvaharness.util import errlog as _errlog
from vvaharness.util.counters import COUNTERS

_LAZY_PROBE = (
    "import importlib, sys\n"
    "importlib.import_module('vvaharness.backends.llm.registry')\n"
    "print('LEAKED' if 'openai' in sys.modules else 'LAZY')\n"
)


@pytest.fixture(autouse=True)
def _reset_oai_state(monkeypatch):
    """Isolate the module-level client singleton and cfg between tests."""
    monkeypatch.setattr(oai, "_client", None, raising=False)
    # Restore cfg to its documented defaults so a configure() in one test
    # cannot leak into another.
    monkeypatch.setattr(
        oai,
        "_cfg",
        {"api_key": None, "base_url": None, "verify_ssl": True,
         "ca_cert": None, "organization": None},
        raising=False,
    )
    # Keep the suite from depending on a real key in the environment.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    yield


# _scrub_secrets

def test_scrub_secrets_redacts_sk_key():
    out = oai._scrub_secrets("here is sk-ABCDEFghijklmnop1234567890 done")
    # First 6 chars of the suffix are kept (the regex group is sk- + 6 chars).
    assert "sk-ABCDEF***" in out
    assert "ghijklmnop1234567890" not in out


def test_scrub_secrets_redacts_bearer_token():
    out = oai._scrub_secrets("Header X: Bearer abc123.DEF-456_ghi value")
    assert "Bearer ***" in out
    assert "abc123.DEF-456_ghi" not in out


def test_scrub_secrets_redacts_authorization_line():
    out = oai._scrub_secrets("Authorization: sometoplevelsecretvalue")
    assert "Authorization: ***" in out
    assert "sometoplevelsecretvalue" not in out


def test_scrub_secrets_redacts_cookie_and_apikey_lines():
    text = "Set-Cookie: session=deadbeef\napi_key = supersecretkeyvalue"
    out = oai._scrub_secrets(text)
    assert "deadbeef" not in out
    assert "supersecretkeyvalue" not in out
    assert "Set-Cookie: ***" in out
    assert "api_key = ***" in out


def test_scrub_secrets_preserves_non_secret_text():
    text = "Connection failed: please check your network settings."
    assert oai._scrub_secrets(text) == text


def test_scrub_secrets_empty_input_returns_input():
    assert oai._scrub_secrets("") == ""
    assert oai._scrub_secrets(None) is None


# _summarise_status_error

class _FakeResp:
    def __init__(self, text):
        self.text = text


class _FakeStatusErr(Exception):
    def __init__(self, *, response=None, message=None):
        super().__init__(message or "")
        self.response = response
        self.message = message


def test_summarise_collapses_dlp_html_block():
    body = ('<html><body><div class="block rsn">Not allowed to access this '
            'file type</div></body></html> dlp proxy')
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert "blocked by corporate proxy/DLP" in out
    assert "Not allowed to access this file type" in out
    # The 12 KB of HTML/CSS must be collapsed away.
    assert "<html>" not in out
    assert "<div" not in out


def test_summarise_dlp_with_no_reason_uses_policy_block():
    body = "<html><body>dlp generic page with no parseable block detail</body></html>"
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert "blocked by corporate proxy/DLP" in out
    assert "policy block" in out


def test_summarise_dlp_scrubs_secret_in_reason():
    body = ('<html>dlp <div class="block rsn">reflected sk-ABCDEFsecrettail123456'
            '</div></html>')
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert "secrettail123456" not in out
    assert "sk-ABCDEF***" in out


def test_summarise_non_html_body_scrubbed_and_length_capped():
    # A long, non-DLP error body: returned scrubbed and capped to 300 chars.
    body = "plain upstream error " * 100  # well over 300 chars
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert len(out) <= 300
    assert out == oai._scrub_secrets(body)[:300]


def test_summarise_falls_back_to_message_when_no_response():
    err = _FakeStatusErr(response=None, message="upstream 503 unavailable")
    out = oai._summarise_status_error(err)
    assert "upstream 503 unavailable" in out


def test_summarise_non_dlp_body_secrets_scrubbed():
    body = "trace dump Authorization: leakedtokenvalue123 end"
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert "leakedtokenvalue123" not in out


# configure()

def test_configure_stores_cfg_and_resets_client(monkeypatch):
    # Pretend a client already exists; configure() must clear it.
    monkeypatch.setattr(oai, "_client", object(), raising=False)
    oai.configure(api_key="sk-ant-EXAMPLE", base_url="https://api.example.test/v1",
                  organization="org-example")
    assert oai._cfg["api_key"] == "sk-ant-EXAMPLE"
    assert oai._cfg["base_url"] == "https://api.example.test/v1"
    assert oai._cfg["organization"] == "org-example"
    assert oai._client is None


def test_configure_verify_ssl_false_is_stored(monkeypatch):
    oai.configure(verify_ssl=False)
    assert oai._cfg["verify_ssl"] is False


def test_configure_none_values_do_not_overwrite(monkeypatch):
    oai.configure(api_key="sk-ant-EXAMPLE")
    # A subsequent call with no api_key must not wipe the stored key.
    oai.configure(base_url="https://api.example.test/v1")
    assert oai._cfg["api_key"] == "sk-ant-EXAMPLE"
    assert oai._cfg["base_url"] == "https://api.example.test/v1"


def test_configure_stores_no_proxy_without_mutating_environ(monkeypatch):
    # configure() must never touch the real process environment (the fixed bug).
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    oai.configure(no_proxy="example.com")
    assert oai._cfg["no_proxy"] == "example.com"
    assert "NO_PROXY" not in os.environ
    assert "no_proxy" not in os.environ


# _get_client — DefaultHttpxClient only used when verify != True

class _FakeOpenAIClient:
    def __init__(self, **kw):
        self.kw = kw


class _FakeHttpxClient:
    def __init__(self, *, verify):
        self.verify = verify


def _install_fake_openai(monkeypatch):
    import types
    fake = types.SimpleNamespace()
    fake.OpenAI = _FakeOpenAIClient
    fake.DefaultHttpxClient = _FakeHttpxClient
    monkeypatch.setattr(oai, "openai", fake, raising=False)
    return fake


def test_get_client_scopes_no_proxy_env_and_restores_prior_value(monkeypatch):
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setenv("no_proxy", "prior.example")
    fake = _install_fake_openai(monkeypatch)
    seen: dict[str, str | None] = {}

    class _CapturingOpenAI:
        def __init__(self, **_kw):
            seen["NO_PROXY"] = os.environ.get("NO_PROXY")
            seen["no_proxy"] = os.environ.get("no_proxy")

    fake.OpenAI = _CapturingOpenAI
    oai._cfg["no_proxy"] = "example.com"
    oai._get_client()
    assert seen == {"NO_PROXY": "example.com", "no_proxy": "example.com"}
    # Restored immediately after construction: no permanent global mutation.
    assert "NO_PROXY" not in os.environ
    assert os.environ["no_proxy"] == "prior.example"


def test_the_dispatcher_does_not_import_this_backend_until_it_is_selected():
    """Replaces a test of the `openai is None` guard, which no longer exists.

    See the twin in test_backend_sdk.py: the guard existed because importing the dispatcher
    imported every backend. Selection is lazy now, so this pins that instead.
    """
    out = subprocess.run(
        [sys.executable, "-c", _LAZY_PROBE], capture_output=True, text=True, check=False
    )
    assert "LAZY" in out.stdout, out.stdout + out.stderr


def test_get_client_no_http_client_when_verify_true(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    # default _cfg verify_ssl is True
    client = oai._get_client()
    assert isinstance(client, _FakeOpenAIClient)
    # When verify is True the DefaultHttpxClient path must be skipped.
    assert "http_client" not in client.kw
    assert client.kw["api_key"] == "sk-ant-EXAMPLE"


def test_get_client_uses_httpx_client_when_verify_false(monkeypatch, capsys):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://gateway.internal/v1")
    # Avoid importing real urllib3 warning machinery: patch warnings module use
    # by configuring verify_ssl=False which triggers the urllib3 import branch.
    oai.configure(verify_ssl=False)
    client = oai._get_client()
    assert "http_client" in client.kw
    assert isinstance(client.kw["http_client"], _FakeHttpxClient)
    assert client.kw["http_client"].verify is False
    # Disabling TLS must NEVER be silent: a loud, endpoint-naming warning fires.
    err = capsys.readouterr().err
    assert "TLS verification DISABLED" in err
    assert "gateway.internal" in err


def test_get_client_uses_httpx_client_with_ca_cert(monkeypatch, tmp_path):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    ca = tmp_path / "ca.pem"
    ca.write_text("-----FAKE CERT-----")
    oai.configure(ca_cert=str(ca))
    client = oai._get_client()
    # verify resolves to the ca path (truthy string != True) -> httpx client used.
    assert "http_client" in client.kw
    assert client.kw["http_client"].verify == str(ca)


def test_get_client_missing_ca_cert_falls_back_to_verify_ssl(monkeypatch, capsys):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    oai.configure(ca_cert="/nonexistent/path/ca.pem")  # verify_ssl stays True
    client = oai._get_client()
    err = capsys.readouterr().err
    assert "not found" in err
    # ca dropped, verify_ssl True -> no http_client.
    assert "http_client" not in client.kw


def test_get_client_strips_whitespace_from_key(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE\n")
    client = oai._get_client()
    assert client.kw["api_key"] == "sk-ant-EXAMPLE"


def test_get_client_default_base_url(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    client = oai._get_client()
    assert client.kw["base_url"] == "https://api.openai.com/v1"


def test_get_client_blank_base_url_env_falls_back_to_default(monkeypatch):
    # A present-but-empty OPENAI_BASE_URL (the blank `OPENAI_BASE_URL=` shipped
    # in .env.example) must fall back to the default endpoint, not be passed
    # through as "" — which the HTTP client rejects as "missing protocol".
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    monkeypatch.setenv("OPENAI_BASE_URL", "")
    client = oai._get_client()
    assert client.kw["base_url"] == "https://api.openai.com/v1"


def test_get_client_configured_base_url(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    oai.configure(base_url="https://api.example.test/v1")
    client = oai._get_client()
    assert client.kw["base_url"] == "https://api.example.test/v1"


def test_get_client_is_cached_singleton(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    first = oai._get_client()
    second = oai._get_client()
    assert first is second


# prompt() — param-drop retry: a rejection on the LAST attempt still re-sends

import types as _types


class _Delta:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.delta = _Delta(content)


class _Ev:
    def __init__(self, content=None, usage=None):
        self.choices = [_Choice(content)] if content is not None else []
        self.usage = usage


def test_prompt_param_drop_on_last_attempt_still_resends(monkeypatch):
    # Three distinct rejections across the three base attempts — the third
    # lands on the LAST attempt. With the live-bound retry loop the cleaned
    # request gets one more (capped) send and succeeds; the old fixed-range
    # loop would have hard-failed with "exhausted all retries".
    class BadRequestError(Exception):
        def __init__(self, msg, status_code=400):
            super().__init__(msg)
            self.status_code = status_code

    class APIStatusError(Exception):
        def __init__(self, msg="", status_code=400):
            super().__init__(msg)
            self.status_code = status_code
            self.message = msg

    class APIConnectionError(Exception):
        pass

    monkeypatch.setattr(oai, "openai", _types.SimpleNamespace(
        BadRequestError=BadRequestError,
        APIStatusError=APIStatusError,
        APIConnectionError=APIConnectionError,
    ))
    monkeypatch.setattr(oai, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(oai, "_USE_LEGACY_MAXTOK", set())

    calls = {"n": 0}

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            n = calls["n"]
            if n == 1 and "temperature" in kw:
                raise BadRequestError("unexpected parameter: temperature")
            if n == 2 and "max_completion_tokens" in kw:
                raise BadRequestError("max_completion_tokens is not supported")
            if n == 3 and "max_tokens" in kw:
                raise BadRequestError("this model requires max_completion_tokens")
            return [_Ev("done", usage=None)]

    class _Client:
        chat = _types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())

    out = oai.prompt("hi", model="gpt-x", temperature=0.5)
    assert out == "done"
    # 3 rejections (incl. the last attempt) + 1 successful re-send.
    assert calls["n"] == 4

# prompt() — VVAH-E005: finish_reason="length" (output budget exhausted)

class _FinishChoice:
    def __init__(self, content, finish_reason=None):
        self.delta = _Delta(content)
        self.finish_reason = finish_reason


class _FinishEv:
    def __init__(self, content=None, usage=None, finish_reason=None):
        self.choices = ([_FinishChoice(content, finish_reason)]
                        if content is not None or finish_reason is not None
                        else [])
        self.usage = usage


class _TruncBadRequestError(Exception):
    def __init__(self, msg, status_code=400):
        super().__init__(msg)
        self.status_code = status_code


class _TruncAPIStatusError(Exception):
    def __init__(self, msg="", status_code=400):
        super().__init__(msg)
        self.status_code = status_code
        self.message = msg


class _TruncAPIConnectionError(Exception):
    pass


def _install_trunc_client(monkeypatch, responses):
    """Serve one canned stream or exception per create() call, recording every kwargs dict."""
    monkeypatch.setattr(oai, "openai", _types.SimpleNamespace(
        BadRequestError=_TruncBadRequestError,
        APIStatusError=_TruncAPIStatusError,
        APIConnectionError=_TruncAPIConnectionError,
    ))
    monkeypatch.setattr(oai, "_USE_LEGACY_MAXTOK", set())
    monkeypatch.setattr(oai, "_NO_TEMP_MODELS", set())
    calls: list[dict] = []

    class _Completions:
        def create(self, **kw):
            calls.append(dict(kw))
            r = responses[len(calls) - 1]
            if isinstance(r, Exception):
                raise r
            return r

    class _Client:
        chat = _types.SimpleNamespace(completions=_Completions())

        def with_options(self, **_k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    return calls


def test_prompt_truncated_reply_retries_once_at_doubled_budget(monkeypatch):
    full = "x" * 400
    calls = _install_trunc_client(monkeypatch, [
        [_FinishEv("partial", finish_reason="length")],
        [_FinishEv(full, finish_reason="stop")],
    ])

    out = oai.prompt("hi", model="gpt-x", max_tokens=1000)

    assert out == full
    assert len(calls) == 2
    assert calls[0]["max_completion_tokens"] == 1000
    assert calls[1]["max_completion_tokens"] == 2000
    # The retry is observable: a recovered E005 warning record, never silence.
    recs = [json.loads(line) for line in
            _errlog.current_path().read_text().splitlines() if line.strip()]
    assert any(r.get("error_code") == "VVAH-E005" and r.get("recovered") is True
               for r in recs)


def test_prompt_truncated_twice_raises_e005_and_bumps_counter(monkeypatch):
    calls = _install_trunc_client(monkeypatch, [
        [_FinishEv("partial", finish_reason="length")],
        [_FinishEv("still partial", finish_reason="length")],
    ])

    with pytest.raises(TruncatedResponseError) as ei:
        oai.prompt("hi", model="gpt-x", max_tokens=1000)

    assert "VVAH-E005" in str(ei.value)
    assert len(calls) == 2, "exactly one retry, then fail loud"
    assert COUNTERS.snapshot().get("llm_truncated_replies", 0) == 1


def test_prompt_doubled_budget_rejected_as_too_large_raises_e005(monkeypatch):
    """A 400 naming the budget param during the truncation retry is the provider's cap: E005."""
    calls = _install_trunc_client(monkeypatch, [
        [_FinishEv("partial", finish_reason="length")],
        _TruncBadRequestError(
            "max_completion_tokens is too large: 2000; at most 1500"),
    ])

    with pytest.raises(TruncatedResponseError) as ei:
        oai.prompt("hi", model="gpt-x", max_tokens=1000)

    assert "VVAH-E005" in str(ei.value)
    assert len(calls) == 2


def test_prompt_normal_stop_finish_reason_is_unchanged(monkeypatch):
    full = "y" * 400
    calls = _install_trunc_client(monkeypatch, [
        [_FinishEv(full, finish_reason="stop")],
    ])
    assert oai.prompt("hi", model="gpt-x") == full
    assert len(calls) == 1


def test_cap_tool_result_truncates_oversized():
    out = oai._cap_tool_result("x" * 100000)
    assert len(out) < oai._TOOL_RESULT_CAP + 200
    assert "truncated" in out


def test_cap_tool_result_passthrough_small():
    assert oai._cap_tool_result("hello") == "hello"
    assert oai._cap_tool_result("") == ""


def test_shrink_history_evicts_oldest_large_tool_message():
    msgs = [
        {"role": "system", "content": "s"},
        {"role": "tool", "content": "y" * 5000},
        {"role": "tool", "content": "z" * 5000},
    ]
    assert oai._shrink_history(msgs) is True
    assert len(msgs[1]["content"]) < 2100
    assert len(msgs[2]["content"]) == 5000        # only the oldest is touched
    # Nothing left large enough -> returns False (loop then raises, no hang).
    small = [{"role": "tool", "content": "short"}]
    assert oai._shrink_history(small) is False


def test_shrink_history_advances_across_repeated_calls():
    # Repeated overflows must evict DIFFERENT messages (not re-pick the first),
    # then return False once all oversized tool results are evicted — otherwise
    # multi-large-read overflows never free enough context.
    msgs = [{"role": "tool", "content": "a" * 5000},
            {"role": "tool", "content": "b" * 5000}]
    assert oai._shrink_history(msgs) is True          # evicts #0
    assert oai._shrink_history(msgs) is True          # ADVANCES to #1
    assert msgs[0]["content"].endswith(oai._EVICTED_MARK)
    assert msgs[1]["content"].endswith(oai._EVICTED_MARK)
    assert oai._shrink_history(msgs) is False         # nothing left to evict


# Transient classifier: retry 429/5xx by status plus gateway transient prose in
# `.message` OR the response body (the sdk._is_transient_sdk fallback, widened to
# the body because the SDK does not always copy it into `.message`), never
# terminal 4xx.

@pytest.mark.parametrize("sc,expected", [
    (429, True), (500, True), (502, True), (503, True), (504, True), (529, True),
    (400, False), (401, False), (403, False), (404, False), (None, False),
])
def test_is_transient_oai_status_path(sc, expected):
    import types
    assert oai._is_transient_oai(
        types.SimpleNamespace(status_code=sc, message="terminal")) is expected


def test_is_transient_oai_message_fallback():
    # The same hole existed here as in sdk: a transient the gateway
    # reports only in the message, under a status no retryable set contains.
    import types
    NS = types.SimpleNamespace
    assert oai._is_transient_oai(NS(
        status_code=200,
        message="Rate limiting temporarily unavailable. Please try again.")) is True
    for phrase in ("server_error", "overloaded", "service unavailable"):
        assert oai._is_transient_oai(NS(status_code=200, message=phrase)) is True


def test_is_transient_oai_message_fallback_excludes_permanent_errors():
    import types
    assert oai._is_transient_oai(types.SimpleNamespace(
        status_code=200, message="invalid_request_error: unknown parameter")) is False


def _status_err(*, status_code, message=None, response=None):
    err = _FakeStatusErr(response=response, message=message)
    err.status_code = status_code
    return err


def test_is_transient_oai_classifies_on_message_not_response_body():
    """The classifier reads `.message` ONLY, on purpose.

    openai-python builds `.message` from the body, and the one case where it does
    not — a stream closed unread — is also the case where `response.text` raises,
    so searching the body adds no coverage. It would add false positives: see
    test_is_transient_oai_incidental_429_in_body_is_not_transient."""
    err = _status_err(status_code=200, message="Error code: 200",
                      response=_FakeResp("Rate limiting temporarily "
                                         "unavailable. Please try again."))
    assert oai._is_transient_oai(err) is False


def test_is_transient_oai_incidental_429_in_body_is_not_transient():
    """A request id or token count containing 429 satisfies `\\b429\\b`. Reading
    the body would flip a terminal 400 into three attempts with 60s waits."""
    err = _status_err(status_code=400, message="invalid_request_error",
                      response=_FakeResp("request id req-429-abc: you requested "
                                         "429 tokens but the max is 128"))
    assert oai._is_transient_oai(err) is False


@pytest.mark.parametrize("status", [401, 403])
def test_is_transient_oai_explicit_auth_status_beats_transient_prose(status):
    """A proxy/DLP block page under 401/403 routinely says "Service Unavailable".
    Prose must not promote an unhealable auth status — agentic() has no auth
    branch, so without this it burns 10+20+30+40s on it."""
    err = _status_err(status_code=status,
                      message="Service Unavailable: request not authorized",
                      response=None)
    assert oai._is_transient_oai(err) is False


@pytest.mark.parametrize("phrase", ["Internal server error", "Bad Gateway"])
def test_is_transient_oai_prose_wrapped_5xx_under_200(phrase):
    """A gateway that prose-wraps a 500/502 inside an HTTP 200 payload: the
    machine token `server_error` needs its underscore, so these spellings must be
    matched explicitly or the work unit is lost."""
    err = _status_err(status_code=200, message=phrase, response=None)
    assert oai._is_transient_oai(err) is True


def test_is_transient_oai_prose_only_in_message():
    err = _status_err(status_code=200, response=None,
                      message="rate limit exceeded, please slow down")
    assert oai._is_transient_oai(err) is True


def test_is_transient_oai_permanent_with_neither_field_transient():
    err = _status_err(status_code=400,
                      message="invalid_request_error: unknown parameter",
                      response=_FakeResp("invalid_request_error: unknown parameter"))
    assert oai._is_transient_oai(err) is False


def test_is_transient_oai_body_read_never_raises():
    """A classifier must never raise. `resp.text` can (unread stream, decode
    failure), and this passes trivially only because the classifier no longer
    touches the body — which is the property being pinned: if someone reintroduces
    a body read without guarding it, this fails."""
    class _RaisingResp:
        @property
        def text(self):
            raise RuntimeError("Attempted to read streaming response content")

    still_transient = _status_err(status_code=200, response=_RaisingResp(),
                                  message="rate limit exceeded")
    assert oai._is_transient_oai(still_transient) is True
    permanent = _status_err(status_code=400, response=_RaisingResp(),
                            message="invalid_request_error")
    assert oai._is_transient_oai(permanent) is False


def test_prompt_retries_transient_500_then_succeeds(monkeypatch):
    import types as _t

    class APIStatusError(Exception):
        def __init__(self, status_code):
            super().__init__(f"status {status_code}")
            self.status_code = status_code

    class BadRequestError(APIStatusError):
        pass

    class APIConnectionError(Exception):
        pass

    monkeypatch.setattr(oai, "openai", _t.SimpleNamespace(
        APIStatusError=APIStatusError, BadRequestError=BadRequestError,
        APIConnectionError=APIConnectionError))
    monkeypatch.setattr(oai, "_summarise_status_error", lambda e: str(e))
    monkeypatch.setattr(oai.time, "sleep", lambda s: None)   # no real backoff
    monkeypatch.setattr(oai, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(oai, "_USE_LEGACY_MAXTOK", set())

    calls = {"n": 0}

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise APIStatusError(500)        # transient -> should retry
            return [_Ev("done", usage=None)]

    class _Client:
        chat = _t.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    out = oai.prompt("hi", model="gpt-x")
    assert out == "done"
    assert calls["n"] == 2                        # one 500 retry + success


def test_prompt_does_not_retry_terminal_404(monkeypatch):
    import types as _t

    class APIStatusError(Exception):
        def __init__(self, status_code):
            super().__init__(f"status {status_code}")
            self.status_code = status_code

    class BadRequestError(APIStatusError):
        pass

    class APIConnectionError(Exception):
        pass

    monkeypatch.setattr(oai, "openai", _t.SimpleNamespace(
        APIStatusError=APIStatusError, BadRequestError=BadRequestError,
        APIConnectionError=APIConnectionError))
    monkeypatch.setattr(oai, "_summarise_status_error", lambda e: str(e))
    monkeypatch.setattr(oai.time, "sleep", lambda s: None)
    monkeypatch.setattr(oai, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(oai, "_USE_LEGACY_MAXTOK", set())

    calls = {"n": 0}

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            raise APIStatusError(404)            # terminal -> must NOT retry

    class _Client:
        chat = _t.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    with pytest.raises(RuntimeError):
        oai.prompt("hi", model="gpt-x")
    assert calls["n"] == 1


# Provider message shapes (neutral placeholder model/limits) returned when the
# prompt exceeds the model's input window — the regex must match every variant
# so the agentic loop recovers instead of dropping work.
@pytest.mark.parametrize("msg", [
    "Input tokens exceed the configured limit of N tokens. Your messages resulted in M tokens.",
    "The context length of model test-model is N your query has M tokens in the prompts.",
    "Could not process the query for model test-model. Error: ... Input tokens exceed the configured limit of N tokens.",
    "context_length_exceeded",
])
def test_ctx_overflow_regex_matches_all_observed_shapes(msg):
    assert oai._CTX_OVERFLOW_RX.search(msg.lower())


# Redaction ordering: redact() must see the FULL error text BEFORE any [:400]
# truncation. Truncating first can cut a JWT's third segment below the pattern
# minimum, after which redact() no longer matches and raw token text survives.

_JWT_HEADER = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
_JWT_PAYLOAD = "eyJzdWIiOiJ2dmFoLXNjYW4iLCJleHAiOjIwMDAwMDAwMDB9"
_JWT_SIG = "U2VjcmV0U2lnbmF0dXJlTWF0ZXJpYWw" * 4
_JWT = f"{_JWT_HEADER}.{_JWT_PAYLOAD}.{_JWT_SIG}"


def test_auth_error_redacts_full_body_before_truncation(monkeypatch):
    """REGRESSION: redact(str(e)[:400]) truncated the JWT's third segment below
    the pattern's 10-char minimum, so redaction missed and raw token text
    reached the AuthenticationError. The order must be redact-then-truncate."""
    import types as _t

    from vvaharness.backends.harness.models import AuthenticationError

    class APIStatusError(Exception):
        def __init__(self, msg, status_code=401):
            super().__init__(msg)
            self.status_code = status_code

    class BadRequestError(Exception):
        pass

    class APIConnectionError(Exception):
        pass

    monkeypatch.setattr(oai, "openai", _t.SimpleNamespace(
        APIStatusError=APIStatusError, BadRequestError=BadRequestError,
        APIConnectionError=APIConnectionError))
    monkeypatch.setattr(oai, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(oai, "_USE_LEGACY_MAXTOK", set())
    monkeypatch.setattr(oai, "_AUTH_MAX_RETRIES_OAI", 0)  # no backoff sleeps

    seen: list[str] = []
    real_redact = oai.redact

    def spy(text):
        seen.append(text)
        return real_redact(text)

    monkeypatch.setattr(oai, "redact", spy)

    body = ("gateway rejected the request; " * 20)[:299] + "presented " + _JWT
    sig_start = body.index(_JWT_SIG)
    # Geometry pin: >400 chars total, and [:400] leaves a <10-char third JWT
    # segment — exactly the shape that defeated truncate-first redaction.
    assert len(body) > 400 > sig_start
    assert 400 - sig_start < 10

    class _Completions:
        def create(self, **kw):
            raise APIStatusError(body, status_code=401)

    class _Client:
        chat = _t.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    with pytest.raises(AuthenticationError) as ei:
        oai.prompt("hi", model="gpt-x")
    # The FULL, untruncated error text reached redact().
    assert seen and seen[0] == body
    msg = str(ei.value)
    assert "[REDACTED-JWT]" in msg
    for i in range(len(_JWT) - 12):  # no 12-char fragment of the token survives
        assert _JWT[i:i + 12] not in msg


def test_configure_warns_that_openai_cannot_present_a_client_cert(capsys):
    """`openai.client_cert` has no plumbing on this route — say so, don't ignore it.

    Silently dropping the knob leaves an operator believing mTLS is active.
    Mirrors the equivalent `via: cli` warning.
    """
    oai.configure(client_cert="/etc/pki/client-combined.pem")
    err = capsys.readouterr().err
    assert "cannot present a client certificate" in err
    assert "via: sdk" in err  # points at the routes that CAN do mTLS
    assert "client-combined.pem" not in err  # path is not echoed


def test_configure_stays_quiet_when_no_client_cert_is_set(capsys):
    """No client_cert configured means no mTLS warning at all."""
    oai.configure(organization="org-x")
    # Strict: the quietness claim is only meaningful if NOTHING was emitted.
    assert capsys.readouterr().err == ""


# Mid-stream transport truncation (httpx2-raised, escapes the SDK entirely).
# openai>=3 is backed by httpx2, NOT classic httpx: a RemoteProtocolError
# raised while ITERATING the stream is httpx2's class, surfaces raw (never
# wrapped into APIConnectionError), and no SDK/library retry covers it. The
# widened handler must therefore catch the httpx2 family — an except clause
# written against classic httpx would silently never match.

def _fake_oai_excs(monkeypatch):
    class BadRequestError(Exception):
        def __init__(self, msg, status_code=400):
            super().__init__(msg)
            self.status_code = status_code

    class APIStatusError(Exception):
        def __init__(self, msg="", status_code=500):
            super().__init__(msg)
            self.status_code = status_code

    class APIConnectionError(Exception):
        pass

    monkeypatch.setattr(oai, "openai", _types.SimpleNamespace(
        BadRequestError=BadRequestError,
        APIStatusError=APIStatusError,
        APIConnectionError=APIConnectionError,
    ))
    monkeypatch.setattr(oai.time, "sleep", lambda s: None)  # no real backoff
    monkeypatch.setattr(oai, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(oai, "_USE_LEGACY_MAXTOK", set())
    return BadRequestError


def _client_for(completions):
    class _Client:
        chat = _types.SimpleNamespace(completions=completions)

        def with_options(self, **k):
            return self

    return _Client()


def test_midstream_catch_set_covers_the_httpx2_exception_family():
    """Pin the class identity the whole fix hinges on: the installed openai
    (>=3) raises httpx2's RemoteProtocolError from stream iteration, which is
    NOT a subclass of classic httpx's — the handler must match httpx2's."""
    httpx2 = pytest.importorskip("httpx2")
    import httpx as classic_httpx
    assert not issubclass(httpx2.RemoteProtocolError,
                          classic_httpx.RemoteProtocolError)
    assert any(issubclass(httpx2.RemoteProtocolError, t)
               for t in oai._MIDSTREAM_TRANSPORT_ERRORS)


def test_prompt_retries_mid_stream_truncation_and_records_it(monkeypatch, capsys):
    """A RemoteProtocolError raised MID-ITERATION (after partial content) must
    be retried as a whole call, the partial text discarded, and the retry
    recorded — not escape every handler and lose the chunk's analysis."""
    httpx2 = pytest.importorskip("httpx2")
    _fake_oai_excs(monkeypatch)
    calls = {"n": 0}

    def _truncated_stream():
        yield _Ev("partial-", usage=None)
        raise httpx2.RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(incomplete chunked read)")

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                return _truncated_stream()
            return iter([_Ev("done", usage=None)])

    monkeypatch.setattr(oai, "_get_client", lambda: _client_for(_Completions()))
    out = oai.prompt("hi", model="gpt-x")
    assert out == "done"                 # partial text discarded, not glued in
    assert calls["n"] == 2               # one truncation + one full re-send
    err = capsys.readouterr().err
    assert "mid-stream transport error" in err
    assert "RemoteProtocolError" in err


def test_prompt_mid_stream_truncation_exhaustion_raises_not_silent(monkeypatch):
    """A persistently truncating upstream exhausts the bounded attempts and
    RAISES (so the caller records outcome=error) — never absorbed as success."""
    httpx2 = pytest.importorskip("httpx2")
    _fake_oai_excs(monkeypatch)
    calls = {"n": 0}

    def _truncated_stream():
        yield _Ev("partial-", usage=None)
        raise httpx2.RemoteProtocolError(
            "peer closed connection without sending complete message body")

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            return _truncated_stream()

    monkeypatch.setattr(oai, "_get_client", lambda: _client_for(_Completions()))
    with pytest.raises(RuntimeError) as ei:
        oai.prompt("hi", model="gpt-x")
    assert calls["n"] == 3               # the existing whole-call attempt cap
    msg = str(ei.value)
    assert "stream truncated" in msg
    assert "RemoteProtocolError" in msg


# Terminal 400 with a payload-contradicting vendor message: never retried,
# but the recorded error must carry enough request-shape context to tell
# "our payload was wrong" from "the gateway is mislabelling".

def test_prompt_400_image_rejection_not_retried_and_diagnosable(monkeypatch):
    BadRequestError = _fake_oai_excs(monkeypatch)
    calls = {"n": 0}

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            raise BadRequestError(
                "image understanding feature is not available or enabled")

    monkeypatch.setattr(oai, "_get_client", lambda: _client_for(_Completions()))
    user = ("analyse this template:\n"
            "<img src='data:image/jpeg;base64,{{img_str}}'>\n")
    with pytest.raises(RuntimeError) as ei:
        oai.prompt(user, model="glm-x", system_prompt="you are a scanner")
    assert calls["n"] == 1               # deterministic 400 -> exactly one send
    msg = str(ei.value)
    # Shape metadata proves the payload was text-only and names the trigger.
    assert "payload sent: 2 message(s)" in msg
    assert "types=['text']" in msg
    assert "data-URI markers in text=1" in msg
    assert "request was text-only" in msg
    # Never the content itself: no prompt text or template payload is echoed.
    assert "img_str" not in msg
    assert "analyse this template" not in msg


def test_prompt_400_without_image_wording_gets_shape_but_no_vision_hint(monkeypatch):
    BadRequestError = _fake_oai_excs(monkeypatch)

    class _Completions:
        def create(self, **kw):
            raise BadRequestError("invalid request: unknown field `foo`")

    monkeypatch.setattr(oai, "_get_client", lambda: _client_for(_Completions()))
    with pytest.raises(RuntimeError) as ei:
        oai.prompt("plain text prompt", model="gpt-x")
    msg = str(ei.value)
    assert "payload sent: 1 message(s)" in msg
    assert "data-URI markers in text=0" in msg
    assert "request was text-only" not in msg   # hint is image-message-matched


def test_payload_shape_reports_non_text_blocks_without_content():
    # A genuinely multimodal payload must be distinguishable ("our payload was
    # wrong") — and no block content may leak into the line.
    messages = [
        {"role": "user", "content": [
            {"type": "text", "text": "look at data:image/png;base64,AAAA"},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
        ]},
    ]
    line = oai._payload_shape(messages, "image understanding not available")
    assert "types=['image_url', 'text']" in line
    assert "data-URI markers in text=1" in line
    # Not text-only -> the gateway-sniffing hint must NOT be offered.
    assert "request was text-only" not in line
    assert "AAAA" not in line


# ─────────────────────────────────────────────────────────────────────────────
# agentic() caller-supplied tools (extra_tools / extra_dispatch), the result cap,
# and Anthropic→OpenAI schema conversion. These back the exploit-verification
# attacker loop when its model resolves `via: openai`.
# ─────────────────────────────────────────────────────────────────────────────
import json as _json


class _AFn:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _ATC:
    def __init__(self, id, name, arguments):
        self.id = id
        self.type = "function"
        self.function = _AFn(name, arguments)

    def model_dump(self):
        return {"id": self.id, "type": "function",
                "function": {"name": self.function.name,
                             "arguments": self.function.arguments}}


class _AMsg:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class _AChoice:
    def __init__(self, msg):
        self.message = msg


class _ARsp:
    def __init__(self, msg):
        self.choices = [_AChoice(msg)]
        self.usage = None


def _seq_oai_client(monkeypatch, responses):
    """Wire oai._get_client() to a fake whose chat.completions.create returns the scripted
    responses in order. Returns the list capturing create() kwargs per turn."""
    rec: list = []
    it = iter(responses)

    class _Completions:
        def create(self, **kw):
            rec.append(kw)
            result = next(it)
            if isinstance(result, BaseException):
                raise result
            return result

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    return rec


def _probe_anthropic_schema():
    return {"name": "probe", "description": "run a probe",
            "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}


def _tool_msgs(create_kwargs):
    return [m for m in create_kwargs["messages"] if m.get("role") == "tool"]


def test_anthropic_tool_to_openai_conversion():
    out = oai._anthropic_tool_to_openai(_probe_anthropic_schema())
    assert out["type"] == "function"
    assert out["function"]["name"] == "probe"
    assert out["function"]["parameters"]["properties"]["q"]["type"] == "string"


def test_agentic_dispatches_extra_tool_then_returns_final(monkeypatch):
    rec = _seq_oai_client(monkeypatch, [
        _ARsp(_AMsg(tool_calls=[_ATC("t1", "probe", _json.dumps({"q": "x"}))])),
        _ARsp(_AMsg(content="VERDICT")),
    ])
    seen = []
    out = oai.agentic("go", model="m", system_prompt="sys", allowed_tools=[], cwd=".",
                      extra_tools=[_probe_anthropic_schema()],
                      extra_dispatch=lambda n, a: (seen.append((n, a)) or "TOOLOUT"))
    assert out == "VERDICT"
    assert seen == [("probe", {"q": "x"})]
    # the converted tool was advertised to the model
    assert any(t["function"]["name"] == "probe" for t in rec[0]["tools"])
    # its result was fed back as a role:tool message on turn 2
    assert _tool_msgs(rec[1])[0]["content"] == "TOOLOUT"


def test_agentic_extra_dispatch_defers_to_localtools(monkeypatch):
    monkeypatch.setattr(oai._localtools, "execute",
                        lambda name, args, *, cwd: f"FILE:{name}")
    rec = _seq_oai_client(monkeypatch, [
        _ARsp(_AMsg(tool_calls=[_ATC("t1", "Read", _json.dumps({"path": "app.py"}))])),
        _ARsp(_AMsg(content="ok")),
    ])
    out = oai.agentic("go", model="m", system_prompt="s", allowed_tools=["Read"], cwd="/repo",
                      extra_tools=[_probe_anthropic_schema()], extra_dispatch=lambda n, a: None)
    assert out == "ok"
    assert _tool_msgs(rec[1])[0]["content"] == "FILE:Read"   # localtools ran on the defer


def test_agentic_forces_final_at_turn_budget(monkeypatch):
    def tool_turn():
        return _ARsp(_AMsg(tool_calls=[_ATC("t", "probe", "{}")]))
    _seq_oai_client(monkeypatch,
                    [tool_turn(), tool_turn(), _ARsp(_AMsg(content="FORCED"))])
    out = oai.agentic("go", model="m", system_prompt="s", allowed_tools=[], cwd=".",
                      extra_tools=[_probe_anthropic_schema()], extra_dispatch=lambda n, a: "R",
                      max_turns=2)
    assert out == "FORCED"


def test_agentic_forced_final_retries_transient(monkeypatch):
    class _Transient(Exception):
        status_code = 503

    monkeypatch.setattr(oai.openai, "APIStatusError", _Transient)
    monkeypatch.setattr(oai, "_is_transient_oai", lambda _e: True)
    monkeypatch.setattr(oai.time, "sleep", lambda _seconds: None)

    def tool_turn():
        return _ARsp(_AMsg(tool_calls=[_ATC("t", "probe", "{}")] ))

    rec = _seq_oai_client(monkeypatch, [tool_turn(), _Transient(),
                                        _ARsp(_AMsg(content="FORCED"))])
    out = oai.agentic("go", model="m", allowed_tools=[], cwd=".",
                      extra_tools=[_probe_anthropic_schema()],
                      extra_dispatch=lambda _n, _a: "R", max_turns=1)
    assert out == "FORCED"
    assert "tools" not in rec[1]
    assert "tools" not in rec[2]
