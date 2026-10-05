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

"""Offline unit tests for vvaharness.backends.llm.cli.

Covers envelope parsing (dict / streamed-list / guardrail refusal), the
TLS/proxy env builder + configure() matrix, error extraction, the argv/tail
formatting helpers, and parse_json_response. No network, no real `claude`
subprocess, no live LLM — all behaviour is exercised through pure functions
and module config state, which is reset between tests via an autouse fixture.
"""
import json
import subprocess

import pytest

from vvaharness.backends.llm import cli as claude_cli


@pytest.fixture(autouse=True)
def _reset_cli_globals(monkeypatch):
    """Isolate module-global TLS config so test order never matters.

    claude_cli._cfg and claude_cli._tls_extra are process-global singletons
    mutated by configure(); reset them to pristine defaults around every test.
    """
    monkeypatch.setattr(
        claude_cli,
        "_cfg",
        {"verify_ssl": True, "ca_cert": None,
         "client_cert": None, "no_proxy": None, "effort": "high"},
        raising=True,
    )
    monkeypatch.setattr(claude_cli, "_tls_extra", {}, raising=True)
    yield


# _parse_envelope

def test_parse_envelope_dict_shape():
    env = {"result": "  hello world  ",
           "usage": {"input_tokens": 5, "output_tokens": 7}}
    text, usage, *_ = claude_cli._parse_envelope(json.dumps(env))
    assert text == "hello world"          # .result, stripped
    assert usage == {"input_tokens": 5, "output_tokens": 7}


def test_parse_envelope_dict_non_string_result_returns_empty():
    raw = json.dumps({"result": {"nested": 1}, "usage": None})
    text, usage, *_ = claude_cli._parse_envelope(raw)
    assert text == ""
    assert usage is None


def test_parse_envelope_list_no_text_parts_returns_empty():
    env = [
        {"type": "system", "subtype": "init"},
        {"type": "assistant",
         "message": {"content": [{"type": "tool_use", "name": "Read"}]}},
        {"type": "result", "result": None, "usage": None},
    ]
    text, usage, *_ = claude_cli._parse_envelope(json.dumps(env))
    assert text == ""


def test_parse_envelope_list_streamed_shape():
    env = [
        {"type": "system", "subtype": "init"},
        {"type": "assistant", "message": {"content": [{"type": "text",
                                                        "text": "ignored"}]}},
        {"type": "result", "result": " final answer ",
         "usage": {"output_tokens": 3}},
    ]
    text, usage, *_ = claude_cli._parse_envelope(json.dumps(env))
    assert text == "final answer"
    assert usage == {"output_tokens": 3}


def test_parse_envelope_list_stitches_assistant_text_when_no_result_text():
    # result event present but its .result is not a string -> stitch assistant
    # text blocks together.
    env = [
        {"type": "assistant",
         "message": {"content": [{"type": "text", "text": "foo"},
                                 {"type": "text", "text": "bar"}]}},
        {"type": "result", "result": None, "usage": {"output_tokens": 1}},
    ]
    text, usage, *_ = claude_cli._parse_envelope(json.dumps(env))
    assert text == "foobar"
    assert usage == {"output_tokens": 1}


def test_parse_envelope_non_json_returns_raw_stripped():
    text, usage, *_ = claude_cli._parse_envelope("  not json at all  ")
    assert text == "not json at all"
    assert usage is None


def test_parse_envelope_top_level_scalar_returns_raw():
    # Valid JSON but neither dict nor list (a bare number).
    text, usage, *_ = claude_cli._parse_envelope("42")
    assert text == "42"
    assert usage is None


def test_parse_envelope_usage_not_dict_becomes_none():
    raw = json.dumps({"result": "ok", "usage": "garbage"})
    text, usage, *_ = claude_cli._parse_envelope(raw)
    assert text == "ok"
    # Both branches now guard, so a non-dict usage is dropped rather than passed on; TOKENS.add
    # discarded it anyway, and the list branch already returned None.
    assert usage is None


def test_parse_envelope_list_usage_not_dict_becomes_none():
    env = [{"type": "result", "result": "ok", "usage": "garbage"}]
    text, usage, *_ = claude_cli._parse_envelope(json.dumps(env))
    assert text == "ok"
    assert usage is None  # list branch coerces non-dict usage to None


def test_parse_envelope_stream_json_recovers_last_assistant_when_result_empty():
    lines = [
        json.dumps({"type": "assistant",
                    "message": {"content": [{"type": "text", "text": "early chatter"}]}}),
        json.dumps({"type": "assistant",
                    "message": {"content": [{"type": "text", "text": '{"modules":[]}'}]}}),
        json.dumps({"type": "result", "result": None, "usage": {"output_tokens": 9}}),
    ]
    text, usage, *_ = claude_cli._parse_envelope("\n".join(lines))
    assert text == '{"modules":[]}'        # last assistant event, not merged
    assert usage == {"output_tokens": 9}


def test_parse_envelope_guardrail_refusal_dict_raises():
    env = {"result": "Your request was not allowed",
           "num_turns": 1, "is_error": False,
           "usage": {"output_tokens": 0}}
    with pytest.raises(claude_cli.GuardrailBlocked):
        claude_cli._parse_envelope(json.dumps(env))


def test_parse_envelope_guardrail_refusal_list_raises():
    env = [{"type": "result", "result": "Your request was not allowed",
            "num_turns": 1, "is_error": False, "usage": {}}]
    with pytest.raises(claude_cli.GuardrailBlocked):
        claude_cli._parse_envelope(json.dumps(env))


def test_guardrail_exact_match_only_not_substring():
    # A legitimately short reply that merely CONTAINS the canned phrase must
    # NOT be treated as a block (exact-match-only is the security property).
    env = {"result": "Your request was not allowed because of XYZ, here's why",
           "num_turns": 1, "is_error": False}
    text, *_ = claude_cli._parse_envelope(json.dumps(env))
    assert text.startswith("Your request was not allowed because")


def test_guardrail_not_triggered_when_is_error_true():
    env = {"result": "Your request was not allowed",
           "num_turns": 1, "is_error": True}
    # is_error short-circuits the guardrail check -> no raise, returns text.
    text, *_ = claude_cli._parse_envelope(json.dumps(env))
    assert text == "Your request was not allowed"


def test_guardrail_not_triggered_when_multi_turn():
    env = {"result": "Your request was not allowed",
           "num_turns": 3, "is_error": False}
    text, *_ = claude_cli._parse_envelope(json.dumps(env))
    assert text == "Your request was not allowed"


# _extract_envelope_error

def test_extract_envelope_error_none_and_empty():
    assert claude_cli._extract_envelope_error(None) is None
    assert claude_cli._extract_envelope_error("") is None
    assert claude_cli._extract_envelope_error("not json") is None


def test_extract_envelope_error_dict_with_status():
    env = {"is_error": True, "api_error_status": 401,
           "result": "Invalid API key"}
    out = claude_cli._extract_envelope_error(json.dumps(env))
    assert out == "401 Invalid API key"


def test_extract_envelope_error_dict_without_status():
    env = {"subtype": "error", "message": "boom"}
    out = claude_cli._extract_envelope_error(json.dumps(env))
    assert out == "boom"


def test_extract_envelope_error_dict_not_error_returns_none():
    env = {"result": "fine", "is_error": False}
    assert claude_cli._extract_envelope_error(json.dumps(env)) is None


def test_extract_envelope_error_list_shape_anchors_on_bracket():
    # The list shape must not be truncated to its first inner '{'.
    env = [
        {"type": "system"},
        {"type": "result", "is_error": True,
         "api_error_status": 500, "error": "server error"},
    ]
    out = claude_cli._extract_envelope_error(json.dumps(env))
    assert out == "500 server error"


def test_extract_envelope_error_list_with_prose_prefix():
    # Leading prose before the bracket — finder anchors on first '[' or '{'.
    env = [{"type": "result", "subtype": "error_during_execution",
            "result": "exec failed"}]
    blob = "some warning line\n" + json.dumps(env)
    out = claude_cli._extract_envelope_error(blob)
    assert out == "exec failed"


def test_extract_envelope_error_unknown_error_default_message():
    env = {"is_error": True}
    out = claude_cli._extract_envelope_error(json.dumps(env))
    assert out == "unknown error"


# _build_tls_env / configure MATRIX

def test_tls_no_cert_is_noop():
    # Pristine defaults (verify_ssl=True, nothing else) -> empty env.
    assert claude_cli._build_tls_env() == {}


def test_configure_no_args_is_noop():
    claude_cli.configure()
    assert claude_cli._tls_extra == {}


def test_configure_ca_cert_existing_sets_node_extra_ca_certs(tmp_path):
    ca = tmp_path / "root-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")
    claude_cli.configure(ca_cert=str(ca))
    assert claude_cli._tls_extra["NODE_EXTRA_CA_CERTS"] == str(ca)
    assert "NODE_TLS_REJECT_UNAUTHORIZED" not in claude_cli._tls_extra


def test_ca_bundle_via_string_valued_verify_ssl(tmp_path):
    # verify=ca or verify_ssl precedence: a string verify_ssl is a bundle path.
    ca = tmp_path / "bundle.pem"
    ca.write_text("x")
    claude_cli.configure(verify_ssl=str(ca))
    assert claude_cli._tls_extra["NODE_EXTRA_CA_CERTS"] == str(ca)


def test_configure_missing_ca_path_warns_and_unset(tmp_path, capsys):
    missing = str(tmp_path / "does-not-exist.pem")
    claude_cli.configure(ca_cert=missing)
    assert "NODE_EXTRA_CA_CERTS" not in claude_cli._tls_extra
    err = capsys.readouterr().err
    assert "not found" in err
    assert "NODE_EXTRA_CA_CERTS" in err


def test_configure_verify_ssl_false_disables_node_tls(capsys):
    claude_cli.configure(verify_ssl=False)
    assert claude_cli._tls_extra["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"
    err = capsys.readouterr().err
    assert "TLS verification disabled" in err


def test_configure_verify_ssl_string_false_disables_node_tls():
    claude_cli.configure(verify_ssl="false")
    assert claude_cli._tls_extra.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0"
    assert "NODE_EXTRA_CA_CERTS" not in claude_cli._tls_extra


def test_configure_no_proxy_sets_both_case_vars():
    claude_cli.configure(no_proxy="api.example.test,localhost")
    assert claude_cli._tls_extra["NO_PROXY"] == "api.example.test,localhost"
    assert claude_cli._tls_extra["no_proxy"] == "api.example.test,localhost"


def test_configure_client_cert_warns_and_not_injected(tmp_path, capsys):
    # mTLS client certs must NOT be injected (Node has no env path) — only warn.
    cert = tmp_path / "client.pem"
    cert.write_text("x")
    claude_cli.configure(client_cert=str(cert))
    # Nothing TLS-bearing should be set from a client cert.
    assert claude_cli._tls_extra == {}
    err = capsys.readouterr().err
    assert "client_cert" in err or "mTLS" in err
    assert "cannot present a client certificate" in err
    # And the cert path itself must never leak into the subprocess env.
    assert str(cert) not in json.dumps(claude_cli._tls_extra)


def test_configure_combined_matrix(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    claude_cli.configure(ca_cert=str(ca), verify_ssl=False,
                         no_proxy="example.com", client_cert="ignored.pem")
    extra = claude_cli._tls_extra
    assert extra["NODE_EXTRA_CA_CERTS"] == str(ca)
    assert extra["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"
    assert extra["NO_PROXY"] == "example.com"
    assert extra["no_proxy"] == "example.com"


def test_configure_persists_partial_updates(tmp_path):
    # Falsy/None args should not clobber a previously stored value.
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    claude_cli.configure(ca_cert=str(ca))
    claude_cli.configure(no_proxy="example.com")  # ca_cert not re-passed
    assert claude_cli._cfg["ca_cert"] == str(ca)
    assert claude_cli._tls_extra["NODE_EXTRA_CA_CERTS"] == str(ca)
    assert claude_cli._tls_extra["NO_PROXY"] == "example.com"


# _tail / _short_cmd

def test_tail_none_and_empty():
    assert claude_cli._tail(None) == ""
    assert claude_cli._tail("") == ""


def test_tail_short_text_unchanged():
    assert claude_cli._tail("  hi  ", n=100) == "hi"


def test_tail_long_text_truncated_from_end():
    text = "A" * 50 + "B" * 50
    out = claude_cli._tail(text, n=20)
    assert out.startswith("...\n")
    assert out.endswith("B" * 20)
    assert len(out) == len("...\n") + 20


def test_short_cmd_elides_long_args():
    long_arg = "X" * 200
    out = claude_cli._short_cmd(["claude", "-p", long_arg])
    assert "claude -p " in out
    assert "<200 chars>" in out
    assert long_arg not in out  # full long arg never reproduced


def test_short_cmd_keeps_short_args_and_strips_newlines_in_head():
    long_arg = "line1\n" + "Y" * 100
    out = claude_cli._short_cmd([long_arg])
    # Newline inside the elided head is flattened to a space.
    assert "\n" not in out.split("...")[0]
    assert "<" in out and "chars>" in out


# parse_json_response

def test_parse_json_response_envelope_with_string_result():
    payload = {"findings": [1, 2, 3]}
    envelope = json.dumps({"result": json.dumps(payload)})
    assert claude_cli.parse_json_response(envelope) == payload


def test_parse_json_response_envelope_with_object_result():
    envelope = json.dumps({"result": {"k": "v"}})
    assert claude_cli.parse_json_response(envelope) == {"k": "v"}


def test_parse_json_response_plain_json_object():
    assert claude_cli.parse_json_response('{"a": 1}') == {"a": 1}


def test_parse_json_response_falls_back_to_extract_json_with_fence():
    text = "here is the output:\n```json\n{\"x\": 42}\n```\ntrailing prose"
    assert claude_cli.parse_json_response(text) == {"x": 42}


def test_parse_json_response_recovers_json_buried_in_prose():
    text = "Sure! The result is {\"ok\": true} as requested."
    assert claude_cli.parse_json_response(text) == {"ok": True}


def test_parse_json_response_no_json_raises():
    with pytest.raises((ValueError, json.JSONDecodeError)):
        claude_cli.parse_json_response("no structured data here")


# GuardrailBlocked type

def test_guardrailblocked_is_runtimeerror():
    assert issubclass(claude_cli.GuardrailBlocked, RuntimeError)


def test_guardrailblocked_is_one_class_across_the_family():
    """cli re-exports models' class; two classes sharing the name made `except` silently miss."""
    from vvaharness.backends.llm import models

    assert claude_cli.GuardrailBlocked is models.GuardrailBlocked


# _run_with_retry — structured transient classification
#
# The retry decision must come from the terminal result event's
# api_error_status, NOT a substring scan of the whole JSON envelope (which
# routinely carries a `rate_limit_event` telemetry block and numeric fields).
# These tests drive _run_with_retry with a fake _run and a recording sleep so
# no real subprocess or wall-clock wait occurs.

def _cp(returncode, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["claude"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _seq_run(monkeypatch, results):
    """Install a fake _run that returns `results` in order; returns a call
    counter dict so a test can assert how many times _run was invoked."""
    calls = {"n": 0}

    def fake_run(cmd, **kw):
        r = results[min(calls["n"], len(results) - 1)]
        calls["n"] += 1
        return r

    monkeypatch.setattr(claude_cli, "_run", fake_run)
    return calls


def _record_sleeps(monkeypatch):
    sleeps = []
    monkeypatch.setattr(claude_cli.time, "sleep", lambda s: sleeps.append(s))
    return sleeps


def test_run_with_retry_telemetry_rate_limit_event_not_retried(monkeypatch):
    # Envelope carries a routine rate_limit_event telemetry block AND a stray
    # "429" inside duration_ms, but the terminal status is 400 -> terminal.
    envelope = [
        {"type": "system", "subtype": "init"},
        {"type": "rate_limit_event", "rate_limit_info": {"status": "allowed"}},
        {"type": "result", "subtype": "error", "is_error": True,
         "api_error_status": 400, "result": "bad request",
         "usage": {"duration_ms": 429}},
    ]
    calls = _seq_run(monkeypatch, [_cp(1, json.dumps(envelope))])
    sleeps = _record_sleeps(monkeypatch)
    res = claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 1          # no retry
    assert sleeps == []             # no backoff
    assert res.returncode == 1


def test_run_with_retry_null_status_token_cap_not_retried(monkeypatch):
    # The output-token-cap pseudo-error: is_error true, api_error_status null,
    # plus stray 429 digits. Must NOT be retried.
    envelope = {"type": "result", "is_error": True, "api_error_status": None,
                "result": "API Error: response exceeded the 4 output token maximum",
                "usage": {"duration_ms": 1429}, "session_id": "7b429e21-aaaa"}
    calls = _seq_run(monkeypatch, [_cp(1, json.dumps(envelope))])
    sleeps = _record_sleeps(monkeypatch)
    claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 1
    assert sleeps == []


def test_run_with_retry_status_429_is_retried(monkeypatch):
    transient = {"type": "result", "is_error": True, "api_error_status": 429,
                 "result": "rate limited"}
    ok = {"type": "result", "result": "ok"}
    calls = _seq_run(monkeypatch, [_cp(1, json.dumps(transient)),
                                   _cp(0, json.dumps(ok))])
    sleeps = _record_sleeps(monkeypatch)
    res = claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 2          # one retry then success
    assert res.returncode == 0
    assert sum(sleeps) == 30        # first backoff window = 30s (chunked 5s polls)


@pytest.mark.parametrize("status", [502, 503, 529])
def test_run_with_retry_5xx_transient_retried(monkeypatch, status):
    transient = {"type": "result", "is_error": True, "api_error_status": status,
                 "result": "upstream"}
    ok = {"type": "result", "result": "ok"}
    calls = _seq_run(monkeypatch, [_cp(1, json.dumps(transient)),
                                   _cp(0, json.dumps(ok))])
    _record_sleeps(monkeypatch)
    res = claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 2
    assert res.returncode == 0


def test_run_with_retry_500_not_retried(monkeypatch):
    # 500 is intentionally NOT in the retryable set (often a deterministic
    # server error; the CLI already retried internally).
    envelope = {"type": "result", "is_error": True, "api_error_status": 500,
                "result": "internal error"}
    calls = _seq_run(monkeypatch, [_cp(1, json.dumps(envelope))])
    sleeps = _record_sleeps(monkeypatch)
    claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 1
    assert sleeps == []


def test_run_with_retry_hard_cap_not_retried_even_with_429(monkeypatch):
    # Hard usage-cap text short-circuits BEFORE the transient check, even when
    # the status is otherwise retryable.
    envelope = {"type": "result", "is_error": True, "api_error_status": 429,
                "result": "You have hit your usage limit. resets at 7pm."}
    calls = _seq_run(monkeypatch, [_cp(1, json.dumps(envelope))])
    sleeps = _record_sleeps(monkeypatch)
    claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 1
    assert sleeps == []


def test_run_with_retry_no_envelope_fallback_retries_on_transient_text(monkeypatch):
    # Old-CLI / crash path: no JSON envelope; transient phrase in stderr only.
    calls = _seq_run(monkeypatch, [_cp(1, "", "overloaded, temporarily unavailable"),
                                   _cp(0, "ok")])
    _record_sleeps(monkeypatch)
    res = claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 2
    assert res.returncode == 0


def test_run_with_retry_socket_closed_is_retried(monkeypatch):
    transient = {"type": "result", "is_error": True, "api_error_status": None,
                 "result": "API Error: The socket connection was closed unexpectedly"}
    ok = {"type": "result", "result": "ok"}
    calls = _seq_run(monkeypatch, [_cp(1, json.dumps(transient)),
                                   _cp(0, json.dumps(ok))])
    _record_sleeps(monkeypatch)
    res = claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 2
    assert res.returncode == 0


@pytest.mark.parametrize("phrase", [
    # RATE_LIMIT_TRANSIENT_RX — every alternative the old _RL_TRANSIENT matched
    "got 429 from upstream", "rate limit exceeded", "rate-limited",
    "Too Many Requests", "Overloaded", "temporarily unavailable",
    # CLI_CONN_TRANSIENT_RX — every alternative the old _CONN_TRANSIENT matched
    "The socket connection was closed unexpectedly", "connection reset by peer",
    "connection closed", "connection aborted", "ECONNRESET", "EPIPE",
    "broken pipe", "incomplete read", "incompletely read", "prematurely closed",
    "EOF occurred in violation of protocol",
])
def test_run_with_retry_pre_promotion_phrases_still_retried(monkeypatch, phrase):
    # The transient regexes moved to models.py (shared with sdk/openai); every
    # phrase cli retried before the move must still retry after it.
    transient = {"type": "result", "is_error": True, "api_error_status": None,
                 "result": f"API Error: {phrase}"}
    ok = {"type": "result", "result": "ok"}
    calls = _seq_run(monkeypatch, [_cp(1, json.dumps(transient)),
                                   _cp(0, json.dumps(ok))])
    _record_sleeps(monkeypatch)
    res = claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 2
    assert res.returncode == 0


def test_run_with_retry_sdk_only_phrases_still_not_retried(monkeypatch):
    # Sharing flowed cli's regexes outward, not sdk's inward: server-error
    # prose stays non-retryable here, because the binary's own retries already
    # covered it (the same reasoning as the CLI_RETRYABLE_STATUS carve-out).
    envelope = {"type": "result", "is_error": True, "api_error_status": None,
                "result": "server_error: service unavailable"}
    calls = _seq_run(monkeypatch, [_cp(1, json.dumps(envelope))])
    sleeps = _record_sleeps(monkeypatch)
    claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 1
    assert sleeps == []


def _seq_run_raising(monkeypatch, seq):
    """fake _run that raises BaseExceptions in `seq` and returns the rest."""
    calls = {"n": 0}

    def fake_run(cmd, **kw):
        r = seq[min(calls["n"], len(seq) - 1)]
        calls["n"] += 1
        if isinstance(r, BaseException):
            raise r
        return r

    monkeypatch.setattr(claude_cli, "_run", fake_run)
    return calls


def test_run_with_retry_timeout_retried_once_then_succeeds(monkeypatch):
    calls = _seq_run_raising(
        monkeypatch,
        [subprocess.TimeoutExpired(["claude"], 10), _cp(0, '{"result":"ok"}')])
    res = claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 2          # one timeout retry, then success
    assert res.returncode == 0


def test_run_with_retry_timeout_exhausted_reraises(monkeypatch):
    calls = _seq_run_raising(
        monkeypatch,
        [subprocess.TimeoutExpired(["claude"], 10),
         subprocess.TimeoutExpired(["claude"], 10)])
    with pytest.raises(subprocess.TimeoutExpired):
        claude_cli._run_with_retry(["claude"], label="t")
    assert calls["n"] == 2          # retried once (cap=1) then re-raised


def test_run_with_retry_timeout_honors_abort(monkeypatch):
    calls = _seq_run_raising(monkeypatch, [subprocess.TimeoutExpired(["claude"], 10)])
    claude_cli._ABORT.set()
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            claude_cli._run_with_retry(["claude"], label="t")
    finally:
        claude_cli._ABORT.clear()
    assert calls["n"] == 1          # aborted before any retry


def test_terminal_result_fields_list_and_dict_and_non_json():
    # list shape: authoritative status comes from the LAST result event
    lst = json.dumps([{"type": "rate_limit_event"},
                      {"type": "result", "api_error_status": 503, "result": "x"}])
    assert claude_cli._terminal_result_fields(lst) == (503, "x", True)
    # dict shape
    d = json.dumps({"type": "result", "api_error_status": None, "result": "y"})
    assert claude_cli._terminal_result_fields(d) == (None, "y", True)
    # non-JSON -> not found
    assert claude_cli._terminal_result_fields("plain text") == (None, None, False)


# --effort pinning — the scan subprocess must not inherit the operator's
# interactive /effort default (settings.json effortLevel / CLAUDE_EFFORT);
# some models reject levels like 'xhigh'.

def _capture_cmd(monkeypatch):
    captured = {}

    def fake_rwr(cmd, *, label, **kw):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(
            ["claude"], 0, '{"result":"ok","usage":{}}', "")

    monkeypatch.setattr(claude_cli, "_run_with_retry", fake_rwr)
    return captured


def test_prompt_pins_default_effort_high(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    claude_cli.prompt("hi", model="m")
    cmd = captured["cmd"]
    assert "--effort" in cmd
    assert cmd[cmd.index("--effort") + 1] == "high"


def test_agentic_pins_default_effort_high(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    claude_cli.agentic("hi", model="m", cwd=".")
    cmd = captured["cmd"]
    assert "--effort" in cmd
    assert cmd[cmd.index("--effort") + 1] == "high"


def test_configure_overrides_effort(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    claude_cli.configure(effort="max")
    claude_cli.prompt("hi", model="m")
    cmd = captured["cmd"]
    assert cmd[cmd.index("--effort") + 1] == "max"


def test_preflight_probe_applies_configured_effort(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    claude_cli.configure(effort="max")
    claude_cli.prompt("hi", model="m", tag="preflight")
    cmd = captured["cmd"]
    assert "--effort" in cmd
    assert cmd[cmd.index("--effort") + 1] == "max"


def test_agentic_preflight_applies_configured_effort(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    claude_cli.configure(effort="max")
    claude_cli.agentic("hi", model="m", cwd=".", tag="preflight")
    cmd = captured["cmd"]
    assert "--effort" in cmd
    assert cmd[cmd.index("--effort") + 1] == "max"


# allowedTools — the caller's allowlist is honoured AS-GIVEN. Bash is NEVER
# auto-added: a hostile target repo can prompt-inject the agent via files it
# Reads/Greps, and a force-granted shell would turn that into RCE on the
# scanning host. Operators who need Bash list it explicitly.

def _allowed_tools(cmd):
    i = cmd.index("--allowedTools")
    # collect everything up to the next flag (tokens after --allowedTools).
    out = []
    for tok in cmd[i + 1:]:
        if tok.startswith("--"):
            break
        out.append(tok)
    return out


def test_agentic_honours_allowed_tools_verbatim(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    claude_cli.agentic("hi", model="m", cwd=".",
                       allowed_tools=["Read", "Glob", "Grep"])
    tools = _allowed_tools(captured["cmd"])
    assert tools == ["Read", "Glob", "Grep"]
    assert "Bash" not in tools


def test_agentic_passes_bash_only_when_caller_lists_it(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    claude_cli.agentic("hi", model="m", cwd=".",
                       allowed_tools=["Read", "Bash", "Grep"])
    tools = _allowed_tools(captured["cmd"])
    assert tools == ["Read", "Bash", "Grep"]
    assert tools.count("Bash") == 1

def _fake_caps(monkeypatch, *, max_turns):
    monkeypatch.setattr(
        claude_cli, "_cli_capabilities",
        lambda: {"effort": True, "max_turns": max_turns,
                 "permission_modes": set(), "probed": True})


def test_agentic_appends_max_turns_when_supported(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    _fake_caps(monkeypatch, max_turns=True)
    claude_cli.agentic("hi", model="m", cwd=".", max_turns=40)
    cmd = captured["cmd"]
    assert "--max-turns" in cmd
    assert cmd[cmd.index("--max-turns") + 1] == "40"


def test_agentic_omits_max_turns_when_unsupported(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    _fake_caps(monkeypatch, max_turns=False)
    claude_cli.agentic("hi", model="m", cwd=".", max_turns=40)
    assert "--max-turns" not in captured["cmd"]


def test_agentic_omits_max_turns_when_none(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    _fake_caps(monkeypatch, max_turns=True)
    claude_cli.agentic("hi", model="m", cwd=".", max_turns=None)
    assert "--max-turns" not in captured["cmd"]

def test_agentic_pairs_verbose_with_stream_json(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    _fake_caps(monkeypatch, max_turns=True)
    claude_cli.agentic("hi", model="m", cwd=".")
    cmd = captured["cmd"]
    assert "--verbose" in cmd
    oi = cmd.index("--output-format")
    assert cmd[oi + 1] == "stream-json"
    assert cmd[oi + 2] == "--verbose"


def test_is_pending_result_detects_background_markers():
    assert claude_cli._is_pending_result("__PENDING__") is True
    assert claude_cli._is_pending_result("still executing in background") is True
    assert claude_cli._is_pending_result("Task is still pending") is True
    assert claude_cli._is_pending_result("waiting for sub-agent to finish") is True
    assert claude_cli._is_pending_result("waiting for background subagent") is True
    assert claude_cli._is_pending_result("normal final output") is False


def test_agentic_retries_pending_result_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_rwr(cmd, *, label, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return subprocess.CompletedProcess(
                ["claude"], 0,
                json.dumps({"result": "__PENDING__ still executing", "usage": {}}),
                "",
            )
        return subprocess.CompletedProcess(
            ["claude"], 0,
            json.dumps({"result": "final-json", "usage": {}}),
            "",
        )

    monkeypatch.setattr(claude_cli, "_run_with_retry", fake_rwr)
    monkeypatch.setattr(claude_cli.time, "sleep", lambda s: None)

    out = claude_cli.agentic("hi", model="m", cwd=".")
    assert out == "final-json"
    assert calls["n"] == 2


def test_agentic_raises_when_pending_persists(monkeypatch):
    calls = {"n": 0}

    def fake_rwr(cmd, *, label, **kw):
        calls["n"] += 1
        return subprocess.CompletedProcess(
            ["claude"], 0,
            json.dumps({"result": "__PENDING__ still executing", "usage": {}}),
            "",
        )

    monkeypatch.setattr(claude_cli, "_run_with_retry", fake_rwr)
    monkeypatch.setattr(claude_cli.time, "sleep", lambda s: None)

    with pytest.raises(RuntimeError, match="unfinished background-subagent"):
        claude_cli.agentic("hi", model="m", cwd=".")
    # Initial call + exactly _PENDING_MAX_RETRIES retries.
    assert calls["n"] == claude_cli._PENDING_MAX_RETRIES + 1


def test_agentic_retries_pending_subagent_wording_variant(monkeypatch):
    calls = {"n": 0}

    def fake_rwr(cmd, *, label, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return subprocess.CompletedProcess(
                ["claude"], 0,
                json.dumps({"result": "Task is still pending; waiting for sub-agent", "usage": {}}),
                "",
            )
        return subprocess.CompletedProcess(
            ["claude"], 0,
            json.dumps({"result": "final-json", "usage": {}}),
            "",
        )

    monkeypatch.setattr(claude_cli, "_run_with_retry", fake_rwr)
    monkeypatch.setattr(claude_cli.time, "sleep", lambda s: None)

    out = claude_cli.agentic("hi", model="m", cwd=".")
    assert out == "final-json"
    assert calls["n"] == 2


def test_prompt_uses_json_and_no_verbose(monkeypatch):
    captured = _capture_cmd(monkeypatch)
    _fake_caps(monkeypatch, max_turns=True)
    claude_cli.prompt("hi", model="m")
    cmd = captured["cmd"]
    assert "--verbose" not in cmd
    oi = cmd.index("--output-format")
    assert cmd[oi + 1] == "json"


def test_find_claude_cmd_honors_existing_override(monkeypatch, tmp_path):
    binpath = tmp_path / "claude"
    binpath.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("VVAHARNESS_CLAUDE_BINARY", str(binpath))
    assert claude_cli._find_claude_cmd() == [str(binpath)]


def test_find_claude_cmd_missing_override_falls_back(monkeypatch):
    monkeypatch.setenv("VVAHARNESS_CLAUDE_BINARY", "/no/such/claude-xyz")
    monkeypatch.setattr(claude_cli.os, "name", "posix")
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: "/usr/bin/claude")
    # bogus override is NOT used; falls back to the PATH-resolved abs path
    assert claude_cli._find_claude_cmd() == ["/usr/bin/claude"]


def test_find_claude_cmd_pins_abs_path_no_override(monkeypatch):
    monkeypatch.delenv("VVAHARNESS_CLAUDE_BINARY", raising=False)
    monkeypatch.setattr(claude_cli.os, "name", "posix")
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: "/opt/bin/claude")
    # Unix: absolute resolved path, NOT the bare name
    assert claude_cli._find_claude_cmd() == ["/opt/bin/claude"]


def test_find_claude_cmd_bare_fallback_when_unresolvable(monkeypatch):
    monkeypatch.delenv("VVAHARNESS_CLAUDE_BINARY", raising=False)
    monkeypatch.setattr(claude_cli.os, "name", "posix")
    monkeypatch.setattr(claude_cli.shutil, "which", lambda n: None)
    assert claude_cli._find_claude_cmd() == ["claude"]   # last-resort, with warning


# ─────────────────────────────────────────────────────────────────────────────
# Caller-supplied tools: the CLI runs its loop in a subprocess with only its
# built-in tools, so it cannot carry one (e.g. exploit verification's
# http_request). It must fail loud, before spawning anything, pointing the caller
# at the backends that can (sdk / openai).
# ─────────────────────────────────────────────────────────────────────────────

def test_agentic_rejects_caller_supplied_tools():
    schema = {"name": "http_request", "description": "x",
              "input_schema": {"type": "object", "properties": {}}}
    with pytest.raises(NotImplementedError) as ei:
        claude_cli.agentic("go", model="m", cwd=".",
                           extra_tools=[schema], extra_dispatch=lambda n, a: "x")
    msg = str(ei.value)
    assert "via: sdk" in msg and "via: openai" in msg   # names the way out


def test_parse_envelope_carries_reported_spend():
    """num_turns / total_cost_usd reach the caller; absent stays None, never zero."""
    env = {"result": "ok", "usage": {"input_tokens": 5},
           "num_turns": 4, "total_cost_usd": 0.031}
    res = claude_cli._parse_envelope(json.dumps(env))
    assert (res.turns, res.usd) == (4, 0.031)

    bare = claude_cli._parse_envelope(json.dumps({"result": "ok"}))
    assert bare.turns is None and bare.usd is None


def test_parse_envelope_streamed_shape_carries_spend():
    """The list/stream shape reads spend off the result event, same as the dict shape."""
    env = [{"type": "assistant", "message": {"content": [{"type": "text", "text": "hi"}]}},
           {"type": "result", "result": "ok", "num_turns": 2, "total_cost_usd": 0.5}]
    res = claude_cli._parse_envelope(json.dumps(env))
    assert (res.turns, res.usd) == (2, 0.5)


_JWT = ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiJ2dmFoLXNjYW4iLCJleHAiOjIwMDAwMDAwMDB9"
        + "." + "U2VjcmV0U2lnbmF0dXJlTWF0ZXJpYWw" * 4)


def test_format_cli_error_redacts_before_tailing():
    """REGRESSION: redact(_tail(x)) dropped a token's leading `eyJ` anchor.

    _tail keeps only the LAST 1200 chars, so a JWT straddling that cut lost its
    header, stopped matching report.redact's pattern, and the remainder reached
    stderr verbatim. Order must be _tail(redact(x)).
    """
    # Geometry pin: _tail keeps the LAST 1200 chars, so the token must sit far
    # enough from the end that the cut falls INSIDE it -- that is the only shape
    # that ever leaked. Trailing filler pushes the token's head out of the window.
    # Verified separately: redact() masks a whole JWT but leaves ANY suffix
    # fragment of one completely unmasked, which is why the cut position matters.
    trailing = "trailing diagnostic noise; " * 41          # ~1107 chars
    stderr = "leading context\n" + _JWT + "\n" + trailing
    tail_start = len(stderr.strip()) - 1200
    jwt_start = stderr.strip().index(_JWT)
    assert jwt_start < tail_start < jwt_start + len(_JWT), (
        "test is vacuous unless the tail boundary lands inside the token")

    msg = claude_cli._format_cli_error(
        "claude failed", ["claude", "-p"],
        subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=stderr),
    )
    # No 12-char window of the token may survive anywhere in the message.
    for i in range(len(_JWT) - 12):
        assert _JWT[i:i + 12] not in msg, f"raw token fragment at offset {i} leaked"
    assert "REDACTED" in msg
