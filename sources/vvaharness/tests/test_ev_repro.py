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

"""Replayable repro capture — ReproDetail from the transcript, and its curl.

The curl has to match how the executor actually sent the request, or an analyst
following the repro reproduces something else. The fidelity rules pinned here:
query lives outside ``url``, a dict body replays with the content type it was sent
under (JSON by default, form when the endpoint declared it), redirects are not
followed, and credentials are never recorded.
"""
from __future__ import annotations

from vvaharness.exploit_verification.executor.model import EvResponse, RequestRecord
from vvaharness.exploit_verification.payloads.markers import mint_markers
from vvaharness.exploit_verification.verify import oracle
from vvaharness.exploit_verification.verify.model import MAX_BODY, ReproDetail
from vvaharness.exploit_verification.verify.repro import (best_effort_record,
                                                          detail_from_record,
                                                          render_block, to_curl,
                                                          to_line)


class _F:
    chunk_id, file, line_start, title = "c", "app.py", 1, "t"


def _rec(**kw):
    base = dict(method="GET", url="http://h/user", params={}, body=None, authed=False,
                payload_label="p", injection_point="query.id",
                response=EvResponse(200, "ok", {"Content-Type": "text/html"}, 0.01, "http://h/user"))
    base.update(kw)
    return RequestRecord(**base)


# ── capture ──────────────────────────────────────────────────────────────────

def test_detail_captures_request_and_response():
    d = detail_from_record(_rec(params={"id": "1' OR '1'='1"}), "id")
    assert d.method == "GET" and d.url == "http://h/user"
    assert d.params == {"id": "1' OR '1'='1"}      # query kept apart from the url
    assert d.param == "id" and d.authed is False
    assert d.resp_status == 200 and d.resp_body == "ok"


def test_response_body_truncated_at_capture_time():
    big = "X" * (MAX_BODY + 900)
    d = detail_from_record(_rec(response=EvResponse(200, big, {}, 0.0, "u")))
    assert len(d.resp_body) == MAX_BODY and d.resp_truncated is True


def test_short_body_not_flagged_truncated():
    d = detail_from_record(_rec(response=EvResponse(200, "small", {}, 0.0, "u")))
    assert d.resp_truncated is False


def test_capture_keeps_only_evidence_bearing_response_headers():
    resp = EvResponse(302, "", {"Location": "http://evil", "Date": "now", "Server": "x"}, 0.0, "u")
    d = detail_from_record(_rec(response=resp))
    keys = {k.lower() for k in d.resp_headers}
    assert "location" in keys                       # carries the open-redirect tell
    assert "date" not in keys and "server" not in keys      # noise dropped


def test_capture_never_carries_credentials():
    # the executor records only payload-controlled headers; assert we don't invent more
    d = detail_from_record(_rec(authed=True, sent_headers={"X-Payload": "1"}))
    assert d.sent_headers == {"X-Payload": "1"} and d.authed is True
    assert not any("authorization" in k.lower() for k in d.sent_headers)


def test_no_response_is_survivable():
    d = detail_from_record(_rec(response=None))
    assert d.resp_status is None and d.resp_body == "" and d.elapsed == 0.0


def test_capture_coerces_non_string_header_and_param_values():
    """The oracle is the authority for CONFIRMED and must never raise: a non-str
    header value used to fail ReproDetail validation inside ``confirm()``, turning
    a confirmed finding into a crash."""
    resp = EvResponse(200, "x", {"content-length": 12}, 0.0, "u")
    d = detail_from_record(_rec(params={"a": 1}, response=resp))
    assert d.resp_headers == {"content-length": "12"} and d.params == {"a": "1"}


# ── curl fidelity ────────────────────────────────────────────────────────────

def test_curl_reassembles_query_onto_url():
    # regression: the executor strips the query off `url`, so a curl built from
    # `url` alone would omit the payload entirely and prove nothing.
    d = detail_from_record(_rec(params={"id": "1 OR 1=1"}), "id")
    curl = to_curl(d)
    assert "id=1+OR+1%3D1" in curl and curl.count("?") == 1


def test_curl_appends_query_with_ampersand_when_url_already_has_one():
    d = ReproDetail(method="GET", url="http://h/u?a=1", params={"b": "2"})
    assert "http://h/u?a=1&b=2" in to_curl(d)


def test_curl_single_quotes_are_shell_escaped():
    # an unescaped `'` in a payload would break the command and shell-inject
    d = ReproDetail(method="POST", url="http://h/u", body="o'brien")
    assert "'o'\\''brien'" in to_curl(d)


def test_curl_marks_dict_body_as_form_encoded():
    d = detail_from_record(_rec(method="POST", body={"branch": "x"},
                                content_type="application/x-www-form-urlencoded"))
    curl = to_curl(d)
    assert d.form_encoded is True
    assert "application/x-www-form-urlencoded" in curl and "branch=x" in curl


def test_curl_renders_json_body_for_a_json_endpoint():
    # a dict body on a JSON endpoint must replay as JSON, not form — else the
    # replayed request 422s where the live one succeeded.
    d = detail_from_record(_rec(method="POST", url="http://h/api/items",
                                body={"priority": "high"},
                                content_type="application/json"))
    curl = to_curl(d)
    assert d.form_encoded is False
    assert "Content-Type: application/json" in curl
    assert '"priority": "high"' in curl                  # JSON, not priority=high
    assert "priority=high" not in curl


def test_json_is_the_default_body_encoding():
    # RequestRecord.content_type defaults to application/json, so a body with no
    # explicit content_type replays as JSON (modern-API default).
    d = detail_from_record(_rec(method="POST", body={"a": "1"}))
    assert d.form_encoded is False and '"a": "1"' in to_curl(d)


def test_curl_does_not_override_an_explicit_content_type():
    d = detail_from_record(_rec(method="POST", body={"a": "1"},
                                sent_headers={"Content-Type": "application/json"}))
    assert to_curl(d).count("Content-Type") == 1


def test_curl_never_follows_redirects():
    # -L would chase the redirect and hide the Location header that IS the finding
    d = detail_from_record(_rec(response=EvResponse(302, "", {"Location": "http://evil"}, 0.0, "u")))
    assert " -L" not in to_curl(d)


# ── rendered block ───────────────────────────────────────────────────────────

def test_block_states_no_credentials_for_unauth_repro():
    out = "\n".join(render_block(detail_from_record(_rec(authed=False))))
    assert "NO credentials" in out and "Authorization: Bearer" not in out


def test_block_offers_a_credential_placeholder_for_authed_repro():
    out = "\n".join(render_block(detail_from_record(_rec(authed=True))))
    assert "not recorded" in out and "Authorization: Bearer" in out


def test_block_emits_parseable_curl_line_outside_the_details():
    lines = render_block(detail_from_record(_rec()))
    curl_at = next(i for i, ln in enumerate(lines) if ln.startswith("**Curl:**"))
    details_at = next(i for i, ln in enumerate(lines) if ln.startswith("<details"))
    # enrich.py skips <details> wholesale, so the curl must precede it to reach SARIF
    assert curl_at < details_at
    assert lines[-2] == "</details>"


def test_block_surfaces_the_best_effort_note():
    d = detail_from_record(_rec(), note="best-effort: agent-judged")
    assert "# best-effort: agent-judged" in "\n".join(render_block(d))


def test_to_line_matches_the_one_line_repro_format():
    d = detail_from_record(_rec(params={"id": "x"}), "id")
    assert to_line(d) == "GET http://h/user [id] (unauthenticated)"


# ── best-effort selection (agent-judged, no tell fired) ──────────────────────

def test_best_effort_prefers_a_payload_request_over_the_baseline():
    base = _rec(payload_label="__baseline__")
    payload = _rec(payload_label="sqli-1")
    assert best_effort_record([base, payload]) is payload


def test_best_effort_falls_back_to_the_baseline_when_only_it_landed():
    base = _rec(payload_label="__baseline__")
    dead = _rec(payload_label="p", response=EvResponse(None, "", {}, 0.0, "u", error="boom"))
    assert best_effort_record([base, dead]) is base


def test_best_effort_skips_not_reached_statuses():
    blocked = _rec(response=EvResponse(404, "", {}, 0.0, "u"))
    assert best_effort_record([blocked]) is None


def test_best_effort_on_empty_transcript():
    assert best_effort_record([]) is None


# ── the oracle attaches it on CONFIRMED ──────────────────────────────────────

def test_oracle_confirm_attaches_repro_detail():
    hit = _rec(params={"id": "1'"},
               response=EvResponse(200, "You have an error in your SQL syntax near", {}, 0.0, "u"))
    base = _rec(payload_label="__baseline__", params={"id": "1"})
    v = oracle.confirm([base, hit], subtype="sqli", markers=mint_markers(_F()), oob=None)
    assert v.status == "CONFIRMED"
    assert v.repro_detail is not None
    assert v.repro_detail.params == {"id": "1'"}
    assert v.repro == to_line(v.repro_detail)        # one-liner derives from the detail


def test_oracle_leaves_repro_detail_unset_when_not_confirmed():
    v = oracle.confirm([_rec(response=EvResponse(200, "nothing", {}, 0.0, "u"))],
                       subtype="sqli", markers=mint_markers(_F()), oob=None)
    assert v.status != "CONFIRMED" and v.repro_detail is None


def test_repro_detail_is_hidden_from_the_agent_prompt_schema():
    # the model must not be invited to fabricate an exchange that looks like evidence
    from vvaharness.exploit_verification.verify.model import Verdict
    schema = Verdict.schema_json_compact()
    assert "repro_detail" not in schema and "ReproDetail" not in schema


# ── credential redaction: a token must never reach the report ─────────────────
#
# The confirming exchange can carry a credential — EV_AUTH-injected, shipped in the
# collection, or a token the attacker agent found in the target's own code and sent as a
# payload against an endpoint that echoes it back in the body. The report renders the
# request+response, so it redacts at render time. ReproDetail itself stays raw (so
# `_matches_repro` can still pin the confirming record).

_JWT = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ0ZXN0LTEyMyJ9.c3ludGhldGljX3Rlc3Rfc2ln"


def test_report_curl_redacts_a_token_in_the_query_and_headers():
    d = ReproDetail(method="GET", url="http://t/api/session",
                    params={"SESSIONID": _JWT}, sent_headers={"Cookie": f"SESSIONID={_JWT}"})
    curl = to_curl(d)
    assert _JWT not in curl and "redacted" in curl.lower()


def test_report_response_block_redacts_the_token_body_and_cookie():
    d = ReproDetail(method="GET", url="http://t/api/session", resp_status=200,
                    resp_headers={"set-cookie": f"SESSIONID={_JWT}; HttpOnly"},
                    resp_body='{"name":"testuser","token":"' + _JWT + '"}', authed=True)
    block = "\n".join(render_block(d))
    assert _JWT not in block                       # token in the response body — redacted
    assert "redacted" in block.lower()


def test_repro_detail_is_left_raw_so_matching_still_works():
    # redaction is at render, not capture — the stored detail keeps the real values so a
    # replay bundle can still identify the confirming record by params/body.
    d = ReproDetail(method="GET", url="http://t/x", params={"SESSIONID": _JWT})
    assert d.params["SESSIONID"] == _JWT
