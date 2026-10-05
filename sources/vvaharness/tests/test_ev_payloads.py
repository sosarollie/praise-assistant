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

"""Payload templates + the per-finding attack-plan builder."""

from __future__ import annotations
import pytest
from vvaharness.exploit_verification.classify import ACTIVE_SUBTYPES, PASSIVE_SUBTYPES
from vvaharness.exploit_verification.payloads import (
    TemplateError,
    load_template,
)
from types import SimpleNamespace
from vvaharness.exploit_verification.collection.model import EndpointHint
from vvaharness.exploit_verification.mapping import EndpointMatch
from vvaharness.exploit_verification.payloads import build_attack_plan


# ════ templates / loader ════

def _write(tmp_path, subtype, text):
    (tmp_path / f"{subtype}.yaml").write_text(text, encoding="utf-8")
    return tmp_path


# ── packaged template (proves importlib.resources path + packaging) ───────────

def test_loads_packaged_sqli_template():
    t = load_template("sqli")
    assert t is not None and t.subtype == "sqli" and t.kind == "active"
    labels = {p.label for p in t.payloads}
    assert "boolean_true" in labels
    assert any(p.raw == "'" for p in t.payloads)


def test_missing_template_returns_none():
    assert load_template("nonexistent_subtype_xyz") is None


# ── every classify subtype ships a valid, loadable template (corpus) ──────────

@pytest.mark.parametrize("subtype", sorted(ACTIVE_SUBTYPES))
def test_every_active_subtype_has_valid_template(subtype):
    t = load_template(subtype)
    assert t is not None, f"no template shipped for ACTIVE subtype {subtype!r}"
    assert t.kind == "active" and len(t.payloads) >= 1


@pytest.mark.parametrize("subtype", sorted(PASSIVE_SUBTYPES))
def test_every_passive_subtype_has_valid_template(subtype):
    t = load_template(subtype)
    assert t is not None, f"no template shipped for PASSIVE subtype {subtype!r}"
    assert t.kind == "passive" and len(t.payloads) >= 1


# ── happy paths via a templates_dir override ─────────────────────────────────

def test_active_template_defaults(tmp_path):
    _write(tmp_path, "xss", """
subtype: xss
payloads:
  - label: reflect
    raw: "<b>{{XSS_MARKER}}</b>"
""")
    t = load_template("xss", templates_dir=tmp_path)
    assert t.kind == "active"                                  # default
    assert t.injection_points_default == ("query", "body")    # default
    p = t.payloads[0]
    assert p.destructive is False and p.identity == "primary"


def test_passive_template_with_headers(tmp_path):
    _write(tmp_path, "cors", """
subtype: cors
kind: passive
injection_points_default: [header]
payloads:
  - label: reflect_origin
    set_headers: {Origin: "https://evil.example"}
""")
    t = load_template("cors", templates_dir=tmp_path)
    assert t.kind == "passive"
    assert t.payloads[0].raw is None
    assert t.payloads[0].set_headers == {"Origin": "https://evil.example"}


def test_known_placeholders_accepted(tmp_path):
    _write(tmp_path, "ssrf", """
subtype: ssrf
payloads:
  - label: oob
    raw: "http://{{OOB_URL}}/{{NONCE}}"
    oob_required: true
""")
    t = load_template("ssrf", templates_dir=tmp_path)
    assert t.payloads[0].oob_required is True


# ── strict validation ─────────────────────────────────────────────────────────

def _bad(tmp_path, subtype, text):
    _write(tmp_path, subtype, text)
    with pytest.raises(TemplateError):
        load_template(subtype, templates_dir=tmp_path)


def test_subtype_must_match_filename(tmp_path):
    _bad(tmp_path, "sqli", "subtype: xss\npayloads: []\n")


def test_unknown_top_level_key_rejected(tmp_path):
    _bad(tmp_path, "sqli", "subtype: sqli\nbogus: 1\npayloads: []\n")


def test_unknown_payload_key_rejected(tmp_path):
    _bad(tmp_path, "sqli", "subtype: sqli\npayloads:\n  - label: a\n    raww: \"'\"\n")


def test_missing_label_rejected(tmp_path):
    _bad(tmp_path, "sqli", "subtype: sqli\npayloads:\n  - raw: \"'\"\n")


def test_duplicate_label_rejected(tmp_path):
    _bad(tmp_path, "sqli",
         "subtype: sqli\npayloads:\n  - label: a\n    raw: \"'\"\n  - label: a\n    raw: x\n")


def test_unknown_placeholder_rejected(tmp_path):
    _bad(tmp_path, "xss", "subtype: xss\npayloads:\n  - label: a\n    raw: \"{{XSS_MARKR}}\"\n")


def test_bad_kind_rejected(tmp_path):
    _bad(tmp_path, "sqli", "subtype: sqli\nkind: weird\npayloads: []\n")


def test_bad_identity_rejected(tmp_path):
    _bad(tmp_path, "sqli",
         "subtype: sqli\npayloads:\n  - label: a\n    raw: x\n    identity: admin\n")


def test_non_bool_flag_rejected(tmp_path):
    _bad(tmp_path, "sqli",
         "subtype: sqli\npayloads:\n  - label: a\n    raw: x\n    destructive: yes_please\n")


def test_bad_injection_location_rejected(tmp_path):
    _bad(tmp_path, "sqli", "subtype: sqli\ninjection_points_default: [cookie]\npayloads: []\n")


# ════ attack-plan builder ════

def _finding(**kw):
    base = dict(file="app.py", line_start=10, title="t", description="", cwe="", vuln_class="")
    base.update(kw)
    return SimpleNamespace(**base)


def _match(path="/user", method="GET", param="id", location="query",
           query=None, body=None, path_params=None, headers=None):
    ep = EndpointHint(method=method, path=path, query_params=query or {},
                      path_params=path_params or {}, body_template=body,
                      headers=headers or {})
    return EndpointMatch(endpoint=ep, method=method, param=param, location=location)


def _labels(plan):
    return [s.payload_label for s in plan.specs]


# ── baseline + placement ──────────────────────────────────────────────────────

def test_baseline_first_and_injects_at_pinned_param():
    m = _match(param="id", location="query", query={"id": "1"})
    plan = build_attack_plan(_finding(), "sqli", m)
    assert plan.specs[0].payload_label == "__baseline__"
    assert plan.specs[0].query == {"id": "1"}                 # benign
    injected = [s for s in plan.specs if s.payload_label != "__baseline__"]
    assert injected and all(s.injection_point == "query.id" for s in injected)
    assert any(s.query["id"] == "'" for s in injected)        # a payload landed at the param


def test_path_injection_replaces_segment():
    m = _match(path="/files/{file}", param="file", location="path")
    plan = build_attack_plan(_finding(), "path", m)
    injected = [s for s in plan.specs if s.payload_label != "__baseline__"]
    assert any("etc/passwd" in s.path and s.path.startswith("/files/") for s in injected)


def test_header_injection_places_payload_in_the_header():
    """A pinned header target must actually carry the payload — not the benign baseline
    value while still being labelled a header injection, which is a silent false negative.
    The endpoint's other declared headers must ride alongside it."""
    m = _match(path="/users", param="X-Request-Context", location="header",
               headers={"Accept": "application/json"})
    plan = build_attack_plan(_finding(), "sqli", m)
    injected = [s for s in plan.specs if s.payload_label != "__baseline__"]
    assert injected and all(s.injection_point == "header.X-Request-Context"
                            for s in injected)                      # labelled a header inj.
    assert any(s.headers.get("X-Request-Context") == "'" for s in injected)   # payload landed
    assert all(s.headers.get("Accept") == "application/json" for s in injected)


# ── markers filled; OOB left for the executor ─────────────────────────────────

def test_xss_marker_is_filled():
    m = _match(param="name", location="query", query={"name": "x"})
    plan = build_attack_plan(_finding(), "xss", m)
    vals = [s.query["name"] for s in plan.specs if s.payload_label != "__baseline__"]
    assert any(plan.markers.xss in v for v in vals)           # {{XSS_MARKER}} → minted marker
    assert all("{{XSS_MARKER}}" not in v for v in vals)


def test_oob_placeholder_left_intact_and_gated():
    m = _match(param="url", location="query", query={"url": "http://x"})
    off = build_attack_plan(_finding(), "ssrf", m, oob_available=False)
    assert "oob_http_callback" not in _labels(off)            # dropped when OOB unavailable
    on = build_attack_plan(_finding(), "ssrf", m, oob_available=True)
    oob = [s for s in on.specs if s.payload_label == "oob_http_callback"]
    assert oob and "{{OOB_URL}}" in oob[0].query["url"]       # builder leaves OOB for the executor


# ── gating: safe_mode drops destructive ───────────────────────────────────────

def test_safe_mode_drops_destructive():
    m = _match(param=None, location=None, body={})
    assert "python_pickle_reduce_gadget" not in _labels(
        build_attack_plan(_finding(), "deser", m, safe_mode=True))
    assert "python_pickle_reduce_gadget" in _labels(
        build_attack_plan(_finding(), "deser", m, safe_mode=False))


# ── whole-body (xxe/deser) ─────────────────────────────────────────────────────

def test_xxe_is_whole_body_document():
    m = _match(path="/parse", method="POST", param=None, location=None)
    plan = build_attack_plan(_finding(), "xxe", m)
    injected = [s for s in plan.specs if s.payload_label != "__baseline__"]
    assert injected
    s = injected[0]
    assert isinstance(s.body, str) and s.body.startswith("<?xml")   # whole body, not a field
    assert s.content_type == "application/xml"                      # template override


# ── no-raw payloads: authz identity swap + passive header shaping ─────────────

def test_authz_sends_identity_none_without_injection():
    m = _match(path="/admin", param=None, location=None)
    plan = build_attack_plan(_finding(), "authz", m)
    no_cred = [s for s in plan.specs if s.payload_label == "no_credentials"]
    assert no_cred and no_cred[0].identity == "none" and no_cred[0].injection_point == ""
    bad = [s for s in plan.specs if s.payload_label == "invalid_bearer_token"]
    assert bad and bad[0].headers.get("Authorization") == "Bearer invalid_token_12345"


def test_passive_cors_shapes_origin_header():
    m = _match(path="/api", param=None, location=None)
    plan = build_attack_plan(_finding(), "cors", m)
    reflect = [s for s in plan.specs if s.payload_label == "reflect_arbitrary_origin"]
    assert reflect and reflect[0].headers == {"Origin": "https://evil.example"}


# ── cap + no-template ─────────────────────────────────────────────────────────

def test_max_specs_caps_payloads():
    m = _match(param="id", location="query", query={"id": "1"})
    plan = build_attack_plan(_finding(), "sqli", m, max_specs=2)
    assert len(plan.specs) <= 3                               # 1 baseline + 2 payloads


def test_no_template_yields_empty_plan():
    plan = build_attack_plan(_finding(), "not_a_subtype", _match())
    assert plan.specs == [] and plan.markers is not None

# ── {{BASE}}: prepend the legitimate value where the payload needs it ─────────

def _sent(plan, label, param):
    s = next(s for s in plan.specs if s.payload_label == label)
    return s.query.get(param) if param in (s.query or {}) else None


def test_base_token_prepends_the_legitimate_query_value():
    # cmd separators keep the real host so the command stays well-formed:
    # `ping -c 1 127.0.0.1; id`, not the malformed `ping -c 1 ; id`.
    m = _match(path="/ping", param="host", location="query", query={"host": "127.0.0.1"})
    plan = build_attack_plan(_finding(), "cmd", m)
    assert _sent(plan, "semicolon_id", "host") == "127.0.0.1; id"
    assert _sent(plan, "dollar_paren_id", "host") == "127.0.0.1$(id)"


def test_base_token_collapses_to_empty_without_a_base_value():
    # no example value for the param → {{BASE}} → "" → the bare separator.
    m = _match(path="/ping", param="host", location="query", query={"host": ""})
    plan = build_attack_plan(_finding(), "cmd", m)
    assert _sent(plan, "semicolon_id", "host") == "; id"


def test_payloads_without_base_still_replace_the_value():
    # path traversal / SSRF must REPLACE, not keep the original — no {{BASE}}.
    m = _match(path="/read", param="path", location="query", query={"path": "readme.txt"})
    plan = build_attack_plan(_finding(), "path", m)
    sent = _sent(plan, next(s.payload_label for s in plan.specs
                            if s.payload_label != "__baseline__"), "path")
    assert "readme.txt" not in (sent or "")        # replaced, not appended


# ── the collection's declared headers reach the wire ──────────────────────────
#
# The reachability probe sends an endpoint's declared headers; the plan builder used to
# drop them (`headers={}`), so the probe and the verifier talked to the endpoint
# differently — a route that gates on a declared header looks reachable and then refuses
# to produce evidence. Credentials are the one thing NOT forwarded: a collection can
# hard-code an Authorization, and an identity="none" spec that inherited it would be
# recorded as unauthenticated while presenting a credential.

def test_declared_headers_reach_every_spec():
    m = _match(param="id", location="query", query={"id": "1"},
               headers={"Accept": "application/json", "X-Api-Version": "3"})
    plan = build_attack_plan(_finding(), "sqli", m)
    assert plan.specs, "expected a plan to compare against"
    for s in plan.specs:
        assert s.headers.get("Accept") == "application/json"
        assert s.headers.get("X-Api-Version") == "3"


@pytest.mark.parametrize("name", ["Authorization", "Cookie", "X-API-Key",
                                  "authorization", "PROXY-AUTHORIZATION"])
@pytest.mark.parametrize("subtype", ["sqli", "authz"])
def test_a_credential_declared_in_the_collection_is_never_forwarded(name, subtype):
    """The collection's credential VALUE must never ride on a spec.

    The header *name* can legitimately appear: authz's ``invalid_bearer_token`` control
    sets its own ``Authorization`` on purpose. What must not happen is the collection's
    hard-coded value being inherited — an ``identity="none"`` spec carrying it would be
    recorded as unauthenticated while presenting a real credential.
    """
    m = _match(param="id", location="query", query={"id": "1"},
               headers={name: "SECRET-FROM-COLLECTION", "Accept": "application/json"})
    plan = build_attack_plan(_finding(), subtype, m)
    assert plan.specs
    for s in plan.specs:
        assert "SECRET-FROM-COLLECTION" not in " ".join(map(str, s.headers.values()))
        assert s.headers.get("Accept") == "application/json"   # the rest still rides


@pytest.mark.parametrize("name", ["Authorization", "Cookie", "X-API-Key"])
def test_a_credential_name_is_dropped_when_no_template_sets_it(name):
    """With a template that sets no auth header of its own, the name disappears too."""
    m = _match(param="id", location="query", query={"id": "1"},
               headers={name: "SECRET-FROM-COLLECTION"})
    plan = build_attack_plan(_finding(), "sqli", m)
    assert plan.specs
    for s in plan.specs:
        assert not any(k.lower() == name.lower() for k in s.headers), s.headers


def test_a_payload_template_header_wins_over_the_collections():
    """A template's own value overrides a declared one; declared headers it does not
    name still ride alongside."""
    from vvaharness.exploit_verification.collection.model import EndpointHint
    from vvaharness.exploit_verification.payloads.builder import _endpoint_headers
    ep = EndpointHint(method="POST", path="/x",
                      headers={"Accept": "application/json", "X-Api-Version": "3"})
    merged = _endpoint_headers(ep, {"Accept": "text/html"})
    assert merged["Accept"] == "text/html"          # template wins on conflict
    assert merged["X-Api-Version"] == "3"           # the rest survives

    # end to end: authz's `invalid_bearer_token` control sets its own Authorization, and
    # the collection's Accept survives next to it
    m = _match(param="id", location="query", query={"id": "1"},
               headers={"Accept": "application/json"})
    plan = build_attack_plan(_finding(), "authz", m)
    tmpl = [s for s in plan.specs if s.headers.get("Authorization")]
    assert tmpl, "expected the invalid-credential control to set Authorization"
    assert tmpl[0].headers["Accept"] == "application/json"


# ── the endpoint's example body, whatever shape the collection gave it ────────

def test_a_json_array_example_body_reaches_the_spec():
    """Batch endpoints declare a top-level array. Narrowing this to dict silently sent
    NO body for exactly those endpoints."""
    m = _match(path="/batch", method="POST", param=None, location="body",
               body=[{"cve": "CVE-1"}, {"cve": "CVE-2"}])
    plan = build_attack_plan(_finding(), "sqli", m)
    assert plan.specs[0].payload_label == "__baseline__"
    assert plan.specs[0].body == [{"cve": "CVE-1"}, {"cve": "CVE-2"}]


def test_a_raw_string_example_body_reaches_the_spec():
    m = _match(path="/x", method="POST", param=None, location="body",
               body="<order><id>1</id></order>")
    plan = build_attack_plan(_finding(), "sqli", m)
    assert plan.specs[0].body == "<order><id>1</id></order>"


def test_a_dict_example_body_is_copied_not_shared():
    body = {"a": "1"}
    m = _match(path="/x", method="POST", param="a", location="body", body=body)
    plan = build_attack_plan(_finding(), "sqli", m)
    injected = [s for s in plan.specs if s.payload_label != "__baseline__"]
    assert injected and injected[0].body["a"] != "1"      # payload landed
    assert body == {"a": "1"}                             # caller's dict untouched
