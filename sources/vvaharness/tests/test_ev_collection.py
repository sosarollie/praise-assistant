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

"""Collection ingest (Postman / OpenAPI parsing), the run's collection checkpoint,
plus Exploit Verification survival through S7 dedup.

Offline: ``VVAHARNESS_STATE_DIR`` points at a tmp dir so the checkpoint tests never
touch the operator's real state DB.
"""

from __future__ import annotations
import json
import time
from types import SimpleNamespace
import pytest

from vvaharness.exploit_verification.errors import EVInputError
from vvaharness.exploit_verification.collection import _formats, parsers
from vvaharness.models import ContextPackage, Finding, VulnClass
from vvaharness.orchestrator import scan, store
from vvaharness.orchestrator.checkpoints import (EV_COLLECTION_STEP, load_ckpt,
                                                 run_id_for, save_ckpt)
from vvaharness.pipeline.stages import s7_dedup
from test_ev_config import ev_config


# ════ parsers ════

def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_postman_parse_folders_auth_body_and_path_params(tmp_path):
    pm = {
        "info": {"name": "x"},
        "auth": {"type": "bearer"},
        "item": [{"name": "folder", "item": [
            {"name": "get", "request": {"method": "GET", "url": "{{base}}/api/users/123"}},
            {"name": "post", "request": {"method": "POST", "url": "/api/login",
                                         "body": {"mode": "raw", "raw": '{"u": "a"}'}}},
        ]}],
    }
    col = parsers.parse(_write(tmp_path, "pm.json", pm))
    assert col.source_format == "postman"
    assert col.auth.type == "bearer"
    by_path = {e.path: e for e in col.endpoints}
    # hard-coded id segment is parameterized with the value kept as a seed
    assert "/api/users/{usersId}" in by_path
    assert by_path["/api/users/{usersId}"].path_params == {"usersId": "123"}
    assert by_path["/api/login"].body_template == {"u": "a"}


# ── raw bodies: parse what is sendable, refuse to invent the rest ────────────
#
# An unparsed body used to be sent as `{"_raw": "<the text>"}`. That is worse than
# sending nothing: the server rejects it, and the rejection becomes the baseline every
# differential on the endpoint is then measured against.

def _pm_raw(raw, language=None):
    body = {"mode": "raw", "raw": raw}
    if language:
        body["options"] = {"raw": {"language": language}}
    return {"info": {"name": "x"}, "item": [
        {"name": "p", "request": {"method": "POST", "url": "/api/x", "body": body}}]}


def _only(tmp_path, pm, name="pm.json"):
    return parsers.parse(_write(tmp_path, name, pm)).endpoints[0]


def test_a_json_array_body_is_a_valid_body(tmp_path):
    """Batch and bulk endpoints take a top-level array. Requiring a dict sent
    `{"_raw": "[…]"}` instead, so those endpoints could never be tested."""
    ep = _only(tmp_path, _pm_raw('[{"a": 1}, {"a": 2}]'))
    assert ep.body_template == [{"a": 1}, {"a": 2}]
    assert ep.content_type == "application/json"
    assert ep.body_unparsed == ""


@pytest.mark.parametrize("raw", ['42', '"hello"', 'true', 'null'])
def test_a_bare_scalar_raw_body_is_sendable_not_unparsed(tmp_path, raw):
    """A bare JSON scalar is still a sendable body. Dropping it also reported the
    reason as "not valid JSON", which was false — it parses fine, it just isn't a
    dict or a list."""
    ep = _only(tmp_path, _pm_raw(raw))
    assert ep.body_template == raw                  # the verbatim text, sent as JSON
    assert ep.content_type == "application/json"
    assert ep.body_unparsed == ""                   # never blamed on unparseable JSON


@pytest.mark.parametrize("raw", [
    '// the old payload\n{"a": 1}',
    '/* block */ {"a": 1}',
    '// one\n// two\n{"a": 1}\n',
])
def test_json_with_comments_parses(tmp_path, raw):
    """Postman edits raw bodies in a JSON editor that tolerates comments, so exported
    collections routinely carry a commented-out example above the live payload."""
    assert _only(tmp_path, _pm_raw(raw)).body_template == {"a": 1}


def test_a_non_json_raw_body_keeps_its_declared_content_type(tmp_path):
    ep = _only(tmp_path, _pm_raw("<order><id>1</id></order>", language="xml"))
    assert ep.body_template == "<order><id>1</id></order>"
    assert ep.content_type == "application/xml"
    assert ep.body_unparsed == ""


def test_an_unresolvable_body_is_marked_not_fabricated(tmp_path):
    ep = _only(tmp_path, _pm_raw("this is not json"))
    assert ep.body_template is None                  # NOT {"_raw": …}
    assert "not valid JSON" in ep.body_unparsed


def test_an_unresolved_variable_is_named_in_the_reason(tmp_path):
    ep = _only(tmp_path, _pm_raw('{"id": {{ORDER_ID}}}'))
    assert ep.body_template is None
    assert "{{ORDER_ID}}" in ep.body_unparsed


def test_openapi_parse_paths_params_refs_and_base_prefix(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com/v1"}],
        "components": {
            "securitySchemes": {"b": {"type": "http", "scheme": "bearer"}},
            "schemas": {"User": {"properties": {"name": {"type": "string"}}}},
        },
        "paths": {
            "/users/{id}": {"get": {
                "parameters": [{"name": "id", "in": "path", "example": "42"}],
                "security": [{"b": []}]}},
            "/users": {"post": {"requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/User"}}}}}},
        },
    }
    col = parsers.parse(_write(tmp_path, "oa.json", spec))
    assert col.source_format == "openapi"
    assert col.auth.type == "bearer"
    paths = {(e.method, e.path) for e in col.endpoints}
    assert ("GET", "/v1/users/{id}") in paths          # servers[0] path prefix applied
    assert ("POST", "/v1/users") in paths
    post = next(e for e in col.endpoints if e.method == "POST")
    assert post.body_template == {"name": "FUZZ"}       # $ref resolved to a body example


def test_an_openapi_top_level_array_body_yields_a_one_element_list(tmp_path):
    """A requestBody whose schema is a top-level array (batch/bulk create) used to fall
    through to no body at all, so the endpoint went out bodyless. The array now wraps the
    item example the same way a plain object body resolves."""
    spec = {
        "openapi": "3.0.0",
        "components": {"schemas": {"User": {"properties": {"name": {"type": "string"}}}}},
        "paths": {
            "/users": {"post": {"requestBody": {"content": {"application/json": {
                "schema": {"type": "array",
                           "items": {"$ref": "#/components/schemas/User"}}}}}}},
        },
    }
    col = parsers.parse(_write(tmp_path, "oa.json", spec))
    post = next(e for e in col.endpoints if e.method == "POST")
    assert post.body_template == [{"name": "FUZZ"}]     # the array wraps the item, not None


# ── expansion bounds: a `$ref` reused across siblings must not re-expand ──────
#
# A schema graph is a DAG, not a tree. The cycle guard tracks only the refs on the
# current PATH — which is what stops `A -> B -> A` — so a `$ref` reused across sibling
# properties was rebuilt once per sibling: two siblings per level doubled the built body
# per level of nesting, and a spec of a few dozen tiny schemas exhausted the host before
# the parse returned. These pin the two ceilings that bound it.

def _nodes(obj) -> int:
    """Nodes in a built body example — what the node ceiling is expressed in."""
    if isinstance(obj, dict):
        return 1 + sum(_nodes(v) for v in obj.values())
    if isinstance(obj, list):
        return 1 + sum(_nodes(v) for v in obj)
    return 1


def _body_of(tmp_path, schema, extra=None):
    """The body template a POST requestBody with ``schema`` parses to."""
    spec = {"openapi": "3.0.0",
            "paths": {"/x": {"post": {"requestBody": {"content": {
                "application/json": {"schema": schema}}}}}}}
    spec.update(extra or {})
    return parsers.parse(_write(tmp_path, "oa.json", spec)).endpoints[0].body_template


def _sibling_ref_spec(depth, siblings=2):
    """``L0`` -> ``siblings`` properties each ``$ref``-ing ``L1`` -> … -> a scalar leaf.

    One schema per level, so the spec is tiny on disk — and ``siblings ** depth`` nodes
    if a reused ``$ref`` re-expands per sibling.
    """
    schemas = {f"L{d}": {"type": "object",
                         "properties": {f"s{i}": {"$ref": f"#/components/schemas/L{d + 1}"}
                                        for i in range(siblings)}}
               for d in range(depth)}
    schemas[f"L{depth}"] = {"type": "object", "properties": {"leaf": {"type": "string"}}}
    return schemas


def test_a_ref_reused_across_siblings_stays_bounded(tmp_path):
    """40 levels of two-sibling reuse is 2**40 nodes if each sibling re-expands, from a
    spec of 41 one-line schemas. It must come back bounded instead of consuming the host.
    """
    body = _body_of(tmp_path, {"$ref": "#/components/schemas/L0"},
                    {"components": {"schemas": _sibling_ref_spec(40)}})
    assert _nodes(body) <= _formats._MAX_EXAMPLE_NODES + 1
    # Still a usable template rather than nothing. The ceiling is spent depth-first, so
    # the first branch expands and the trailing siblings collapse — which is why it sits
    # far above any legitimate spec: only a pathological one is shaped by it at all.
    assert isinstance(body, dict) and set(body) <= {"s0", "s1"}


def test_a_deep_chain_of_objects_stops_at_the_depth_ceiling(tmp_path):
    """A chain of single-property objects never trips the node ceiling — it is linear —
    so the depth ceiling is what bounds it, and it must stop rather than recurse until
    Python's own stack gives out."""
    schema = {"type": "object", "properties": {"leaf": {"type": "string"}}}
    for _ in range(300):
        schema = {"type": "object", "properties": {"n": schema}}
    body = _body_of(tmp_path, schema)
    depth, cur = 0, body
    while isinstance(cur, dict) and cur:
        cur, depth = cur.get("n"), depth + 1
    assert depth <= _formats._MAX_EXAMPLE_DEPTH + 2


def test_a_shared_ref_still_expands_under_every_sibling(tmp_path):
    """The control: bounding expansion must not change what an ordinary spec produces.
    One schema reused by two properties is still rendered in full under both."""
    body = _body_of(
        tmp_path,
        {"type": "object", "properties": {"billing": {"$ref": "#/components/schemas/Addr"},
                                          "shipping": {"$ref": "#/components/schemas/Addr"}}},
        {"components": {"schemas": {
            "Addr": {"type": "object", "properties": {"city": {"type": "string"}}}}}})
    assert body == {"billing": {"city": "FUZZ"}, "shipping": {"city": "FUZZ"}}


def test_a_recursive_ref_still_terminates(tmp_path):
    """The path-based cycle guard is what makes a self-referential schema terminate, and
    it must keep doing so — the ceilings are a backstop for reuse, not a replacement."""
    body = _body_of(
        tmp_path, {"$ref": "#/components/schemas/Node"},
        {"components": {"schemas": {"Node": {
            "type": "object", "properties": {"name": {"type": "string"},
                                             "next": {"$ref": "#/components/schemas/Node"}}}}}})
    assert body["name"] == "FUZZ"
    assert body["next"] == {}              # the cycle collapses rather than recursing


def _allof_ref_spec(depth):
    """``A1 = allOf[$ref A2, $ref A2]`` … down to a bare object.

    The same reuse as :func:`_sibling_ref_spec`, expressed through ``allOf`` instead of
    ``properties`` — and therefore filling no property slot on the way down.
    """
    schemas = {f"A{i}": {"allOf": [{"$ref": f"#/components/schemas/A{i + 1}"},
                                   {"$ref": f"#/components/schemas/A{i + 1}"}]}
               for i in range(1, depth)}
    schemas[f"A{depth}"] = {"type": "object"}
    return schemas


def test_allof_recursion_is_charged_against_the_budget():
    """Every recursive branch must spend budget, not only one that fills a property slot.

    This is the precise form of the defect: an ``allOf`` chain fills no slot, so the budget
    stayed at zero however deep it went and the head-of-call ceiling never engaged. Asserted
    on the budget rather than the clock so it is exact and instant in both directions.
    """
    spec = {"components": {"schemas": _allof_ref_spec(20)}}
    budget = _formats._new_budget()
    _formats._extract_body_example({"$ref": "#/components/schemas/A1"}, spec,
                                   _budget=budget)
    assert budget["total"] >= _formats._MAX_EXAMPLE_NODES, (
        f"allOf expansion spent only {budget['total']} nodes — it is not being charged, "
        f"so neither ceiling can bind it")


def test_a_ref_reused_across_allof_siblings_stays_bounded(tmp_path):
    """The same reuse as the ``properties`` case, and it must be bounded the same way.

    Depth 22 is ~4.2M expansions unbounded (seconds, doubling with every level added) and
    flat once the ceiling binds. The threshold sits well above the bounded cost and well
    below the unbounded one, so this reports rather than hanging when it regresses.
    """
    start = time.monotonic()
    body = _body_of(tmp_path, {"$ref": "#/components/schemas/A1"},
                    {"components": {"schemas": _allof_ref_spec(22)}})
    elapsed = time.monotonic() - start
    assert elapsed < 2.0, f"allOf expansion took {elapsed:.1f}s — the ceiling is not binding"
    assert body is None or _nodes(body) <= _formats._MAX_EXAMPLE_NODES + 1


def test_the_node_ceiling_is_not_per_operation(tmp_path):
    """A per-body ceiling still multiplies by the operation count.

    Each extra operation costs a spec author a few bytes and bought another full body
    allowance, so a small spec could still expand to hundreds of megabytes of templates —
    all of it retained on the collection and written to the checkpoint.
    """
    spec = {"openapi": "3.0.0",
            "components": {"schemas": _sibling_ref_spec(30)},
            "paths": {f"/r{i}": {"post": {"requestBody": {"content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/L0"}}}}}}
                for i in range(200)}}
    endpoints = parsers.parse(_write(tmp_path, "oa.json", spec)).endpoints
    assert len(endpoints) == 200                       # every operation still parsed
    total = sum(_nodes(e.body_template) for e in endpoints if e.body_template)
    assert total <= _formats._MAX_TOTAL_EXAMPLE_NODES + 200


def test_an_authored_example_is_not_shared_between_slots(tmp_path):
    """Two slots reaching one ``$ref`` must get independent objects.

    The payload builder overwrites a slot in place to plant an injection. Handing back the
    spec's own dict made that write land in every sibling sharing the ref — and in the
    parsed spec — so a payload aimed at one parameter silently appeared in another and the
    transcript misattributed which one was injected.
    """
    body = _body_of(
        tmp_path,
        {"type": "object", "properties": {"a": {"$ref": "#/components/schemas/P"},
                                          "b": {"$ref": "#/components/schemas/P"}}},
        {"components": {"schemas": {"P": {"type": "object", "example": {"k": "v"}}}}})
    assert body == {"a": {"k": "v"}, "b": {"k": "v"}}
    body["a"]["k"] = "PAYLOAD"
    assert body["b"] == {"k": "v"}, "writing one slot changed its sibling"


def test_openapi_security_controls_auth_required(tmp_path):
    # An explicit `security: []` opts the operation out of auth; a non-empty list
    # requires it; an absent key inherits the spec-level default.
    spec = {
        "openapi": "3.0.0",
        "security": [{"g": []}],                          # global default: auth required
        "paths": {
            "/public":   {"get": {"security": []}},        # explicit opt-out
            "/private":  {"get": {"security": [{"b": []}]}},  # explicit requirement
            "/inherits": {"get": {}},                      # no key → inherits global
        },
    }
    col = parsers.parse(_write(tmp_path, "oa.json", spec))
    by_path = {e.path: e for e in col.endpoints}
    assert by_path["/public"].auth_required is False       # `security: []` = no auth
    assert by_path["/private"].auth_required is True
    assert by_path["/inherits"].auth_required is True       # inherits the global requirement


def test_openapi_auth_required_defaults_true_when_unspecified(tmp_path):
    # No security anywhere → unspecified → treated conservatively as auth-required.
    spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {}}}}
    col = parsers.parse(_write(tmp_path, "oa.json", spec))
    assert col.endpoints[0].auth_required is True


def test_credential_headers_are_stripped(tmp_path):
    pm = {"info": {"name": "x"}, "item": [
        {"name": "g", "request": {"method": "GET", "url": "/a",
                                  "header": [{"key": "Authorization", "value": "Bearer secret"},
                                             {"key": "Accept", "value": "application/json"}]}}]}
    col = parsers.parse(_write(tmp_path, "pm.json", pm))
    hdrs = col.endpoints[0].headers
    assert "Authorization" not in hdrs      # credential header never persisted
    assert hdrs.get("Accept") == "application/json"


def test_credential_query_params_are_stripped(tmp_path):
    """A secret resolved into the query string is the same credential vector in another
    position, so it must not reach the persisted collection either. A body credential is
    different and is deliberately kept: nothing re-injects one at request time, so
    dropping it would send a request that cannot authenticate."""
    pm = {"info": {"name": "x"}, "item": [
        {"name": "p", "request": {"method": "POST", "url": "/login?apikey=s3cr3t&limit=10",
                                  "body": {"mode": "raw", "raw": '{"password": "x"}'}}}]}
    ep = parsers.parse(_write(tmp_path, "pm.json", pm)).endpoints[0]
    assert "apikey" not in ep.query_params          # credential query param not persisted
    assert ep.query_params.get("limit") == "10"     # a plain param survives the filter
    assert ep.body_template == {"password": "x"}    # body credential retained by design


def test_unknown_format_raises(tmp_path):
    p = _write(tmp_path, "junk.json", {"not": "a collection"})
    with pytest.raises(parsers.UndetectedCollectionFormat):
        parsers.parse(p)


# ════ the run's collection checkpoint ════
#
# The collection is checkpointed so a --resume run re-enables EV without the
# operator re-supplying EV_API_COLLECTION. Resolution lives in
# ``scan._ev_collection_in``; it returns ``(collection, resumed)``.

@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    d = tmp_path / "state"
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(d))
    return d


def _col(tmp_path, path="/api/thing", name="pm.json"):
    pm = {"info": {"name": "x"}, "auth": {"type": "bearer"}, "item": [
        {"name": "g", "request": {"method": "GET", "url": path}}]}
    return parsers.parse(_write(tmp_path, name, pm))


def _repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir(exist_ok=True)
    return r


def _args(resume=False, stop_after=None):
    """What argv still supplies; the collection comes from EV_API_COLLECTION."""
    return SimpleNamespace(resume=resume, stop_after=stop_after)


def _set_collection(monkeypatch, path="pm.json"):
    """Configure the run's input. Setting EV_API_COLLECTION is what says "this run has a
    collection" — conftest hides every EV_* variable, so a test must opt in."""
    monkeypatch.setenv("EV_API_COLLECTION", path)


def _cfg_ev(enabled="auto"):
    """A config EV can actually verify with.

    The model roles are part of that: a run that enables EV must configure at least a
    `judge` and a `classify`, or `_ev_prep` refuses rather than let a scan finish with no
    verification and no explanation. `via: cli` needs only the `claude` binary, which
    these tests never invoke — the probe and the model calls are stubbed.
    """
    return ev_config({
        "models": {"exploit_verification": {
            "judge":    {"id": "claude-sonnet-4-6", "via": "cli"},
            "classify": {"id": "claude-sonnet-4-6", "via": "cli"},
        }},
    }, enabled=enabled)


def _stub_probe(monkeypatch):
    """Stand in for the ONLINE stages — these tests are about persistence, not HTTP.

    The fake probe annotates ``reachability`` exactly where a live one would, so a
    test can tell whether what got stored was the parsed input or the probed result.
    """
    def _fake_probe(col, opts, *a, **kw):
        col.reachability = {"/api/thing": "exists"}
        return col
    monkeypatch.setattr("vvaharness.exploit_verification.probe.run_probe", _fake_probe)
    monkeypatch.setattr(scan, "_ev_oob_selftest", lambda opts: None)


def test_collection_round_trips_through_the_checkpoint_store(tmp_path, state_dir):
    col = _col(tmp_path)
    save_ckpt(state_dir, "run1", EV_COLLECTION_STEP, col)
    back = load_ckpt(state_dir, "run1", EV_COLLECTION_STEP)
    assert [e.path for e in back.endpoints] == [e.path for e in col.endpoints]
    assert (back.source_format, back.auth.type) == ("postman", "bearer")


def test_resume_without_a_path_reuses_the_checkpointed_collection(tmp_path, state_dir):
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    save_ckpt(state_dir, run_id, EV_COLLECTION_STEP, _col(tmp_path))
    col, resumed = scan._ev_collection_in(repo, _args(resume=True), state_dir, run_id)
    assert resumed is True
    assert [e.path for e in col.endpoints] == ["/api/thing"]


def test_a_fresh_run_without_a_path_never_picks_up_the_checkpoint(tmp_path, state_dir):
    # EV sends live payloads, so only an explicit --resume may re-enable it from
    # stored state — a plain scan that never mentioned EV must stay SAST-only.
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    save_ckpt(state_dir, run_id, EV_COLLECTION_STEP, _col(tmp_path))
    assert scan._ev_collection_in(repo, _args(), state_dir, run_id) == (None, False)


def test_resume_with_no_checkpointed_collection_leaves_ev_off(tmp_path, state_dir):
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    assert scan._ev_collection_in(repo, _args(resume=True), state_dir, run_id) == (None, False)


def test_a_supplied_path_wins_over_the_checkpoint(tmp_path, state_dir, monkeypatch):
    # The gate handed over the freshly-parsed collection in memory; it is used, and
    # `resumed` is False so the caller overwrites the stale checkpoint row.
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    save_ckpt(state_dir, run_id, EV_COLLECTION_STEP,
              _col(tmp_path, path="/stale", name="old.json"))
    fresh = _col(tmp_path, path="/fresh")

    _set_collection(monkeypatch)
    col, resumed = scan._ev_collection_in(repo, _args(resume=True),
                                         state_dir, run_id, fresh)
    assert resumed is False
    assert [e.path for e in col.endpoints] == ["/fresh"]


def test_a_path_with_no_handed_over_collection_skips_ev(tmp_path, state_dir, monkeypatch):
    # EV_API_COLLECTION was set but nothing was parsed and handed in (a direct
    # scan_repo call that skipped the gate). Nothing to verify against → EV off.
    _set_collection(monkeypatch)
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    assert scan._ev_collection_in(repo, _args(),
                                  state_dir, run_id, None) == (None, False)


def test_a_fresh_scan_reset_drops_the_collection_row(tmp_path, state_dir):
    # reset_run() is what makes "fresh scan" mean an empty slate — the collection is
    # an input row, but it is not exempt, which is why the test above holds.
    save_ckpt(state_dir, "run1", EV_COLLECTION_STEP, _col(tmp_path))
    store.reset_run("run1")
    assert load_ckpt(state_dir, "run1", EV_COLLECTION_STEP) is None


def test_a_corrupt_checkpoint_row_leaves_ev_off(tmp_path, state_dir):
    # A row written by an incompatible version — or tampered with — fails the
    # validate-on-load gate, so EV degrades to off instead of failing the scan.
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    save_ckpt(state_dir, run_id, EV_COLLECTION_STEP, _col(tmp_path))
    con = store.connect()
    with con:
        con.execute("UPDATE checkpoints SET payload = ? WHERE run_id = ? AND step = ?",
                    (b'{"endpoints": "not-a-list"}', run_id, EV_COLLECTION_STEP))
    con.close()
    assert scan._ev_collection_in(repo, _args(resume=True),
                                  state_dir, run_id) == (None, False)


def test_stop_after_ev_on_a_resume_with_no_row_says_why(tmp_path, state_dir, capsys):
    # Without this the combination is a silent no-op: the run stops before S1 having
    # printed nothing at all.
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    scan._ev_collection_in(repo, _args(resume=True, stop_after="ev"), state_dir, run_id)
    assert "EV_API_COLLECTION" in capsys.readouterr().err

    # ...while an ordinary SAST-only resume stays quiet about EV entirely.
    scan._ev_collection_in(repo, _args(resume=True), state_dir, run_id)
    assert capsys.readouterr().err == ""


# ── the write side: scan._ev_prep, with the online stages stubbed ─────────────

def test_a_supplied_collection_is_checkpointed_for_a_later_resume(tmp_path, state_dir,
                                                                 monkeypatch):
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    _stub_probe(monkeypatch)

    # The gate hands the parsed collection over in memory; _ev_prep persists it.
    _set_collection(monkeypatch)
    out = scan._ev_prep(repo, _args(), _cfg_ev(),
                        ckpt_dir=state_dir, run_id=run_id, collection_in=_col(tmp_path))
    assert out is not None                          # EV ran for this scan
    stored = load_ckpt(state_dir, run_id, EV_COLLECTION_STEP)
    assert [e.path for e in stored.endpoints] == ["/api/thing"]
    # the parsed INPUT is what persists — reachability belongs to one deployment, and
    # the resumed run re-probes, so the probe's annotation must not be in the row
    assert stored.reachability == {}


# ── --stop-after ev must not destroy a prior run's checkpoints ────────────────
#
# `--stop-after ev` is a PREFLIGHT: it parses and probes the collection, then returns
# before S1. A fresh (non-`--resume`) scan clears the run's checkpoint rows so a later
# `--resume` cannot load state this scan never reached — correct for a real scan, but
# wrong here: it clears a completed run's s1..s9 checkpoints just to preflight one
# collection, and does so even when the probe then fails, leaving the state cleared with
# nothing gained.

class _StopHere(Exception):
    """Sentinel: abort scan_repo right after the reset decision, so these tests
    isolate that decision without running any pipeline stage."""


def _seed_checkpoints(run_id, *steps):
    con = store.connect()
    try:
        with con:
            con.execute("INSERT OR REPLACE INTO runs(run_id, repo_root) VALUES (?, '')",
                        (run_id,))
            for step in steps:
                blob = b"{}"
                con.execute("INSERT OR REPLACE INTO checkpoints(run_id, step, payload, size)"
                            " VALUES (?, ?, ?, ?)", (run_id, step, blob, len(blob)))
    finally:
        con.close()


def _steps(run_id):
    con = store.connect()
    try:
        return sorted(r[0] for r in con.execute(
            "SELECT step FROM checkpoints WHERE run_id = ?", (run_id,)))
    finally:
        con.close()


def _scan_to_the_reset(tmp_path, monkeypatch, stop_after):
    """Run scan_repo far enough to make the reset decision, then abort."""
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    _seed_checkpoints(run_id, "s1", "s2", "s3", "s4", "s7", "s8", "s9")
    monkeypatch.setattr(scan, "_ev_prep",
                        lambda *a, **kw: (_ for _ in ()).throw(_StopHere()))
    args = SimpleNamespace(resume=False, stop_after=stop_after, auto_step1=False)
    with pytest.raises(_StopHere):
        scan.scan_repo(repo, "repo", None, args, _cfg_ev())
    return run_id


def test_stop_after_ev_keeps_a_prior_runs_checkpoints(tmp_path, state_dir, monkeypatch):
    run_id = _scan_to_the_reset(tmp_path, monkeypatch, stop_after="ev")
    assert _steps(run_id) == ["s1", "s2", "s3", "s4", "s7", "s8", "s9"]


def test_a_normal_fresh_scan_still_resets(tmp_path, state_dir, monkeypatch):
    """The other half: the reset is right for a scan that actually runs stages, so the
    exemption above must be narrow rather than a blanket disable."""
    run_id = _scan_to_the_reset(tmp_path, monkeypatch, stop_after=None)
    assert _steps(run_id) == []


def test_stop_after_ev_returns_a_scanoutcome_not_a_bare_tuple(tmp_path, state_dir,
                                                              monkeypatch):
    """`--stop-after ev` returns before S1, but it still returns a ScanOutcome:
    entry.main reads `.exit_code` off it, so a bare `(None, 0)` tuple crashed the whole
    command with AttributeError right after a clean preflight. Let _ev_prep return
    (no stages run) and assert the type the caller depends on."""
    repo = _repo(tmp_path)
    monkeypatch.setattr(scan, "_ev_prep", lambda *a, **kw: None)
    args = SimpleNamespace(resume=False, stop_after="ev", auto_step1=False)
    out = scan.scan_repo(repo, "repo", None, args, _cfg_ev())
    assert isinstance(out, scan.ScanOutcome)
    assert out.exit_code == 0


def test_ev_switched_off_in_the_profile_resolves_nothing(tmp_path, state_dir, monkeypatch):
    # `enabled: false` must short-circuit before any collection is looked for: that
    # search reads from disk and logs, neither of which a disabled stage should do.
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    _stub_probe(monkeypatch)
    monkeypatch.setattr(scan, "_ev_collection_in",
                        lambda *a, **kw: pytest.fail("looked for a collection with EV off"))

    _set_collection(monkeypatch)
    assert scan._ev_prep(repo, _args(), _cfg_ev("false"),
                         ckpt_dir=state_dir, run_id=run_id,
                         collection_in=_col(tmp_path)) is None
    assert load_ckpt(state_dir, run_id, EV_COLLECTION_STEP) is None      # nothing written


# ════ dedup survival ════

def _f(line_start, **kw):
    base = dict(chunk_id="c", file="app.py", line_start=line_start, line_end=line_start + 1,
                vuln_class=VulnClass.INJECTION, cwe="CWE-89", title="SQLi", description="d",
                code_snippet="x", confidence=1.0)
    base.update(kw)
    return Finding(**base)


def _cfg():
    return SimpleNamespace(step7_dedup=SimpleNamespace(line_tolerance=10, semantic=False))


def test_ev_confirmed_survives_dedup_over_plain_duplicate():
    confirmed = _f(10, ev_status="CONFIRMED", ev_evidence="SQL error",
                   ev_method="deterministic", ev_confidence="high",
                   verdict="TRUE_POSITIVE", verdict_confidence=10)
    plain = _f(12)                        # same file/vuln_class, within tolerance → duplicate
    # `ctx` is a required precondition of the stage (it roots the semantic pass's
    # filesystem and feeds root-cause grouping); `semantic=False` above keeps this on the
    # deterministic path, so a bare repo_root is all it needs.
    canonical, dropped = s7_dedup.run([confirmed, plain], _cfg(),
                                      ctx=ContextPackage(repo_root="/tmp/repo",
                                                         language="python"))
    assert len(canonical) == 1 and len(dropped) == 1
    assert canonical[0].ev_status == "CONFIRMED"        # the verified one survives
    assert canonical[0].ev_method == "deterministic"


# ── the two gaps the startup preflight cannot close ───────────────────────────
#
# `orchestrator.entry` decides both questions before a collection exists: it accepts a
# --resume for `enabled: true` (the collection may be checkpointed) and it leaves EV's
# models out of the credential check on a bare --resume (there may be no collection).
# `_ev_prep` is the first place that KNOWS, so both are settled here.

def _cfg_models(judge="cli", classify="cli", attacker=None, enabled="auto"):
    ev = {}
    if judge:
        ev["judge"] = {"id": "claude-sonnet-4-6", "via": judge}
    if classify:
        ev["classify"] = {"id": "claude-sonnet-4-6", "via": classify}
    if attacker:
        ev["attacker"] = {"id": "claude-sonnet-4-6", "via": attacker}
    return ev_config({"models": {"exploit_verification": ev}}, enabled=enabled)


def test_required_with_an_empty_checkpoint_fails_instead_of_skipping(tmp_path, state_dir,
                                                                    monkeypatch):
    """`enabled: true` + --resume + nothing checkpointed. The startup check waved this
    through because a resume MIGHT carry a collection; here we know it does not. Skipping
    silently would spend the scan and return a report with no Exploit Verification stamps —
    which a reader cannot tell apart from "EV ran and confirmed nothing"."""
    repo = _repo(tmp_path)
    _stub_probe(monkeypatch)
    with pytest.raises(EVInputError) as exc:
        scan._ev_prep(repo, _args(resume=True), _cfg_models(enabled="true"),
                      ckpt_dir=state_dir, run_id=run_id_for(repo))
    assert "requires a collection" in str(exc.value)
    assert "enabled: auto" in str(exc.value)            # names the way out


def test_optional_with_an_empty_checkpoint_stays_quiet(tmp_path, state_dir, monkeypatch):
    """The other half: `auto` asked for nothing, so nothing is owed. No raise, EV off."""
    repo = _repo(tmp_path)
    _stub_probe(monkeypatch)
    assert scan._ev_prep(repo, _args(resume=True), _cfg_models(enabled="auto"),
                         ckpt_dir=state_dir, run_id=run_id_for(repo)) is None


def test_a_resumed_run_still_checks_its_models(tmp_path, state_dir, monkeypatch):
    """A resumed collection reaches S6 without ever passing the startup credential check,
    so the models are verified here. An `attacker` declared on a backend it cannot use is
    a misconfiguration, and this is where it surfaces."""
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    save_ckpt(state_dir, run_id, EV_COLLECTION_STEP, _col(tmp_path))   # a prior run's
    _stub_probe(monkeypatch)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")

    with pytest.raises(EVInputError) as exc:
        scan._ev_prep(repo, _args(resume=True), _cfg_models(attacker="cli"),
                      ckpt_dir=state_dir, run_id=run_id)
    assert "must be via:sdk" in str(exc.value)


def test_a_resumed_run_with_usable_models_proceeds(tmp_path, state_dir, monkeypatch):
    """The control for the test above — the check must not block a sound configuration.

    A resumed run re-runs the offline gate (the CLI gate had no path to work on), so the
    target env has to be present here as it would be for any real EV run.
    """
    repo = _repo(tmp_path)
    run_id = run_id_for(repo)
    save_ckpt(state_dir, run_id, EV_COLLECTION_STEP, _col(tmp_path))
    _stub_probe(monkeypatch)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    monkeypatch.setenv("EV_TARGET_URL", "http://127.0.0.1:5000")
    # The fixture collection declares bearer auth, so the gate wants a token. Pinned
    # rather than inherited: EV_AUTH_* comes from the ambient environment, so a
    # developer's own .env would otherwise decide this test.
    monkeypatch.setenv("EV_AUTH_STRATEGY", "bearer")
    monkeypatch.setenv("EV_AUTH_TOKEN", "t")

    out = scan._ev_prep(repo, _args(resume=True), _cfg_models(),
                        ckpt_dir=state_dir, run_id=run_id)
    assert out is not None                              # EV ran off the checkpoint
