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

"""Mapping findings to endpoints.

Part 1 is the endpoint->code index, Part 2 the finding->endpoint map, and both
share one read-only code agent.
"""

from __future__ import annotations
import json
import threading
from types import SimpleNamespace
import pytest
from vvaharness.backends.llm import registry as _llm
from vvaharness.exploit_verification.collection.model import EndpointHint, NormalizedCollection
from vvaharness.exploit_verification.mapping._agent import run_code_agent
from vvaharness.exploit_verification.mapping.endpoint_index import (
    EndpointCode,
    EndpointIndex,
    build_index,
)
from vvaharness.exploit_verification.mapping.finding_map import map_to_endpoints


# ════ Part 1: endpoint -> code index ════

def _col(*eps):
    return NormalizedCollection(endpoints=[EndpointHint(method=m, path=p) for m, p in eps])


def _ctx(entry_points=None, call_graph_files=None):
    return SimpleNamespace(entry_points=entry_points or [],
                           call_graph_files=call_graph_files or {})


@pytest.fixture
def repo(tmp_path):
    """A repo whose one file is long enough for the cited line ranges to be valid."""
    (tmp_path / "app.py").write_text("\n".join(f"# line {i}" for i in range(1, 200)))
    return str(tmp_path)


def _runner(records_by_path):
    """A scripted agent: returns the given records for whatever routes it is asked."""
    def run(routes, entry_hint, *, repo_root, model, max_turns):
        out = []
        for r in routes:
            rec = records_by_path.get(r["path"])
            if rec is not None:
                out.append({"method": r["method"], "path": r["path"], **rec})
        return json.dumps(out)
    return run


# ── happy path ────────────────────────────────────────────────────────────────

def test_located_endpoint_is_indexed_with_its_range(repo):
    idx = build_index(
        _col(("GET", "/transfer")), _ctx(), model="m", repo_root=repo,
        runner=_runner({"/transfer": {"found": True, "file": "app.py",
                                       "function": "transfer", "decl_line": 118,
                                       "body_start": 118, "body_end": 125,
                                       "evidence": "@app.route('/transfer')"}}))
    assert len(idx.located) == 1 and not idx.dropped
    e = idx.located[0]
    assert (e.method, e.path, e.function) == ("GET", "/transfer", "transfer")
    assert (e.body_start, e.body_end) == (118, 125)


# ── the drop rule ───────────────────────────────────────────────────────────────

def test_not_found_endpoint_is_dropped(repo):
    idx = build_index(
        _col(("GET", "/login")), _ctx(), model="m", repo_root=repo,
        runner=_runner({"/login": {"found": False, "evidence": "no route in repo"}}))
    assert not idx.located
    assert [e.path for e in idx.dropped] == ["/login"]


def test_a_route_the_agent_omits_is_dropped(repo):
    idx = build_index(_col(("GET", "/ghost")), _ctx(), model="m", repo_root=repo,
                      runner=_runner({}))          # agent returns nothing for it
    assert not idx.located and [e.path for e in idx.dropped] == ["/ghost"]


@pytest.mark.parametrize("bad", [
    {"found": True, "file": "app.py", "function": "", "body_start": 1, "body_end": 9},
    {"found": True, "file": "app.py", "function": "f", "body_start": 9, "body_end": 1},
    {"found": True, "file": "app.py", "function": "f", "body_start": 0, "body_end": 0},
    {"found": True, "file": "does_not_exist.py", "function": "f",
     "body_start": 1, "body_end": 9},
])
def test_a_bad_citation_is_dropped_not_indexed(repo, bad):
    idx = build_index(_col(("GET", "/x")), _ctx(), model="m", repo_root=repo,
                      runner=_runner({"/x": bad}))
    assert not idx.located and [e.path for e in idx.dropped] == ["/x"]


def test_an_absolute_or_escaping_path_is_rejected(repo):
    idx = build_index(_col(("GET", "/x")), _ctx(), model="m", repo_root=repo,
                      runner=_runner({"/x": {"found": True, "file": "/etc/passwd",
                                             "function": "f", "body_start": 1,
                                             "body_end": 9}}))
    assert not idx.located                          # jail rejects the absolute path


# ── unknown routes / dedup ────────────────────────────────────────────────────

def test_a_route_the_agent_invents_is_ignored(repo):
    def run(routes, entry_hint, *, repo_root, model, max_turns):
        return json.dumps([
            {"method": "GET", "path": "/x", "found": True, "file": "app.py",
             "function": "f", "decl_line": 5, "body_start": 5, "body_end": 9},
            {"method": "GET", "path": "/hallucinated", "found": True, "file": "app.py",
             "function": "ghost", "decl_line": 1, "body_start": 1, "body_end": 2}])
    idx = build_index(_col(("GET", "/x")), _ctx(), model="m", repo_root=repo, runner=run)
    assert [e.path for e in idx.located] == ["/x"]   # invented route not admitted


def test_duplicate_routes_are_deduped(repo):
    idx = build_index(
        _col(("GET", "/dup"), ("GET", "/dup")), _ctx(), model="m", repo_root=repo,
        runner=_runner({"/dup": {"found": True, "file": "app.py", "function": "d",
                                 "decl_line": 3, "body_start": 3, "body_end": 8}}))
    assert len(idx.located) == 1


# ── chunking ────────────────────────────────────────────────────────────────────

def test_routes_are_chunked_and_merged(repo):
    eps = [("GET", f"/r{i}") for i in range(25)]
    sizes = []

    def run(routes, entry_hint, *, repo_root, model, max_turns):
        sizes.append(len(routes))
        return json.dumps([{"method": r["method"], "path": r["path"], "found": True,
                            "file": "app.py", "function": f"h{r['path']}",
                            "decl_line": 2, "body_start": 2, "body_end": 4}
                           for r in routes])
    idx = build_index(_col(*eps), _ctx(), model="m", repo_root=repo, runner=run, chunk=10)
    # sorted(): the sessions run concurrently, so which one answers first is not
    # ours to predict. The sizes are the contract; their arrival order is not.
    assert sorted(sizes) == [5, 10, 10]
    assert len(idx.located) == 25


def test_the_index_is_ordered_by_chunk_not_by_who_finished_first(repo):
    """Concurrency must not reach the index: `located` — and so the per-endpoint log
    — is assembled in chunk order however the sessions interleave. The last chunk
    answers first here, which is exactly the case that would reorder a naive merge."""
    eps = [("GET", f"/r{i}") for i in range(25)]
    gate = threading.Event()

    def run(routes, entry_hint, *, repo_root, model, max_turns):
        if routes[0]["path"] == "/r0":
            gate.wait(timeout=10)              # first chunk finishes last
        else:
            gate.set()
        return json.dumps([{"method": r["method"], "path": r["path"], "found": True,
                            "file": "app.py", "function": f"h{r['path']}",
                            "decl_line": 2, "body_start": 2, "body_end": 4}
                           for r in routes])
    idx = build_index(_col(*eps), _ctx(), model="m", repo_root=repo, runner=run,
                      chunk=10, parallel=3)
    assert [e.path for e in idx.located] == [f"/r{i}" for i in range(25)]


def test_index_chunk_sessions_run_concurrently(repo):
    """The sessions are independent, so they overlap rather than going one round-trip
    at a time. A barrier is the deterministic proof: were this serial, the first
    session would block on siblings that have not been dispatched and it would break."""
    eps = [("GET", f"/r{i}") for i in range(25)]
    barrier = threading.Barrier(3, timeout=10)

    def run(routes, entry_hint, *, repo_root, model, max_turns):
        barrier.wait()                         # BrokenBarrierError unless parallel
        return json.dumps([{"method": r["method"], "path": r["path"], "found": True,
                            "file": "app.py", "function": "h", "decl_line": 2,
                            "body_start": 2, "body_end": 4} for r in routes])
    idx = build_index(_col(*eps), _ctx(), model="m", repo_root=repo, runner=run,
                      chunk=10, parallel=3)
    assert len(idx.located) == 25


def test_one_failing_chunk_drops_only_its_routes(repo):
    eps = [("GET", f"/r{i}") for i in range(20)]

    def run(routes, entry_hint, *, repo_root, model, max_turns):
        # Keyed off the chunk's CONTENT, not a call ordinal: the sessions run
        # concurrently, so "the first call" no longer picks out one chunk.
        if routes[0]["path"] == "/r0":
            raise RuntimeError("chunk failed")
        return json.dumps([{"method": r["method"], "path": r["path"], "found": True,
                            "file": "app.py", "function": "h", "decl_line": 2,
                            "body_start": 2, "body_end": 4} for r in routes])
    idx = build_index(_col(*eps), _ctx(), model="m", repo_root=repo, runner=run, chunk=10)
    assert len(idx.located) == 10 and len(idx.dropped) == 10   # chunk 2 survived
    assert [e.path for e in idx.dropped] == [f"/r{i}" for i in range(10)]


def test_an_unparseable_chunk_is_retried_then_drops(repo):
    calls = {"n": 0}

    def run(routes, entry_hint, *, repo_root, model, max_turns):
        calls["n"] += 1
        return "no json here"
    idx = build_index(_col(("GET", "/x")), _ctx(), model="m", repo_root=repo,
                      runner=run, attempts=3)
    assert calls["n"] == 3 and [e.path for e in idx.dropped] == ["/x"]


# ── degradation ──────────────────────────────────────────────────────────────

def test_no_repo_yields_an_empty_index_with_everything_dropped():
    called = []
    idx = build_index(_col(("GET", "/x")), _ctx(), model="m", repo_root=None,
                      runner=lambda *a, **k: called.append(1) or "[]")
    assert called == [] and not idx.located and len(idx.dropped) == 1


def test_no_model_yields_an_empty_index():
    idx = build_index(_col(("GET", "/x")), _ctx(), model="", repo_root="/tmp",
                      runner=lambda *a, **k: "[]")
    assert not idx.located and len(idx.dropped) == 1


def test_empty_collection_is_a_noop(repo):
    idx = build_index(_col(), _ctx(), model="m", repo_root=repo,
                      runner=lambda *a, **k: "[]")
    assert not idx.located and not idx.dropped


# ── the call-graph hint reaches the agent ────────────────────────────────────

def test_entry_points_are_passed_as_a_hint(repo):
    seen = {}

    def run(routes, entry_hint, *, repo_root, model, max_turns):
        seen["hint"] = entry_hint
        return json.dumps([{"method": r["method"], "path": r["path"], "found": False}
                           for r in routes])
    ctx = _ctx(entry_points=[SimpleNamespace(function="transfer", file="app.py",
                                             kind="network")],
               call_graph_files={"transfer": ["app.py:118"]})
    build_index(_col(("GET", "/transfer")), ctx, model="m", repo_root=repo, runner=run)
    assert seen["hint"] == [{"function": "transfer", "file": "app.py", "def_line": 118}]


# ════ Part 2: finding -> endpoint map ════

def _fm_col(*eps, reach=None):
    hints = [EndpointHint(method=m, path=p, query_params=(q or {})) for m, p, q in eps]
    return NormalizedCollection(endpoints=hints, reachability=reach or {})


def _idx(*located):
    ix = EndpointIndex()
    for m, p, fn, bs, be in located:
        ix.located.append(EndpointCode(method=m, path=p, found=True, file="app.py",
                                       function=fn, decl_line=bs - 1,
                                       body_start=bs, body_end=be))
    return ix


def _f(fid, file="app.py", line=None, sink="", subtype="sqli", title="", code=""):
    f = SimpleNamespace(file=file, line_start=line, line_end=line, sink_ref=sink,
                        source_ref=None, title=title, code_snippet=code)
    return (fid, f, subtype)


def _fm_runner(records):
    """Scripted agent: returns the given per-finding records regardless of input."""
    def run(index_payload, findings_payload, *, repo_root, model, max_turns):
        ids = {p["id"] for p in findings_payload}
        return json.dumps([r for r in records if r["id"] in ids])
    return run


_COMMON = dict(repo_root="/repo", model="m")


# ── happy path ────────────────────────────────────────────────────────────────

def test_maps_a_finding_to_a_located_endpoint_with_param():
    col = _fm_col(("GET", "/user", {"id": "1"}))
    idx = _idx(("GET", "/user", "get_user", 51, 57))
    out = map_to_endpoints(
        [_f("F1", line=53, subtype="sqli")], idx, col, None,
        runner=_fm_runner([{"id": "F1", "mapped": True, "endpoints": [
            {"method": "GET", "path": "/user", "param": "id", "location": "query",
             "confidence": "high", "reason": "line 53 inside get_user [51-57]"}]}]),
        **_COMMON)
    assert "F1" in out and len(out["F1"]) == 1
    m = out["F1"][0]
    assert m.method == "GET" and m.endpoint.path == "/user"
    assert m.param == "id" and m.location == "query"
    assert m.signals == ["agent_map"] and m.confidence == "high"


def test_agentic_finding_maps_without_a_param():
    col = _fm_col(("GET", "/apply-coupon", None))
    idx = _idx(("GET", "/apply-coupon", "apply_coupon", 107, 115))
    out = map_to_endpoints(
        [_f("R1", line=110, subtype=None)], idx, col, None,      # agentic
        runner=_fm_runner([{"id": "R1", "mapped": True, "endpoints": [
            {"method": "GET", "path": "/apply-coupon", "param": None,
             "location": None, "confidence": "medium"}]}]),
        **_COMMON)
    assert out["R1"][0].param is None


# ── ranking / cap ─────────────────────────────────────────────────────────────

def test_ranked_endpoints_are_kept_in_order_and_capped_at_five():
    col = _fm_col(*[("GET", f"/e{i}", None) for i in range(7)])
    idx = _idx(*[("GET", f"/e{i}", f"h{i}", 10 + i, 12 + i) for i in range(7)])
    eps = [{"method": "GET", "path": f"/e{i}", "confidence": "low"} for i in range(7)]
    out = map_to_endpoints(
        [_f("F", line=10, subtype="sqli")], idx, col, None,
        runner=_fm_runner([{"id": "F", "mapped": True, "endpoints": eps}]), **_COMMON)
    paths = [m.endpoint.path for m in out["F"]]
    assert paths == ["/e0", "/e1", "/e2", "/e3", "/e4"]         # first 5, in order
    assert out["F"][0].score > out["F"][-1].score               # descending rank


# ── guardrails ────────────────────────────────────────────────────────────────

def test_an_endpoint_not_in_the_index_is_rejected():
    col = _fm_col(("GET", "/real", None), ("GET", "/dropped", None))
    idx = _idx(("GET", "/real", "real", 5, 9))                   # /dropped NOT located
    out = map_to_endpoints(
        [_f("F", line=6)], idx, col, None,
        runner=_fm_runner([{"id": "F", "mapped": True, "endpoints": [
            {"method": "GET", "path": "/dropped"},              # rejected
            {"method": "GET", "path": "/real"}]}]),
        **_COMMON)
    assert [m.endpoint.path for m in out["F"]] == ["/real"]


def test_an_invented_route_is_rejected():
    col = _fm_col(("GET", "/real", None))
    idx = _idx(("GET", "/real", "real", 5, 9))
    out = map_to_endpoints(
        [_f("F", line=6)], idx, col, None,
        runner=_fm_runner([{"id": "F", "mapped": True, "endpoints": [
            {"method": "GET", "path": "/hallucinated"}]}]),
        **_COMMON)
    assert out.get("F", []) == []                               # nothing valid -> static


def test_mapped_false_goes_to_static():
    col = _fm_col(("GET", "/user", None))
    idx = _idx(("GET", "/user", "get_user", 51, 57))
    out = map_to_endpoints(
        [_f("F", line=999)], idx, col, None,
        runner=_fm_runner([{"id": "F", "mapped": False}]), **_COMMON)
    assert "F" not in out


def test_reachability_is_carried_onto_the_match():
    col = _fm_col(("GET", "/user", None), reach={"/user": "exists"})
    idx = _idx(("GET", "/user", "get_user", 51, 57))
    out = map_to_endpoints(
        [_f("F", line=53)], idx, col, None,
        runner=_fm_runner([{"id": "F", "mapped": True, "endpoints": [
            {"method": "GET", "path": "/user"}]}]), **_COMMON)
    assert out["F"][0].reachable == "exists"


# ── chunking / failure ────────────────────────────────────────────────────────

def test_findings_are_chunked():
    col = _fm_col(("GET", "/u", None))
    idx = _idx(("GET", "/u", "u", 1, 9))
    sizes = []

    def run(index_payload, findings_payload, *, repo_root, model, max_turns):
        sizes.append(len(findings_payload))
        return json.dumps([{"id": p["id"], "mapped": True, "endpoints": [
            {"method": "GET", "path": "/u"}]} for p in findings_payload])
    cands = [_f(f"F{i}", line=2) for i in range(13)]
    out = map_to_endpoints(cands, idx, col, None, runner=run, chunk=5, **_COMMON)
    # sorted(): the sessions run concurrently, so which one answers first is not ours
    # to predict. The sizes are the contract; their arrival order is not.
    assert sorted(sizes) == [3, 5, 5] and len(out) == 13


def test_answers_are_zipped_back_onto_their_own_chunk():
    """Concurrency must not cross the chunks: each session's answers are matched to
    the findings that session was asked about. The last chunk answers first here,
    which is exactly the case a completion-order merge would mis-pair — and since
    every chunk maps to the same route, a mis-pair shows up as findings lost."""
    col = _fm_col(("GET", "/u", None))
    idx = _idx(("GET", "/u", "u", 1, 9))
    gate = threading.Event()

    def run(index_payload, findings_payload, *, repo_root, model, max_turns):
        if findings_payload[0]["id"] == "F0":
            gate.wait(timeout=10)                   # first chunk finishes last
        else:
            gate.set()
        return json.dumps([{"id": p["id"], "mapped": True, "endpoints": [
            {"method": "GET", "path": "/u"}]} for p in findings_payload])
    cands = [_f(f"F{i}", line=2) for i in range(15)]
    out = map_to_endpoints(cands, idx, col, None, runner=run, chunk=5, parallel=3,
                           **_COMMON)
    assert list(out) == [f"F{i}" for i in range(15)]


def test_map_chunk_sessions_run_concurrently():
    """The sessions are independent, so they overlap rather than going one round-trip
    at a time. A barrier is the deterministic proof: were this serial, the first
    session would block on siblings that have not been dispatched and it would break."""
    col = _fm_col(("GET", "/u", None))
    idx = _idx(("GET", "/u", "u", 1, 9))
    barrier = threading.Barrier(3, timeout=10)

    def run(index_payload, findings_payload, *, repo_root, model, max_turns):
        barrier.wait()                              # BrokenBarrierError unless parallel
        return json.dumps([{"id": p["id"], "mapped": True, "endpoints": [
            {"method": "GET", "path": "/u"}]} for p in findings_payload])
    cands = [_f(f"F{i}", line=2) for i in range(15)]
    out = map_to_endpoints(cands, idx, col, None, runner=run, chunk=5, parallel=3,
                           **_COMMON)
    assert len(out) == 15


def test_one_failing_chunk_sends_only_its_findings_to_static():
    col = _fm_col(("GET", "/u", None))
    idx = _idx(("GET", "/u", "u", 1, 9))

    def run(index_payload, findings_payload, *, repo_root, model, max_turns):
        # Keyed off the chunk's CONTENT, not a call ordinal: the sessions run
        # concurrently, so "the first call" no longer picks out one chunk.
        if findings_payload[0]["id"] == "F0":
            raise RuntimeError("agent error")
        return json.dumps([{"id": p["id"], "mapped": True, "endpoints": [
            {"method": "GET", "path": "/u"}]} for p in findings_payload])
    cands = [_f(f"F{i}", line=2) for i in range(10)]
    out = map_to_endpoints(cands, idx, col, None, runner=run, chunk=5, **_COMMON)
    assert len(out) == 5                                        # only the 2nd chunk mapped
    assert list(out) == [f"F{i}" for i in range(5, 10)]          # and it was chunk 2's


def test_unparseable_chunk_is_retried_then_all_go_to_static():
    col = _fm_col(("GET", "/u", None))
    idx = _idx(("GET", "/u", "u", 1, 9))
    calls = {"n": 0}

    def run(index_payload, findings_payload, *, repo_root, model, max_turns):
        calls["n"] += 1
        return "not json"
    out = map_to_endpoints([_f("F", line=2)], idx, col, None, runner=run,
                           attempts=3, **_COMMON)
    assert calls["n"] == 3 and out == {}


# ── degradation ──────────────────────────────────────────────────────────────

def test_empty_index_maps_nothing():
    called = []
    out = map_to_endpoints([_f("F", line=2)], EndpointIndex(), _fm_col(("GET", "/u", None)),
                           None, runner=lambda *a, **k: called.append(1) or "[]",
                           **_COMMON)
    assert called == [] and out == {}


def test_no_model_maps_nothing():
    idx = _idx(("GET", "/u", "u", 1, 9))
    out = map_to_endpoints([_f("F", line=2)], idx, _fm_col(("GET", "/u", None)), None,
                           repo_root="/repo", model="",
                           runner=lambda *a, **k: "[]")
    assert out == {}


def test_no_candidates_is_a_noop():
    idx = _idx(("GET", "/u", "u", 1, 9))
    out = map_to_endpoints([], idx, _fm_col(("GET", "/u", None)), None,
                           runner=lambda *a, **k: "[]", **_COMMON)
    assert out == {}


# ════ shared code agent ════

def _capture(monkeypatch):
    seen = {}

    def fake_agentic(user_prompt, *, model, **kw):
        seen["user"] = user_prompt
        seen["model"] = model
        seen.update(kw)
        return '[{"ok": true}]'
    monkeypatch.setattr(_llm, "agentic", fake_agentic)
    return seen


def test_run_code_agent_delegates_to_agentic(monkeypatch):
    seen = _capture(monkeypatch)
    out = run_code_agent("SYSTEM", "USER", repo_root="/repo/root",
                         model="claude-sonnet-4-6", max_turns=20, tag="s6-ev x")
    # returns whatever the shared loop returns — the caller parses this
    assert out == '[{"ok": true}]'
    # prompt + system are threaded through verbatim
    assert seen["user"] == "USER"
    assert seen["system_prompt"] == "SYSTEM"
    # jailed to the repo, bounded by the caller's turn budget, attributed by tag
    assert seen["cwd"] == "/repo/root"
    assert seen["max_turns"] == 20
    assert seen["tag"] == "s6-ev x"


def test_run_code_agent_offers_only_read_only_tools(monkeypatch):
    seen = _capture(monkeypatch)
    run_code_agent("s", "u", repo_root="/r", model="m", max_turns=5)
    # never Edit/Write/Bash — mapping only reads code
    assert list(seen["allowed_tools"]) == ["Read", "Glob", "Grep"]


@pytest.mark.parametrize("via", ["cli", "sdk", "openai"])
def test_run_code_agent_honours_the_roles_backend(monkeypatch, via):
    """The mapper's own ``via`` must survive to ``agentic``.

    This agent only reads code — no live target, no caller-supplied tool — so nothing
    here justifies pinning a provider. Pinning an sdk spec would override whatever
    backend the role names, making the mapper unusable on a login-only or OpenAI
    deployment. Verified through the real resolver rather than by inspecting the node's
    shape.
    """
    seen = _capture(monkeypatch)
    node = SimpleNamespace(id="claude-sonnet-4-6", via=via)
    run_code_agent("s", "u", repo_root="/r", model=node, max_turns=5)
    assert _llm.resolve(seen["model"])[:2] == ("claude-sonnet-4-6", via)


def test_run_code_agent_passes_a_bare_id_through_unchanged(monkeypatch):
    """A bare string still resolves the way the shared dispatcher reads one (via:cli),
    rather than being rewritten to something the caller did not ask for."""
    seen = _capture(monkeypatch)
    run_code_agent("s", "u", repo_root="/r", model="claude-sonnet-4-6", max_turns=5)
    assert _llm.resolve(seen["model"])[:2] == ("claude-sonnet-4-6", "cli")


def test_tag_defaults_when_caller_omits_it(monkeypatch):
    seen = _capture(monkeypatch)
    run_code_agent("s", "u", repo_root="/r", model="m", max_turns=5)
    assert seen["tag"] == "s6-ev map"


# ── call-graph context in the mapping prompts (mirrors the static verifier) ────
#
# finding→endpoint now carries a per-finding `call_graph` block (network entries that
# reach the sink + local callers/callees); endpoint→code's entry hint carries each
# handler's callees. Prompt context only — no extra model calls. Helpers are reused from
# callgraph_consumer / _bridge, monkeypatched here so the tests stay hermetic.

from vvaharness.exploit_verification.mapping import finding_map as FM      # noqa: E402
from vvaharness.exploit_verification.mapping import endpoint_index as EI   # noqa: E402


def test_finding_graph_ctx_builds_the_block(monkeypatch):
    monkeypatch.setattr(FM, "network_entries_for_sink", lambda sf, sl, ctx: {"checkout", "login"})
    monkeypatch.setattr(FM, "qnodes_at", lambda view, f, ls, le, **k: ["pkg.svc.query"])
    monkeypatch.setattr(FM, "neighborhood",
                        lambda view, qns, **k: {"pkg.svc.query": {"callers": ["h"], "callees": ["db"]}})
    f = SimpleNamespace(file="svc.py", line_start=10, line_end=12, sink_ref="svc.py:11", source_ref=None)
    block = FM._finding_graph_ctx(f, ctx=object(), view=object())
    assert block["reaches_network_entries"] == ["checkout", "login"]        # sorted, capped
    assert block["around"]["pkg.svc.query"]["callees"] == ["db"]


def test_finding_graph_ctx_is_none_when_graph_is_empty(monkeypatch):
    monkeypatch.setattr(FM, "network_entries_for_sink", lambda *a, **k: set())
    monkeypatch.setattr(FM, "qnodes_at", lambda *a, **k: [])
    monkeypatch.setattr(FM, "neighborhood", lambda *a, **k: {})
    f = SimpleNamespace(file="x.py", line_start=1, line_end=1, sink_ref="", source_ref=None)
    assert FM._finding_graph_ctx(f, object(), object()) is None
    assert FM._finding_graph_ctx(f, object(), None) is None                 # no view → none


def test_finding_payload_carries_call_graph_only_when_present():
    f = SimpleNamespace(file="a.py", line_start=1, line_end=1, sink_ref="", source_ref=None,
                        title="t", code_snippet="c")
    assert "call_graph" not in FM._finding_payload("F1", f, "sqli")
    p = FM._finding_payload("F1", f, "sqli", graph_ctx={"reaches_network_entries": ["h"], "around": {}})
    assert p["call_graph"]["reaches_network_entries"] == ["h"]


def test_finding_payload_carries_narrative_hints_capped():
    f = SimpleNamespace(file="a.py", line_start=1, line_end=1, sink_ref="", source_ref=None,
                        title="t", code_snippet="c",
                        impact="reads another account's records",
                        description="x" * 5000,           # over the cap
                        exploit_scenario="POST /invoice/{id} with a crafted id")
    p = FM._finding_payload("F1", f, "sqli")
    assert p["impact"] == "reads another account's records"
    assert p["exploit_scenario"] == "POST /invoice/{id} with a crafted id"
    assert len(p["description"]) == FM._TEXT_CAP        # truncated to the cap


def test_finding_payload_omits_empty_narrative_hints():
    f = SimpleNamespace(file="a.py", line_start=1, line_end=1, sink_ref="", source_ref=None,
                        title="t", code_snippet="c",
                        impact="", description="", exploit_scenario="")
    p = FM._finding_payload("F1", f, "sqli")
    assert "impact" not in p and "description" not in p and "exploit_scenario" not in p


def test_map_to_endpoints_feeds_call_graph_to_the_agent(monkeypatch):
    monkeypatch.setattr(FM, "graph_view", lambda ctx: object())             # non-None view
    monkeypatch.setattr(FM, "network_entries_for_sink", lambda sf, sl, ctx: {"get_user"})
    monkeypatch.setattr(FM, "qnodes_at", lambda *a, **k: ["m.get_user"])
    monkeypatch.setattr(FM, "neighborhood", lambda *a, **k: {"m.get_user": {"callers": [], "callees": ["q"]}})
    seen = {}
    def run(index_payload, findings_payload, *, repo_root, model, max_turns):
        seen["p"] = findings_payload
        return json.dumps([{"id": "F1", "mapped": False, "endpoints": []}])
    col = _fm_col(("GET", "/user", {"id": "1"}))
    idx = _idx(("GET", "/user", "get_user", 51, 57))
    ctx = SimpleNamespace(call_graph={"m.get_user": ["q"]})
    map_to_endpoints([_f("F1", line=53)], idx, col, ctx, runner=run, **_COMMON)
    assert seen["p"][0]["call_graph"]["reaches_network_entries"] == ["get_user"]


def test_map_to_endpoints_omits_call_graph_without_a_graph():
    seen = {}
    def run(index_payload, findings_payload, *, repo_root, model, max_turns):
        seen["p"] = findings_payload
        return json.dumps([{"id": "F1", "mapped": False, "endpoints": []}])
    col = _fm_col(("GET", "/user", {"id": "1"}))
    idx = _idx(("GET", "/user", "get_user", 51, 57))
    map_to_endpoints([_f("F1", line=53)], idx, col, None, runner=run, **_COMMON)   # ctx=None
    assert "call_graph" not in seen["p"][0]


def test_entry_hint_includes_callees_when_the_graph_has_them(monkeypatch):
    monkeypatch.setattr(EI, "graph_view", lambda ctx: object())
    monkeypatch.setattr(EI, "qnodes_at", lambda view, f, a, b, **k: ["m.h"])
    monkeypatch.setattr(EI, "neighborhood",
                        lambda view, qns, **k: {"m.h": {"callers": [], "callees": ["render", "query"]}})
    ep = SimpleNamespace(kind="network", function="h", file="app.py")
    ctx = SimpleNamespace(entry_points=[ep], call_graph_files={"h": ["app.py:20"]},
                          call_graph={"m.h": ["render"]})
    hints = EI._entry_hint(ctx)
    assert hints[0]["def_line"] == 20 and hints[0]["calls"] == ["query", "render"]


def test_entry_hint_has_no_calls_without_a_graph():
    ep = SimpleNamespace(kind="network", function="h", file="app.py")
    ctx = SimpleNamespace(entry_points=[ep], call_graph_files={"h": ["app.py:20"]})  # no call_graph
    hints = EI._entry_hint(ctx)
    assert hints[0]["def_line"] == 20 and "calls" not in hints[0]


# ── sink-ref parsing feeds the call-graph bridge ───────────────────────────────
#
# extract_hints parses the sink `file:line` that seeds network_entries_for_sink. A ranged
# tail (`file:71-74`) is not a bare int, so the line is dropped — but the file path must
# stay intact, because the bridge compares the sink file exactly.

from vvaharness.exploit_verification.mapping._bridge import network_entries_for_sink  # noqa: E402
from vvaharness.exploit_verification.mapping._signals import extract_hints            # noqa: E402


def test_range_tail_sink_ref_keeps_the_file_path_for_the_exact_compare():
    """Keeping the whole 'svc.py:71-74' ref as the path breaks the bridge's exact file
    compare, so the enclosing function is never found and the call-graph hint comes back
    empty — an advisory prompt block silently goes missing."""
    f = SimpleNamespace(file="", sink_ref="svc.py:71-74", source_ref=None)
    h = extract_hints(f)
    assert (h.sink_file, h.sink_line) == ("svc.py", 0)      # file kept, garbage line dropped
    ctx = _ctx(entry_points=[SimpleNamespace(function="handler", file="svc.py",
                                             kind="network")],
               call_graph_files={"handler": ["svc.py:60"]})
    # the kept path matches the exact compare; the corrupt ref matched nothing
    assert network_entries_for_sink(h.sink_file, h.sink_line, ctx) == {"handler"}
