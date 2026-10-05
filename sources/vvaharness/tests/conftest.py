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

"""Shared fixtures for the vvaharness test suite.

Isolates the process-global singletons that several modules expose, so the
full suite is order-independent no matter which files run together:
  - util.errlog._path  — the structured error-log sink, redirected to a
    per-test temp file so log() never appends to a real on-disk log.
  - util.tokens.TOKENS — the process-wide token counter, reset (including its
    `_phase`, which TOKENS.reset() does not clear) before and after each test.
  - util.stage_telemetry.STAGES — the process-wide per-stage recorder, reset
    before and after each test for the same reason.
  - util.response_quality._consecutive — the per-tag consecutive-short-response
    counter behind the degenerate-response guard, reset for the same reason.

  - os.environ EV_* — the developer's real .env must never reach a test (see
    _no_ambient_ev_config below).

Per-backend singletons (sdk/oai/claude_cli `._cfg`, `_client`, drift sets) are
intentionally NOT reset here — each lives in exactly one test module and is
reset locally, so hoisting them would needlessly couple unrelated backends and
force every test module to import all three SDKs.

Also provides, for tests that need a real pipeline stage to run without a
network connection or a live model:
  - `_deny_network`   — AUTOUSE. Every test in this suite is expected to be
    offline and deterministic; this makes a stray non-local socket connection
    fail loudly instead of hanging or silently succeeding against a live
    endpoint.
  - `stub_prompt`      — OPT-IN. Deterministic, offline replacement for
    `vvaharness.backends.llm.registry.prompt`, scoped to the stages that call it
    directly. See tests/fixtures/prompt_stub.py for the full contract.
  - `repo_nested_manifests`, `repo_extensionless` — checked-in file trees
    under tests/fixtures/; each fixture returns the Path to its root.
    READ-ONLY: tests must not mutate these in place (copy to tmp_path first if
    a test needs to write).
  - `repo_deep`, `repo_symlink_escape` — generated fresh under `tmp_path`
    (too many files / an outside-repo symlink to commit). See
    tests/fixtures/repo_builders.py for why.
  - `ctx_framework_eps`, `ctx_taint_multi`, `ctx_frontier_ne_full` —
    in-memory `ContextPackage` builders. See tests/fixtures/ctx_builders.py.
"""
from pathlib import Path
import ipaddress
import os

import pytest

from fixtures import ctx_builders, repo_builders
from fixtures.prompt_stub import PromptStub

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _restore_environ():
    """Snapshot and restore ``os.environ`` around every test.

    Two distinct leaks made this necessary, and both were silent:

    * Anything that reaches ``cli.main()`` runs ``_load_dotenv()``, which loads
      the developer's real ``.env`` into the process. Every later test that
      branches on whether a credential is merely PRESENT then sees a machine it
      was never written for — a readiness check that must report a missing key
      instead reported it satisfied. It also pulled real credentials into the
      test process, where a failure diff could surface them.
    * ``configure()`` on the backends writes ``NO_PROXY``/``no_proxy`` directly.
      A test that only calls ``monkeypatch.delenv(..., raising=False)`` first
      registers nothing to undo when the name was absent, so the write escaped.

    Restoring the mapping wholesale fixes both classes at once and any future
    one, rather than asking each test to remember. ``os.environ`` is mutated in
    place (not rebound) so ``putenv`` stays consistent for child processes.
    """
    import os
    saved = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


@pytest.fixture(autouse=True)
def _isolate_errlog_path(tmp_path, monkeypatch):
    from vvaharness.util import errlog
    monkeypatch.setattr(errlog, "_path", tmp_path / "errors.jsonl")


@pytest.fixture(autouse=True)
def _no_ambient_ev_config(monkeypatch):
    """Hide every ``EV_*`` variable from the test process.

    Exploit verification reads its target and credentials from the environment
    (``options.load_options(..., os.environ)``), so ambient config silently turns
    "hermetic" tests into live ones. That was not hypothetical: ``cli.main()``
    loads the developer's real ``.env`` (``cli.py:415``), and once ``test_cli.py``
    had run, ``EV_TARGET_URL`` was set for every later test — which flipped
    ``resolve_oob`` to *enabled* and made the s6 router tests bind a real
    listener on port 9090. They passed only because the port happened to be free,
    and failed the moment a real scan held it. For a target outside loopback that
    listener binds ``0.0.0.0`` (``executor/oob.py:243``).

    ``test_cli.py`` also stubs ``dotenv`` so the load cannot happen at all; this
    is the belt to that braces, and covers any future path that leaks EV config.
    A test that wants EV config sets it with ``monkeypatch.setenv`` in its body,
    which runs after this fixture.
    """
    for key in [k for k in os.environ if k.startswith("EV_")]:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _reset_token_counter():
    from vvaharness.util.tokens import TOKENS, DEFAULT_PHASE
    TOKENS.reset()
    TOKENS._phase = DEFAULT_PHASE
    yield
    TOKENS.reset()
    TOKENS._phase = DEFAULT_PHASE


@pytest.fixture(autouse=True)
def _reset_stage_counters():
    """Reset the process-wide stage counters around every test.

    Sits here beside the token and stage-telemetry resets for the same reason:
    it is a process-global that outlives a test. Several test files already
    carry their own local reset, which is why no ordering bug is visible today —
    but a future test that READS a counter without one would become silently
    order-dependent, passing alone and failing after a file that bumps.

    reset_all(), not reset(): a plain reset() RETIRES counts into the
    never-cleared cumulative maps, so snapshot_cumulative() and the
    count/note exclusivity guards would still see every earlier test.
    """
    from vvaharness.util.counters import COUNTERS
    COUNTERS.reset_all()
    yield
    COUNTERS.reset_all()


@pytest.fixture(autouse=True)
def _reset_case_rollup():
    """Reset the invocation-wide remediation/validation rollup around every test.

    Same class of process-global as the counters above: ``case_rollup.record`` folds
    each repo's tally into a module-level accumulator that outlives the test which
    filled it, so a test that reads ``totals()`` without a reset would become silently
    order-dependent — passing alone and failing after a file that records.
    """
    from vvaharness.orchestrator import case_rollup
    case_rollup.reset()
    yield
    case_rollup.reset()


@pytest.fixture(autouse=True)
def _reset_ev_known_secrets():
    """Clear exploit verification's known-credential set around every test.

    Same class of process-global as the counters above: ``auth.build_headers`` registers
    whatever credential it injects so the redactor can mask it wherever it comes back, and
    that set outlives the test that filled it. Nothing is visibly broken today, but a test
    that asserts on a literal another test happened to register as a credential would be
    masked into a mismatch — passing alone and failing after its neighbour.
    """
    from vvaharness.exploit_verification import safety
    safety._KNOWN_SECRETS.clear()
    yield
    safety._KNOWN_SECRETS.clear()


@pytest.fixture(autouse=True)
def _reset_ev_host_resolution_cache():
    """Clear the localhost-only check's resolution cache around every test.

    ``safety.check_allowed`` resolves a hostname and caches the answer for the process, so
    a test that stubs ``socket.getaddrinfo`` to simulate a remapped ``localhost`` would
    otherwise leave that answer visible to every later test — and a test that stubs
    nothing would inherit it. Same class of process-global as the set above.
    """
    from vvaharness.exploit_verification import safety
    safety._resolve_addrs.cache_clear()
    yield
    safety._resolve_addrs.cache_clear()


@pytest.fixture(autouse=True)
def _reset_response_quality_counters():
    """Reset the per-tag consecutive-short-response counter around every test.

    `util.response_quality` keeps `_consecutive` as module-global state so the
    degenerate-response guard can fire on the Nth short reply IN A ROW for one
    tag. That makes any test which drives a backend more than twice with the
    same tag and a stub response order-dependent: the third call raises
    `DegenerateResponseError` from state a PREVIOUS test left behind, and the
    test passes alone while failing in a full run.

    This is not hypothetical — it is exactly how the caching tests broke, since
    they legitimately reuse one tag with deliberately tiny stub responses to
    isolate cache behaviour from response content. Resetting here fixes that
    class of failure once, rather than asking every future test that reuses a
    tag to remember a guard it has no reason to know about.
    """
    from vvaharness.util.response_quality import reset_counters
    reset_counters()
    yield
    reset_counters()


@pytest.fixture(autouse=True)
def _reset_stage_recorder():
    from vvaharness.util.stage_telemetry import STAGES
    STAGES.reset()
    yield
    STAGES.reset()


# ─────────────────────────────────────────────────────────────────────────────
# The prompt() stub contract.
#
# Design choice: the NETWORK KILL below is autouse; the MODEL STUB
# (`stub_prompt`) is opt-in. An autouse stub that silently replaced prompt()
# everywhere would make it impossible to ever notice a stage that stopped
# calling prompt() at all (or started calling agentic() instead) — the test
# would still pass, model or no model. An autouse network kill has no such
# failure mode: it only ever *fires* on an actual outbound connection, which
# no test in this suite should ever make.
# ─────────────────────────────────────────────────────────────────────────────

class _NetworkBlocked(RuntimeError):
    pass


def _blocked(*_a, **_kw):
    raise _NetworkBlocked(
        "real network access attempted during a test run. Every test in this "
        "suite is expected to be offline and deterministic — request the "
        "`stub_prompt` fixture instead of calling a real prompt()/backend."
    )


def _is_local(host) -> bool:
    h = str(host or "").strip("[]").split("%", 1)[0]     # strip [] and zone id
    if h in ("", "localhost", "0.0.0.0", "::"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False                                     # a name we would resolve


def _local_dest(address) -> bool:
    return isinstance(address, (str, bytes)) or (        # AF_UNIX path
        isinstance(address, (tuple, list)) and bool(address) and _is_local(address[0]))


@pytest.fixture(autouse=True)
def _deny_network(monkeypatch):
    import socket

    # Loopback is permitted: the guard exists to stop egress, and a test that
    # starts its own server on 127.0.0.1 is not egress. `idx`/`key` are where the
    # destination sits in each signature, positionally or by keyword.
    def guard(real, idx, key, ok):
        def wrapper(*a, **kw):
            dest = a[idx] if len(a) > idx else kw.get(key)
            if not ok(dest):
                _blocked(dest)
            return real(*a, **kw)
        return wrapper

    monkeypatch.setattr(socket.socket, "connect",
                        guard(socket.socket.connect, 1, "address", _local_dest))
    monkeypatch.setattr(socket.socket, "connect_ex",
                        guard(socket.socket.connect_ex, 1, "address", _local_dest))
    # Name resolution egresses before any connect() does, so guard it too —
    # otherwise a test can still perform real DNS lookups against the outside
    # world and merely fail one step later.
    monkeypatch.setattr(socket, "getaddrinfo",
                        guard(socket.getaddrinfo, 0, "host", _is_local))
    monkeypatch.setattr(socket, "create_connection",
                        guard(socket.create_connection, 0, "address", _local_dest))
    # KNOWN, DELIBERATE GAP — a child process is not covered by any of the
    # above, because these patches apply to this interpreter only. One backend
    # drives the `claude` binary as a subprocess, so a test that reaches it on a
    # machine where that binary is installed can make real, billable calls with
    # every guard here still green.
    #
    # It is left uncovered on purpose. Blocking `subprocess` wholesale breaks the
    # many tests that legitimately shell out to `git`, and blocking that
    # backend's entry points breaks the tests that legitimately exercise it with
    # a mocked subprocess. Both were tried; each cost more than the risk it
    # removed. The real control is that tests exercising that backend mock it —
    # which is a review question, not something an autouse fixture can enforce
    # without breaking the tests doing it correctly.


@pytest.fixture
def stub_prompt(monkeypatch):
    """Opt-in, offline, deterministic `prompt()` for the threat-model,
    decompose, and deep-dive stages.

    Patches the origin `vvaharness.backends.llm.registry.prompt`. No stage
    binds the name any more: s2/s3/s4 call `_deepagents.dispatch_prompt`,
    whose non-deepagents branch resolves `registry.prompt` at call time, so
    the origin patch covers them with byte-identical kwargs — see
    tests/fixtures/prompt_stub.py's module docstring for the history of why
    a bound name needed its own patch.
    Returns a `PromptStub` instance — see that module for `.set_response`,
    `.set_raise`, and `.calls`.
    """
    stub = PromptStub()
    from vvaharness.backends.llm import registry as llm

    monkeypatch.setattr(llm, "prompt", stub, raising=True)
    return stub


# ─────────────────────────────────────────────────────────────────────────────
# On-disk / generated file-tree fixtures.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def repo_nested_manifests() -> Path:
    return FIXTURES_DIR / "repo_nested_manifests"


@pytest.fixture
def repo_extensionless() -> Path:
    return FIXTURES_DIR / "repo_extensionless"


@pytest.fixture
def repo_deep(tmp_path) -> Path:
    return repo_builders.build_repo_deep(tmp_path / "repo_deep")


@pytest.fixture
def repo_symlink_escape(tmp_path):
    return repo_builders.build_repo_symlink_escape(tmp_path)


# ─────────────────────────────────────────────────────────────────────────────
# In-memory ContextPackage builder fixtures.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def ctx_framework_eps():
    return ctx_builders.make_framework_eps_ctx()


@pytest.fixture
def ctx_taint_multi():
    return ctx_builders.make_taint_multi_ctx()


@pytest.fixture
def ctx_frontier_ne_full():
    return ctx_builders.make_frontier_ne_full_ctx()
