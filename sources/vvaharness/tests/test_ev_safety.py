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

"""Exploit-verification safety envelope — localhost-only enforcement, and disclosure.

Pure functions — no network. This release only targets the local machine; a
request at any non-local host is refused, in code, with no allowlist or override.

The second half covers the other guard in ``safety``: the layered redactor, its three
layers and one deliberate gap, and the mask-then-cap invariant every sink that writes EV's
free text outwards has to satisfy. The sink checks reach into ``verify`` / ``replay`` to
call those sinks for real, which keeps them honest — but they stay pure, since a sink takes
a record and returns text.
"""
from __future__ import annotations

import ast
from types import SimpleNamespace
from urllib.parse import quote, quote_plus, urlencode

import pytest

import vvaharness.exploit_verification.executor._core as core_mod
from vvaharness.exploit_verification import safety
from vvaharness.exploit_verification.executor.model import EvResponse, RequestRecord
from vvaharness.exploit_verification.replay import capture as capture_mod
from vvaharness.exploit_verification.replay import run as replay_run
from vvaharness.exploit_verification.replay.model import MAX_BODY as REPLAY_MAX_BODY
from vvaharness.exploit_verification.verify import judge as judge_mod
from vvaharness.exploit_verification.verify.model import JUDGE_MAX_BODY
from vvaharness.exploit_verification.verify.model import MAX_BODY as REPORT_MAX_BODY
from vvaharness.exploit_verification.verify.repro import detail_from_record


@pytest.mark.parametrize("url,ok", [
    ("http://localhost:8000/p", True),
    ("http://LocalHost:8000/p", True),          # case-insensitive name
    ("http://127.0.0.1:5000/p", True),
    ("http://127.0.0.1:8000/p", True),          # url port irrelevant
    ("http://127.5.6.7/p", True),               # anywhere in 127.0.0.0/8
    ("http://[::1]:8000/p", True),              # IPv6 loopback
    ("http://0.0.0.0:8000/p", False),           # "all interfaces" is not loopback
    ("http://10.0.0.5/p", False),               # private LAN is not local
    ("http://192.168.1.10/p", False),
    ("https://api.example/p", False),           # a remote name
    ("https://127.0.0.1.example/p", False),     # loopback-looking name, not loopback
])
def test_is_local(url, ok):
    from urllib.parse import urlparse
    assert safety._is_local(urlparse(url).hostname or "") is ok


def test_check_allowed_raises_on_non_local_host():
    with pytest.raises(safety.SafetyError):
        safety.check_allowed("https://api.example/p")


def test_check_allowed_raises_on_private_lan_host():
    with pytest.raises(safety.SafetyError):
        safety.check_allowed("http://192.168.1.10:8000/p")


def _resolves_to(monkeypatch, *addrs, fail=False):
    """Stub name resolution, so these stay hermetic instead of reading this machine's."""
    def fake_getaddrinfo(host, port, *a, **kw):
        if fail:
            raise OSError("name resolution failed")
        return [(2, 1, 6, "", (ip, 0)) for ip in addrs]
    monkeypatch.setattr(safety.socket, "getaddrinfo", fake_getaddrinfo)


def test_check_allowed_passes_for_localhost(monkeypatch):
    _resolves_to(monkeypatch, "127.0.0.1", "::1")     # the ordinary mapping
    safety.check_allowed("http://localhost:8000/p")   # no raise
    safety.check_allowed("http://127.0.0.1:5000/p")   # no raise
    safety.check_allowed("http://[::1]:8000/p")       # no raise


# ── a name is not an address: `localhost` is resolved before it is trusted ──────
#
# `_is_local` says a host is SPELLED local. The name itself points wherever this machine's
# resolution says, so the check would otherwise pass while the request left the box. Every
# mapped address must be loopback — not merely one of them, since which address the client
# picks is not EV's to choose.

def test_a_remapped_localhost_is_refused(monkeypatch):
    _resolves_to(monkeypatch, "10.0.0.5")
    with pytest.raises(safety.SafetyError) as e:
        safety.check_allowed("http://localhost:8000/p")
    assert "10.0.0.5" in str(e.value) and "not loopback" in str(e.value)


def test_a_localhost_that_maps_partly_off_box_is_refused(monkeypatch):
    """Mixed answer: loopback AND something else. Refused — EV does not get to assume the
    client will pick the harmless one."""
    _resolves_to(monkeypatch, "127.0.0.1", "10.0.0.5")
    with pytest.raises(safety.SafetyError) as e:
        safety.check_allowed("http://localhost:8000/p")
    assert "10.0.0.5" in str(e.value)


def test_an_unresolvable_name_is_refused(monkeypatch):
    """Cannot be shown to be local, so it is not treated as local."""
    _resolves_to(monkeypatch, fail=True)
    with pytest.raises(safety.SafetyError) as e:
        safety.check_allowed("http://localhost:8000/p")
    assert "does not resolve" in str(e.value)


def test_resolution_narrows_and_never_widens(monkeypatch):
    """A name that is not spelled local stays refused even when it resolves to loopback.

    The guard that keeps this from becoming a DNS-rebinding accept path: if resolving
    could ADD hosts, whoever controls the answer would control what EV targets."""
    _resolves_to(monkeypatch, "127.0.0.1")
    for host in ("evil.example", "127.0.0.1.example", "loopback.invalid"):
        with pytest.raises(safety.SafetyError) as e:
            safety.check_allowed(f"http://{host}:8000/p")
        assert "is not local" in str(e.value)


def test_an_ip_literal_is_never_resolved(monkeypatch):
    """A literal IS its address, so the accept path for the documented target shape does
    no lookup at all — `check_allowed` runs on every request."""
    def explode(*a, **kw):
        raise AssertionError("resolved an IP literal")
    monkeypatch.setattr(safety.socket, "getaddrinfo", explode)
    for host in ("127.0.0.1", "127.5.6.7", "[::1]"):
        safety.check_allowed(f"http://{host}:5000/p")   # no raise, no lookup


def test_the_resolution_answer_is_cached(monkeypatch):
    """One lookup per host per process: the check is on the per-request path, so a slow
    resolver must not be paid thousands of times."""
    calls = []

    def counting(host, port, *a, **kw):
        calls.append(host)
        return [(2, 1, 6, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(safety.socket, "getaddrinfo", counting)
    for _ in range(5):
        safety.check_allowed("http://localhost:8000/p")
    assert calls == ["localhost"]


def test_a_transient_resolver_failure_is_not_cached(monkeypatch):
    """Only a real answer is worth remembering.

    The cache held the failure too, so one momentary resolver outage — a DNS blip, a
    container still coming up — refused ``localhost`` for the rest of the process and failed
    the whole run over a lookup that succeeds a second later.
    """
    state = {"up": False}

    def flaky(host, port, *a, **kw):
        if not state["up"]:
            raise OSError("resolver temporarily unavailable")
        return [(2, 1, 6, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(safety.socket, "getaddrinfo", flaky)

    with pytest.raises(safety.SafetyError):
        safety.check_allowed("http://localhost:8000/p")
    state["up"] = True
    safety.check_allowed("http://localhost:8000/p")     # must not raise


def test_a_credential_is_masked_in_its_form_encoded_spelling():
    """``urlencode`` writes a space as ``+``, ``quote`` writes ``%20``.

    A form login body and a rendered curl repro both go through ``urlencode``, so
    registering only the ``quote`` form left that spelling of any credential containing a
    space readable in the stored probe, the replay bundle and the report.
    """
    secret = "correct horse battery"
    safety.register_secret(secret)
    for wire in (urlencode({"password": secret}), quote_plus(secret), quote(secret, safe="")):
        assert secret.replace(" ", "+") not in safety.redact_secrets(wire)
        assert secret not in safety.redact_secrets(wire)


# ── egress: one client, built in one place ────────────────────────────────────
#
# `check_allowed` vets the host in the URL; `hardened_client`'s `trust_env=False` stops a
# URL that passed it being routed elsewhere by HTTP_PROXY / ALL_PROXY, and
# `follow_redirects=False` stops a 30x handing it to another host. Both are proven
# behaviourally in `test_ev_executor.py` — once through `send` (which shares its client with
# `probe.run_probe`) and once through the OOB self-test, which builds its own. What this adds
# is the invariant no behavioural test can express: that those are the only clients, and that
# a fourth call path cannot appear without this failing.
#
# It is written as a denial, not a list of approved shapes. The version this replaces
# enumerated the call shapes it would inspect — `httpx.Client`, `httpx.AsyncClient`, then a
# tuple of module-level verbs — so it could only catch a spelling someone had already
# thought of. `import httpx as hx` and `from httpx import get` both walked straight past it
# while issuing exactly the request it existed to forbid, and it reported clean. An
# enumeration is the wrong shape for this check: the next client is written by someone who
# has not read it.

#: The one module allowed to build a client, relative to the package root. Every other
#: module gets one from it — see ``safety.hardened_client``.
_CLIENT_SITE = "safety.py"

#: Other HTTP clients, none of which EV uses. `requests` and `urllib.request` both honour
#: proxy environment variables, so adopting one would reopen the egress `trust_env=False`
#: closes, in a module a scan for httpx alone would read as clean. Matched by prefix (see
#: :func:`_is_other_client`), the same way the httpx side is: a submodule import is the
#: ordinary spelling, not an evasion, and an exact-match list would miss every one of them.
_OTHER_CLIENTS = ("requests", "urllib.request", "http.client", "httpcore", "aiohttp",
                  "urllib3")


def _is_other_client(module: str) -> bool:
    """Whether a dotted module name is, or is inside, one of :data:`_OTHER_CLIENTS`."""
    return any(module == c or module.startswith(c + ".") for c in _OTHER_CLIENTS)


def _reaches_httpx(node, names: set[str]) -> bool:
    """Whether an expression reaches httpx: ``hx``, ``httpx.Client``, ``httpx._client.C``.

    Attribute access is followed to its root rather than matched on the attribute, so no
    depth of qualification hides where the object came from."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name) and node.id in names


def _httpx_names(tree) -> set[str]:
    """Every local name in one module that reaches httpx, however it was bound.

    Tracks the three ways a module can rebind it — ``import httpx as hx``,
    ``from httpx import Client``, and an assignment (``C = httpx.Client``) — because
    matching the literal name ``httpx`` is defeated by any of the three, which is precisely
    how the shape this file guards against survived being "guarded" before."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "httpx" or a.name.startswith("httpx."):
                    names.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "httpx":
                names.update(a.asname or a.name for a in node.names)
    # Rebindings resolve only once the imports are known, and one can feed another
    # (`H = httpx`, then `C = H.Client`), so this runs to a fixed point rather than once.
    grew = True
    while grew:
        grew = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not _reaches_httpx(node.value, names):
                continue
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id not in names:
                    names.add(t.id)
                    grew = True
    return names


def _is_dynamic_import(func) -> bool:
    """Whether a call fetches a module by name at run time — ``__import__`` or any spelling
    of ``importlib.import_module``, aliased or imported bare. Matched on the mechanism
    rather than on the string it is given, because the string may be built."""
    if isinstance(func, ast.Name):
        return func.id in ("__import__", "import_module")
    return isinstance(func, ast.Attribute) and func.attr == "import_module"


def _is_module_table(node) -> bool:
    """Whether an expression subscripts a module table — ``sys.modules["httpx"]``.

    The same run-time lookup :func:`_is_dynamic_import` refuses, by a third spelling. The
    rule is about the mechanism, so covering two of its forms and not the third would leave
    the rule itself incomplete rather than merely miss a shape."""
    return (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute)
            and node.value.attr == "modules")


def _non_executing(tree) -> set:
    """The nodes where naming httpx cannot send anything: an ``except`` clause's exception
    type, and a type annotation.

    Neither position is inert in general — an ``except`` type is evaluated on every match,
    and an annotation at ``def`` time in a module without ``from __future__ import
    annotations`` — so a subtree is exempted only when it contains no call at all. That is
    what makes the exemption safe rather than merely conventional: a name is looked up, and
    nothing more happens. Anything with a call in it falls through to the denial, since an
    exemption is what a later reader inherits without checking why it was safe."""
    exempt: set = set()

    def _add(sub) -> None:
        nodes = list(ast.walk(sub))
        if not any(isinstance(n, ast.Call) for n in nodes):
            exempt.update(nodes)

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            _add(node.type)
        for field in ("annotation", "returns"):
            ann = getattr(node, field, None)
            if ann is not None:
                _add(ann)
    return exempt


def _scan_module(where: str, source: str, *, allowed: bool) -> tuple[list[str], list]:
    """Scan one module for egress that leaves the envelope.

    Returns ``(complaints, client_calls)``. Split out from the package sweep so it can be run
    against source the sweep will never see — see
    :func:`test_the_egress_guard_catches_every_way_around_it`, which feeds it the spellings a
    checker of this kind is liable to miss, two of which really did defeat its predecessor. A
    guard that cannot be shown to fail is the defect it is guarding against."""
    bad: list[str] = []
    sites: list = []
    tree = ast.parse(source)                          # a syntax error must raise, not skip
    names = _httpx_names(tree)
    exempt = _non_executing(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _is_other_client(a.name):
                    bad.append(f"{where}:{node.lineno} imports {a.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            # A star import binds names that cannot be read out of this file, so the rest
            # of this scan would be reasoning about a module whose contents it cannot see.
            # EV has none; refused rather than approximated.
            if any(a.name == "*" for a in node.names):
                bad.append(f"{where}:{node.lineno} star-imports {mod}, so what it binds "
                           f"cannot be determined from the source")
            for a in node.names:
                if _is_other_client(mod) or _is_other_client(f"{mod}.{a.name}"):
                    bad.append(f"{where}:{node.lineno} imports {mod}.{a.name}")
        elif isinstance(node, ast.Call):
            # `getattr(httpx, "get")` reaches the module without naming the attribute, so
            # it is refused wherever it appears, allowlisted site included.
            if (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                    and node.args and _reaches_httpx(node.args[0], names)):
                bad.append(f"{where}:{node.lineno} reaches httpx through getattr")
            # A module fetched by name at run time is invisible to every check above,
            # whatever the string says — so the mechanism is refused rather than the
            # argument inspected. Nothing in EV imports dynamically (`payloads/loader.py`
            # uses `importlib.resources`, which is not this), so the rule costs nothing;
            # were a real need to arise, this failing is the right place to weigh it.
            elif _is_dynamic_import(node.func):
                bad.append(f"{where}:{node.lineno} imports a module dynamically, which "
                           f"no static check can follow")
            elif allowed and _reaches_httpx(node.func, names):
                sites.append((f"{where}:{node.lineno}", node))
        elif _is_module_table(node):
            bad.append(f"{where}:{node.lineno} reaches a module through a run-time module "
                       f"table, which no static check can follow")
        elif not allowed and isinstance(node, (ast.Name, ast.Attribute)) \
                and node not in exempt and _reaches_httpx(node, names):
            # Reported at the root of the reference, so `httpx.Client` is one complaint
            # rather than one per level of attribute access.
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            entry = (f"{where}:{root.lineno} names httpx outside {_CLIENT_SITE} — get a "
                     f"client from safety.hardened_client")
            if entry not in bad:
                bad.append(entry)
    return bad, sites


def _check_client_call(where: str, call) -> list[str]:
    """What the one allowed construction must and must not be given."""
    bad: list[str] = []
    if any(k.arg is None for k in call.keywords):
        bad.append(f"{where} splats **kwargs into the client, which can carry any "
                   f"keyword including trust_env=True")
    for name in ("trust_env", "follow_redirects"):
        v = next((k.value for k in call.keywords if k.arg == name), None)
        # A literal False and nothing else. A variable, a conditional, a `0` may each be
        # False at run time and none can be shown to be from here, so an unresolved
        # spelling fails rather than being guessed at. Failing on a safe spelling costs one
        # rewrite; passing an unsafe one costs the control.
        if not (isinstance(v, ast.Constant) and v.value is False):
            bad.append(f"{where} does not pin {name}=False as a literal")
    for name in ("proxy", "proxies", "mounts", "transport"):
        if any(k.arg == name for k in call.keywords):
            bad.append(f"{where} passes {name}=, which httpx honours regardless of "
                       f"trust_env — the egress it closes is reopened")
    return bad


def test_only_the_safety_envelope_builds_an_http_client():
    """No EV request can be built outside the envelope, or with the envelope's two
    egress controls relaxed.

    Four things are asserted together, because each is a way the same control comes undone:
    that exactly one module constructs a client; that it pins ``trust_env=False`` and
    ``follow_redirects=False`` as literals and is given no argument that re-admits what they
    close; that no other module in the package reaches for httpx — under any alias,
    from-import or rebinding — or for another HTTP library; and that nothing anywhere
    reaches a module by a name resolved at run time, which would put it beyond the reach of
    all three.

    The failure this is calibrated against is not a client someone builds carelessly but
    one that reads as ordinary: the OOB self-test issued a freshly minted callback nonce
    through a module-level helper, which a proxy exported in the environment carried off
    the machine, and the check of the day inspected constructor calls and so could not see
    it. Hence a denial over a single allowlisted site rather than a list of shapes to
    inspect: an unrecognised spelling now fails instead of passing unexamined."""
    from pathlib import Path

    from vvaharness import exploit_verification

    root = Path(exploit_verification.__file__).parent
    sites, bad = [], []
    for path in sorted(root.rglob("*.py")):
        where = str(path.relative_to(root))
        found, calls = _scan_module(where, path.read_text(encoding="utf-8"),
                                    allowed=where == _CLIENT_SITE)
        bad += found
        sites += calls

    if len(sites) != 1:
        bad.append(f"expected exactly one client construction, in {_CLIENT_SITE}; "
                   f"found {[w for w, _ in sites]}")
    else:
        bad += _check_client_call(*sites[0])

    assert bad == [], ("EV's HTTP egress controls can be bypassed, so a request that "
                       "passed check_allowed may still leave the machine: "
                       + "; ".join(bad))


#: Ways to get an unhardened request out of a module that may not have one: httpx under some
#: other spelling, a module fetched by name at run time, or a different client library
#: altogether. The first two entries are the ones that defeated the previous check while
#: issuing the exact request it forbade. Each must be REFUSED — and the point is that the
#: guard denies what it does not recognise, so this list does not have to be complete for the
#: check to hold, and adding to it cannot be how the check stays sound.
_EVASIONS = [
    ("aliased import", "import httpx as hx\nhx.get('http://127.0.0.1/x')\n"),
    ("from-import of a verb", "from httpx import get\nget('http://127.0.0.1/x')\n"),
    ("from-import of the class", "from httpx import Client\nClient(timeout=1)\n"),
    ("aliased from-import", "from httpx import Client as C\nC(timeout=1)\n"),
    ("module rebound to a name", "import httpx\n_H = httpx\n_H.get('http://x')\n"),
    ("class rebound to a name", "import httpx\nC = httpx.Client\nC(timeout=1)\n"),
    ("chained rebinding", "import httpx\nH = httpx\nC = H.Client\nC(timeout=1)\n"),
    ("private submodule", "import httpx\nhttpx._client.Client(timeout=1)\n"),
    ("submodule import", "import httpx._client\nhttpx._client.Client(timeout=1)\n"),
    ("getattr", "import httpx\ngetattr(httpx, 'get')('http://x')\n"),
    ("subclassing", "import httpx\nclass C(httpx.Client):\n    pass\n"),
    ("returned from a helper", "import httpx\ndef f():\n    return httpx.Client\n"),
    ("annotated assignment", "import httpx\nc: httpx.Client = httpx.Client(timeout=1)\n"),
    ("held in a container", "import httpx\nD = {'c': httpx.Client}\nD['c'](timeout=1)\n"),
    ("bare construction", "import httpx\nhttpx.Client(timeout=1)\n"),
    ("star import", "from httpx import *\nClient(timeout=1)\n"),
    ("importlib", "import importlib\nimportlib.import_module('httpx').get('http://x')\n"),
    ("bare import_module",
     "from importlib import import_module\nimport_module('httpx').get('http://x')\n"),
    ("__import__", "__import__('httpx').get('http://x')\n"),
    ("run-time module table", "import sys\nsys.modules['httpx'].get('http://x')\n"),
    ("a call in an annotation",
     "import httpx\ndef f() -> httpx.Client(timeout=1):\n    pass\n"),
    ("another client library", "import requests\nrequests.get('http://x')\n"),
    ("a submodule of another client library",
     "from requests.sessions import Session\nSession().get('http://x')\n"),
    ("a proxy-honouring stdlib client",
     "from urllib import request\nrequest.urlopen('http://x')\n"),
]


@pytest.mark.parametrize("label,source", _EVASIONS, ids=[e[0] for e in _EVASIONS])
def test_the_egress_guard_catches_every_way_around_it(label, source):
    """The guard must fail for each spelling, not merely for the one that was reported.

    This is the half that was missing, and the reason it was missing is worth stating
    exactly. Two checks preceded this one. The first inspected constructor calls only, so a
    module-level request helper was invisible to it and it read clean while the defect it
    existed to catch sat in the tree. The second added those helpers to what it inspected —
    which closed the reported shape and no other, since an alias or a from-import is a
    different node and the check was a list of nodes it knew about. Neither could fail for
    its own subject, because neither was ever run against a spelling it did not already
    handle. Feeding the guard its evasions directly is what changes that: a gap shows up as
    a red test rather than as a clean run."""
    bad, _ = _scan_module("evasion.py", source, allowed=False)
    assert bad, f"{label} slips past the egress guard"


def test_the_allowlisted_site_may_not_reach_httpx_dynamically_either():
    """The allowlist is a licence to construct the client, not to reach httpx by any means.

    Pins the ``getattr`` rule on its own: everywhere else that rule is shadowed by the
    reference denial, which fires on the same line, so this is the only place its removal
    would show."""
    bad, sites = _scan_module(_CLIENT_SITE,
                              "import httpx\ngetattr(httpx, 'get')('http://x')\n",
                              allowed=True)
    assert sites == [] and bad and "getattr" in bad[0]


@pytest.mark.parametrize("kwargs,why", [
    ("timeout=1", "neither control pinned"),
    ("timeout=1, trust_env=False", "follow_redirects not pinned"),
    ("timeout=1, follow_redirects=False", "trust_env not pinned"),
    ("timeout=1, trust_env=_OFF, follow_redirects=False", "trust_env is not a literal"),
    ("timeout=1, trust_env=0, follow_redirects=False", "0 is not False"),
    ("timeout=1, trust_env=False, follow_redirects=False, proxy='http://p'", "proxy given"),
    ("timeout=1, trust_env=False, follow_redirects=False, mounts={}", "mounts given"),
    ("timeout=1, trust_env=False, follow_redirects=False, transport=None", "transport given"),
    # Both controls spelled out, so the ONLY thing this case can fail on is the splat —
    # which is the rule that stops `httpx.Client(**BASE)` re-admitting trust_env=True.
    ("timeout=1, trust_env=False, follow_redirects=False, **kw",
     "kwargs may carry anything"),
])
def test_the_allowed_client_site_is_held_to_both_controls(kwargs, why):
    """The single allowed construction is not trusted for being the allowed one: relaxing
    either control there, or passing an argument that reopens what they close, fails."""
    bad, sites = _scan_module(_CLIENT_SITE, f"import httpx\nhttpx.Client({kwargs})\n",
                              allowed=True)
    assert bad == [] and len(sites) == 1                  # the site itself is not complained of
    assert _check_client_call(*sites[0]), why


def test_the_real_client_site_satisfies_its_own_checks():
    """A sanity anchor for the denials above: the shape the package actually ships passes,
    so their failures mean a relaxed control rather than an over-strict check."""
    bad, sites = _scan_module(
        _CLIENT_SITE,
        "import httpx\nhttpx.Client(timeout=t, verify=v, trust_env=False, "
        "follow_redirects=False)\n",
        allowed=True)
    assert bad == [] and len(sites) == 1
    assert _check_client_call(*sites[0]) == []


# ── redaction: the three layers, and the one gap that is deliberate ────────────
#
# Every EV sink (the s6-ev probe log, the ev_probes / ev_replays tables, and the ev_* fields
# that reach the report) funnels through `safety.redact_secrets` / `redact_params` /
# `redact_body`, so these pin the contract for all of them at once. The synthetic secrets
# below are invented for the test; none is a real credential.

_T_JWT = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ0ZXN0LTEyMyJ9.c3ludGhldGljX3Rlc3Rfc2ln"
_T_PAN = "4111111111111111"          # Luhn-valid test card (Visa test BIN)


def test_layer1_masks_shaped_secrets():
    """Shape-recognisable material is masked by the shared product redactor."""
    out = safety.redact_secrets(f"tok {_T_JWT} card {_T_PAN}")
    assert _T_JWT not in out and _T_PAN not in out
    assert "[REDACTED-JWT]" in out and "[REDACTED-PAN]" in out


def test_layer1_masks_a_truncated_jwt():
    """EV keeps a shorter per-segment floor than the shared redactor: the executor caps
    bodies, so a real token can arrive with its signature cut short and is still a
    credential."""
    out = safety.redact_secrets("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig123abc")
    assert "[REDACTED-JWT]" in out


def test_layer2_masks_credential_named_values_at_any_depth():
    """A token nested under a credential-named key is as sensitive as one at the top."""
    out = safety.redact_body({"data": {"session": "abc123xyz", "name": "alice"},
                              "rows": [{"password": "hunter2"}]})
    assert out["data"]["session"] == "[REDACTED]"
    assert out["rows"][0]["password"] == "[REDACTED]"
    assert out["data"]["name"] == "alice"            # non-credential values untouched


def test_layer3_masks_a_credential_ev_itself_injected():
    """An opaque token has no shape a regex can recognise — but EV knows the bytes it sent,
    so it can mask them when the target echoes them back."""
    safety.register_secret("opaque-session-value-9f2b")
    out = safety.redact_secrets("the response echoed opaque-session-value-9f2b back")
    assert "opaque-session-value-9f2b" not in out and "[REDACTED]" in out


def test_a_too_short_value_is_never_registered():
    """Masking a 3-character 'secret' would match inside unrelated words and turn a
    response into noise."""
    safety.register_secret("abc")
    assert "abc" in safety.redact_secrets("abcdef ghi")


def test_a_generic_credential_is_not_masked_by_value():
    """Layer 3 replaces literals, so a low-entropy credential would corrupt what it touches:
    `EV_AUTH_PASSWORD=password` would rewrite every `"password"` KEY to `"[REDACTED]"` and
    mangle ordinary prose, leaving an unreadable report while protecting nothing. Such a
    value is dropped at registration — the key-name layer still masks it wherever it sits
    under a credential-named key."""
    safety.register_secret("password")
    body = '{"password": "x", "note": "reset your password here"}'
    assert safety.redact_secrets(body) == body            # structure and prose intact
    assert safety.redact_body({"password": "x"}) == {"password": "[REDACTED]"}


@pytest.mark.parametrize("value,maskable", [
    ("hunter2", True),                    # has a digit -> distinctive
    ("Str0ngP@ss", True),                 # mixed classes
    ("opaque-sess-9f2b1c", True),         # generated token shape
    ("correcthorsebatterystaple", True),  # long enough to be implausible as prose
    ("password", False),                  # a key name AND a common word
    ("qwerty", False),                    # short bare dictionary word
    ("admin", False),
    ("abc", False),                       # too short
])
def test_which_values_are_distinctive_enough_to_mask(value, maskable):
    assert safety._maskable(value) is maskable


def test_documented_gap_a_bare_value_in_a_positional_array_is_not_masked():
    """The KNOWN LIMITATION, pinned so it stays deliberate.

    A value that is sensitive by MEANING but carries neither a recognisable shape nor a
    credential-named key cannot be caught: in `{"rows": [[1, "alice", "password123"]]}` the
    column name lives in the schema, not in the response bytes, so no layer has anything to
    anchor on. It is third-party data EV never supplied, so the known-value layer cannot see
    it either. If this ever starts passing, the limitation has been closed and the docs
    should say so."""
    body = '{"rows": [[1,"alice","a@e.com","password123"]]}'
    assert "password123" in safety.redact_secrets(body)


def test_layer3_is_a_no_op_when_nothing_is_registered():
    """The common case — a run with no credential, or one before the first injection.
    Layer 3 has nothing to do, so it must not scan (or lock) to discover that: this runs on
    every header, parameter and body of every transcript record."""
    assert not safety._KNOWN_SECRETS                  # the autouse fixture cleared it
    body = '{"note": "nothing registered, so nothing to mask"}'
    assert safety._mask_known(body) is body           # returned untouched, not rebuilt


def test_layer3_masks_the_longest_secret_first():
    """A credential nested inside a longer one must not be masked out from under it —
    otherwise the longer value survives in part."""
    safety.register_secret("sess-9f2b1c")
    safety.register_secret("sess-9f2b1c-extended-tail")
    out = safety.redact_secrets("echo sess-9f2b1c-extended-tail back")
    assert out == "echo [REDACTED] back"              # masked whole, not "[REDACTED]-extended-tail"


def test_layer3_ordering_is_stable_for_equal_length_secrets():
    """Two equal-length secrets that OVERLAP in the text: whichever is replaced first
    decides the output, so the order cannot be left to set iteration — that varies with
    PYTHONHASHSEED, and `ev-replay` re-masks a stored OLD body and a fresh NEW one in
    different processes before comparing them. A masking difference must never read as a
    difference the fix made."""
    safety.register_secret("abcd1234")
    safety.register_secret("1234efgh")
    # lexicographic tie-break: "1234efgh" sorts before "abcd1234", so it is replaced first
    assert safety.redact_secrets("Xabcd1234efghY") == "Xabcd[REDACTED]Y"


def test_the_marker_is_left_alone_on_a_second_pass():
    """Redaction is applied at several boundaries and a stored body may be re-redacted when
    ev-replay compares it, so a second pass must not double-mask its own marker."""
    once = safety.redact_secrets(f"tok {_T_JWT}")
    assert safety.redact_secrets(once) == once


# ── mask THEN cap: the invariant at every sink that writes EV's text outwards ──
#
# Each of these has to mask a credential AND cap what it keeps, and the order is not
# interchangeable: layer 3 matches a credential as a literal, so capping first leaves a token
# straddling the boundary as a truncated fragment nothing can recognise. Not hypothetical —
# two sinks shipped with the operations reversed while a third had them the right way round,
# which is why the pair now lives in `safety.redact_then_cap` and why these tests call every
# sink for real instead of trusting each call site to read correctly. A new sink belongs in
# `_SINKS`; the checks are behavioural, so a sink that caps too early fails however it is
# written. `router._probe_rows` is the sixth sink, covered in test_ev_router.py where its
# fixtures live.

#: Opaque, mixed-class, long enough for `_maskable` — a stand-in for a session token.
#: Deliberately NOT a JWT or an `sk-` key: those have shapes layer 1 catches on its own,
#: which would mask the very thing under test and let a broken sink pass.
_T_TOKEN = "sess-9f2b1c7d4e8a0b3f6c2d"


def _straddling_body(cap: int) -> str:
    """A JSON body whose credential starts 12 bytes before ``cap`` and ends past it."""
    head = '{"echoed":"'
    body = head + "x" * (cap - 12 - len(head)) + _T_TOKEN + '"}'
    assert body.index(_T_TOKEN) == cap - 12          # the fixture itself must straddle
    return body


def _record(body: str) -> RequestRecord:
    return RequestRecord(method="GET", url="http://127.0.0.1:5000/x", params={}, body=None,
                         authed=False, payload_label="p", injection_point="query.id",
                         response=EvResponse(200, body, {}, 0.01, "http://127.0.0.1:5000/x"))


def _sink_report_repro(body):
    """`ev_repro_detail` -> the shareable Markdown report."""
    return detail_from_record(_record(body)).resp_body


def _sink_replay_bundle(body):
    """The stored `ev_replays` bundle -> re-checked and quoted later by `ev-replay`."""
    return capture_mod._response_from_record(_record(body)).body


def _sink_replay_new_body(body):
    """The NEW response shown to the remediation judge and the ev-replay report."""
    return replay_run._excerpt(_record(body))


def _sink_replay_stored_body(body):
    """The OLD side of an ev-replay diff, re-normalised through the current redactor."""
    return replay_run._stored_body(SimpleNamespace(body=body))


def _sink_judge_prompt(body):
    """The confirm judge's transcript view — this one leaves the process entirely."""
    return judge_mod._transcript_view([_record(body)])[0]["response"]["body"]


def _sink_attacker_tool_result(body):
    """The attacker's `http_request` result — the OTHER path that leaves the process.

    It shipped un-redacted while the judge view beside it masked the same bytes field by
    field, which is the asymmetry this row exists to keep closed: one model-bound path
    redacting and the other not is worse than neither doing it, because the careful
    neighbour is what makes the gap invisible in review.

    Returns the body section only, like every other row — the status/header prefix is not
    what this cap governs. The header and transport-error halves of the same result have
    their own coverage in ``test_ev_executor.py``.
    """
    return core_mod.format_response(_record(body).response).split("body:\n", 1)[1]


_SINKS = [
    ("report repro detail", REPORT_MAX_BODY, _sink_report_repro),
    ("ev_replays bundle", REPLAY_MAX_BODY, _sink_replay_bundle),
    ("ev-replay new body", REPLAY_MAX_BODY, _sink_replay_new_body),
    ("ev-replay stored body", REPLAY_MAX_BODY, _sink_replay_stored_body),
    ("confirm judge prompt", JUDGE_MAX_BODY, _sink_judge_prompt),
    ("attacker tool result", core_mod.ATTACKER_MAX_BODY, _sink_attacker_tool_result),
]


@pytest.mark.parametrize("name,cap,sink", _SINKS, ids=[s[0] for s in _SINKS])
def test_no_sink_lets_a_credential_survive_its_own_cap(name, cap, sink):
    safety.register_secret(_T_TOKEN)
    out = sink(_straddling_body(cap))
    assert _T_TOKEN not in out, f"{name} wrote the whole credential"
    assert _T_TOKEN[:12] not in out, f"{name} capped before redacting — leaked a prefix"
    assert "[REDACTED]" in out, f"{name} dropped the marker that proves masking ran"


@pytest.mark.parametrize("name,cap,sink", _SINKS, ids=[s[0] for s in _SINKS])
def test_every_sink_still_caps_what_it_keeps(name, cap, sink):
    """The other half of the pair: redacting first must not have removed the cap. Masking can
    shorten a body, so the bound is the cap, not equality with it."""
    safety.register_secret(_T_TOKEN)
    out = sink("y" * (cap * 3))
    assert len(out) <= cap + 60, f"{name} kept {len(out)} chars for a cap of {cap}"


def test_a_sinks_error_branch_redacts_like_its_body_branch():
    """The `_SINKS` rows above exercise each sink's BODY. A response can instead carry a
    transport error, and that is a second branch through the same sink — one that reaches
    the same remediation-judge prompt and the same report. It shipped returning the error
    raw because the comment promising redaction sat *below* the early return, so the
    guarantee described a branch it did not cover.
    """
    safety.register_secret(_T_TOKEN)
    rec = SimpleNamespace(response=SimpleNamespace(
        error=f"ConnectError: refused for http://127.0.0.1/x?token={_T_TOKEN}", text=""))
    out = replay_run._excerpt(rec)
    assert out.startswith("ERROR: ")          # the branch still reads as an error
    assert _T_TOKEN not in out
    assert "[REDACTED]" in out


def test_redact_then_cap_is_the_shared_implementation():
    """The helper the sinks route through: a credential spanning the cut is masked, and the
    reverse order is what leaked — pinned so the reasoning cannot go stale."""
    safety.register_secret(_T_TOKEN)
    body = _straddling_body(64)
    assert _T_TOKEN[:12] not in safety.redact_then_cap(body, 64)
    assert _T_TOKEN[:12] in safety.redact_secrets(body[:64])      # the bug this replaced


def test_is_maskable_is_the_gates_public_view_of_the_same_rule():
    """The gate warns an operator when their credential cannot be masked, so it needs the
    same predicate registration uses — not a second copy that could drift from it."""
    assert safety.is_maskable("sess-9f2b1c7d4e8a0b3f6c2d") is True
    assert safety.is_maskable("admin") is False
    assert safety.is_maskable("  ") is False and safety.is_maskable(None) is False
