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

"""Shared TLS-config coercion and mTLS client-chain handling for the backend clients.

`verify_ssl` is usually a YAML boolean (a real ``bool``), but a value templated
from the environment (e.g. ``${VERIFY_SSL:-false}``) or written as a quoted YAML
scalar arrives as a *string*. A string is truthy, so an un-coerced ``"false"``
would silently leave TLS verification enabled (the backends test ``verify is
False`` / pass the value straight to httpx). ``coerce_verify`` normalises the
common string booleans to a real ``bool`` while leaving any other string — which
is a CA-bundle path — and real bools untouched.

The client-chain helpers (:func:`resolve_client_chain`, :func:`load_client_chain`)
implement one mTLS policy for every route that offers it (``via: sdk`` and the
deepagents model builder), and :func:`warn_verify_disabled` emits the single
TLS-off warning for every route that can disable verification (``via: sdk``,
``via: openai`` and the deepagents model builder). A missing client certificate
warns and degrades to server-authenticated TLS because the run need not require
mTLS. CA-bundle validation remains each caller's responsibility: the DeepAgents
model builder rejects missing, wrong-type, and malformed CA material rather than
falling back to ambient or system trust. Warnings carry paths and exception types
only, never file contents.
Warnings carry the path and exception type only, never file contents. This module
stays stdlib-only on purpose (it is imported by paths that must not pull httpx);
each caller builds its own httpx/ssl context and passes it in.
"""
from __future__ import annotations

import os
import ssl
import sys
from collections.abc import Iterator
from contextlib import contextmanager

_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}
_NO_PROXY_KEYS = ("NO_PROXY", "no_proxy")
_OAUTH_TOKEN_PREFIX = "sk-ant-oat"
_OAUTH_BETA_HEADER = "oauth-2025-04-20"


def anthropic_auth_kwargs(token: str | None) -> dict[str, object]:
    """Return Anthropic client authentication kwargs for a static key or OAuth token."""
    token = (token or "").strip()
    if token.startswith(_OAUTH_TOKEN_PREFIX):
        return {
            "auth_token": token,
            "default_headers": {"anthropic-beta": _OAUTH_BETA_HEADER},
        }
    return {"api_key": token} if token else {}


def is_anthropic_oauth_token(token: str | None) -> bool:
    """True when *token* has Anthropic's documented OAuth workspace-token prefix."""
    return (token or "").strip().startswith(_OAUTH_TOKEN_PREFIX)


def coerce_verify(value):
    """Return ``value`` with string booleans mapped to real ``bool``.

    - ``bool`` / ``None`` → returned unchanged.
    - a string matching a known boolean literal (case-insensitive) → ``bool``.
    - any other string (a CA-bundle path) → returned unchanged.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in _FALSE:
            return False
        if low in _TRUE:
            return True
    return value


def chain_paths(cert: str | tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Normalise either accepted client-chain shape to a tuple of paths.

    A combined-PEM path is one string; a cert/key pair is a tuple, or a **list**
    when it came from YAML. Matching on ``tuple`` alone is the bug this exists to
    prevent: it made one profile work on the deepagents route and raise
    ``TypeError`` on ``via: sdk``. Single definition so the three call sites
    (both helpers here, and the deepagents carrier builder) cannot drift apart.
    """
    return tuple(cert) if isinstance(cert, (tuple, list)) else (cert,)


def resolve_client_chain(
    cert: str | tuple[str, ...] | list[str] | None, *, label: str,
    noun: str = "client_cert",
) -> str | tuple[str, ...] | list[str] | None:
    """Return the configured client chain, or None (warned) when a file is missing.

    A configured-but-ABSENT cert/key file warns and disables mTLS rather than
    failing the run — deliberately weaker than a malformed CA bundle, which the
    callers fail closed on. *noun* names the material in the warning (the
    deepagents route carries a split cert/key pair, so it says ``client_cert/key``;
    ``via: sdk`` says ``client_cert``). The warning carries the path only, never
    file contents. Both chain shapes are accepted on every route — see
    :func:`chain_paths`.
    """
    if not cert:
        return None
    paths = chain_paths(cert)
    missing = next((p for p in paths if p and not os.path.exists(p)), None)
    if missing is not None:
        print(f"WARN [{label}]: {noun} '{missing}' not found — disabling mTLS",
              file=sys.stderr)
        return None
    return cert


def load_client_chain(
    context: ssl.SSLContext, cert: str | tuple[str, ...] | list[str], *, label: str
) -> bool:
    """Load the client chain onto *context*, warning and returning False on failure.

    TRAP (httpx 0.28.1): ``create_ssl_context(verify=<str CA path> or False,
    cert=...)`` returns BEFORE its ``cert=`` handling, so a ``cert=`` kwarg riding
    alongside a non-True ``verify=`` silently never presents the client
    certificate (the CA-plus-mTLS gateway deployment). Callers must therefore
    build the SSL context explicitly and load the chain onto it here — never pass
    ``cert=`` to the httpx client; calling ``load_cert_chain`` on the built
    context covers every ``verify`` shape.

    An unloadable chain warns loudly (the operator configured mTLS and must not
    believe it is active) and returns False so the caller keeps
    server-authenticated TLS instead of failing the run — path and exception type
    only, never file contents.
    """
    args = chain_paths(cert)
    try:
        context.load_cert_chain(*args)
    except Exception as exc:
        print(f"WARN [{label}]: client_cert '{args[0]}' could not be loaded "
              f"({type(exc).__name__}) — mTLS is NOT active; continuing "
              f"with server-authenticated TLS only", file=sys.stderr)
        return False
    return True


def warn_verify_disabled(base: str | None, *, label: str,
                         default_endpoint: str = "<default endpoint>",
                         ca_hint: str = "ca_cert") -> None:
    """Warn loudly that TLS verification is off, naming the resolved endpoint.

    *base* is the endpoint the caller resolved for the vendor branch being built
    (never whichever base URL merely rides along in the env); *ca_hint* names the
    config knob that would verify a private-CA gateway instead on that route.
    """
    print(f"WARN [{label}]: TLS verification DISABLED (verify_ssl=false) "
          f"for base_url={base or default_endpoint} — prompts, source snippets, "
          f"outputs and the auth header are interceptable by an active MITM. "
          f"Set {ca_hint} to a CA bundle to verify a private-CA gateway instead.",
          file=sys.stderr)


def _restore_env_value(key: str, value: str | None) -> None:
    """Restore *key* to *value*, or delete it entirely when *value* is None."""
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value


@contextmanager
def scoped_no_proxy_env(no_proxy: str | None) -> Iterator[None]:
    """Set NO_PROXY/no_proxy only for httpx's one-time env read at client construction."""
    if not no_proxy:
        yield
        return
    prior = {key: os.environ.get(key) for key in _NO_PROXY_KEYS}
    try:
        os.environ.update(dict.fromkeys(_NO_PROXY_KEYS, no_proxy))
        yield
    finally:
        for key, value in prior.items():
            _restore_env_value(key, value)
