"""Scope and asset-boundary policy for PraiseAssistant.

Pure, standard-library functions that validate engagement scope documents and
decide whether a URL or a local path falls inside an authorized asset. The
runtime and CLI layers delegate all boundary questions here so the rules stay
in one place and remain independently testable.

Boundary rules:

* A URL-scoped asset is an exact origin (scheme + host + port) plus a
  boundary-aware path prefix. A target URL is allowed only when its origin
  matches exactly and its path equals the prefix or descends from it at a path
  segment boundary (``/api/v1`` allows ``/api/v1/users`` but not
  ``/api/v1evil``).
* URLs must not embed credentials, carry a fragment, or smuggle traversal
  through literal or percent-encoded ``..``, ``/``, or ``\\``.
* A directory-scoped asset is an absolute local directory; a local path is
  allowed only when its real path is the directory or descends from it.
"""

from __future__ import annotations

import math
import os
from urllib.parse import urlsplit

#: Engagement modes accepted in a scope document.
ALLOWED_MODES = ("blackbox", "source", "audit", "patch", "development")

#: URL schemes accepted for a URL-scoped asset.
_ALLOWED_SCHEMES = ("http", "https")

#: Literal and percent-encoded byte sequences that can smuggle traversal or
#: ambiguous path boundaries through an otherwise normal-looking URL. Checked
#: against the lower-cased path.
_AMBIGUOUS_TOKENS = (
    "%2e",    # '.'
    "%2f",    # '/'
    "%5c",    # '\'
    "%252e",  # double-encoded '.'
    "%252f",  # double-encoded '/'
    "%255c",  # double-encoded '\'
    "\\",     # literal backslash
)


def classify_asset(asset: str) -> tuple[str, str]:
    """Return ``("url", value)`` or ``("dir", value)`` for an asset string.

    Raises ``ValueError`` for an empty or non-string asset.
    """
    if not isinstance(asset, str) or not asset.strip():
        raise ValueError("asset must be a non-empty string")
    value = asset.strip()
    if value.lower().startswith(("http://", "https://")):
        return ("url", value)
    return ("dir", value)


def split_url(url: str) -> tuple[str, str, int | None, str]:
    """Parse and boundary-validate ``url``; return ``(scheme, host, port, path)``.

    Raises ``ValueError`` on any violation: non-http(s) scheme, embedded
    credentials, missing host, control characters, a fragment, or ambiguous
    traversal/encoding in the path.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("empty URL")
    url = url.strip()
    if any(ord(c) < 0x20 or c == "\x7f" for c in url):
        raise ValueError("URL contains control characters")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ValueError(f"malformed URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"unsupported URL scheme {parts.scheme!r}")
    if not parts.hostname:
        raise ValueError("URL has no host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL must not embed credentials")
    if parts.fragment:
        raise ValueError("URL must not carry a fragment")

    path = parts.path or "/"
    if ".." in path:
        raise ValueError("URL path must not contain traversal segments")
    lowered = path.lower()
    for token in _AMBIGUOUS_TOKENS:
        if token in lowered:
            raise ValueError("URL path contains ambiguous encoding/traversal")

    host = parts.hostname.lower()
    port = parts.port
    return scheme, host, port, path


def validate_url(url: str) -> str:
    """Boundary-validate ``url`` and return it unchanged (or raise ``ValueError``)."""
    split_url(url)
    return url


def _origin_key(parsed: tuple[str, str, int | None, str]) -> tuple[str, str, int | None]:
    scheme, host, port, _ = parsed
    return scheme, host, port


def url_allowed(asset: str, url: str) -> bool:
    """Return ``True`` when ``url`` is inside the boundary of URL ``asset``.

    Both are boundary-validated first; an invalid asset or url raises.
    """
    a_scheme, a_host, a_port, a_path = split_url(asset)
    u_scheme, u_host, u_port, u_path = split_url(url)

    if (a_scheme, a_host, a_port) != (u_scheme, u_host, u_port):
        return False

    # Boundary-aware path prefix: strip a trailing slash, then require the
    # target path to equal the prefix or descend from it at a segment boundary.
    prefix = a_path
    if prefix != "/":
        prefix = prefix.rstrip("/")
    if prefix in ("", "/"):
        return True
    if u_path == prefix:
        return True
    return u_path.startswith(prefix + "/")


def path_allowed(root: str, path: str) -> bool:
    """Return ``True`` when local ``path`` is ``root`` or descends from it.

    Uses ``realpath`` so a symlink that points outside ``root`` never matches.
    """
    try:
        root_real = os.path.realpath(root)
        path_real = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    if not os.path.isdir(root_real):
        return False
    return os.path.commonpath((root_real, path_real)) == root_real


def validate_asset(asset: str, mode: str, require_existing: bool = False) -> str:
    """Validate one asset against ``mode``; return its normalized form.

    ``require_existing`` additionally requires directory assets to exist as
    directories now (used at init time).
    """
    kind, value = classify_asset(asset)
    if mode == "blackbox" and kind != "url":
        raise ValueError(f"mode 'blackbox' requires URL assets, got {value!r}")
    if mode == "source" and kind != "dir":
        raise ValueError(f"mode 'source' requires local directory assets, got {value!r}")

    if kind == "url":
        split_url(value)
        return value

    if not os.path.isabs(value):
        raise ValueError(f"directory asset must be an absolute path: {value!r}")
    if require_existing and not os.path.isdir(value):
        raise ValueError(f"directory asset is not an existing directory: {value!r}")
    return os.path.realpath(value)


def validate_scope(scope: object) -> dict:
    """Validate and normalize a scope document; raise ``ValueError`` on problems.

    Returns a normalized dict that adds ``url_assets`` and ``source_roots``
    derived lists (the latter are the authorized local directory roots the OMP
    extension uses to constrain native reads).
    """
    if not isinstance(scope, dict):
        raise ValueError("scope must be a JSON object")

    program = scope.get("program")
    basis = scope.get("authorization_basis")
    mode = scope.get("mode")
    assets = scope.get("assets")
    methods = scope.get("allowed_methods")

    if not isinstance(program, str) or not program.strip():
        raise ValueError("scope.program must be a non-empty string")
    if not isinstance(basis, str) or not basis.strip():
        raise ValueError("scope.authorization_basis must be a non-empty string")
    if mode not in ALLOWED_MODES:
        raise ValueError(f"scope.mode must be one of {ALLOWED_MODES!r}, got {mode!r}")
    if not isinstance(assets, list) or not assets:
        raise ValueError("scope.assets must be a non-empty array")
    if not isinstance(methods, list) or not methods:
        raise ValueError("scope.allowed_methods must be a non-empty array")

    max_requests = scope.get("max_requests", 0)
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or max_requests < 0:
        raise ValueError("scope.max_requests must be a non-negative integer")

    interval_seconds = scope.get("interval_seconds", 1.0)
    if (
        isinstance(interval_seconds, bool)
        or not isinstance(interval_seconds, (int, float))
        or not math.isfinite(interval_seconds)
        or interval_seconds < 0
    ):
        raise ValueError("scope.interval_seconds must be a finite non-negative number")

    created_at = scope.get("created_at")
    if not isinstance(created_at, str) or not created_at.strip():
        raise ValueError("scope.created_at must be a non-empty string")

    normalized_methods: list[str] = []
    for m in methods:
        if not isinstance(m, str) or not m.strip():
            raise ValueError("scope.allowed_methods entries must be non-empty strings")
        normalized_methods.append(m.strip().upper())

    url_assets: list[str] = []
    source_roots: list[str] = []
    for asset in assets:
        normalized = validate_asset(asset, mode, require_existing=False)
        kind, _ = classify_asset(asset)
        if kind == "url":
            url_assets.append(normalized)
        else:
            source_roots.append(normalized)

    return {
        "program": program.strip(),
        "authorization_basis": basis.strip(),
        "mode": mode,
        "assets": [a if isinstance(a, str) else a for a in assets],
        "allowed_methods": normalized_methods,
        "max_requests": max_requests,
        "interval_seconds": interval_seconds,
        "created_at": created_at.strip(),
        "url_assets": url_assets,
        "source_roots": source_roots,
    }
