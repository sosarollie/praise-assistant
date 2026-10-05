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

"""Environment readiness engine shared by ``vvaharness setup`` and
``vvaharness doctor``.

Pure, side-effect-free detection: each check returns a :class:`Check` with a
status and a human detail. NEVER prints or returns credential material — only
presence (set / unset). The CLI layer renders these; this module never touches
stdout, so it stays unit-testable and reusable.
"""
from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import shutil
import socket
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

from vvaharness import config as config_mod
from vvaharness.backends.harness.provider_routing import routes_to_anthropic
from vvaharness.backends.llm.registry import (
    DEEPAGENTS_ROLES,
    POST_SCAN_ROLES,
    unrecognized_model_keys,
)
from vvaharness.config.constants import LOCAL_OVERLAY_NAME, NO_LOCAL_CONFIG_ENV
from vvaharness.orchestrator.config_paths import _iter_model_roles
from vvaharness.validation.config.validate_role import (
    normalize_validate_backend,
    validate_model_spec,
)

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass(frozen=True)
class Check:
    name: str
    status: str            # OK | WARN | FAIL
    detail: str
    # A FAIL here blocks `setup`/`doctor`, which report "not ready", skip the live
    # probe and exit non-zero. It does NOT gate `scan`: nothing on the scan path
    # calls run_checks — the orchestrator runs its own preflight instead.
    required: bool = False


def _is_set(env: str) -> bool:
    return bool(os.environ.get(env))


def _looks_like_jwt(v: str | None) -> bool:
    """Claude Code / gateway session tokens are JWTs ('eyJ…'); a real Anthropic
    API key is 'sk-ant-…'. We only inspect the PREFIX shape, never log the
    value."""
    if not v:
        return False
    if v.startswith("eyJ"):
        return True
    # Some gateways issue opaque JWT-like session tokens that don't begin with
    # eyJ but still follow the three-segment shape.
    parts = v.split(".")
    if len(parts) == 3 and v.startswith("ey"):
        return all(bool(p) for p in parts)
    return False


def python_check() -> Check:
    """Interpreter floor, read from installed package metadata.

    The literal below is only the metadata-absent fallback (an uninstalled
    source tree); every documented install resolves the real floor from
    ``Requires-Python``. It sits one minor version under that floor, which
    cannot mislabel a live interpreter: a sub-3.11 one cannot import this
    package at all — ``models/vocab.py`` needs ``enum.StrEnum`` (3.11+) — so it
    never reaches this check. Raise it if you like, but that is cosmetic.
    """
    floor = (3, 10)
    try:
        import re
        from importlib.metadata import metadata
        req = metadata("vvaharness").get("Requires-Python") or ""
        m = re.search(r">=\s*(\d+)\.(\d+)", req)
        if m:
            floor = (int(m.group(1)), int(m.group(2)))
    except Exception:
        pass
    cur = ".".join(str(v) for v in sys.version_info[:3])
    if sys.version_info[:2] >= floor:
        return Check("Python", OK, f"{cur} (≥ {floor[0]}.{floor[1]})")
    return Check("Python", FAIL,
                 f"{cur} — requires ≥ {floor[0]}.{floor[1]}", required=True)


def tool_check(cmd: str, why: str, *, required: bool = False) -> Check:
    path = shutil.which(cmd)
    if path:
        return Check(cmd, OK, path)
    return Check(cmd, FAIL if required else WARN, f"not on PATH ({why})",
                 required=required)


# AI coding agents the harness can drive (or that indicate available creds).
# (display, command, the env key that powers it, backend it maps to)
_AGENTS = [
    ("Claude Code", "claude", ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                               "CLAUDE_CODE_OAUTH_TOKEN"), "via:cli"),
    ("OpenAI Codex", "codex", ("OPENAI_API_KEY",), "via:openai"),
    ("Gemini CLI", "gemini", ("GEMINI_API_KEY", "GOOGLE_API_KEY"), "—"),
    ("Cursor Agent", "cursor-agent", (), "—"),
    ("GitHub Copilot CLI", "copilot", (), "via:cli"),
]


def _claude_code_login_present() -> bool:
    if (Path.home() / ".claude" / ".credentials.json").exists():
        return True
    state = Path.home() / ".claude.json"
    if not state.exists():
        return False
    try:
        import json
        data = json.loads(state.read_text(encoding="utf-8"))
    except Exception:
        return False
    return bool(data.get("oauthAccount"))


def agent_checks() -> list[Check]:
    """Detect installed AI agents and whether they are ready to use.
    Presence only — never the key value."""
    out: list[Check] = []
    oauth = _claude_code_login_present()
    for display, cmd, keys, backend in _AGENTS:
        path = shutil.which(cmd)
        if not path:
            out.append(Check(f"agent: {display}", WARN, "not installed"))
            continue
        has_auth = (not keys) or any(_is_set(k) for k in keys) or (cmd == "claude" and oauth)
        if not keys:
            keyinfo = "installed"
        else:
            keyinfo = "installed and logged in" if has_auth else "installed; login not detected"
        status = OK if has_auth else WARN
        out.append(Check(f"agent: {display}", status,
                         f"{cmd} ✓ ({backend}) — {keyinfo}"))
    return out


# (module import name, required for baseline runtime)
_DEPS = [
    ("pydantic", True),
    ("yaml", True),
    ("anthropic", True),
    ("tree_sitter", False),
    ("tree_sitter_language_pack", False),
    ("openai", False),
]


def dep_checks() -> list[Check]:
    out: list[Check] = []
    for mod, required in _DEPS:
        present = importlib.util.find_spec(mod) is not None
        label = {
            "yaml": "PyYAML",
            "tree_sitter": "tree-sitter",
            "tree_sitter_language_pack": "tree-sitter-language-pack",
        }.get(mod, mod)
        if present:
            out.append(Check(f"dep: {label}", OK, "importable"))
        elif required:
            out.append(Check(f"dep: {label}", FAIL, "missing", required=True))
        elif mod == "tree_sitter":
            out.append(Check(
                f"dep: {label}",
                WARN,
                "NOT INSTALLED — call graph falls back to regex (degraded taint coverage)",
            ))
        elif mod == "tree_sitter_language_pack":
            out.append(Check(
                f"dep: {label}",
                WARN,
                "NOT INSTALLED — tree-sitter AST plugins unavailable; call graph degrades",
            ))
        else:
            out.append(Check(f"dep: {label}", WARN,
                             "missing (optional — needed only for via:openai)"))
    return out


def _release(version: str) -> tuple[int, ...]:
    """The numeric release segment of *version*, for ordering comparisons.

    Drops any PEP 440 epoch (``1!0.5.0``) and local segment (``+local``) and
    compares the numeric components left to right, so a two-sided bound inside
    a single major (``<0.200``) orders correctly instead of collapsing to its
    major and rejecting the very versions it allows. Not a full PEP 440
    implementation — ``packaging`` is not a declared dependency and a ceiling
    check does not need one. A prerelease of the ceiling itself (``1.0rc1``
    against ``<1.0``) reads as out of range, which is also what PEP 440 says —
    an exclusive ``<1.0`` already excludes ``1.0rc1`` — and is the safe
    direction regardless, since a 1.0 release candidate carries the same
    breaking change as 1.0.
    """
    import re

    core = version.split("!")[-1].split("+")[0]
    return tuple(int(n) for n in re.findall(r"\d+", core))


def anthropic_version_check() -> Check:
    """The installed ``anthropic`` against the ceiling vvaharness declares.

    The bound is read from our own ``Requires-Dist``, never hardcoded, so it
    cannot drift from ``pyproject.toml`` — the same discipline as
    ``python_check()``. A pin stops a fresh resolve from selecting a breaking
    major; this catches what a pin cannot, an in-place ``pip install -U
    anthropic`` in an already-built environment. It matters because anthropic
    1.0 removed ``temperature`` from the Messages methods, so a ``via:sdk``
    role configured with one raises ``TypeError`` before any request is sent —
    which the backend's 400-handler cannot catch.

    Every path that cannot read a bound degrades to OK rather than raising or
    blocking — a readiness check must never be the thing that breaks
    ``doctor``.
    """
    import re

    try:
        installed = importlib.metadata.version("anthropic")
    except importlib.metadata.PackageNotFoundError:
        # Deliberately not a FAIL: `dep: anthropic` above already blocks when
        # the package cannot be imported, and the two probe different things —
        # that row uses find_spec, this one needs .dist-info. A hand-vendored
        # copy (a package directory with no .dist-info) is importable with no
        # metadata, so say precisely that rather than contradicting the row
        # above. Note `pip install --target` is NOT such a case: it writes the
        # .dist-info alongside, so metadata resolves normally.
        return Check("anthropic version", OK,
                     "no version metadata found (see dep: anthropic)")
    try:
        reqs = importlib.metadata.requires("vvaharness") or []
    except importlib.metadata.PackageNotFoundError:
        reqs = []  # running from a source tree, with no distribution metadata
    # `[` so a future extra ("anthropic[vertex]<1.0") still matches rather than
    # silently disabling the check.
    spec = next((r for r in reqs if re.match(r"anthropic\s*[\[<>=!~]", r)), "")
    # Match the ceiling clause wherever it sits: packaging NORMALISES a
    # two-sided requirement and emits the upper bound FIRST
    # ("anthropic<1.0,>=0.125.0"), so neither clause's position can be assumed.
    ceiling = re.search(r"<\s*(\d[^,\s]*)", spec)
    if not ceiling:
        return Check("anthropic version", OK,
                     f"{installed} (no declared ceiling to check against)")
    if _release(installed) < _release(ceiling.group(1)):
        return Check("anthropic version", OK,
                     f"{installed} (supported: <{ceiling.group(1)})")
    return Check(
        "anthropic version", FAIL,
        f"{installed} is out of the supported range — run "
        f"`pip install 'anthropic<{ceiling.group(1)}'`. anthropic 1.0 removed "
        f"`temperature` from the Messages methods, so a via:sdk model "
        f"configured with one fails before any request is sent.",
        required=True)


# Credential env vars we report presence for (NEVER the value).
_CRED_ENVS = [
    "ANTHROPIC_SDK_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY", "GEMINI_API_KEY",
    "GITHUB_TOKEN",
]


def credential_checks() -> list[Check]:
    out: list[Check] = []
    for env in _CRED_ENVS:
        out.append(Check(f"cred: {env}", OK if _is_set(env) else WARN,
                         "set" if _is_set(env) else "unset"))
    return out


# ── LangChain → LangSmith tracing (undocumented-egress hazard) ────────────────
# langchain-core (the DeepAgents backend's model layer) consults
# langsmith.utils.tracing_is_enabled() before every run and, when it returns
# True, attaches a tracer that uploads each prompt — which embeds scanned
# repository source — and each model completion to the configured LangSmith
# service. Verified against the installed langsmith 0.11.1:
#   - langchain_core/tracers/context.py:132-135 and
#     langchain_core/callbacks/manager.py:2497 call tracing_is_enabled().
#   - langsmith/utils.py:141-142 — the environment gate is
#     get_env_var("TRACING_V2", default=get_env_var("TRACING", default=""))
#     and tracing is on iff that value == "true" (exact string).
#   - langsmith/utils.py:419-442 — get_env_var checks the ("LANGSMITH",
#     "LANGCHAIN") namespaces in order and returns the first non-empty value.
# Net precedence, most-specific first (a non-"true" value in an earlier
# variable DISABLES tracing even if a later one says "true"):
_TRACING_GATE_ENVS = (
    ("LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING_V2"),   # TRACING_V2 lookup
    ("LANGSMITH_TRACING", "LANGCHAIN_TRACING"),         # its TRACING fallback
)
# Upload credential (presence reported, value NEVER printed). Without it the
# hosted service rejects the upload with 401 — but the client still POSTs the
# run payload (langsmith/client.py:729-738 merely warns on a missing key), so
# the prompt bytes leave the machine either way.
_TRACING_KEY_ENVS = ("LANGSMITH_API_KEY", "LANGCHAIN_API_KEY")


def _langsmith_tracing_gate() -> str | None:
    """The env var that switches LangChain→LangSmith tracing ON, or None.

    Replicates langsmith.utils.tracing_is_enabled()'s environment fallback
    exactly (citations above) instead of calling it: the library lru_caches
    its env reads (utils.py:418), which would freeze the answer for the
    process, and importing langsmith here would make a transitive dependency
    load-bearing for doctor.
    """
    for group in _TRACING_GATE_ENVS:
        for name in group:
            v = os.environ.get(name)
            if v is not None and v.strip() != "":
                # First non-empty value in the group wins outright; only the
                # exact string "true" enables tracing (utils.py:142).
                return name if v == "true" else None
    return None


def langsmith_tracing_check() -> Check:
    """Warn when LangSmith tracing would exfiltrate prompt payloads.

    WARN, never FAIL: an operator may be deliberately tracing in a lab. The
    API key is reported by PRESENCE only, per this module's no-values rule.
    """
    gate = _langsmith_tracing_gate()
    if gate is None:
        return Check("LangSmith tracing", OK,
                     "disabled (no LANGSMITH_TRACING* / LANGCHAIN_TRACING* "
                     "gate variable is \"true\")")
    if importlib.util.find_spec("langsmith") is None:
        return Check("LangSmith tracing", OK,
                     f"{gate}=true is set, but the langsmith package is not "
                     "installed — no tracing can occur")
    key = next((k for k in _TRACING_KEY_ENVS if _is_set(k)), None)
    key_note = (f" {key} is also set, so the upload will be accepted."
                if key else
                " No LANGSMITH_API_KEY/LANGCHAIN_API_KEY is set, so the "
                "service will reject the upload — but the payload is still "
                "transmitted.")
    return Check(
        "LangSmith tracing", WARN,
        f"{gate}=true — every model prompt (which contains scanned "
        "repository source) and every completion will be sent to the "
        "LangSmith service, a third-party egress channel this tool does not "
        f"otherwise use.{key_note} Unset {gate} unless you are deliberately "
        "tracing in an isolated lab.")


def _gateway_check() -> Check:
    """The exact trap we hit: a JWT-shaped ANTHROPIC_API_KEY with no
    ANTHROPIC_BASE_URL → it is a gateway/Claude-Code token that will 401
    against the public Anthropic API. Flag it loudly with the remedy."""
    base = os.environ.get("ANTHROPIC_BASE_URL")
    key = os.environ.get("ANTHROPIC_API_KEY")
    if base:
        # Strip any query string before echoing — a token embedded as a query
        # parameter must not be printed by doctor/setup.
        return Check("via:sdk endpoint", OK,
                     f"ANTHROPIC_BASE_URL={base.split('?', 1)[0]}")
    if _looks_like_jwt(key):
        return Check("via:sdk endpoint", FAIL,
                     "ANTHROPIC_API_KEY looks like a gateway/Claude-Code token "
                     "(eyJ…) but ANTHROPIC_BASE_URL is unset — it will 401 "
                     "against the public API. Set ANTHROPIC_BASE_URL to your "
                     "gateway (and SSL_CERT_FILE — or sdk.ca_cert in the "
                     "profile — if it needs a private CA).",
                     required=True)
    return Check("via:sdk endpoint", OK, "public api.anthropic.com (default)")


_RC_FILES = (".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile")
_BASE_URL_RX = None  # compiled lazily


def detect_gateway() -> tuple[str | None, str | None]:
    """Find a usable ANTHROPIC_BASE_URL even if the user hasn't exported it.
    Order: live env → a (possibly commented-out) export in the shell rc files.
    Returns (url, source) or (None, None). Reads only; never writes."""
    import re
    live = os.environ.get("ANTHROPIC_BASE_URL")
    if live:
        return live, "environment"
    rx = re.compile(r'ANTHROPIC_BASE_URL\s*=\s*["\']?(https?://[^"\'\s]+)')
    for name in _RC_FILES:
        p = Path.home() / name
        if not p.is_file():
            continue
        try:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                m = rx.search(line)
                if m:
                    return m.group(1), f"~/{name}"
                    # (commented lines match too — that's the point: surface it)
        except OSError:
            continue
    return None, None


def detect_ca_cert() -> str | None:
    """A private-CA bundle the gateway may need (NODE_EXTRA_CA_CERTS), or the
    conventional ~/cacerts.pem if present."""
    env_cert = os.environ.get("NODE_EXTRA_CA_CERTS")
    if env_cert and Path(env_cert).is_file():
        return env_cert
    default = Path.home() / "cacerts.pem"
    return str(default) if default.is_file() else None


def recommend_profile() -> tuple[str | None, str]:
    """Suggest the shipped profile that matches the credentials actually
    available. This is a starting-profile recommendation, not a claim that
    every enabled post-scan stage is ready; ``config_check`` reports those
    provider credentials separately.
    Returns (profile_name, reason)."""
    # `default.yaml` routes S1-S11 through deepagents/Anthropic, so a standard
    # Anthropic credential can cover the whole run. Keep this as a starting
    # recommendation only; config_check reports exact route gaps below.
    cli_auth = shutil.which("claude") and (
        _looks_like_jwt(os.environ.get("ANTHROPIC_API_KEY"))
        or _is_set("ANTHROPIC_AUTH_TOKEN")
        or _is_set("CLAUDE_CODE_OAUTH_TOKEN")
        or _claude_code_login_present())
    if cli_auth and _is_set("ANTHROPIC_SDK_API_KEY"):
        return "default", ("Claude Code auth and ANTHROPIC_SDK_API_KEY both "
                           "present — default.yaml routes through "
                           "deepagents/Anthropic and setup checks any "
                           "remaining provider gaps separately")
    if cli_auth:
        return "default", ("Claude Code auth detected — default.yaml uses "
                           "deepagents/Anthropic; set ANTHROPIC_API_KEY, "
                           "ANTHROPIC_AUTH_TOKEN, or ANTHROPIC_SDK_API_KEY "
                           "before scanning")
    # Without CLI auth, suggest the profile associated with an available API
    # key. Later checks still report any other credentials that profile needs.
    if _is_set("ANTHROPIC_SDK_API_KEY"):
        return "sdk", ("ANTHROPIC_SDK_API_KEY is set — sdk.yaml routes model "
                       "roles via sdk; setup checks the S11 credential separately")
    if _is_set("OPENAI_API_KEY"):
        return "full", ("OPENAI_API_KEY is set — full.yaml includes OpenAI "
                        "roles; setup checks its other backends separately")
    return None, "no usable credential detected yet"


def dotenv_check() -> Check:
    """Report the trusted cwd/home .env selected by CLI startup, if present."""
    from vvaharness.cli import _dotenv_selection

    path, source, rejected = _dotenv_selection()
    ignored = ", ".join(str(p) for p in rejected)
    if path is None:
        if rejected:
            return Check(".env", WARN, f"ignored untrusted file(s): {ignored}")
        return Check(".env", OK, "not found (optional; use setup --write-env)")
    detail = ".env found" if source == "cwd" else f"{path} found"
    if rejected:
        return Check(".env", WARN, f"{detail}; ignored untrusted file(s): {ignored}")
    return Check(".env", OK, detail)


def _applied_overlay_check(name: str, local: Path, cfg_path: str | Path) -> Check:
    """Render a trusted overlay's overridden leaf keys with resolved values."""
    try:
        over = yaml.safe_load(local.read_text(encoding="utf-8")) or {}
        cfg = config_mod.load(cfg_path)
    except (OSError, ValueError, yaml.YAMLError) as e:
        return Check(name, FAIL, f"{local} failed to load: {e}", required=True)
    if not isinstance(over, dict):
        return Check(name, FAIL, f"{local} must be a YAML mapping", required=True)
    detail = ", ".join(config_mod._overlay_override_entries(
        config_mod._leaf_paths(over), cfg._data)) or "(empty)"
    return Check(name, OK, f"{local} applied (overrides: {detail})")


def overlay_check(cfg_path: str | Path) -> Check:
    """config.local.yaml status: absent, skipped, untrusted, or the applied overrides."""
    name = "config overlay"
    local = Path(cfg_path).with_name(LOCAL_OVERLAY_NAME)
    if not local.exists():
        check = Check(name, OK, f"{LOCAL_OVERLAY_NAME} not found (optional)")
    elif os.environ.get(NO_LOCAL_CONFIG_ENV):
        check = Check(name, OK,
                      f"{local} present but skipped ({NO_LOCAL_CONFIG_ENV} set)")
    elif (getattr(os, "geteuid", None) is not None
            and not config_mod._local_overlay_trusted(local)):
        check = Check(
            name, FAIL,
            f"{local} untrusted — must be owned by the invoking user (or "
            f"root) and not group/world-writable; `chmod go-w` / `chown` it, "
            f"or set {NO_LOCAL_CONFIG_ENV} to skip it",
            required=True)
    else:
        check = _applied_overlay_check(name, local, cfg_path)
    return check


def _via_gap_check(name: str, gap: str, roles: set[str], *,
                   hint: str = "") -> Check:
    """Grade a backend credential/tool gap the way preflight does.

    Mirrors ``preflight._report_credential_gap``: a gap any detection role
    depends on is a blocking FAIL; one confined to the post-scan roles
    (S10/S11) is advisory, because the scan's own gates skip those stages.
    *hint* is an optional remedy suffix appended to the blocking detail.
    """
    if not (roles <= POST_SCAN_ROLES):
        return Check(name, FAIL, f"{gap} (required by this profile){hint}",
                     required=True)
    return Check(name, WARN,
                 f"{gap} (required only by {', '.join(sorted(roles))} — "
                 "that stage will be skipped)")


def config_check(cfg_path: str | Path) -> list[Check]:
    """Confirm the active profile loads and report which backends it uses and
    whether the credential each backend needs is present."""
    p = Path(cfg_path)
    if not p.exists():
        return [Check("config", FAIL, f"not found: {p}", required=True)]
    try:
        from vvaharness import config as config_mod
        cfg = config_mod.load(p)
    except Exception as e:  # noqa: BLE001
        return [Check("config", FAIL, f"failed to load {p}: {e}", required=True)]
    cwd_cfg = Path.cwd() / "config.yaml"
    if p.resolve() == cwd_cfg.resolve():
        detail = "config.yaml loads"
    elif not cwd_cfg.exists():
        detail = (f"{p.name} loads — create ./config.yaml for local defaults "
                  f"(config.yml is not auto-loaded)")
    else:
        detail = f"{p.name} loads"
    out = [Check("config", OK, detail)]
    # Resolve roles through preflight's own _iter_model_roles — the single
    # role list, the validate → orchestrator unwrap, and the §14.5 callgraph
    # guard all live there. Hand-rolling the walk here once injected a phantom
    # `cli` backend (the raw `validate` wrapper has no .via), making doctor
    # and scan disagree about which credentials a profile needs.
    nodes: dict[str, object] = dict(_iter_model_roles(cfg))
    # via → the roles that depend on it: decides whether a credential gap is
    # fatal (touches a detection role) or advisory (post-scan only), exactly
    # like preflight._report_credential_gap.
    roles_by_via: dict[str, set[str]] = {}
    for r, node in nodes.items():
        roles_by_via.setdefault((getattr(node, "via", None) or "cli"), set()).add(r)
    vias = set(roles_by_via)
    out.append(Check("active backends", OK, ", ".join(sorted(vias)) or "(none)"))
    invalid_deepagents = sorted(
        r for r, node in nodes.items()
        if (getattr(node, "via", None) or "cli") == "deepagents"
        and r not in DEEPAGENTS_ROLES
    )
    if invalid_deepagents:
        # Supported-role list derived from the frozenset so this text can
        # never drift from the gate's actual membership again.
        supported = ", ".join(f"models.{r}" for r in sorted(DEEPAGENTS_ROLES))
        out.append(Check(
            "via:deepagents roles",
            FAIL,
            f"supported only for {supported}; invalid "
            f"role(s): {', '.join(invalid_deepagents)}",
            required=True,
        ))
    # Same derivation as preflight.check_backends: an unknown key is read by
    # no consumer, so a typo silently changes nothing — advisory, never fatal.
    unknown_keys = [
        f"models.{r}.{key}"
        for r, node in nodes.items()
        for key in unrecognized_model_keys(node)
    ]
    if unknown_keys:
        out.append(Check(
            "model config keys",
            WARN,
            f"unrecognized model key(s) ignored: {', '.join(unknown_keys)}",
        ))
    if "sdk" in vias:
        out.append(_gateway_check())
        sdk_cfg = getattr(cfg, "sdk", None)
        has_sdk_key = (_is_set("ANTHROPIC_SDK_API_KEY")
                       or bool(getattr(sdk_cfg, "api_key", None)))
        # Same sdk_sole predicate as preflight.configure_backends() — the
        # canonical rationale for the shared-credential fallback lives there.
        sdk_sole = vias <= {"sdk", "deepagents"}
        fallback = sdk_sole and (_is_set("ANTHROPIC_API_KEY")
                                 or _is_set("ANTHROPIC_AUTH_TOKEN"))
        if has_sdk_key:
            pass  # SDK-specific key present — nothing to flag
        elif fallback:
            out.append(Check("via:sdk credential", OK,
                             "ANTHROPIC_SDK_API_KEY unset — using "
                             "ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN fallback "
                             "(no via:cli role in this profile)"))
        else:
            hint = (" — or set ANTHROPIC_API_KEY (accepted as a fallback)"
                    if sdk_sole else "")
            out.append(_via_gap_check("via:sdk credential",
                                      "ANTHROPIC_SDK_API_KEY not set",
                                      roles_by_via["sdk"], hint=hint))
        # The profile also reads three OPTIONAL SDK knobs via ${ENV}. Unset is
        # valid (public api.anthropic.com, system trust store, no mTLS) — so
        # these are never blocking — but surface presence so an enterprise /
        # gateway user knows the levers exist and which env var sets each.
        for env_name, attr, note in (
            ("ANTHROPIC_SDK_BASE_URL", "base_url",
             "gateway endpoint — defaults to public api.anthropic.com"),
            ("ANTHROPIC_SDK_CA_CERT", "ca_cert",
             "gateway CA bundle — only for a private-CA gateway"),
            ("ANTHROPIC_SDK_CLIENT_CERT", "client_cert",
             "client cert for mTLS — off when unset"),
        ):
            present = _is_set(env_name) or bool(getattr(sdk_cfg, attr, None))
            out.append(Check(f"via:sdk {env_name}", OK if present else WARN,
                             "set" if present else f"unset (optional: {note})"))
    if "openai" in vias and not _is_set("OPENAI_API_KEY"):
        out.append(_via_gap_check("via:openai credential",
                                  "OPENAI_API_KEY not set",
                                  roles_by_via["openai"]))
    if "cli" in vias and not shutil.which("claude"):
        out.append(_via_gap_check("via:cli backend",
                                  "`claude` CLI not on PATH",
                                  roles_by_via["cli"]))
    out += _deepagents_checks(nodes, cfg=cfg, gateway_done="sdk" in vias)
    # Profile-controlled post-scan steps (s10 remediate / s11 validate) never block
    # the core scan — when misconfigured the orchestrator disables the step and
    # continues — so their checks are advisory (WARN), but surfacing them here
    # tells an operator who enabled the flags whether the step will actually run.
    out += _remediate_checks(cfg)
    out += _validate_checks(cfg)
    return out


def remediation_inputs_check() -> Check:
    """Ensure fail-closed remediation defaults are available."""
    from vvaharness.remediation_agent import rule_paths
    missing = rule_paths.missing_rules(rule_paths.__file__)
    configured = rule_paths.configured_inputs_dir()
    if not missing:
        detail = (f"using {configured}" if configured else
                  "bundled policy and playbook available")
        return Check("remediation inputs", OK, detail)
    return Check(
        "remediation inputs", FAIL,
        f"missing {', '.join(missing)}; run interactive `vvaharness setup` "
        "to select the inputs directory", required=True)


def _backend_credential_ok(
    via: str, model_id: str = "", provider: str | None = None,
    *, cfg: object | None = None,
) -> tuple[bool, str]:
    """(ready, detail) for a model role's backend. Presence only — never the value.

    *cfg* (the loaded config, optional) lets the deepagents branch also accept
    a config-provided ``sdk.api_key`` / ``openai.api_key`` — the credential
    the runtime actually exports for that route (see
    ``provider_routing.credential_env_overrides``). The default ``cfg=None``
    preserves the env-only behaviour for callers that do not pass it.
    """
    if via == "cli":
        if shutil.which("claude"):
            return True, "`claude` CLI on PATH"
        return False, "`claude` CLI not on PATH"
    if via == "sdk":
        if (_is_set("ANTHROPIC_SDK_API_KEY") or _is_set("ANTHROPIC_API_KEY")
                or _is_set("ANTHROPIC_AUTH_TOKEN")):
            return True, "Anthropic SDK credential present"
        return False, ("ANTHROPIC_SDK_API_KEY not set "
                       "(or ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN)")
    if via == "openai":
        if _is_set("OPENAI_API_KEY"):
            return True, "OPENAI_API_KEY set"
        return False, "OPENAI_API_KEY not set"
    if via == "deepagents":
        return _deepagents_credential_ok(model_id, provider, cfg)
    return True, f"via:{via}"


def _cfg_api_key_present(cfg: object | None, block: str) -> bool:
    """Whether the profile itself binds an ``api_key`` under *block*
    (``sdk``/``openai``). Presence only — the value is never read out."""
    return bool(getattr(getattr(cfg, block, None), "api_key", None))


def _deepagents_credential_ok(
    model_id: str, provider: str | None, cfg: object | None
) -> tuple[bool, str]:
    """Deepagents credential presence for the resolved vendor route.

    Accepts the matching config block's ``api_key`` as satisfying the
    credential: at runtime ``credential_env_overrides`` exports exactly that
    key (``sdk.api_key`` for the Anthropic route, ``openai.api_key``
    otherwise) before the model is built, so a key bound in the profile is as
    good as one in the environment.
    """
    if not routes_to_anthropic(model_id, provider):
        if _cfg_api_key_present(cfg, "openai") or _is_set("OPENAI_API_KEY"):
            return True, "OpenAI-compatible DeepAgents credential present"
        return False, ("OPENAI_API_KEY not set "
                       "(set OPENAI_BASE_URL for a custom endpoint)")
    if (_cfg_api_key_present(cfg, "sdk") or _is_set("ANTHROPIC_API_KEY")
            or _is_set("ANTHROPIC_AUTH_TOKEN")):
        return True, "Anthropic-compatible DeepAgents credential present"
    return False, "ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN not set"


def _deepagents_targets(
    nodes: dict[str, object],
) -> dict[tuple[str, str | None], set[str]]:
    """(model_id, provider) -> roles, for every active via:deepagents role.

    Credentials are per target, not per via: one profile may route different
    deepagents roles to different vendors, so each pair is checked on its own.
    """
    targets: dict[tuple[str, str | None], set[str]] = {}
    for role, node in nodes.items():
        if (getattr(node, "via", None) or "cli") != "deepagents":
            continue
        key = (str(getattr(node, "id", "") or ""), getattr(node, "provider", None))
        targets.setdefault(key, set()).add(role)
    return targets


def _deepagents_checks(nodes: dict[str, object], *, cfg: object | None,
                       gateway_done: bool) -> list[Check]:
    """Doctor's static credential pass for ``via: deepagents`` roles.

    A credential gap touching any detection role blocks (a scan that cannot
    detect must not start); a gap confined to post-scan roles (S10/S11) is
    advisory, because the scan's own gates skip those stages. *cfg* is the
    loaded config, so a profile-bound ``sdk.api_key`` / ``openai.api_key``
    counts as the credential (it is what the runtime exports). Appends the
    gateway check when a deepagents target resolves to Anthropic — the same
    JWT-shaped ANTHROPIC_API_KEY / missing ANTHROPIC_BASE_URL trap via:sdk
    already flags — unless *gateway_done* says the sdk branch added it.
    """
    out: list[Check] = []
    anthropic_route = False
    targets = _deepagents_targets(nodes)
    # Sort on a total order: provider is None for name-inferred targets, which
    # would make a bare tuple comparison against a str provider raise.
    for (model_id, provider), roles in sorted(
            targets.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        anthropic_route = anthropic_route or routes_to_anthropic(model_id, provider)
        ready, detail = _backend_credential_ok("deepagents", model_id, provider,
                                               cfg=cfg)
        blocking = not (roles <= POST_SCAN_ROLES)
        status = OK if ready else (FAIL if blocking else WARN)
        out.append(Check(
            f"via:deepagents {model_id}", status,
            detail + ("" if ready else f" (role(s): {', '.join(sorted(roles))})"),
            required=blocking and not ready,
        ))
    if anthropic_route and not gateway_done:
        # Same trap as via:sdk, relabelled: deepagents-Anthropic reads
        # ANTHROPIC_API_KEY directly, so a JWT-shaped value with no
        # ANTHROPIC_BASE_URL will 401 against the public endpoint.
        gw = _gateway_check()
        out.append(Check("via:deepagents endpoint", gw.status, gw.detail,
                         required=gw.required))
    return out


def _remediate_checks(cfg) -> list[Check]:
    """Step-10 readiness — empty unless ``step_remediate.enabled``. Mirrors
    ``orchestrator.scan._remediate_preflight``: needs a configured
    ``models.remediate`` role whose backend credential is present."""
    if not getattr(getattr(cfg, "step_remediate", None), "enabled", False):
        return []
    rem = getattr(getattr(cfg, "models", None), "remediate", None)
    if rem is None:
        return [Check("step10: remediate", WARN,
                      "step_remediate.enabled but models.remediate is unset "
                      "— remediation will be skipped")]
    via = getattr(rem, "via", "cli")
    ready, detail = _backend_credential_ok(via, getattr(rem, "id", ""),
                                           getattr(rem, "provider", None), cfg=cfg)
    return [Check("step10: remediate", OK if ready else WARN,
                  f"via:{via} — {detail}"
                  + ("" if ready else " — remediation will be skipped"))]


def _validate_checks(cfg) -> list[Check]:
    """Step-11 readiness — empty unless ``step_validate.enabled``. Mirrors the
    s11 preflight: the legacy via:openai backend is routed to DeepAgents (so the
    credential reported is the one s11 will actually use), and the bundled
    ``claude_agent_sdk`` must be importable. The hoisted via:deepagents route is
    supported."""
    if not getattr(getattr(cfg, "step_validate", None), "enabled", False):
        return []
    out: list[Check] = []
    val = validate_model_spec(cfg)
    if val is None:
        out.append(Check("step11: validate", WARN,
                         "step_validate.enabled but models.validate.orchestrator is unset "
                         "— validation will be skipped"))
    else:
        raw_via = getattr(val, "via", "cli")
        via, provider = normalize_validate_backend(raw_via, getattr(val, "provider", None))
        ready, detail = _backend_credential_ok(via, getattr(val, "id", ""),
                                               provider, cfg=cfg)
        routed = f" (via:{raw_via} routed to {via})" if via != raw_via else ""
        out.append(Check("step11: validate", OK if ready else WARN,
                         f"via:{via} — {detail}{routed}"
                         + ("" if ready else " — validation will be skipped")))
    if importlib.util.find_spec("claude_agent_sdk") is not None:
        out.append(Check("step11: claude_agent_sdk", OK,
                         "claude_agent_sdk importable"))
    else:
        out.append(Check("step11: claude_agent_sdk", WARN,
                         "claude_agent_sdk missing — reinstall vvaharness (pip install .)"))
    return out


def tls_check() -> Check:
    """Definitively determine whether a private CA bundle is needed: do a real
    TLS handshake to the active Anthropic endpoint using the system trust store
    (plus NODE_EXTRA_CA_CERTS if set). This is how setup tells a *public* user
    ("no CA needed") apart from an *enterprise gateway* user whose endpoint
    chains to a corporate root CA. No tokens spent — just a TLS handshake.

    - verifies cleanly        → OK   (public/trusted CA, or the configured bundle works)
    - certificate not trusted → FAIL (needs the org CA bundle; auto-suggests one)
    - network/DNS/timeout     → WARN (can't determine here; the live probe will)"""
    base = os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com"
    u = urlparse(base if "://" in base else f"https://{base}")
    host, port = u.hostname or "api.anthropic.com", u.port or 443
    cafile = os.environ.get("NODE_EXTRA_CA_CERTS")
    use_bundle = bool(cafile and Path(cafile).is_file())
    try:
        ctx = ssl.create_default_context(cafile=cafile if use_bundle else None)
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass
        # NODE_EXTRA_CA_CERTS proves reach for this probe, but at scan time
        # only via:cli (and deepagents-OpenAI) read it — via:sdk and
        # deepagents-Anthropic ignore it, so say so instead of false-greening.
        src = (" via NODE_EXTRA_CA_CERTS — note: via:sdk and "
               "deepagents-Anthropic ignore that variable; they need "
               "SSL_CERT_FILE or sdk.ca_cert"
               if use_bundle else " (system trust store)")
        return Check("TLS / CA cert", OK,
                     f"{host}:{port} verified{src} — no extra CA bundle needed"
                     if not use_bundle else f"{host}:{port} verified{src}")
    except ssl.SSLCertVerificationError:
        # Name the variable each route actually honours: SSL_CERT_FILE covers
        # via:sdk and via:deepagents (both vendors); only the via:cli Node
        # subprocess reads NODE_EXTRA_CA_CERTS.
        ca = detect_ca_cert()
        hint = ((f" A bundle was detected — run: export SSL_CERT_FILE={ca} "
                 f"(covers via:sdk and via:deepagents; via:cli reads "
                 f"NODE_EXTRA_CA_CERTS={ca} instead).")
                if ca else
                " Point SSL_CERT_FILE at your org's CA bundle (covers "
                "via:sdk and via:deepagents; via:cli reads "
                "NODE_EXTRA_CA_CERTS instead).")
        return Check("TLS / CA cert", FAIL,
                     f"{host} presents a certificate the system trust store does "
                     f"not accept — this machine reaches it through a private CA "
                     f"(an internal gateway or a TLS-intercepting corporate "
                     f"proxy), so you need your org's CA bundle.{hint}")
    except Exception as e:  # noqa: BLE001 — DNS/timeout/proxy: can't decide here
        return Check("TLS / CA cert", WARN,
                     f"could not verify {host}:{port} ({type(e).__name__}) — "
                     f"skipping CA determination; the live probe will confirm")


def run_checks(cfg_path: str | Path) -> list[Check]:
    """The full readiness report, in display order."""
    checks: list[Check] = [python_check(),
                           tool_check("git", "batch --repo-file cloning"),
                           tool_check("pip3", "installing optional extras")]
    checks += agent_checks()
    checks += credential_checks()
    # Advisory egress guard: fires whenever the process environment would let
    # langchain-core upload prompt payloads (scanned source) to LangSmith.
    checks.append(langsmith_tracing_check())
    checks += dep_checks()
    # Reads with the `dep: anthropic` row above it: that one says whether the
    # package is importable, this one whether its version is one we support.
    checks.append(anthropic_version_check())
    checks.append(tls_check())
    checks.append(remediation_inputs_check())
    cfg_checks = config_check(cfg_path)
    if cfg_checks:
        checks.append(cfg_checks[0])
        checks.append(dotenv_check())
        checks.append(overlay_check(cfg_path))
        checks += cfg_checks[1:]
    return checks


def summarize(checks: list[Check]) -> tuple[int, int, int]:
    """(#ok, #warn, #fail-required) — required fails are what block a scan."""
    n_ok = sum(1 for c in checks if c.status == OK)
    n_warn = sum(1 for c in checks if c.status == WARN)
    n_blocking = sum(1 for c in checks if c.status == FAIL and c.required)
    return n_ok, n_warn, n_blocking
