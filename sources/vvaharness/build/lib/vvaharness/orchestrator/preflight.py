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


"""orchestrator.preflight — see package docstring."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from vvaharness.backends.llm import cli, sdk
from vvaharness.backends.llm import openai as oai
from vvaharness.backends.llm.models import validate_detection_tools
from vvaharness.backends.llm.registry import (
    DEEPAGENTS_ROLES,
    POST_SCAN_ROLES,
    unrecognized_model_keys,
    use_responses_api_of,
)
from vvaharness.backends.llm.registry import resolve as resolve_model
from vvaharness.backends.llm.tls import coerce_verify
from vvaharness.orchestrator.config_paths import _iter_model_roles, _resolve_against
from vvaharness.report.redact import redact
from vvaharness.backends.harness.models import (
    DegenerateResponseError,
    TruncatedResponseError,
)
from vvaharness.util.response_quality import stage_floors
from vvaharness.util.tokens import TOKENS
from vvaharness.util.tokens import (  # noqa: F401 — re-export; test_s4_prompt_order imports it
    estimate_tokens as estimate_tokens,
)





def _resolve_verify_path(cfg_dir: Path, value: object) -> object:
    """Anchor a CA-bundle path supplied via ``verify_ssl`` at the profile dir.

    ``verify_ssl`` is a tri-state: a real bool, a string boolean literal, or a
    CA-bundle PATH. Only the path form may be resolved — running ``"false"``
    through :func:`_resolve_against` would turn a boolean into the filename
    ``<cfg_dir>/false``. :func:`coerce_verify` is the discriminator: it returns a
    ``str`` only for the path form.

    Resolving matters for more than relative paths: ``_resolve_against`` is also
    where UNC/SMB inputs are refused, and a CA path is read by the TLS stack. A
    raw ``verify_ssl: //host/share/ca.pem`` would otherwise reach that read and
    leak an NTLM hash on Windows — the exact vector that guard exists to block.

    The emptiness test is load-bearing, not defensive noise: ``coerce_verify("")``
    returns ``""`` (it is a string matching no boolean literal), and
    ``Path("")`` is ``Path(".")``, so resolving it would yield the PROFILE
    DIRECTORY and hand the TLS stack a directory as its CA bundle.
    """
    coerced = coerce_verify(value)
    if isinstance(coerced, str) and coerced.strip():
        return _resolve_against(cfg_dir, coerced)
    return value


def _resolve_cert_chain(cfg_dir: Path, cert: object) -> object:
    """Anchor a client chain at the profile dir, for both accepted shapes.

    A combined-PEM path arrives as ``str``; a ``(cert, key)`` pair arrives as a
    tuple, or as a **list** when it came from YAML. Those file paths get the same
    profile-dir anchoring and UNC refusal as the single-file form.

    ONLY the first two members are paths. httpx/ssl accept a third — the private
    key's PASSWORD — and resolving that would both corrupt it into
    ``<cfg_dir>/<password>`` (silently killing mTLS for an encrypted key) and
    risk echoing it: ``_resolve_against``'s UNC refusal puts the offending value
    in its exception message. It is passed through untouched.

    Members are mapped positionally, never filtered. Dropping an empty member
    would renumber the rest, turning ``["cert.pem", ""]`` into a one-element
    chain — i.e. silently reinterpreting a pair as a combined PEM with no key.
    """
    if isinstance(cert, str):
        return _resolve_against(cfg_dir, cert)
    if isinstance(cert, (tuple, list)):
        return tuple(
            _resolve_against(cfg_dir, m)
            if i < 2 and isinstance(m, str) and m.strip() else m
            for i, m in enumerate(cert)
        )
    return cert


def _mask(v: str | None) -> str:
    """Credential PRESENCE only — never emit key material, a prefix, or the
    length. Even a masked prefix/length leaks the token type and size into
    terminals, CI logs, and screen-shares; for a security tool we report binary
    presence and nothing more."""
    return "set ✓" if v else "<unset>"


def configure_backends(cfg, cfg_dir: Path) -> None:
    """Apply cfg.sdk / cfg.openai / cfg.cli (api_key, base_url, TLS/proxy) to the
    backend clients. Called by main() before scanning AND by `vvaharness doctor`
    so the live preflight probe in check_backends() hits the same
    gateway/credentials the real scan will use."""
    # One Anthropic credential may serve sdk and deepagents; only `cli` (whose
    # token is a gateway JWT consumed by the `claude` subprocess) must keep its
    # own. So the SDK's ANTHROPIC_API_KEY/AUTH_TOKEN fallback stays available
    # unless a via:cli role shares the run — deepagents reads ANTHROPIC_API_KEY
    # directly while sdk merely PREFERS ANTHROPIC_SDK_API_KEY; the two never
    # compete for the same env name. Mirrors the same condition in
    # check_backends() and doctor's config_check().
    vias = {resolve_model(m).via for _, m in _iter_model_roles(cfg)}
    sdk_sole = vias <= {"sdk", "deepagents"}

    # Prompt-cache settings are top-level, because they are properties of the
    # model route rather than of any one credential block — so they are pushed
    # UNCONDITIONALLY, before the per-backend blocks below. Gating them on the
    # presence of an `sdk:`/`openai:` section would make the marker kill switch
    # unreachable for a config that omits those sections, and the kill switch is
    # the escape hatch for an operator whose endpoint rejects a cache field.
    # The same applies to `cache_route`: it is the only way a config with no
    # `sdk:` section can declare its gateway's marker regime (or force "none").
    _cache_markers = getattr(cfg, "cache_markers", None)
    _cache_min_block = getattr(cfg, "cache_min_block_tokens", None)
    # Forwarded RAW: sdk.configure() owns normalization (case, YAML `false` ->
    # "none", warn-and-fall-back-to-"auto" on junk), and an `or None` here
    # would erase the meaningful False. None means "not configured" and leaves
    # the module default ("auto"). Only the sdk backend takes it — oai has no
    # marker regime to declare; it routes via `prompt_cache_key` instead.
    _cache_route = getattr(cfg, "cache_route", None)
    sdk.configure(cache_markers=_cache_markers,
                  cache_min_block_tokens=_cache_min_block,
                  cache_route=_cache_route)
    oai.configure(cache_markers=_cache_markers)

    sdk_cfg = getattr(cfg, "sdk", None)
    if sdk_cfg is not None:
        ca_cert = getattr(sdk_cfg, "ca_cert", None) or None
        client_cert = getattr(sdk_cfg, "client_cert", None) or None
        sdk.configure(
            api_key=getattr(sdk_cfg, "api_key", None),
            base_url=getattr(sdk_cfg, "base_url", None),
            verify_ssl=_resolve_verify_path(cfg_dir, getattr(sdk_cfg, "verify_ssl", True)),
            ca_cert=_resolve_against(cfg_dir, ca_cert) if ca_cert else None,
            client_cert=_resolve_cert_chain(cfg_dir, client_cert),
            no_proxy=getattr(sdk_cfg, "no_proxy", None) or None,
            allow_api_key_fallback=sdk_sole,
        )
    oai_cfg = getattr(cfg, "openai", None)
    if oai_cfg is not None:
        ca_cert = getattr(oai_cfg, "ca_cert", None) or None
        oai.configure(
            api_key=getattr(oai_cfg, "api_key", None),
            base_url=getattr(oai_cfg, "base_url", None),
            verify_ssl=_resolve_verify_path(cfg_dir, getattr(oai_cfg, "verify_ssl", True)),
            ca_cert=_resolve_against(cfg_dir, ca_cert) if ca_cert else None,
            # Forwarded UNRESOLVED and only so the backend can warn: this route
            # has no mTLS plumbing, so the value is never opened as a file.
            client_cert=getattr(oai_cfg, "client_cert", None) or None,
            organization=getattr(oai_cfg, "organization", None) or None,
            no_proxy=getattr(oai_cfg, "no_proxy", None) or None,
        )
    # via:cli roles shell out to the `claude` binary; push the same gateway
    # TLS/proxy settings into the subprocess env (auth/endpoint stay delegated
    # to the CLI). No-op when there is no cli: block.
    cli_cfg = getattr(cfg, "cli", None)
    if cli_cfg is not None:
        ca_cert = getattr(cli_cfg, "ca_cert", None) or None
        client_cert = getattr(cli_cfg, "client_cert", None) or None
        cli.configure(
            verify_ssl=_resolve_verify_path(cfg_dir, getattr(cli_cfg, "verify_ssl", True)),
            ca_cert=_resolve_against(cfg_dir, ca_cert) if ca_cert else None,
            client_cert=_resolve_cert_chain(cfg_dir, client_cert),
            no_proxy=getattr(cli_cfg, "no_proxy", None) or None,
            effort=getattr(cli_cfg, "effort", None) or None,
        )
    # No deepagents branch: that route holds no process-global configuration.
    # Its credentials and TLS material travel per call, threaded from the
    # stage's cfg through backends.llm.deepagents (build_harness_env).


def _reachable_despite_degenerate_reply(e: BaseException) -> bool:
    """A terse probe reply proves reachability; it must not fail preflight.

    The probe tags are shared CONSTANTS ("preflight", "preflight-agentic",
    "cache-probe"), so the VVAH-E003 consecutive counter accumulates across
    EVERY probed target rather than per model. Three terse-but-successful
    replies — e.g. three agentic targets whose one-turn probe ends on a
    tool_use with no final text — therefore raise DegenerateResponseError out
    of the third probe, which the handlers below would report as "FAILED",
    return False from probe_backends(), exit 1 and skip --cache-probe. That is
    a hard failure manufactured from three HTTP 200s.

    A degenerate reply is a content judgement, not a connectivity one, and the
    probe only asks "can we reach this model": the credential and transport
    failures preflight exists to catch raise AuthenticationError/ProxyError or
    a connection error instead. So treat it exactly like the token-cap case.
    """
    return isinstance(e, DegenerateResponseError)


def _reachable_despite_truncated_reply(e: BaseException) -> bool:
    """A reply cut off by the probe's own output budget proves reachability."""
    # Backstop to _PROBE_PING_MAX_TOKENS: thinking tokens count against
    # max_tokens on adaptive models, so no budget is provably un-exhaustible.
    return isinstance(e, TruncatedResponseError)


def _reachable_despite_token_cap(err_msg: str) -> bool:
    """True when a probe error actually proves the model is reachable.

    A via:cli model that responded but whose reply exceeded the tiny preflight
    max_tokens cap surfaces as an error ("...response exceeded the N output
    token maximum..."), yet it demonstrably reached the model — so the probe
    should pass. (sdk/openai surface the same condition as a typed
    TruncatedResponseError instead — see _reachable_despite_truncated_reply;
    this string match stays for via:cli, which has no truncation detection at
    all. Real scans use a large max_tokens and an over-long output there is a
    genuine result worth surfacing, which is why this is scoped to the probe.)"""
    low = (err_msg or "").lower()
    return "exceeded" in low and "output token" in low


def _post_scan_only(roles: Iterable[str]) -> bool:
    """True when every role in *roles* runs after detection (S10/S11).

    Empty is False: an unattributed gap is never assumed harmless.
    """
    return bool(roles) and set(roles) <= POST_SCAN_ROLES


def _report_credential_gap(message: str, roles: Iterable[str], *remedies: str) -> bool:
    """Print a credential gap; return True when it must abort the run.

    A gap that only affects post-scan roles is a WARN: S1-S9 detection needs nothing
    from that credential, and the S10/S11 gates in orchestrator.scan disable the
    affected stage on their own. A credential shared with ANY detection role stays
    fatal exactly as before - a scan that cannot detect must not start.
    """
    if _post_scan_only(roles):
        print(f"  WARN: {message}", file=sys.stderr)
        print(f"    required only by {', '.join(sorted(roles))} — that stage "
              f"will be skipped", file=sys.stderr)
        return False
    print(f"ERROR: {message}", file=sys.stderr)
    for line in remedies:
        print(f"  {line}", file=sys.stderr)
    return True


def check_backends(cfg, *, skip_roles: Iterable[str] = ()) -> bool:
    """
    Verify whichever backend(s) the config actually uses:
      - any role with via:cli  → `claude` must be on PATH
      - any role with via:sdk  → ANTHROPIC_SDK_API_KEY (or cfg.sdk.api_key) must be set

    ``skip_roles`` drops roles this invocation cannot reach, so their backends are not
    required. Exploit verification is the case that needs it: it is off unless a
    collection is supplied, and a credential gap on a *detection-era* role is fatal (see
    :func:`_post_scan_only`) — so a profile naming an EV model on some other backend
    would otherwise demand that credential from every scan, including the ones that
    never enable EV.
    """
    skip = set(skip_roles)
    model_roles = [(r, m) for r, m in _iter_model_roles(cfg) if r not in skip]
    vias = {resolve_model(m).via for _, m in model_roles}
    # Which roles depend on each backend — decides whether a gap is fatal (any
    # detection role) or a skip-this-stage WARN (post-scan roles only).
    roles_by_via: dict[str, set[str]] = {}
    for _role, _model in model_roles:
        roles_by_via.setdefault(resolve_model(_model).via, set()).add(_role)

    # An unknown model-node key is read by no consumer, so a typo (e.g.
    # use_responses_apis) silently changes nothing — warn, never fail.
    unknown_keys = [
        f"models.{role}.{key}"
        for role, model in model_roles
        for key in unrecognized_model_keys(model)
    ]
    if unknown_keys:
        print(f"  WARN: unrecognized model key(s) ignored: "
              f"{', '.join(unknown_keys)}", file=sys.stderr)

    print(f"  [auth] active backends: {', '.join(sorted(vias)) or '(none)'}",
          file=sys.stderr)

    # Undocumented-egress hazard, WARNING-ONLY: with a LangSmith tracing gate
    # exported, langchain-core (the deepagents route's model layer) uploads
    # every prompt — repository source — and completion to LangSmith. The scan
    # is where that egress actually happens, so it is surfaced here too, not
    # only in doctor. Deliberately never mutates os.environ (S10/S11 share
    # this process environment) and never flips the preflight result: an
    # operator may be tracing on purpose in a lab.
    from vvaharness.util.environment import WARN as _WARN
    from vvaharness.util.environment import langsmith_tracing_check
    _tracing = langsmith_tracing_check()
    if _tracing.status == _WARN:
        print(f"  WARN: {_tracing.detail}", file=sys.stderr)

    # CLI auth is validated by the live probe, not env-var presence: Claude Code
    # can authenticate from its normal login/keychain state.
    if "cli" in vias:
        print("  [auth] cli: delegated to configured CLI; live probe verifies login",
              file=sys.stderr)
        if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            print("    NOTE: ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN is set and is "
                  "passed through to the `claude` CLI — it will use that "
                  "credential per its native precedence (API key → auth token "
                  "→ OAuth on disk).", file=sys.stderr)
        if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
            print("    CLAUDE_CODE_OAUTH_TOKEN present for unattended CLI auth ✓",
                  file=sys.stderr)

    # Presence dump only for credentials required by active API backends.
    # via:sdk uses the Anthropic Python SDK and requires SDK/API credentials.
    if "sdk" in vias:
        sdk_cfg = getattr(cfg, "sdk", None)
        print("  [auth] sdk credential sources (presence only — secrets never printed):",
              file=sys.stderr)
        print(f"    env  ANTHROPIC_SDK_API_KEY     = {_mask(os.environ.get('ANTHROPIC_SDK_API_KEY'))}",
              file=sys.stderr)
        print(f"    cfg  sdk.api_key               = {_mask(getattr(sdk_cfg, 'api_key', None))}",
              file=sys.stderr)
        print(f"    cfg  sdk.base_url              = {_mask(getattr(sdk_cfg, 'base_url', None))}",
              file=sys.stderr)

    if "openai" in vias:
        openai_cfg = getattr(cfg, "openai", None)
        print("  [auth] openai credential sources (presence only — secrets never printed):",
              file=sys.stderr)
        print(f"    env  OPENAI_API_KEY            = {_mask(os.environ.get('OPENAI_API_KEY'))}",
              file=sys.stderr)
        print(f"    cfg  openai.api_key            = {_mask(getattr(openai_cfg, 'api_key', None))}",
              file=sys.stderr)
        print(f"    cfg  openai.base_url           = {_mask(getattr(openai_cfg, 'base_url', None))}",
              file=sys.stderr)

    ok = True
    invalid_deepagents = sorted(
        role for role, model in model_roles
        if resolve_model(model).via == "deepagents" and role not in DEEPAGENTS_ROLES
    )
    if invalid_deepagents:
        # Supported-role list derived from the frozenset so the message can
        # never drift from the gate's actual membership again.
        supported = ", ".join(f"models.{r}" for r in sorted(DEEPAGENTS_ROLES))
        print(
            f"ERROR: via:deepagents is supported only for {supported}; "
            f"invalid role(s): {', '.join(invalid_deepagents)}",
            file=sys.stderr,
        )
        ok = False
    if "cli" in vias:
        if not (shutil.which("claude") or shutil.which("claude.cmd")):
            if _report_credential_gap(
                    "`claude` CLI not found on PATH (required by via:cli roles).",
                    roles_by_via["cli"],
                    "Install: https://docs.anthropic.com/en/docs/claude-code"):
                ok = False
        else:
            print("  [cli] claude found on PATH ✓", file=sys.stderr)

    if "sdk" in vias:
        key = getattr(getattr(cfg, "sdk", None), "api_key", None) \
              or os.environ.get("ANTHROPIC_SDK_API_KEY")
        # Same sdk_sole predicate as configure_backends() — the canonical
        # rationale for the shared-credential fallback lives beside it there.
        sdk_sole = vias <= {"sdk", "deepagents"}
        used_fallback = False
        if not key and sdk_sole:
            key = os.environ.get("ANTHROPIC_API_KEY") \
                  or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            used_fallback = bool(key)
        if not key:
            remedies = ["export ANTHROPIC_SDK_API_KEY=sk-ant-..."]
            if sdk_sole:
                remedies.append("(or set ANTHROPIC_API_KEY — accepted as a fallback "
                                "because no via:cli role shares this run)")
            if _report_credential_gap(
                    "ANTHROPIC_SDK_API_KEY not set (required by via:sdk roles).",
                    roles_by_via["sdk"], *remedies):
                ok = False
        elif used_fallback:
            print("  [sdk] ANTHROPIC_SDK_API_KEY unset — using "
                  "ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN fallback "
                  "(no via:cli role shares this run) ✓", file=sys.stderr)
        else:
            print("  [sdk] ANTHROPIC_SDK_API_KEY present ✓", file=sys.stderr)

    if "openai" in vias:
        key = getattr(getattr(cfg, "openai", None), "api_key", None) \
              or os.environ.get("OPENAI_API_KEY")
        if not key:
            if _report_credential_gap(
                    "OPENAI_API_KEY not set (required by via:openai roles).",
                    roles_by_via["openai"], "export OPENAI_API_KEY=sk-..."):
                ok = False
        else:
            print("  [openai] OPENAI_API_KEY present ✓", file=sys.stderr)

    if "deepagents" in vias:
        from vvaharness.util.environment import _backend_credential_ok

        # Credentials are per (model_id, provider) target, not per via, so the
        # fatal/WARN decision needs the roles behind each individual target.
        deep_specs: dict[tuple[str, str | None], set[str]] = {}
        for role, model in model_roles:
            if resolve_model(model).via != "deepagents":
                continue
            spec = (resolve_model(model).model_id, getattr(model, "provider", None))
            deep_specs.setdefault(spec, set()).add(role)
        # Sort on a total order: provider is None for name-inferred targets, which
        # would make a bare tuple comparison against a str provider raise.
        for (model_id, provider), roles in sorted(
                deep_specs.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
            # cfg travels so a profile-bound sdk.api_key / openai.api_key
            # satisfies preflight exactly as it satisfies doctor and the
            # runtime (credential_env_overrides exports that same key).
            ready, detail = _backend_credential_ok("deepagents", model_id,
                                                   provider, cfg=cfg)
            if ready:
                print(f"  [deepagents] {model_id}: {detail} ✓", file=sys.stderr)
            elif _report_credential_gap(f"DeepAgents {model_id}: {detail}", roles):
                ok = False

    # Skipped when credential checks already failed (nothing to probe).
    if not ok:
        print("  [probe] skipped — fix credential errors above first",
              file=sys.stderr)
        return ok
    # Catch the gateway gap (JWT-shaped ANTHROPIC_API_KEY with no
    # ANTHROPIC_BASE_URL) BEFORE the live probe — otherwise the request goes to
    # the public endpoint and (behind a corporate proxy) hangs to a 60s+ timeout
    # instead of giving the actionable fix. Fail fast with the exact remedy.
    from vvaharness.util.environment import FAIL as _FAIL
    from vvaharness.util.environment import _gateway_check
    gw = _gateway_check()
    if gw.status == _FAIL:
        print(f"ERROR: {gw.detail}", file=sys.stderr)
        return False
    return probe_backends(cfg)


#: Roles that always drive the agentic() backend path: s1_preprocess.py and
#: s6_verify.py. Every other role uses prompt() -- except `threatmodel`, which
#: is agentic ONLY when `step2.agentic` is set, so it is resolved per-config by
#: `_agentic_roles` rather than listed here.
_ALWAYS_AGENTIC_ROLES = ("preprocess", "verify")


def _agentic_roles(cfg) -> tuple[str, ...]:
    """The roles this config will actually call agentic() for.

    `threatmodel` is conditional: s2 switches from prompt() to agentic() on
    `step2.agentic` (s2_threatmodel.py's `getattr(s2, "agentic", False)`
    branch). Omitting it here left the opt-in shipping with NO agentic smoke
    probe for that role, so a profile that enabled it discovered a broken
    agentic path mid-scan rather than in preflight. Derived from the same flag
    the stage reads, so the two cannot drift.
    """
    if getattr(getattr(cfg, "step2", None), "agentic", False):
        return (*_ALWAYS_AGENTIC_ROLES, "threatmodel")
    return _ALWAYS_AGENTIC_ROLES


def _agentic_role_tools(cfg, role: str, via: str | None = None) -> list[str]:
    """The allowed_tools each agentic role passes to llm.agentic(), computed
    by the SAME `validate_detection_tools` call the stage makes
    (inline at the top of s1_preprocess.run, s6_verify.run, s2_threatmodel's
    agentic branch) — same config key, same `DEFAULT_READ_TOOLS` fallback, same
    `via: cli` exemption — so the probe sends exactly the tool set the real
    scan will. The tool set is part of the probe's identity (it is what makes
    a via:sdk/openai role delegate or raise), and a duplicated literal here
    has already drifted from the stages once; deriving from the shared guard
    also means a profile the stage would refuse raises the stage's own
    ValueError HERE, at preflight, instead of mid-scan after S1-S5 spend.

    *via* is the role's resolved via — the caller already has it from
    resolve_model, and every stage threads its own model's via the same way.
    """
    if role == "preprocess":
        return validate_detection_tools(
            getattr(getattr(cfg, "step1", None), "allowed_tools", None),
            config_key="step1.allowed_tools", via=via)
    if role == "verify":
        return validate_detection_tools(
            getattr(getattr(cfg, "step6_verify", None), "allowed_tools", None),
            config_key="step6_verify.allowed_tools", via=via)
    if role == "threatmodel":
        # Only reached when step2.agentic is on (see _agentic_roles).
        return validate_detection_tools(
            getattr(getattr(cfg, "step2", None), "allowed_tools", None),
            config_key="step2.allowed_tools", via=via)
    return []


# VVAH-E003 floors for this module's live probes — the prompt ping ("ping" →
# "pong", tag "preflight"), the agentic smoke probe ("reply with the single
# word ok", tag "preflight-agentic"), and the cache probe ("Reply with the
# single word PONG.", tag "cache-probe"). Every one of them asks for a single
# word, so the shortest reply the probe itself considers valid is one word:
# 2 chars / 1 provider-reported output token ("ok"). The global defaults
# (150 chars / 30 tokens) are sized for report prose and are keyed off the
# tag, so they flagged each of these design-correct replies as degenerate —
# a scan whose agentic roles run via deepagents opened with a VVAH-E003
# warning about its own probe, printed above the credential summary an
# operator is actually meant to read. 1/1 sits just below the one-word reply
# and keeps the only signal worth having here: a model that answers with
# nothing at all still trips. The degenerate archetypes ABOVE one word
# (empty fenced block ~4 chars, one-sentence refusal ~8-9 tokens — see the
# derivation at s1_autoexclude._MIN_RESPONSE_*) cannot be separated from a
# valid reply this short; accepted, because a probe's real failure modes
# (bad credential, unreachable gateway, unknown model) raise and are handled
# by the probes' own except paths — the floor exists solely for the silent
# empty-200 case. Never lower these to 0: min_chars=0 / min_tokens=0 make
# `len(stripped) < 0` and `output_tokens < 0` unsatisfiable, silently
# disabling the check for the probe while every artifact still reads as
# covered. Counters are per-tag, so these scopes can never influence a real
# stage's consecutive-failure tally.
_PROBE_PING_MIN_CHARS = 1
_PROBE_PING_MIN_TOKENS = 1

# Must clear a one-word reply plus preamble; at 4 every sdk/openai probe
# truncated, costing a second billed call and a VVAH-E005 record.
_PROBE_PING_MAX_TOKENS = 256
_PROBE_PING_TIMEOUT_S = 120


def _probe_agentic_roles(cfg) -> bool:
    """Smoke-probe the agentic() backend path for the preprocess + verify roles.

    The prompt-based probe in probe_backends() only exercises prompt(); it
    never touches agentic(). That blind spot let two whole classes of failure
    reach mid-scan silently: (1) a via:cli stream-json argv regression
    (e.g. missing --verbose) that exits rc=1 before any output, and (2) a role
    moved to via:sdk/openai whose allowed_tools contain a tool those backends
    reject (NotImplementedError). A bounded 1-turn agentic call per unique
    (model, via, tool-set) surfaces both here instead.

    Failure is signalled ONLY by a raised exception: a 1-turn agent may
    legitimately end on a tool_use with no final text, so _parse_envelope
    returns "" — an empty reply is NOT a failure. Bounded by max_turns=1 and a
    tiny prompt; note that no wall-clock timeout is plumbed through
    llm.agentic (the cli backend caps itself at its own subprocess timeout).

    A via:deepagents role routes through the deepagents wrapper instead —
    exercising the exact streaming path S1 uses."""
    from vvaharness.backends.llm import deepagents as _deepagents
    from vvaharness.backends.llm.registry import agentic as _probe_agentic
    # (model_id, via, provider, frozenset(tools)) -> (node, tools, [roles]).
    # provider is in the key for the same reason as _probe_targets: collapsing
    # two providers sharing a model id would leave one of them untested.
    targets: dict[tuple, tuple] = {}
    agentic_roles = _agentic_roles(cfg)
    ok = True
    for role, m in _iter_model_roles(cfg):
        if role not in agentic_roles:
            continue
        mid, via, _ = resolve_model(m)
        try:
            tools = _agentic_role_tools(cfg, role, via)
        except ValueError as e:
            # The stage's own allowlist guard (validate_detection_tools),
            # raised at preflight so a config the stage would refuse at its
            # start — e.g. step6_verify.allowed_tools naming Bash on via:sdk —
            # fails HERE instead of mid-scan after S1-S5 spend. Routed through
            # the shared fatal/WARN classifier: every agentic role today is a
            # detection role, so this aborts; a POST_SCAN_ROLES member would
            # correctly degrade to a skip-this-stage WARN instead.
            if _report_credential_gap(str(e), {role}):
                ok = False
            continue
        key = (mid, via, getattr(m, "provider", None), frozenset(tools))
        _node, _t, roles = targets.setdefault(key, (m, tools, []))
        roles.append(role)

    if not targets:
        return ok

    print(f"  [probe] agentic backend path ({len(targets)} agentic "
          f"role/backend pair(s)):", file=sys.stderr)
    for (mid, via, _provider, _tk), (mcfg, tools, roles) in targets.items():
        role_list = ",".join(roles)
        t0 = time.time()
        workdir = tempfile.mkdtemp(prefix="vva-preflight-")
        try:
            # Same floor relaxation as the prompt ping in probe_backends():
            # of these two dispatches only the deepagents one reaches the
            # VVAH-E003 gate today (deepagents.agentic checks its final text;
            # sdk/openai/cli agentic() never call the gate), and its valid
            # "ok" reply is ~2 chars / 1 token — so every scan whose agentic
            # roles ran via deepagents opened with a degenerate-response
            # warning about a probe behaving exactly as designed. The scope
            # covers both branches because they share the one tag and this
            # loop is serial (overlapping scopes on one tag corrupt each
            # other — see stage_floors()). One caveat this floor accepts: a
            # 1-turn agentic call may legitimately end on a tool_use with no
            # final text (this probe counts that as a pass, see docstring),
            # and a floor of 1 cannot separate that empty text from a truly
            # empty answer. That costs at most a cosmetic WARN and never a
            # probe failure — but only because these tags are shared CONSTANTS
            # whose consecutive counter accumulates across every probed target,
            # so three terse-but-successful replies used to raise
            # DegenerateResponseError out of the third probe and report a
            # FAILED backend from three HTTP 200s. What makes the claim true
            # is _reachable_despite_degenerate_reply() in the handlers below,
            # alongside _reachable_despite_truncated_reply() for the same
            # reason on the output-budget axis; do not remove either and leave
            # this comment standing.
            # Still worth keeping over 0/0, which would disable the check while
            # reading as coverage.
            with stage_floors("preflight-agentic",
                              min_chars=_PROBE_PING_MIN_CHARS,
                              min_tokens=_PROBE_PING_MIN_TOKENS):
                if via == "deepagents":
                    _deepagents.agentic("reply with the single word ok",
                                        model=mcfg, system_prompt=None,
                                        allowed_tools=list(tools), cwd=workdir,
                                        max_turns=1, tag="preflight-agentic",
                                        graph_name="preflight-agentic",
                                        sdk_cfg=getattr(cfg, "sdk", None),
                                        openai_cfg=getattr(cfg, "openai", None))
                else:
                    _probe_agentic("reply with the single word ok",
                                   model=mcfg, system_prompt=None,
                                   allowed_tools=list(tools), cwd=workdir,
                                   max_turns=1, tag="preflight-agentic")
            print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                  f"agentic roles: {role_list}", file=sys.stderr)
        except Exception as e:
            if _reachable_despite_token_cap(str(e)) or \
                    _reachable_despite_degenerate_reply(e) or \
                    _reachable_despite_truncated_reply(e):
                print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                      f"agentic roles: {role_list}  (reachable; terse or "
                      f"token-capped reply)", file=sys.stderr)
                continue
            lines = str(e).splitlines()
            msg = (lines[0][:160] if lines else "") or "(no message)"
            print(f"    ✗ [{via:<6}] {mid:<32} FAILED (agentic)  "
                  f"roles: {role_list}", file=sys.stderr)
            print(f"      {type(e).__name__}: {msg}", file=sys.stderr)
            ok = False
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    return ok


def _probe_targets(cfg) -> dict[tuple[str, str, str | None],
                                tuple[object, list[str]]]:
    """Unique probe targets: (model_id, via, provider) -> (node, roles).

    The original cfg node is kept so llm.resolve() (which reads .id/.via via
    getattr) works. ``provider`` is part of the key so two roles sharing a
    model id but naming different providers are probed separately — collapsing
    them would let the untested provider pass silently.
    """
    targets: dict[tuple[str, str, str | None], tuple[object, list[str]]] = {}
    for role, m in _iter_model_roles(cfg):
        mid, via, _ = resolve_model(m)
        key = (mid, via, getattr(m, "provider", None))
        _node, roles = targets.setdefault(key, (m, []))
        roles.append(role)
    return targets


def _probe_deepagents_harness(cfg, model_id: str, provider: str | None,
                              *, include_tls: bool = True,
                              use_responses_api: bool | None = None) -> None:
    """One bounded one-shot through the deepagents harness — the ONLY
    deepagents route since the registry adapter was removed: every stage
    dispatching a ``via: deepagents`` role runs on this same harness.
    Raises on any failure; a normal return is a pass.

    *include_tls* mirrors an asymmetry between the runtime seams. A detection
    role's env comes from ``build_harness_env`` — credentials PLUS the
    profile's TLS material (``ca_cert`` / ``client_cert`` / ``verify_ssl``,
    relative cert paths anchored at the config directory). The S10/S11
    plugin_runner, by contrast, builds its env from
    ``credential_env_overrides`` alone — no TLS carriers — so a target that
    only post-scan roles use must be probed the same way: probing it with a
    client certificate the real run will not send would pass an mTLS profile
    that then fails at S10."""
    # noqa reason: imported only when a deepagents role is actually probed.
    from vvaharness.backends.harness import OneShotOptions  # noqa: PLC0415
    from vvaharness.backends.harness.provider_routing import (  # noqa: PLC0415
        credential_env_overrides,
    )
    from vvaharness.backends.llm.deepagents import (  # noqa: PLC0415
        build_harness_env,
        markers_on,
        run_oneshot,
    )

    sdk_cfg = getattr(cfg, "sdk", None)
    openai_cfg = getattr(cfg, "openai", None)
    if include_tls:
        env = build_harness_env(
            model_id, provider, sdk_cfg=sdk_cfg, openai_cfg=openai_cfg,
            cfg_dir=getattr(cfg, "_data", {}).get("_config_dir"),
        )
    else:
        # Byte-identical to plugin_runner._invoke_deepagents's env build.
        env = {
            **os.environ,
            **credential_env_overrides(
                model_id, provider, sdk_cfg=sdk_cfg, openai_cfg=openai_cfg,
            ),
        }
    with tempfile.TemporaryDirectory(
            prefix="vva-preflight-deepagents-") as workdir:
        # Through llm.deepagents so the probe primes _model_cache on the same
        # persistent loop the scan's harness calls run on.
        result = run_oneshot(
            "reply with the single word ok",
            OneShotOptions(
                model=model_id,
                cwd=Path(workdir),
                env=env,
                model_provider=provider,
                use_responses_api=use_responses_api,
                max_turns=2,
                # A marker-rejecting gateway must stay reachable with the kill
                # switch set, or preflight blocks the scan it exists to enable.
                cache_markers=markers_on(sdk_cfg),
            ),
        )
    if result.is_error:
        raise RuntimeError(
            f"DeepAgents preflight failed: {result.subtype or 'unknown error'}")


def probe_backends(cfg) -> bool:
    """Live connectivity probe: one minimal request per unique
    (model_id, via, provider) so bad credentials, an unreachable
    base_url, TLS/proxy misconfig, or an unknown model id fail HERE instead of
    mid-scan after tokens are spent (~4 output tokens each). Shared by
    check_backends() and `vvaharness doctor` so both exercise the same path
    the real scan will use. The prompt ping is followed by a bounded agentic
    smoke probe for the agentic-only roles."""
    from vvaharness.backends.llm.registry import prompt as _probe
    invalid_deepagents = sorted(
        role for role, model in _iter_model_roles(cfg)
        if resolve_model(model).via == "deepagents" and role not in DEEPAGENTS_ROLES
    )
    if invalid_deepagents:
        # Supported-role list derived from the frozenset — see check_backends().
        print(
            "ERROR: refusing DeepAgents probe for unsupported role(s): "
            + ", ".join(invalid_deepagents)
            + f" (via:deepagents role(s): {', '.join(sorted(DEEPAGENTS_ROLES))})",
            file=sys.stderr,
        )
        return False
    targets = _probe_targets(cfg)

    print(f"  [probe] live model connectivity ({len(targets)} unique "
          f"model/backend pair(s)):", file=sys.stderr)
    ok = True
    # Post-scan roles whose model is unreachable. Tracked so the closing summary
    # cannot claim "all reachable" right after WARNing that one was not.
    skipped: set[str] = set()
    for (mid, via, provider), (mcfg, roles) in targets.items():
        role_list = ",".join(roles)
        t0 = time.time()
        try:
            if via == "deepagents":
                # Every via:deepagents role — detection and post-scan alike —
                # dispatches through the harness now (the registry adapter is
                # gone), so the harness one-shot is the seam the probe must
                # exercise for all of them. TLS carriers travel only when a
                # detection role shares the target: the S10/S11 runtime env
                # is credentials-only. A model shared by a detection AND a
                # post-scan role dedups into ONE probe with TLS (the
                # detection role genuinely needs it) — the post-scan half is
                # then probed with more TLS material than its runtime env
                # carries, accepted over paying for a second probe of a
                # configuration no shipped profile has.
                _probe_deepagents_harness(
                    cfg, mid, provider,
                    include_tls=not _post_scan_only(roles),
                    use_responses_api=use_responses_api_of(mcfg))
            else:
                # A one-word pong is the entire POINT of this probe, but the
                # VVAH-E003 floors (150 chars / 30 tokens, sized for report
                # prose) are keyed off the tag and so misfired on it: every
                # scan opened with "degenerate response (1/3 consecutive)"
                # warnings describing a probe behaving exactly as designed,
                # ahead of the credential and stage output an operator is
                # actually meant to read. Floors of 1 keep the one signal
                # worth having here — a model that answers with nothing at all
                # still trips — and the counter is per-tag, so this scope can
                # never influence a real stage's consecutive-failure tally.
                # (Floor values and their derivation: _PROBE_PING_MIN_*.)
                with stage_floors("preflight",
                                  min_chars=_PROBE_PING_MIN_CHARS,
                                  min_tokens=_PROBE_PING_MIN_TOKENS):
                    _probe("ping", model=mcfg,
                           max_tokens=_PROBE_PING_MAX_TOKENS,
                           timeout=_PROBE_PING_TIMEOUT_S, tag="preflight")
            print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                  f"roles: {role_list}", file=sys.stderr)
        except Exception as e:
            if _reachable_despite_token_cap(str(e)) or \
                    _reachable_despite_degenerate_reply(e) or \
                    _reachable_despite_truncated_reply(e):
                print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                      f"roles: {role_list}  (reachable; terse or token-capped "
                      f"reply)", file=sys.stderr)
                continue
            # str(e) can be empty (some socket/timeout/SDK connection errors
            # carry no message) — splitlines() then yields [], so guard the
            # index to avoid an IndexError masking the real probe failure.
            lines = str(e).splitlines()
            msg = (lines[0][:160] if lines else "") or "(no message)"
            # A model only S10/S11 use being unreachable degrades that stage, not the
            # scan: detection never touches it and the S10/S11 gates skip it.
            if _post_scan_only(roles):
                print(f"    WARN [{via:<6}] {mid:<32} unreachable  roles: "
                      f"{role_list} — that stage will be skipped", file=sys.stderr)
                print(f"      {type(e).__name__}: {msg}", file=sys.stderr)
                skipped.update(roles)
                continue
            print(f"    ✗ [{via:<6}] {mid:<32} FAILED  roles: {role_list}",
                  file=sys.stderr)
            print(f"      {type(e).__name__}: {msg}", file=sys.stderr)
            ok = False

    # Exercise the agentic() path too (the roles _agentic_roles selects:
    # preprocess/verify, plus threatmodel when step2.agentic is on). Listed first so
    # it always runs even when a prompt probe already failed — more complete
    # diagnostics in one pass.
    ok = _probe_agentic_roles(cfg) and ok

    if ok and skipped:
        print(f"  [probe] detection backends reachable ✓ — "
              f"{', '.join(sorted(skipped))} unreachable, so that stage is "
              f"skipped (see WARN above)", file=sys.stderr)
    elif ok:
        print("  [probe] all model backends reachable ✓", file=sys.stderr)
    else:
        print("ERROR: one or more model backends unreachable — fix before "
              "scanning, or pass --skip-preflight to bypass.", file=sys.stderr)
    return ok


# ═════════════════════════════════════════════════════════════════════════════
# `vvaharness doctor --cache-probe` — live diagnostic for prompt-cache behaviour.
#
# Measured cache-read rates have varied wildly across configured model routes
# (from 0% to over 20%), and those routes use different caching mechanisms
# (the Anthropic SDK's explicit cache_control marker, OpenAI's implicit prefix
# cache, a CLI subprocess) — so a single aggregate number can't tell you
# whether a particular route is broken, below its minimum cacheable block
# size, rate-limited by request concurrency, or just using a mechanism that
# never reports a write. This probe isolates which of those is happening, per
# model, so an operator (or a follow-on change to the backends) is acting on
# an established cause rather than a guess. It is opt-in (`doctor
# --cache-probe`), spends real tokens, and never runs during a scan or from
# plain `doctor`.
#
# Hard constraint: usage is read ONLY from what the backends themselves
# record into the process-wide `TOKENS` accumulator around a normal
# `backends.llm.prompt()` call — snapshot-diffed counters for token VALUES,
# and the usage dicts the backend passes to `TOKENS.add()` for field
# PRESENCE (see _call_and_diff). Building a separate API client here would
# bypass sdk.py's own request construction (the `thinking` gate, and
# `_build_system_content`'s GATED cache_control marker placement — route +
# kill switch + minimum-size, not unconditional) and oai.py's — which would
# invalidate the result, since the probe would then be testing a request the
# real scan never sends.
# ═════════════════════════════════════════════════════════════════════════════

# The backends the `backends.llm.prompt()` arm of this probe diagnoses. `via:
# deepagents` roles never flow through `backends.llm.prompt()` and are NOT in
# this set — they have their own arm (_probe_deepagents_cache) that drives the
# real dispatch_prompt seam, exercising the harness's own block-marker
# middleware. Do not widen this set; extend the deepagents arm instead.
_PROMPT_VIAS = frozenset({"sdk", "openai", "cli"})

_FILLER_MIN_TOKENS = 8192
_FILLER_CHARS_PER_TOKEN = 4      # same rough heuristic as cli._estimate (bytes // 4)
_FILLER_MARGIN = 1.25            # build past the floor, not right at it — see
                                  # cache_probe_filler()'s docstring.

# Only `usage` matters, but the budget must still clear a real reply: this
# arm has no VVAH-E005 exemption, so a truncation here is a hard FAILED.
_PROBE_MAX_TOKENS = 256
_PROBE_TIMEOUT_S = 120
_CALL_B_DEADLINE_S = 5.0         # well under any provider's cache TTL, so a
                                  # slow probe run is never mistaken for expiry
# Arbitrary probe-only value used to force `thinking` ON for the "with
# thinking" arm. No shipped profile in config/profiles/*.yaml sets
# thinking_budget today (grepped all four) — the probe supplies its own value
# so "does enabling extended thinking change cache behaviour" can be tested
# regardless of what production sends.
_PROBE_THINKING_BUDGET = 1024

# Deterministic, distinct ~50-token user turns for Call A / Call B — the two
# calls must differ so a cache hit on Call B can only come from the shared
# system-prompt prefix, never from an identical full request. Fixed text, no
# randomness/clock, so two probe runs are comparable.
_USER_MSG_A = (
    "Reply with the single word PONG. cache-probe call A deterministic marker "
    "sequence diagnostic token filler padding text alpha bravo charlie delta "
    "echo foxtrot golf hotel india juliet kilo lima mike november oscar"
)
_USER_MSG_B = (
    "Reply with the single word PONG. cache-probe call B deterministic marker "
    "sequence diagnostic token filler padding text papa quebec romeo sierra "
    "tango uniform victor whiskey xray yankee zulu alpha bravo charlie"
)

# Verdict codes for the six-way classification below, split by which usage
# fields the route's responses actually carry. Kept as short machine-stable
# codes; operator-facing text lives in _VERDICT_TEXT.
# The ANTHROPIC/OPENAI prefixes name the cache-accounting SHAPE the pair
# OBSERVABLY carried (write field present vs absent), not the transport that
# carried it: an openai route whose gateway bills cache writes reports
# `cache_creation_input_tokens` (openai.py::_normalise_usage) and correctly
# classifies in the explicit-write (ANTHROPIC_*) family.
V_ANTHROPIC_WORKS = "anthropic_works"
V_ANTHROPIC_ROUTING_GAP = "anthropic_write_ok_read_fails"
V_ANTHROPIC_NOT_HONOURED = "anthropic_marker_not_honoured"
V_ANTHROPIC_ALREADY_WARM = "anthropic_works_prefix_already_cached"
V_OPENAI_WORKING = "openai_implicit_working"
V_OPENAI_BELOW_MIN = "openai_below_minimum_or_unstable"
V_NO_CACHE_FIELDS = "no_cache_fields_treat_as_implicit"
# Not one of classify_cache_verdict()'s six rows: assigned only by
# run_cache_probe()'s post-classification override, when the sdk backend's
# OWN gate confirms no cache_control marker was ever placed on the call —
# see _marker_would_be_placed(). A 0-write/0-read result then implicates
# this tool's gate, not the gateway.
V_MARKER_WITHHELD = "anthropic_marker_withheld_by_gate"

_VERDICT_TEXT = {
    V_ANTHROPIC_WORKS: (
        "cache markers are honoured on this route; explicit breakpoints are "
        "an optimisation here, not a fix."),
    V_ANTHROPIC_ROUTING_GAP: (
        "writes succeed but reads do not — investigate request routing or "
        "cache-key affinity, not marker placement."),
    V_ANTHROPIC_NOT_HONOURED: (
        "the marker is not taking effect at all — check whether base_url "
        "points at a gateway that strips it, whether the block is below this "
        "model's minimum cacheable size, retest with thinking disabled, and "
        "retest against the vendor endpoint directly."),
    V_ANTHROPIC_ALREADY_WARM: (
        "caching is working; nothing new was written because this prefix was "
        "already cached from an earlier call, and it was read back. Re-run "
        "after the cache lifetime has elapsed if you want to observe a write."),
    V_OPENAI_WORKING: (
        "the implicit prefix cache is working normally; no explicit marker "
        "is needed or available on this route."),
    V_OPENAI_BELOW_MIN: (
        "no cache read observed — the prompt may be below this route's "
        "minimum cacheable size, or its prefix is unstable across calls; "
        "re-probe with a larger filler to tell which."),
    V_NO_CACHE_FIELDS: (
        "this route reports no cache accounting at all — treat caching as "
        "implicit and unmeasurable here; rely on keeping the prompt prefix "
        "stable rather than on any marker."),
    V_MARKER_WITHHELD: (
        "this tool's own gate never placed a cache_control marker on this "
        "call (unrecognised route, cache markers switched off, or the prompt "
        "is below this model's estimated minimum cacheable size) — the "
        "gateway was never asked to cache anything, so there is nothing to "
        "investigate there. Re-probe with a larger prompt shape, or set "
        "cache_route / cache_min_block_tokens to change the gate's decision."),
}

def cache_probe_filler(min_tokens: int = _FILLER_MIN_TOKENS) -> str:
    """Deterministic filler of at least `min_tokens` ESTIMATED tokens for the
    cache probe's synthetic system prompt.

    Deterministic: identical content on every call (no randomness, no clock),
    so two probe runs — today and next week — are comparable.

    Built well past `min_tokens`, not right at it. Provider-published minimum
    cacheable block sizes go as high as 4096 tokens on some models, and any
    offline estimate is only approximate — a probe whose filler actually
    tokenizes to, say, 3,900 real tokens against an 8192 *nominal* target
    would still clear a naive floor while landing right at a real provider's
    cutoff, and get misdiagnosed as "marker not honoured" rather than "filler
    too small". This generator targets `_FILLER_MARGIN` (1.25x) past the
    requested floor to leave headroom for that estimation error.

    Sizing stays chars-based (`_FILLER_CHARS_PER_TOKEN`) on purpose: resizing
    to the shared estimator's prose ratio (~4.4 chars/token) would grow the
    filler ~10% — about +4-5k real tokens per model pair on a probe that
    already spends real money — for no diagnostic gain, because the current
    chars*1.25 sizing already overshoots what the shared estimator (and the
    backends' marker gate built on it — see `estimate_tokens` in
    util/tokens.py) requires. The invariant that matters — the filler clears
    `sdk._cache_prefix_meets_minimum` for every row of the per-model minimum
    table, so it can never land on the wrong side of the gate it audits — is
    asserted by tests/test_cache_probe.py instead of paid for on every probe.
    """
    target_chars = int(min_tokens * _FILLER_CHARS_PER_TOKEN * _FILLER_MARGIN)
    words = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet "
             "kilo lima mike november oscar papa quebec romeo sierra tango "
             "uniform victor whiskey xray yankee zulu").split()
    lines: list[str] = []
    total = 0
    i = 0
    while total < target_chars:
        line = f"CACHE-PROBE-FILLER-LINE-{i:06d} " + " ".join(words) + f" {i}\n"
        lines.append(line)
        total += len(line)
        i += 1
    return "".join(lines)


def _scheme_host(url: str | None) -> str:
    """Reduce a URL to `scheme://host[:port]` only — never a path, query
    string, or userinfo, any of which can carry embedded auth. This diagnostic
    must never print a credential or a base_url with embedded auth. Passed
    through redact() as a defense-in-depth backstop — reusing the existing
    redaction helper rather than writing a new pattern."""
    if not url:
        return "(default)"
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        # `hostname` strips the brackets an IPv6 literal needs. Without putting
        # them back, `[2001:db8::1]:8443` renders as `2001:db8::1:8443`, where
        # the port is indistinguishable from another address group.
        if ":" in host:
            host = f"[{host}]"
        if parts.port:
            host = f"{host}:{parts.port}"
        if parts.scheme and host:
            out = f"{parts.scheme}://{host}"
        else:
            out = host or "(unparseable)"
    except Exception:
        out = "(unparseable)"
    return redact(out)


def _resolved_base_url_scheme_host(via: str) -> str:
    """The base_url actually in force for `via`, scheme+host only, read from
    the backend's own already-configured client (post configure_backends())
    so it can never drift from what the real request will use.

    The backend modules are deliberately not modified by this diagnostic —
    `_get_client()` is called (as `configure_backends()` already causes to
    happen implicitly on the first real call), never modified."""
    try:
        if via == "sdk":
            raw = str(sdk._get_client().base_url)
        elif via == "openai":
            raw = str(oai._get_client().base_url)
        else:
            return "(cli subprocess — no base_url)"
    except Exception:
        return "(unresolved)"
    return _scheme_host(raw)


def _thinking_actually_sent(model_id: str, requested_budget: int | None) -> bool:
    """Ground truth for whether the FINAL successful request carried
    `thinking`, checked AFTER the call returns.

    `sdk.py`'s gate in `prompt()` (~:500) sends `thinking` only when
    `thinking_budget` is set AND `model not in _NO_THINK_MODELS` — and that
    set is populated at RUNTIME (`_NO_THINK_MODELS.add`, ~:560) inside the
    retry-and-drop handler when the API rejects
    the field with a 400. So a model can start a call with thinking requested
    and have it silently stripped mid-call on a retry that then succeeds; the
    only faithful answer is post-hoc, not "did I ask for it"."""
    if not requested_budget:
        return False
    return model_id not in sdk._NO_THINK_MODELS


def _marker_would_be_placed(via: str, system_prompt: str,
                            model_id: str) -> bool | None:
    """Whether the sdk backend's OWN gate would place a `cache_control`
    marker on this probe call's system block — asked of the backend's gate
    functions themselves (`_cache_markers_enabled`, `_cache_route` against
    `_CACHE_CONTROL_ROUTES`, `_cache_prefix_meets_minimum`), never re-derived
    here, so the answer can never drift from what sdk.py actually sends. The
    probe's prompt() path carries no tools, so the system prompt alone is the
    cumulative prefix the real gate evaluates.

    Returns None when the answer is not knowable from this process: `via:
    cli` builds its own request inside the `claude` subprocess, and `via:
    openai` places no `cache_control` markers by design (implicit prefix
    cache) — for both, "our gate withheld the marker" is not a statement this
    diagnostic can make. Any failure inside the gate functions is also None:
    an unanswerable question must never flip a verdict."""
    if via != "sdk":
        return None
    try:
        if not sdk._cache_markers_enabled():
            return False
        if sdk._cache_route(sdk._get_client()) not in sdk._CACHE_CONTROL_ROUTES:
            return False
        return bool(sdk._cache_prefix_meets_minimum(system_prompt, model_id))
    except Exception:  # noqa: BLE001 — diagnostic-only; never break the probe
        return None


def usage_dict_for_classifier(*, cache_write: int, cache_read: int,
                              write_present: bool,
                              read_present: bool) -> tuple[dict, dict]:
    """Build the (usage_a, usage_b) dicts classify_cache_verdict() expects
    from ONE probe pair's measurements: the snapshot-diffed token VALUES plus
    the OBSERVED field-presence flags, both returned by _call_and_diff().

    `write_present` / `read_present` state whether Call A's / Call B's
    recorded usage actually carried `cache_creation_input_tokens` /
    `cache_read_input_tokens` — observed at the TOKENS.add() seam, never
    reconstructed from the transport (`via`) name. An earlier version of this
    function inferred presence from `via` alone and unconditionally dropped
    the write field for `via: openai`; that guess went stale the moment
    openai.py's `_normalise_usage` (~:539) started setting
    `cache_creation_input_tokens` whenever the endpoint reports
    `prompt_tokens_details.cache_write_tokens` — a gateway that bills cache
    writes then printed a non-zero creation column while the verdict claimed
    "below minimum cacheable size", which the observed write disproves.
    Presence on that route is per-call, so it can only be observed, not
    derived from a route table.

    A call whose backend recorded no usage dict at all yields False flags and
    lands on the "no cache fields at all" row, rather than being guessed into
    either family.
    """
    usage_a: dict = {}
    usage_b: dict = {}
    if write_present:
        usage_a["cache_creation_input_tokens"] = cache_write
    if read_present:
        usage_b["cache_read_input_tokens"] = cache_read
    return usage_a, usage_b


def classify_cache_verdict(usage_a: dict, usage_b: dict) -> str:
    """Pure classifier that turns two calls' cache usage into one of six
    verdicts, split by which usage fields the route's responses carry at all.

    `usage_a` / `usage_b` are the per-call usage-shaped dicts for Call A
    (system prompt + first user turn) and Call B (system prompt + a
    *different* user turn, within 5s) respectively.

    Field PRESENCE — not just value — is the row-selecting signal: a
    correctly-working OpenAI-style route looks like
    (`cache_creation_input_tokens` ABSENT from usage_a, `cache_read_input_tokens`
    present and > 0 in usage_b). A naive single-condition check would leave
    that combination unclassified, or wrongly collapse it into "not honoured".
    Presence is checked with `in`, never inferred from a numeric default, so a
    route that never reports a write field is distinguished from one that
    reports it as zero.
    """
    creation_present = "cache_creation_input_tokens" in usage_a
    read_present = "cache_read_input_tokens" in usage_b
    if not creation_present and not read_present:
        return V_NO_CACHE_FIELDS
    read = int(usage_b.get("cache_read_input_tokens", 0) or 0)
    if creation_present:
        creation = int(usage_a.get("cache_creation_input_tokens", 0) or 0)
        if creation > 0 and read > 0:
            return V_ANTHROPIC_WORKS
        if creation > 0 and read == 0:
            return V_ANTHROPIC_ROUTING_GAP
        if creation == 0 and read > 0:
            # Nothing was written because the prefix was ALREADY cached, and it
            # was read back. That is a working cache, not a broken one — it is
            # what a re-run inside the lifetime window looks like, and what the
            # second measurement arm sees after the first arm has warmed the
            # same system prompt. Reporting "marker not honoured" here tells the
            # operator to go hunting for a gateway stripping a field that is in
            # fact working.
            return V_ANTHROPIC_ALREADY_WARM
        return V_ANTHROPIC_NOT_HONOURED
    return V_OPENAI_WORKING if read > 0 else V_OPENAI_BELOW_MIN


def _deepdive_system_prompt() -> str:
    """The real system prompt the deep-dive stage sends on every call,
    imported read-only rather than copied, so the probe always tests the
    exact text a live scan sends — not a snapshot of it that can drift out of
    sync. Local import: keeps this module import-light for every caller that
    never runs the probe, and re-reads the live value if that prompt changes."""
    from vvaharness.pipeline.stages.s4_deepdive import SYSTEM
    return SYSTEM


def _cache_probe_targets(cfg) -> dict[tuple[str, str], object]:
    """Unique (model_id, via) -> model config node, restricted to the vias
    `backends.llm.prompt()` actually dispatches to. Mirrors probe_backends()'s
    own dedup-by-(model_id, via) so the cache probe never double-charges a
    model that several roles share."""
    targets: dict[tuple[str, str], object] = {}
    for _role, m in _iter_model_roles(cfg):
        mid, via, _extras = resolve_model(m)
        if via not in _PROMPT_VIAS:
            continue
        targets.setdefault((mid, via), m)
    return targets


def _observe_call(phase_label: str, invoke) -> dict:
    """Run ONE backend call via *invoke* and return its cache usage: token
    VALUES by snapshot-diffing the global TOKENS accumulator around it (the
    only way to see a single call's cache read/write counts, since the
    backends return just the reply text), and field PRESENCE by observing the
    usage dicts the backend itself records into TOKENS during the call.

    Presence cannot come from the counter diff: `_bucket()` pre-fills every
    counter at 0 and `TOKENS.add()` coerces absent fields with `or 0`, so
    "the route never reported a write field" and "the route reported a write
    of 0" are indistinguishable in the aggregated counters — yet that exact
    distinction selects the verdict row (see classify_cache_verdict), and on
    the openai route the write field is per-call conditional
    (openai.py::_normalise_usage sets `cache_creation_input_tokens` only when
    the endpoint reports `prompt_tokens_details.cache_write_tokens`). So
    presence is OBSERVED at the one seam this process has: `TOKENS.add` is
    wrapped for the duration of the call — delegating to the real method, so
    accounting is byte-for-byte unchanged — and the TokenUsage dicts recorded
    under this call's phase label are captured. The capture filters on the
    accumulator's own current phase, i.e. the same attribution rule the
    counter diff uses.

    `phase_label` is unique per call, so the "before" bucket is always empty
    and the "after" bucket is exactly this call's contribution — still an
    explicit diff (not just a read of the post-call bucket), so this stays
    correct even if it is ever called concurrently for different labels.

    *invoke* must make exactly one call through a real backend seam — never a
    separate API client — so the request is built by the backend's own code
    exactly as a real scan would send it. Nothing about the request changes:
    the wrapper only watches what the backend was going to record anyway.
    """
    observed: list[dict] = []
    _sentinel = object()
    prev_add = TOKENS.__dict__.get("add", _sentinel)
    real_add = TOKENS.add

    def _observing_add(usage, **kw):
        if isinstance(usage, dict) and TOKENS.current_phase() == phase_label:
            observed.append(dict(usage))
        return real_add(usage, **kw)

    with TOKENS.phase(phase_label):
        before = dict(TOKENS.snapshot()["by_phase"].get(phase_label, {}))
        TOKENS.add = _observing_add
        try:
            invoke()
        finally:
            if prev_add is _sentinel:
                TOKENS.__dict__.pop("add", None)   # back to the class method
            else:
                TOKENS.add = prev_add
        after = dict(TOKENS.snapshot()["by_phase"].get(phase_label, {}))
    return {
        "cache_read": after.get("cache_read", 0) - before.get("cache_read", 0),
        "cache_write": after.get("cache_write", 0) - before.get("cache_write", 0),
        # Observed, per-call: did any usage this call recorded carry the field
        # at all (present-at-zero counts as present; absent stays absent)?
        "cache_read_present": any("cache_read_input_tokens" in u
                                  for u in observed),
        "cache_write_present": any("cache_creation_input_tokens" in u
                                   for u in observed),
    }


def _call_and_diff(*, model, system_prompt: str, user_prompt: str,
                    thinking_budget: int | None, phase_label: str) -> dict:
    """One `backends.llm.prompt()` call observed through _observe_call, so the
    request is built by sdk.py's/oai.py's own code (the `thinking` gate, the
    cache_control marker) exactly as a real scan would send it."""
    from vvaharness.backends.llm.registry import prompt as _prompt

    def _invoke():
        # The probe's whole point is `usage`, not the reply — the model is
        # told to answer "PONG" (4 chars, 1-2 tokens) under a 16-token
        # cap, so the report-prose defaults (150/30), keyed off the tag,
        # flag every design-correct answer as degenerate: same defect as
        # the connectivity ping in probe_backends(), just confined to
        # `doctor --cache-probe` output instead of a scan's. All of a
        # probe run's A/B calls share this one tag serially, so three of
        # them answering with literally nothing raises out of _prompt()
        # into run_cache_probe()'s per-arm handler — a FAILED row, which
        # an all-empty route deserves. Values derived at _PROBE_PING_MIN_*.
        with stage_floors("cache-probe",
                          min_chars=_PROBE_PING_MIN_CHARS,
                          min_tokens=_PROBE_PING_MIN_TOKENS):
            _prompt(user_prompt, model=model, system_prompt=system_prompt,
                    thinking_budget=thinking_budget,
                    max_tokens=_PROBE_MAX_TOKENS,
                    timeout=_PROBE_TIMEOUT_S, tag="cache-probe")

    return _observe_call(phase_label, _invoke)


def _deepagents_cache_probe_targets(cfg) -> dict[tuple[str, str], object]:
    """Unique (model_id, "deepagents") -> model config node — the roles the
    prompt-route probe skips. Mirrors _cache_probe_targets()'s dedup so a
    model several deepagents roles share is probed (and billed) once."""
    targets: dict[tuple[str, str], object] = {}
    for _role, m in _iter_model_roles(cfg):
        mid, via, _extras = resolve_model(m)
        if via != "deepagents":
            continue
        targets.setdefault((mid, via), m)
    return targets


def _deepagents_marker_would_be_placed(cfg, model_id: str,
                                       provider: str | None) -> bool:
    """Whether the deepagents route's OWN gate places block markers on this
    call — asked of the same two predicates the middleware threading uses
    (`markers_on` reads the sdk block's `cache_markers` key;
    `BlockMarkerPromptCaching` marks only Anthropic-routed models), never
    re-derived here. No `cache_route` host detection exists on this route."""
    from vvaharness.backends.harness.provider_routing import routes_to_anthropic
    from vvaharness.backends.llm.deepagents import markers_on
    return (markers_on(getattr(cfg, "sdk", None))
            and routes_to_anthropic(model_id, provider))


def _deepagents_base_url(cfg, model_id: str, provider: str | None) -> str:
    """Scheme+host of the base URL the deepagents route will actually use,
    read from the same env build the dispatch seam performs."""
    from vvaharness.backends.harness.deepagents.models import (
        anthropic_base,
        openai_base,
    )
    from vvaharness.backends.harness.provider_routing import routes_to_anthropic
    from vvaharness.backends.llm.deepagents import build_harness_env
    try:
        env = build_harness_env(
            model_id, provider,
            sdk_cfg=getattr(cfg, "sdk", None),
            openai_cfg=getattr(cfg, "openai", None),
            cfg_dir=getattr(cfg, "_data", {}).get("_config_dir"),
        )
        raw = (anthropic_base(env) if routes_to_anthropic(model_id, provider)
               else openai_base(env))
    except Exception:  # noqa: BLE001 — diagnostic label only; never break the probe
        return "(unresolved)"
    return _scheme_host(raw)


def _probe_deepagents_cache(cfg, model_node, *, label_base: str) -> tuple[dict, dict]:
    """Two dispatch_prompt calls (A then B) sharing one filler system prompt.

    Write-then-read shape: Call A should create cache entries
    (`cache_creation > 0`), Call B — a different user turn — should read the
    shared system prefix back (`cache_read > 0`). Runs in a throwaway
    directory (the harness roots its virtual filesystem at `cwd`), through
    the real dispatch seam, so the request carries exactly the block markers
    a live scan's one-shot would."""
    from vvaharness.backends.llm.deepagents import dispatch_prompt
    system_prompt = cache_probe_filler()

    def _call(user_prompt: str, phase_label: str, workdir: str) -> dict:
        def _invoke():
            # Same PONG-sized reply and per-tag floors as _call_and_diff.
            with stage_floors("cache-probe",
                              min_chars=_PROBE_PING_MIN_CHARS,
                              min_tokens=_PROBE_PING_MIN_TOKENS):
                dispatch_prompt(user_prompt, model=model_node, cfg=cfg,
                                cwd=workdir, system_prompt=system_prompt,
                                max_tokens=_PROBE_MAX_TOKENS, tag="cache-probe")

        return _observe_call(phase_label, _invoke)

    with tempfile.TemporaryDirectory(prefix="vva-cache-probe-deepagents-") as workdir:
        write = _call(_USER_MSG_A, f"{label_base}::A", workdir)
        read = _call(_USER_MSG_B, f"{label_base}::B", workdir)
    return write, read


def run_cache_probe(cfg) -> bool:
    """The live diagnostic behind `vvaharness doctor --cache-probe`.

    For every (model_id, via) pair in *cfg* that flows through
    `backends.llm.prompt()`, for each of two system-prompt shapes (a synthetic
    ≥8192-token deterministic filler, and the deep-dive stage's real system
    prompt) and two `thinking` arms (forced on via a probe-only budget, forced
    off), fires two calls — Call A and Call B, within `_CALL_B_DEADLINE_S`
    seconds of each other — with the same system prompt and a different
    ~50-token user turn. Usage is read by diffing TOKENS around each call,
    and cache-field presence is observed from the usage dicts the backend
    records during it (see _call_and_diff). Prints one row per (model,
    filler, thinking-arm) and a
    closing, plain-language verdict per row, using classify_cache_verdict().

    Never invoked during a scan, and never implicitly: only `doctor
    --cache-probe` calls this, and only after the ordinary backend
    connectivity probe has already passed (nothing to diagnose otherwise).
    """
    targets = _cache_probe_targets(cfg)
    deepagents_targets = _deepagents_cache_probe_targets(cfg)
    shapes = (("synthetic", cache_probe_filler()),
             ("deepdive-system", _deepdive_system_prompt()))
    n_models = len(targets)
    n_deepagents = len(deepagents_targets)
    # prompt routes: shapes x thinking-arms x (A, B); deepagents: (A, B) only.
    n_calls = n_models * len(shapes) * 2 * 2 + n_deepagents * 2
    if not n_calls:
        print("  [cache-probe] no sdk/openai/cli/deepagents model roles "
              "configured — nothing to probe", file=sys.stderr)
        return True
    print(f"  [cache-probe] {n_models} prompt-route pair(s) x {len(shapes)} filler "
          f"shape(s) x 2 thinking arm(s) x 2 calls + {n_deepagents} deepagents "
          f"pair(s) x 2 calls = {n_calls} call(s), "
          f"~8.2k tokens/call -> ~{n_calls * 8200:,} tokens total",
          file=sys.stderr)

    ok = True
    rows: list[dict] = []
    for (model_id, via), model_node in sorted(targets.items()):
        base_url = _resolved_base_url_scheme_host(via)
        for shape_name, system_prompt in shapes:
            for think_label, budget in (("on", _PROBE_THINKING_BUDGET), ("off", None)):
                label_base = f"cache_probe::{model_id}::{via}::{shape_name}::{think_label}"
                try:
                    t0 = time.time()
                    write = _call_and_diff(
                        model=model_node, system_prompt=system_prompt,
                        user_prompt=_USER_MSG_A, thinking_budget=budget,
                        phase_label=f"{label_base}::A")
                    read = _call_and_diff(
                        model=model_node, system_prompt=system_prompt,
                        user_prompt=_USER_MSG_B, thinking_budget=budget,
                        phase_label=f"{label_base}::B")
                    elapsed = time.time() - t0
                except Exception as e:  # noqa: BLE001 — report and keep probing
                    print(f"    ✗ [{via}] {model_id} filler={shape_name} "
                          f"thinking={think_label} FAILED: {type(e).__name__}: "
                          f"{redact(str(e))[:200]}", file=sys.stderr)
                    ok = False
                    continue
                if elapsed > _CALL_B_DEADLINE_S:
                    print(f"    WARN [{via}] {model_id} filler={shape_name} "
                          f"thinking={think_label}: call A->B took {elapsed:.1f}s "
                          f"(> the {_CALL_B_DEADLINE_S:.0f}s target — still far "
                          f"under the 5-minute TTL, but re-run to confirm)",
                          file=sys.stderr)
                thinking_sent = _thinking_actually_sent(model_id, budget)
                usage_a, usage_b = usage_dict_for_classifier(
                    cache_write=write["cache_write"],
                    cache_read=read["cache_read"],
                    write_present=write["cache_write_present"],
                    read_present=read["cache_read_present"])
                verdict = classify_cache_verdict(usage_a, usage_b)
                if (verdict == V_ANTHROPIC_NOT_HONOURED
                        and _marker_would_be_placed(
                            via, system_prompt, model_id) is False):
                    # 0-write/0-read has two distinct causes: the gateway
                    # ignored a marker it was sent, or our own gate never sent
                    # one (unknown route, kill switch off, prompt below the
                    # model's minimum). Only the backend's own gate can tell
                    # them apart — and only a definite "no marker went out"
                    # (False, never None) may move the blame off the gateway.
                    verdict = V_MARKER_WITHHELD
                rows.append({
                    "model_id": model_id, "via": via, "filler": shape_name,
                    "thinking_requested": think_label, "thinking_sent": thinking_sent,
                    "base_url": base_url, "cache_creation": write["cache_write"],
                    "cache_read": read["cache_read"], "verdict": verdict,
                })
                print(f"    [{via:<6}] {model_id:<28} filler={shape_name:<10} "
                      f"thinking_sent={'yes' if thinking_sent else 'no':<3} "
                      f"base_url={base_url:<30} creation={write['cache_write']:<8} "
                      f"read={read['cache_read']:<8} -> {verdict}", file=sys.stderr)

    for (model_id, via), model_node in sorted(deepagents_targets.items()):
        provider = getattr(model_node, "provider", None)
        base_url = _deepagents_base_url(cfg, model_id, provider)
        label_base = f"cache_probe::{model_id}::{via}::synthetic::off"
        try:
            t0 = time.time()
            write, read = _probe_deepagents_cache(cfg, model_node,
                                                  label_base=label_base)
            elapsed = time.time() - t0
        except Exception as e:  # noqa: BLE001 — report and keep probing
            print(f"    ✗ [{via}] {model_id} filler=synthetic FAILED: "
                  f"{type(e).__name__}: {redact(str(e))[:200]}", file=sys.stderr)
            ok = False
            continue
        if elapsed > _CALL_B_DEADLINE_S:
            # Expected on this route: graph build dominates the first call.
            print(f"    WARN [{via}] {model_id} filler=synthetic: call A->B "
                  f"took {elapsed:.1f}s (> the {_CALL_B_DEADLINE_S:.0f}s target "
                  f"— still far under the 5-minute TTL, but re-run to confirm)",
                  file=sys.stderr)
        usage_a, usage_b = usage_dict_for_classifier(
            cache_write=write["cache_write"],
            cache_read=read["cache_read"],
            write_present=write["cache_write_present"],
            read_present=read["cache_read_present"])
        verdict = classify_cache_verdict(usage_a, usage_b)
        if (verdict == V_ANTHROPIC_NOT_HONOURED
                and not _deepagents_marker_would_be_placed(cfg, model_id, provider)):
            # Same disambiguation as the prompt-route arm: only "our own gate
            # never placed a marker" may move the blame off the gateway.
            verdict = V_MARKER_WITHHELD
        rows.append({
            "model_id": model_id, "via": via, "filler": "synthetic",
            "thinking_requested": "off", "thinking_sent": False,
            "base_url": base_url, "cache_creation": write["cache_write"],
            "cache_read": read["cache_read"], "verdict": verdict,
        })
        print(f"    [{via:<6}] {model_id:<28} filler={'synthetic':<10} "
              f"thinking_sent={'no':<3} base_url={base_url:<30} "
              f"creation={write['cache_write']:<8} "
              f"read={read['cache_read']:<8} -> {verdict}", file=sys.stderr)

    print("\n  [cache-probe] verdicts:", file=sys.stderr)
    for r in rows:
        print(f"    {r['model_id']} / via={r['via']} / filler={r['filler']} / "
              f"thinking_requested={r['thinking_requested']}: "
              f"{_VERDICT_TEXT[r['verdict']]}", file=sys.stderr)
    if not rows:
        print("    (no successful calls — see FAILED lines above)", file=sys.stderr)
    return ok
