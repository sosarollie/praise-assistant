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

"""Run-level scan manifest (vvaharness).

Captures tool version, active model roles, config hash, target git SHA, and
timing for each run, written to ./run_manifest_YYYYMMDDTHHMMSSZ.json, plus the per-stage
duration/token/dollar table composed from the pipeline's two process-global
recorders (util.stage_telemetry.STAGES and util.tokens.TOKENS). The manifest is
the only output that sees the FULL run: the markdown report is rendered before
s10/s11 by design, so their spend appears here and nowhere else.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Flag names whose VALUE is a likely secret — matched case-insensitively as a
# substring of the flag token, so --git-token / --anthropic-api-key /
# --db-password all hit. ("key" alone is intentionally excluded so --keep-clones
# etc. don't false-match.)
_SECRET_FLAG_RX = re.compile(
    r"(?i)(token|password|passwd|pwd|secret|api[_-]?key|access[_-]?key"
    r"|client[_-]?secret|auth|credential|bearer|private[_-]?key)")


_RUN_MANIFEST_STEM = "run_manifest"


def _manifest_ts_from_started(started_iso: str) -> str:
    """Return the UTC timestamp token used in default run-manifest names."""
    try:
        dt = _dt.datetime.fromisoformat(started_iso.replace("Z", "+00:00"))
    except Exception:
        dt = _dt.datetime.now(_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _default_manifest_dest(started_iso: str, cwd: Path | None = None) -> Path:
    """Choose a timestamped manifest path in cwd without overwriting."""
    root = cwd or Path.cwd()
    ts = _manifest_ts_from_started(started_iso)
    first = root / f"{_RUN_MANIFEST_STEM}_{ts}.json"
    if not first.exists():
        return first
    i = 1
    while True:
        candidate = root / f"{_RUN_MANIFEST_STEM}_{ts}_{i:02d}.json"
        if not candidate.exists():
            return candidate
        i += 1


def _scrub_argv(argv: list[str]) -> list[str]:
    """Redact secret-bearing values from a captured argv before it persists to
    run_manifest.json (defense-in-depth — no shipped flag takes a secret, but a
    manifest can outlive the process and land in shared logs).

    Two passes:
      1. The value after a secret-like flag — both ``--token VALUE`` (next token)
         and the inline ``--token=VALUE`` form — is replaced with ``***``.
      2. ``redact_tree()`` over the result masks secret-SHAPED tokens (URL
         userinfo, JWTs, AWS/GitHub keys, PANs/SSNs) regardless of flag name, so
         e.g. an inline-credential URL passed as any argument is scrubbed too.
    """
    out: list[str] = []
    i, n = 0, len(argv)
    while i < n:
        tok = argv[i]
        if tok.startswith("-") and "=" in tok:                 # --flag=VALUE
            flag, _eq, val = tok.partition("=")
            if val and _SECRET_FLAG_RX.search(flag):
                out.append(f"{flag}=***")
                i += 1
                continue
        if (tok.startswith("-") and _SECRET_FLAG_RX.search(tok)  # --flag VALUE
                and i + 1 < n and not argv[i + 1].startswith("-")):
            out.append(tok)
            out.append("***")
            i += 2
            continue
        out.append(tok)
        i += 1
    # Shape-based second pass — catches secret-looking values regardless of flag.
    from vvaharness.report.redact import redact_tree
    return redact_tree(out)


def _git_sha(args: list[str]) -> str | None:
    repo = None
    for i, a in enumerate(args):
        if a == "--repo" and i + 1 < len(args):
            repo = args[i + 1]
        elif a.startswith("--repo="):
            repo = a.split("=", 1)[1]
    if not repo:
        return None
    # Treat --repo as data, not git options. This runs in manifest.capture()
    # BEFORE the orchestrator validates args.repo, so normalize+validate the path
    # here and run git with cwd= rather than the -C flag — the value is then
    # never in git's option position. (`git -C <v>` already takes <v> as a
    # literal path, so leading-dash option-injection does not reproduce; this is
    # defensive hardening of an otherwise-unvalidated sink, not a live exploit.)
    try:
        repo_dir = Path(repo).resolve()
    except (OSError, ValueError):
        return None
    if not repo_dir.is_dir():
        return None
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_dir),
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or None
    except Exception:
        return None


# Every role the run can spend on — the same list orchestrator.config_paths
# walks at startup (including the s0 callgraph roles, which config_paths skips
# at runtime unless step0.callgraph_detection: llm selects them), kept local so
# _models() stays independent of the (heavy) orchestrator package.
# models.validate is spelled as a nested `orchestrator` role, so it is
# unwrapped below.
_MODEL_ROLES = ("graph_annotate", "callgraph_creation", "autoexclude",
                "preprocess", "threatmodel", "decompose", "deepdive", "verify",
                "dedup", "chain", "remediate", "validate")
# exploit_verification is NOT here on purpose (unlike config_paths._MODEL_ROLES):
# validate above unwraps ONE sub-role (orchestrator) into this same flat shape, but EV
# has N sub-roles (judge/attacker/...) that each need their own entry, recorded
# separately below as "exploit_verification.<sub_role>" — flattening it here would mean
# picking one sub-role and silently dropping the rest. See
# test_manifest_covers_every_top_level_model_role for the guard that keeps this the only
# difference from config_paths._MODEL_ROLES.


# Vendor each fixed transport reaches, regardless of what the model is named:
# `via: cli` shells out to the `claude` binary (backends/llm/cli.py), `via: sdk`
# builds an anthropic.Anthropic client (backends/llm/sdk.py), and `via: openai`
# speaks the OpenAI-compatible wire format at OPENAI_BASE_URL
# (backends/llm/openai.py). Only `deepagents` picks its vendor per model
# (deepagents/options/model_building.py branches on routes_to_anthropic), so
# the name/provider heuristic in _resolved_route applies to that via ALONE.
# Do not "simplify" this back to heuristic-for-every-via: on a fixed transport
# the heuristic records what the model is *named*, not where the call went —
# a gateway alias without "claude" on via:sdk is still an Anthropic call, and
# a claude-named id on via:openai still goes to the OpenAI-compatible endpoint.
_FIXED_VIA_ROUTES = {"cli": "anthropic", "sdk": "anthropic", "openai": "openai"}


def _resolved_route(via: str, model_id: str, provider: str | None) -> str | None:
    """Return the vendor route this role's calls actually reach.

    ``"anthropic"``/``"openai"`` per _FIXED_VIA_ROUTES for the three fixed
    transports; the routes_to_anthropic name/provider heuristic for
    ``deepagents``, the one via that chooses its vendor per model. An
    unrecognised via yields ``None`` — the manifest's convention for
    not-determinable (target_git_sha, config_local_sha256, provider) — because
    this is an audit record: a confidently wrong vendor for a transport we do
    not understand is worse than an absent one.
    """
    fixed = _FIXED_VIA_ROUTES.get(via)
    if fixed is not None:
        return fixed
    if via == "deepagents":
        # Route resolution stays import-light on purpose: provider_routing's
        # transitive closure pulls no langchain/deepagents/anthropic/openai,
        # whereas backends.llm.registry eagerly imports the cli backend at
        # module scope — and any exception here is swallowed by _models(),
        # which would silently degrade the entire `models` section to {}.
        from vvaharness.backends.harness.provider_routing import routes_to_anthropic
        return "anthropic" if routes_to_anthropic(model_id, provider) else "openai"
    return None


#: The one via that selects its vendor and transport per model.
_DEEPAGENTS_VIA = "deepagents"


def _resolved_transport(via: str, model_id: str, provider: str | None,
                        node: object) -> str | None:
    """Return the CONFIGURED OpenAI-branch transport this role's calls use.

    Only ``deepagents`` selects a transport, and only on its OpenAI branch:
    every other via — and the Anthropic route — yields ``None`` (the
    manifest's not-determinable convention, matching ``_resolved_route``).
    Override-aware: a boolean ``use_responses_api`` on the node wins, else the
    Responses default. Runtime-learned fallbacks are visible separately, via
    the ``deepagents_responses_fallback`` counter in the counters dump. Same
    import-light discipline as ``_resolved_route``.
    """
    if via != _DEEPAGENTS_VIA:
        return None
    from vvaharness.backends.harness.provider_routing import (  # noqa: PLC0415
        TRANSPORT_CHAT_COMPLETIONS,
        TRANSPORT_RESPONSES,
        routes_to_anthropic,
    )
    if routes_to_anthropic(model_id, provider):
        return None
    override = getattr(node, "use_responses_api", None)
    return TRANSPORT_CHAT_COMPLETIONS if override is False else TRANSPORT_RESPONSES


def _models(cfg_path: Path) -> dict:
    try:
        from vvaharness import config as config_mod
        cfg = config_mod.load(cfg_path)
        roles = {}
        for name in _MODEL_ROLES:
            r = getattr(cfg.models, name, None)
            is_validate = name == "validate"
            if is_validate and r is not None:
                r = getattr(r, "orchestrator", None)
            if r is not None:
                model_id = getattr(r, "id", str(r))
                # provider is null when the profile does not pin one (matching
                # the manifest's null-for-absent convention: target_git_sha,
                # config_local_sha256, pricing). resolved_route is the vendor
                # the call actually reaches, derived from the via (see
                # _resolved_route); recording both makes the run reproducible.
                provider = getattr(r, "provider", None)
                # `or "cli"`: registry.resolve() coerces a falsy via (absent OR
                # an explicit `via: null`) to the cli default — mirror it so the
                # recorded via/route match the actual dispatch (registry.py).
                via = getattr(r, "via", None) or "cli"
                if is_validate:
                    # Same normalizer the runtime uses, so models.validate can
                    # never disagree with validation_panel.orchestrator.
                    from vvaharness.validation.config.validate_role import (  # noqa: PLC0415
                        normalize_validate_backend,
                    )
                    via, provider = normalize_validate_backend(via, provider)
                use_responses_api = getattr(r, "use_responses_api", None)
                roles[name] = {
                    "id": model_id,
                    "via": via,
                    "provider": provider,
                    "resolved_route": _resolved_route(via, model_id, provider),
                    "resolved_transport": _resolved_transport(
                        via, model_id, provider, r),
                    "use_responses_api": (
                        use_responses_api
                        if isinstance(use_responses_api, bool) else None),
                }
        # EV's roles are nested (models.exploit_verification.*), so the loop above cannot
        # reach them. Recorded under their dotted names — the spelling EV_MODEL_ROLES and
        # the preflight already use — because a manifest that omits them cannot answer
        # which model held the confirmation authority for a report's EV stamps.
        ev = getattr(cfg.models, "exploit_verification", None)
        if ev is not None:
            from vvaharness.exploit_verification.settings import EV_MODULES
            for sub_name in EV_MODULES:
                node = getattr(ev, sub_name, None)
                if node is None:          # optional by design (no attacker = no loop)
                    continue
                # Same shape and the same `or "cli"` coercion as the loop above, so an
                # EV role is auditable on the terms every other role already is.
                model_id = getattr(node, "id", str(node))
                provider = getattr(node, "provider", None)
                via = getattr(node, "via", None) or "cli"
                use_responses_api = getattr(node, "use_responses_api", None)
                roles[f"exploit_verification.{sub_name}"] = {
                    "id": model_id,
                    "via": via,
                    "provider": provider,
                    "resolved_route": _resolved_route(via, model_id, provider),
                    "resolved_transport": _resolved_transport(
                        via, model_id, provider, node),
                    "use_responses_api": (
                        use_responses_api
                        if isinstance(use_responses_api, bool) else None),
                }
        return roles
    except Exception as e:
        print(f"  [manifest] could not load model roles from {cfg_path}: {e}",
              file=sys.stderr)
        return {}


def _model_spec(role) -> dict | None:
    if role is None:
        return None
    spec = {"id": getattr(role, "id", str(role)),
            "via": getattr(role, "via", "cli")}
    provider = getattr(role, "provider", None)
    if provider:
        spec["provider"] = provider
    use_responses_api = getattr(role, "use_responses_api", None)
    if isinstance(use_responses_api, bool):
        spec["use_responses_api"] = use_responses_api
    return spec


_PANEL_ORCHESTRATOR = "orchestrator"
_PANEL_PERSONAS = ("security_architect", "penetration_tester",
                   "cross_repo_analyzer")


def _panel_specs(validate: object) -> dict:
    """Collect the present models.validate role specs, orchestrator first."""
    specs = {}
    orch = getattr(validate, _PANEL_ORCHESTRATOR, None)
    if orch is not None:
        specs[_PANEL_ORCHESTRATOR] = orch
    for name in _PANEL_PERSONAS:
        spec = getattr(validate, name, None)
        if spec is not None:
            specs[name] = spec
    return specs


def _panel_entry(spec: object, via: str, provider: str | None) -> dict:
    model_id = getattr(spec, "id", str(spec))
    return {
        "id": model_id,
        "via": via,
        "provider": provider,
        "resolved_route": _resolved_route(via, model_id, provider),
    }


def _validation_panel(validate: object) -> dict:
    """Serialize models.validate with every entry on the orchestrator's route.

    Personas run as subagents inside the orchestrator's harness session, so a
    persona-level ``via``/``provider`` is dead config and is never read here
    (default.yaml documents the inheritance; validation/cli/_model.py warns
    when a profile declares one).
    """
    if validate is None:
        return {}
    specs = _panel_specs(validate)
    orch = specs.get(_PANEL_ORCHESTRATOR)
    if orch is None:
        # No orchestrator: validation cannot run and no route is derivable.
        return {name: {"id": getattr(spec, "id", str(spec))}
                for name, spec in specs.items()}
    # Lazy import for the same reason as provider_routing in _resolved_route.
    from vvaharness.validation.config.validate_role import (  # noqa: PLC0415
        normalize_validate_backend,
    )
    # `or "cli"`: mirror registry.resolve()'s coercion of a falsy via (_models).
    via = getattr(orch, "via", None) or "cli"
    via, provider = normalize_validate_backend(via, getattr(orch, "provider", None))
    return {name: _panel_entry(spec, via, provider) for name, spec in specs.items()}


def _pick(section, *names: str) -> dict:
    return {name: getattr(section, name, None) for name in names}


def _input_fingerprint(value, config_dir: Path) -> dict | None:
    if value is None or not str(value).strip():
        return None
    configured_path = Path(str(value))
    resolved_path = configured_path if configured_path.is_absolute() else config_dir / configured_path
    return {
        "path": str(configured_path),
        "sha256": _config_sha256(resolved_path),
    }


def _effective_scan_controls(cfg_path: Path) -> dict:
    """Return the non-secret configuration that materially changes scan output."""
    try:
        from vvaharness import config as config_mod
        cfg = config_mod.load(cfg_path)
        panel = _validation_panel(getattr(cfg.models, "validate", None))

        config_dir = Path(getattr(cfg, "_config_dir", cfg_path.parent))
        inject = getattr(cfg, "inject", None)
        remediate = getattr(cfg, "step_remediate", None)
        controls = {
            "cache": _pick(cfg, "cache_markers", "cache_route", "cache_min_block_tokens"),
            "step0": _pick(cfg.step0, "enabled", "callgraph_detection", "sources_yaml",
                           "sinks_yaml", "call_graph_max_targets"),
            "step1": _pick(cfg.step1, "auto_exclude", "auto_exclude_max_tokens", "mode",
                           "call_graph", "max_budget_usd", "max_turns", "max_file_kb",
                           "call_graph_validate", "call_graph_supplement", "call_graph_rounds",
                           "call_graph_max_targets", "config_dedup"),
            "step2": _pick(cfg.step2, "enabled", "max_tokens", "max_threats", "baseline",
                           "max_doc_chars", "max_manifest_chars", "max_modules",
                           "max_entry_points", "max_config_reps", "max_api_artefacts",
                           "max_graph_files", "max_graph_sinks", "max_graph_edges"),
            "step3": _pick(cfg.step3, "max_tokens", "timeout", "taint_chunks",
                           "taint_max_hops", "taint_max_chunks", "taint_files_per_hop",
                           "pack_by", "chunk_token_budget", "chunk_overhead_tokens",
                           "risk_chunk_loc", "catchall_enabled",
                           "catchall_deduct_lens_coverage", "catchall_mode",
                           "catchall_chunk_loc", "catchall_max_files", "max_files_per_chunk",
                           "specialists", "specialist_chunk_loc", "threat_surface_fallbacks",
                           "max_threat_fallback_chunks"),
            "step4": _pick(cfg.step4, "parallel", "timeout", "runs", "taint_runs",
                           "taint_prompt_mode", "vote_threshold", "specialist_runs",
                           "line_bucket", "max_findings_per_run", "max_tokens",
                           "neighbor_context_lines", "neighbor_context_max"),
            "step5_prefilter": _pick(cfg.step5_prefilter, "min_pre_confidence",
                                       "require_evidence", "line_tolerance",
                                       "pre_verify_semantic", "pre_verify_threshold"),
            "step6_verify": _pick(cfg.step6_verify, "parallel", "min_confidence",
                                    "max_budget_usd", "max_turns", "allowed_tools"),
            "step7_dedup": _pick(cfg.step7_dedup, "line_tolerance", "semantic", "max_tokens"),
            "step8": _pick(cfg.step8, "max_tokens", "timeout"),
            "step_remediate": _pick(remediate, "enabled", "enforce_policy", "top_n_findings",
                                      "max_budget_usd", "max_turns", "allowed_tools"),
            "remediation_model": _model_spec(getattr(cfg.models, "remediate", None)),
            "step_validate": _pick(cfg.step_validate, "enabled", "effort", "max_turns",
                                     "max_budget_usd", "max_findings", "allowed_tools"),
            "validation_panel": panel,
            "input_hashes": {
                "step0_sources_yaml": _input_fingerprint(getattr(cfg.step0, "sources_yaml", None), config_dir),
                "step0_sinks_yaml": _input_fingerprint(getattr(cfg.step0, "sinks_yaml", None), config_dir),
                "cve_file": _input_fingerprint(getattr(inject, "cve_file", None), config_dir),
                "controls_file": _input_fingerprint(getattr(inject, "controls_file", None), config_dir),
                "cmdb_file": _input_fingerprint(getattr(inject, "cmdb_file", None), config_dir),
                "policy_file": _input_fingerprint(getattr(remediate, "policy_file", None), config_dir),
                "playbook_file": _input_fingerprint(getattr(remediate, "playbook_file", None), config_dir),
            },
        }
        return controls
    except Exception as e:
        print(f"  [manifest] could not capture effective scan controls from {cfg_path}: {e}",
              file=sys.stderr)
        return {}


def _pricing_file(cfg_path: Path) -> str | None:
    try:
        from vvaharness import config as config_mod
        cfg = config_mod.load(cfg_path)
        return getattr(getattr(cfg, "pricing", None), "file", None)
    except Exception as e:
        print(f"  [manifest] could not read pricing.file from {cfg_path}: {e}",
              file=sys.stderr)
        return None


def _telemetry_fields(cfg_path: Path, models: dict) -> dict:
    """Compose the per-stage duration/token/cost fields for this run.

    Imports are deferred so a manifest write never depends on the pipeline
    modules being importable, and the whole thing is wrapped: telemetry is
    reporting, so a failure here must degrade to a manifest without the section
    rather than lose the manifest.
    """
    try:
        from vvaharness.util import stage_telemetry
        from vvaharness.util.pricing import load_pricing
        from vvaharness.util.tokens import TOKENS
        role_models = {role: spec["id"] for role, spec in models.items()
                       if isinstance(spec, dict) and spec.get("id")}
        section = stage_telemetry.compose_stage_section(
            stage_telemetry.STAGES.snapshot(), TOKENS.snapshot(),
            role_models, load_pricing(_pricing_file(cfg_path)))
        return dict(section)
    except Exception as e:
        print(f"  [manifest] WARNING: per-stage telemetry unavailable: {e}",
              file=sys.stderr)
        return {}


def _config_sha256(cfg_path: Path) -> str | None:
    if not cfg_path.exists():
        return None
    try:
        return hashlib.sha256(cfg_path.read_bytes()).hexdigest()
    except OSError as e:
        print(f"  [manifest] could not hash config {cfg_path}: {e}",
              file=sys.stderr)
        return None
def _ev_collection() -> Path | None:
    """The configured EV collection path, or ``None``.

    Read through EV's own resolver so the manifest and the run cannot disagree about what
    "configured" means. Wrapped, like the rest of this module: a manifest must never fail
    over a field it could not fill.
    """
    try:
        from vvaharness.exploit_verification.options import collection_path
        path = collection_path()
        return Path(path) if path else None
    except Exception as e:                      # noqa: BLE001 — reporting, never fatal
        print(f"  [manifest] could not read EV_API_COLLECTION: {e}", file=sys.stderr)
        return None


@contextlib.contextmanager
def capture(cfg_path: Path, args: list[str], out: Path | None = None):
    cfg_path = Path(cfg_path)
    from vvaharness import __version__
    ev_collection = _ev_collection()
    m: dict = {
        "tool": "vvaharness",
        "version": __version__,
        "started": datetime.now(timezone.utc).isoformat(),
        "argv": _scrub_argv(args),
        "config_profile": str(cfg_path),
        "config_sha256": _config_sha256(cfg_path),
        # A config.local.yaml sibling silently overrides the chosen profile;
        # hash it too so the manifest records the *effective* configuration
        # (None when no overlay is present).
        "config_local_sha256": _config_sha256(cfg_path.with_name("config.local.yaml")),
        # The API collection EV verified against. It comes from EV_API_COLLECTION rather
        # than argv, so the captured argv no longer records it — and a reader cannot tell
        # which collection produced a report's EV stamps without it. Hashed for the same
        # reason the profile is: the path alone does not pin the contents. Records what
        # was CONFIGURED; whether EV then ran is what the stage telemetry below shows.
        "ev_api_collection": (str(ev_collection) if ev_collection else None),
        "ev_api_collection_sha256": (_config_sha256(ev_collection)
                                     if ev_collection else None),
        "models": _models(cfg_path),
        "effective_scan_controls": _effective_scan_controls(cfg_path),
        "target_git_sha": _git_sha(args),
        "exit_code": None,
    }
    t0 = time.time()
    try:
        yield m
    finally:
        # Only persist a manifest when a scan actually ran. The caller sets
        # exit_code after orchestrator.main() returns; if argparse rejected the
        # args, printed --help, or otherwise raised SystemExit before the scan
        # began, exit_code stays None and we write nothing — no junk manifest
        # for a help screen or a usage error.
        #
        # NB: guard with `if`, never `return`, inside this finally — a return
        # here would suppress an in-flight exception (e.g. argparse's
        # SystemExit) propagating through the `with`, which is exactly the case
        # we must let through.
        if m.get("exit_code") is not None:
            m["ended"] = datetime.now(timezone.utc).isoformat()
            m["duration_sec"] = round(time.time() - t0, 1)
            m.update(_telemetry_fields(cfg_path, m.get("models") or {}))
            # Append per-stage error counts so run_manifest.json surfaces scan
            # health alongside timing. Best-effort — a missing log yields {}.
            try:
                from vvaharness.util import errlog as _errlog
                errors = _errlog.counts_by_stage()
                if errors:
                    m["errors_by_stage"] = errors
            except Exception:
                pass
            # The remediation/validation rollup s11 recorded. Best-effort, and
            # omitted when S11 did not run (a --stop-after s10 run, a disabled
            # step_validate, or a preflight-disabled stage) — a validation
            # rollup with no validation is unknown rather than clean.
            # Invocation-wide for the same reason the counters block below
            # takes snapshot_cumulative(): this manifest covers the whole
            # invocation, not the last repo of a batch.
            try:
                from vvaharness.orchestrator import case_rollup
                rollup = case_rollup.totals()
                if rollup:
                    m["remediation"] = rollup
            except Exception:
                pass
            # Every counter, verbatim. The report renders only names on a
            # hand-kept whitelist in util/metrics.py, and that list rots: every
            # counter added since it was written is bumped and then discarded,
            # so diagnostics of real coverage loss (dropped facts, files evicted
            # on a scan error) reached no surface at all. This is the engineer
            # view, so it takes the whole snapshot and needs no maintenance.
            # snapshot() also carries COUNTERS.note strings; today those are an
            # output-shape enum, repo-kind labels and baseline ids — no paths or
            # credentials. Future notes must keep that: this dump is unfiltered.
            try:
                from vvaharness.util.counters import COUNTERS as _COUNTERS
                # Cumulative, not snapshot(): a batch run resets the counters per
                # repo while this manifest covers the whole invocation, so
                # snapshot() would report only the last repo as if it were the
                # run's totals.
                snap = _COUNTERS.snapshot_cumulative()
                if snap:
                    m["counters"] = {k: snap[k] for k in sorted(snap)}
            except Exception:
                pass
            dest = out or _default_manifest_dest(str(m.get("started") or ""))
            try:
                # default=str, and deliberately not a widened `except`. This
                # manifest is the run's only record of what the scan cost, and
                # this write sits in a `finally` on the CLI exit path: one
                # non-JSON-native value — a Path noted into COUNTERS, say —
                # would otherwise raise TypeError past the OSError handler,
                # kill the CLI with a raw traceback after a successful scan,
                # and take the whole cost record with it. Widening the except
                # would "fix" the crash by losing the file instead; degrading
                # one exotic value to its string form keeps the record.
                dest.write_text(json.dumps(m, indent=2, default=str),
                                encoding="utf-8")
                print(f"  [manifest] wrote {dest}", file=sys.stderr)
            except OSError as e:
                print(f"  [manifest] WARNING: failed to write run manifest "
                      f"{dest}: {e}", file=sys.stderr)
