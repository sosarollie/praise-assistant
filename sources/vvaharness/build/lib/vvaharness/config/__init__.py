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

"""Config loader. Reads config.yaml, expands ${ENV:-default} placeholders."""
from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit

import yaml

from vvaharness.config.constants import (
    CREDENTIAL_DESTINATIONS,
    ENDPOINT_KEYS,
    LOCAL_OVERLAY_NAME,
    NO_LOCAL_CONFIG_ENV,
    TLS_ROUTING_KEYS,
    is_secret_var_name,
)

_ENV_PAT = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")


class ConfigPolicyError(ValueError):
    """Refusal to load a config that violates the interpolation or overlay-trust policy."""

# Overlay paths already announced this process — load() is called several times
# per run (manifest capture, orchestrator, doctor, …); dedupe so the
# config.local.yaml provenance line is emitted once per unique overlay, not once
# per load() call.
_logged_overlays: set[str] = set()


def _expand_env(m: re.Match[str], path: tuple[str, ...]) -> str:
    name, default = m.group(1), m.group(2)
    key_path = ".".join(path)
    # Refused on the variable NAME alone, set or unset, so a profile fails the
    # same way on every machine instead of only where the secret is present.
    if is_secret_var_name(name) and key_path not in CREDENTIAL_DESTINATIONS:
        allowed = ", ".join(sorted(CREDENTIAL_DESTINATIONS))
        raise ConfigPolicyError(
            f"config key {key_path or '(root)'!r} interpolates environment "
            f"variable {name!r}, whose name matches a secret pattern; "
            f"secret-named variables may expand only into: {allowed}. "
            f"Remedies: move the value to one of those keys, rename the "
            f"variable, or write the value literally instead of interpolating.")
    # POSIX ${VAR:-default}: use the default when VAR is unset OR set-but-empty.
    val = os.environ.get(name)
    if val:
        return val
    return default if default is not None else ""


def _expand(val: object, path: tuple[str, ...] = ()) -> object:
    if isinstance(val, str):
        return _ENV_PAT.sub(lambda m: _expand_env(m, path), val)
    if isinstance(val, dict):
        return {k: _expand(v, (*path, str(k))) for k, v in val.items()}
    if isinstance(val, list):
        return [_expand(v, path) for v in val]
    return val


def _expand_tree(tree: dict, path: tuple[str, ...] = ()) -> dict:
    """Dict-preserving wrapper over _expand for the whole config tree."""
    return {k: _expand(v, (*path, str(k))) for k, v in tree.items()}


class Config:
    """Thin attribute wrapper over the YAML dict. cfg.models.deepdive etc."""
    def __init__(self, data: dict):
        self._data = data

    def __getattr__(self, name):
        # Guard against recursion during copy.deepcopy: _data and dunder probes
        # (__deepcopy__, __setstate__, __getstate__, ...) must NOT re-enter via
        # self._data, which is absent while the object is being reconstructed.
        if (name.startswith("__") and name.endswith("__")) or name == "_data":
            raise AttributeError(name)
        data = self.__dict__.get("_data")
        try:
            v = data[name]
        except (KeyError, TypeError) as e:
            raise AttributeError(name) from e
        return Config(v) if isinstance(v, dict) else v

    def __getitem__(self, k):
        return self._data[k]

    def __repr__(self):
        return f"Config({self._data!r})"


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


# Merged UNDER any loaded config so a partial/hand-written config can never
# crash a stage with KeyError/AttributeError (e.g. a CLI-only config missing
# step4 knobs). User values always win; these only fill gaps. Structural keys
# (lists/dicts like exclude_dirs, specialists, config_dedup, allowed_tools) are
# intentionally omitted — the stages already default those internally and a
# defaults-layer entry would interfere with their append/merge semantics.
#
# Resolution order for any key registered here: profile value > this table >
# the call-site `getattr(cfg.stepN, key, X)` fallback. The last never fires
# through load() for a registered key — the merge guarantees the key exists —
# so an inline fallback that disagrees with this table (e.g. s3_decompose's
# taint_max_chunks fallback of 40 vs the 60 registered below) is dead code on
# the normal path, not a third effective default. When auditing "what value
# actually runs", read the loaded profile, never a single layer: three
# reviewers once reported three different taint_max_chunks values because
# each read a different layer of this stack.
_STEP_DEFAULTS: dict = {
    "step0": {
        # Profile-controlled static seed. The scalar fallback is disabled;
        # default.yaml, full.yaml and taint.yaml explicitly enable it. Rules mode requires
        # source/sink YAML; without applicable rules it returns an empty seed.
        "enabled": False,
        "callgraph_detection": "rules",
        "sources_yaml": None, "sinks_yaml": None,
        # Optional static-seed language filter (s0_seed._filter_step0_languages).
        "languages": None,
    },
    "step1": {
        "max_budget_usd": 25.0, "max_turns": 40, "max_file_kb": 1024,
        # call_graph: DELIBERATE pin, kept at "regex". It overrides the
        # in-code getattr fallback in s1_preprocess (which names
        # "tree_sitter"), so any profile that omits the key — only sdk.yaml,
        # which documents relying on exactly this — runs the regex supplement,
        # while shipped default.yaml/taint.yaml/full.yaml opt into
        # tree_sitter explicitly. The tree-sitter AST builder is installed as
        # a standard dependency and is agent-independent; flipping this
        # default would change behaviour for every existing key-omitting
        # profile, so do it only as a deliberate, benchmarked change (large-
        # repo runtime/memory) together with the sdk.yaml comment,
        # and update the pin test in tests/test_config_stage_key_defaults.py.
        "mode": "full", "call_graph": "regex",
        "call_graph_validate": True, "call_graph_supplement": True,
        "call_graph_rounds": 4, "call_graph_max_targets": 3,
        # Opt-in LLM auto-exclusion pass (s1_autoexclude): when enabled, an
        # extra model call proposes scan exclusions from a repo survey.
        # auto_exclude_max_tokens caps that survey prompt.
        "auto_exclude": False, "auto_exclude_max_tokens": 8000,
        # Back-compat symlink toggle: off-root symlink targets are dropped
        # regardless; when set, s1 warns rather than silently honouring it.
        "follow_symlinks": False,
    },
    "step2": {
        "enabled": True, "max_tokens": 64000, "max_threats": 50,
        "baseline": "auto", "max_doc_chars": 20000, "max_manifest_chars": 4000,
        "max_modules": 100, "max_entry_points": 400, "max_config_reps": 80,
        "max_api_artefacts": 100,
        "max_graph_files": 220, "max_graph_sinks": 80, "max_graph_edges": 100,
        "max_notes_chars": 2500, "max_function_sites": 80,
        # Prompt-truncation caps, distinct from the frontier-view caps above
        # (max_modules / max_entry_points).
        "max_prompt_modules": 100, "max_prompt_entry_points": 400,
        # NOTE on `0` semantics, which differ between s2 and s3 and are easy to
        # get wrong: s2's caps go through `_cap_int` (s2_threatmodel.py), where
        # `0` means "emit none of this block" — a legitimate operator choice.
        # The s3 caps below are read as `int(getattr(...) or default)`
        # in the decompose stage, where `0` is falsy and therefore still means
        # "use the stated default". Do not assume one idiom from the other when
        # adding a read site.
        "timeout": 1800, "max_assets": 40, "max_trust_boundaries": 60,
        "max_manifest_depth": 3, "max_manifests": 12,
        "max_manifests_per_kind": 2, "max_manifest_total_chars": 24000,
        # Config-representative CONTENTS: the first max_config_rep_bodies
        # reps are packed as redacted bodies capped at max_config_rep_chars
        # each; the rest of the selection stays path-only.
        "max_config_rep_chars": 2000, "max_config_rep_bodies": 12,
        # Agentic threat modelling — ships dark. When true, s2 swaps
        # prompt() -> agentic() with this read-only allowlist (validated in
        # the stage against {Read, Glob, Grep}; Bash/Edit are rejected) and
        # max_turns as the only real bound (max_budget_usd is a no-op on
        # sdk/openai). allowed_tools is registered here despite the
        # structural-key note above because step2 has no append/merge
        # semantics: a profile value simply replaces this list outright.
        # A tuple, not a list: _deep_merge assigns this default OBJECT into
        # every load()'d config, so a mutable default is shared process-wide and
        # one in-place mutation would poison every later load() in a batch run.
        # Immutable removes the aliasing hazard outright; consumers already
        # normalise with list(...).
        "agentic": False, "allowed_tools": ("Read", "Glob", "Grep"),
        "max_turns": 12,
    },
    "step3": {
        "max_tokens": 64000, "timeout": 3600, "taint_chunks": True,
        # taint_max_chunks: 60 here is what sdk.yaml and any key-omitting
        # profile run; default.yaml, full.yaml and taint.yaml raise it to
        # 120. The s3_decompose call-site fallback of 40 is unreachable
        # through load() (see the resolution-order note above). Two campaign
        # arms saturated at exactly 60/60 on a 227-file target, so the `[s3]
        # taint:` summary equalling the cap means candidates were dropped.
        "taint_max_hops": 10, "taint_max_chunks": 60, "taint_files_per_hop": 5,
        "pack_by": "loc", "chunk_token_budget": 180000,
        "chunk_overhead_tokens": 80000, "risk_chunk_loc": 10000,
        "catchall_enabled": True, "catchall_mode": "all", "catchall_chunk_loc": 4000,
        "catchall_max_files": 100, "max_files_per_chunk": 80,
        # When true, catch-all runs LAST — after specialists and threat-
        # fallback — but its "covered" set includes only risk/taint/threat-
        # fallback claims, NOT specialist claims (a specialist lens is scoped
        # guidance, not a generic review). Default false preserves the legacy
        # backstop role: catch-all runs FIRST, before specialists exist.
        "catchall_deduct_lens_coverage": False,
        "specialist_chunk_loc": 10000, "taint_chunk_slice": "file",
        # S3 prompt-frontier caps. These registered values are what every
        # key-omitting profile runs — sdk.yaml and taint.yaml omit them —
        # while default.yaml and full.yaml raise entry points/sinks/edges to
        # 200/200/200 and notes to 5000. The divergence is live behaviour: a
        # 227-file campaign target trimmed at the 80-edge cap under a
        # key-omitting profile (`call edges 109->80 dropped_by_cap=17`), so
        # do not assume the flagship's numbers when tuning another profile.
        # The s3_decompose.py call-site fallbacks happen to match this table
        # but are dead code for these registered keys (resolution-order note
        # above).
        "max_prompt_files": 180, "max_prompt_entry_points": 60,
        "max_prompt_sinks": 80, "max_prompt_modules": 24,
        "max_prompt_call_edges": 80, "max_prompt_notes_chars": 2500,
        "catchall_reachable_min_ratio": 0.0, "catchall_reachable_min_files": 0,
        # Caps on what the decompose prompt carries from the threat model.
        # Read as `int(getattr(...) or default)` by the decompose stage, so a
        # configured `0` means "use the stated default" here — see the
        # `0`-semantics note under step2.
        "max_prompt_threats": 50, "max_prompt_assets": 20,
        "max_prompt_boundaries": 30, "max_prompt_threat_context_chars": 2500,
        "max_cohesion_groups": 64,
        # Coalesce ADJACENT under-filled _pack() buckets until the LOC/char and
        # file caps bind. Without it the bucket count tracks cohesion-GROUP
        # count rather than code volume (one bucket per group, never
        # back-filled), and every bucket costs one s4 call per lens — measured
        # at a median fill of 84 LOC against a 10,000-LOC cap on one target.
        # `false` restores that one-bucket-per-group packing byte-for-byte:
        # the escape hatch if detection regresses on a specific target.
        "pack_merge_underfilled": True,
        # Matches `max_prompt_threats` so the threat-coverage guarantee holds
        # for every threat that can reach s3, and this cap only binds when an
        # operator deliberately lowers it. It was 12 while the fallback pass
        # exempted any threat carrying s2's `baseline:` marker, which left only
        # a handful eligible — the ceiling was never reached, so it read as
        # harmless. With that exemption narrowed to threats naming no code
        # surface, 12 silently dropped real threats from coverage.
        "max_threat_fallback_chunks": 50,
        # Read with an inline default by the threat-fallback pass but never
        # registered here, so an operator had no way to discover them. The
        # values match those call sites, making registration behaviour-neutral;
        # it only extends the setting to user-authored profiles, which the
        # shipped ones already carry.
        "threat_surface_fallbacks": True, "threat_fallback_max_files": 12,
    },
    "step4": {
        # Single-pass scalar default. Only full.yaml opts into majority voting
        # (runs: 3 / vote_threshold: 2); sdk.yaml ships a temperature-capable
        # deepdive but keeps runs: 1. Only via:cli is
        # collapsed to 1/1 by _effective_runs() (see s4_deepdive); an sdk model
        # that rejects `temperature` runs all N at provider-default sampling.
        "parallel": 5, "timeout": 1800, "runs": 1, "vote_threshold": 1,
        # max_findings_per_run: 10 here is what a key-omitting profile runs; all
        # four shipped profiles raise it to 25, so this floor applies only to a
        # hand-written config. The s4_deepdive call-site fallback of None (= cap off) is
        # unreachable through load() (resolution-order note above). Over-cap
        # findings are counted as s4_findings_truncated and surfaced in the
        # report's Pipeline Diagnostics.
        "specialist_runs": 1, "line_bucket": 10, "max_findings_per_run": 10,
        "max_tokens": 64000, "neighbor_context_lines": 25,
        "neighbor_context_max": 50,
        # taint-first overrides. The registered values keep the legacy path
        # (discover prompt, no per-kind run/model override) for any profile
        # that omits the keys. default.yaml does NOT inherit these any more —
        # it sets taint_prompt_mode: confirm_refute and taint_runs: 1
        # explicitly, as do full.yaml and taint.yaml. (An older comment here
        # claimed they were "all no-ops under default.yaml"; stale since the
        # flagship moved to the confirm/refute taint path.)
        "taint_prompt_mode": "discover", "taint_runs": None, "taint_model": None,
        # Optional override of step3.taint_chunk_slice. Left None so the
        # effective mode is read from step3; set to "file"/"function" here to
        # override the chunk slicing mode for the deep-dive stage only.
        "taint_chunk_slice": None,
        # `frontier_fallback_head_lines` was registered here (default 80) but
        # read nowhere: s4's span fallback deliberately ships fallback files
        # WHOLE (see s4_deepdive) rather than truncated to a fixed head, so
        # the knob never had an effect. Deregistered rather than wired — a
        # configured value in an existing profile remains harmless (Config is
        # non-strict) and simply keeps doing nothing.
        "frontier_max_funcs_per_file": 24,
    },
    "step5_prefilter": {"min_pre_confidence": 0.6, "require_evidence": True,
                        "ast_backfill_evidence": True},
    "step6_verify": {
        "parallel": 5, "min_confidence": 7, "max_budget_usd": 10.0,
        "max_turns": 30,
    },
    # Exploit verification (S6-EV). Flat for everything that means ONE thing, with a
    # sub-block only where a name would otherwise collide: `parallel` is
    # findings-at-once here but chunk-sessions-in-flight under classify/mapper,
    # `max_turns` is the attacker's loop budget but a mapping session's elsewhere, and
    # the only `max_tokens` is the judge's output cap. Which classify verdicts are
    # tested live is NOT a knob here or in a profile — it is `classify.LIVE_CLASSES`, a code
    # constant, because the set has no meaningful alternative value.
    "step6_exploit_verification": {
        # the pass as a whole
        "enabled": "auto", "on_unreachable": "drop", "ev_overrides_static": False,
        "parallel": 4, "store_probes": False,
        # every sender: transport, safety, budgets
        "timeout_s": 15, "safe_mode": True, "allow_state_changing_methods": False,
        "rate_limit_rps": 0,
        # Capped, not unlimited: every shipped profile chose 8/4, so 0 was a default no
        # profile used — and the one profile that inherited it ran uncapped against the
        # target. 0 still means "no cap" if an operator asks for it explicitly.
        "max_concurrency_target": 8, "max_concurrency_endpoint": 4,
        # ONE budget, shared by the deterministic first set AND the adaptive loop
        "max_requests_per_finding": 20,
        # sizes the DETERMINISTIC set (payloads.builder), which runs before the attacker
        "max_payloads_per_finding": 15,
        "oob": "auto",
        # auth
        "on_auth_failure": "degrade", "auth_expiry_skew_s": 60, "max_reauth": 3,
        # `vvaharness ev-replay`; flat because the name does not collide. Whether the
        # remediation judge runs is NOT a knob: it is the only thing that can turn "the tell
        # stopped firing" into a REMEDIATED verdict, so disabling it left the command able
        # to report still-vulnerable and nothing else. A run with no
        # `models.exploit_verification.judge` node already degrades to inconclusive, with a
        # reason that names the missing model.
        "ev_replay_variants": True,
        # per module
        "classify": {"batch": 10, "parallel": 4},
        "mapper": {
            # both mapping stages share these; only the chunk size differs, because a
            # finding_map chunk may read code while an endpoint_index chunk lists routes
            "max_turns": 20, "parallel": 4,
            "endpoint_index": {"chunk": 20},
            "finding_map": {"chunk": 6, "max_endpoints": 5},
        },
        "attacker": {"enabled": True, "max_turns": 15,
                     "max_tool_result_chars": 12000},
        # 4000, not 1500: a reply cut off mid-JSON does not parse, so too low a cap
        # costs the whole ruling rather than shortening it — and nothing detects the
        # truncation, so it reads as "the judge gave no verdict". Real rulings measure
        # 500-750 output tokens; max_tokens is a ceiling, not a reservation, so the
        # headroom is free.
        "judge": {"max_tokens": 4000, "max_records": 24},
    },
    "step7_dedup": {"line_tolerance": 3, "semantic": True, "max_tokens": 64000},
    "step8": {"max_tokens": 64000, "timeout": 3600},
    "step_remediate": {"max_budget_usd": 10.0, "max_turns": 40,
                       "top_n_findings": 20},
    "step_validate": {"enabled": False, "effort": "high", "max_turns": 50, "max_budget_usd": 15.0, "max_findings": 20},
    "output": {"emit_unreachable_appendix": False},
    # Top-level rather than per-step, because all three are properties of the
    # model route rather than of any one stage. `cache_min_block_tokens` is an
    # optional GLOBAL override of the per-model minimum cacheable block size
    # the sdk backend looks up for the model in use: providers publish a
    # minimum that varies (non-monotonically) by model, and a marker below it
    # is ignored silently while still consuming one of the few available
    # marker slots. Leave it null to use the published per-model minimums;
    # set it only for a gateway that enforces its own floor.
    # `cache_markers: off` suppresses every marker this tool places on the
    # `cli`, `sdk` and `openai` routes — the escape hatch for an endpoint that
    # rejects the field outright.
    #
    # It does NOT reach `via: deepagents`: that route gates ALL its markers
    # (the middleware's system/tools/tail breakpoints and the `cache_prefix`
    # one) on the `cache_markers` key of the `sdk:` transport block instead —
    # a deliberate reuse of the existing key rather than a third switch. An
    # operator silencing a strict gateway sets both. Documented in
    # docs/configuration.md; do not restore the "every route" claim without
    # making it true.
    "cache_min_block_tokens": None,
    "cache_markers": "on",
    # How the sdk backend decides which cache-marker regime the endpoint
    # honours. "auto" (default) detects it from the base_url host, failing
    # closed to no markers on anything unrecognised. "anthropic" / "vertex" /
    # "bedrock" declare the regime for a gateway detection cannot classify —
    # e.g. a corporate proxy that is Anthropic-Messages-compatible and honours
    # cache_control. "none" forces no markers. Quote the value: an unquoted
    # `no`/`off` is a YAML boolean (tolerated, but quoting is clearer).
    "cache_route": "auto",
    # Operator-supplied model price table (US dollars per million tokens) used
    # to cost the run manifest's per-stage token counts. No table is bundled —
    # rates are account/gateway-specific. VVAHARNESS_PRICING_FILE overrides
    # this key; with neither set every cost_usd is reported as null.
    "pricing": {"file": None},
    # CWE knowledge-base overlays. kb_overlays is an operator-supplied path (or
    # list of paths) to extra rules/*.kb.yaml corpora spliced onto the built-in
    # KB by CweKB.load(overlays=...) for the s4 confirm/refute prompt. None ⇒
    # built-in KB only.
    "rules": {"kb_overlays": None},
}


def _local_overlay_trusted(path: Path) -> bool:
    """POSIX trust gate for the overlay: EUID- or root-owned, no group/world write."""
    try:
        st = path.stat()
    except OSError:
        return False
    get_euid = getattr(os, "geteuid", None)
    # File-only, unlike cli._dotenv_path_is_trusted: a file swapped in through a
    # writable parent is attacker-owned and already fails the UID check here.
    if get_euid is not None and st.st_uid not in (get_euid(), 0):
        return False
    return get_euid is None or not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _require_overlay_trust(local: Path, log_overlay: bool) -> None:
    """Raise unless the overlay passes the POSIX trust gate; non-POSIX logs once instead."""
    if getattr(os, "geteuid", None) is None:
        if log_overlay:
            print(f"  config overlay: {local} ownership unverified "
                  f"(non-POSIX platform)", file=sys.stderr)
        return
    if not _local_overlay_trusted(local):
        raise ConfigPolicyError(
            f"config overlay {local} is not trusted: it must be owned "
            f"by the invoking user (or root) and not group/world-"
            f"writable. Fix with `chmod go-w {local}` (and `chown` it "
            f"to yourself if needed), or set {NO_LOCAL_CONFIG_ENV} to "
            f"skip the overlay.")


def _local_overlay(local: Path) -> tuple[dict | None, bool]:
    """Trust-check and read config.local.yaml; (mapping, or None when absent/skipped)."""
    if not local.exists():
        return None, False
    key = str(local.resolve())
    log_overlay = key not in _logged_overlays
    _logged_overlays.add(key)
    if os.environ.get(NO_LOCAL_CONFIG_ENV):
        if log_overlay:
            print(f"  config overlay: {local} present but SKIPPED "
                  f"({NO_LOCAL_CONFIG_ENV} set)", file=sys.stderr)
        return None, log_overlay
    _require_overlay_trust(local, log_overlay)
    over = yaml.safe_load(local.read_text(encoding="utf-8")) or {}
    if not isinstance(over, dict):
        # ValueError, not TypeError: the loader's YAML-shape refusal contract.
        raise ValueError(  # noqa: TRY004
            f"config {local} must be a YAML mapping, got {type(over).__name__}")
    return over, log_overlay


def _leaf_paths(tree: dict, prefix: tuple[str, ...] = ()) -> list[str]:
    """Dotted key paths of every leaf (non-dict) value in a nested mapping."""
    out: list[str] = []
    for k, v in tree.items():
        path = (*prefix, str(k))
        if isinstance(v, dict) and v:
            out.extend(_leaf_paths(v, path))
        else:
            out.append(".".join(path))
    return out


def _resolved_leaf(data: dict, path: str) -> object:
    node: object = data
    for seg in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(seg)
    return node


def _override_entry(path: str, resolved: dict) -> str:
    """Render one overlay override with the visibility its value class allows."""
    value = _resolved_leaf(resolved, path)
    if path in CREDENTIAL_DESTINATIONS:
        entry = f"{path} ({'set' if value else 'unset'})"
    elif path in ENDPOINT_KEYS:
        # urlsplit locally, not preflight's _scheme_host: config must not import orchestrator.
        entry = f"{path} -> {urlsplit(str(value)).netloc or value}"
    elif path in TLS_ROUTING_KEYS or path.rsplit(".", 1)[-1] in TLS_ROUTING_KEYS:
        entry = f"{path}={value}"
    else:
        entry = path
    return entry


def _overlay_override_entries(leaves: list[str], resolved: dict) -> list[str]:
    """Per-class banner entries for the overlay's leaf key paths, sorted."""
    return [_override_entry(path, resolved) for path in sorted(leaves)]


def load(path: str | Path = "config.yaml") -> Config:
    p = Path(path)
    # safe_load returns None for an empty/all-comments/whitespace file; treat
    # that as an empty mapping rather than crashing on later attribute access.
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"config {p} must be a YAML mapping, got {type(raw).__name__}")
    # Fill any missing scalar step-knobs from the built-in defaults so partial
    # configs never crash a stage. User-supplied values take precedence.
    raw = _deep_merge(_STEP_DEFAULTS, raw)
    # config.local.yaml (git-ignored, never bundled) deep-merges OVER the chosen
    # config. It can override security-relevant keys (model routing, sdk/openai
    # base_url, TLS ca_cert, tool permissions), so it is honoured only when the
    # file is trusted (see _local_overlay_trusted) and the merge is made VISIBLE
    # rather than silent: log the overlay file and the leaf keys it overrides,
    # with resolved endpoint hosts, on every command (not just scan). Set
    # VVAHARNESS_NO_LOCAL_CONFIG (to any value) to skip the overlay entirely —
    # for a reproducible run that honours only the operator-selected config.
    # The overlay resolves next to the --config path (operator-controlled),
    # never the scanned target.
    local = p.with_name(LOCAL_OVERLAY_NAME)
    over, log_overlay = _local_overlay(local)
    if over is not None:
        raw = _deep_merge(raw, over)
    data = _expand_tree(raw)
    # Banner emitted AFTER expansion so endpoint/TLS entries show resolved values.
    if over is not None and log_overlay:
        overrides = ", ".join(_overlay_override_entries(_leaf_paths(over), data)) or "(empty)"
        print(f"  config overlay: {local} applied "
              f"(overrides: {overrides})", file=sys.stderr)
    cfg = Config(data)
    # Record the directory the config was loaded from so input-style paths
    # (e.g. inject.cve_file, step_remediate.policy_file) can be resolved
    # against it — exactly how scan.py resolves cfg.inject.* against cfg_dir.
    cfg._data["_config_dir"] = str(p.resolve().parent)
    return cfg


def _replace_merge(base: dict, over: dict) -> dict:
    """Deep-merge where dicts recurse and everything else (incl. lists)
    REPLACES. Used for nested step1 sub-blocks like config_dedup so the
    latest overlay's list values win outright instead of accumulating."""
    out = dict(base)
    for k, v in over.items():
        cur = out.get(k)
        if isinstance(v, dict) and isinstance(cur, dict):
            out[k] = _replace_merge(cur, v)
        else:
            out[k] = v
    return out


def _append_merge(base: dict, over: dict) -> dict:
    """step1 overlay merge: top-level lists (exclude_dirs/exts/globs) APPEND
    so per-app files add to the global baseline; nested dicts switch to
    replace-merge so e.g. config_dedup.exts is taken from the latest overlay
    rather than concatenated."""
    out = dict(base)
    for k, v in over.items():
        cur = out.get(k)
        if isinstance(v, dict) and isinstance(cur, dict):
            out[k] = _replace_merge(cur, v)
        elif isinstance(v, list) and isinstance(cur, list):
            out[k] = list(cur) + [x for x in v if x not in cur]
        else:
            out[k] = v
    return out


def is_network_path(path: str | Path) -> bool:
    """True if *path* is a UNC / network location (``\\\\host\\share`` or
    ``//host/share``). Reading such a path on Windows triggers SMB
    authentication, which transmits the caller's NTLMv2 hash to the (possibly
    attacker-controlled) host. Callers must refuse these before any filesystem
    access. Evaluated with PureWindowsPath so the result is identical on every
    OS, not just where the run happens to land."""
    s = str(path).strip()
    if s.startswith("\\\\") or s.startswith("//"):
        return True
    # UNC drives render as '\\host\share'; local drives render as 'C:'.
    return PureWindowsPath(s).drive.startswith("\\\\")


def apply_step1_overlay(cfg: Config, path: str | Path, *,
                        expand: bool = True) -> tuple[Config, bool]:
    """Layer a per-scan step1 file on top of cfg.step1. Accepts either a
    bare-key file (exclude_dirs:, exclude_exts:, …) or one wrapped in a
    top-level `step1:` block. Lists append; scalars replace. Returns
    (cfg, applied). expand=False keeps ${...} literal — for the LLM-authored
    auto-step1 overlay, which must never reach the operator's environment."""
    p = Path(path)
    # Refuse network/UNC paths before the first filesystem touch (is_file
    # below) — on Windows that touch would leak the user's NTLM hash via SMB.
    if is_network_path(p):
        raise ValueError(
            f"step1 overlay must be a local path; refusing network/UNC path {p!r} "
            f"(reading it could leak credentials over SMB)")
    if not p.is_file():
        return cfg, False
    over = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(over, dict):
        raise ValueError(f"step1 overlay {p} must be a YAML mapping")
    if set(over) == {"step1"} and isinstance(over["step1"], dict):
        over = over["step1"]
    over = _expand_tree(over, ("step1",)) if expand else over
    base1 = cfg._data.get("step1") or {}
    cfg._data["step1"] = _append_merge(base1, over)
    return cfg, True
