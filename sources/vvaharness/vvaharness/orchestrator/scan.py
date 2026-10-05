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
from __future__ import annotations

"""orchestrator.scan — see package docstring."""
import copy
import os
import subprocess
import sys
import time
from collections.abc import MutableMapping
from dataclasses import dataclass
from pathlib import Path

import httpx

from vvaharness import config as config_mod
from vvaharness.backends.llm.registry import resolve as resolve_model
from vvaharness.backends.llm.tls import coerce_verify
from vvaharness.injectors.cve_feed import load_cves
from vvaharness.injectors.design_controls import load_controls
from vvaharness.models import (
    ContextPackage,
    FinalReport,
    TaskManifest,
    ThreatModel,
)
from vvaharness.orchestrator import store as _store
from vvaharness.orchestrator.artifacts import SCAN_DIR_NAME
from vvaharness.orchestrator.case_ids import mint_case_ids
from vvaharness.orchestrator.checkpoints import load_ckpt, run_id_for, save_ckpt, EV_COLLECTION_STEP
from vvaharness.orchestrator.cmdb import _load_app_profile
from vvaharness.orchestrator.config_paths import _iter_model_roles, _resolve_against
from vvaharness.orchestrator.enrich_findings import _enrich_findings
from vvaharness.orchestrator.findings_json import write_findings_json
from vvaharness.orchestrator.sarif_ids import stamp_case_ids
from vvaharness.pipeline.stages import (
    s0_seed,
    s1_autoexclude,
    s1_preprocess,
    s2_threatmodel,
    s3_decompose,
    s4_deepdive,
    s5_prefilter,
    s6_verify,
    s7_dedup,
    s8_chain,
)
from vvaharness.report import enrich as vcs_enrich
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.util import metrics as _metrics
from vvaharness.util.counters import COUNTERS
from vvaharness.util.scan_progress import ScanProgress, set_active_tracker
from vvaharness.util.stage_telemetry import STAGES
from vvaharness.util.status import stage
from vvaharness.util.tokens import TOKENS




@dataclass(frozen=True)
class ScanOutcome:
    """What one repo's scan produced, and whether every stage of it succeeded — ``exit_code`` reflects an in-pipeline remediation or validation failure instead of swallowing it."""
    report_path: Path | None
    finding_count: int
    exit_code: int = 0


def _head_sha(repo: Path) -> str | None:
    """Return the scanned repo's current git HEAD SHA, or None for a non-git target / git failure."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=20)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:                                  # noqa: BLE001
        return None


def _prune_ev_replays(run_id: str, canonical, ctx) -> None:
    """Drop replay bundles for findings that S7 dedup collapsed.

    EV stores its bundles at the end of S6, before dedup runs, so the stored set can
    contain a finding that never reaches the report — ``ev-replay`` would then re-check
    something the operator cannot look up. Best-effort and additive: a store failure
    must never fail the scan, and a run where EV never armed has nothing to prune.
    """
    if not getattr(ctx, "ev_collection", None):
        return
    try:
        from vvaharness.exploit_verification.verify.router import replay_key
        removed = _store.prune_replays(run_id, {replay_key(f) for f in canonical})
        if removed:
            print(f"  [s6-ev] pruned {removed} replay bundle(s) for finding(s) "
                  f"collapsed by dedup", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — pruning is housekeeping, never fatal
        print(f"  [s6-ev] WARN: could not prune replay bundles "
              f"({type(exc).__name__})", file=sys.stderr)


def _ev_collection_in(repo: Path, args, ckpt_dir: Path, run_id: str, collection_in=None):
    """Resolve the collection EV should work from: ``(collection, resumed)``.

    Two sources, in precedence order:

    * ``EV_API_COLLECTION`` — the offline gate (orchestrator.entry) already parsed
      it this invocation and handed the normalized object over in memory
      (``collection_in``); use that. It is persisted to the SQLite checkpoint below,
      which is the copy a later ``--resume`` reads.
    * the ``ev_collection`` checkpoint — used ONLY on ``--resume`` with the variable
      unset, so continuing a run keeps its EV input without the operator re-supplying
      it. A fresh scan cannot reach this branch, and its ``reset_run`` has dropped the
      row anyway: EV sends live payloads, so it must never switch itself on for a
      command that never asked for it.

    ``(None, False)`` means "no collection" — the caller leaves EV off.
    """
    from vvaharness.exploit_verification import options as ev_options

    if ev_options.collection_path(os.environ):
        if collection_in is None:
            # The gate parses the configured path and hands the object over; reaching here
            # without it means a caller invoked the scan directly without running the
            # gate (e.g. a test). Nothing to verify against, so leave EV off.
            print("  [ev-probe] no parsed collection handed to the scan; skipping "
                  "exploit verification", file=sys.stderr)
            return None, False
        return collection_in, False

    if not getattr(args, "resume", False):
        return None, False
    col = load_ckpt(ckpt_dir, run_id, EV_COLLECTION_STEP)
    if col is None:
        # Silent for an ordinary SAST-only resume; a --stop-after ev resume asked
        # for an EV check specifically, so say why there is nothing to do.
        if getattr(args, "stop_after", None) == "ev":
            print("  [ev] no checkpointed collection for this run — set "
                  "EV_API_COLLECTION", file=sys.stderr)
        return None, False
    print(f"  [ev] reusing the checkpointed collection "
          f"({len(col.endpoints)} endpoint(s), {col.source_format}) — exploit "
          f"verification is ON for this resumed run", file=sys.stderr)
    return col, True


def _ev_prep(repo: Path, args, cfg, *, ckpt_dir: Path, run_id: str,
             collection_in=None) -> dict | None:
    """Exploit-verification prep: probe the collection's reachability against the
    live target and return the (reachability-annotated) collection as a dict to
    attach to ``ctx.ev_collection``.

    Runs BEFORE S1 (and before the auto-step1 survey) so a collection check
    (``--stop-after ev``) needs no call graph and no model spend. Resolves the
    collection (CLI artifact or checkpoint — see :func:`_ev_collection_in`), runs
    the ONLINE safe probe, and checkpoints the collection so a later ``--resume``
    can reuse it. Returns ``None`` when EV is disabled or the abort policy fired.
    Raises :class:`EVUnreachableError` when nothing is reachable — caught in
    ``orchestrator.entry.main`` and surfaced as a clean exit 2. Never edits the
    target; the probe uses safe methods only. Fresh scans must reset stale run
    state before calling this, because this function writes the live collection
    checkpoint that resume relies on."""
    from vvaharness.exploit_verification import options as ev_options, probe as ev_probe
    from vvaharness.exploit_verification.errors import EVInputError

    # Read the profile's master switch before resolving anything: looking for a
    # collection reads from disk and logs, which a run with EV switched off must not do.
    if ev_options.profile_disabled(cfg):
        return None
    col_in, resumed = _ev_collection_in(repo, args, ckpt_dir, run_id, collection_in)
    if col_in is None:
        # `enabled: true` means verification is required, and this is the first point
        # that knows whether a collection exists — the startup check accepts a --resume
        # because it cannot see inside the checkpoint. Returning None here would spend
        # the whole scan and hand back a report with no Exploit Verification stamps, which a
        # reader cannot tell apart from "EV ran and confirmed nothing".
        if ev_options.required(cfg):
            raise EVInputError(
                "step6_exploit_verification.enabled: true requires a collection, and "
                "this run resolved none (EV_API_COLLECTION unset, and no checkpointed "
                "collection to resume). Set EV_API_COLLECTION, or set "
                "enabled: auto to make verification optional.")
        return None
    opts = ev_options.load_options(cfg, os.environ, resumed_collection=resumed)
    if not opts.enabled:
        return None

    # EV is going to verify, so its models must be usable. Checked here rather than only
    # at startup because a resumed run reaches this point without having been checked:
    # the collection came from the checkpoint, which the startup preflight cannot read.
    # Mirrors _remediate_preflight / _validate_preflight, and fails rather than degrades
    # — the collection was supplied, so verification was asked for.
    _model_err = ev_options.model_preflight(cfg)
    if _model_err:
        raise EVInputError(_model_err)

    if resumed:
        # The offline gate in entry.main had no path to run on, so run its
        # environment-dependent checks here — still before S1 and any model spend.
        # EVInputError propagates to entry.main as a clean exit 2.
        from vvaharness.exploit_verification import gate as ev_gate
        result = ev_gate.run_gate(opts, os.environ, collection=col_in)
        if result.checks:
            print("  [exploit-verification] collection gate (from checkpoint):",
                  file=sys.stderr)
            print(ev_gate.format_checks(result.checks), file=sys.stderr)
    else:
        # Persist the parsed input, not the probe's annotations: reachability is a
        # property of one deployment, and a resumed run re-probes from scratch.
        save_ckpt(ckpt_dir, run_id, EV_COLLECTION_STEP, col_in)

    col = ev_probe.run_probe(
        col_in, opts,
        allow_state_changing=bool(ev_options.ev_section(cfg).allow_state_changing_methods))
    # None → the on_unreachable=abort policy disabled EV for this run.
    if col is None:
        return None
    _ev_oob_selftest(opts)
    return col.model_dump()


def _ev_oob_selftest(opts) -> None:
    """Validate the OOB listener early (before model spend) and log the outcome.

    Starts the listener, self-tests it, logs clearly, then stops it — this stage
    only *validates* the config; the S6 verify flow runs its own listener when it
    fires blind payloads (wired with the payload/oracle steps). The self-test
    proves reachability from our vantage — equal to the target's only for a
    same-host (local) deployment (see executor.oob)."""
    from vvaharness.exploit_verification.executor.oob import resolve_oob

    mgr = resolve_oob(opts)
    if not mgr.enabled:
        if (opts.oob_mode or "auto") != "off":
            print("  [ev-oob] out-of-band listener off (no EV_OOB_URL and the target "
                  "is not loopback) — blind-only findings will fall to static",
                  file=sys.stderr)
        return
    try:
        mgr.start()
        ok = mgr.self_test()
        print(f"  [ev-oob] listener {'reachable ✓' if ok else 'NOT reachable ✗'} "
              f"(self-test {mgr.advertised_url}); the target must be able to reach "
              f"this URL", file=sys.stderr)
    finally:
        mgr.stop()


def _hydrate_ctx_callgraph_from_store(run_id: str, ctx: ContextPackage,
                                      *steps: str) -> ContextPackage:
    """Use the stored SQLite callgraph for runtime prompt context, searching the step list in order — first hit wins."""
    for step in steps:
        graph = _store.load_callgraph(run_id, step)
        if not graph:
            continue
        print(
            "  [graphdb] hydrated ctx.call_graph from sqlite: "
            f"step={step} nodes={graph['node_count']} edges={graph['edge_count']}",
            file=sys.stderr,
        )
        return ctx.model_copy(update={
            "call_graph": graph["call_graph"],
            "call_graph_files": graph["call_graph_files"],
            "def_spans": graph["def_spans"],
        })
    return ctx


def _upload_to_ingest(md_path: Path, sarif_path: Path, *,
                      repository_name: str, application_id: str | None,
                      cfg, cfg_dir: Path) -> bool:
    """Upload the Step 9 markdown+SARIF artifacts to the ingest hub.

    The upload is non-fatal by design: failures are logged and scanning
    continues.

    Requires both ``output.ingest_url`` and ``output.ingest_token``; every shipped
    profile leaves the two empty, so this is inert unless an operator sets them.
    Three properties are worth knowing before changing anything here. The
    destination is unrestricted -- there is no host or scheme check, in contrast
    to the loopback-only envelope the exploit-verification package enforces in
    ``exploit_verification.safety``. The client below is a plain ``httpx.Client``
    rather than that package's ``hardened_client``, so it inherits httpx's
    environment trust and carries the POST through any ambient proxy. And
    ``ingest_verify`` decides TLS: ``default.yaml`` ships ``false`` while the
    other three profiles ship ``true``, and a CA-bundle path that does not
    resolve falls back to no verification (below).
    """
    output_cfg = getattr(cfg, "output", None)
    url = getattr(output_cfg, "ingest_url", None)
    token = getattr(output_cfg, "ingest_token", None)
    if not url:
        print("  [ingest] no output.ingest_url configured - skipping",
              file=sys.stderr)
        return False
    if not token:
        print("  [ingest] no output.ingest_token configured - skipping",
              file=sys.stderr)
        return False
    if not md_path.exists() or not sarif_path.exists():
        print(f"  [ingest] report files missing ({md_path}, {sarif_path}) - skipping",
              file=sys.stderr)
        return False

    verify = getattr(output_cfg, "ingest_verify", None)
    if verify is None:
        verify = getattr(getattr(cfg, "sdk", None), "verify_ssl", True)
    verify = coerce_verify(verify)
    if isinstance(verify, str):
        verify = _resolve_against(cfg_dir, verify)
        if not Path(verify).exists():
            print(f"WARN [ingest]: ingest_verify path '{verify}' not found - "
                  "disabling TLS verification for upload.",
                  file=sys.stderr)
            verify = False

    headers = {
        "Authorization": f"Bearer {token}",
        "accept": "application/json",
    }
    data = {"repositoryName": repository_name}
    if application_id:
        data["applicationId"] = application_id

    print(f"  [ingest] POST {url}  verify={verify!r}", file=sys.stderr)
    try:
        with open(md_path, "rb") as md_f, open(sarif_path, "rb") as sarif_f:
            files = {
                "file": (md_path.name, md_f, "text/markdown"),
                "sarifFile": (sarif_path.name, sarif_f, "application/json"),
            }
            with httpx.Client(timeout=60, verify=verify) as client:
                resp = client.post(url, headers=headers, data=data, files=files)
        if resp.status_code >= 400:
            body = (resp.text or "")[:500]
            print(f"  [ingest] upload failed (non-fatal): HTTP {resp.status_code} "
                  f"for {url}\n"
                  f"  [ingest] server response: {body}", file=sys.stderr)
            return False
        print(f"  [ingest] uploaded {md_path.name} + {sarif_path.name} - "
              f"{resp.status_code}", file=sys.stderr)
        return True
    except Exception as e:
        print(f"  [ingest] upload failed (non-fatal): {e}", file=sys.stderr)
        return False


def _recorded_stage_outcome(step_id: str, fallback: str) -> str:
    """The outcome STAGES actually recorded for *step_id*, else *fallback*.

    status.stage() may close a stage as ``completed_with_errors`` while the
    call site still passes the plain default, so the progress tracker must
    echo the record, not the argument. Defensive by design: a missing entry
    (or one with no terminal outcome yet) falls back rather than raising.
    """
    rec = STAGES.snapshot().get(step_id) or {}
    recorded = rec.get("outcome")
    if recorded in (None, "running", "not_run"):
        return fallback
    return recorded


def _artifact_module_name(repo_name: str) -> str:
    """Return a non-empty, filesystem-safe module name for scan artifacts."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in repo_name)
    return safe if safe and safe.strip(".") else "repo"


def scan_repo(repo: Path, repo_name: str, application_id: str | None,
              args, cfg,
              path_prefix: str | None = None,
              ev_collection_in=None) -> ScanOutcome:
    """
    Run the profile-selected S0-S11 workflow against one local checkout, returning a :class:`ScanOutcome`
    (raises on failure; the batch driver catches it).

    ``ev_collection_in`` is the collection the offline gate already parsed this
    invocation (``entry._ev_gate``), handed over in memory so EV prep does not
    re-read it from disk. ``None`` on a ``--resume`` (the collection comes from the
    SQLite checkpoint instead) or a batch run (EV is single-repo only).
    """


    run_id = run_id_for(repo)

    # SECURITY: checkpoint state MUST NOT live inside the scanned repo — a hostile target could otherwise pre-plant state that --resume would load.
    # state_root() resolves without creating: this runs before the in-target safety
    # check below and before an early --stop-after return, neither of which should
    # leave a directory behind in the operator's home.
    _state = _store.state_root()
    ckpt_dir = _state / "checkpoints" / run_id
    # Checkpoints live in the SQLite state store; ckpt_dir is kept for save_ckpt/load_ckpt call-site compatibility and used on disk only for the --auto-step1 overlay.
    _store.register_run(run_id, repo_root=str(repo.resolve()),
                        repo_name=repo_name, app_id=application_id)

    # Fresh scan (no --resume) == start over: purge this run's stale checkpoint rows so a later --resume can't load one from a prior scan.
    #    `--stop-after ev` is a PREFLIGHT: it parses and probes the collection and
    #     returns before S1, so it computes nothing a later --resume could confuse
    #     itself with. Resetting there would clear a completed run's s1..s9 checkpoints
    #     just to check one collection — including when the probe then fails, leaving
    #     the command with nothing done and the state gone.
    #     `_ev_prep` still overwrites the ev_collection row (INSERT OR REPLACE), so
    #     re-checking with a different collection works exactly as before.
    if not args.resume and args.stop_after != "ev":
        _cleared = _store.reset_run(run_id)
        if _cleared:
            print(f"  [ckpt] reset {run_id[:12]}… — cleared {_cleared} stale "
                  f"checkpoint row(s) from a prior scan", file=sys.stderr)

    out_dir = repo / SCAN_DIR_NAME

    # Step 10's exit code, carried to every return so an early --stop-after and a full run report the same way.
    rem_rc = 0

    # Belt-and-braces: refuse --resume if ckpt_dir somehow resolves inside the target tree.
    if args.resume:
        try:
            ckpt_dir.resolve().relative_to(repo.resolve())
        except ValueError:
            pass  # good — ckpt_dir is OUTSIDE the repo
        else:
            print("✗ refusing --resume: checkpoint dir resolves inside the "
                  "scanned repository", file=sys.stderr)
            return ScanOutcome(None, 0)

    t0 = time.time()
    start_ts = _metrics.now_iso()
    # Filesystem-safe timestamp (':' is illegal on Windows).
    ts_safe = start_ts.replace(":", "").replace("-", "")
    module_safe = _artifact_module_name(repo_name)
    out_path = out_dir / f"{module_safe}_{ts_safe}_report.md"
    sarif_path = out_dir / f"{module_safe}_{ts_safe}_report.sarif"
    # Configure the per-scan error log BEFORE any stage can call _errlog.log(), so failures land in <repo>/security-scan/ rather than the module-global default.
    _errlog.configure(out_dir / f"{module_safe}_{ts_safe}_errors.jsonl")

    # ── Exploit-verification prep — runs BEFORE auto-step1 / S1 so a collection
    #    check (--stop-after ev) needs no call graph and no model spend. Probes
    #    reachability and holds the result to attach to ctx after S1. Raises
    #    EVUnreachableError (caught in entry.main → exit 2) on a dead target.
    #    Deliberately AFTER the reset_run() above: it checkpoints the collection,
    #    and a fresh scan's reset would otherwise delete the row it just wrote.
    ev_collection = _ev_prep(repo, args, cfg, ckpt_dir=ckpt_dir, run_id=run_id,
                             collection_in=ev_collection_in)
    if args.stop_after == "ev":
        return ScanOutcome(None, 0)

    # Runs once per cloned target, BEFORE s1, layering its exclusions on top of config.yaml's step1; cfg is deep-copied so batch entries don't accumulate each other's overlays.
    if getattr(args, "auto_step1", False):
        # Through store so this directory gets the same owner-only mode as the DB's:
        # the --auto-step1 overlay written next to it is configuration a later stage reads.
        _store.ensure_state_dir("checkpoints", run_id)
        auto_path = ckpt_dir / "step1.yaml"
        if not (args.resume and auto_path.is_file()):
            try:
                with TOKENS.phase("s1-autoexclude"):
                    s1_autoexclude.run(repo, cfg, out_path=auto_path)
            except Exception as e:
                print(f"  [auto-step1] WARN: failed ({e}); continuing with "
                      f"global step1 only.", file=sys.stderr)
                _errlog.log("s1.autoexclude", repo_name, e)
                auto_path = None
        else:
            print(f"  [auto-step1] reusing {auto_path}", file=sys.stderr)
        if auto_path and auto_path.is_file():
            cfg = config_mod.Config(copy.deepcopy(cfg._data))
            # expand=False: the overlay is LLM-authored; ${...} must stay literal.
            cfg, _ = config_mod.apply_step1_overlay(cfg, auto_path, expand=False)
            s1 = cfg._data.get("step1", {})
            print(f"  [auto-step1] applied overlay  "
                  f"(exclude_dirs={len(s1.get('exclude_dirs') or [])} "
                  f"exts={len(s1.get('exclude_exts') or [])} "
                  f"globs={len(s1.get('exclude_globs') or [])})",
                  file=sys.stderr)

    # Optional file/chunk progress tracker (stages consume cfg._scan_progress).
    tracker = ScanProgress.from_cfg(cfg, repo_name=repo_name)
    set_active_tracker(tracker)
    cfg._data["_scan_progress"] = tracker

    def _sp_start(step_id: str, label: str) -> None:
        if tracker.enabled:
            tracker.stage_started(step_id, label=label)

    def _sp_done(step_id: str, *, outcome: str = "completed",
                 detail: str = "") -> None:
        # completed/error already carry a measured duration from status.stage();
        # every other outcome ran no timed body, so record it here (unconditionally
        # — the manifest needs it even when the progress tracker is off).
        if outcome not in ("completed", "error"):
            STAGES.mark(step_id, outcome)
        if tracker.enabled:
            # Echo the outcome status.stage() actually recorded — it may have
            # closed the stage as completed_with_errors — falling back to the
            # passed value when no (terminal) record exists.
            tracker.stage_done(step_id,
                               outcome=_recorded_stage_outcome(step_id, outcome),
                               detail=detail)

    print(f"Agentic SAST  repo={repo}  module={repo_name}  "
          f"app_id={application_id or '-'}  run_id={run_id}",
          file=sys.stderr)
    print("  models:", file=sys.stderr)
    for role, m in _iter_model_roles(cfg):
        mid, via, extras = resolve_model(m)
        ex = f" {extras}" if extras else ""
        print(f"    {role:<11} -> {mid:<28} [{via}]{ex}", file=sys.stderr)

    cfg_dir = Path(args.config).resolve().parent
    cves = load_cves(_resolve_against(cfg_dir, cfg.inject.cve_file))
    controls = load_controls(_resolve_against(cfg_dir, cfg.inject.controls_file))
    app_profile, app_info = _load_app_profile(application_id)
    print(f"  injected: {len(cves)} CVEs, {len(controls)} controls, "
          f"app_profile={'yes' if app_profile else 'no'}", file=sys.stderr)

    def _m(role: str) -> str:
        mid, via, _ = resolve_model(getattr(cfg.models, role))
        return f"{mid} [{via}]"

    # Pure static, zero tokens: runs the configured seed engine and returns EntryPoint/Sink/taint-path lists that s1 merges into the ContextPackage.
    seed = load_ckpt(ckpt_dir, run_id, "s0") if args.resume else None
    if seed is None:
        s0_engine = getattr(getattr(cfg, "step0", None), "engine", "callgraph")
        _sp_start("s0", f"{s0_engine}")
        with stage(f"Step 0 — Static seed ({s0_engine})", n=0, total=11,
                   stage_id="s0"), TOKENS.phase("s0-seed"):
            seed = s0_seed.run(str(repo), cfg, ckpt_dir=ckpt_dir)
        save_ckpt(ckpt_dir, run_id, "s0", seed)
        _sp_done("s0", detail=(f"entry_points={len(getattr(seed, 'entry_points', []) or [])} "
                               f"sinks={len(getattr(seed, 'unsafe_sinks', []) or [])}"))
    else:
        _sp_done("s0", outcome="cached")
    _store.save_callgraph(run_id, "s0", seed)
    if args.stop_after == "s0":
        return ScanOutcome(None, 0)

    ctx: ContextPackage | None = load_ckpt(ckpt_dir, run_id, "s1") if args.resume else None
    if ctx is None:
        _sp_start("s1", f"{_m('preprocess')}")
        with stage(f"Step 1 — Pre-process ({_m('preprocess')})", n=1, total=11,
                   stage_id="s1"), TOKENS.phase("s1-preprocess"):
            ctx = s1_preprocess.run(str(repo), cfg, cves, controls, seed=seed)
        save_ckpt(ckpt_dir, run_id, "s1", ctx)
        _sp_done("s1", detail=f"files={len(getattr(ctx, 'all_files', []) or [])}")
    else:
        _sp_done("s1", outcome="cached")
    _store.save_callgraph(run_id, "s1", ctx)
    ctx = _hydrate_ctx_callgraph_from_store(run_id, ctx, "s1", "s0")
    ctx.app_profile = app_profile
    ctx.ev_collection = ev_collection      # from the pre-S1 EV probe (None when EV off)
    if args.stop_after == "s1":
        return ScanOutcome(None, 0)

    # ── Step 2 — Threat model (optional; reasons over s1's mapped surface) ─
    s2_enabled = getattr(getattr(cfg, "step2", None), "enabled", True)
    tm: ThreatModel | None = (load_ckpt(ckpt_dir, run_id, "s2")
                              if args.resume else None)
    if tm is None and s2_enabled:
        try:
            _sp_start("s2", f"{_m('threatmodel')}")
            with stage(f"Step 2 — Threat model ({_m('threatmodel')})",
                       n=2, total=11, stage_id="s2"), \
                    TOKENS.phase("s2-threatmodel"):
                tm = s2_threatmodel.run(str(repo), repo_name, cfg, cves,
                                        controls, ctx=ctx,
                                        app_profile=app_profile)
            # `ThreatModel.model_validate({})` succeeds (every field defaults), so checkpointing an
            # empty model would make `--resume` inherit it forever and s2 would never re-run.
            if tm.threats or tm.assets or tm.trust_boundaries:
                save_ckpt(ckpt_dir, run_id, "s2", tm)
            else:
                COUNTERS.bump("s2_degraded")
            _sp_done("s2", detail=(f"assets={len(tm.assets)} boundaries={len(tm.trust_boundaries)} "
                                   f"threats={len(tm.threats)}"))
        except Exception as e:
            print(f"  [s2] WARN: threat-model step failed ({e}); "
                  f"continuing without it.", file=sys.stderr)
            _errlog.log("s2", repo_name, e)
            _sp_done("s2", outcome="error",
                     detail=redact(f"{type(e).__name__}: {e}"))
            # The worse outcome than an empty model: no threat model at all, so attribution, the
            # threat-surface fallback and the access-control lens force-on are all gone downstream.
            COUNTERS.bump("s2_degraded")
            tm = None
    elif tm is not None:
        _sp_done("s2", outcome="cached")
    else:
        _sp_done("s2", outcome="skipped", detail="disabled in config")
    # Always re-attach (s2/CMDB may differ across resumed runs).
    ctx.threat_model = tm
    _store.save_callgraph(run_id, "s2", ctx)
    ctx = _hydrate_ctx_callgraph_from_store(run_id, ctx, "s2", "s1", "s0")
    if args.stop_after == "s2":
        return ScanOutcome(None, 0)

    manifest: TaskManifest | None = load_ckpt(ckpt_dir, run_id, "s3") if args.resume else None
    if manifest is None:
        _sp_start("s3", f"{_m('decompose')}")
        with stage(f"Step 3 — Decompose ({_m('decompose')})", n=3, total=11,
                   stage_id="s3"), TOKENS.phase("s3-decompose"):
            manifest = s3_decompose.run(ctx, cfg)
        save_ckpt(ckpt_dir, run_id, "s3", manifest)
        _sp_done("s3", detail=f"chunks={len(getattr(manifest, 'chunks', []) or [])}")
    else:
        _sp_done("s3", outcome="cached")
    _store.save_callgraph(run_id, "s3", ctx)
    if args.stop_after == "s3":
        return ScanOutcome(None, 0)

    s4_ckpt = load_ckpt(ckpt_dir, run_id, "s4") if args.resume else None
    s4_resumed = s4_ckpt is not None
    chunk_outcomes: dict[str, str] = {}
    if s4_ckpt is None:
        _sp_start("s4", f"{_m('deepdive')}")
        with stage(f"Step 4 — Deep-dive ({_m('deepdive')}; {cfg.step4.runs} runs, "
                   f"vote≥{cfg.step4.vote_threshold}, "
                   f"parallel={getattr(cfg.step4, 'parallel', 1)})",
                   n=4, total=11, stage_id="s4"), TOKENS.phase("s4-deepdive"):
            findings, chunk_outcomes = s4_deepdive.run(manifest.sorted_chunks(), ctx, cfg)
        # Bundle the per-chunk outcomes with the findings so a --resume that rebuilds metrics still sees the coverage tally.
        save_ckpt(ckpt_dir, run_id, "s4",
                  {"findings": findings, "outcomes": chunk_outcomes})
        _sp_done("s4", detail=f"findings={len(findings)}")
    elif isinstance(s4_ckpt, dict):
        findings = s4_ckpt.get("findings", [])
        chunk_outcomes = s4_ckpt.get("outcomes", {})
        _sp_done("s4", outcome="cached")
    else:  # legacy bare-list checkpoint (pre outcome-tracking)
        findings = s4_ckpt
        _sp_done("s4", outcome="cached")
    _store.save_callgraph(run_id, "s4", ctx)
    if args.stop_after == "s4":
        return ScanOutcome(None, 0)

    raw_count = len(findings)

    # ── Steps 5+6+7 — independent progress + legacy-compatible S7 bundle ──
    s7_ckpt = load_ckpt(ckpt_dir, run_id, "s7") if args.resume else None
    if s7_ckpt is None:
        # A valid S5 row can only be reused when its S4 prerequisite was also
        # restored. If S4 had to rerun, any leftover downstream row is stale.
        s5_ckpt = (load_ckpt(ckpt_dir, run_id, "s5")
                   if args.resume and s4_resumed else None)
        s5_resumed = s5_ckpt is not None
        if s5_ckpt is None:
            _sp_start("s5", "prefilter")
            with stage("Step 5 — Pre-filter (deterministic + semantic pre-dedup)",
                       n=5, total=11, stage_id="s5"), \
                    TOKENS.phase("s5-prefilter"):
                findings, pre_dropped = s5_prefilter.run(findings, ctx, cfg)
            save_ckpt(ckpt_dir, run_id, "s5", {
                "findings": findings,
                "pre_dropped": pre_dropped,
            })
            _sp_done("s5", detail=f"kept={len(findings)} dropped={len(pre_dropped)}")
        else:
            findings = s5_ckpt["findings"]
            pre_dropped = s5_ckpt["pre_dropped"]
            _sp_done("s5", outcome="cached")
        if args.stop_after == "s5":
            return ScanOutcome(None, 0)

        # Only reuse S6 when S5 was restored too. A newly-run S5 may have
        # produced a different input set, so a leftover S6 row cannot apply.
        s6_ckpt = (load_ckpt(ckpt_dir, run_id, "s6")
                   if args.resume and s5_resumed else None)
        if s6_ckpt is None:
            # Re-hydrate callgraph context from SQLite right before verification so s6 reasons over the latest persisted graph snapshot.
            ctx = _hydrate_ctx_callgraph_from_store(
                run_id, ctx, "s4", "s3", "s2", "s1", "s0")
            _sp_start("s6", f"{_m('verify')}")
            with stage(f"Step 6 — Verify ({_m('verify')})", n=6, total=11,
                       stage_id="s6"), TOKENS.phase("s6-verify"):
                if getattr(ctx, "ev_collection", None):
                    # Exploit verification is armed (a collection was probed at prep):
                    # route live-verifiable findings to the confirm-agent, the rest to
                    # the static verifier. Purely additive — SAST behavior is unchanged
                    # for everything it doesn't confirm.
                    from vvaharness.exploit_verification.verify import router as ev_router
                    verified, dropped = ev_router.run(findings, ctx, cfg)
                else:
                    verified, dropped = s6_verify.run(findings, ctx, cfg, run_id=run_id)
            save_ckpt(ckpt_dir, run_id, "s6", {
                "verified": verified,
                "dropped": dropped,
            })
            _sp_done("s6", detail=f"verified={len(verified)} dropped={len(dropped)}")
        else:
            verified = s6_ckpt["verified"]
            dropped = s6_ckpt["dropped"]
            _sp_done("s6", outcome="cached")
        if args.stop_after == "s6":
            return ScanOutcome(None, 0)
        # Ensure s7 semantic dedup sees the latest sqlite-backed callgraph context before making root-cause grouping decisions.
        ctx = _hydrate_ctx_callgraph_from_store(run_id, ctx,
                                                "s4", "s3", "s2", "s1", "s0")
        _sp_start("s7", f"{_m('dedup')}")
        with stage(f"Step 7 — Dedup ({_m('dedup')})", n=7, total=11,
                   stage_id="s7"), TOKENS.phase("s7-dedup"):
            canonical, dup_dropped = s7_dedup.run(verified, cfg, ctx=ctx)
        _sp_done("s7", detail=f"canonical={len(canonical)} dup_dropped={len(dup_dropped)}")
        _prune_ev_replays(run_id, canonical, ctx)
        save_ckpt(ckpt_dir, run_id, "s7",
                  (pre_dropped, verified, dropped, canonical, dup_dropped))
    elif len(s7_ckpt) == 5:
        pre_dropped, verified, dropped, canonical, dup_dropped = s7_ckpt
        _sp_done("s5", outcome="cached")
        _sp_done("s6", outcome="cached")
        _sp_done("s7", outcome="cached")
    else:  # legacy 4-tuple checkpoint (pre_dropped not stored)
        verified, dropped, canonical, dup_dropped = s7_ckpt
        pre_dropped = []
        _sp_done("s5", outcome="cached")
        _sp_done("s6", outcome="cached")
        _sp_done("s7", outcome="cached")
    # Honour --stop-after s5/s6 even on a --resume: the in-branch early-returns above are skipped when a combined s5+6+7 checkpoint is loaded.
    if args.stop_after in ("s5", "s6"):
        return ScanOutcome(None, 0)
    _enrich_findings(canonical, app_info, path_prefix=path_prefix)
    all_dropped = pre_dropped + dropped + dup_dropped
    _store.save_callgraph(run_id, "s7", ctx)
    if args.stop_after == "s7":
        return ScanOutcome(None, 0)

    # Ensure chain analysis sees the latest sqlite-backed callgraph context for reachability reasoning and exploit-chain assembly.
    ctx = _hydrate_ctx_callgraph_from_store(run_id, ctx,
                                            "s4", "s3", "s2", "s1", "s0")
    report: FinalReport | None = load_ckpt(ckpt_dir, run_id, "s8") if args.resume else None
    if report is None:
        end_ts = _metrics.now_iso()
        fp = sum(1 for d in dropped if d.reason == "FALSE_POSITIVE")
        # Count actual TRUE_POSITIVE verdicts, not len(verified): exploit verification
        # may retain an EV-confirmed finding the static verifier rejected (verdict
        # FALSE_POSITIVE) so it stays visible — such a finding must not inflate the
        # true-positive/precision metric.
        true_pos = sum(1 for f in verified if getattr(f, "verdict", None) == "TRUE_POSITIVE")
        metrics = _metrics.build(
            ctx, manifest,
            repo_name=repo_name, start_ts=start_ts, end_ts=end_ts,
            raw_findings=raw_count, true_pos=true_pos,
            false_pos=fp, duplicates=len(dup_dropped),
            chunk_outcomes=chunk_outcomes,
        )
        _sp_start("s8", f"{_m('chain')}")
        with stage(f"Step 8 — Chain ({_m('chain')})", n=8, total=11,
                   stage_id="s8"), TOKENS.phase("s8-chain"):
            report = s8_chain.run(canonical, ctx, cfg,
                              dropped=all_dropped,
                              raw_findings_count=raw_count,
                              metrics=metrics)
        # build() ran before s8 (the chain stage renders the metrics block), so
        # the metrics it captured are blind to s8's own spend. Re-snapshot now
        # that s8 has returned, before the report and the checkpoint persist it.
        _metrics.refresh_tokens(report.metrics, end_ts=_metrics.now_iso())
        report.repo_name = repo_name
        report.threat_model = tm
        report.app_profile = app_profile
        if getattr(cfg.output, "emit_unreachable_appendix", False):
            report.unreachable_files = manifest.unreachable_files
        # B9: pin HEAD so step 10 (now or later via remediate --from-report) can refuse on mismatch.
        report.git_sha = _head_sha(repo)
        save_ckpt(ckpt_dir, run_id, "s8", report)
        _sp_done("s8", detail=f"findings={len(report.findings)} chains={len(report.chains)}")
    else:
        _sp_done("s8", outcome="cached")
    _store.save_callgraph(run_id, "s8", ctx)

    # Identity before persistence, deliberately: mint_case_ids asserts uniqueness across the report, and the id names a case directory, so a clash must stop the run before anything is written.
    _ids = mint_case_ids(report)
    print(f"  [case] {_ids['minted']} case id(s) minted, "
          f"{_ids['preassigned']} already assigned"
          + (f", {_ids['collisions']} bucket collision(s) disambiguated"
             if _ids["collisions"] else ""),
          file=sys.stderr)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # The typed result, written beside the rendering: re-parsing the Markdown instead is what lost source_ref/sink_ref and every duplicate location.
    findings_path = write_findings_json(report, repo)
    print(f"  [out] wrote {findings_path}", file=sys.stderr)
    md_text = redact(report.to_markdown())
    out_path.write_text(md_text, encoding="utf-8")
    n_redacted = sum(getattr(redact, "last_counts", {}).values())
    print(f"  [out] wrote {out_path}"
          + (f"  ({n_redacted} sensitive values masked)" if n_redacted else ""),
          file=sys.stderr)
    if args.stop_after == "s8":
        return ScanOutcome(out_path, len(report.findings), rem_rc)

    s9_done = load_ckpt(ckpt_dir, run_id, "s9") if args.resume else None
    if s9_done is None or not sarif_path.exists():
        _sp_start("s9", "sarif")
        scan_health = {
            "executionSuccessful": not report.degraded,
            "degraded": report.degraded,
            "chunks_failed": report.metrics.chunks_failed if report.metrics else 0,
            "errors_by_stage": (report.metrics.errors_by_stage
                                if report.metrics else {}),
        }
        with stage(f"Step 9 — SARIF (app_id={application_id or '-'})",
                   n=9, total=11, stage_id="s9"):
            vcs_enrich.md_to_sarif(str(out_path), application_id, app_info,
                                    str(sarif_path), scan_health=scan_health)
        # md_to_sarif re-parses the Markdown and never holds a typed Finding, so the case id is stamped on afterwards from the report we do hold.
        stamp_case_ids(sarif_path, report)
        print(f"  [out] wrote {sarif_path}", file=sys.stderr)
        save_ckpt(ckpt_dir, run_id, "s9", str(sarif_path))
        _sp_done("s9", detail=f"sarif={sarif_path.name}")
    else:
        _sp_done("s9", outcome="cached")
    _store.save_callgraph(run_id, "s9", ctx)

    # Upload Step 9 artifacts to the ingest hub once per run. A successful
    # upload is checkpointed so --resume does not re-send the same pair.
    ingest_done = load_ckpt(ckpt_dir, run_id, "ingest") if args.resume else None
    if ingest_done:
        print("  [ingest] already uploaded (checkpoint) - skipping",
              file=sys.stderr)
    else:
        ok = _upload_to_ingest(
            out_path,
            sarif_path,
            repository_name=repo_name,
            application_id=application_id,
            cfg=cfg,
            cfg_dir=cfg_dir,
        )
        if ok:
            save_ckpt(ckpt_dir, run_id, "ingest", True)

    if args.stop_after == "s9":
        return ScanOutcome(out_path, len(report.findings), rem_rc)

    # B3: runs INSIDE scan_repo() so the clone still exists; writes per-finding artefacts under <repo>/security-remediation/<slug>/, same layout as the standalone `vvaharness remediate` command.
    rem_cfg = getattr(cfg, "step_remediate", None)
    rem_on = bool(getattr(args, "remediate", False)
                  or getattr(rem_cfg, "enabled", False))

    if not (rem_on and report.findings):
        _sp_done("s10", outcome="disabled")
    else:
        rem_err = _remediate_preflight(cfg, args, repo, report)
        if rem_err:
            print(f"  [s10] DISABLED — {rem_err}", file=sys.stderr)
            _errlog.log("s10.preflight", repo_name, RuntimeError(rem_err))
            _sp_done("s10", outcome="disabled")
        else:
            rem_progress: dict[str, int] = {}
            _sp_start("s10", f"{_m('remediate')}")
            with stage(f"Step 10 — Remediate ({_m('remediate')})",
                       n=10, total=11, stage_id="s10"), \
                    TOKENS.phase("s10-remediate"):
                rem_rc = _run_remediation(report, repo, cfg, ckpt_dir, run_id,
                                          resume=args.resume,
                                          top=getattr(args, "top", None),
                                          report_md=out_path,
                                          progress=rem_progress)
            _sp_done("s10", detail=_progress_detail(
                rem_progress, "attempted", "fixed", "not_fixed"))
            if rem_rc:
                print("  [s10] WARN: remediation did not process every finding "
                      f"(exit {rem_rc}); the scan's exit code reflects it",
                      file=sys.stderr)

    if args.stop_after == "s10":
        return ScanOutcome(out_path, len(report.findings), rem_rc)

    # Step 11's exit code. Initialised HERE, on the straight-line path, and not at the
    # call below: the disabled and preflight-refused branches skip that call entirely
    # and still reach both returns underneath.
    val_rc = 0
    val_cfg = getattr(cfg, "step_validate", None)
    val_on = bool(getattr(val_cfg, "enabled", False))
    # `and report.findings`, mirroring s10 one screen above. Without it s11 runs on a
    # clean repo, finds no case to validate, and returns 1 for it — so a scan that found
    # nothing would report a failure now that the code is no longer discarded.
    if not (val_on and report.findings):
        _sp_done("s11", outcome="disabled")
    else:
        val_err = _validate_preflight(cfg)
        if val_err:
            print(f"  [s11] DISABLED — {val_err}", file=sys.stderr)
            _errlog.log("s11.preflight", repo_name, RuntimeError(val_err))
            _sp_done("s11", outcome="disabled")
        else:
            val_progress: dict[str, int] = {}
            _sp_start("s11", "validation")
            with stage("Step 11 — Validate (s11)", n=11, total=11,
                       stage_id="s11"), TOKENS.phase("s11-validate"):
                val_rc = _run_validation(repo, cfg, config_path=args.config,
                                         resume=args.resume, report_md=out_path,
                                         progress=val_progress)
            _sp_done("s11", detail=_progress_detail(
                val_progress, "validated", "passed", "failed"))
    if args.stop_after == "s11":
        # s10 first: a broken pipeline outranks a broken validation, so `or` and not
        # max()/sum() — the order is the precedence.
        return ScanOutcome(out_path, len(report.findings), rem_rc or val_rc)

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.0f}s. {len(report.findings)} verified findings "
          f"({len(report.dropped)} dropped), {len(report.chains)} chains.",
          file=sys.stderr)
    m = report.metrics
    tok_p = m.prompt_tokens if m and m.prompt_tokens is not None else "unavailable"
    tok_c = m.completion_tokens if m and m.completion_tokens is not None else "unavailable"
    tok_t = m.total_tokens if m and m.total_tokens is not None else "unavailable"
    print(f"Tokens: prompt={tok_p}, completion={tok_c}, total={tok_t}",
          file=sys.stderr)
    print(f"Report: {out_path}", file=sys.stderr)

    # Print markdown to stdout for piping
    print(md_text)
    return ScanOutcome(out_path, len(report.findings), rem_rc or val_rc)


def _run_remediation(report: FinalReport, repo: Path, cfg, ckpt_dir, run_id,
                     *, resume: bool = False, top: int | None = None,
                     report_md: Path | None = None,
                     progress: MutableMapping[str, int] | None = None) -> int:
    """Walk the verified findings one-by-one with the Remediation Agent, delegating to the same ``runner.process_targets`` the standalone ``vvaharness remediate`` command uses."""
    from vvaharness.remediation_agent.discovery import Layout
    from vvaharness.remediation_agent.options import RemediateOptions
    from vvaharness.remediation_agent.report_parser import REMEDIATION_DIR_NAME
    from vvaharness.remediation_agent.runner import process_targets
    from vvaharness.remediation_agent.target import RemediationTarget
    from vvaharness.remediation_agent.select import resolve_top, select_top_logged

    rem_dir = repo / REMEDIATION_DIR_NAME
    rem_dir.mkdir(parents=True, exist_ok=True)

    # Top-N cap: profile's step_remediate.top_n_findings is the source of truth; --top N overrides it ad-hoc.
    eff_top = resolve_top(top, cfg)
    selected = select_top_logged(
        report.findings, eff_top,
        score_of=lambda rf: rf.finding.cvss_score,
        log_prefix="[s10]")
    findings = [rf.finding for rf in selected]

    # The Anthropic and DeepAgents harnesses expose confined Edit/Write tools; via:openai remains read-only on the legacy dispatcher.
    _, _remediate_via, _ = resolve_model(cfg.models.remediate)
    if _remediate_via in ("cli", "sdk", "deepagents"):
        print(f"  [s10] ⚠ FIX MODE — about to EDIT source files in {repo}; "
              f"rerun with --stop-after s9 to scan without modifying the target", file=sys.stderr)
    else:
        print(f"  [s10] ⚠ {_remediate_via} backend cannot edit files (no Edit/Write tool); "
              f"fix mode errors per finding — use report-only or via:cli/sdk/deepagents",
              file=sys.stderr)
    print(f"  [s10] remediating {len(findings)} finding(s) via Remediation Agent; "
          f"artefacts → {rem_dir}", file=sys.stderr)

    # Thread the scan's existing ckpt_dir/run_id through Layout so resume state is shared with the standalone command, and bind *report_md* so the combined report can't be redirected by a newest-wins glob.
    layout = Layout(rem_dir=rem_dir, ckpt_dir=ckpt_dir, run_id=run_id)
    opts = RemediateOptions(resume=resume, mode="fix")
    # This list is freshly built and ranked, so 1..N IS its display order (the standalone path keeps the report's own ordinals instead).
    targets = [RemediationTarget(finding=f, index=i)
               for i, f in enumerate(findings, start=1)]
    kwargs = {"progress": progress} if progress is not None else {}
    return process_targets(targets, layout=layout, cfg=cfg, repo_path=repo,
                           opts=opts, report=report_md, **kwargs)


def _run_validation(repo: Path, cfg, *, config_path: str, resume: bool = False,
                    report_md: Path | None = None,
                    progress: MutableMapping[str, int] | None = None) -> int:
    """Invoke the s11 validation package against the case records s10 left under security-remediation/, returning its exit code rather than discarding it."""
    from vvaharness.pipeline.stages.s11_validate import run as s11_run
    kwargs = {"progress": progress} if progress is not None else {}
    rc = s11_run(repo, cfg=cfg, config_path=config_path, resume=resume,
                 report_md=report_md, **kwargs)
    if rc != 0:
        print(f"  [s11] WARN: validation exited with code {rc}; "
              "the scan's exit code reflects it", file=sys.stderr)
    return rc


def _progress_detail(progress: MutableMapping[str, int], *fields: str) -> str:
    """Format stable key/value counters for a stage-done progress record."""
    return " ".join(f"{field}={progress.get(field, 0)}" for field in fields)


def _remediate_preflight(cfg, args, repo: Path, report) -> str | None:
    """Hard checks before remediation may run; returns an error string (which DISABLES remediation, scan continues) or None to proceed."""
    rem = getattr(cfg.models, "remediate", None)
    if rem is None:
        return "models.remediate must be set"

    # Imported locally: vvaharness.util.environment reaches back into the validation CLI, which imports this package.
    from vvaharness.util.environment import _backend_credential_ok
    model_id, via, _ = resolve_model(rem)
    ready, detail = _backend_credential_ok(via, model_id, getattr(rem, "provider", None))
    if not ready:
        return f"models.remediate via:{via} — {detail}"

    # B9: refuse if the working tree has moved since the report was built (line numbers would be stale, patch lands on wrong code).
    cur = _head_sha(repo)
    if (report.git_sha and cur and report.git_sha != cur
            and not getattr(args, "force", False)):
        return (f"HEAD moved since scan ({report.git_sha[:8]} → "
                f"{cur[:8]}); pass --force to override")
    return None


def _validate_preflight(cfg: object) -> str | None:
    """Hard checks before in-scan s11 validation may run; returns an error string (which DISABLES validation, scan continues) or None to proceed. Symmetrical with ``_remediate_preflight``."""
    # Local import: see the note in _remediate_preflight.
    from vvaharness.util.environment import _backend_credential_ok
    from vvaharness.validation.config.validate_role import (  # noqa: PLC0415 — lazy: validation is optional here
        normalize_validate_backend,
        validate_model_spec,
    )

    val = validate_model_spec(cfg)
    if val is None:
        return "models.validate.orchestrator must be set"

    model_id, via, _ = resolve_model(val)
    # Same routing the validate CLI applies, so this gate checks the credential for the backend s11 will actually use.
    via, provider = normalize_validate_backend(via, getattr(val, "provider", None))

    ready, detail = _backend_credential_ok(via, model_id, provider)
    return None if ready else f"models.validate.orchestrator via:{via} — {detail}"
