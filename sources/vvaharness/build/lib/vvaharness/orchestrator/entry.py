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

"""orchestrator.entry — see package docstring."""
import argparse
import os
import sys
import traceback
from pathlib import Path

from vvaharness import config as config_mod
from vvaharness.backends.harness.models import AuthenticationError, ProxyError
from vvaharness.orchestrator.batch import run_batch
from vvaharness.orchestrator.cmdb import _cmdb_path, _set_cmdb_path
from vvaharness.orchestrator.config_paths import _default_config, EV_MODEL_ROLES
from vvaharness.orchestrator.preflight import check_backends, configure_backends
from vvaharness.orchestrator.scan import scan_repo
from vvaharness.pipeline.stages.s1_preprocess import EmptyScopeError
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.exploit_verification.options import (
    collection_path as ev_collection_path,
    load_options as ev_load_options,
    may_run as ev_may_run,
    resolution_error as ev_resolution_error)
from vvaharness.exploit_verification.errors import (EVInputError,
                                                    EVUnreachableError)

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass


def _top_arg(raw: str):
    """argparse ``type`` for ``--top``: a positive integer cap or the ``all``/``*`` wildcard, reusing the same coercion the standalone ``remediate`` command uses."""
    from vvaharness.remediation_agent.select import _coerce_top_value
    try:
        return _coerce_top_value(raw, source="--top")
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


def _ev_gate(args, cfg) -> tuple[int | None, object]:
    """Run the OFFLINE exploit-verification collection gate.

    Returns ``(exit_code_or_None, collection)``: the exit code aborts ``main()`` when
    not ``None``; the collection is the parsed, normalized one for ``main`` to hand to
    the scan in memory (``None`` when EV was not requested here). Never touches the
    network or a model.

    With no collection path there is nothing to parse here. A ``--resume`` run may
    still have a checkpointed collection, so it continues with ``(None, None)`` —
    ``scan.py``'s EV prep loads that from the SQLite state store and runs these same
    checks over it (see ``gate.run_gate``'s ``collection`` argument).
    """
    path = ev_collection_path(os.environ)
    if not path:
        if (getattr(args, "stop_after", None) == "ev"
                and not getattr(args, "resume", False)):
            print("ERROR: --stop-after ev requires EV_API_COLLECTION to be set "
                  "(or --resume, to re-probe this run's checkpointed collection)",
                  file=sys.stderr)
            return 2, None
        return None, None
    if config_mod.is_network_path(path):
        print(f"ERROR: EV_API_COLLECTION must be a local path; refusing "
              f"network/UNC path {path}", file=sys.stderr)
        return 2, None
    if args.repo_file:
        # One EV_TARGET_URL cannot stand in for every repo in a batch, so a batch run
        # verifies nothing rather than sending one target's payloads for all of them.
        print("  WARN: exploit verification is single-repo only; ignoring "
              "EV_API_COLLECTION for this batch (--repo-file) run.", file=sys.stderr)
        return None, None
    from vvaharness.exploit_verification import gate as ev_gate
    try:
        result = ev_gate.run_gate(ev_load_options(cfg, os.environ))
    except EVInputError as e:
        print(f"  ✗ exploit verification: {redact(str(e))}", file=sys.stderr)
        return 2, None
    if result.enabled:
        print("  [exploit-verification] collection gate:", file=sys.stderr)
        print(ev_gate.format_checks(result.checks), file=sys.stderr)
    return None, result.collection


def _resolve_auto_step1(flag: bool, cfg,
                        disable: bool = False) -> tuple[bool, str | None]:
    """Resolve whether AI auto-exclude runs for this scan: ``--no-auto-step1`` wins over ``--auto-step1``, which wins over ``step1.auto_exclude`` in config; returns ``(enabled, source-label)``."""
    if disable:
        return False, "--no-auto-step1"
    if flag:
        return True, "--auto-step1"
    step1 = getattr(cfg, "step1", None)
    if bool(getattr(step1, "auto_exclude", False)):
        return True, "step1.auto_exclude"
    return False, None


def _repo_name(repo: Path, explicit: str | None) -> str:
    """Return a non-empty display name for a single-repository scan."""
    if explicit and explicit.strip():
        return explicit.strip()
    return repo.resolve().name or "repo"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vvaharness scan", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo", help="path to a single local target codebase")
    src.add_argument("--repo-file",
                     help="batch input: either a .txt with one "
                          "'application_id,repository_name,path' per line, "
                          "or a .csv with header columns AppID,RepoName[,Path] "
                          "(Path derived from batch.git_base_url when absent); "
                          "each entry is cloned/scanned in sequence with a "
                          "fresh context")
    ap.add_argument("--config", default=str(_default_config()))
    ap.add_argument("--repo-name",
                    help="module / repositoryName tag for report filenames and "
                         "SARIF run.properties (single-repo mode only; "
                         "default: dir name)")
    ap.add_argument("--application-id",
                    help="application/asset ID — drives CMDB AppProfile lookup, "
                         "VulContextSeverity scoring, and SARIF run.properties.applicationId")
    ap.add_argument("--workspace", default="./batch-workspace",
                    help="directory to clone remote repos into (batch mode)")
    ap.add_argument("--keep-clones", action="store_true",
                    help="do not delete cloned repos after scanning (batch mode)")
    ap.add_argument("--group-by-app", action="store_true",
                    help="batch mode: clone every repo sharing an AppID under "
                         "{workspace}/{app_id}/ and run ONE scan over that "
                         "directory (one report per application instead of "
                         "one per repo)")
    ap.add_argument("--resume", action="store_true",
                    help="reuse existing checkpoints for completed steps")
    ap.add_argument("--stop-after",
                    choices=["clone", "ev", "s0", "s1", "s2", "s3", "s4", "s5",
                             "s6", "s7", "s8", "s9", "s10", "s11"],
                    help="stop after the named step (for debugging); "
                         "'clone' stops right after acquiring repos in batch "
                         "mode and implies --keep-clones; 'ev' verifies the "
                         "collection named by EV_API_COLLECTION (parse + "
                         "reachability probe) and stops before S1)")
    ap.add_argument("--s6-progress-file", action="store_true",
                    help="write state/s6_progress/<run_id>/s6_progress.json "
                         "after each S6 verification")
    ap.add_argument("--remediate", action="store_true",
                    help="run step 10 in fix mode: the Remediation Agent can "
                         "apply a fix to selected verified findings and writes "
                         "per-finding artefacts under "
                         "<repo>/security-remediation/ (also enabled via "
                         "step_remediate.enabled in config)")
    ap.add_argument("--top", type=_top_arg, default=None, metavar="N|all",
                    help="when step 10 is enabled: override "
                         "step_remediate.top_n_findings "
                         "for this run — remediate only the N highest-CVSS "
                         "findings (limit & reorder, highest score first), or "
                         "pass 'all' / '*' to remediate every finding. The "
                         "profile's top_n_findings is the default cap.")
    ap.add_argument("--force", action="store_true",
                    help="override safety refusals (currently: the s10 "
                         "git-SHA staleness check)")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="skip the startup credential/backend readiness probe "
                         "(does NOT bypass model/API authentication)")
    ap.add_argument("--step1-config",
                    help="explicit step1 overlay YAML (exclude_dirs/exts/"
                         "globs, max_file_kb, config_dedup). Lists APPEND to "
                         "config.yaml's step1. Mutually exclusive with "
                         "--auto-step1 (this wins). No implicit default.")
    auto_grp = ap.add_mutually_exclusive_group()
    auto_grp.add_argument("--auto-step1", action="store_true",
                    help="after clone, AI-survey each target to derive its "
                         "step1 overlay; writes <state>/checkpoints/<run_id>/"
                         "step1.yaml and applies it before s1. Ignored when "
                         "--step1-config is given. Also enabled via "
                        "step1.auto_exclude in config (enabled by default in "
                        "all shipped profiles); this flag forces it on.")
    auto_grp.add_argument("--no-auto-step1", action="store_true",
                    help="hard-disable AI auto-exclude for this run, "
                         "irrespective of step1.auto_exclude in the "
                        "active profile. Wins over --auto-step1 and "
                         "any config default. (To also disable it persistently, "
                         "set step1.auto_exclude: false in your profile.)")
    args = ap.parse_args(argv)

    # Trust gate: a config sourced from INSIDE the scan target is attacker-influenced (the canonical "cd into the checkout, then scan" CI pattern); refuse it and fall back to the packaged default unless the operator opts in.
    if args.repo and not os.environ.get("VVAHARNESS_ALLOW_CWD_CONFIG"):
        from vvaharness.orchestrator.config_paths import _packaged_default, _path_within
        if _path_within(args.config, args.repo):
            print(f"  WARN: ignoring config inside the scan target "
                  f"({args.config}) — attacker-influenced; using the packaged "
                  f"default. Set VVAHARNESS_ALLOW_CWD_CONFIG=1 to override.",
                  file=sys.stderr)
            args.config = str(_packaged_default())

    try:
        cfg = config_mod.load(args.config)
    except config_mod.ConfigPolicyError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if args.s6_progress_file:
        cfg.step6_verify.progress_file = True
    cfg_path = Path(args.config)
    cfg_dir = cfg_path.resolve().parent
    cfg_display = "config.yaml" if cfg_path.resolve() == (Path.cwd() / "config.yaml").resolve() else str(cfg_path)
    print(f"  config: {cfg_display}", file=sys.stderr)
    # The config.local.yaml overlay is logged by config.load() itself now, uniformly across every command — no separate provenance print needed here.
    _set_cmdb_path(cfg, cfg_dir)

    # AI auto-exclude precedence: --no-auto-step1 hard-disables; --step1-config still wins over an enabled auto-derivation, handled below.
    args.auto_step1, auto_step1_src = _resolve_auto_step1(
        args.auto_step1, cfg, disable=args.no_auto_step1)
    if args.no_auto_step1:
        print("  step1 overlay: --no-auto-step1 (AI auto-exclude disabled, "
              "overriding any config default)", file=sys.stderr)

    if args.step1_config:
        if config_mod.is_network_path(args.step1_config):
            print(f"ERROR: --step1-config must be a local path; refusing "
                  f"network/UNC path {args.step1_config}", file=sys.stderr)
            return 2
        s1_path = Path(args.step1_config)
        try:
            cfg, s1_applied = config_mod.apply_step1_overlay(cfg, s1_path)
        except config_mod.ConfigPolicyError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        if not s1_applied:
            print(f"ERROR: --step1-config {s1_path} not found", file=sys.stderr)
            return 2
        s1 = cfg._data.get("step1", {})
        print(f"  step1 overlay: {s1_path}  "
              f"(exclude_dirs={len(s1.get('exclude_dirs') or [])} "
              f"exts={len(s1.get('exclude_exts') or [])} "
              f"globs={len(s1.get('exclude_globs') or [])})", file=sys.stderr)
        if args.auto_step1:
            print(f"  step1 overlay: --step1-config given; ignoring "
                  f"{auto_step1_src}", file=sys.stderr)
            args.auto_step1 = False
    elif args.auto_step1:
        print(f"  step1 overlay: {auto_step1_src} (per-target "
              f"checkpoints/step1.yaml will be derived)", file=sys.stderr)

    # CMDB is OPTIONAL — without it, VulContextSeverity environmental scoring is skipped (CVSS + OffensivePriority still computed). Warn, continue.
    _cmdb = _cmdb_path()
    if not _cmdb or not os.path.isfile(_cmdb):
        _where = _cmdb or "inject.cmdb_file unset"
        print(f"  WARN: no CMDB file ({_where}) — VulContextSeverity environmental scoring "
              f"skipped (CVSS + OffensivePriority still computed).", file=sys.stderr)

    configure_backends(cfg, cfg_dir)

    # ── Exploit verification: profile switch vs command line, before anything acts on
    #    either. `enabled: true`/`false` are hard — one requires verification, the other
    #    forbids it — so either paired with the opposite command line stops the run here.
    #    Cheaper than the alternative: a full scan whose report cannot say whether EV was
    #    skipped. `auto` is defined by the command line and never conflicts.
    _ev_err = ev_resolution_error(cfg, args)
    if _ev_err:
        print(f"ERROR: {_ev_err}", file=sys.stderr)
        return 2

    # ── Exploit verification: OFFLINE collection gate, before any model spend.
    #    Validates the collection named by EV_API_COLLECTION is complete (parse + auth
    #    creds) and returns it to hand to the scan in memory. Hard-fails (return 2)
    #    when EV was requested but the collection can't run; a no-op otherwise.
    rc, ev_collection_in = _ev_gate(args, cfg)
    if rc is not None:
        return rc

    # ── Verify whichever backend(s) the config uses ────────────────────
    # 'ev' (collection check only) needs no model backend — skip the backend
    # verification so it stays fast and spend-free (the online reachability probe
    # still runs later, in scan_repo's EV prep).
    if not args.skip_preflight and args.stop_after not in ("clone", "ev"):
        # A stage this command cannot reach must not demand a credential. EV is off
        # unless a collection is supplied, and its roles are detection-era, so a gap on
        # one is fatal rather than a skip-this-stage WARN.
        _skip = () if (not args.repo_file and ev_may_run(cfg, os.environ)) else EV_MODEL_ROLES
        try:
            if not check_backends(cfg, skip_roles=_skip):
                return 1
        except KeyboardInterrupt:
            print("\n  ✗ scan aborted by user (Ctrl-C).", file=sys.stderr)
            return 130

    if args.repo_file:
        list_file = Path(args.repo_file)
        if not list_file.is_file():
            print(f"ERROR: {list_file} is not a file", file=sys.stderr)
            return 2
        return run_batch(list_file, args, cfg)

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"ERROR: {repo} is not a directory", file=sys.stderr)
        return 2
    repo_name = _repo_name(repo, args.repo_name)
    try:
        outcome = scan_repo(repo, repo_name, args.application_id, args, cfg,
                            ev_collection_in=ev_collection_in)
    except KeyboardInterrupt:
        print("\n  ✗ scan aborted by user (Ctrl-C).", file=sys.stderr)
        return 130
    except AuthenticationError as e:
        # VVAH-E001 is not retryable in-process: halt so the operator can re-auth and --resume.
        print(f"\n  ✗ {e}", file=sys.stderr)
        _errlog.log("auth", repo_name, e,
                    error_code=AuthenticationError.error_code,
                    application_id=getattr(args, "application_id", None))
        print("  (use `vvaharness doctor` to verify credentials; "
              "add --resume to continue from the last checkpoint)",
              file=sys.stderr)
        return 1
    except ProxyError as e:
        # VVAH-E002 is a configuration fault, not a transient one — no retry can clear it.
        print(f"\n  ✗ {e}", file=sys.stderr)
        _errlog.log("proxy", repo_name, e,
                    error_code=ProxyError.error_code,
                    application_id=getattr(args, "application_id", None))
        print("  (use `vvaharness doctor` to verify network/TLS settings)",
              file=sys.stderr)
        return 1
    except EVUnreachableError as e:
        # EV target unreachable (nothing live). This aborts the run early, before
        # S2+ model spend — fix connectivity/auth or unset EV_API_COLLECTION.
        print(f"  ✗ exploit verification: {redact(str(e))}", file=sys.stderr)
        return 2
    except EVInputError as e:
        # A resumed run's checkpointed collection failed the offline gate's
        # environment checks (see scan._ev_prep) — the same checklist and exit code
        # the pre-scan gate above produces for a supplied collection.
        print(f"  ✗ exploit verification: {redact(str(e))}", file=sys.stderr)
        return 2
    except EmptyScopeError as e:
        # Exit 2 = refused pre-spend, not 1 — must precede `except Exception`.
        print(f"\n  ✗ {e}", file=sys.stderr)
        _errlog.log("s1", repo_name, e,
                    reason="empty_scope",
                    application_id=getattr(args, "application_id", None))
        return 2
    except Exception as e:
        # Clean one-line failure for the operator; a raw traceback on stdout/stderr is exactly what tempts an agent to "fix" the source, so the full traceback goes to the error log and VVAHARNESS_DEBUG only.
        print(f"  ✗ scan failed: {type(e).__name__}: {redact(str(e))}", file=sys.stderr)
        # Log here too so the single-repo path is consistent with both batch paths (which log via _errlog.log("batch", ...)).
        _errlog.log("scan", repo_name, e, application_id=args.application_id)
        if os.environ.get("VVAHARNESS_DEBUG"):
            traceback.print_exc(file=sys.stderr)
        else:
            print("  (set VVAHARNESS_DEBUG=1 for the full traceback; details "
                  "in the *_errors.jsonl under security-scan/)", file=sys.stderr)
        return 1
    # A stage that ran and did not finish its work is not a clean run — remediation's exit code used to be discarded here, masking an s10 failure as a clean run.
    return outcome.exit_code
