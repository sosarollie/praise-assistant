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

"""vvaharness CLI entry point — `scan` (default), `doctor`, `estimate`, and the other subcommands."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from vvaharness.validation.constants.artifacts import VALIDATE_COMMANDS

if TYPE_CHECKING:
    from vvaharness.config import Config


def _doctor(rest: list[str]) -> int:
    """Read-only diagnostic: static readiness checks, a live backend probe, and opt-in --cache-probe."""
    if "--help" in rest or "-h" in rest:
        # Without this, asking for help RUNS the diagnostic against live backends.
        print(
            "usage: vvaharness doctor [--config PATH] [--cache-probe]\n"
            "\n"
            "Check credentials and live backend connectivity (read-only).\n"
            "Exits non-zero on any blocking issue or probe failure.\n"
            "\n"
            "  --config PATH   config to check (same resolution as `scan`)\n"
            "  --cache-probe   additionally run a prompt-cache diagnostic against\n"
            "                  each configured model route. Spends real tokens;\n"
            "                  prints an estimate first. Never runs during a scan.\n"
        )
        return 0

    from vvaharness.orchestrator import probe_backends
    from vvaharness.util import environment as env
    cfg_path = _config_path_from(rest)
    if not Path(cfg_path).exists():
        print(f"doctor: config not found: {cfg_path}", file=sys.stderr)
        return 2
    # Doctor must diagnose, not crash: on a policy refusal run_checks below
    # still renders the FAIL check.
    cfg = _load_and_configure(cfg_path, "doctor")

    checks = env.run_checks(cfg_path)
    for c in checks:
        print(f"  {_ICON.get(c.status, '?')} {c.name:<30} {c.detail}")
    n_ok, n_warn, n_blocking = env.summarize(checks)
    print("  " + "─" * 60)
    print(f"  {n_ok} ok · {n_warn} warning(s) · {n_blocking} blocking issue(s)")

    if n_blocking or cfg is None:
        print("  [probe] skipped — fix the blocking item(s) above first")
        return 1
    rc = 0 if probe_backends(cfg) else 1
    if "--cache-probe" in rest:
        if rc != 0:
            print("  [cache-probe] skipped — fix the backend probe failure(s) "
                  "above first", file=sys.stderr)
            return rc
        from vvaharness.orchestrator.preflight import run_cache_probe
        rc = 0 if run_cache_probe(cfg) else 1
    return rc


def _estimate(rest: list[str]) -> int:
    repo = None
    for i, a in enumerate(rest):
        # Accepts both `--repo PATH` and `--repo=PATH`, matching scan's argparse.
        if a == "--repo" and i + 1 < len(rest):
            repo = rest[i + 1]
        elif a.startswith("--repo="):
            repo = a.split("=", 1)[1]
    if not repo:
        print("usage: vvaharness estimate --repo <path>", file=sys.stderr)
        return 2
    root = Path(repo)
    if not root.exists():
        print(f"no such path: {repo}", file=sys.stderr)
        return 1
    text_ext = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs",
                ".c", ".cpp", ".h", ".kt", ".scala", ".rs", ".sql", ".yaml",
                ".yml", ".json", ".tf", ".sh"}
    files = bytes_ = 0
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in text_ext:
            try:
                bytes_ += p.stat().st_size
                files += 1
            except OSError:
                pass
    approx_tokens = bytes_ // 4
    print(f"scope estimate for {repo}")
    print(f"  code files       : {files:,}")
    print(f"  bytes            : {bytes_:,}")
    print(f"  ~input tokens    : {approx_tokens:,} (rough, bytes/4)")
    print("  note: the pipeline reads each file across several stages; expect")
    print("  total token usage to be a multiple of the above. Cost depends on")
    print("  the model in config.yaml. Use --stop-after s3 for an exact scope.")
    return 0


def _gc(rest: list[str]) -> int:
    """Delete old run records from the SQLite state DB, keeping reports under security-scan/ untouched."""
    import argparse

    from vvaharness.orchestrator.checkpoints import prune_checkpoints, run_id_for
    ap = argparse.ArgumentParser(prog="vvaharness gc")
    ap.add_argument("--keep-runs", type=int, default=100,
                    help="retain the N most-recent run_ids (default: 100)")
    ap.add_argument("--max-age-days", type=int, default=5,
                    help="delete runs older than D days (default: 5)")
    ap.add_argument("--run", metavar="PATH",
                    help="fully evict the run for this repo PATH (its run_id is "
                         "derived from the path) instead of age/count pruning")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be deleted; touch nothing")
    a = ap.parse_args(rest)

    # Targeted eviction: purge exactly the run for a given repo path.
    if a.run:
        from vvaharness.orchestrator import store
        rid = run_id_for(a.run)
        if a.dry_run:
            print(f"  [dry-run] gc: would evict run {rid} for {a.run}")
            return 0
        ok = store.delete_run(rid)
        print(f"  gc: {'evicted' if ok else 'no run found for'} {a.run} "
              f"(run_id {rid})")
        return 0

    r = prune_checkpoints(keep_runs=a.keep_runs,
                          max_age_days=a.max_age_days,
                          dry_run=a.dry_run)
    tag = "[dry-run] " if a.dry_run else ""
    print(f"  gc: {r['root']}")
    print(f"  {tag}kept {r['kept']} run(s), "
          f"{'would delete' if a.dry_run else 'deleted'} {len(r['deleted'])}")
    for rid in r["deleted"]:
        print(f"    - {rid}")
    return 0


def _validate(rest: list[str]) -> int:
    """Run the s11 agentic validation agent (invocable as `validate` or `s11`)."""
    from vvaharness.validation.cli import main as validate_main
    return validate_main(rest)


def _load_and_configure(cfg_path: str, label: str) -> Config | None:
    """load() plus backend configuration; a policy refusal is reported and returns None."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import configure_backends
    try:
        cfg = config_mod.load(cfg_path)
    except config_mod.ConfigPolicyError as e:
        print(f"{label}: {e}", file=sys.stderr)
        return None
    # Uses the same config the scan will use, so live probes hit the real endpoints.
    configure_backends(cfg, Path(cfg_path).resolve().parent)
    return cfg


def _remediate(rest: list[str]) -> int:
    """Drive remediation from a prior scan's findings, using the configured `models.remediate` role."""
    from vvaharness.remediation_agent import remediate
    repo = _repo_from(rest)
    if not repo:
        print("usage: vvaharness remediate --repo <path>", file=sys.stderr)
        return 2
    cfg_path = _config_path_from(rest)
    if not Path(cfg_path).exists():
        print(f"remediate: config not found: {cfg_path}", file=sys.stderr)
        return 2
    cfg = _load_and_configure(cfg_path, "remediate")
    if cfg is None:
        return 2
    return remediate(repo, rest, cfg)


def _ev_replay(rest: list[str]) -> int:
    """Re-check previously exploit-verified findings against a REDEPLOYED target.

    Reads the confirming exchanges a prior scan stored (``store.ev_replays``) and
    re-sends each, deciding whether the finding was remediated. No scan artefacts are
    read and no source is touched; the target + credentials come from ``EV_*`` env,
    exactly as a scan's exploit-verification stage does. Delegates to
    :func:`..exploit_verification.replay.run.replay_run`."""
    from vvaharness import config as config_mod
    from vvaharness.orchestrator import configure_backends
    from vvaharness.exploit_verification.replay.run import replay_run
    repo = _repo_from(rest)
    if not repo:
        print("usage: vvaharness ev-replay --repo <path>", file=sys.stderr)
        return 2
    cfg_path = _config_path_from(rest)
    if not Path(cfg_path).exists():
        print(f"ev-replay: config not found: {cfg_path}", file=sys.stderr)
        return 2
    cfg = config_mod.load(cfg_path)
    # The remediation judge (for tell-gone cases) uses the same model backend a scan
    # configures; configure it here so an env-only invocation still resolves it.
    configure_backends(cfg, Path(cfg_path).resolve().parent)
    return replay_run(repo, rest, cfg)


def _config_path_from(rest: list[str]) -> str:
    """Resolve the effective --config path (or =-joined form), else the packaged default."""
    from vvaharness.orchestrator import _default_config
    found: str | None = None
    for i, a in enumerate(rest):
        # Last occurrence wins, matching argparse's behaviour on a repeated flag.
        if a == "--config" and i + 1 < len(rest):
            found = rest[i + 1]
        elif a.startswith("--config="):
            found = a.split("=", 1)[1]
    return found if found is not None else str(_default_config())



def _check_python() -> str | None:
    """Return an error string if the interpreter is older than the package's Requires-Python floor, else None."""
    try:
        from importlib.metadata import metadata
        req = metadata("vvaharness").get("Requires-Python") or ""
    except Exception:
        return None
    import re
    m = re.search(r">=\s*(\d+)\.(\d+)", req)
    if not m:
        return None
    floor = (int(m.group(1)), int(m.group(2)))
    if sys.version_info[:2] < floor:
        cur = ".".join(str(v) for v in sys.version_info[:3])
        return (f"vvaharness requires Python >= {floor[0]}.{floor[1]}; this "
                f"interpreter is {cur}. Please use a newer Python.")
    return None


def _repo_from(rest: list[str]) -> str | None:
    """Extract the --repo target (split or =-joined form) from raw args, else None."""
    for i, a in enumerate(rest):
        if a == "--repo" and i + 1 < len(rest):
            return rest[i + 1]
        if a.startswith("--repo="):
            return a.split("=", 1)[1]
    return None


def _dotenv_path_is_trusted(path: Path) -> bool:
    """Reject unsafe POSIX ownership/modes; exact-location checks protect other OSes."""
    try:
        entries = (path.parent.stat(), path.stat())
    except OSError:
        return False
    get_euid = getattr(os, "geteuid", None)
    if get_euid is None:
        return True
    effective_uid = get_euid()
    for entry in entries:
        if entry.st_uid != effective_uid:
            return False
        if entry.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
    return True


def _dotenv_selection(
    repo: str | None = None, *, warn: bool = False,
) -> tuple[Path | None, str | None, tuple[Path, ...]]:
    """Return the selected dotenv path, its source, and rejected candidates."""
    roots: list[tuple[str, Path]] = []
    for source, get_root in (("cwd", Path.cwd), ("home", Path.home)):
        try:
            roots.append((source, get_root().resolve()))
        except (OSError, RuntimeError):
            continue

    rejected: list[Path] = []
    seen_roots: set[Path] = set()
    for source, root in roots:
        if root in seen_roots:
            continue
        seen_roots.add(root)
        candidate = root / ".env"
        if not candidate.is_file():
            continue
        try:
            path = candidate.resolve(strict=True)
        except OSError:
            continue
        if path.parent != root or not _dotenv_path_is_trusted(path):
            rejected.append(candidate)
            if warn:
                print(f"  WARN: ignoring untrusted .env ({candidate}) — it must be "
                      f"a user-owned, non-group/world-writable file in cwd or home.",
                      file=sys.stderr)
            continue
        if repo and not os.environ.get("VVAHARNESS_ALLOW_CWD_CONFIG"):
            from vvaharness.orchestrator.config_paths import _path_within
            if _path_within(path, repo):
                rejected.append(candidate)
                if warn:
                    print(f"  WARN: ignoring .env inside the scan target ({path}) — "
                          f"attacker-influenced; set VVAHARNESS_ALLOW_CWD_CONFIG=1 "
                          f"to override.", file=sys.stderr)
                continue
        return path, source, tuple(rejected)
    return None, None, tuple(rejected)


def _dotenv_path(repo: str | None = None, *, warn: bool = False) -> Path | None:
    """Return the first trusted cwd/home ``.env`` accepted for this invocation."""
    return _dotenv_selection(repo, warn=warn)[0]


def _load_dotenv(repo: str | None = None) -> None:
    """Load a trusted .env from exactly cwd or home, never an arbitrary ancestor."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    path = _dotenv_path(repo, warn=True)
    if path is None:
        return
    load_dotenv(path, override=False)
    print(f"  [env] loaded {path}", file=sys.stderr)


_ICON = {"ok": "✓", "warn": "⚠", "fail": "✗"}


def _install_agents() -> int:
    """Drop operating instructions into each installed AI agent's file, leaving existing files untouched."""
    import shutil

    from vvaharness import agentdoc
    cwd, home = Path.cwd(), Path.home()

    def put(path: Path, content: str) -> None:
        if path.exists():
            print(f"    • exists, left as-is: {path}")
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"    ✓ wrote {path}")

    # Cross-tool standard + Copilot: no CLI to detect, so always provide it.
    put(cwd / "AGENTS.md", agentdoc.AGENT_DOC)
    put(cwd / ".github" / "copilot-instructions.md", agentdoc.AGENT_DOC)
    if shutil.which("claude"):
        put(cwd / "CLAUDE.md", agentdoc.AGENT_DOC)
        put(home / ".claude" / "skills" / "vvaharness" / "SKILL.md",
            agentdoc.CLAUDE_SKILL)
    if shutil.which("gemini"):
        put(cwd / "GEMINI.md", agentdoc.gemini_doc())
    return 0


def _setup(rest: list[str]) -> int:
    """Guided readiness wizard: checks env/deps/config and offers to scaffold a .env; read-only unless --write-env."""
    from vvaharness import __version__
    from vvaharness.util import environment as env
    from vvaharness.util.environment import FAIL

    cfg_path = _config_path_from(rest)
    write_env = "--write-env" in rest

    print(f"\n  ⟐  vvaharness {__version__} — setup\n")
    _prompt_for_remediation_inputs()
    checks = env.run_checks(cfg_path)
    for c in checks:
        print(f"  {_ICON.get(c.status, '?')} {c.name:<30} {c.detail}")

    n_ok, n_warn, n_blocking = env.summarize(checks)
    print("  " + "─" * 60)
    print(f"  {n_ok} ok · {n_warn} warning(s) · {n_blocking} blocking issue(s)")

    # Recommends the profile matching the creds actually present, not just the sdk default.
    prof, why = env.recommend_profile()
    if prof:
        print(f"\n  → Recommended profile: {prof}  ({why})")
        if prof != "default":
            print(f"      vvaharness scan --repo <path> "
                  f"--config vvaharness/config/profiles/{prof}.yaml")

    # Targets the most common trap: gateway token present but no base_url set.
    gw = next((c for c in checks if c.name == "via:sdk endpoint"
               and c.status == FAIL), None)
    gw_url, gw_src = env.detect_gateway()
    ca = env.detect_ca_cert()
    if gw:
        print("\n  → Fix the Anthropic endpoint:")
        if gw_url:
            print(f"      export ANTHROPIC_BASE_URL={gw_url.split('?', 1)[0]}"
                  f"   # found in {gw_src}")
        else:
            print("      export ANTHROPIC_BASE_URL=https://<your-gateway>/")
        if ca:
            # This block fixes the Anthropic endpoint reached by via:sdk /
            # via:deepagents(anthropic) — those Python clients read
            # SSL_CERT_FILE (or the profile's sdk.ca_cert), never
            # NODE_EXTRA_CA_CERTS; that variable only reaches the Node paths
            # (via:cli roles, Agent-SDK S11 launcher).
            print(f"      export SSL_CERT_FILE={ca}   # via:sdk + "
                  "via:deepagents; or set ANTHROPIC_SDK_CA_CERT — the shipped "
                  "profiles expand it into sdk.ca_cert")
        print("      export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1   "
              "# if the gateway rejects beta flags (400)")

    # Deliberately NOT inside `if gw:` above. That block only prints when the
    # via:sdk endpoint check FAILED, and the case this advisory exists for is the
    # opposite one: a gateway that works perfectly and bills every prompt token
    # uncached, because host detection cannot recognise it and so fails closed and
    # withholds cache markers. The scan says so too, but only once it is already
    # spending; setup is where the operator first learns the endpoint at all.
    if gw_url:
        from urllib.parse import urlsplit

        from vvaharness.backends.llm import sdk as _sdk
        _host = (urlsplit(gw_url).hostname or "").lower()
        _known = any(rx.search(_host) for rx in (_sdk._ANTHROPIC_HOST_RX,
                                                 _sdk._VERTEX_HOST_RX,
                                                 _sdk._BEDROCK_HOST_RX))
        if not _known:
            print("\n  → Prompt caching on this endpoint (cost only — results "
                  "are identical either way):")
            print(f"      {_host} is not recognisably Anthropic, Vertex or "
                  f"Bedrock, so cache markers are withheld and every prompt "
                  f"token bills uncached.")
            print("      If the gateway is Anthropic-Messages-compatible, put "
                  "this in config.local.yaml")
            print("      beside your profile (git-ignored, merged over it; the "
                  "file must be owned\n      by you and not group/world-writable):")
            print("          cache_route: anthropic")
            print("      then confirm it before a real scan:")
            print("          vvaharness doctor --cache-probe")

    # .env scaffold — pre-fill the discovered gateway/CA so the next run works.
    env_file = Path(".env")
    if not env_file.exists():
        example = Path(".env.example")
        if write_env:
            base = example.read_text(encoding="utf-8") if example.exists() else ""
            extra = ""
            if gw_url:
                extra += f"\n# auto-detected from {gw_src}\nANTHROPIC_BASE_URL={gw_url}\n"
            if ca:
                extra += (
                    "# CA bundle for the Anthropic endpoint — via:sdk and "
                    "via:deepagents read SSL_CERT_FILE\n"
                    "# (shipped profiles also expand ANTHROPIC_SDK_CA_CERT "
                    "into sdk.ca_cert):\n"
                    f"SSL_CERT_FILE={ca}\n"
                    "# only the Node-based paths (via:cli roles, the "
                    "Agent-SDK S11 launcher) read this one:\n"
                    f"NODE_EXTRA_CA_CERTS={ca}\n"
                )
            if gw_url or ca:
                extra += "# uncomment if the gateway rejects beta flags (400):\n" \
                         "# CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1\n"
            env_file.write_text(base + extra, encoding="utf-8")
            print("\n  ✓ wrote .env"
                  + (" (incl. detected gateway)" if gw_url else "")
                  + " — fill in any remaining keys, then "
                  "`set -a && source .env && set +a`")

    # Surfaces rulepack generation when the generated source/sink files are absent.
    rules_dir = Path(__file__).resolve().parent / "rules"
    src_gen = rules_dir / "sources.generated.yaml"
    sink_gen = rules_dir / "sinks.generated.yaml"
    if not src_gen.is_file() and not sink_gen.is_file():
        print("\n  → Optional (taint profile): generated callgraph rulepacks not found")
        print(f"      missing: {src_gen.name}, {sink_gen.name}")
        print("      build them from local corpus clones:")
        print("      python -m vvaharness.rules.build_kb \\")
        print("        --semgrep /path/to/semgrep-rules \\")
        print("        --codeql /path/to/codeql \\")
        print(f"        --sources-out {src_gen} \\")
        print(f"        --sinks-out {sink_gen}")
        print("      No corpus clones yet? See docs/SETUP_GUIDE.md section")
        print("      'Generated source/sink rule files (taint profile)'.")

    # Opt-in (--install-agents); otherwise just suggest it.
    if "--install-agents" in rest:
        print("\n  Installing AI-agent instructions:")
        _install_agents()
    else:
        print("\n  AI agent driving this? Run `vvaharness setup --install-agents` "
              "to drop the right instructions for your agent (Claude/Copilot/"
              "Gemini) so it runs the tool instead of editing it.")
        print("  (Operating manual: AGENTS.md · capabilities: docs/SKILLS.md)")
    if n_blocking:
        print(f"\n  Not ready: fix the {n_blocking} blocking item(s) above, "
              f"then `vvaharness scan`.\n")
        return 1
    print("\n  Ready ✓  →  vvaharness scan --repo /path/to/target")
    print("  The packaged default profile skips S10 remediation and S11 validation.")
    print("  ⚠ --remediate enables S10 only and can edit target source; "
          "in-scan S11 needs step_validate.enabled: true.")
    print("    Other profiles or a local overlay can enable S10/S11; "
          "--stop-after s9 skips both with any profile.\n")
    return 0


def _prompt_for_remediation_inputs() -> None:
    """Persist an inputs directory when wheel defaults cannot be resolved."""
    from vvaharness.remediation_agent import rule_paths

    missing = rule_paths.missing_rules(rule_paths.__file__)
    if not missing or not sys.stdin.isatty():
        return
    print("  ! remediation defaults are missing: " + ", ".join(missing))
    while True:
        try:
            answer = input(
                "  Path to the VVAH inputs directory (blank to skip): "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not answer:
            return
        directory, absent = rule_paths.validate_inputs_dir(answer)
        if absent:
            print(f"  ! {directory} is missing: {', '.join(absent)}")
            continue
        target = rule_paths.save_inputs_dir(directory)
        print(f"  ✓ saved remediation inputs directory in {target}")
        return


def _print_help() -> None:
    from vvaharness import __version__
    print(f"""vvaharness {__version__} — agentic SAST pipeline

Usage: vvaharness <command> [options]

Commands:
    --version  Print the installed Visa Vulnerability Agentic Harness version
  setup      Guided readiness check: AI agents, keys, deps, gateway, config
  doctor     Check credentials + live backend connectivity (read-only)
             (--cache-probe: opt-in live prompt-cache diagnostic — spends
              real tokens (~65-70k/model, printed before it runs); never
              runs without this flag, never runs during `scan`)
  estimate   Print a rough scope/cost preview for a repo (no API spend)
  gc         Delete old checkpoint runs (--keep-runs / --max-age-days / --dry-run)
  scan       Scan a repo (or --repo-file batch) for vulnerabilities
             (packaged default skips S10/S11; --remediate enables S10 only and can edit source)
             (in-scan S11 needs step_validate.enabled: true; --stop-after s9 skips both)
  remediate  Walk findings from a prior scan and remediate them (Remediation Agent)
             (--interactive/-i to pick issues from a menu; --mode fix|report-only;
              --top N overrides step_remediate.top_n_findings to remediate only
              the N highest-CVSS findings (--top all / --top * remediates every one);
              --verbose/-v to print the prompt + raw LLM response per finding)
  validate   Run the s11 agentic validation agent on applied remediations
  s11        Alias for `validate` — the s11 agentic validation stage
  ev-replay  Re-check exploit-verified findings against a REDEPLOYED target: re-send
             each stored confirming payload and report remediated / still-vulnerable
             (needs a prior scan run with EV_API_COLLECTION; EV_TARGET_URL + EV_* env)

Run 'vvaharness scan --help' for the full list of scan options.
Run 'vvaharness validate --help' (or 'vvaharness s11 --help') for validation options.
Config:
  vvaharness uses ./config.yaml when present; otherwise it uses the packaged default.
  Customise: cp vvaharness/config/profiles/sdk.yaml config.yaml   (all-SDK profile; see also full.yaml)
    sdk/full profiles enable S10/S11; default/taint disable them. A local overlay can override these flags.
    Standalone remediate and validate remain available when the scan flags are false.
Quick start:
  vvaharness setup
  vvaharness estimate --repo /path/to/target
    vvaharness scan --repo /path/to/target --application-id 12345   # packaged default skips S10/S11
    vvaharness scan --repo /path/to/target --stop-after s9          # explicitly skip S10/S11 with any profile
""")



def _configure_logging(args: list[str]) -> list[str]:
    """Honour --log-level / --log-file (stripped, since subcommand parsers don't declare them), returning *args* without them."""
    from vvaharness.util.logs import configure

    level, path, rest = None, None, []
    it = iter(range(len(args)))
    skip = -1
    for i in it:
        if i <= skip:
            continue
        arg = args[i]
        for flag, setter in (("--log-level", "level"), ("--log-file", "path")):
            if arg == flag and i + 1 < len(args):
                value, skip = args[i + 1], i + 1
                break
            if arg.startswith(f"{flag}="):
                value, setter = arg.split("=", 1)[1], setter
                break
        else:
            rest.append(arg)
            continue
        if setter == "level":
            level = value
        else:
            path = value
    configure(level, path)
    return rest


def _version() -> int:
    """Print the package version without loading configuration or environment."""
    from vvaharness import __version__

    print(f"Visa Vulnerability Agentic Harness {__version__}")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        err = _check_python()
        if err:
            print(f"ERROR: {err}", file=sys.stderr)
            return 2

        args = list(sys.argv[1:] if argv is None else argv)
        if args == ["--version"]:
            return _version()
        _load_dotenv(_repo_from(args))
        # Consumed here (before any command) rather than per-subcommand parser, since three are hand-rolled.
        args = _configure_logging(args)
        # Must not silently default to `scan`, which would write a junk run_manifest.json.
        if not args or args[0] in ("-h", "--help", "help"):
            _print_help()
            return 0
        cmd = args[0]
        if cmd in ("setup", "init"):
            return _setup(args[1:])
        if cmd == "doctor":
            return _doctor(args[1:])
        if cmd == "estimate":
            return _estimate(args[1:])
        if cmd == "gc":
            return _gc(args[1:])
        if cmd == "remediate":
            return _remediate(args[1:])
        if cmd == "ev-replay":
            return _ev_replay(args[1:])
        if cmd in VALIDATE_COMMANDS:
            return _validate(args[1:])
        if cmd == "scan":
            args = args[1:]

        from vvaharness import manifest, orchestrator
        cfg_path = _config_path_from(args)
        # Explicit argv avoids global sys.argv mutation, so concurrent in-process main() calls don't collide.
        with manifest.capture(cfg_path, args) as m:
            rc = orchestrator.main(args)
            m["exit_code"] = rc
        return rc
    except KeyboardInterrupt:
        print("\n  ✗ command aborted by user (Ctrl-C).", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
