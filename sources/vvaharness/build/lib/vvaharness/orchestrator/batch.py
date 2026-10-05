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

"""orchestrator.batch — see package docstring."""
import csv
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

from vvaharness.backends.harness.models import AuthenticationError, ProxyError
from vvaharness.backends.llm import cli
# The single audited Markdown neutraliser — a hardening fix there must never leave this path behind.
from vvaharness.models import _md_cell
from vvaharness.orchestrator import store as _store
from vvaharness.orchestrator.case_rollup import EXIT_NOT_REMEDIATED
from vvaharness.orchestrator.cleanup import _preserve_set, _purge_clone, _rmtree_rw
from vvaharness.orchestrator.cmdb import _load_app_profile
from vvaharness.orchestrator.scan import ScanOutcome, scan_repo
from vvaharness.util import errlog as _errlog
from vvaharness.util.counters import COUNTERS
from vvaharness.util.response_quality import reset_counters as _reset_quality_counters
from vvaharness.util.stage_telemetry import STAGES
from vvaharness.util.tokens import TOKENS
from vvaharness.util.warn_once import reset_warn_once_registries as _reset_warn_once


def _module_name_from(ref: str) -> str:
    tail = ref.rstrip("/").split("/")[-1]
    if tail.lower().endswith(".git"):
        tail = tail[:-4]
    return tail or "repo"


def _is_remote(ref: str) -> bool:
    return ref.startswith(("http://", "https://", "git@", "ssh://")) or ref.endswith(".git")


# Strip `scheme://user:token@host` userinfo down to `scheme://***@host` so an inline credential in a repo URL never reaches stderr, an error string, or the batch summary.
_URL_USERINFO_RX = re.compile(r"(\w[\w+.\-]*://)[^/@\s]+@")


def _scrub_url_secrets(s: str) -> str:
    if not s:
        return s
    return _URL_USERINFO_RX.sub(r"\1***@", s)


def _stash_url_for(repo_name: str, base: str) -> str:
    """RepoName is the full repo slug — '{base}/{repo_name}.git'."""
    return f"{base.rstrip('/')}/{repo_name}.git"


# A staged repo is bound to the repo it was created from via a marker kept in the operator-private state dir, so a writer who controls only the (shared) workspace cannot forge reuse of a stale/foreign/pre-seeded dir.
def _state_root() -> Path:
    return _store.state_root()


def _ref_id(ref: str) -> str:
    """Stable, token-free id for a repo ref — the original csv URL / local path, not the token-bearing clone URL."""
    return hashlib.sha256(str(ref).encode("utf-8")).hexdigest()[:32]


def _stage_marker_path(dest: Path) -> Path:
    key = hashlib.sha256(str(Path(dest).resolve()).encode("utf-8")).hexdigest()[:32]
    return _state_root() / "stage-markers" / f"{key}.json"


def _write_stage_marker(dest: Path, ref: str, kind: str) -> None:
    """Record that `dest` was staged from `ref`. Best-effort — a marker-write failure just means the next run re-stages."""
    mp = _stage_marker_path(dest)
    try:
        # Through store, so this integrity control is not the one directory under
        # the state root created at the umask default: a marker a foreign writer can
        # read is a marker they can learn to forge around.
        _store.ensure_state_dir("stage-markers")
        mp.write_text(json.dumps({"v": 1, "kind": kind, "ref_id": _ref_id(ref)}),
                      encoding="utf-8")
    except OSError as e:
        print(f"  [batch] WARN: could not write stage marker for {dest}: {e}",
              file=sys.stderr)


def _stage_dir_bound(dest: Path, ref: str) -> bool:
    """True iff `dest` carries a state-dir marker proving it was staged from `ref` by a prior run; missing/mismatched/corrupt means the caller must re-stage."""
    try:
        data = json.loads(_stage_marker_path(dest).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("ref_id") == _ref_id(ref)


def _assign_slugs(repos: list[dict]) -> list[str]:
    """Map each repo in an app group to a UNIQUE staging slug, so two repo names with the same tail don't collide and silently reuse one dir."""
    slugs: list[str] = []
    used: set[str] = set()
    for r in repos:
        base = _module_name_from(r["repo_name"])
        slug = base
        salt = r["repo_name"]
        while slug in used:                  # collision (or pathological re-hit)
            slug = f"{base}-{hashlib.sha1(salt.encode('utf-8')).hexdigest()[:8]}"
            salt = slug + r["repo_name"]
        used.add(slug)
        slugs.append(slug)
    return slugs


# Bounds the decode/parse so an oversized or pathological manifest fails fast instead of OOM-killing the batch runner; caps are deliberately generous.
_MANIFEST_MAX_BYTES = 64 * 1024 * 1024      # 64 MiB on disk
_MANIFEST_MAX_ROWS = 200_000                # data rows / physical lines


def _check_manifest_size(list_file: Path) -> None:
    """Reject a manifest larger than the byte cap before it is decoded into memory; raises ValueError (caught by run_batch -> exit 2)."""
    try:
        size = list_file.stat().st_size
    except OSError as e:
        raise ValueError(f"{list_file}: cannot stat manifest: {e}")
    if size > _MANIFEST_MAX_BYTES:
        raise ValueError(
            f"{list_file}: manifest is {size} bytes, over the "
            f"{_MANIFEST_MAX_BYTES // (1024 * 1024)} MiB cap — split the batch "
            f"into smaller manifests")


def _parse_repo_csv(list_file: Path, git_base_url: str | None) -> list[dict]:
    """Parse a .csv batch sheet with an AppID/RepoName[/Path] header (case-insensitive aliases accepted)."""
    _check_manifest_size(list_file)
    # Stream the reader rather than list(csv.reader(fh)) so a manifest is never fully materialized into memory before validation.
    with open(list_file, newline="", encoding="utf-8-sig") as fh:
        rows = csv.reader(fh)
        try:
            header = next(rows)
        except StopIteration:
            raise ValueError(f"{list_file}: empty file")

        hdr = {str(h).strip().lower(): i for i, h in enumerate(header) if h}
        def col(*names):
            for n in names:
                if n in hdr:
                    return hdr[n]
            return None
        i_app = col("appid", "application_id", "app_id", "applicationid")
        i_repo = col("reponame", "repository_name", "repo_name", "repo")
        i_path = col("path", "url", "repo_url", "ref")
        if i_app is None or i_repo is None:
            raise ValueError(
                f"{list_file}: header must contain AppID and RepoName columns "
                f"(found: {list(hdr.keys())})")
        if i_path is None and not git_base_url:
            raise ValueError(
                f"{list_file}: no Path column and batch.git_base_url is not set — "
                f"cannot derive clone URLs")

        entries: list[dict] = []
        errors: list[str] = []
        seen: set[str] = set()
        for lineno, row in enumerate(rows, 2):
            if lineno - 1 > _MANIFEST_MAX_ROWS:
                raise ValueError(
                    f"{list_file}: over {_MANIFEST_MAX_ROWS} data rows — "
                    f"split the batch into smaller manifests")
            def at(i):
                if i is None or i >= len(row):
                    return ""
                return str(row[i]).strip()
            app_id, repo_name, ref = at(i_app), at(i_repo), at(i_path)
            if not app_id and not repo_name:
                continue
            if not app_id or not repo_name:
                errors.append(f"row {lineno}: AppID and RepoName are both required")
                continue
            if not ref:
                # A blank Path cell can only be resolved when git_base_url is set; otherwise this is a validation error caught up-front, not an opaque AttributeError mid-derive.
                if not git_base_url:
                    errors.append(
                        f"row {lineno}: Path is blank and batch.git_base_url is "
                        f"not set — cannot derive a clone URL")
                    continue
                ref = _stash_url_for(repo_name, git_base_url)
            if ref.lstrip().startswith("-"):
                # A leading "-" would be consumed by `git clone` as an option rather than a URL operand. Reject up front.
                errors.append(f"row {lineno}: path '{ref}' may not start with '-'")
                continue
            if not _is_remote(ref) and not Path(ref).is_dir():
                errors.append(f"row {lineno}: path '{ref}' is neither a git URL "
                              f"nor an existing local directory")
                continue
            if ref in seen:
                errors.append(f"row {lineno}: duplicate path '{ref}'")
                continue
            seen.add(ref)
            entries.append({"application_id": app_id,
                            "repo_name": repo_name,
                            "ref": ref})

    if errors:
        raise ValueError(f"{list_file}: {len(errors)} validation error(s):\n  - "
                         + "\n  - ".join(errors))
    if not entries:
        raise ValueError(f"{list_file}: no repo entries found")
    return entries


def _parse_repo_file(list_file: Path) -> list[dict]:
    """Parse the batch input file: each non-blank, non-comment line is ``application_id,repository_name,path``, validated up-front so a bad line fails before any scan starts."""
    _check_manifest_size(list_file)
    entries: list[dict] = []
    errors: list[str] = []
    seen: set[str] = set()

    # Stream lines rather than read_text().splitlines() so a manifest is never fully materialized into memory.
    with open(list_file, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            if lineno > _MANIFEST_MAX_ROWS:
                raise ValueError(
                    f"{list_file}: over {_MANIFEST_MAX_ROWS} lines — "
                    f"split the batch into smaller manifests")
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 3:
                errors.append(f"line {lineno}: expected 3 comma-separated fields "
                              f"(application_id,repository_name,path) — got {len(parts)}")
                continue

            app_id, repo_name, ref = parts
            if not app_id:
                errors.append(f"line {lineno}: application_id is empty")
            if not repo_name:
                errors.append(f"line {lineno}: repository_name is empty")
            if not ref:
                errors.append(f"line {lineno}: path is empty")
            if not (app_id and repo_name and ref):
                continue

            if ref.lstrip().startswith("-"):
                # A leading "-" would be consumed by `git clone` as an option rather than a URL operand. Reject up front.
                errors.append(f"line {lineno}: path '{ref}' may not start with '-'")
                continue
            if not _is_remote(ref) and not Path(ref).is_dir():
                errors.append(f"line {lineno}: path '{ref}' is neither a git URL "
                              f"nor an existing local directory")
                continue

            if ref in seen:
                errors.append(f"line {lineno}: duplicate path '{ref}'")
                continue
            seen.add(ref)

            entries.append({"application_id": app_id,
                            "repo_name": repo_name,
                            "ref": ref})

    if errors:
        msg = f"{list_file}: {len(errors)} validation error(s):\n  - " \
              + "\n  - ".join(errors)
        raise ValueError(msg)
    if not entries:
        raise ValueError(f"{list_file}: no repo entries found")
    return entries


def _with_token(url: str, token: str | None) -> str:
    if not token or not url.startswith(("http://", "https://")) or "@" in url.split("//", 1)[1]:
        return url
    scheme, rest = url.split("://", 1)
    return f"{scheme}://x-access-token:{token}@{rest}"


def _acquire_repo(ref: str, workspace: Path, git_token: str | None,
                  dest_name: str | None = None) -> Path:
    """Return a local directory for `ref`, cloning into `workspace` if remote."""
    if not _is_remote(ref):
        p = Path(ref)
        if not p.is_dir():
            raise RuntimeError(f"local path does not exist: {ref}")
        return p

    workspace.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "._-" else "_"
                   for c in (dest_name or _module_name_from(ref)))
    # "." and ".." survive the per-char allowlist and would escape the workspace, after which _purge_clone deletes the PARENT. Refuse.
    if safe in (".", "..") or not safe.strip("."):
        raise RuntimeError(
            f"refusing unsafe clone dest name {safe!r} derived from "
            f"{(dest_name or ref)!r}: '.'/'..' would escape the workspace")
    dest = workspace / safe
    if dest.exists():
        has_content = any(p for p in dest.iterdir() if p.name != ".git")
        # Reuse ONLY a dir that is both non-empty AND bound (by a state-dir marker) to THIS ref — never a stale/foreign/pre-seeded dir.
        if has_content and _stage_dir_bound(dest, ref):
            print(f"  [batch] reusing verified checkout {dest}", file=sys.stderr)
            return dest
        reason = ("empty" if not has_content else
                  "unverified (no matching stage marker — stale, foreign, or "
                  "pre-seeded)")
        print(f"  [batch] {reason} dir at {dest} — removing and re-cloning",
              file=sys.stderr)
        _rmtree_rw(dest)
        if dest.exists():
            print(f"  [batch] could not remove {dest}; reusing as-is",
                  file=sys.stderr)
            return dest
    clone_url = _with_token(ref, git_token)
    print(f"  [batch] git clone {_scrub_url_secrets(ref)} -> {dest}",
          file=sys.stderr)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    # Bound the clone so a network stall / unresponsive remote cannot hang the whole batch; GIT_TERMINAL_PROMPT=0 only suppresses interactive auth, not stalls.
    try:
        r = subprocess.run(["git", "-c", "core.longpaths=true",
                            "clone", "--depth", "1", "--", clone_url, str(dest)],
                           capture_output=True, text=True, env=env,
                           timeout=600)
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"git clone timed out after 600s: {ref} (network stall or "
            f"unresponsive remote)")
    if r.returncode != 0:
        err = (r.stderr.strip() or r.stdout.strip())
        if git_token:
            err = err.replace(git_token, "***")
        # Mask any inline userinfo credential the remote echoed back before the RuntimeError reaches stderr / errlog / the batch summary.
        err = _scrub_url_secrets(err)
        raise RuntimeError(f"git clone failed: {err}")
    _write_stage_marker(dest, ref, "remote")
    return dest


def _outcome_status(outcome: ScanOutcome) -> dict[str, object]:
    """Fold one repo's scan outcome into the summary row's status fields; a stage that exited non-zero is DEGRADED, while a run that finished and validated nothing it remediated is NOT_REMEDIATED."""
    if outcome.exit_code == 0:
        status, error = "OK", ""
    elif outcome.exit_code == EXIT_NOT_REMEDIATED:
        # An outcome claim, not a health claim: every stage ran. Reporting this row as
        # "a scan stage exited 3" would rebuild at the batch layer the exact conflation
        # between a broken run and an unsuccessful one that the exit code removes.
        status = "NOT_REMEDIATED"
        error = "the scan completed but nothing it remediated validated as fixed"
    else:
        status = "DEGRADED"
        error = f"a scan stage exited {outcome.exit_code}; see the per-repo log"
    return {
        "status": status,
        "findings": outcome.finding_count,
        "report": str(outcome.report_path) if outcome.report_path else "",
        "error": error,
    }


def _split_non_ok(results: list[dict]) -> tuple[list[dict], list[dict]]:
    """Partition the non-OK rows into ``(unremediated, failures)``.

    One function because the ``status != "OK"`` fold exists three times — both
    invocation returns and the summary's Failures section — and all three now need the
    same three-way answer. Fixing two of them and not the third would leave
    batch_summary.md contradicting the exit code it was written beside.

    A deny-list on purpose: any status this has never heard of lands in *failures*, so a
    sixth status added later cannot fall out of both buckets and silently turn a failure
    into "all repos OK". That is also why ABORTED needs no mention here — it is set per
    repo on KeyboardInterrupt, and an interrupted batch did not run fine and validate
    nothing.
    """
    unremediated = [r for r in results if r["status"] == "NOT_REMEDIATED"]
    failures = [r for r in results if r["status"] not in ("OK", "NOT_REMEDIATED")]
    return unremediated, failures


def run_batch(list_file: Path, args, cfg) -> int:
    batch_cfg = getattr(cfg, "batch", None)
    git_token = getattr(batch_cfg, "git_token", None) or None
    git_base = getattr(batch_cfg, "git_base_url", None) or None
    try:
        if list_file.suffix.lower() == ".csv":
            entries = _parse_repo_csv(list_file, git_base)
        else:
            entries = _parse_repo_file(list_file)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    # Filtered out here, before cloning/scanning, via case-insensitive fnmatch globs against RepoName (e.g. "*automation*", "*-karate*").
    skip_pats = [p.lower() for p in
                 (getattr(batch_cfg, "skip_repo_patterns", None) or [])]
    if skip_pats:
        kept: list[dict] = []
        for e in entries:
            name = e["repo_name"]
            hit = next((p for p in skip_pats
                        if fnmatch.fnmatch(name.lower(), p)), None)
            if hit:
                print(f"  [batch] skipping '{name}' (app {e['application_id']}) "
                      f"— matches batch.skip_repo_patterns: {hit}",
                      file=sys.stderr)
            else:
                kept.append(e)
        if len(kept) != len(entries):
            print(f"  [batch] {len(entries)} rows → {len(kept)} after "
                  f"skip_repo_patterns ({len(entries) - len(kept)} dropped)",
                  file=sys.stderr)
        entries = kept
        if not entries:
            print(f"ERROR: all rows in {list_file} were excluded by "
                  f"batch.skip_repo_patterns", file=sys.stderr)
            return 2

    workspace = Path(args.workspace)

    if getattr(args, "group_by_app", False):
        return _run_batch_grouped(entries, workspace, git_token, args, cfg,
                                  list_file)

    results: list[dict] = []
    batch_t0 = time.time()

    for i, entry in enumerate(entries, 1):
        ref = entry["ref"]
        repo_name = entry["repo_name"]
        app_id = entry["application_id"]
        print(f"\n{'='*72}\n[batch {i}/{len(entries)}] {repo_name}  "
              f"app_id={app_id}  ({_scrub_url_secrets(ref)})\n{'='*72}",
              file=sys.stderr)
        TOKENS.reset()  # fresh accounting per repo
        STAGES.reset()
        COUNTERS.reset()
        _reset_quality_counters()
        # Re-arm the one-shot diagnostics too: without this, repo N>1 loses
        # every warn-once (including the deepagents "no token usage recorded"
        # WARN — the only signal that a stage's usage went unrecorded there).
        _reset_warn_once()
        cli.reset_abort()  # don't let a prior repo's guardrail abort poison this one
        t0 = time.time()
        cloned: Path | None = None
        try:
            local = _acquire_repo(ref, workspace, git_token,
                                  dest_name=repo_name)
            if _is_remote(ref):
                cloned = local
            if args.stop_after == "clone":
                results.append({
                    "ref": ref, "module": repo_name, "app_id": app_id,
                    "status": "OK", "findings": 0, "report": str(local),
                    "elapsed": time.time() - t0, "error": "",
                })
                continue
            outcome = scan_repo(local, repo_name, app_id, args, cfg,
                                path_prefix=repo_name)
            results.append({
                "ref": ref, "module": repo_name, "app_id": app_id,
                **_outcome_status(outcome),
                "elapsed": time.time() - t0,
            })
        except KeyboardInterrupt:
            results.append({"ref": ref, "module": repo_name, "app_id": app_id,
                            "status": "ABORTED", "findings": 0, "report": "",
                            "elapsed": time.time() - t0,
                            "error": "interrupted by user"})
            raise
        except (AuthenticationError, ProxyError):
            # VVAH-E001 / VVAH-E002 are environment-wide — every remaining repo would fail identically.
            raise
        except Exception as e:
            # Ordinary failures are repo-scoped: record them and keep the rest
            # of the batch moving.
            traceback.print_exc(file=sys.stderr)
            _errlog.log("batch", repo_name, e, app_id=app_id, ref=ref)
            results.append({"ref": ref, "module": repo_name, "app_id": app_id,
                            "status": "FAILED", "findings": 0, "report": "",
                            "elapsed": time.time() - t0, "error": str(e)[:500]})
        finally:
            if cloned and not args.keep_clones and args.stop_after != "clone":
                _purge_clone(cloned, _preserve_set(cfg))

    summary_path = workspace / "batch_summary.md"
    workspace.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(_render_batch_summary(results, list_file,
                                                  time.time() - batch_t0),
                            encoding="utf-8")
    print(f"\n[batch] summary written to {summary_path}", file=sys.stderr)

    unremediated, failed = _split_non_ok(results)
    if not (unremediated or failed):
        print(f"\n[batch] all {len(results)} repos OK", file=sys.stderr)
        return 0
    if unremediated:
        print(f"\n[batch] {len(unremediated)}/{len(results)} repos validated nothing "
              f"they remediated:", file=sys.stderr)
        for r in unremediated:
            print(f"  - {r['module']} ({_scrub_url_secrets(r['ref'])})",
                  file=sys.stderr)
    if failed:
        print(f"\n[batch] {len(failed)}/{len(results)} repos FAILED:", file=sys.stderr)
        for r in failed:
            print(f"  - {r['module']} ({_scrub_url_secrets(r['ref'])}): "
                  f"{_scrub_url_secrets(r['error'])}", file=sys.stderr)
        # Health outranks outcome, the same precedence the single-repo path applies: a
        # batch with a real failure in it reports the failure, not the shortfall.
        return 1
    return EXIT_NOT_REMEDIATED


def _stage_repo(ref: str, app_dir: Path, slug: str, git_token: str | None) -> None:
    """Place repo `ref` at app_dir/slug — clone if remote, copytree if local."""
    if _is_remote(ref):
        _acquire_repo(ref, app_dir, git_token, dest_name=slug)
        return
    src = Path(ref)
    if not src.is_dir():
        raise RuntimeError(f"local path does not exist: {ref}")
    dest = app_dir / slug
    if dest.exists():
        # Reuse ONLY a copy bound (by a state-dir marker) to THIS ref — never a stale/foreign/pre-seeded dir that happens to sit at the same path.
        if _stage_dir_bound(dest, ref):
            print(f"  [batch] reusing verified local copy {dest}", file=sys.stderr)
            return
        print(f"  [batch] unverified local copy at {dest} (stale, foreign, or "
              f"pre-seeded) — replacing", file=sys.stderr)
        _rmtree_rw(dest)
        if dest.exists():
            print(f"  [batch] could not remove {dest}; reusing as-is",
                  file=sys.stderr)
            return
    app_dir.mkdir(parents=True, exist_ok=True)
    print(f"  [batch] copytree {src} -> {dest}", file=sys.stderr)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".git"))
    _write_stage_marker(dest, ref, "local")


def _app_module_name(app_id: str, repos: list[dict]) -> str:
    profile, _ = _load_app_profile(app_id)
    if profile and profile.name:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in profile.name)
        return safe or f"app_{app_id}"
    if len(repos) == 1:
        return _module_name_from(repos[0]["repo_name"])
    return f"app_{app_id}"


def _run_batch_grouped(entries: list[dict], workspace: Path,
                       git_token: str | None, args, cfg,
                       list_file: Path) -> int:
    from collections import defaultdict
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        groups[e["application_id"]].append(e)

    results: list[dict] = []
    batch_t0 = time.time()

    for n, (app_id, repos) in enumerate(sorted(groups.items()), 1):
        # app_id is operator/CMDB-supplied; sanitise before using as a path component so "../x" / "." cannot escape the workspace root.
        safe_app = "".join(c if c.isalnum() or c in "._-" else "_"
                           for c in str(app_id)).strip(".") or "app"
        app_dir = workspace / safe_app
        slugs = _assign_slugs(repos)   # unique per repo — no silent slug collision
        print(f"\n{'='*72}\n[batch {n}/{len(groups)}] app_id={app_id}  "
              f"({len(repos)} repos → {app_dir})\n  repos: {', '.join(slugs)}\n"
              f"{'='*72}", file=sys.stderr)
        TOKENS.reset()
        STAGES.reset()
        COUNTERS.reset()
        _reset_quality_counters()
        _reset_warn_once()  # re-arm one-shot diagnostics for this app-group
        cli.reset_abort()  # don't let a prior app's guardrail abort poison this one
        t0 = time.time()
        try:
            staged: list[str] = []
            for r, slug in zip(repos, slugs):
                try:
                    _stage_repo(r["ref"], app_dir, slug, git_token)
                    staged.append(slug)
                except Exception as ce:
                    print(f"  [batch] WARN skipping repo '{slug}': {ce}",
                          file=sys.stderr)
                    _errlog.log("batch.clone", slug, ce, app_id=app_id)
            if not staged:
                raise RuntimeError(
                    f"all {len(repos)} repo(s) failed to stage for app {app_id}")
            if len(staged) < len(repos):
                print(f"  [batch] staged {len(staged)}/{len(repos)} repos for "
                      f"app {app_id}; continuing scan", file=sys.stderr)
            module = _app_module_name(app_id, repos)
            if args.stop_after == "clone":
                results.append({
                    "ref": f"{len(repos)} repos", "module": module,
                    "app_id": app_id, "status": "OK", "findings": 0,
                    "report": str(app_dir), "elapsed": time.time() - t0,
                    "error": "",
                })
                continue
            outcome = scan_repo(app_dir, module, app_id, args, cfg)
            results.append({
                "ref": f"{len(repos)} repos", "module": module, "app_id": app_id,
                **_outcome_status(outcome),
                "elapsed": time.time() - t0,
            })
        except KeyboardInterrupt:
            results.append({"ref": f"{len(repos)} repos", "module": str(app_id),
                            "app_id": app_id, "status": "ABORTED", "findings": 0,
                            "report": "", "elapsed": time.time() - t0,
                            "error": "interrupted by user"})
            raise
        except (AuthenticationError, ProxyError):
            # VVAH-E001 / VVAH-E002 are environment-wide — every remaining app would fail identically.
            raise
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            _errlog.log("batch", f"app_{app_id}", e, app_id=app_id)
            results.append({"ref": f"{len(repos)} repos", "module": str(app_id),
                            "app_id": app_id, "status": "FAILED", "findings": 0,
                            "report": "", "elapsed": time.time() - t0,
                            "error": str(e)[:500]})
        finally:
            if not args.keep_clones and args.stop_after != "clone":
                _purge_clone(app_dir, _preserve_set(cfg))

    summary_path = workspace / "batch_summary.md"
    workspace.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(_render_batch_summary(results, list_file,
                                                  time.time() - batch_t0),
                            encoding="utf-8")
    print(f"\n[batch] summary written to {summary_path}", file=sys.stderr)

    unremediated, failed = _split_non_ok(results)
    if not (unremediated or failed):
        print(f"\n[batch] all {len(results)} apps OK", file=sys.stderr)
        return 0
    if unremediated:
        print(f"\n[batch] {len(unremediated)}/{len(results)} apps validated nothing "
              f"they remediated:", file=sys.stderr)
        for r in unremediated:
            print(f"  - app_id={r['app_id']}", file=sys.stderr)
    if failed:
        print(f"\n[batch] {len(failed)}/{len(results)} apps FAILED:", file=sys.stderr)
        for r in failed:
            print(f"  - app_id={r['app_id']}: {_scrub_url_secrets(r['error'])}",
                  file=sys.stderr)
        return 1
    return EXIT_NOT_REMEDIATED


def _render_batch_summary(results: list[dict], list_file: Path, elapsed: float) -> str:
    ok = sum(1 for r in results if r["status"] == "OK")
    # The same three-way split the invocation returns use. Without it this report calls an
    # unremediated repo failed while the exit code beside it says otherwise.
    unremediated, failed = _split_non_ok(results)
    counts = f"{ok} OK"
    if unremediated:
        counts += f", {len(unremediated)} not remediated"
    counts += f", {len(failed)} failed"
    out = [
        "# Agentic SAST batch summary",
        "",
        f"- Input list: `{list_file}`",
        f"- Repos: {len(results)} ({counts})",
        f"- Total elapsed: {elapsed:.0f}s",
        "",
        "| # | App ID | Repo | Status | Findings | Elapsed (s) | Report | Source |",
        "|--:|---|---|---|--:|--:|---|---|",
    ]
    for i, r in enumerate(results, 1):
        # Every operator-supplied field is credential-scrubbed then Markdown-neutralised via _md_cell, so a crafted value can't forge cells or append fake Markdown.
        # Inside a code span a backslash escape is inert, so an embedded backtick is folded to U+02CB — nothing else can stop it closing the span early.
        rep = (f"`{_md_cell(r['report']).replace(chr(96), chr(0x2CB))}`"
               if r["report"] else "")
        src = _md_cell(_scrub_url_secrets(r["ref"]))
        out.append(f"| {i} | {_md_cell(r['app_id'])} | {_md_cell(r['module'])} | "
                   f"{_md_cell(r['status'])} | {r['findings']} | {r['elapsed']:.0f} | "
                   f"{rep} | {src} |")
    # Its own section, not an entry under Failures and not only a status cell: the table
    # carries no error column, so dropping these rows from the fold below would leave the
    # report with no prose at all saying what happened.
    if unremediated:
        out.extend(["", "## Not remediated", "",
                    "These scans ran to completion. Nothing they remediated validated as "
                    "fixed.", ""])
        for r in unremediated:
            out.extend([f"### {_md_cell(r['module'])} (app {_md_cell(r['app_id'])})",
                        f"- Source: `"
                        f"{_md_cell(_scrub_url_secrets(r['ref'])).replace(chr(96), chr(0x2CB))}`",
                        ""])
    if failed:
        out.extend(["", "## Failures", ""])
        for r in failed:
            out.extend([f"### {_md_cell(r['module'])} (app {_md_cell(r['app_id'])})",
                        f"- Source: `"
                        f"{_md_cell(_scrub_url_secrets(r['ref'])).replace(chr(96), chr(0x2CB))}`",
                        f"- Error: {_md_cell(_scrub_url_secrets(r['error']))}", ""])
    return "\n".join(out) + "\n"
