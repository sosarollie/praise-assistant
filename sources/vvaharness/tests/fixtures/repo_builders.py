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

"""Generators for the two on-disk fixtures that must NOT be committed as
real files: ``repo_deep`` (too many files to check in) and
``repo_symlink_escape`` (a symlink pointing outside its own checkout cannot
be committed to git reliably across platforms/clone methods). Both are built
fresh under ``tmp_path`` by the conftest fixtures of the same name.
"""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

# Matches the default `max_graph_files` cap (`_STEP_DEFAULTS` step2 block,
# `~config/__init__.py:123`) on how many files feed the threat-model stage's
# AST frontier. Any count above this
# exercises the reduced-view-vs-full-list distinction below; the exact
# number is arbitrary, so it is not re-imported from config here —
# duplicating the value keeps this fixture from silently changing shape if
# that default is ever retuned (which we would want called out, not masked).
MAX_GRAPH_FILES_DEFAULT = 220

N_SERVICES = 12          # >= 12 top-level dirs
FILES_PER_SERVICE = 20   # 1 config + 19 source files
TOTAL_FILES = N_SERVICES * FILES_PER_SERVICE  # 240, > 220


def build_repo_deep(root: Path) -> Path:
    """A monorepo shape: N_SERVICES top-level dirs, each with one config file
    and (FILES_PER_SERVICE - 1) source files — TOTAL_FILES (240) > 220.

    The threat-model stage's evidence gathering
    (``s2_threatmodel._gather_evidence``) reads TWO views of the repository:
    graph-derived blocks (modules, entry points, function sites, call edges)
    come from the AST frontier — ``ctx.ast_context_view(max_files=...)``,
    capped at 220 by default — while the repo-"shape" blocks (top-level
    directory names, representative config files, language mix, doc extras,
    API artefacts; assembled at `~s2_threatmodel.py:791-830`) read the FULL
    file list. The shape blocks used to read the reduced view too, and this
    fixture is the shape that regression costs: with no entry points/sinks
    to seed the frontier, its fallback padding walks the file list in list
    order, so if a consuming test builds ``all_files`` by sorting a real
    directory walk (each service's config file sorts before its 19 source
    files because "config" < "mod" lexically), the first 220 of 240 sorted
    files cover exactly ``service_00``..``service_10`` and drop
    ``service_11`` — including its config file — entirely from a summary
    computed off that view, even though it is really there. On a repository
    with hundreds of services that was the mechanism behind a summary
    reporting only one top-level directory and no representative config
    files at all, despite dozens of each existing; shape blocks fed from the
    full list must instead see all 12 directories and all 12 config files.

    Every service directory has EXACTLY ONE config-shaped file
    (``config.yaml``) so a per-directory representative-config selector has
    exactly one candidate to find per directory — the dropped 12th
    directory's file is exactly what the reduced-view truncation above
    costs.
    """
    root.mkdir(parents=True, exist_ok=True)
    for s in range(N_SERVICES):
        svc = root / f"service_{s:02d}"
        svc.mkdir(parents=True, exist_ok=True)
        (svc / "config.yaml").write_text(f"service: service_{s:02d}\n", encoding="utf-8")
        for f in range(FILES_PER_SERVICE - 1):
            (svc / f"mod_{f:02d}.py").write_text(
                f"def handler_{s:02d}_{f:02d}():\n    return {s * FILES_PER_SERVICE + f}\n",
                encoding="utf-8",
            )
    return root


def all_files_of(root: Path) -> list[str]:
    """Deterministic, sorted repo-relative file list for a built fixture —
    the same shape a test would hand to ``ContextPackage(all_files=...)``.
    """
    return sorted(
        str(p.relative_to(root)).replace(os.sep, "/")
        for p in root.rglob("*")
        if p.is_file()
    )


def build_repo_symlink_escape(tmp_path: Path) -> SimpleNamespace:
    """A repo with one symlink that escapes the checkout and one that does
    not. The threat-model stage's document reads still locate candidates by
    hardcoded name straight off disk, outside the repository's own file
    inventory (``p = root / name; if p.is_file()`` over ``_DOC_CANDIDATES``,
    `~s2_threatmodel.py:716-719`; manifests moved to the bounded
    ``_find_manifests`` walk), and ``Path.is_file()`` follows symlinks — so
    a symlinked ``ARCHITECTURE.md`` used to pull an arbitrary file from
    outside the repository into the prompt, the model provider, and the
    rendered system context. Every such read now routes through the
    containment chokepoint ``_read_capped`` -> ``_contained``
    (`~s2_threatmodel.py:288` / `:250`), which ``resolve(strict=True)``-s
    the candidate and requires ``is_relative_to(root)`` — defeating ``..``
    traversal, prefix-sibling roots, and the symlink escape this fixture
    builds, while still following symlinks that stay inside the repo. The
    fixture pins both halves of that fix: escape blocked, in-repo link
    still readable.

    Built under ``tmp_path`` rather than committed: a symlink whose target
    resolves OUTSIDE its own repo cannot be committed to git in a way that
    survives every checkout method (git itself stores the link target as a
    literal string, but a relative ``../../../../etc/passwd``-style escape
    depends on exactly where the clone lands, and some CI checkout actions
    strip or refuse to materialize symlinks that resolve outside the
    workspace at all) — so the escape must be constructed fresh, at a known
    absolute location, every test run.

    Returns a namespace with:
      root              — the repo root (Path) — pass this as ``repo_root``.
      escape_link       — repo/"ARCHITECTURE.md", a symlink to OUTSIDE root.
      escape_target     — the out-of-repo file it points to (Path).
      escape_marker     — sentinel string written into escape_target; a
                          passing fix means this string never appears in
                          anything s2 sends to a provider.
      in_repo_link      — repo/"README.md", a symlink to a file INSIDE root.
      in_repo_target    — the in-repo file it points to (Path).
      in_repo_marker    — sentinel string written into in_repo_target; this
                          one MUST still be readable — the fix is "block the
                          escape", not "stop following symlinks at all".
    """
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    outside_dir = tmp_path / "outside_secrets"
    outside_dir.mkdir(parents=True, exist_ok=True)

    escape_marker = "HOST-SECRET-MARKER-outside-repo-do-not-leak"
    escape_target = outside_dir / "secret_host_file.txt"
    escape_target.write_text(escape_marker + "\n", encoding="utf-8")
    escape_link = root / "ARCHITECTURE.md"
    escape_link.symlink_to(escape_target)

    in_repo_marker = "in-repo-notes-content-marker"
    in_repo_target = root / "NOTES.md"
    in_repo_target.write_text(in_repo_marker + "\n", encoding="utf-8")
    in_repo_link = root / "README.md"
    in_repo_link.symlink_to(in_repo_target)

    return SimpleNamespace(
        root=root,
        escape_link=escape_link,
        escape_target=escape_target,
        escape_marker=escape_marker,
        in_repo_link=in_repo_link,
        in_repo_target=in_repo_target,
        in_repo_marker=in_repo_marker,
    )
