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

"""Filesystem permissioning, backend selection, and skill-source resolution."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from deepagents.backends import FilesystemBackend
from deepagents.backends.protocol import (
    DeleteResult,
    EditResult,
    FileInfo,
    GlobResult,
    GrepResult,
    LsResult,
    ReadResult,
    WriteResult,
)
from deepagents.middleware.filesystem import FilesystemPermission

# The scan-scope registry (set_scope / _scope_for / _excluded_rel / _SCOPE_ERROR)
# is shared with the sdk/openai tool surface so ONE s1_preprocess registration
# confines every backend to the SAME exclusion-filtered inventory, and the
# refusal message stays byte-identical across backends. Reusing it follows the
# model_building.py precedent of importing backends.llm helpers to keep
# semantics identical rather than re-deriving them here.
from vvaharness.backends.harness.deepagents.models import (
    GIT_INTERNALS_DENY,
    READ_ONLY_PERMISSIONS,
)
from vvaharness.backends.harness.models import OneShotOptions, StreamingOptions
from vvaharness.backends.llm import tools as _scan_scope


def _filesystem_permissions(
    options: OneShotOptions | StreamingOptions,
) -> list[FilesystemPermission]:
    """Deny all writes for a read-only session; permit them when the caller opts in.

    Even opted-in (fix mode), ``.git`` internals stay write-denied — see
    ``GIT_INTERNALS_DENY``.
    """
    if options.allow_writes:
        # DeepAgents' filesystem middleware is rooted at cwd; refuse a broader writable_paths scope.
        root = options.cwd.resolve()
        for raw in options.writable_paths:
            candidate = Path(raw).resolve()
            if candidate != root and root not in candidate.parents:
                raise ValueError(f"writable path escapes harness cwd: {raw}")
        return GIT_INTERNALS_DENY
    return READ_ONLY_PERMISSIONS


@lru_cache(maxsize=8)
def _in_scope_dirs(scope: frozenset[str]) -> frozenset[str]:
    """Every ancestor directory (repo-relative posix) of an in-scope file.

    Lets ``ls`` keep listing directories that still contain in-scope files while
    hiding ones the inventory never reaches (e.g. an operator-excluded answer
    key, whose very NAME must not leak). Cached per scope frozenset: one scan
    registers one inventory per root, so this computes once, not per listing.
    """
    dirs: set[str] = set()
    for rel in scope:
        parts = rel.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:depth]))
    return frozenset(dirs)


#: Refusal a detection session's backend returns for any write-class operation.
_WRITE_REFUSED = "write operations are disabled on detection sessions: {path}"


class _NoWriteBackend(FilesystemBackend):
    """A ``FilesystemBackend`` whose write surface fails closed, touching no disk.

    Detection graphs must never write into the scanned repository, and the
    backend is the single choke point every write must pass — the same seam
    ``_ScopedReadBackend`` already uses for read scoping. ``READ_ONLY_PERMISSIONS``
    and the ``PermitTools`` gate close the MODEL-driven write paths, but
    upstream MIDDLEWARE writes bypass both: deepagents 0.7.x
    ``FilesystemMiddleware`` persists any >200k-char trailing HumanMessage to
    ``conversation_history/<uuid>.md`` and any oversized ToolMessage to
    ``large_tool_results/<id>``, and ``SummarizationMiddleware`` offloads
    history the same way — all straight through ``backend.write``, into the
    scanned repo.

    Failing the write neutralizes all three via upstream's own documented
    failure handling, which is what makes this safe on the public surface:

    * human-message eviction: ``_apply_eviction_and_truncate`` tags/truncates
      only on a SUCCESSFUL write, so the model receives the full prompt —
      on the tool-less one-shot path an evicted prompt is otherwise replaced
      by a read_file stub the model cannot follow (parse failure or silent
      empty findings);
    * tool-result eviction: ``_offload_tool_message_content`` returns None on
      write failure and the caller keeps the original ToolMessage;
    * summarization offload: a None return is documented non-fatal; the
      session proceeds.

    Overriding the sync methods covers the ``a*`` wrappers too (they delegate
    via ``asyncio.to_thread``). Construction sites that must keep writes
    (frozen S10 fix mode / S11) never receive this class — see
    ``_session_backend``.
    """

    def write(self, file_path: str, content: str) -> WriteResult:  # noqa: ARG002
        return WriteResult(error=_WRITE_REFUSED.format(path=file_path))

    def edit(
        self,
        file_path: str,
        old_string: str,  # noqa: ARG002
        new_string: str,  # noqa: ARG002
        replace_all: bool = False,  # noqa: ARG002 — upstream signature
    ) -> EditResult:
        return EditResult(error=_WRITE_REFUSED.format(path=file_path))

    def delete(self, file_path: str) -> DeleteResult:
        return DeleteResult(error=_WRITE_REFUSED.format(path=file_path))


class _ScopedReadBackend(_NoWriteBackend):
    """A ``FilesystemBackend`` whose READ surface is confined to the scan scope.

    The root jail (``virtual_mode=True``) is necessary but not sufficient: it
    still lets a model read ``.git/config``, the pipeline's own
    ``security-scan/`` output, or directories the operator excluded from the
    scan precisely to keep them away from the model. This subclass additionally
    confines ``read``/``grep``/``glob``/``ls`` to the exclusion-filtered file
    inventory ``s1_preprocess.run()`` registers (``backends.llm.tools.set_scope``)
    before dispatching any agentic call — the same registry, exclusion
    semantics and refusal message as the sdk/openai tool surface, so the two
    backends cannot drift. Until/unless a scope is registered (e.g. a stage
    that runs before s1), the confinement-critical directory names
    (``.git``/``.hg``/``.svn``/``checkpoints``/``security-scan``) are refused
    unconditionally, exactly as there.

    Writes are closed by the ``_NoWriteBackend`` base: ``READ_ONLY_PERMISSIONS``
    and the ``PermitTools`` executor gate refuse MODEL-driven writes, but
    upstream middleware (eviction/summarization offload) writes through the
    backend directly, below both layers.

    Enforced at the backend choke point so every dispatch path — sync and the
    protocol's ``a*`` wrappers (which delegate to these sync methods via
    ``asyncio.to_thread``), parent and sub-agent alike — passes through it.
    """

    def _scope(self) -> frozenset[str] | None:
        """The registered inventory for this root, or None when s1 has not run."""
        return _scan_scope._scope_for(self.cwd)

    def _rel_of(self, file_path: str) -> str | None:
        """Repo-relative posix path for *file_path*, or None when it cannot resolve.

        Resolution failures (traversal, escape, symlink loop) return None so the
        stock method shapes the error exactly as an unscoped backend would —
        the scope check must never REPLACE the jail's own refusals.
        """
        try:
            return self._resolve_path(file_path).relative_to(self.cwd).as_posix()
        except (ValueError, OSError, RuntimeError):
            return None

    def read(self, file_path: str, offset: int = 0, limit: int = 2000) -> ReadResult:
        rel = self._rel_of(file_path)
        # Scope check BEFORE super()'s existence check, so an excluded path is
        # refused without acting as an existence oracle for it.
        if rel is not None and rel != "." and _scan_scope._excluded_rel(rel, self._scope()):
            return ReadResult(error=_scan_scope._SCOPE_ERROR.format(path=file_path))
        return super().read(file_path, offset, limit)

    def grep(
        self,
        pattern: str,
        path: str | None = None,
        glob: str | None = None,
        *,
        max_count: int | None = None,
        context_lines: int = 0,
    ) -> GrepResult:
        scope = self._scope()
        if path is not None:
            # Refuse an explicitly named excluded FILE with the scope message
            # (mirrors backends.llm.tools._grep); directory targets fall through
            # to the match filter below — a directory is never in the file
            # inventory, so testing it directly would refuse every legal subtree.
            rel = self._rel_of(path)
            if (
                rel is not None
                and rel != "."
                and (self.cwd / rel).is_file()
                and _scan_scope._excluded_rel(rel, scope)
            ):
                return GrepResult(
                    error=_scan_scope._SCOPE_ERROR.format(path=path), matches=[]
                )
        result = super().grep(
            pattern, path, glob, max_count=max_count, context_lines=context_lines
        )
        if result.matches:
            # Match paths are virtual ("/rel/posix") on this always-virtual backend.
            result.matches = [
                m
                for m in result.matches
                if not _scan_scope._excluded_rel(m["path"].lstrip("/"), scope)
            ]
        return result

    def glob(self, pattern: str, path: str | None = None) -> GlobResult:
        result = super().glob(pattern, path)
        if result.matches:
            scope = self._scope()
            result.matches = [
                m
                for m in result.matches
                if not _scan_scope._excluded_rel(m["path"].lstrip("/"), scope)
            ]
        return result

    def _entry_excluded(self, entry: FileInfo, scope: frozenset[str] | None) -> bool:
        rel = entry["path"].strip("/")
        if not entry.get("is_dir"):
            return bool(rel) and _scan_scope._excluded_rel(rel, scope)
        if any(part.lower() in _scan_scope._ALWAYS_EXCLUDED_DIRS for part in rel.split("/")):
            return True
        return bool(rel) and scope is not None and rel not in _in_scope_dirs(scope)

    def ls(self, path: str) -> LsResult:
        result = super().ls(path)
        if result.entries:
            scope = self._scope()
            result.entries = [
                e for e in result.entries if not self._entry_excluded(e, scope)
            ]
        return result


def _session_backend(
    options: OneShotOptions | StreamingOptions,
) -> FilesystemBackend | None:
    """Use a real, repo-confined filesystem; read-only sessions still need native reads."""
    # Always disk-backed: native read_file/grep/glob are the only read path; StateBackend is empty.
    _filesystem_permissions(options)
    # Inventory confinement is OPT-IN PER CONSTRUCTION SITE, keyed off the SAME
    # ``StreamingOptions.permitted_tool_calls`` field that opts a site into the
    # executor-seam gate — never computed independently, the exact discipline
    # ``_extra_excluded_tools`` (options/streaming.py) applies, so the gated and
    # the scoped surface cannot drift. Only the detection ``agentic()``
    # construction site (``backends/llm/deepagents.py``) passes a set; the
    # frozen S10 remediation and S11 validation option builders never set it
    # (models.py pins that contract), and OneShotOptions does not carry the
    # field at all. This mirrors the ``tls_carriers_for`` precedent
    # (options/model_building.py): the seam opts in; a path that does not takes
    # exactly its historical shape.
    if getattr(options, "permitted_tool_calls", None) is not None:
        return _ScopedReadBackend(root_dir=options.cwd, virtual_mode=True)
    # Every one-shot construction is a detection parser (S10/S11 reach the
    # harness only through run_streaming), so it gets the fail-closed write
    # surface: on the tool-less single turn an upstream eviction is otherwise
    # unrecoverable — the model is told to read_file a stub it has no tool for.
    if isinstance(options, OneShotOptions):
        return _NoWriteBackend(root_dir=options.cwd, virtual_mode=True)
    # Frozen S10/S11 streaming: stock backend, byte-identical by construction.
    return FilesystemBackend(root_dir=options.cwd, virtual_mode=True)


def _skill_sources(skill_root: Path | None, cwd: Path) -> list[str]:
    """Return *skill_root* as a virtual-path skill source, re-rooted under the session cwd."""
    if skill_root is None or not skill_root.is_dir():
        return []
    root, base = skill_root.resolve(), cwd.resolve()
    if not root.is_relative_to(base):
        msg = f"skill_root {root} must live under the session cwd {base}"
        raise ValueError(msg)
    relative = root.relative_to(base).as_posix()
    return [f"/{relative}" if relative != "." else "/"]
