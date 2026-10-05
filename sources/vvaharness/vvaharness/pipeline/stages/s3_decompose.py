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

"""
Step 3 — the strategist LLM receives the ContextPackage (no raw code) and produces a
risk-ranked TaskManifest. A single prompt() call on whichever backend the role
configures (sdk in the shipped default; deepagents-capable); repeating it wastes tokens.
"""
from __future__ import annotations

import logging
import re
import sys
from collections import defaultdict
from pathlib import Path, PurePosixPath

log = logging.getLogger(__name__)

# Module import keeps the monkeypatch seam for tests.
from vvaharness.backends.llm import deepagents as _deepagents
from vvaharness.lang.hints import (
    EXT_TO_LANG,
    SECURITY_CONFIG_EXTS as _SECURITY_CONFIG_EXTS,
    SECURITY_CONFIG_NAMES as _SECURITY_CONFIG_NAMES,
    detect_languages,
    is_iac_file,
    is_source as _is_source,
)
from vvaharness.models import Chunk, ChunkSize, ContextPackage, TaskManifest
from vvaharness.pipeline.callgraph_consumer import (
    graph_view,
    qnodes_at,
    seed_paths_by_file,
    seed_reachable_files,
)
from vvaharness.pipeline.stages.s1_preprocess import q_file, q_join, q_name
from vvaharness.report.redact import redact
from vvaharness.util import errlog as _errlog
from vvaharness.util.counters import COUNTERS
from vvaharness.util.json_extract import extract_json

_SYSTEM_TMPL = """You are a vulnerability research strategist. You receive a structured
map of a codebase — NOT the source code itself — and produce a prioritized
hunting plan.

GROUNDING RULE (read first): the FILE INVENTORY block lists every file that
exists, each with an id like F001. Entry points have ids like E001 and sinks
like K001. You MUST reference files and entry points by id ONLY. Never write a
file path. Never invent an id. If the work you want to do needs a file that is
not in the inventory, say so in "rationale" — do not guess a path.

Your job:
1. Rank attack surfaces by risk. Unauth-reachable entry points + unsafe sinks
   in the same data flow path = highest priority.
2. Hunt for VARIANTS of known CVEs. If CVE-X is a heap overflow in a parser,
   look for sibling parsers with the same pattern.
3. Account for design controls. A bug behind strong auth ranks lower than the
   same bug pre-auth.
4. {threat_rule}
5. Chunk the work. Each chunk = a coherent set of files to deep-dive together.
   Use the CALL GRAPH section: when caller -> callee crosses files, put BOTH
   file ids in the same chunk so the entry point and its sink are reviewed
   together.
6. For chunks you expect to be large, name the entry-point ids to anchor a
   sliding window. Chunk size is computed by the caller — do not report it.

Respond with ONLY a JSON object, no prose:
{
  "rationale": "one paragraph explaining your ranking, plus any file you
                needed that was not in the inventory",
  "chunks": [
    {
      "id": "chunk-01",
      "risk_rank": 1,
      "file_ids": ["F014", "F015"],
      "focus_entry_point_ids": ["E007"],
      "hypothesis": "Specific reasoning about what to hunt and why",{threat_id_example}
      "related_cves": ["CVE-2024-1234"]
    }
  ]
}"""

# Rule 4 has two forms because s2 can legitimately produce no threat model — a
# parse failure there degrades the scan rather than aborting it. The MUST-cite
# form then contradicts the prompt itself: no THREAT MODEL section is rendered,
# and an observed run refused outright ("No THREAT MODEL section was provided…
# I cannot invent threat ids"), yielding a ValidationError and losing the entire
# LLM ranking pass. The chunk- kind it produces is the top true-positive
# contributor, so a total refusal is a real recall loss, not a cosmetic one.
_THREAT_RULE = """Tie every chunk to a THREAT. The THREAT MODEL section lists ranked threats
   T1..Tn. Each chunk MUST cite the threat_id it tests. Every threat should be
   covered by at least one chunk; if a threat has no plausible code surface,
   omit it — do NOT invent a chunk."""

_NO_THREAT_RULE = """No ranked threats are available for this run: any THREAT MODEL
   section carries background context only, and no threat ids exist. Omit
   "threat_id" from every chunk, or set it to null. Do NOT invent threat ids,
   and do NOT refuse to produce chunks over the missing threat list — rank by
   the entry points, sinks and call graph you were given."""

# The response EXAMPLE varies too, not just the rule. Models copy schema
# exemplars, so showing `"threat_id": "T3"` while telling the model no threat ids
# exist produced invented ids that the id-resolution pass then stripped one by
# one, printing a "unknown threat_id -> dropped" line per chunk and polluting the
# threat-coverage metric — noise on precisely the degraded path this is meant to
# keep clean. The no-threats form omits the key entirely.
_THREAT_ID_EXAMPLE = '\n      "threat_id": "T3",'

# Substituted with str.replace, not str.format: the template embeds a JSON
# example whose braces format() would try to interpret as fields.
# SYSTEM is preserved as the threat-model-present form — it is the normal path,
# and tests and any external reader treat this name as "the s3 system prompt".
SYSTEM = (_SYSTEM_TMPL.replace("{threat_rule}", _THREAT_RULE)
          .replace("{threat_id_example}", _THREAT_ID_EXAMPLE))
_SYSTEM_NO_THREATS = (_SYSTEM_TMPL.replace("{threat_rule}", _NO_THREAT_RULE)
                      .replace("{threat_id_example}", ""))

def _has_threats(ctx) -> bool:
    """True when s2 produced a threat model with at least one ranked threat.

    The prompt's threat rules are only satisfiable when the rendered THREAT MODEL
    block actually lists ids, which it does only if `threats` is non-empty.
    """
    tm = getattr(ctx, "threat_model", None)
    return bool(tm is not None and getattr(tm, "threats", None))


_TOKEN_RX = re.compile(r"[a-z0-9]+")


def _cap(step3, key: str, default: int) -> int:
    """A non-negative integer cap from config, or `default`.

    Every cap here used to be read as ``int(getattr(...) or default)``, which
    crashes the stage on a non-numeric value (``ValueError``) and on a YAML
    float infinity (``OverflowError``, and ``.inf`` is a valid scalar) — and,
    worse, passes a negative through to be used as a slice bound, silently
    dropping items from the end of a list instead of capping it.

    `0` keeps meaning "use the stated default" on this stage, which is the
    behaviour its shipped profiles already rely on. Note the threat-model stage
    deliberately differs: there `0` means "emit none of this block". The two
    idioms are documented side by side where the keys are registered.
    """
    v = getattr(step3, key, None)
    if v is None:
        return default
    try:
        n = int(v)
    except (TypeError, ValueError, OverflowError):
        return default
    return n if n > 0 else default


def run(ctx: ContextPackage, cfg) -> TaskManifest:
    log.info("s3/decompose: starting task decomposition - files=%d entry_points=%d sinks=%d modules=%d",
             len(ctx.all_files), len(ctx.entry_points), len(ctx.unsafe_sinks), len(ctx.modules))
    prompt_ctx = ctx.ast_context_view(
        max_files=_cap(cfg.step3, "max_prompt_files", 180),
        max_entry_points=_cap(cfg.step3, "max_prompt_entry_points", 60),
        max_sinks=_cap(cfg.step3, "max_prompt_sinks", 80),
        max_modules=_cap(cfg.step3, "max_prompt_modules", 24),
        max_edges=_cap(cfg.step3, "max_prompt_call_edges", 80),
        max_notes_chars=_cap(cfg.step3, "max_prompt_notes_chars", 2500),
    )
    user_prompt = prompt_ctx.to_decompose_prompt_block(
        max_assets=_cap(cfg.step3, "max_prompt_assets", 20),
        max_boundaries=_cap(cfg.step3, "max_prompt_boundaries", 30),
        max_threats=_cap(cfg.step3, "max_prompt_threats", 50),
        max_context_chars=_cap(cfg.step3, "max_prompt_threat_context_chars", 2500),
    )
    # Captured at the exact moment of rendering, not re-derived later, so
    # id resolution can assert it is running against the SAME object —
    # never a fresh `ast_context_view()` call, and never `ctx` itself.
    _rendered_from_id = id(prompt_ctx)
    fstats = prompt_ctx.ast_frontier_stats or {}
    print(
        "  [s3] ast frontier: "
        f"files {len(ctx.all_files)}->{len(prompt_ctx.all_files)}, "
        f"entry points {len(ctx.entry_points)}->{len(prompt_ctx.entry_points)}, "
        f"sinks {len(ctx.unsafe_sinks)}->{len(prompt_ctx.unsafe_sinks)}, "
        f"modules {len(ctx.modules)}->{len(prompt_ctx.modules)}, "
        f"call edges {sum(len(v) for v in ctx.call_graph.values())}"
        f"->{sum(len(v) for v in prompt_ctx.call_graph.values())}"
        + (f" (hot={fstats.get('hot', 0)} cold={fstats.get('cold', 0)} "
           f"dropped_by_cap={fstats.get('dropped_by_cap', 0)} "
           f"of {fstats.get('edges_total', 0)})" if fstats else ""),
        file=sys.stderr,
    )
    log.debug("s3/decompose: prompt frontier - files=%d->%d eps=%d->%d sinks=%d->%d modules=%d->%d edges=%d->%d",
              len(ctx.all_files), len(prompt_ctx.all_files),
              len(ctx.entry_points), len(prompt_ctx.entry_points),
              len(ctx.unsafe_sinks), len(prompt_ctx.unsafe_sinks),
              len(ctx.modules), len(prompt_ctx.modules),
              sum(len(v) for v in ctx.call_graph.values()),
              sum(len(v) for v in prompt_ctx.call_graph.values()))

    try:
        # Routed through the deepagents dispatch seam: `via: deepagents`
        # reaches the harness one-shot rooted at the scanned repo, anything
        # else reaches `registry.prompt` with these exact kwargs, as before.
        raw = _deepagents.dispatch_prompt(
            user_prompt,
            model=cfg.models.decompose,
            cfg=cfg,
            cwd=ctx.repo_root,
            # Test the THREATS, not the object: a pydantic model is always
            # truthy, and s2 legitimately returns a ThreatModel with threats=[]
            # (it errlogs "zero threats" and the orchestrator still attaches it).
            # to_compact_prompt_block then renders a "THREAT MODEL:" header with
            # no ranked list, so keying on the object alone still hands the model
            # the MUST-cite-threat_id prompt with no ids to cite — the exact
            # self-contradiction this branch exists to avoid.
            system_prompt=(SYSTEM if _has_threats(ctx)
                           else _SYSTEM_NO_THREATS),
            max_tokens=getattr(cfg.step3, "max_tokens", None),
            timeout=getattr(cfg.step3, "timeout", 1800),
            tag="s3 decompose",
        )
    except Exception as e:  # provider timeout/network/auth
        print(f"  [s3] WARN: strategist call failed ({e}); proceeding "
              "with deterministic coverage only (no LLM ranking).",
              file=sys.stderr)
        _errlog.log("s3", "decompose", e, phase="llm_call_failed")
        raw = "{}"

    # degrade — don't abort the whole scan — on malformed/empty/wrong-shape
    # strategist output, mirroring how s4/s8 fall back instead of crashing.
    # extract_json raises ValueError on empty/non-JSON; TaskManifest raises
    # ValidationError on a valid-but-wrong-shape response. Degradation is
    # per CHUNK, not per manifest: a whole-tree ValidationError first goes
    # through _salvage_chunks so one off-schema chunk drops that chunk, not
    # the entire LLM ranking. Only when nothing is salvageable (no usable
    # "chunks" list — the marker of a genuinely malformed reply) do we
    # recover with an empty manifest: the taint / catch-all / specialist
    # passes below still sweep every ground-truth file, so file coverage is
    # preserved (only the LLM's risk RANKING is lost on that path).
    # All three are bound before the try: `extract_json` can raise before the
    # shape inspection runs, and the recovery path below still falls through
    # to normalisation.
    shapes: list[str] = []
    raw_paths: list[list[str]] = []
    data: object = None
    try:
        data = extract_json(raw)
        shapes, raw_paths = _prepare_chunk_shapes(data, prompt_ctx)
        manifest = TaskManifest.model_validate(data)
    except Exception as e:  # provider/model output is heterogeneous
        # redact() BEFORE the [:500] cut, never after: slicing first can bisect
        # a credential quoted in the strategist reply, and the surviving prefix
        # matches no redaction pattern — it would reach stderr and the errlog
        # raw_head unmasked (same trap documented at s7's parse fallback).
        head = redact(raw or "")[:500].replace("\n", "\\n")
        kept, kept_idx, total = _salvage_chunks(data)
        if kept:
            # shapes/raw_paths are aligned 1:1 with data["chunks"] (see
            # _prepare_chunk_shapes); a dropped chunk takes its entries
            # along, or the lists are cleared if _prepare_chunk_shapes was
            # what raised and the alignment never existed.
            if len(shapes) == total:
                shapes = [shapes[i] for i in kept_idx]
                raw_paths = [raw_paths[i] for i in kept_idx]
            else:
                shapes, raw_paths = [], []
            dropped = total - len(kept)
            print(f"  [s3] WARN: {dropped}/{total} strategist chunks failed "
                  f"validation and were dropped; {len(kept)} kept ({e}). "
                  f"raw[:500]={head!r}", file=sys.stderr)
            _errlog.log("s3", "decompose", e, phase="chunks_partially_dropped",
                        chunks_kept=len(kept), chunks_dropped=dropped,
                        raw_head=head)
            rationale = data.get("rationale") if isinstance(data, dict) else ""
            manifest = TaskManifest(
                chunks=kept,
                rationale=rationale if isinstance(rationale, str) else "")
        else:
            print(f"  [s3] WARN: strategist response not usable ({e}); "
                  f"proceeding with deterministic coverage only (no LLM ranking). "
                  f"raw[:500]={head!r}", file=sys.stderr)
            _errlog.log("s3", "decompose", e, phase="response_unusable",
                        raw_head=head)
            manifest = TaskManifest(chunks=[], rationale=(
                f"s3 strategist output unusable ({e}); risk ranking unavailable. "
                f"All files covered via deterministic taint/catch-all/specialist "
                f"passes."))

    # Normalize model-emitted paths against the ground-truth list, drop
    # hallucinated paths, then sweep any uncovered files into catch-all chunks.
    _normalize_chunk_files(manifest, ctx, prompt_ctx, shapes, raw_paths,
                          rendered_from_id=_rendered_from_id)
    _drop_empty_chunks(manifest)
    cb = _char_budget(cfg)
    if cb is not None:
        print(f"    [s3] pack_by=tokens  budget="
              f"{getattr(cfg.step3, 'chunk_token_budget', 180000)}tok "
              f"− overhead={getattr(cfg.step3, 'chunk_overhead_tokens', 80000)}tok "
              f"→ {cb} chars/chunk  (legacy *_chunk_loc caps ignored)",
              file=sys.stderr)
    else:
        print("    [s3] pack_by=loc  (legacy *_chunk_loc caps active)",
              file=sys.stderr)
    n_taint = _add_taint_chunks(manifest, ctx, cfg)
    # The splitter (below) must run BEFORE any packer — risk chunks split
    # against `risk_chunk_loc`, but catch-all packs to its own
    # `catchall_max_files` (LARGER than `max_files_per_chunk` in every shipped
    # profile: 50 vs 30, 100 vs 80, 60 vs 40) and specialists to
    # `specialist_chunk_loc`. If the splitter ran after them, it would
    # re-split every catch-all / specialist bucket and re-pack against
    # `risk_chunk_loc` (10000) instead of the pass's own tighter budget —
    # discarding that budget and ADDING s4 calls on every profile.
    _split_oversize_risk_chunks(manifest, ctx, cfg)

    # ── Producer order ─────────────────────────────────────────────────────
    # With `catchall_deduct_lens_coverage: true`, catch-all runs LAST, after
    # specialists and threat-fallback. Its `covered` set (see
    # `_add_catchall_chunks`) only picks up risk/taint/threat-fallback claims —
    # a specialist's claim on a file is scoped guidance, not a generic review,
    # so it does NOT suppress catch-all's review of that same file. Running
    # last still saves cost: any file a risk/taint/threat-fallback chunk
    # already claimed is skipped, and the specialist passes above have
    # already primed the provider-side prompt cache for the same files.
    # Default (false) preserves legacy order: catch-all runs FIRST, over
    # every file no risk/taint chunk claimed, before specialists exist.
    deduct_lens_coverage = bool(getattr(
        cfg.step3, "catchall_deduct_lens_coverage", False))
    if deduct_lens_coverage:
        n_spec = _add_specialist_chunks(manifest, ctx, cfg)
        n_fallback = _add_threat_surface_fallback_chunks(manifest, ctx, cfg)
        n_catchall = _add_catchall_chunks(manifest, ctx, cfg)
    else:
        n_catchall = _add_catchall_chunks(manifest, ctx, cfg)
        # ── Specialist passes (repo-wide; lenses defined in _lang_hints.SPECIALIST_HINTS) ──
        n_spec = _add_specialist_chunks(manifest, ctx, cfg)
        n_fallback = _add_threat_surface_fallback_chunks(manifest, ctx, cfg)

    # Runs LAST, after every chunk producer (risk, taint, catch-all,
    # specialist, threat-fallback) has had its say, so no future producer can
    # silently ship an untagged chunk the way threat-fallback chunks used to.
    repo_root = Path(ctx.repo_root)
    for c in manifest.chunks:
        c.languages = detect_languages(c.files, repo_root=repo_root)

    _report_threat_coverage(manifest, ctx)
    _report_chunk_loc(manifest, ctx, cfg)

    tracker = getattr(cfg, "_scan_progress", None)
    if tracker is not None:
        for chunk in manifest.chunks:
            tracker.queued(chunk)

    print(
        f"  [s3] done: {len(manifest.chunks)} chunks "
        f"({n_taint} taint, {n_catchall} catch-all, {n_spec} specialist, "
        f"{n_fallback} threat-fallback), "
        f"top risk = {manifest.sorted_chunks()[0].id if manifest.chunks else 'none'}",
        file=sys.stderr,
    )
    log.info(
        "s3/decompose: decomposition complete - chunks=%d (taint=%d catchall=%d specialist=%d threat_fallback=%d)",
        len(manifest.chunks), n_taint, n_catchall, n_spec, n_fallback,
    )
    return manifest


# Coverage helpers

def _prepare_chunk_shapes(
        data: object,
        prompt_ctx: ContextPackage) -> tuple[list[str], list[list[str]]]:
    """Inspect the RAW parsed JSON (before Pydantic validation) to learn which
    input shape each chunk actually used, and resolve any id-shaped
    focus-entry-point references in place.

    ``Chunk.files`` has a `file_ids` alias (`populate_by_name=True`), so
    ``Chunk.model_validate({"file_ids": [...]})`` and
    ``Chunk.model_validate({"files": [...]})`` land in the identical field
    with an identical ``model_fields_set`` — after construction there is no
    way to tell which shape the model emitted. That distinction has to be
    read off the dict returned by ``extract_json``, before
    ``TaskManifest.model_validate`` erases it. The returned list is aligned
    1:1 with ``data["chunks"]`` (and, once validation succeeds without
    raising, with ``manifest.chunks``; when a raw item fails to build a
    ``Chunk`` the caller salvages per chunk via :func:`_salvage_chunks` and
    re-filters this function's result by the kept indices to preserve the
    alignment).

    ``Chunk`` has no alias for ``focus_entry_points`` (unlike ``files``), so
    an id-shaped ``focus_entry_point_ids`` value would otherwise be silently
    dropped by Pydantic's default "ignore unknown keys" behaviour — there is
    no post-validation recovery path for it the way there is for files. It is
    resolved here, in the raw dict, writing real function names into
    ``focus_entry_points`` before validation ever runs.

    Returns ``(shapes, raw_paths)``, both aligned 1:1 with ``data["chunks"]``.
    ``raw_paths`` carries the raw ``files`` value only for a chunk that sent
    BOTH keys, because Pydantic's alias makes ``file_ids`` win and the ``files``
    payload would otherwise be unrecoverable — a model that hedged by sending
    an empty ``file_ids`` alongside real paths would lose the chunk entirely.
    """
    shapes: list[str] = []
    raw_paths: list[list[str]] = []
    chunks = data.get("chunks") if isinstance(data, dict) else None
    if not isinstance(chunks, list):
        return shapes, raw_paths
    ids_seen = paths_seen = False
    eps_inv: dict[str, dict] | None = None
    for item in chunks:
        if not isinstance(item, dict):
            shapes.append("")
            raw_paths.append([])
            continue
        has_ids = isinstance(item.get("file_ids"), list)
        has_paths = isinstance(item.get("files"), list)
        if has_ids:
            ids_seen = True
        if has_paths:
            paths_seen = True
        shapes.append("mixed" if has_ids and has_paths
                      else "ids" if has_ids
                      else "paths" if has_paths
                      else "")
        raw_paths.append([p for p in item.get("files", []) if isinstance(p, str)]
                         if has_ids and has_paths else [])

        fep_ids = item.get("focus_entry_point_ids")
        if isinstance(fep_ids, list) and fep_ids:
            if eps_inv is None:
                eps_inv = prompt_ctx.id_inventory()["entry_points"]
            resolved = [eps_inv[eid]["function"] for eid in fep_ids
                       if isinstance(eid, str) and eid in eps_inv
                       and eps_inv[eid].get("function")]
            if resolved:
                existing = item.get("focus_entry_points")
                existing = existing if isinstance(existing, list) else []
                item["focus_entry_points"] = list(dict.fromkeys(existing + resolved))

    overall = ("mixed" if ids_seen and paths_seen
              else "ids" if ids_seen
              else "paths" if paths_seen
              else "")
    COUNTERS.note("s3_output_shape", overall)
    return shapes, raw_paths


def _salvage_chunks(data: object) -> tuple[list[Chunk], list[int], int]:
    """Per-chunk salvage for a strategist reply that failed whole-tree
    validation.

    ``TaskManifest.model_validate`` aggregates every chunk's errors into ONE
    ``ValidationError``, so a single off-schema chunk (or manifest-level
    field) used to discard the entire LLM ranking. Re-validate each raw
    ``chunks`` item individually and keep the ones that stand on their own;
    the caller drops the failures (with their shapes/raw_paths entries) and
    reports the kept/dropped counts.

    Returns ``(kept_chunks, kept_indices, total_raw_items)``. ``kept`` is
    empty when the reply carries no usable ``chunks`` list — the deliberate
    marker of a genuinely malformed reply (see ``TaskManifest``) — so the
    caller's empty-manifest fallback still applies there.
    """
    items = data.get("chunks") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return [], [], 0
    kept: list[Chunk] = []
    kept_idx: list[int] = []
    for i, item in enumerate(items):
        try:
            kept.append(Chunk.model_validate(item))
            kept_idx.append(i)
        except Exception:
            continue
    return kept, kept_idx, len(items)


def _normalize_chunk_files(manifest: TaskManifest, ctx: ContextPackage,
                           prompt_ctx: ContextPackage,
                           shapes: list[str] | None = None,
                           raw_paths: list[list[str]] | None = None, *,
                           rendered_from_id: int | None = None) -> None:
    """Resolve each chunk's file references onto real repo paths, dropping
    anything that doesn't exist.

    Two independent resolution paths, chosen per chunk from the RAW shape
    recorded by :func:`_prepare_chunk_shapes` — never guessed from
    ``chunk.files`` itself, which is shape-ambiguous after validation:

    * **id path** (``file_ids`` in the raw payload): resolve through
      ``prompt_ctx.id_inventory()`` — the SAME object the prompt was
      rendered from (asserted below). There are no paths to mis-match on
      this path, so an unknown id is simply absent from the map and is
      dropped — safe by construction.
    * **legacy path** (``files`` in the raw payload — a model that ignored
      the id contract): suffix-match against the FULL ground truth
      (``ctx.all_files``), reusing the same path-suffix idiom already used
      for call-graph qnode matching elsewhere in this module. A model
      sometimes drops leading directories (``core/utils.py`` for
      ``app/core/utils.py``); a unique suffix match recovers that file. A
      hallucinated path whose directory suffix genuinely coincides with an
      unrelated real file (invented ``service/UserService.java`` when only
      ``foo/service/UserService.java`` is real) still relocates wrongly —
      but it is now logged and counted, and that coincidence is far rarer
      than the bare-basename collisions this replaces.

    A chunk with no raw shape at all (neither key present) or an empty file
    list falls through with nothing resolved; the caller drops empty chunks
    separately.
    """
    # `rendered_from_id` is `id(prompt_ctx)` captured at the ONE call site,
    # at the moment the prompt was actually rendered from it — not
    # re-derived here. A future refactor that renamed a variable and passed
    # a *different* object (most dangerously, `ctx` itself) would otherwise
    # silently resolve every id against the wrong file list; comparing
    # object identity, not equality, is deliberate — two independently built
    # views could have equal `all_files` by coincidence on a small fixture
    # and still be the wrong object on a real repo.
    # A raise, not an assert: asserts are stripped under `python -O`, which
    # would silently remove the only runtime protection against resolving
    # every file id against the wrong list.
    if rendered_from_id is not None and id(prompt_ctx) != rendered_from_id:
        raise RuntimeError(
            "file ids must be resolved against the EXACT object the prompt "
            "was rendered from, never a separately obtained view — a "
            "differently-sized view's ids address different files"
        )
    truth = set(ctx.all_files)
    inv_files = prompt_ctx.id_inventory()["files"]
    shapes = shapes or []
    raw_paths = raw_paths or []

    def _resolve_ids(chunk_id: str, fids: list[str]) -> list[str]:
        out: list[str] = []
        for fid in fids:
            path = inv_files.get(fid)
            if path is not None:
                out.append(path)
            else:
                print(f"    [s3] dropped unknown file id from {chunk_id}: {fid}",
                      file=sys.stderr)
                _errlog.log("s3", chunk_id, f"unknown file id {fid!r}")
                COUNTERS.bump("s3_unknown_file_ids")
        return out

    def _resolve_paths(chunk_id: str, paths: list[str]) -> list[str]:
        out: list[str] = []
        for f in paths:
            cand = f.replace("\\", "/")
            while cand.startswith("./"):
                cand = cand[2:]
            if cand in truth:
                out.append(cand)
                continue
            matches = [t for t in truth
                      if t == cand or t.endswith("/" + cand) or cand.endswith("/" + t)]
            if len(matches) == 1:
                out.append(matches[0])
                print(f"    [s3] relocated {f!r} -> {matches[0]!r} in {chunk_id}",
                      file=sys.stderr)
                # recovered=True: the file was resolved to its real path —
                # nothing lost. Genuine drops below log unmarked.
                _errlog.log("s3", chunk_id, f"relocated {f!r} -> {matches[0]!r}",
                            recovered=True)
                COUNTERS.bump("s3_relocated_paths")
            else:
                print(f"    [s3] dropped non-existent file from {chunk_id}: {f}",
                      file=sys.stderr)
                _errlog.log("s3", chunk_id,
                           f"dropped {f!r} ({len(matches)} suffix matches)")
                COUNTERS.bump("s3_dropped_paths")
        return out

    for i, chunk in enumerate(manifest.chunks):
        shape = shapes[i] if i < len(shapes) else ""
        if shape == "mixed":
            # Both keys were sent. The alias makes `file_ids` win, so
            # `chunk.files` holds the ids and the raw paths were captured
            # separately. Resolve both and union, rather than discarding one
            # payload — a model that hedged with an empty `file_ids` beside real
            # paths would otherwise lose the chunk and its risk ranking.
            raw = raw_paths[i] if i < len(raw_paths) else []
            fixed = _resolve_ids(chunk.id, chunk.files) + _resolve_paths(chunk.id, raw)
        elif shape == "ids":
            fixed = _resolve_ids(chunk.id, chunk.files)
        else:
            fixed = _resolve_paths(chunk.id, chunk.files)
        chunk.files = list(dict.fromkeys(fixed))  # dedupe, keep order


def _drop_empty_chunks(manifest: TaskManifest) -> None:
    """Drop any chunk left with no resolvable files after normalisation — an
    emptied chunk still carries a risk_rank and would otherwise reach s4 as a
    no-op call that reviews nothing."""
    kept: list[Chunk] = []
    for c in manifest.chunks:
        if not c.files:
            print(f"    [s3] dropped {c.id}: no resolvable files after normalization",
                  file=sys.stderr)
            _errlog.log("s3", c.id, "empty chunk after normalization")
            COUNTERS.bump("s3_dropped_empty_chunks")
            continue
        kept.append(c)
    manifest.chunks = kept


def _file_call_graph(ctx: ContextPackage) -> dict[str, set[str]]:
    """Project the qualified call_graph onto an undirected FILE graph.
    Every node is `file::name` (P5), so the file is read straight off the
    key — no more component-walk over unlocated bare names."""
    adj: dict[str, set[str]] = defaultdict(set)
    for caller, callees in (ctx.call_graph or {}).items():
        cf = q_file(caller)
        if not cf:
            continue
        for cal in callees:
            tf = q_file(cal)
            if tf and tf != cf:
                adj[cf].add(tf)
                adj[tf].add(cf)
    return adj


def _merge_dir_groups_to_cap(by_dir: dict[str, list[str]],
                             max_groups: int) -> dict[str, list[str]]:
    """Fold the smallest directory group into its own parent, one level at a
    time, until at most `max_groups` remain (or nothing more can merge).

    Smallest-first bounds how many files move per merge, and "one level at a
    time" (never straight to root) means a handful of oversize monorepo
    directories don't all collapse into "." on the very first pass."""
    if max_groups <= 0 or len(by_dir) <= max_groups:
        return by_dir
    groups = dict(by_dir)
    while len(groups) > max_groups:
        candidates = [k for k in groups if k != "."]
        if not candidates:
            break
        smallest = min(candidates, key=lambda k: (len(groups[k]), k))
        parent = str(PurePosixPath(smallest).parent)
        if parent == smallest:
            parent = "."
        moved = groups.pop(smallest)
        groups[parent] = groups.get(parent, []) + moved
    return groups


def _cohesive_groups(files: list[str], ctx: ContextPackage,
                     max_groups: int | None = None) -> list[tuple[str, list[str]]]:
    """
    Partition `files` into semantically related groups so a researcher sees
    callers and callees together. Preference order:
      1. ctx.modules (s1's agentic grouping — already relation-aware)
      2. call-graph connected components (controller+service+DAO stay together
         even when they live under /web/, /svc/, /dao/)
      3. immediate parent directory (last resort for files with no graph
         edges) — "." for root-level files. If that leaves more than
         `max_groups` directory groups, the smallest ones fold into their
         parent, one level at a time, until the count fits.
    Every input file lands in exactly one group.
    """
    pending = set(files)
    groups: list[tuple[str, list[str]]] = []

    for m in ctx.modules:
        hit = [f for f in m.files if f in pending]
        if hit:
            groups.append((m.name, hit))
            pending.difference_update(hit)

    adj = _file_call_graph(ctx)
    visited: set[str] = set()
    for f in sorted(pending):
        if f in visited or f not in adj:
            continue
        comp, stack = [], [f]
        while stack:
            n = stack.pop()
            if n in visited or n not in pending:
                continue
            visited.add(n)
            comp.append(n)
            stack.extend(adj.get(n, ()))
        if comp:
            groups.append((f"cg:{PurePosixPath(comp[0]).stem}", sorted(comp)))
    pending.difference_update(visited)

    by_dir: dict[str, list[str]] = defaultdict(list)
    for f in sorted(pending):
        key = str(PurePosixPath(f).parent)
        by_dir[key].append(f)
    if max_groups is not None:
        by_dir = defaultdict(list, _merge_dir_groups_to_cap(dict(by_dir), max_groups))
    for key in sorted(by_dir):
        groups.append((key, sorted(by_dir[key])))

    COUNTERS.bump("s3_cohesion_groups", len(groups))
    return groups


# Must stay identical to the pattern the threat-model stage uses when it writes
# these evidence strings. The two cannot share one constant: that stage already
# imports from this module, so importing back would be a cycle. A test asserts
# the two patterns are equal, which is what actually prevents them drifting.
_BASELINE_EVIDENCE_RX = re.compile(r"baseline:\s*(BL-[A-Z]+-\w+)")


def _is_baseline_threat(t) -> bool:
    """A threat s2 emitted to satisfy the mandatory baseline disposition,
    identified by the `"baseline: <ID>"` evidence prefix its emitter writes.

    The pattern deliberately matches the emitter's own, which requires a
    well-formed checklist id after the prefix. A looser `startswith` would
    also swallow a real, repo-specific threat whose evidence merely opened
    with the word.

    This marker alone says nothing about whether the threat is real — s2 asks
    for it on EVERY disposed baseline item and tells the model to prefer a
    threat over an open question when in doubt, so on a normal repo most
    threats carry it. Use :func:`_is_unmatched_baseline_threat` for the
    exemption decision; this is only the marker test."""
    return _BASELINE_EVIDENCE_RX.match(t.evidence or "") is not None


# A path-shaped token inside a threat's `surface` string: `routes/b2bOrder.ts`,
# `lib/insecurity.ts::decode(token)`, `server.ts::configureApp`. Deliberately
# requires a file extension, so prose surfaces ("npm dependencies", "frontend
# Angular routes", "terraform/ IaC") yield nothing and stay exempt.
_SURFACE_PATH_RX = re.compile(r"[\w./\\-]+\.[A-Za-z0-9]{1,6}")


def _surface_names_a_real_file(t, all_files: set[str]) -> bool:
    """Whether the threat's `surface` names a path that resolves to a file
    actually in scope, using the same path-suffix idiom as chunk-file
    resolution (a model routinely drops leading directories)."""
    for tok in _SURFACE_PATH_RX.findall(t.surface or ""):
        cand = tok.replace("\\", "/")
        while cand.startswith("./"):
            cand = cand[2:]
        if cand in all_files or any(f.endswith("/" + cand) for f in all_files):
            return True
    return False


def _is_unmatched_baseline_threat(t, all_files: set[str]) -> bool:
    """A baseline disposition that pins itself to no code surface in this repo.

    These, and only these, are exempted both from ever costing a dedicated
    fallback chunk and from the coverage report's denominator — otherwise a
    baseline item with no matching code surface prints as permanently
    UNCOVERED, and a dedicated chunk for it would select noise through the
    generous fallback-routing regexes above for no recall benefit.

    Testing the marker alone is NOT sufficient and was actively harmful: s2
    requires a `"baseline: <ID>"` disposition for every checklist item and
    steers the model toward emitting one, so a threat naming a concrete
    surface (`routes/b2bOrder.ts::b2bOrder`) carries the same marker as pure
    filler (`npm dependencies (express-jwt 0.1.3, ...)`). Keying off the
    marker therefore stripped the coverage guarantee from most real threats
    while leaving it to the ones with no evidence at all. The surface is the
    discriminator, because it is what a fallback chunk would be built from."""
    return _is_baseline_threat(t) and not _surface_names_a_real_file(t, all_files)


def _report_threat_coverage(manifest: TaskManifest, ctx: ContextPackage) -> None:
    tm = ctx.threat_model
    if not tm or not tm.threats:
        return
    # `known` is every real threat id, used to null out a chunk citing an id
    # that does not exist at all. `valid` is the denominator for the ratio —
    # baseline-derived threats are excluded from it so one with no matching
    # code surface doesn't print as UNCOVERED forever (they are still
    # perfectly legitimate `threat_id` citations if a chunk happens to name
    # one; they just don't count against or toward the ratio).
    known = {t.id for t in tm.threats}
    all_files = set(ctx.all_files)
    valid = {t.id for t in tm.threats
             if not _is_unmatched_baseline_threat(t, all_files)}
    covered: set[str] = set()
    for c in manifest.chunks:
        if c.threat_id and c.threat_id not in known:
            print(f"    [s3] {c.id}: unknown threat_id {c.threat_id!r} → dropped",
                  file=sys.stderr)
            c.threat_id = None
        if c.threat_id:
            covered.add(c.threat_id)
    covered &= valid
    missing = sorted(valid - covered)
    print(f"    [s3] threat coverage: {len(covered)}/{len(valid)} threats have ≥1 chunk"
          + (f"; UNCOVERED: {', '.join(missing)}" if missing else ""),
          file=sys.stderr)


_THREAT_IAC_RX = re.compile(
    r"\b(supply\s*chain|dependency|dependencies|package|sbom|build|release|"
    r"ci/?cd|pipeline|workflow|actions?|github\s*actions|jenkins|docker|"
    r"kubernetes|k8s|terraform|helm|image)\b",
    re.IGNORECASE,
)
_THREAT_LLM_RX = re.compile(
    r"\b(llm|prompt|jailbreak|rag|tool\s*call|agent|assistant|model\s*output|"
    r"prompt\s*inject|indirect\s*inject)\b",
    re.IGNORECASE,
)
_THREAT_AUTHZ_RX = re.compile(
    r"\b(authz|authorization|access\s*control|idor|rbac|acl|privilege|session|"
    r"csrf|oauth|jwt|tenant\s*isolation)\b",
    re.IGNORECASE,
)
_THREAT_CRYPTO_RX = re.compile(
    r"\b(crypto|cipher|encryption|decrypt|signature|hmac|hash|md5|sha|tls|ssl|"
    r"x509|certificate|secret\s*key|key\s*management)\b",
    re.IGNORECASE,
)
_THREAT_DESER_RX = re.compile(
    r"\b(deserial|pickle|marshal|yaml\.load|objectinputstream|readobject|"
    r"binaryformatter|xstream|snakeyaml|hessian|kryo)\b",
    re.IGNORECASE,
)
_THREAT_BATCH_RX = re.compile(
    r"\b(batch|etl|file\s*ingest|bulk\s*import|job\s*scheduler|mainframe|"
    r"jcl|cobol|record\s*format)\b",
    re.IGNORECASE,
)
_THREAT_CONFIG_RX = re.compile(
    r"\b(config|configuration|policy|feature\s*flag|runtime\s*toggle|"
    r"environment\s*variable|env\b|deployment\s*setting)\b",
    re.IGNORECASE,
)
_IAC_PATH_RX = re.compile(
    r"(\.github/workflows/|dockerfile|jenkinsfile|\.gitlab-ci|azure-pipelines|"
    r"\.tf$|helm/|k8s/|kubernetes/|chart\.ya?ml$|values\.ya?ml$|"
    r"pom\.xml$|package\.json$|requirements(\.txt)?$|pyproject\.toml$|"
    r"poetry\.lock$|setup\.py$)",
    re.IGNORECASE,
)
_LLM_PATH_RX = re.compile(
    r"(llm|prompt|agent|assistant|openai|anthropic|rag|chat|completion|tool)",
    re.IGNORECASE,
)
_AUTHZ_PATH_RX = re.compile(
    r"(auth|oauth|jwt|rbac|acl|permission|policy|session|tenant)",
    re.IGNORECASE,
)
_CONFIG_EXTS = {".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".properties", ".xml", ".env"}


def _tok(s: str) -> set[str]:
    return set(_TOKEN_RX.findall((s or "").lower()))


def _is_config_file(rel: str) -> bool:
    p = PurePosixPath(rel)
    if p.name.lower().startswith(".env"):
        return True
    if p.suffix.lower() in _CONFIG_EXTS:
        return True
    name = p.name.lower()
    return ("config" in name or "policy" in name or "settings" in name)


def _threat_text(t) -> str:
    # `controls` deliberately excluded: it describes MITIGATIONS, the
    # opposite of where to hunt, so a threat whose controls text mentions
    # "JWT signature validation" would otherwise pull in every file
    # containing "jwt" regardless of whether that file has anything to do
    # with the threat itself. `evidence` is also excluded (unrelated reason:
    # it carries the `baseline: BL-*` provenance prefix, which must not
    # pollute file-routing regexes).
    return " ".join(filter(None, [t.threat, t.surface, t.asset, t.actor]))


def _matches_threat_surface(ep, t) -> bool:
    surface_tokens = _tok(t.surface)
    if not surface_tokens:
        return False
    fn = (ep.function or "").lower()
    if fn and t.surface.lower() == fn:
        return True
    return bool(surface_tokens & _tok(ep.function or ""))


def _candidate_files_for_threat(t, ctx: ContextPackage,
                                specialist_files: dict[str, list[str]],
                                max_files: int) -> list[str]:
    txt = _threat_text(t)
    all_files_set = set(ctx.all_files)
    files = [f for f in ctx.all_files if _is_source(f) or _is_config_file(f)]
    chosen: list[str] = []
    chosen_set: set[str] = set()

    def _add(seq):
        for f in seq:
            if f in chosen_set or f not in all_files_set:
                continue
            chosen.append(f)
            chosen_set.add(f)
            if len(chosen) >= max_files:
                return

    # Order matters under truncation: entry-point hits are the strongest
    # signal — the threat's surface names a function that literally IS this
    # entry point — so they must survive even when many regex/specialist
    # candidates exist. Their call-graph neighbours (the functions those
    # entry points actually call into) are the next strongest signal.
    # Regex/specialist heuristics, which have no direct evidence tying them
    # to this specific threat, come last and are the first to be truncated
    # away at `max_files`.
    ep_hits = [ep.file for ep in ctx.entry_points if _matches_threat_surface(ep, t)]
    _add(ep_hits)

    if len(chosen) < max_files and ep_hits:
        adj = _file_call_graph(ctx)
        neighbours: list[str] = []
        for f in ep_hits:
            neighbours.extend(sorted(adj.get(f, ())))
        _add(neighbours)

    if len(chosen) < max_files:
        if t.actor == "supply_chain" or _THREAT_IAC_RX.search(txt):
            _add(specialist_files.get("iac", []))
            _add([f for f in files if is_iac_file(f) or _IAC_PATH_RX.search(f)])
        if _THREAT_LLM_RX.search(txt):
            _add([f for f in files if _LLM_PATH_RX.search(f)])
        if t.actor in {"remote_unauth", "remote_auth"} or _THREAT_AUTHZ_RX.search(txt):
            _add(specialist_files.get("access-control", []))
            _add([f for f in files if _AUTHZ_PATH_RX.search(f)])
        if _THREAT_CRYPTO_RX.search(txt):
            _add(specialist_files.get("crypto", []))
        if _THREAT_DESER_RX.search(txt):
            _add(specialist_files.get("deserialization", []))
        if _THREAT_BATCH_RX.search(txt):
            _add(specialist_files.get("batch-etl", []))
        if _THREAT_CONFIG_RX.search(txt):
            _add([f for f in files if _is_config_file(f)])

    if chosen:
        return chosen[:max_files]
    return []


def _add_threat_surface_fallback_chunks(manifest: TaskManifest,
                                        ctx: ContextPackage,
                                        cfg) -> int:
    """Deterministically map uncovered threats to concrete code surface chunks.

    This closes known blind spots where specialist/catch-all chunks provide
    review coverage but do not increment threat coverage because they carry no
    ``threat_id``.
    """
    step3 = getattr(cfg, "step3", None)
    if not bool(getattr(step3, "threat_surface_fallbacks", True)):
        return 0
    tm = ctx.threat_model
    if not tm or not tm.threats:
        return 0

    # Baseline dispositions that name no code surface are exempt: they select
    # noise through these same fallback-routing regexes, so giving each one a
    # dedicated chunk would buy re-reads of already-covered files under a
    # mismatched lens for no recall benefit. A baseline-marked threat that
    # DOES name a real file is a normal threat and keeps its guarantee.
    all_files = set(ctx.all_files)
    valid = [t for t in tm.threats
             if t.id and not _is_unmatched_baseline_threat(t, all_files)]
    covered = {c.threat_id for c in manifest.chunks if c.threat_id}
    missing = [t for t in valid if t.id not in covered]
    if not missing:
        return 0

    max_files = _cap(step3, "threat_fallback_max_files", 12)
    # The registered `_STEP_DEFAULTS` value is what actually governs; this
    # inline default only applies to a config object missing the key entirely.
    # Keep the two in step — and see that entry for why it is not smaller than
    # the threat ceiling. Whatever the value, `capped` below reports its cost.
    max_chunks = _cap(step3, "max_threat_fallback_chunks", 50)
    base_rank = max((c.risk_rank for c in manifest.chunks), default=0)
    repo_root = Path(ctx.repo_root)

    specialist_files: dict[str, list[str]] = defaultdict(list)
    for c in manifest.chunks:
        if c.specialist:
            specialist_files[c.specialist].extend(c.files)
    for k, v in specialist_files.items():
        specialist_files[k] = list(dict.fromkeys(v))

    added = 0
    capped = 0
    for t in missing:
        files = _candidate_files_for_threat(t, ctx, specialist_files, max_files)
        if not files:
            continue
        if added >= max_chunks:
            # A candidate chunk existed for this threat but the cap was
            # already reached — count it as suppressed, not merely skipped,
            # so an operator can see the fallback pass hit its ceiling
            # instead of concluding every remaining threat had no surface.
            capped += 1
            continue
        # Bound the chunk by LOC as well as file count. `threat_fallback_max_files`
        # caps files only, and 12 files of Java can be enormous: observed fallback
        # chunks reached 1.5M chars (47k LOC in 10 files) and returned 0 and 1 raw
        # findings. Yield per chunk peaks at ~1.62 in the 60-150k char band and
        # collapses to ~0.15-0.18 past 300k, so an unbounded chunk does not merely
        # cost tokens, it loses the findings it was created to catch.
        #
        # Trimmed at build time rather than split afterwards, deliberately: the
        # splitter would turn one capped chunk into several, so an operator's
        # `max_threat_fallback_chunks` ceiling would silently become a multiple of
        # itself in s4 calls. Fewest-files-dropped order is preserved (the
        # candidate list is already risk-ranked), and at least one file always
        # survives so a single oversized file is still reviewed.
        # Read the key the way the splitter does, NOT through `_cap`. Three
        # shipped profiles document `risk_chunk_loc: 0` as "0 = off" and the
        # splitter honours that with a plain getattr, but `_cap` deliberately
        # maps a configured 0 onto its default — a contract the s3
        # `max_prompt_*` family relies on, so `_cap` itself must not change.
        # Routing this key through it silently overrode the operator's off
        # switch with a 10,000-LOC budget and left the `loc_budget` guard below
        # permanently true. Garbage values still fall through to `_cap`, which
        # sanitises them to the registered default.
        _raw_loc = getattr(step3, "risk_chunk_loc", None)
        if _raw_loc is not None and not _raw_loc:
            loc_budget = 0
        else:
            loc_budget = _cap(step3, "risk_chunk_loc", 10000)
        kept: list[str] = []
        loc = 0
        for f in files:
            f_loc = _count_loc(repo_root / f)
            if kept and loc_budget and loc + f_loc > loc_budget:
                continue
            kept.append(f)
            loc += f_loc
        if len(kept) < len(files):
            COUNTERS.bump("s3_fallback_files_trimmed", len(files) - len(kept))
        files = kept
        cid = f"threat-{t.id.lower()}-fallback"
        used = {c.id for c in manifest.chunks}
        if cid in used:
            n = 2
            while f"{cid}-{n}" in used:
                n += 1
            cid = f"{cid}-{n}"
        focus = [ep.function for ep in ctx.entry_points if _matches_threat_surface(ep, t)][:8]
        manifest.chunks.append(Chunk(
            id=cid,
            size=_size_for(loc),
            risk_rank=base_rank + added + 1,
            files=files,
            focus_entry_points=focus,
            hypothesis=(
                f"Deterministic threat-surface fallback for {t.id}: "
                f"{t.threat}. Review likely files derived from actor/surface "
                "signals and repository specialist coverage."
            ),
            related_cves=[],
            threat_id=t.id,
        ))
        added += 1

    if added:
        print(f"    [s3] threat-surface fallback: added {added} chunk(s) "
              f"for previously uncovered threats",
              file=sys.stderr)
    if capped:
        COUNTERS.bump("s3_fallback_chunks_dropped", capped)
        print(f"    [s3] threat-surface fallback: {capped} more chunk(s) "
              f"suppressed by step3.max_threat_fallback_chunks={max_chunks}",
              file=sys.stderr)
    return added


def _pick_hop_files(candidates, anchors: list[str], cap: int) -> list[str]:
    """Return ≤`cap` candidate files, ranked by longest common directory
    prefix with any anchor (entry/sink file). Java package == dir path, so
    same-package definitions sort first. cap<=0 ⇒ no cap."""
    cands = list(dict.fromkeys(candidates))
    if cap <= 0 or len(cands) <= cap:
        return cands
    aps = [a.split("/") for a in anchors if a]

    def _aff(f: str) -> int:
        fp = f.split("/")
        best = 0
        for ap in aps:
            n = 0
            for x, y in zip(fp, ap):
                if x != y:
                    break
                n += 1
            best = max(best, n)
        return best

    cands.sort(key=lambda f: (-_aff(f), f))
    return cands[:cap]


def _qnode_for_file_line(ctx: ContextPackage, file_rel: str,
                         line: int) -> str | None:
    """Best-effort qnode lookup for a concrete file:line anchor.

    Uses the shared, call-graph-first resolver
    (:func:`callgraph_consumer.qnodes_at`); ``nearest_if_empty`` gives a
    single-anchor result when neither a span nor the call graph resolves the
    file.
    """
    if line <= 0:
        return None
    hits = qnodes_at(graph_view(ctx), file_rel, line, line,
                     limit=1, nearest_if_empty=True)
    return hits[0] if hits else None


def _sink_qnodes_for_sink(s, ctx: ContextPackage,
                          match_qnodes) -> list[str]:
    """Resolve sink candidates to qnodes using function then line anchors."""
    out: list[str] = []
    if s.function:
        out.extend(match_qnodes(s.file, s.function))
    if not out and getattr(s, "line", 0):
        qn = _qnode_for_file_line(ctx, s.file, int(s.line))
        if qn:
            out.append(qn)
    return list(dict.fromkeys(out))


def _seed_paths_for_entry(ctx: ContextPackage, ep,
                          sink_by_qn: dict[str, list],
                          all_file_set: set[str]) -> list[tuple[str, list[str], str | None, str | None, list[str]]]:
    """Materialize seed taint paths touching an entry file into taint hits.

    Returns tuples of:
      (sink_qn, qnode_path, source_ref, sink_ref, sink_cwe)
    """
    out: list[tuple[str, list[str], str | None, str | None, list[str]]] = []

    def _ref_file(ref: str) -> str:
        if not ref:
            return ""
        if "::" in ref:
            return ref.split("::", 1)[0]
        return ref.split(":", 1)[0]

    def _ref_line(ref: str) -> int:
        if not ref or "::" in ref:
            return 0
        _, _, tail = ref.rpartition(":")
        return int(tail) if tail.isdigit() else 0

    def _ref_function(ref: str) -> str:
        # Only a qnode-shaped ref ("file::func") carries a function name; a
        # legacy "file:line" ref does not, so there is nothing to match on
        # and the caller falls back to file-only matching for those.
        if ref and "::" in ref:
            return ref.rpartition("::")[2]
        return ""

    # Prefer structured taint evidence when available; fall back to legacy
    # seed_taint_paths when there is no matching evidence for this entry.
    if ctx.seed_taint_evidence:
        seen_ev: set[tuple[str, str, tuple[str, ...]]] = set()
        for evidence in ctx.seed_taint_evidence:
            source_ref = evidence.source_ref or ""
            sink_ref = evidence.sink_ref or ""
            source_file = _ref_file(source_ref).replace("\\", "/")
            sink_file = _ref_file(sink_ref).replace("\\", "/")
            if source_file != ep.file:
                continue
            # Match by function too, when the evidence's source ref names
            # one. Matching by file alone let every seeded function in a
            # multi-entry-point file pull in every OTHER function's evidence
            # as well — N entry points in one file produced up to N^2
            # near-duplicate chunks instead of N.
            ev_fn = _ref_function(source_ref)
            if ev_fn and ev_fn != ep.function:
                continue

            qpath = list(dict.fromkeys(evidence.path_funcs or []))
            hop_files = [q_file(fn) for fn in qpath if q_file(fn)]
            hop_files = [f for f in dict.fromkeys(hop_files) if f in all_file_set]
            if not hop_files:
                hop_files = [f for f in (source_file, sink_file) if f in all_file_set]
            if len(hop_files) < 2:
                continue

            sink_qn = ""
            sink_line = _ref_line(sink_ref)
            if sink_file in all_file_set and sink_line > 0:
                sink_qn = _qnode_for_file_line(ctx, sink_file, sink_line) or ""
            if not sink_qn and qpath:
                sink_qn = qpath[-1]

            sink_cwe = sorted(dict.fromkeys(evidence.sink_cwe or []))
            if not sink_cwe and sink_qn in sink_by_qn:
                sink_cwe = sorted({c for s in sink_by_qn[sink_qn]
                                   for c in getattr(s, "cwe", None) or ()})

            ev_key = (source_ref, sink_ref, tuple(qpath))
            if ev_key in seen_ev:
                continue
            seen_ev.add(ev_key)
            out.append((sink_qn, qpath, source_ref, sink_ref, sink_cwe))

        if out:
            return out

    by_file = seed_paths_by_file(ctx.seed_taint_paths)
    for path in by_file.get(ep.file, ()): 
        if len(path) < 2:
            continue
        qpath: list[str] = []
        hop_files: list[str] = []
        for hop in path:
            hf, _, hline = hop.rpartition(":")
            file_rel = hf if hline else hop
            file_rel = file_rel.replace("\\", "/")
            if file_rel not in all_file_set:
                continue
            hop_files.append(file_rel)
            if hline.isdigit():
                qn = _qnode_for_file_line(ctx, file_rel, int(hline))
                if qn:
                    qpath.append(qn)
        if len(hop_files) < 2:
            continue
        sink_ref = path[-1]
        sf, _, sl = sink_ref.rpartition(":")
        sink_qn = ""
        sink_cwe: list[str] = []
        if sf and sl.isdigit():
            sink_qn = _qnode_for_file_line(ctx, sf, int(sl)) or ""
            if sink_qn in sink_by_qn:
                sink_cwe = sorted({c for s in sink_by_qn[sink_qn]
                                   for c in getattr(s, "cwe", None) or ()})
        source_ref = path[0]
        out.append((sink_qn, qpath, source_ref, sink_ref, sink_cwe))
    return out


def _add_taint_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> int:
    """
    Walk ctx.call_graph from each entry point to each unsafe sink and emit one
    chunk per reachable (entry, sink) pair containing every file we can resolve
    along the path. Guarantees the s4 researcher sees source AND sink together,
    which is the precondition for a confirmed data-flow finding.
    """
    if not getattr(cfg.step3, "taint_chunks", True):
        return 0
    if not ctx.entry_points or not ctx.unsafe_sinks:
        print("    [s3] taint: skipped (no entry points or sinks from s1)",
              file=sys.stderr)
        return 0

    graph = ctx.call_graph or {}
    graph_nodes: set[str] = set(graph)
    for vs in graph.values():
        graph_nodes.update(vs)
    by_bare: dict[str, list[str]] = defaultdict(list)
    for k in graph_nodes:
        by_bare[q_name(k)].append(k)

    def _match_qnodes(file: str, name: str) -> list[str]:
        cands = by_bare.get(name, [])
        hit = [k for k in cands if q_file(k) == file]
        if hit:
            return hit
        # Path-suffix match, but anchored on a "/" boundary so a partial
        # filename component can't match: "auth.py" must NOT match
        # "src/oauth.py". A == B, or one ends with "/" + the other.
        def _path_suffix(a: str, b: str) -> bool:
            return a == b or a.endswith("/" + b) or b.endswith("/" + a)
        hit = [k for k in cands if _path_suffix(q_file(k), file)]
        return hit or [q_join(file, name)]

    sink_qnodes: set[str] = set()
    sink_by_qn: dict[str, list] = defaultdict(list)
    for s in ctx.unsafe_sinks:
        if not s.function and not getattr(s, "line", 0):
            continue
        for qn in _sink_qnodes_for_sink(s, ctx, _match_qnodes):
            sink_qnodes.add(qn)
            sink_by_qn[qn].append(s)

    repo_root = Path(ctx.repo_root)
    max_hops = getattr(cfg.step3, "taint_max_hops", 8)
    max_chunks = getattr(cfg.step3, "taint_max_chunks", 40)
    per_hop = int(getattr(cfg.step3, "taint_files_per_hop", 5) or 0)

    # Taint chunks are the highest-signal work — rank them ABOVE the LLM's
    # risk chunks so s4 processes them first.
    for c in manifest.chunks:
        c.risk_rank += max_chunks

    threats = ctx.threat_model.threats if ctx.threat_model else []

    # Per-threat surface tokens are loop-invariant across entry points, so
    # tokenize each threat surface once here rather than on every _threat_for
    # call.
    _threat_tokens = [(t, _tok(t.surface)) for t in threats if t.surface]

    def _threat_for(ep) -> str | None:
        # Associate a taint chunk with a threat by matching the threat's
        # surface (an entry-point/function NAME) to the entry function on a
        # whole-token / exact basis. Looser substring matching (incl. matching
        # against the file PATH) over-tagged this coverage metric, so it is
        # avoided. Exact (case-insensitive) wins; otherwise the first threat
        # sharing a whole token with the function name.
        fn_lower = (ep.function or "").lower()
        fn_tokens = _tok(fn_lower)
        best: str | None = None
        for t, surf_tokens in _threat_tokens:
            if t.surface.lower() == fn_lower:
                return t.id
            if best is None and fn_tokens and (surf_tokens & fn_tokens):
                best = t.id
        return best

    seen_paths: set[tuple] = set()
    seen_ep_sink: set[tuple] = set()  # (ep_qn, sink_qn) — ep_qn = q_join(ep.file, ep.function)
    reached_fns: set[str] = set()
    entry_files = {e.file for e in ctx.entry_points}
    added = 0
    entries = sorted(ctx.entry_points,
                     key=lambda e: (not e.reachable_from_unauth, e.kind))

    all_file_set = set(ctx.all_files)

    # Seed-evidence hits are collected across ALL entry points, keyed by
    # their resolved file set, and only turned into chunks after every entry
    # point has been scanned. Several entry-point functions defined in the
    # SAME file commonly resolve to the identical two-file (source, sink)
    # set — emitting one chunk per function there would just be the same
    # bytes reviewed N times with a different focus-function label. Merging
    # by file set collapses those into one chunk whose `focus_entry_points`
    # and `path_funcs` record every contributing function.
    seed_groups: dict[tuple[str, ...], dict] = {}
    seed_order: list[tuple[str, ...]] = []

    for ep in entries:
        ep_qn = q_join(ep.file, ep.function)  # file-qualified key for dedup
        hits: list[tuple[str, list[str]]] = []

        # Prefer concrete S0-proven taint paths when available.
        for sink_qn, qpath, src_ref, snk_ref, cwes in _seed_paths_for_entry(
                ctx, ep, sink_by_qn, all_file_set):
            hop_files = [q_file(fn) for fn in qpath if q_file(fn)]
            if not hop_files:
                # Keep at least source/sink files from seed hops.
                sf, _, _ = (src_ref or "").rpartition(":")
                tf, _, _ = (snk_ref or "").rpartition(":")
                hop_files = [x for x in (sf, tf) if x]
            files = _pick_hop_files(hop_files, [ep.file],
                                    per_hop * max(1, len(qpath) or 2))
            files.append(ep.file)
            if snk_ref:
                tf, _, _ = snk_ref.rpartition(":")
                if tf:
                    files.append(tf)
            files = [f for f in dict.fromkeys(files) if f in all_file_set]
            if not files:
                continue
            sig = (ep.function, sink_qn or snk_ref or "seed", tuple(sorted(files)))
            if sig in seen_paths:
                continue
            seen_paths.add(sig)
            seen_ep_sink.add((ep_qn, sink_qn or snk_ref or "seed"))

            key = tuple(sorted(files))
            grp = seed_groups.get(key)
            if grp is None:
                grp = {"files": files, "funcs": [], "eps": [], "qpaths": [],
                      "srcs": [], "snks": [], "cwe": set()}
                seed_groups[key] = grp
                seed_order.append(key)
            if ep.function not in grp["funcs"]:
                grp["funcs"].append(ep.function)
            grp["eps"].append(ep)
            grp["qpaths"].extend(qpath)
            if src_ref:
                grp["srcs"].append(src_ref)
            grp["snks"].append(snk_ref or (q_file(sink_qn) if sink_qn else ""))
            grp["cwe"].update(cwes)

    # Phase B: emit the merged seed-evidence chunks FIRST — S0-proven paths
    # are higher-quality evidence than a BFS walk, so they earn the lowest
    # (highest-priority) risk_rank / lowest `taint-NN` numbers, exactly as
    # before this function grouped by file set instead of by (entry point,
    # hit) pair.
    for key in seed_order:
        if added >= max_chunks:
            break
        grp = seed_groups[key]
        added += 1
        dedup_qpaths = list(dict.fromkeys(grp["qpaths"]))
        threat_id = None
        for e in grp["eps"]:
            threat_id = _threat_for(e)
            if threat_id:
                break
        funcs = grp["funcs"]
        snk_sample = next((s for s in grp["snks"] if s), "")
        if len(funcs) == 1:
            hyp = (
                f"Seed path evidence: {grp['eps'][0].kind} input at {funcs[0]}() "
                f"[{grp['eps'][0].file}] reaches sink [{snk_sample or 'unknown'}]. "
                "Validate each hop for missing sanitization and real exploitability."
            )
        else:
            hyp = (
                f"Seed path evidence ({len(funcs)} entry functions merged): "
                f"{', '.join(funcs)} in {grp['eps'][0].file} share a proven "
                f"source→sink path. Validate each for missing sanitization."
            )
        manifest.chunks.append(Chunk(
            id=f"taint-{added:02d}",
            size=_size_for(sum(_count_loc(repo_root / f) for f in grp["files"])),
            risk_rank=added,
            files=grp["files"],
            focus_entry_points=funcs,
            hypothesis=hyp,
            related_cves=[],
            threat_id=threat_id,
            path_funcs=dedup_qpaths,
            source_ref=grp["srcs"][0] if grp["srcs"] else "",
            sink_ref=snk_sample,
            sink_cwe=sorted(grp["cwe"]),
        ))

    # Phase C: BFS-derived chunks, capped at whatever headroom the seed pass
    # left under `max_chunks`.
    for ep in entries:
        if added >= max_chunks:
            break
        ep_qn = q_join(ep.file, ep.function)  # file-qualified key for dedup
        hits: list[tuple[str, list[str]]] = []

        for start in _match_qnodes(ep.file, ep.function):
            hits.extend(_bfs_to_sinks(start, graph, sink_qnodes, max_hops, sink_by_qn))
        reached_fns.update(qn for qn, _ in hits)
        # Direct sink in the entry file with no graph edge → still a chunk.
        if not hits:
            hits = [(q_join(s.file, s.function),
                     [q_join(ep.file, ep.function), q_join(s.file, s.function)])
                    for s in ctx.unsafe_sinks if s.file == ep.file]

        # #1: Drop BFS hits already covered by a seed-evidence chunk for this EP.
        # Seed evidence (S0 proven path) is higher quality than BFS; no need for
        # a second chunk reaching the same sink via a different file set.
        hits = [(sqn, p) for sqn, p in hits
                if (ep_qn, sqn) not in seen_ep_sink]

        # #2: Merge same-EP, same-CWE BFS sinks into one chunk to reduce S4 calls.
        # Sinks that share a CWE represent the same vulnerability class from the
        # same entry point — S4 can review them together with coherent KB guidance.
        # Sinks with no CWE form their own group to avoid diluting CWE-targeted prompts.
        cwe_groups: dict[tuple, list] = defaultdict(list)
        for sink_qn, path in hits:
            sinks_here = sink_by_qn.get(sink_qn, ())
            cwes = tuple(sorted({c for s in sinks_here
                                  for c in getattr(s, "cwe", None) or ()}))
            cwe_groups[cwes or ("",)].append((sink_qn, path))

        unauth = "UNAUTH " if ep.reachable_from_unauth else ""
        for cwe_key, group in cwe_groups.items():
            if added >= max_chunks:
                break

            # Collect files and structural metadata across all sinks in this group.
            all_hop_files: list[str] = []
            all_sink_files: list[str] = []
            all_path_funcs: list[str] = []
            all_sink_refs: list[str] = []
            all_sinks: list = []
            group_sink_qns: list[str] = []
            max_path_len = 1
            for sink_qn, path in group:
                sinks_here = sink_by_qn.get(sink_qn, ())
                sink_files = [s.file for s in sinks_here] or [q_file(sink_qn)]
                all_hop_files.extend(q_file(fn) for fn in path if q_file(fn))
                all_sink_files.extend(sink_files)
                all_path_funcs.extend(path)
                all_sink_refs.extend(f"{s.file}:{s.line}" for s in sinks_here[:2])
                all_sinks.extend(sinks_here)
                group_sink_qns.append(sink_qn)
                max_path_len = max(max_path_len, len(path))

            files = _pick_hop_files(all_hop_files, [ep.file, *all_sink_files],
                                    per_hop * max(1, max_path_len))
            files.append(ep.file)
            files.extend(all_sink_files)
            files = [f for f in dict.fromkeys(files) if f in all_file_set]
            if not files:
                continue

            sig = (ep.function, tuple(sorted(group_sink_qns)), tuple(sorted(files)))
            if sig in seen_paths:
                continue
            seen_paths.add(sig)
            for sqn in group_sink_qns:
                seen_ep_sink.add((ep_qn, sqn))
            added += 1

            # Hypothesis: single-sink gets the original directed flow text;
            # merged group names the count and CWE class so S4 knows to check all.
            n = len(group)
            deduped_refs = list(dict.fromkeys(all_sink_refs))
            sink_refs_str = ", ".join(deduped_refs[:6])
            if len(deduped_refs) > 6:
                sink_refs_str += f", …(+{len(deduped_refs) - 6})"
            first_sink = all_sinks[0] if all_sinks else None
            first_sink_qn = group_sink_qns[0]

            if n == 1:
                _, path = group[0]
                hyp = (
                    f"Taint path: {unauth}{ep.kind} input at "
                    f"{ep.function}() [{ep.file}] flows via "
                    f"{' -> '.join(q_name(fn) for fn in path)} to sink "
                    f"{q_name(first_sink_qn)}() [{sink_refs_str}]. Verify every hop "
                    f"for sanitization/validation; if none, this is exploitable."
                )
            else:
                cwe_label = cwe_key[0] if cwe_key != ("",) else "unknown-class"
                hyp = (
                    f"Taint paths ({n} {cwe_label} sinks merged): "
                    f"{unauth}{ep.kind} input at {ep.function}() [{ep.file}] "
                    f"reaches {n} sinks [{sink_refs_str}]. "
                    f"Verify each sink for missing sanitization; "
                    f"any unsanitized path is exploitable."
                )

            # Deduplicate path_funcs across merged paths while preserving order.
            seen_pf: set[str] = set()
            deduped_path_funcs: list[str] = []
            for pf in all_path_funcs:
                if pf not in seen_pf:
                    seen_pf.add(pf)
                    deduped_path_funcs.append(pf)

            manifest.chunks.append(Chunk(
                id=f"taint-{added:02d}",
                size=_size_for(sum(_count_loc(repo_root / f) for f in files)),
                risk_rank=added,
                files=files,
                focus_entry_points=[ep.function],
                hypothesis=hyp,
                related_cves=[],
                threat_id=_threat_for(ep),
                path_funcs=deduped_path_funcs,
                source_ref=q_join(ep.file, ep.function),
                sink_ref=(f"{first_sink.file}:{first_sink.line}"
                          if first_sink else q_file(first_sink_qn)),
                sink_cwe=sorted(set(cwe_key) - {""}),
            ))

    reached_sink_objs = {id(s) for qn in reached_fns
                         for s in sink_by_qn.get(qn, ())}
    orphans = [s for s in ctx.unsafe_sinks
               if id(s) not in reached_sink_objs and s.file not in entry_files]
    n_sinks = len(ctx.unsafe_sinks)
    pct = (100 * (n_sinks - len(orphans)) / n_sinks) if n_sinks else 0
    sample = ", ".join(f"{s.file}:{s.line}" for s in orphans[:6])
    if len(orphans) > 6:
        sample += f", …(+{len(orphans) - 6})"
    print(f"    [s3] taint reachability: {n_sinks - len(orphans)}/{n_sinks} "
          f"sinks ({pct:.0f}%) on ≥1 entry→sink path"
          + (f"; ORPHANED: {sample}" if orphans else ""), file=sys.stderr)

    if added:
        print(f"    [s3] taint: {added} entry→sink path chunks "
              f"({len(ctx.entry_points)} entries × {len(ctx.unsafe_sinks)} sinks, "
              f"graph={len(graph)} nodes)", file=sys.stderr)
    else:
        # Nothing reachable — undo the rank shift so ordering is unchanged.
        for c in manifest.chunks:
            c.risk_rank -= max_chunks
        print("    [s3] taint: 0 reachable entry→sink paths in call graph",
              file=sys.stderr)
    return added


# Names accepted as neutralizing taint for ANY sink class — the classic
# escaping/parameterization primitives whose job is exactly "make this
# string safe to use," regardless of what uses it afterward. Rebuilt-per-call
# `_SANITIZER_BARE` used to fold `validate`/`clean` in here too; both are
# removed — `validate_input(x)` is not evidence that any specific sink class
# was neutralized, so treating it as universal silently dropped real
# command/SQL-injection findings behind an aptly-named but unproven function.
_SANITIZER_UNIVERSAL: frozenset[str] = frozenset({
    "escape", "quote", "strip_tags", "html_escape", "xml_escape",
    "quote_plus", "urlencode", "bleach_clean", "prepared_statement",
    "parameterized",
})

# Names that only neutralize taint for a SPECIFIC CWE class. A numeric
# coercion stops a SQL-injection payload built from that value, but does
# nothing for a command-injection payload built from the SAME tainted
# string reaching a different sink — so whether one of these counts as a
# sanitizer can only be decided once the arriving sink's CWE is known, not
# per-hop while the path is still being walked.
_SANITIZER_BY_CWE: dict[str, frozenset[str]] = {
    "CWE-89": frozenset({"int", "float", "bool", "to_int"}),
    "CWE-90": frozenset({"int", "float", "bool", "to_int"}),
    "CWE-79": frozenset({"encode", "html_escape"}),
}
_SANITIZER_CLASS_NAMES: frozenset[str] = frozenset().union(*_SANITIZER_BY_CWE.values())


def _bfs_to_sinks(start: str, graph: dict[str, list[str]],
                  sinks: set[str], max_hops: int,
                  sink_by_qn: dict[str, list] | None = None,
                  ) -> list[tuple[str, list[str]]]:
    """Return [(sink_fn, path_funcs)] for every sink reachable from `start`
    via a path that does NOT pass through a sanitizer that actually
    neutralizes THAT sink's vulnerability class.

    Paths that cross a universal sanitizer, or a class-specific one that
    matches the CWE of the sink actually arrived at, are silently dropped:
    they still generate reachability noise but carry no proven taint, so
    skipping them reduces false-positive chunk generation. S4 (LLM
    confirm/refute) handles the residual uncertain cases.

    A universal-sanitizer hit is decided per hop (as before) because it
    neutralizes every class, so it can safely gate BFS expansion the moment
    it's seen. A class-specific hit CANNOT be decided per hop — the sink at
    the far end of the path, and therefore its CWE, isn't known yet — so the
    path instead carries forward the *set* of class-specific bare names it
    has passed through, and the decision is made only at sink arrival,
    against ``sink_by_qn``'s CWE list for that specific sink.

    Sink visited-tracking is intentionally separate from non-sink nodes:
    a sink first reached via a sanitized path is NOT added to ``visited``,
    so a later clean (unsanitized) path can still discover it — the classic
    auth-bypass / validation-bypass pattern where the same sink is reachable
    both through and around a sanitizer. ``sanitized_sinks_expanded`` bounds
    BFS expansion through sanitized-only sinks to one level, preventing loops.
    """
    if not start:
        return []
    sink_by_qn = sink_by_qn or {}
    out: list[tuple[str, list[str]]] = []
    # visited_clean / visited_sanitized key on (node, universal_hit,
    # class_hits) rather than just (node, bool) — class_hits is realistically
    # 0-2 names on any real path, so this stays cheap while still letting two
    # paths through the same node with different class-specific history be
    # explored independently, since which one "counts" depends on the sink
    # each eventually reaches.
    State = tuple  # (node, bool, frozenset[str])
    start_state: State = (start, False, frozenset())
    visited_clean: set[State] = {start_state}
    visited_sanitized: set[State] = set()
    clean_sinks: set[str] = set()               # sinks confirmed via a clean path (done)
    sanitized_sinks_expanded: set[State] = set()  # (sink, uhit, chits) expanded once
    # frontier entries: (node, path, universal_hit, class_hits)
    frontier: list[tuple[str, list[str], bool, frozenset[str]]] = [
        (start, [start], False, frozenset())
    ]
    while frontier:
        nxt: list[tuple[str, list[str], bool, frozenset[str]]] = []
        for node, path, uhit, chits in frontier:
            for callee in graph.get(node, ()):
                callee_bare = callee.rpartition("::")[2].lower()
                new_uhit = uhit or callee_bare in _SANITIZER_UNIVERSAL
                new_chits = (chits | {callee_bare}
                            if callee_bare in _SANITIZER_CLASS_NAMES else chits)
                p = path + [callee]
                state = (callee, new_uhit, new_chits)
                if callee in sinks:
                    if callee in clean_sinks:
                        continue  # already reported via a clean path — skip
                    cwes = {c for s in sink_by_qn.get(callee, ())
                           for c in getattr(s, "cwe", None) or ()}
                    # EVERY class at this sink must be sanitised, not just one.
                    # A single call site can carry several CWEs — a numeric
                    # coercion legitimately neutralises the SQL aspect while
                    # doing nothing for a command built from the same tainted
                    # string, so suppressing on the first match would discard
                    # the unsanitised aspect and lose a real finding silently.
                    # Requiring all classes errs toward reporting, which is the
                    # correct direction: a later stage re-checks against the
                    # source, but a path never emitted is never re-checked.
                    class_sanitized = bool(cwes) and all(
                        any(name in _SANITIZER_BY_CWE.get(cwe, frozenset())
                            for name in new_chits)
                        for cwe in cwes
                    )
                    hit = new_uhit or class_sanitized
                    if not hit:
                        # Clean path found for THIS sink's actual CWE: report
                        # and mark done.
                        out.append((callee, p))
                        clean_sinks.add(callee)
                        visited_clean.add(state)
                    elif state not in sanitized_sinks_expanded:
                        # Sanitized (for this sink) path only so far: don't
                        # mark clean — a different, cleaner path may still
                        # reach this sink. Expand once.
                        sanitized_sinks_expanded.add(state)
                        if len(p) <= max_hops:
                            nxt.append((callee, p, new_uhit, new_chits))
                else:
                    if not new_uhit:
                        # No universal hit yet on this path: skip only if an
                        # identical (node, uhit, chits) state was already
                        # queued.
                        if state in visited_clean:
                            continue
                        visited_clean.add(state)
                    else:
                        if state in visited_clean or state in visited_sanitized:
                            continue
                        visited_sanitized.add(state)
                    if len(p) <= max_hops:
                        nxt.append((callee, p, new_uhit, new_chits))
        frontier = nxt
    return out


def _size_for(loc: int) -> ChunkSize:
    if loc < 2000:
        return ChunkSize.SMALL
    if loc < 8000:
        return ChunkSize.MEDIUM
    return ChunkSize.LARGE


def _max_cohesion_groups(cfg) -> int:
    return _cap(cfg.step3, "max_cohesion_groups", 64)


def _merge_underfilled(cfg) -> bool:
    """Whether `_pack` may coalesce adjacent under-filled buckets.

    Read through one helper rather than at each of the four `_pack` call
    sites so all packing passes (oversize-risk split, catch-all, specialist
    default + iac) flip together — a lens whose buckets merged while
    another's did not would make the s4 call count impossible to reason
    about. The registered `_STEP_DEFAULTS` value is what actually governs;
    the inline default only covers a config object missing the key."""
    return bool(getattr(cfg.step3, "pack_merge_underfilled", True))


def _char_budget(cfg) -> int | None:
    """Shard-boundary char cap when step3.pack_by == 'tokens', else None.
    chars ≈ tokens × 4; budget = (context window − fixed overhead) × 4."""
    if str(getattr(cfg.step3, "pack_by", "loc")).lower() != "tokens":
        return None
    budget = int(getattr(cfg.step3, "chunk_token_budget", 180_000))
    overhead = int(getattr(cfg.step3, "chunk_overhead_tokens", 80_000))
    return max(10_000, (budget - overhead) * 4)


def _split_oversize_risk_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> None:
    """Re-pack any chunk whose total LOC exceeds step3.risk_chunk_loc (or whose
    char count exceeds the pack_by:tokens budget) into <id>-a, <id>-b, … so s4
    never sends a prompt past the model's context window. Preserves risk_rank,
    hypothesis, CVEs and entry points.

    Called ONCE, on the LLM-emitted chunks only, and BEFORE every packing
    producer (catch-all, specialists, threat-fallback) regardless of the order
    those producers run in — see the call-site comment in run(). Moving it
    after any of them would re-pack their buckets against `risk_chunk_loc`
    (10000) instead of the pass's own tighter budget (catch-all packs to
    `catchall_chunk_loc`, specialists to `specialist_chunk_loc`; the
    threat-fallback pass trims at build time).
    `taint-` chunks are exempt here, for the metadata reason below."""
    max_loc = getattr(cfg.step3, "risk_chunk_loc", 10_000)
    max_files = getattr(cfg.step3, "max_files_per_chunk", 25)
    char_cap = _char_budget(cfg)
    if not max_loc and char_cap is None:
        return
    repo_root = Path(ctx.repo_root)

    out: list[Chunk] = []
    for c in manifest.chunks:
        # Taint chunks carry `source_ref`/`sink_ref`/`path_funcs` that name a
        # SPECIFIC entry→sink pair; re-packing one with the generic cohesion
        # splitter would `model_copy` that metadata onto shards that hold
        # neither the source nor the sink file, telling s4 the wrong thing.
        # An oversize taint chunk stays whole — s4's own sliding-window /
        # function-slice logic is what handles it, not this splitter.
        if c.id.startswith("taint-"):
            out.append(c)
            continue
        loc = sum(_count_loc(repo_root / f) for f in c.files)
        if char_cap is not None:
            chars = sum(_count_chars(repo_root / f) for f in c.files)
            fits = chars <= char_cap and len(c.files) <= max_files
            cap_txt = f"{char_cap} chars (~{char_cap//4} tok)"
            got_txt = f"{chars} chars"
        else:
            fits = loc <= max_loc and len(c.files) <= max_files
            cap_txt = f"{max_loc} LOC"
            got_txt = f"{loc} LOC"
        if fits:
            c.size = _size_for(loc)
            out.append(c)
            continue
        groups = _cohesive_groups(c.files, ctx, max_groups=_max_cohesion_groups(cfg))
        buckets = _pack(groups, repo_root, max_loc, max_files,
                        max_chars=char_cap,
                        merge_underfilled=_merge_underfilled(cfg))
        print(f"    [s3] {c.id}: {got_txt} / {len(c.files)} files > cap "
              f"({cap_txt} / {max_files} files) → split into {len(buckets)}",
              file=sys.stderr)
        for i, (_, files, bloc) in enumerate(buckets):
            suffix = chr(ord("a") + i) if i < 26 else str(i + 1)
            out.append(c.model_copy(update={
                "id": f"{c.id}-{suffix}",
                "files": files,
                "size": _size_for(bloc),
            }))
    manifest.chunks = out


def _pack(groups: list[tuple[str, list[str]]], repo_root: Path,
          max_loc: int, max_files: int, *,
          max_chars: int | None = None,
          merge_underfilled: bool = True) -> list[tuple[str, list[str], int]]:
    """Split each group into (label, files, loc) buckets.

    Shard boundary is decided by `max_chars` (bytes ≈ tokens×4) when given,
    otherwise by `max_loc` — so step3.pack_by switches the metric without
    touching callers. The returned `loc` is always real line count so
    `_size_for()` and the LOC distribution report stay correct in both modes.
    Groups that shard into N>1 buckets get a `[shard k/N]` label suffix.

    The per-group loop below emits at least one bucket PER GROUP and never
    back-fills, so on its own the bucket count tracks GROUP count rather than
    code volume: a repo whose cohesion groups are mostly small directories
    yields dozens of buckets with a median fill far under the cap, and each
    bucket costs one s4 model call per lens. `merge_underfilled` (default on,
    kill switch `step3.pack_merge_underfilled`) folds ADJACENT under-filled
    buckets back together afterwards — see :func:`_coalesce_underfilled`."""
    use_chars = max_chars is not None
    out: list[tuple[str, list[str], int]] = []
    for label, files in groups:
        shards: list[tuple[list[str], int]] = []
        b_files: list[str] = []
        b_loc = b_chars = 0
        for f in files:
            loc = _count_loc(repo_root / f)
            chars = _count_chars(repo_root / f) if use_chars else 0
            over = ((b_chars + chars > max_chars) if use_chars
                    else (b_loc + loc > max_loc))
            if b_files and (over or len(b_files) >= max_files):
                shards.append((b_files, b_loc))
                b_files, b_loc, b_chars = [], 0, 0
            b_files.append(f)
            b_loc += loc
            b_chars += chars
        if b_files:
            shards.append((b_files, b_loc))
        n = len(shards)
        for k, (bf, bl) in enumerate(shards, 1):
            lbl = label if n == 1 else f"{label} [shard {k}/{n}]"
            # The cap check above runs BEFORE a file is added, so a bucket can
            # only ever exceed the cap when it holds exactly one file whose
            # own size already exceeds it — unsplittable by construction.
            # Every other bucket, of any size, is capped correctly. Log the
            # unavoidable case so an operator can see it happened instead of
            # it being silently absorbed into the LOC/char distribution report.
            over_cap = ((bl > max_loc) if not use_chars else
                       (_count_chars(repo_root / bf[0]) > max_chars if bf else False))
            if len(bf) == 1 and over_cap:
                print(f"    [s3] {bf[0]}: single file exceeds the shard cap "
                      f"alone ({bl} LOC) — kept whole, not split further",
                      file=sys.stderr)
            out.append((lbl, bf, bl))
    if merge_underfilled and len(out) > 1:
        out = _coalesce_underfilled(out, repo_root, max_loc, max_files,
                                    max_chars=max_chars)
    COUNTERS.bump("s3_buckets", len(out))
    return out


def _coalesce_underfilled(buckets: list[tuple[str, list[str], int]],
                          repo_root: Path, max_loc: int, max_files: int, *,
                          max_chars: int | None = None
                          ) -> list[tuple[str, list[str], int]]:
    """Fold consecutive under-filled buckets together while the union still
    respects every cap.

    Merging is ADJACENT-only, deliberately: the group order coming out of
    `_cohesive_groups` keeps call-graph components and directory siblings
    next to each other, so a greedy fold over neighbours preserves that
    locality — grouping keeps deciding WHICH files sit together, and the
    caps alone decide HOW MANY buckets that takes. Reordering buckets to
    bin-pack tighter would trade that locality for a marginal count win.

    The cap checks mirror `_pack`'s own: `max_chars` decides the boundary
    when given (pack_by: tokens), else `max_loc`, and `max_files` binds in
    both modes. A single file that alone exceeds the cap arrived here as a
    one-file bucket whose running total already breaches the cap, so nothing
    ever merges into it and it never merges forward — it stays isolated
    (its warning was already printed by `_pack`). Files are concatenated in
    bucket order, so the flattened file sequence is bit-identical to the
    unmerged output: nothing is dropped, duplicated, or reordered.

    Chars are re-derived per file rather than threaded through from `_pack`
    because its shards only carry (files, loc); `_count_chars` is a memoised
    stat(), so the re-derivation costs no additional I/O."""
    use_chars = max_chars is not None
    # accumulator entries: (labels, files, loc, chars)
    merged: list[tuple[list[str], list[str], int, int]] = []
    for lbl, files, loc in buckets:
        chars = (sum(_count_chars(repo_root / f) for f in files)
                 if use_chars else 0)
        if merged:
            labels, cf, cl, cc = merged[-1]
            over = ((cc + chars > max_chars) if use_chars
                    else (cl + loc > max_loc))
            if not over and len(cf) + len(files) <= max_files:
                merged[-1] = (labels + [lbl], cf + files, cl + loc, cc + chars)
                continue
        merged.append(([lbl], list(files), loc, chars))
    out: list[tuple[str, list[str], int]] = []
    for labels, files, loc, _ in merged:
        # Keep the first label and record how many more groups folded in, so
        # the hypothesis text / shard label still says where a bucket came
        # from instead of silently presenting a merged bucket as one group.
        lbl = (labels[0] if len(labels) == 1
               else f"{labels[0]} (+{len(labels) - 1} more groups)")
        out.append((lbl, files, loc))
    return out


# Files that can't realistically carry an exploitable vuln. Dropped from
# catch-all coverage so 90+ chunks of docs/locks/snapshots don't get scanned.
# Credential-prone configs (.env, .npmrc, .yarnrc, *.key/pem/p12…) are KEPT.
_CATCHALL_SKIP_EXTS = {
    ".md", ".mdx", ".txt", ".rst", ".adoc",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
    ".css", ".scss", ".sass", ".less",
    ".lock", ".log", ".map", ".min.js", ".min.css",
    ".snap", ".d.ts",
    ".csv", ".tsv", ".xls", ".xlsx",
    ".po", ".pot", ".mo",
}
_CATCHALL_SKIP_NAMES = {
    "license", "changelog", "changes", "authors", "contributors", "notice",
    "readme", "codeowners", ".gitignore", ".gitattributes", ".editorconfig",
    ".prettierrc", ".prettierignore", ".eslintignore", ".dockerignore",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "go.sum", "cargo.lock", "composer.lock",
}
_CATCHALL_SKIP_DIR_PARTS = {
    "__snapshots__", "__fixtures__", "fixtures", "__mocks__", "mocks",
    "docs", "doc", "examples", "example", "samples",
}


def _catchall_eligible(rel: str) -> bool:
    p = Path(rel)
    name = p.name.lower()
    if name in _CATCHALL_SKIP_NAMES:
        return False
    # Match either the single final suffix (".js") or any trailing
    # multi-suffix tail (".min.js") against the skip set. A bare
    # ``suffixes in SET`` check missed multi-dotted names like
    # ``foo.bundle.min.js`` whose full joined suffixes (".bundle.min.js")
    # is not itself a skip key — so test every trailing dotted tail.
    name = p.name.lower()
    if p.suffix.lower() in _CATCHALL_SKIP_EXTS:
        return False
    if any(name.endswith(ext) for ext in _CATCHALL_SKIP_EXTS):
        return False
    if any(part.lower() in _CATCHALL_SKIP_DIR_PARTS for part in p.parts[:-1]):
        return False
    return True


# Extension-less / multi-dot convention filenames with no entry in
# EXT_TO_LANG. Without this, every one of these is permanently
# language-`None`, which excludes it from the `unknown_lang_files` fail-safe
# below (that fail-safe requires a KNOWN-but-uncovered language) and leaves
# it correctly classified as "language unknown" forever — even though the
# name alone tells a human reviewer exactly what it is.
_BASENAME_LANG: dict[str, str] = {
    "makefile": "make", "dockerfile": "docker", "jenkinsfile": "groovy",
    "procfile": "shell", "gemfile": "ruby", "rakefile": "ruby",
    "cmakelists.txt": "cmake",
}
_SHEBANG_LANG_RX = re.compile(
    r"^#!\S*/(?:env\s+)?(python\d?|bash|sh|zsh|ruby|perl|node)\b"
)
_SHEBANG_TO_LANG = {
    "python": "python", "python3": "python", "bash": "shell", "sh": "shell",
    "zsh": "shell", "ruby": "ruby", "perl": "perl", "node": "javascript",
}


def _lang_of_file(f: str, repo_root: Path | None = None) -> str | None:
    """Language for a repo-relative path, or None if unknown.

    Extension lookup first (zero I/O, covers the vast majority of files).
    Falls back to a basename table for well-known extension-less convention
    names, then — only when `repo_root` is supplied, and only for a file
    that already failed both cheaper checks — a first-line shebang read.
    That read is the only I/O this function ever does, and only fires for
    the minority of files neither check resolves."""
    p = PurePosixPath(f)
    ext = p.suffix.lower()
    lang = EXT_TO_LANG.get(ext)
    if lang:
        return lang
    name = p.name.lower()
    if name in _BASENAME_LANG:
        return _BASENAME_LANG[name]
    if name.startswith(".env"):
        return "dotenv"
    if repo_root is not None:
        try:
            with (repo_root / f).open("r", encoding="utf-8", errors="replace") as fh:
                first_line = fh.readline()
        except OSError:
            first_line = ""
        m = _SHEBANG_LANG_RX.match(first_line)
        if m:
            return _SHEBANG_TO_LANG.get(m.group(1))
    return None


def _reachable_files(ctx: ContextPackage) -> set[str]:
    """
    File-level reachability set for ``step3.catchall_mode: reachable_only``.

    A file is *reachable* iff it lies on the forward closure from any
    ``EntryPoint.file`` OR the backward closure to any ``Sink.file`` over a
    file-level projection of ``ctx.call_graph`` (whose nodes are already
    file-qualified ``path::name``). This is intentionally coarser than the
    function-level taint walk — for catch-all gating we only need to decide
    *which files* might sit on an attacker-controlled data path, not which
    functions. Full BFS (no hop cap): the file graph has ≤ len(all_files)
    nodes, so it's cheap.

    Conservative biases (all widen the set, never shrink it):
      • every EntryPoint.file and Sink.file is always reachable, even if the
        call graph never mentions it;
      • polymorphic defs: any file listed in ``ctx.call_graph_files[name]``
        for a reachable function name is pulled in too, so an interface call
        keeps every implementation file in scope.
    """
    fwd: dict[str, set[str]] = defaultdict(set)
    rev: dict[str, set[str]] = defaultdict(set)
    for caller, callees in (ctx.call_graph or {}).items():
        cf = q_file(caller)
        for callee in callees or ():
            tf = q_file(callee)
            if cf and tf and cf != tf:
                fwd[cf].add(tf)
                rev[tf].add(cf)

    # Polymorphic widening: bare-name → all def-site files. If file F calls
    # bare name N, treat F → every file that defines N.
    name_to_files: dict[str, set[str]] = defaultdict(set)
    for name, sites in (ctx.call_graph_files or {}).items():
        bare = q_name(name)
        for ref in sites or ():
            f = ref.split(":", 1)[0]
            if f:
                name_to_files[bare].add(f)
    for caller, callees in (ctx.call_graph or {}).items():
        cf = q_file(caller)
        if not cf:
            continue
        for callee in callees or ():
            for tf in name_to_files.get(q_name(callee), ()):
                if tf != cf:
                    fwd[cf].add(tf)
                    rev[tf].add(cf)

    def _bfs(seeds: set[str], graph: dict[str, set[str]]) -> set[str]:
        seen = set(seeds)
        frontier = list(seeds)
        while frontier:
            nxt: list[str] = []
            for n in frontier:
                for m in graph.get(n, ()):
                    if m not in seen:
                        seen.add(m)
                        nxt.append(m)
            frontier = nxt
        return seen

    ep_files = {e.file for e in ctx.entry_points if e.file}
    sk_files = {s.file for s in ctx.unsafe_sinks if s.file}
    # s0 codeFlow evidence: any file semgrep placed on a source→sink path is
    # reachable by construction, regardless of whether the call-graph (which
    # is blind to reflection/DI/dynamic dispatch) has an edge for it. This is
    # widen-only — it can never shrink the set.
    seed_files = seed_reachable_files(ctx.seed_taint_paths)

    # Fail-safe for language coverage: the call graph is built only for the
    # languages the s0 engine has plugins for (6 of ~42). Files in a language
    # that contributed *zero* graph nodes are structurally absent from the
    # closures above and would be labelled unreachable purely for lack of a
    # parser — an unknown, not a proven-unreachable, state. Treat such files as
    # reachable so reachable_only never drops a whole language. This is
    # widen-only; a language that DID contribute nodes is still pruned normally.
    #
    # `covered_langs` must be derived ONLY from files the call-graph engine
    # itself produced a node for (`ctx.call_graph`/`ctx.call_graph_files`) —
    # NOT from `ep_files`/`sk_files`/`seed_files`. Entry points and sinks come
    # from a separate detector (an LLM-driven mapper, or S0's static rules)
    # that can register a file in a language the deterministic graph engine
    # never parsed at all. Seeding the language-coverage check with those
    # files made the fail-safe backwards: ONE entry point in language X was
    # enough to mark X "covered," so every OTHER unreachable file in X lost
    # the fail-safe it most needed — the one case where the graph engine has
    # genuinely zero real support for that language.
    graph_only_files: set[str] = set()
    for caller, callees in (ctx.call_graph or {}).items():
        if (cf := q_file(caller)):
            graph_only_files.add(cf)
        for callee in callees or ():
            if (tf := q_file(callee)):
                graph_only_files.add(tf)
    for sites in (ctx.call_graph_files or {}).values():
        for ref in sites or ():
            if (f := ref.split(":", 1)[0]):
                graph_only_files.add(f)
    repo_root = Path(ctx.repo_root)
    covered_langs = {lang for f in graph_only_files
                     if (lang := _lang_of_file(f, repo_root))}
    unknown_lang_files = {
        f for f in ctx.all_files
        if (lang := _lang_of_file(f, repo_root)) is not None
        and lang not in covered_langs
    }

    return (_bfs(ep_files, fwd) | _bfs(sk_files, rev)
            | ep_files | sk_files | seed_files | unknown_lang_files)


def _reachable_only_too_sparse(reachable_count: int, total_count: int, cfg) -> tuple[bool, str]:
    """Return True when reachable-only coverage is too sparse to trust.

    Taint profiles use reachable-only to save tokens, but an under-built graph
    should fail open rather than exclude most catch-all review. Both thresholds
    default to disabled for backwards compatibility; taint profiles opt in.
    """
    if total_count <= 0:
        return False, ""
    step3 = getattr(cfg, "step3", None)
    min_ratio = float(getattr(step3, "catchall_reachable_min_ratio", 0.0) or 0.0)
    min_files = int(getattr(step3, "catchall_reachable_min_files", 0) or 0)
    ratio = reachable_count / total_count
    reasons: list[str] = []
    if min_ratio > 0 and ratio < min_ratio:
        reasons.append(f"reachable ratio {ratio:.0%} < {min_ratio:.0%}")
    if min_files > 0 and reachable_count < min_files:
        reasons.append(f"reachable files {reachable_count} < {min_files}")
    return bool(reasons), "; ".join(reasons)


def _add_catchall_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> int:
    """Create low-rank chunks for every file not already assigned to a chunk.

    Under `catchall_deduct_lens_coverage: true` a specialist chunk's file
    claim does NOT count as "covered" — a specialist lens (crypto,
    logic-bug, ...) is scoped guidance, not a generic review, so excluding
    it here would leave every specialist-claimed source file with no
    generic backstop at all. Risk/taint/threat-fallback claims still count.
    """
    deduct = bool(getattr(cfg.step3, "catchall_deduct_lens_coverage", False))
    covered: set[str] = set()
    for c in manifest.chunks:
        if deduct and c.specialist:
            continue
        covered.update(c.files)
    uncovered = [f for f in ctx.all_files if f not in covered]
    if not getattr(cfg.step3, "catchall_enabled", True):
        print(f"    [s3] coverage: {len(uncovered)} uncovered files — "
              f"catch-all DISABLED (step3.catchall_enabled: false)",
              file=sys.stderr)
        return 0
    eligible = [f for f in uncovered if _catchall_eligible(f)]

    # Drop any catch-all candidate that is NOT forward-reachable from an
    # entry point NOR backward-reachable from a sink on the file-level call
    # graph. Dropped files are recorded on the manifest for the report
    # appendix — coverage is auditable, not silently truncated. Falls back
    # to legacy `all` when there are no entry points/sinks (gating would
    # otherwise drop the whole repo).
    mode = str(getattr(cfg.step3, "catchall_mode", "all")).lower()
    if mode == "reachable_only" and eligible:
        if not (ctx.entry_points or ctx.unsafe_sinks):
            print("    [s3] catchall_mode=reachable_only but s0/s1 produced "
                  "0 entry points and 0 sinks — falling back to mode=all",
                  file=sys.stderr)
        else:
            reach = _reachable_files(ctx) & set(ctx.all_files)
            before = len(eligible)
            dropped = sorted(f for f in eligible if f not in reach)
            kept = [f for f in eligible if f in reach]
            # The sparsity ratio must be measured over every catch-all-eligible
            # file in the repo, not just the ones still `eligible` at this
            # point. Files that were reachable AND already covered by a taint
            # or risk chunk have already been removed from `eligible` — that's
            # WHY they got a chunk — so `eligible` alone is enriched for
            # unreachable files and a ratio computed over it underestimates
            # the graph's true reachable coverage, tripping the sparsity
            # fallback more often than the actual graph quality warrants.
            all_eligible = [f for f in ctx.all_files if _catchall_eligible(f)]
            all_reach_n = sum(1 for f in all_eligible if f in reach)
            too_sparse, sparse_reason = _reachable_only_too_sparse(
                all_reach_n, len(all_eligible), cfg)
            if too_sparse:
                manifest.unreachable_files = []
                print(f"    [s3] catchall_mode=reachable_only: "
                      f"{before} eligible → {len(kept)} reachable; "
                      f"falling back to mode=all ({sparse_reason})",
                      file=sys.stderr)
            else:
                # Non-source eligible files (.env, Makefile, foo/bar.conf) have
                # no specialist backstop at all — `logic-bug` only sweeps
                # `_is_source` files — so dropping one here under
                # reachable_only leaves it with ZERO reviewers, not merely a
                # cheaper review. Re-add exactly that minority; reachability
                # pruning stays in force for source files, which do have a
                # backstop.
                forced = [f for f in dropped if not _is_source(f)]
                if forced:
                    forced_set = set(forced)
                    kept = kept + forced
                    dropped = [f for f in dropped if f not in forced_set]
                    COUNTERS.bump("s3_forced_coverage_files", len(forced))
                    print(f"    [s3] forced coverage: {len(forced)} non-source "
                          f"eligible file(s) with no specialist backstop "
                          f"re-added despite reachable_only (e.g. "
                          f"{', '.join(forced[:5])})", file=sys.stderr)
                eligible = kept
                manifest.unreachable_files = dropped
                pct = (100 * len(dropped) / before) if before else 0
                sample = ", ".join(dropped[:5])
                if len(dropped) > 5:
                    sample += f", …(+{len(dropped) - 5})"
                print(f"    [s3] catchall_mode=reachable_only: "
                      f"{before} eligible → {len(eligible)} reachable "
                      f"({len(dropped)} dropped, {pct:.0f}% — listed in report "
                      f"appendix){'; e.g. ' + sample if dropped else ''}",
                      file=sys.stderr)

    if not eligible:
        if uncovered:
            print(f"    [s3] coverage: {len(uncovered)} uncovered files "
                  f"(all non-source → 0 catch-all chunks)", file=sys.stderr)
        return 0

    repo_root = Path(ctx.repo_root)
    max_loc = getattr(cfg.step3, "catchall_chunk_loc", 20000)
    max_files = getattr(cfg.step3, "catchall_max_files",
                        getattr(cfg.step3, "max_files_per_chunk", 100))
    base_rank = max((c.risk_rank for c in manifest.chunks), default=0)

    groups = _cohesive_groups(eligible, ctx, max_groups=_max_cohesion_groups(cfg))
    buckets = _pack(groups, repo_root, max_loc, max_files,
                    max_chars=_char_budget(cfg),
                    merge_underfilled=_merge_underfilled(cfg))

    for idx, (label, files, loc) in enumerate(buckets, 1):
        manifest.chunks.append(_mk_catchall(idx, label, files, loc, base_rank + idx))

    print(f"    [s3] coverage: {len(uncovered)} uncovered "
          f"→ {len(eligible)} eligible → {len(buckets)} catch-all chunks",
          file=sys.stderr)
    return len(buckets)


def _add_specialist_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> int:
    """
    Append repo-wide specialist passes (crypto, logic-bug). These see ALL source
    files regardless of risk-ranking — they hunt for cross-cutting bug classes
    that per-chunk language researchers miss.

    Sharding is module-aware (via _cohesive_groups) and restricted to actual
    source files so specialists don't waste budget on YAML/shell/markdown.
    """
    enabled = getattr(cfg.step3, "specialists", None)
    if enabled is None:
        enabled = ["crypto", "logic-bug"]
    source = [f for f in ctx.all_files if _is_source(f)]
    enabled = _gate_specialists(enabled, ctx, source)
    if not enabled:
        print("    [s3] specialists: all gated off (no matching surface)", file=sys.stderr)
        return 0
    if not source:
        print("    [s3] specialists: 0 source files after filtering", file=sys.stderr)
        return 0

    repo_root = Path(ctx.repo_root)
    max_loc = getattr(cfg.step3, "specialist_chunk_loc", 6000)
    max_files = getattr(cfg.step3, "max_files_per_chunk", 25)
    char_cap = _char_budget(cfg)
    max_groups = _max_cohesion_groups(cfg)
    base_rank = max((c.risk_rank for c in manifest.chunks), default=0)
    file_func_index = _build_file_function_index(ctx)

    # Default bucketing covers all source and is shared by every lens except
    # `iac`, which narrows to its own IaC-only file set below.
    default_buckets = _pack(_cohesive_groups(source, ctx, max_groups=max_groups),
                            repo_root, max_loc, max_files,
                            max_chars=char_cap,
                            merge_underfilled=_merge_underfilled(cfg))

    n_added = 0
    # Shard-major, not lens-major: for each bucket, emit every unscoped
    # lens's chunk for THAT bucket consecutively (spec-crypto-01,
    # spec-logic-bug-01, spec-access-control-01, ... spec-crypto-02, ...)
    # instead of lens-major (every crypto shard, then every logic-bug shard).
    # All four unscoped lenses see the identical `default_buckets` file sets
    # either way — this only changes emission ORDER, so consecutive s4 calls
    # for the same shard share its SOURCE CODE prefix and can land inside one
    # cache TTL window instead of re-sending the same ~500k-token shard once
    # per lens. `shard_id` records the grouping so a consumer can assert it.
    unscoped = [s for s in enabled if s != "iac"]
    for shard, (label, files, loc) in enumerate(default_buckets, 1):
        shard_id = f"shard-{shard:02d}"
        focus = _specialist_focus_entry_points(files, file_func_index)
        langs = detect_languages(files, repo_root=repo_root)
        for spec in unscoped:
            manifest.chunks.append(_mk_specialist(
                spec, shard, label, files, loc, base_rank + n_added + 1,
                langs, focus, shard_id=shard_id))
            n_added += 1

    if "iac" in enabled:
        iac_source = [f for f in source if is_iac_file(f)]
        if not iac_source:
            print("    [s3] specialist 'iac' has 0 IaC files in source — skipped",
                  file=sys.stderr)
        else:
            iac_buckets = _pack(_cohesive_groups(iac_source, ctx, max_groups=max_groups),
                                repo_root, max_loc, max_files,
                                max_chars=char_cap,
                                merge_underfilled=_merge_underfilled(cfg))
            print(f"    [s3] specialist 'iac': scoped to {len(iac_source)} "
                  f"IaC file(s) → {len(iac_buckets)} shard(s)",
                  file=sys.stderr)
            for shard, (label, files, loc) in enumerate(iac_buckets, 1):
                focus = _specialist_focus_entry_points(files, file_func_index)
                manifest.chunks.append(_mk_specialist(
                    "iac", shard, label, files, loc, base_rank + n_added + 1,
                    detect_languages(files, repo_root=repo_root), focus,
                    shard_id=f"iac-shard-{shard:02d}"))
                n_added += 1

    print(f"    [s3] specialists: {', '.join(enabled)} -> {n_added} chunks "
          f"({len(source)}/{len(ctx.all_files)} source files)",
          file=sys.stderr)
    return n_added


_CRYPTO_RX = re.compile(
    r"\b(AES|RSA|HMAC|SHA-?(1|2|256|384|512)|MD5|PBKDF2|bcrypt|scrypt|argon2"
    r"|Cipher|KeyPair|SecretKey|X509|PKCS|TLS|SSLContext|jwt|jose|nacl|sodium"
    r"|hashlib|hmac\.|cryptography\.|javax\.crypto|BouncyCastle|OpenSSL"
    r"|Crypt::|Digest::|Mcrypt|RandomNumberGenerator|SecureRandom)\b",
    re.IGNORECASE,
)

_DESER_RX = re.compile(
    r"\b(ObjectInputStream|readObject|XMLDecoder|XStream|SnakeYAML|yaml\.load"
    r"|pickle\.|marshal\.load|unserialize|BinaryFormatter|Kryo|Hessian"
    r"|JdkSerializationRedisSerializer|Marshal\.load)\b",
)

_BATCH_ETL_RX = re.compile(
    r"\b(struct\.(?:un)?pack|codecs\.(?:encode|decode)\([^)]*ebcdic"
    r"|cp037|cp1047|COMP-3|packed[_-]?decimal|RECFM|LRECL"
    r"|glob\.glob|os\.listdir|shutil\.(?:move|copy)|csv\.(?:writer|reader)"
    r"|EXEC\s+PGM=|//\w+\s+DD\b|DISP=\()\b",
    re.IGNORECASE,
)

# Matches literal credential/key values in source and config files.
# The pattern looks for an assignment to a security-sensitive key name followed
# by a non-placeholder string value (not an env-var reference or empty string).
_HARDCODED_CREDS_RX = re.compile(
    r"(?:"
    # ── assignment / YAML colon ──────────────────────────────────────────
    r"(?:SECRET_KEY|password|passwd|api[_-]?key|access[_-]?key|secret[_-]?key"
    r"|auth[_-]?token|jwt[_-]?secret|signing[_-]?key|private[_-]?key"
    r"|encryption[_-]?key|database[_-]?url|connection[_-]?string)"
    r"\s*[=:]\s*['\"](?!\s*\$\{)[^'\"]{4,}"
    r"|"
    # ── equality comparison: `if password == 'literal'` ──────────────────
    # Narrowed to password|passwd|username — `user` and `name` are too
    # common in non-credential contexts (menu items, role labels, etc.) and
    # would cause the gate to fire on repos with no hardcoded credentials.
    r"(?:password|passwd|username)"
    r"\s*==\s*['\"][^'\"]{3,}['\"]"
    r"|"
    # ── dict/JSON quoted key: `'password': 'admin123'` ──────────────────
    r"['\"](?:password|passwd|secret[_-]?key)['\"]"
    r"\s*:\s*['\"](?!\s*\$\{)[^'\"]{4,}"
    r")",
    re.IGNORECASE,
)

# Matches CSRF-relevant framework patterns.
_CSRF_RX = re.compile(
    r"\b(csrf_exempt|CsrfViewMiddleware|CSRFProtect|csrf\.exempt"
    r"|csurf|csrf_token|protect_from_forgery|verify_authenticity_token"
    r"|@csrf|HttpPost|@PostMapping|@PutMapping|@DeleteMapping"
    r"|request\.method\s*==\s*['\"]POST['\"]"
    r"|csrf\.disable\(\))",
    re.IGNORECASE,
)

# Presence-only gate: S4 still has to prove attacker flow and missing defences.
_INJECTION_FAMILY_PATTERNS = {
    "sql-nosql": (
        r"\.(?:execute|executemany|executeQuery|executeUpdate|prepareStatement"
        r"|createQuery|createNativeQuery)\s*\("
        r"|\b(?:JdbcTemplate|NamedParameterJdbcTemplate)\s*\.\s*"
        r"(?:query|update|execute|queryForObject|queryForList)\s*\("
        r"|\b(?:session|db|Sequelize|knex)\s*\.\s*(?:query|raw)\s*\("
        r"|\$(?:queryRaw|queryRawUnsafe|executeRaw|executeRawUnsafe|where|function)\b"
        r"|\.(?:aggregate|extra)\s*\("
        r"|\b(?:mysqli_query|pg_query|mysql_query|find_by_sql)\s*\("
        r"|\b(?:GraphDatabaseService\.execute|Neo4j\w*\.run)\s*\("
    ),
    "command-code": (
        r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\("
        r"|\bos\.(?:system|popen|exec\w*)\s*\("
        r"|\bRuntime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("
        r"|\b(?:ProcessBuilder|Process\.Start|exec\.Command(?:Context)?)\s*\("
        r"|\bchild_process\.(?:exec|execSync|spawn)\s*\("
        r"|\b(?:shell_exec|passthru|proc_open|popen)\s*\("
        r"|\bOpen3\.(?:capture\w*|popen\w*)\s*\("
        r"|\b(?:eval|setTimeout|setInterval)\s*\("
        r"|\bnew\s+Function\s*\("
        r"|\b(?:GroovyShell|ScriptEngine)\w*\.\w*eval\w*\s*\("
        r"|\bshell\s*=\s*True\b"
    ),
    "ldap-xpath-xml": (
        r"\b(?:InitialDirContext|LdapContext|DirContext)\w*\.search\s*\("
        r"|\b(?:ldap\.(?:search|search_s)|Connection\.search)\s*\("
        r"|\b(?:XPathFactory|XPathExpression|XPath)\b"
        r"|\.(?:xpath|selectSingleNode|selectNodes)\s*\("
        r"|\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory"
        r"|TransformerFactory|SchemaFactory|XMLReader|DOMParser|XmlReader"
        r"|XmlDocument|Nokogiri::XML|lxml\.etree)\b"
        r"|\betree\.(?:parse|fromstring|XMLParser|XPath)\s*\("
        r"|\bresolve_entities\b"
    ),
    "ssrf": (
        r"\b(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\("
        r"|\b(?:urllib\.request|urllib3|http\.client|aiohttp\.ClientSession)\b"
        r"|\b(?:RestTemplate|WebClient|HttpClient|HttpURLConnection|OkHttpClient"
        r"|GuzzleHttp|Net::HTTP|reqwest|ureq)\b"
        r"|\b(?:fetch|urlopen|file_get_contents|curl_exec)\s*\("
        r"|\bCURLOPT_URL\b"
        r"|\bhttp\.(?:Get|Post|NewRequest)\s*\("
        r"|\bClient\.Do\s*\("
        r"|\baxios\.\w+\s*\("
        r"|\.openConnection\s*\("
    ),
    "path-archive": (
        r"\b(?:java\.io\.File|Paths\.get|Path\.of|pathlib\.Path)\s*\("
        r"|\bFiles\.(?:newInputStream|newOutputStream|readAllBytes|readString|write)\s*\("
        r"|\bos\.path\.(?:join|abspath|realpath)\s*\("
        r"|\bfs\.(?:readFile|readFileSync|writeFile|createReadStream|createWriteStream)\s*\("
        r"|\b(?:sendFile|send_from_directory|fopen|unpack_archive)\s*\("
        r"|\b(?:ZipFile|TarFile)\.(?:extract|extractall)\s*\("
        r"|\b(?:ZipInputStream|TarArchiveInputStream)\b"
        r"|\bextractall\s*\("
    ),
    "template-xss": (
        r"\b(?:render_template_string|mark_safe|bypassSecurityTrustHtml)\s*\("
        r"|\bEnvironment\.from_string\s*\("
        r"|\b(?:Mako\w*\.)?Template\s*\("
        r"|\b(?:Velocity\.(?:evaluate|eval)|SpelExpressionParser|parseExpression"
        r"|Ognl\.(?:getValue|setValue)|JexlEngine|createExpression"
        r"|ELProcessor\.eval|ERB\.new|Handlebars\.compile|Mustache\.compile)\b"
        r"|\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|html_safe)\b"
        r"|\b(?:insertAdjacentHTML|document\.(?:write|writeln))\s*\("
        r"|\b(?:res\.(?:send|write|end)|Response\.Write)\s*\("
    ),
    "redirect-header": (
        r"\b(?:sendRedirect|redirect_to|Response\.Redirect)\s*\("
        r"|\b(?:res\.)?redirect\s*\("
        r"|\bRedirectView\s*\("
        r"|\b(?:setHeader|addHeader|headers\.set|Headers\.Add|set_cookie)\s*\("
    ),
    "regex": (
        r"\b(?:re|Pattern|Regex|regexp)\.(?:compile|Compile|MustCompile|new)\s*\("
        r"|\bnew\s+(?:RegExp|Regex)\s*\("
    ),
}
_INJECTION_RX = re.compile(
    "|".join(f"(?:{pattern})" for pattern in _INJECTION_FAMILY_PATTERNS.values()),
    re.IGNORECASE,
)


def _has_batch_surface(ctx: ContextPackage, repo_root: Path,
                       source: list[str]) -> bool:
    if any(ep.kind in {"file", "cli"} for ep in ctx.entry_points):
        return True
    langs = set(detect_languages(ctx.all_files, repo_root=repo_root))
    if langs & {"cobol", "jcl"}:
        return True
    return _scan_any(repo_root, source, _BATCH_ETL_RX)


def _scan_any(repo_root: Path, files: list[str], rx: re.Pattern) -> bool:
    for rel in files:
        p = repo_root / rel
        try:
            if rx.search(p.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


def _has_authz_surface(ctx: ContextPackage) -> bool:
    if ctx.app_profile and ctx.app_profile.externally_facing:
        return True
    if any(ep.kind in {"network", "ipc"} or ep.reachable_from_unauth
           for ep in ctx.entry_points):
        return True
    if any(c.kind == "auth" for c in ctx.design_controls):
        return True
    if ctx.threat_model:
        for t in ctx.threat_model.threats:
            if t.actor in {"remote_unauth", "remote_auth"}:
                return True
    return False


def _gate_specialists(enabled: list[str], ctx: ContextPackage,
                      source: list[str]) -> list[str]:
    """Drop specialist passes whose target surface doesn't exist in this repo,
    so s4/s5 don't burn budget verifying guaranteed-FP findings."""
    repo_root = Path(ctx.repo_root)
    gates = {
        "access-control":    lambda: _has_authz_surface(ctx),
        "crypto":            lambda: _scan_any(repo_root, source, _CRYPTO_RX),
        "deserialization":   lambda: _scan_any(repo_root, source, _DESER_RX),
        "batch-etl":         lambda: _has_batch_surface(ctx, repo_root, source),
        "iac":               lambda: any(is_iac_file(f) for f in ctx.all_files),
        # hardcoded-creds: only add the specialist pass when literal credential
        # values are actually present (avoids false-alarm budget on pure-IaC
        # or generated-code repos that have no config files with secrets).
        "hardcoded-creds":   lambda: _scan_any(repo_root, source, _HARDCODED_CREDS_RX),
        # csrf: gate on presence of web-framework routing patterns or explicit
        # csrf decorators so non-web repos don't get this pass.
        "csrf":              lambda: _has_authz_surface(ctx) or _scan_any(repo_root, source, _CSRF_RX),
        # injection: gate on presence of at least one injection-family sink
        # (SQL/NoSQL/shell/LDAP/XPath/XML/HTTP-client/file/SSTI/redirect/regex),
        # so pure-library or pure-data repos with no such sink don't get this
        # pass. Broad by design — most web/CLI apps carry at least one.
        "injection":         lambda: _scan_any(repo_root, source, _INJECTION_RX),
        # sensitive-data and log-injection: always on for any app with entry
        # points; no surface-specific gate needed (cost is proportional to LOC).
        "sensitive-data":    lambda: bool(ctx.entry_points),
        "log-injection":     lambda: bool(ctx.entry_points),
    }
    kept: list[str] = []
    for spec in enabled:
        gate = gates.get(spec)
        if gate is None or gate():
            kept.append(spec)
        else:
            print(f"    [s3] specialist '{spec}' gated OFF — no matching surface in repo",
                  file=sys.stderr)
    return kept


def _mk_specialist(spec: str, shard: int, label: str, files: list[str], loc: int,
                   rank: int, langs: list[str],
                   focus: list[str], shard_id: str = "") -> Chunk:
    return Chunk(
        id=f"spec-{spec}-{shard:02d}",
        size=_size_for(loc),
        risk_rank=rank,
        files=files,
        focus_entry_points=focus,
        hypothesis=f"{spec} specialist sweep over module '{label}'.",
        related_cves=[],
        languages=langs,
        specialist=spec,
        shard_id=shard_id,
    )


def _build_file_function_index(ctx: ContextPackage) -> dict[str, list[str]]:
    """file -> [function names defined in it], built ONCE per s3 run from
    ``ctx.call_graph_files``.

    ``_specialist_focus_entry_points`` used to scan the entire
    ``call_graph_files`` dict per shard per lens — with 4 unscoped lenses
    sharing the same shard set, that is 4 redundant repo-wide scans per
    shard. Building the reverse index once and looking files up in it turns
    that into one scan total."""
    idx: dict[str, list[str]] = defaultdict(list)
    for fn, locs in (ctx.call_graph_files or {}).items():
        seen_files: set[str] = set()
        for ref in (locs or ()):
            f = ref.rpartition(":")[0] if ":" in ref else ref
            if f and f not in seen_files:
                seen_files.add(f)
                idx[f].append(fn)
    return idx


def _specialist_focus_entry_points(files: list[str],
                                   file_func_index: dict[str, list[str]],
                                   cap: int = 24) -> list[str]:
    """Best-effort method anchors for specialist shards, read from the
    once-built `file -> [functions]` index; S4 uses these names to prioritize
    spans."""
    out: list[str] = []
    seen: set[str] = set()
    for f in files:
        for fn in file_func_index.get(f, ()):
            if fn in seen:
                continue
            seen.add(fn)
            out.append(fn)
            if len(out) >= cap:
                return out
    return out


def _mk_catchall(idx: int, dir_name: str, files: list[str], loc: int, rank: int) -> Chunk:
    return Chunk(
        id=f"catchall-{idx:02d}",
        size=_size_for(loc),
        risk_rank=rank,
        files=files,
        focus_entry_points=[],
        hypothesis=f"Coverage sweep of '{dir_name}' — files not assigned to any "
                   f"risk-ranked chunk. Hunt for any vulnerability class.",
        related_cves=[],
    )


def _report_chunk_loc(manifest: TaskManifest, ctx: ContextPackage, cfg) -> None:
    repo_root = Path(ctx.repo_root)
    locs = sorted(sum(_count_loc(repo_root / f) for f in c.files)
                  for c in manifest.chunks)
    if not locs:
        return
    n = len(locs)
    cap = getattr(cfg.step3, "risk_chunk_loc", 10_000) or 0
    over = sum(1 for x in locs if cap and x > cap)
    fmt = lambda x: f"{x/1000:.1f}k" if x >= 1000 else str(x)
    print(f"    [s3] chunk LOC: n={n} min={fmt(locs[0])} "
          f"p50={fmt(locs[n // 2])} p90={fmt(locs[min(n - 1, int(n * 0.9))])} "
          f"max={fmt(locs[-1])}"
          + (f"  ({over} over risk_chunk_loc={cap})" if cap else ""),
          file=sys.stderr)


_CHARS_CACHE: dict[str, int] = {}


def _count_chars(p: Path) -> int:
    """File size in bytes (≈ chars for source). stat() only — no read, so
    pack_by:tokens adds ~zero I/O over LOC mode even on 20k-file trees."""
    k = str(p)
    v = _CHARS_CACHE.get(k)
    if v is not None:
        return v
    try:
        v = p.stat().st_size
    except OSError:
        v = 0
    _CHARS_CACHE[k] = v
    return v


_LOC_CACHE: dict[str, int] = {}


def _count_loc(p: Path) -> int:
    """Line count, memoised the same way `_count_chars` already is.

    Keys on `str(p)`; `p` is always `repo_root / rel` and `repo_root` is
    absolute (`scan.py:184`), so the key is already absolute and there is no
    cross-repo collision hazard to guard against — the two functions can
    safely share the same caching idiom."""
    k = str(p)
    v = _LOC_CACHE.get(k)
    if v is not None:
        return v
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            v = sum(1 for _ in fh)
    except OSError:
        v = 0
    _LOC_CACHE[k] = v
    return v
