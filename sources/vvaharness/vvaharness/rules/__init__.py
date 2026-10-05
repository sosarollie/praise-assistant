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
First-party CWE knowledge plus explicit external overlays.

``generic.kb.yaml``
    Per-CWE taint knowledge base — sources / sinks / sanitizers /
    non-sanitizers / FP-checks. Loaded by :class:`CweKB` and spliced into the
    s4 confirm/refute prompt so the verifier applies the same decision rules a
    human reviewer would, instead of relying on model recall.

``cwe_kb.yaml``
    Optional legacy baseline name. It is loaded when present but is not shipped
    by the distribution.

Adding a corpus
---------------
Keep ``<name>.kb.yaml`` outside the package with the ``entries:`` schema shown
in ``generic.kb.yaml``. :meth:`CweKB.load` accepts an ``overlays=`` argument
that splices such corpora onto the built-in KB. To wire an overlay into a scan,
set ``rules.kb_overlays`` in the config to the overlay path (or a list of
paths); s4 passes it through when building the confirm/refute prompt. The path
is operator-supplied and loaded with ``yaml.safe_load``. When
``rules.kb_overlays`` is unset, the scan loads the built-in KB only.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

from vvaharness.rules.families import norm_cwe as _norm_cwe

__all__ = ["CweKB", "RULES_DIR"]

RULES_DIR = Path(__file__).resolve().parent

# List-valued fields on a KB entry. Anything else is scalar metadata.
_LIST_KEYS = ("sources", "sinks", "sanitizers", "non_sanitizers", "fp_checks")

# ``"java: PreparedStatement…"`` — short lowercase token + ':' + space.
# Restrictive on purpose so a free-text item that merely contains ':' is NOT
# misread as a language tag.
_LANG_PREFIX_RX = re.compile(r"^([a-z][a-z0-9_+-]{0,15}):\s+(.+)$")


def _filter_lang(items: list[str], lang: str | None) -> list[str]:
    """Keep unprefixed items + items whose ``lang:`` prefix matches ``lang``;
    strip the prefix on the way out. ``lang=None`` keeps everything."""
    out: list[str] = []
    seen: set[str] = set()
    for it in items:
        m = _LANG_PREFIX_RX.match(it)
        if m:
            if lang is not None and m.group(1) != lang:
                continue
            it = m.group(2)
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


class CweKB:
    """In-memory, merge-on-load CWE knowledge base.

    One instance per process (cached behind :func:`load`). Never raises into
    the pipeline — a missing/unreadable KB degrades to an empty instance and
    :func:`prompt_block` returns ``""`` so the s4 prompt is byte-identical to
    the pre-KB behaviour.
    """

    def __init__(self, by_cwe: dict[str, dict]):
        self._by_cwe = by_cwe

    def __len__(self) -> int:
        return len(self._by_cwe)

    def __contains__(self, cwe) -> bool:
        c = _norm_cwe(cwe)
        return c is not None and c in self._by_cwe

    _cache: "CweKB | None" = None

    @classmethod
    def load(cls, rules_dir: Path | None = None, *,
             overlays=None, include_all_extras: bool = False) -> "CweKB":
        """Load + merge the baseline CWE KB and optional overlays.

        Default runtime loading includes only ``cwe_kb.yaml`` (legacy, when
        present) plus ``generic.kb.yaml``. Org-specific files load only when
        passed via ``overlays`` on the default path. Passing an explicit
        ``rules_dir`` is a maintainer/test workflow and auto-merges every
        ``*.kb.yaml`` in that directory; ``include_all_extras`` keeps that
        behavior available without changing the directory.
        """
        use_default = rules_dir is None
        overlay_list = cls._overlay_list(overlays)
        cacheable = use_default and not overlay_list and not include_all_extras
        if cacheable and cls._cache is not None:
            return cls._cache
        d = Path(rules_dir) if rules_dir else RULES_DIR
        merged: dict[str, dict] = {}
        include_extras = include_all_extras or (rules_dir is not None)
        for p in cls._kb_files(d, overlays=overlay_list,
                               include_all_extras=include_extras):
            for entry in cls._read(p):
                cls._merge(merged, entry)
        kb = cls(merged)
        if cacheable:
            cls._cache = kb
        return kb

    @staticmethod
    def _overlay_list(overlays) -> list[str]:
        if overlays is None:
            return []
        if isinstance(overlays, (str, Path)):
            return [str(overlays)]
        return [str(p) for p in overlays if str(p).strip()]

    @staticmethod
    def _kb_files(d: Path, *, overlays=None,
                  include_all_extras: bool = False) -> list[Path]:
        if not d.is_dir():
            return []
        files: list[Path] = []
        # Built-ins first so their titles define the generic security class.
        for name in ("cwe_kb.yaml", "generic.kb.yaml"):
            p = d / name
            if p.is_file() and p not in files:
                files.append(p)
        if include_all_extras:
            for p in sorted(x for x in d.glob("*.kb.yaml") if x.is_file()):
                if p not in files:
                    files.append(p)
        for raw in CweKB._overlay_list(overlays):
            p = Path(raw)
            if not p.is_absolute():
                candidate = d / p
                p = candidate if candidate.is_file() else p
            if p.is_file() and p not in files:
                files.append(p)
        return files

    @staticmethod
    def _read(p: Path) -> list[dict]:
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as e:  # never abort the scan
            print(f"  [kb] WARN: failed to load {p.name}: {e}", file=sys.stderr)
            return []
        entries = doc.get("entries") if isinstance(doc, dict) else None
        return [e for e in (entries or []) if isinstance(e, dict)]

    @staticmethod
    def _merge(acc: dict[str, dict], entry: dict) -> None:
        cwe = _norm_cwe(entry.get("cwe"))
        if not cwe:
            return
        slot = acc.setdefault(cwe, {"cwe": cwe, "title": "", "origin": [],
                                    **{k: [] for k in _LIST_KEYS}})
        if not slot["title"]:
            slot["title"] = str(entry.get("title") or "")
        origin = str(entry.get("origin") or "")
        if origin and origin not in slot["origin"]:
            slot["origin"].append(origin)
        for k in _LIST_KEYS:
            for v in entry.get(k) or ():
                v = str(v).strip()
                if v and v not in slot[k]:
                    slot[k].append(v)
        # An alias CWE shares the same slot object — so a chunk tagged with
        # the alias resolves to the canonical entry.
        for a in entry.get("aliases") or ():
            an = _norm_cwe(a)
            if an and an not in acc:
                acc[an] = slot

    def for_cwes(self, cwes, lang: str | None = None) -> dict:
        """Return a merged ``{title, origin, sources, sinks, sanitizers,
        non_sanitizers, fp_checks}`` dict for one or more CWE ids, language-
        filtered. Unknown CWEs are skipped; an empty result has empty lists."""
        if isinstance(cwes, str):
            cwes = [cwes]
        out = {"cwe": [], "title": [], "origin": [],
               **{k: [] for k in _LIST_KEYS}}
        seen_slots: set[int] = set()
        for c in cwes or ():
            cn = _norm_cwe(c)
            slot = self._by_cwe.get(cn) if cn else None
            if slot is None or id(slot) in seen_slots:
                continue
            seen_slots.add(id(slot))
            out["cwe"].append(slot["cwe"])
            if slot["title"]:
                out["title"].append(slot["title"])
            for o in slot["origin"]:
                if o not in out["origin"]:
                    out["origin"].append(o)
            for k in _LIST_KEYS:
                for v in _filter_lang(slot[k], lang):
                    if v not in out[k]:
                        out[k].append(v)
        return out

    def prompt_block(self, cwes, lang: str | None = None,
                     limit: int = 20) -> str:
        """Render a compact text block for the s4 confirm/refute prompt.
        Returns ``""`` when nothing is known for ``cwes`` so callers can splice
        unconditionally."""
        ctx = self.for_cwes(cwes, lang)
        if not any(ctx[k] for k in _LIST_KEYS):
            return ""
        title = " / ".join(ctx["title"]) or ", ".join(ctx["cwe"])
        head = f"TAINT KB — {title}"
        if ctx["origin"]:
            head += f"  (origin: {', '.join(ctx['origin'])})"
        lines = [head]
        labels = (
            ("sanitizers",
             "SANITIZERS — if ANY of these sits on the path, REFUTE:"),
            ("non_sanitizers",
             "NON-SANITIZERS — these look safe but are NOT; do NOT refute on "
             "their basis alone:"),
            ("fp_checks",
             "FP CHECKS — if ANY is true, REFUTE:"),
            ("sinks",
             "KNOWN SINKS — for reference; the candidate sink should match "
             "one of these shapes:"),
        )
        for key, label in labels:
            items = ctx[key][:limit]
            if not items:
                continue
            lines.append(f"  {label}")
            lines.extend(f"    - {it}" for it in items)
            if len(ctx[key]) > limit:
                lines.append(f"    - …(+{len(ctx[key]) - limit} more)")
        return "\n".join(lines) + "\n"
