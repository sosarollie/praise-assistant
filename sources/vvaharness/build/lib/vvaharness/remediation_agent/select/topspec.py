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

"""remediation_agent.select.topspec — parse + resolve the ``--top N`` cap.

The ``--top N`` cap can come from a CLI flag (``--top 5`` / ``--top all``) or
the active profile (``step_remediate.top_n_findings``). This module owns the
coercion of either source into a positive int, the :data:`ALL_FINDINGS`
wildcard, or ``None`` (absent), plus the precedence rule that resolves the two
into the effective cap :func:`select_top_by_cvss` consumes."""
from __future__ import annotations

from typing import Sequence

# Wildcard sentinel for "no cap — remediate EVERY finding". Returned by the
# parsers when the user passes ``--top all`` / ``--top *`` (or sets
# ``top_n_findings: all`` / ``*`` in a profile). It is deliberately distinct
# from ``None`` ("flag/key absent → fall back to the profile") so a CLI
# ``--top all`` can OVERRIDE a numeric profile cap. The accepted spellings:
ALL_FINDINGS = "all"
_ALL_TOKENS = frozenset({"all", "*"})


def _coerce_top_value(raw: str, *, source: str) -> int | str:
    """Coerce one raw ``--top`` / ``top_n_findings`` value to either a positive
    int or the :data:`ALL_FINDINGS` wildcard.

    *source* is a short label ("--top" / "top_n_findings") used only in error
    messages. Raises :class:`ValueError` on an empty / non-positive / unparseable
    value so the CLI parser can surface a clean usage error; the profile reader
    catches that and degrades to the wildcard instead."""
    token = (raw or "").strip().lower()
    if token in _ALL_TOKENS:
        return ALL_FINDINGS
    try:
        n = int(token)
    except (TypeError, ValueError):
        raise ValueError(
            f"{source} expects a positive integer or 'all'/'*', got {raw!r}")
    if n <= 0:
        raise ValueError(
            f"{source} must be a positive integer or 'all'/'*', got {n}")
    return n


def parse_top_arg(args: Sequence[str]) -> int | str | None:
    """Parse ``--top N`` / ``--top=N`` (or the ``all``/``*`` wildcard) from a
    raw argv slice.

    Returns the positive integer N, the :data:`ALL_FINDINGS` wildcard (for
    ``--top all`` / ``--top *`` — remediate every finding), or ``None`` when the
    flag is absent. Raises :class:`ValueError` when the flag is present but its
    value is missing, non-positive, or unparseable, so callers can surface a
    clean usage error and exit non-zero."""
    raw: str | None = None
    for i, a in enumerate(args):
        if a == "--top":
            if i + 1 >= len(args):
                raise ValueError(
                    "--top requires a value, e.g. --top 5 or --top all")
            raw = args[i + 1]
            break
        if a.startswith("--top="):
            raw = a.split("=", 1)[1]
            break
    if raw is None:
        return None
    return _coerce_top_value(raw, source="--top")


def cfg_top_n_findings(cfg) -> int | str | None:
    """Read the profile-driven top-N cap from ``step_remediate.top_n_findings``.

    This is the *source of truth* for how many findings remediation processes:
    the cap lives in the shipped profile (``vvaharness/config/profiles/*.yaml``),
    not in a CLI flag. Returns the positive integer cap, the :data:`ALL_FINDINGS`
    wildcard when the profile sets ``all`` / ``*`` / a non-positive value /
    ``null`` (all meaning "no cap — remediate every finding"), or ``None`` only
    when the ``step_remediate`` block is entirely absent. Garbage values degrade
    to the wildcard so a partial config never raises here."""
    sr = getattr(cfg, "step_remediate", None)
    if sr is None:
        return None
    raw = getattr(sr, "top_n_findings", None)
    if raw is None:
        # Key absent but block present → no cap (remediate everything).
        return ALL_FINDINGS
    try:
        return _coerce_top_value(str(raw), source="top_n_findings")
    except ValueError:
        # null / 0 / negative / unparseable in a profile → treat as wildcard
        # rather than crashing the run.
        return ALL_FINDINGS


def resolve_top(cli_top: int | str | None, cfg) -> int | None:
    """Resolve the effective top-N cap to what :func:`select_top_by_cvss` wants:
    a positive int (cap) or ``None`` (no cap — remediate every finding).

    Precedence mirrors the ``validate`` command (``--max-findings`` overrides
    ``step_validate.max_findings``): the CLI ``--top`` override wins when given,
    otherwise the profile's ``step_remediate.top_n_findings`` is the source of
    truth. The :data:`ALL_FINDINGS` wildcard (from ``--top all`` / ``*`` or the
    profile) collapses to ``None`` here so callers never need to know about the
    sentinel — but it still OVERRIDES a numeric profile cap when passed on the
    CLI, because it is distinct from ``None`` ("flag absent")."""
    chosen = cli_top if cli_top is not None else cfg_top_n_findings(cfg)
    if isinstance(chosen, int):
        return chosen
    # None ("flag/key absent") or the ALL_FINDINGS wildcard → no cap.
    return None
