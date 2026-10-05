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

"""remediation_agent.interactive.render — menu rendering + selection parsing.

:func:`render_rows` builds the one-line-per-finding table (pure, so tests assert
it without a terminal); :func:`_clear_and_draw` paints the arrow-key TUI frame;
:func:`parse_selection` parses a numbered-prompt selection (the non-TTY
fallback) into 0-based positions."""
from __future__ import annotations

import re

_GREEN, _CYAN, _DIM, _INV, _RST = (
    "\033[32m", "\033[36m", "\033[2m", "\033[7m", "\033[0m")


def render_rows(findings, *, cursor: int | None = None) -> list[str]:
    """Return the menu rows (one string per finding). *cursor* highlights a row
    for the arrow-key UI; pass None for the plain numbered list. Pure function
    so tests can assert the table without a terminal."""
    rows = []
    for i, f in enumerate(findings):
        mark = f"{_GREEN}✅{_RST}" if f.done else "  "
        line = f"{f.index:>3}  {mark}  [{f.severity:<8}] {f.title}"
        if f.file:
            line += f"  {_DIM}({f.file}){_RST}"
        if cursor is not None and i == cursor:
            line = f"{_INV}❯ {line}{_RST}"
        else:
            line = f"  {line}"
        rows.append(line)
    return rows


def _clear_and_draw(findings, cursor: int, out) -> None:
    n_done = sum(1 for f in findings if f.done)
    out.write("\033[2J\033[H")  # clear screen, home cursor
    out.write(f"  Remediation Agent remediation — {len(findings)} issue(s), "
              f"{n_done} done\n")
    out.write(f"  {_DIM}↑/↓ move · Enter remediate · q quit{_RST}\n\n")
    for row in render_rows(findings, cursor=cursor):
        out.write(row + "\n")
    out.flush()


def parse_selection(text: str, findings) -> list[int] | None:
    """Parse a numbered-prompt selection into a list of 0-based positions in
    *findings*. Returns None to signal quit. Accepts ``all``, ``pending`` (only
    not-done), comma/space lists and ``a-b`` ranges referencing finding INDEX."""
    t = (text or "").strip().lower()
    if t in ("q", "quit", "exit", ""):
        return None
    if t == "all":
        return list(range(len(findings)))
    if t == "pending":
        return [i for i, f in enumerate(findings) if not f.done]

    by_index = {f.index: i for i, f in enumerate(findings)}
    chosen: list[int] = []
    for tok in re.split(r"[,\s]+", t):
        if not tok:
            continue
        if "-" in tok:
            a, _, b = tok.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            for idx in range(lo, hi + 1):
                if idx in by_index and by_index[idx] not in chosen:
                    chosen.append(by_index[idx])
        else:
            try:
                idx = int(tok)
            except ValueError:
                continue
            if idx in by_index and by_index[idx] not in chosen:
                chosen.append(by_index[idx])
    return chosen
