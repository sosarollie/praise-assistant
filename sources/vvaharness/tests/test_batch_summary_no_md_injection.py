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

"""Regression guard: the batch summary must not let operator-supplied
app_id / repo_name (or exception text) inject Markdown.

A crafted AppID/RepoName containing ``|`` or a newline must NOT be able to
forge/shift table cells (e.g. flip a FAILED repo to OK), forge extra rows, or
terminate the table/heading to append attacker-chosen Markdown sections.
``_render_batch_summary`` routes every untrusted field through ``_md_cell``;
this test pins that invariant."""
from __future__ import annotations

from pathlib import Path

from vvaharness.orchestrator.batch import _md_cell, _render_batch_summary


def _result(**overrides) -> dict:
    """A complete results-row dict with safe defaults; override per test."""
    base = {
        "ref": "https://example.com/org/repo.git",
        "module": "repo",
        "app_id": "APP123",
        "status": "OK",
        "findings": 0,
        "report": "/tmp/security-scan/repo_report.md",
        "elapsed": 1.0,
        "error": "",
    }
    base.update(overrides)
    return base


def _data_rows(summary: str) -> list[str]:
    """Table data rows = lines starting with '|' that aren't the header or the
    '|---|' separator."""
    rows = []
    for ln in summary.splitlines():
        if not ln.startswith("|"):
            continue
        if ln.startswith("|--") or " App ID " in ln:
            continue
        rows.append(ln)
    return rows


def test_md_cell_is_the_shared_escaper() -> None:
    # The batch summary must use the single audited escaper from models.py —
    # a hardening fix applied there must never leave this path behind.
    from vvaharness import models
    assert _md_cell is models._md_cell


def test_md_cell_neutralises_pipe_and_newline() -> None:
    assert _md_cell("a|b") == "a\\|b"
    assert _md_cell("a\nb") == "a b"
    assert _md_cell("a\r\nb") == "a  b"
    assert _md_cell(None) == ""
    assert _md_cell(123) == "123"


def test_md_cell_escapes_backslash_before_pipe() -> None:
    # A supplied "\" must be doubled, else it consumes the escape added for "|" and the
    # raw delimiter survives into the rendered summary table.
    assert _md_cell(r"a\|b") == r"a\\\|b"


def test_pipe_in_appid_cannot_forge_or_shift_cells() -> None:
    # An AppID that tries to inject extra columns and flip a FAILED status to OK.
    evil = "x | OK | 0 | 0 | | "
    summary = _render_batch_summary(
        [_result(app_id=evil, status="FAILED")], Path("list.csv"), 2.0
    )
    rows = _data_rows(summary)
    assert len(rows) == 1
    row = rows[0]
    # The injected pipes are escaped, so they cannot create new delimiters.
    assert "x \\| OK \\| 0 \\| 0" in row
    assert "x | OK |" not in row          # no UNescaped injected delimiter
    # A fixed 8-column row has exactly 9 delimiter pipes; escaped pipes (\|) are
    # not delimiters. Stripping them must leave exactly 9.
    assert row.replace("\\|", "").count("|") == 9
    # The real status survives in its own cell and was not shifted away.
    assert "| FAILED |" in row


def test_newline_in_repo_cannot_forge_rows() -> None:
    evil = "repo |\n| 99 | evil-injected | OK | 0 | 0 | | "
    summary = _render_batch_summary(
        [_result(module=evil)], Path("list.csv"), 2.0
    )
    # Exactly one data row despite the embedded newline + faux row.
    assert len(_data_rows(summary)) == 1
    assert "evil-injected" in summary          # present, but inline (escaped)
    # No forged data row carrying the injected marker as its own line.
    assert not any("evil-injected" in r and r != _data_rows(summary)[0]
                   for r in _data_rows(summary))


def test_newline_in_failures_heading_cannot_inject_markdown() -> None:
    evil_module = "repo\n## Pwned Section\n[click](http://evil)"
    summary = _render_batch_summary(
        [_result(module=evil_module, status="FAILED", error="boom")],
        Path("list.csv"), 2.0,
    )
    # The injected text must never appear as a real heading line of its own.
    for ln in summary.splitlines():
        assert not ln.lstrip().startswith("## Pwned")
        assert ln.strip() != "[click](http://evil)"


def test_newline_in_error_cannot_inject_markdown() -> None:
    summary = _render_batch_summary(
        [_result(status="FAILED", error="boom\n## Injected\n- fake bullet")],
        Path("list.csv"), 2.0,
    )
    for ln in summary.splitlines():
        assert not ln.lstrip().startswith("## Injected")


def test_unicode_line_separator_cannot_forge_rows() -> None:
    # U+2028 is not "\n" but str.splitlines() (and some renderers) break on it;
    # it must be folded like a newline or a value forges a row on re-split.
    evil = "repo\u2028| 99 | evil-injected | OK | 0 | 0 | | "
    summary = _render_batch_summary([_result(module=evil)], Path("list.csv"), 2.0)
    assert len(_data_rows(summary)) == 1
    assert "\u2028" not in summary


def test_bidi_and_zero_width_chars_stripped_from_summary() -> None:
    # A bidi override could visually reorder a status; a zero-width char could
    # smuggle an invisible marker. Neither may reach the rendered summary.
    summary = _render_batch_summary(
        [_result(app_id="AP\u202eP1", module="re\u200bpo", status="FAILED",
                 error="bo\u202aom")],
        Path("list.csv"), 2.0,
    )
    for ch in ("\u202e", "\u200b", "\u202a"):
        assert ch not in summary
    assert "| APP1 | repo | FAILED |" in _data_rows(summary)[0]


def test_backtick_cannot_close_report_or_source_code_span() -> None:
    # Report path / source ref are rendered inside `...` code spans. A backslash
    # escape is inert inside a code span, so an embedded backtick must be folded
    # away entirely or it terminates the span and re-enables inline Markdown.
    evil_ref = "https://example.com/x`[click](http://evil)`.git"
    summary = _render_batch_summary(
        [_result(ref=evil_ref, report="/tmp/x`y_report.md", status="FAILED",
                 error="boom")],
        Path("list.csv"), 2.0,
    )
    row = _data_rows(summary)[0]
    # Report cell: only the two wrapping backticks of its code span survive —
    # the embedded backtick was folded, so the span cannot be closed early.
    cells = [c.strip() for c in row.split("|")]
    rep_cell = cells[-3]
    assert rep_cell.startswith("`") and rep_cell.endswith("`")
    assert rep_cell.count("`") == 2
    # And the Failures section's Source span likewise cannot be closed early.
    src_lines = [ln for ln in summary.splitlines() if ln.startswith("- Source:")]
    assert src_lines and all(ln.count("`") == 2 for ln in src_lines)


def test_legitimate_values_render_unchanged() -> None:
    # No special chars → output identical to the raw interpolation (no regression).
    summary = _render_batch_summary(
        [_result(app_id="APP-42", module="payments-api", status="OK", findings=3)],
        Path("list.csv"), 5.0,
    )
    rows = _data_rows(summary)
    assert len(rows) == 1
    assert "| APP-42 | payments-api | OK |" in rows[0]
    assert "\\|" not in rows[0]             # nothing to escape → no backslashes
