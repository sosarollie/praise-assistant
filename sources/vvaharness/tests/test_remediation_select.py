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

"""Tests for the shared "top N by CVSS" selection helper
(``vvaharness.remediation_agent.select``), used by BOTH the standalone
``remediate --top N`` command and the in-pipeline ``scan --remediate --top N``
path — proving the PQ selection logic lives in exactly one place."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from vvaharness.remediation_agent.discovery import cvss_score_of
from vvaharness.remediation_agent.report_parser import parse_findings
from vvaharness.remediation_agent.select import (
    ALL_FINDINGS,
    band_score,
    cfg_top_n_findings,
    parse_top_arg,
    resolve_top,
    select_top_by_cvss,
    select_top_logged,
)


class _Cfg:
    """Minimal stand-in for the harness Config attribute wrapper: a
    ``step_remediate`` object exposing ``top_n_findings``."""
    def __init__(self, top_n_findings):
        self.step_remediate = type("SR", (), {"top_n_findings": top_n_findings})()


@dataclass
class _Item:
    id: str
    score: float | None
    severity: str = "INFO"


def _items() -> list[_Item]:
    return [
        _Item("a", 5.0, "MEDIUM"),
        _Item("b", None, "CRITICAL"),   # band fallback → 9.0
        _Item("c", 9.5, "HIGH"),
        _Item("d", None, "LOW"),        # band fallback → 1.0
        _Item("e", 7.2, "HIGH"),
    ]


def test_parse_top_arg_absent_returns_none():
    assert parse_top_arg([]) is None
    assert parse_top_arg(["--repo", "/x", "--mode", "fix"]) is None


def test_parse_top_arg_split_and_eq_forms():
    assert parse_top_arg(["--top", "3"]) == 3
    assert parse_top_arg(["--top=5"]) == 5
    assert parse_top_arg(["--repo", "/x", "--top", "2"]) == 2


@pytest.mark.parametrize("args", [
    ["--top"],            # missing value
    ["--top", "0"],       # non-positive
    ["--top", "-1"],
    ["--top", "abc"],     # not an int
    ["--top="],           # empty value
])
def test_parse_top_arg_invalid_raises(args):
    with pytest.raises(ValueError):
        parse_top_arg(args)


def test_band_score_known_and_unknown():
    assert band_score("CRITICAL") == 9.0
    assert band_score("high") == 7.0
    assert band_score("  Medium ") == 4.0
    assert band_score("LOW") == 1.0
    assert band_score("INFO") == 0.0
    assert band_score("bogus") == 0.0
    assert band_score(None) == 0.0


def test_select_orders_highest_first_with_band_fallback():
    out = select_top_by_cvss(_items(), 3, score_of=lambda it: it.score)
    # c=9.5, b=9.0(band), e=7.2  → top 3 in that order
    assert [it.id for it in out] == ["c", "b", "e"]


def test_select_none_returns_input_unchanged():
    items = _items()
    out = select_top_by_cvss(items, None, score_of=lambda it: it.score)
    assert out == items


def test_select_n_ge_len_reorders_by_score():
    items = _items()
    out = select_top_by_cvss(items, 99, score_of=lambda it: it.score)
    # Even when N covers everything, output is reordered highest→lowest by
    # score (consistent with N < len) — no seam where a large N falls back to
    # report order. c=9.5, b=9.0(band), e=7.2, a=5.0, d=1.0.
    assert [it.id for it in out] == ["c", "b", "e", "a", "d"]


def test_select_top_equal_len_matches_smaller_top_ordering():
    # --top 5 of 5 and --top 3 of 5 must order their shared items the same way
    # (the 3b consistency guarantee), not flip to report order at the boundary.
    items = _items()
    top_all = [it.id for it in select_top_by_cvss(items, 5, score_of=lambda it: it.score)]
    top_3 = [it.id for it in select_top_by_cvss(items, 3, score_of=lambda it: it.score)]
    assert top_all[:3] == top_3


def test_select_is_stable_on_ties():
    # Two items with identical scores keep their original relative order.
    items = [_Item("x", 8.0), _Item("y", 8.0), _Item("z", 1.0)]
    out = select_top_by_cvss(items, 2, score_of=lambda it: it.score)
    assert [it.id for it in out] == ["x", "y"]


def test_select_uses_severity_attr_by_default():
    # No explicit severity_of → falls back to the item's `.severity` attribute.
    items = [_Item("lo", None, "LOW"), _Item("hi", None, "CRITICAL")]
    out = select_top_by_cvss(items, 1, score_of=lambda it: it.score)
    assert [it.id for it in out] == ["hi"]


@pytest.mark.parametrize("n", [0, -1, -5])
def test_select_non_positive_n_is_noop(n):
    # A stray --top 0 / negative must NOT silently drop every finding: it is
    # treated as "no selection" and returns the input unchanged. This guards
    # the argparse path (entry.py) which, unlike parse_top_arg, accepts 0/neg.
    items = _items()
    out = select_top_by_cvss(items, n, score_of=lambda it: it.score)
    assert [it.id for it in out] == [it.id for it in items]


def test_select_top_logged_narrows_and_logs(capsys):
    out = select_top_logged(_items(), 2, score_of=lambda it: it.score,
                            log_prefix="[s10]")
    assert [it.id for it in out] == ["c", "b"]
    err = capsys.readouterr().err
    assert "[s10] selecting top 2 of 5 finding(s) by CVSS score" in err


def test_select_top_logged_noop_is_quiet(capsys):
    items = _items()
    # top is None → no narrowing, and crucially no log line.
    out = select_top_logged(items, None, score_of=lambda it: it.score,
                            log_prefix="[s10]")
    assert [it.id for it in out] == [it.id for it in items]
    assert "selecting top" not in capsys.readouterr().err


def test_select_top_logged_ge_len_is_quiet(capsys):
    items = _items()
    out = select_top_logged(items, 99, score_of=lambda it: it.score,
                            log_prefix="[Remediation Agent]")
    # N covers everything: no narrowing happened, so nothing is logged — but the
    # set is still complete (order may be reordered by score, see 3b).
    assert {it.id for it in out} == {it.id for it in items}
    assert "selecting top" not in capsys.readouterr().err


_SCORED_BODY = """### 1. [MEDIUM] x
**Class:** CWE-89
**File:** `c.py:3-3`
**CVSS 3.1:** **9.8** (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

#### Description
y
"""

_VECTOR_ONLY_BODY = """### 1. [LOW] z
**CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
"""


def test_cvss_score_of_reads_the_typed_score():
    # There used to be a cheap line-scanning extractor here alongside the full parse, and a
    # test that the two agreed. The score is now typed on the finding, so there is one
    # answer and nothing to keep in agreement.
    assert cvss_score_of(parse_findings(_SCORED_BODY)[0]) == 9.8


def test_cvss_score_of_none_when_vector_only_or_absent():
    assert cvss_score_of(parse_findings(_VECTOR_ONLY_BODY)[0]) is None
    no_cvss = parse_findings("### 1. [LOW] z\n**File:** `a.py:1-1`\n")[0]
    assert cvss_score_of(no_cvss) is None


@pytest.mark.parametrize("args", [
    ["--top", "all"],
    ["--top=all"],
    ["--top", "ALL"],     # case-insensitive
    ["--top", "*"],
    ["--top=*"],
])
def test_parse_top_arg_wildcard_returns_all_findings(args):

    assert parse_top_arg(args) == ALL_FINDINGS


def test_cfg_top_n_findings_reads_positive_int():
    assert cfg_top_n_findings(_Cfg(20)) == 20
    assert cfg_top_n_findings(_Cfg("5")) == 5  # coerces a stringified int


def test_cfg_top_n_findings_wildcard_spellings():
    # Explicit wildcards in a profile resolve to the ALL_FINDINGS sentinel.
    assert cfg_top_n_findings(_Cfg("all")) == ALL_FINDINGS
    assert cfg_top_n_findings(_Cfg("*")) == ALL_FINDINGS


@pytest.mark.parametrize("val", [0, -1, None, "", "abc"])
def test_cfg_top_n_findings_non_positive_or_garbage_is_wildcard(val):
    # In a profile, 0 / negative / null / unparseable → "no cap" wildcard
    # (remediate every finding), never an exception. This is distinct from the
    # CLI parser, which rejects bad values so a typo isn't silently "all".
    assert cfg_top_n_findings(_Cfg(val)) == ALL_FINDINGS


def test_cfg_top_n_findings_missing_block_is_none():
    # A config with no step_remediate block at all → None (caller falls back).
    cfg = type("C", (), {})()
    assert cfg_top_n_findings(cfg) is None


def test_resolve_top_prefers_cli_override():
    # --top N (cli_top) wins over the profile's top_n_findings.
    assert resolve_top(3, _Cfg(20)) == 3


def test_resolve_top_falls_back_to_profile():
    # No --top → the profile's top_n_findings is the source of truth.
    assert resolve_top(None, _Cfg(20)) == 20


def test_resolve_top_cli_wildcard_overrides_numeric_profile():
    # --top all/* must OVERRIDE a numeric profile cap → no cap (None).
    assert resolve_top(ALL_FINDINGS, _Cfg(20)) is None


def test_resolve_top_profile_wildcard_means_no_cap():
    # top_n_findings: all/* in the profile → no cap (None).
    assert resolve_top(None, _Cfg("all")) is None
    assert resolve_top(None, _Cfg("*")) is None


def test_resolve_top_none_both_means_no_cap():
    # Profile block present but key null → wildcard → None ("every finding").
    assert resolve_top(None, _Cfg(None)) is None


