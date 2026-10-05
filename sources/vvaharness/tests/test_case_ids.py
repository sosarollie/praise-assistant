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

# START GENAI
"""Tests for ``orchestrator.case_ids`` — the stable per-finding identity.

The id names the case directory, so the properties under test are not cosmetic:

  * two findings must never share one id, because the second case file would overwrite the
    first with no trace that a finding was there;
  * the same finding must mint the same id across processes, hosts, and path spellings, or the
    case forks into two directories;
  * a re-run that moves a line or reworks a title must NOT mint a new id.
"""
from __future__ import annotations

import unicodedata

import pytest

from vvaharness.models import FinalReport, Finding, RankedFinding, Severity
from vvaharness.orchestrator.case_ids import CASE_ID_PREFIX, mint_case_ids


def _report(*findings: Finding, repo_root: str = "/w/repo") -> FinalReport:
    return FinalReport(
        repo_root=repo_root,
        summary="s",
        chains=[],
        findings=[RankedFinding(finding=f, severity=Severity.HIGH,
                                exploitability_notes="") for f in findings],
    )


def _finding(**over) -> Finding:
    base = {"title": "SQLi", "file": "app/db.py", "line_start": 42,
            "vuln_class": "injection", "cwe": "CWE-89"}
    return Finding(**{**base, **over})


def _ids(report: FinalReport) -> list[str]:
    return [rf.finding.case_id for rf in report.findings]


def test_minted_id_is_prefixed_and_stable():
    """The id is versioned by prefix and reproducible from content alone."""
    first, second = _report(_finding()), _report(_finding())
    mint_case_ids(first)
    mint_case_ids(second)
    assert _ids(first)[0].startswith(CASE_ID_PREFIX)
    assert _ids(first) == _ids(second)


@pytest.mark.parametrize("over", [
    {"line_start": 47},                  # same 10-line bucket
    {"title": "SQL injection in login"},  # reworded by a later run
    {"description": "different prose"},
    {"confidence": 0.9},
])
def test_id_survives_the_jitter_a_rerun_produces(over):
    """Line jitter inside one bucket and LLM rewording must not fork the case."""
    plain, jittered = _report(_finding()), _report(_finding(**over))
    mint_case_ids(plain)
    mint_case_ids(jittered)
    assert _ids(plain) == _ids(jittered)


@pytest.mark.parametrize("over", [
    {"line_start": 52},          # next bucket up
    {"file": "app/other.py"},
    {"cwe": "CWE-79"},
])
def test_id_changes_when_the_addressed_content_changes(over):
    """A different file, class, or bucket is a different case."""
    plain, moved = _report(_finding()), _report(_finding(**over))
    mint_case_ids(plain)
    mint_case_ids(moved)
    assert _ids(plain) != _ids(moved)


def test_absolute_and_relative_paths_mint_the_same_id():
    """A scan holding an absolute path and a consumer holding a relative one agree.

    Otherwise the same bug is two cases depending on which process minted first.
    """
    relative = _report(_finding(file="app/db.py"))
    absolute = _report(_finding(file="/w/repo/app/db.py"))
    mint_case_ids(relative)
    mint_case_ids(absolute)
    assert _ids(relative) == _ids(absolute)


def test_windows_separators_and_nfd_paths_fold_to_one_id():
    """Separator style and Unicode normal form are spellings, not identities."""
    posix = _report(_finding(file="app/café/db.py"))
    windows_nfd = _report(_finding(
        file=unicodedata.normalize("NFD", "app\\café\\db.py")))
    mint_case_ids(posix)
    mint_case_ids(windows_nfd)
    assert _ids(posix) == _ids(windows_nfd)


def test_same_bucket_collision_is_disambiguated_not_dropped():
    """Two findings one file, one class, one bucket apart get two distinct ids.

    This is the case the whole module exists for: without disambiguation both hash the same,
    and the second case file silently overwrites the first.
    """
    report = _report(_finding(line_start=42, title="a"),
                     _finding(line_start=45, title="b"))
    stats = mint_case_ids(report)
    ids = _ids(report)
    assert len(set(ids)) == 2
    assert stats == {"minted": 2, "collisions": 1, "preassigned": 0}


def test_collision_disambiguation_ignores_report_order():
    """The salt follows content, not list position, so a reordered report is unchanged."""
    forward = _report(_finding(line_start=42, title="a"),
                      _finding(line_start=45, title="b"))
    reversed_ = _report(_finding(line_start=45, title="b"),
                        _finding(line_start=42, title="a"))
    mint_case_ids(forward)
    mint_case_ids(reversed_)
    assert set(_ids(forward)) == set(_ids(reversed_))
    # And each finding keeps ITS id, not just the set: title "a" maps to one id either way.
    by_title = {rf.finding.title: rf.finding.case_id for rf in reversed_.findings}
    assert by_title["a"] == _ids(forward)[0]


def test_preassigned_ids_are_kept_and_reserved():
    """A resumed report keeps the ids its case directories already use.

    And a newly minted id can never land on a pre-assigned one, even in the same bucket.
    """
    existing = _finding(line_start=42, title="a")
    mint_case_ids(_report(existing))
    kept = existing.case_id
    report = _report(existing, _finding(line_start=45, title="b"))
    stats = mint_case_ids(report)
    assert existing.case_id == kept
    assert stats["preassigned"] == 1 and stats["minted"] == 1
    assert len(set(_ids(report))) == 2


def test_duplicate_preassigned_ids_are_refused():
    """A report that already carries a clash stops the run before anything is written."""
    report = _report(_finding(title="a", case_id="vvaf1_dupe"),
                     _finding(title="b", file="other.py", case_id="vvaf1_dupe"))
    with pytest.raises(ValueError, match="minted twice"):
        mint_case_ids(report)
