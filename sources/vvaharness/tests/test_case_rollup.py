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

"""Tests for the remediation/validation rollup the run manifest carries.

The rollup keys on the DERIVED ``CaseState`` (the engine's own verdict, via
``derive.state_of``) plus the raw ``Decision`` of the last attempt's verdict, so these
tests build real ``FindingCase`` records on disk and assert the counts they tally to —
including the two mappings worth pinning: ``PARTIALLY_FIXED -> failed`` (readiness
policy belongs to the operator, not the engine) and ``INCONCLUSIVE -> open``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vvaharness.models import (
    Decision,
    Finding,
    FindingCase,
    Remediation,
    RemediationKind,
    Verdict,
)
from vvaharness.orchestrator import case_rollup
from vvaharness.orchestrator.artifacts import CASE_DIR_NAME, CASE_FILE_NAME

# helpers


def _finding(case_id: str) -> Finding:
    return Finding(
        title="t", file="app/x.py", line_start=3, vuln_class="injection",
        severity="high", case_id=case_id, cvss_score=7.5,
    )


def _case(case_id: str, decision: Decision | None = None) -> FindingCase:
    """One applied-edits attempt; judged with *decision* when given, unjudged otherwise."""
    case = FindingCase(case_id=case_id, finding=_finding(case_id)).with_attempt(
        Remediation(
            kind=RemediationKind.EDITS_APPLIED, summary="s",
            files_touched=("app/x.py",), diff="x",
        )
    )
    if decision is not None:
        case = case.with_verdict(Verdict(decision=decision, rationale="r"))
    return case


def _write_case(repo: Path, name: str, case: FindingCase) -> Path:
    sub = repo / CASE_DIR_NAME / name
    sub.mkdir(parents=True)
    path = sub / CASE_FILE_NAME
    case.write(path)
    return path


# rollup_for — the per-repo tally


def test_tallies_case_states_and_decisions(tmp_path: Path) -> None:
    """Every decision plus one unjudged attempt land in the CaseState buckets
    derive._DECISION_STATE implies, and the raw decisions ride along — except the
    unjudged attempt, which contributes to `states` but to no decision."""
    for i, decision in enumerate(
        (Decision.FIXED, Decision.PARTIALLY_FIXED, Decision.NOT_FIXED,
         Decision.INCONCLUSIVE, None)
    ):
        _write_case(tmp_path, f"{i:02d}_finding", _case(f"F-{i}", decision))

    rollup = case_rollup.rollup_for(tmp_path)

    assert rollup == {
        "cases": 5,
        "states": {"failed": 2, "open": 1, "remediated": 1, "validated": 1},
        "decisions": {"fixed": 1, "inconclusive": 1, "not_fixed": 1,
                      "partially_fixed": 1},
    }
    # Sorted keys, for the same stable-diff reason as the manifest's counters dump.
    assert list(rollup["states"]) == sorted(rollup["states"])
    assert list(rollup["decisions"]) == sorted(rollup["decisions"])


def test_partially_fixed_counts_as_failed_not_ready_with_conditions(tmp_path: Path) -> None:
    """The pin that the rollup keys on CaseState, the engine's own verdict: under
    MergeReadiness a PARTIALLY_FIXED case can be conditionally mergeable, but that
    policy belongs to whoever runs the scan — here it is simply `failed`."""
    _write_case(tmp_path, "01_finding", _case("F-1", Decision.PARTIALLY_FIXED))

    rollup = case_rollup.rollup_for(tmp_path)

    assert rollup["states"] == {"failed": 1}
    assert "ready_with_conditions" not in str(rollup)
    # The raw decision is still carried, so an operator can apply their own policy.
    assert rollup["decisions"] == {"partially_fixed": 1}


def test_inconclusive_is_open_not_failed(tmp_path: Path) -> None:
    """Pins derive.py's INCONCLUSIVE -> OPEN mapping: an inconclusive validation leaves
    the case re-validatable, not condemned."""
    _write_case(tmp_path, "01_finding", _case("F-1", Decision.INCONCLUSIVE))

    rollup = case_rollup.rollup_for(tmp_path)

    assert rollup["states"] == {"open": 1}
    assert rollup["decisions"] == {"inconclusive": 1}


def test_no_remediation_dir_yields_an_empty_rollup(tmp_path: Path) -> None:
    """{} — not zeros — so the manifest omits the key and "no validation ran" stays
    distinguishable from "validation ran and everything is zero"."""
    assert case_rollup.rollup_for(tmp_path) == {}


def test_malformed_case_file_warns_and_is_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Same policy as findings_json: the case files live inside the scanned target, so
    a bad one is discarded loudly and the rest still tally — never an abort."""
    _write_case(tmp_path, "01_finding", _case("F-1", Decision.FIXED))
    bad_dir = tmp_path / CASE_DIR_NAME / "02_finding"
    bad_dir.mkdir(parents=True)
    (bad_dir / CASE_FILE_NAME).write_text("{not json", encoding="utf-8")

    rollup = case_rollup.rollup_for(tmp_path)

    assert rollup == {"cases": 1, "states": {"validated": 1},
                      "decisions": {"fixed": 1}}
    assert "is not a readable case record" in capsys.readouterr().err


def test_an_oversized_case_file_is_skipped_without_being_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The size cap: a hostile checkout can pre-seed security-remediation/, and the
    tally must not be a way to make the scanner read a gigabyte into memory.

    The cap has to be checked BEFORE the read, or it protects nothing — so this also
    fails the read outright. Asserting only the empty result would stay green with the
    check moved below the read, which is the whole protection.
    """
    _write_case(tmp_path, "01_finding", _case("F-1", Decision.FIXED))
    monkeypatch.setattr(case_rollup, "_MAX_CASE_BYTES", 16)

    def _must_not_read(path: Path) -> None:
        raise AssertionError(f"read {path} despite the size cap")

    monkeypatch.setattr(case_rollup.FindingCase, "read", staticmethod(_must_not_read))

    assert case_rollup.rollup_for(tmp_path) == {}
    assert "exceeds the" in capsys.readouterr().err


def test_a_case_file_resolving_outside_the_case_dir_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """Path.glob follows symlinks in every position, so a hostile checkout can plant a
    link and have the reader open a file outside the scanned target. Only counts leave
    the module, but a validation error echoes a fragment of whatever it parsed, so the
    read is refused rather than merely being harmless."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / CASE_FILE_NAME).write_text('{"secret": "tok-zqxjvw"}', encoding="utf-8")
    good = tmp_path / "repo"
    _write_case(good, "01_finding", _case("F-1", Decision.FIXED))
    (good / CASE_DIR_NAME / "02_planted").symlink_to(outside)

    rollup = case_rollup.rollup_for(good)
    err = capsys.readouterr().err

    assert rollup == {"cases": 1, "states": {"validated": 1},
                      "decisions": {"fixed": 1}}
    assert "resolves outside" in err
    # The refusal must come before the read, so nothing from the file is echoed.
    assert "tok-zqxjvw" not in err


def test_a_case_path_that_is_not_a_regular_file_is_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The is_file() guard, which is what keeps a device node or a FIFO planted under
    the case directory from blocking the read forever: such a path is not a malformed
    record, so it is skipped silently AND without being opened.

    The "without being opened" half is the part that matters and the part a result-only
    assertion would miss: swapping is_file() for the plausible-looking is_dir() leaves
    the count at zero for this input while letting a planted FIFO reach the read and
    hang the stage. Pinned by failing the read rather than by planting a real FIFO,
    which would hang this test instead of failing it.
    """
    (tmp_path / CASE_DIR_NAME / "01_finding" / CASE_FILE_NAME).mkdir(parents=True)

    def _must_not_read(path: Path) -> None:
        raise AssertionError(f"opened {path}, which is not a regular file")

    monkeypatch.setattr(case_rollup.FindingCase, "read", staticmethod(_must_not_read))

    assert case_rollup.rollup_for(tmp_path) == {}
    assert capsys.readouterr().err == ""


def test_the_tally_covers_exactly_the_cases_s11_itself_discovers(tmp_path: Path) -> None:
    """The rollup must describe the population s11 itself discovers.

    s11's own case_loader.discover_cases globs the same two-segment pattern over the
    whole repo, so the two views are the same set by construction — which is also why
    the rollup deliberately does not filter by file age: security-remediation/ survives
    across runs by design. Discovery is not selection: select_cases may cap or narrow
    what actually gets validated, which is why this tally reports and never decides an
    exit code.
    """
    from vvaharness.validation.ingest.case_loader import discover_cases

    for i, decision in enumerate((Decision.FIXED, Decision.NOT_FIXED, None)):
        _write_case(tmp_path, f"{i:02d}_finding", _case(f"F-{i}", decision))

    assert case_rollup.rollup_for(tmp_path)["cases"] == len(discover_cases(tmp_path))


def test_the_rollup_carries_counts_only(tmp_path: Path) -> None:
    """Nothing the scanned target controls may reach run_manifest.json through the
    rollup: no title, path, case id or snippet — only counts."""
    marker = "zqxjvw"  # distinctive, so a substring of "states"/"decisions" cannot pass
    case = FindingCase(
        case_id=f"case-{marker}",
        finding=Finding(
            title=f"title-{marker}", file=f"app/{marker}.py", line_start=3,
            vuln_class="injection", severity="high", case_id=f"case-{marker}",
            cvss_score=7.5,
        ),
    ).with_attempt(
        Remediation(
            kind=RemediationKind.EDITS_APPLIED, summary=f"summary-{marker}",
            files_touched=(f"app/{marker}.py",), diff=f"diff-{marker}",
        )
    ).with_verdict(Verdict(decision=Decision.FIXED, rationale=f"why-{marker}"))
    _write_case(tmp_path, "01_finding", case)

    rollup = case_rollup.rollup_for(tmp_path)

    assert marker not in str(rollup)
    assert rollup["cases"] == 1
    assert all(isinstance(n, int) for n in rollup["states"].values())
    assert all(isinstance(n, int) for n in rollup["decisions"].values())


# rc_for_verdicts — the exit-code gate


def _verdict(decision: Decision, **kw: object) -> Verdict:
    return Verdict(decision=decision, rationale="r", **kw)


def test_nothing_validated_and_something_failed_trips_the_gate() -> None:
    assert case_rollup.rc_for_verdicts(
        [_verdict(Decision.NOT_FIXED), _verdict(Decision.NOT_FIXED)]
    ) == case_rollup.EXIT_NOT_REMEDIATED
    assert case_rollup.EXIT_NOT_REMEDIATED == 3


def test_any_single_validated_case_clears_the_gate() -> None:
    """Deliberately narrow: one fix that holds is not "nothing was remediated".

    An any-failure gate would go non-zero on most mixed runs, and a signal that is
    almost always red gets wrapped in `|| true` and stops being a signal. Per-case
    detail is in the manifest rollup for an operator who wants a stricter rule.
    """
    assert case_rollup.rc_for_verdicts(
        [_verdict(Decision.FIXED), _verdict(Decision.NOT_FIXED),
         _verdict(Decision.PARTIALLY_FIXED)]
    ) == 0


def test_partially_fixed_alone_trips_the_gate() -> None:
    """PARTIALLY_FIXED derives FAILED, so a run of only partial fixes validated nothing.

    The score below clears the conditional merge threshold, so under MergeReadiness this
    is "ready with conditions" — the ambiguity is real. The engine keys on CaseState, its
    own verdict, and leaves readiness policy to whoever runs the scan.
    """
    assert case_rollup.rc_for_verdicts(
        [_verdict(Decision.PARTIALLY_FIXED, score=0.715)]
    ) == case_rollup.EXIT_NOT_REMEDIATED


def test_only_inconclusive_does_not_trip_the_gate() -> None:
    """INCONCLUSIVE derives OPEN, not FAILED: such a run neither validated nor failed,
    and re-validating it is the answer rather than a red exit code."""
    assert case_rollup.rc_for_verdicts(
        [_verdict(Decision.INCONCLUSIVE), _verdict(Decision.INCONCLUSIVE)]
    ) == 0


def test_no_verdicts_at_all_does_not_trip_the_gate() -> None:
    """Zero cases attempted is not a failure — nothing was promised and nothing broke."""
    assert case_rollup.rc_for_verdicts([]) == 0
    assert case_rollup.rc_for_verdicts([None, None]) == 0


def test_a_ticketed_or_declined_verdict_is_neither_validated_nor_failed() -> None:
    """Keying through the shared verdict_state, not through Decision, is what makes these
    two cases right: a verdict deferred to a ticket derives PENDING and a false positive
    derives DECLINED, so neither counts as a failure to fix and neither trips the gate
    even though its decision is not FIXED."""
    from vvaharness.models import Disposition, Ticket

    assert case_rollup.rc_for_verdicts(
        [_verdict(Decision.NOT_FIXED, ticket=Ticket(ref="REVIEW-1"))]
    ) == 0
    assert case_rollup.rc_for_verdicts(
        [_verdict(Decision.NOT_FIXED, disposition=Disposition.FALSE_POSITIVE)]
    ) == 0


# record / totals — the invocation-wide accumulator


def test_totals_accumulate_across_repos(tmp_path: Path) -> None:
    repo_a, repo_b = tmp_path / "a", tmp_path / "b"
    _write_case(repo_a, "01_finding", _case("F-1", Decision.FIXED))
    _write_case(repo_b, "01_finding", _case("F-2", Decision.FIXED))
    _write_case(repo_b, "02_finding", _case("F-3", Decision.NOT_FIXED))

    # record() returns what it computed, so a caller needing both reads disk once.
    assert case_rollup.record(repo_a)["cases"] == 1
    assert case_rollup.record(repo_b)["cases"] == 2

    assert case_rollup.totals() == {
        "cases": 3,
        "states": {"failed": 1, "validated": 2},
        "decisions": {"fixed": 2, "not_fixed": 1},
    }


def test_rollup_for_is_per_repo_and_totals_is_cumulative(tmp_path: Path) -> None:
    """Why both exist: in a batch where repo 1 validated something and repo 2 validated
    nothing, totals() reports validated > 0 and can never express "THIS repo validated
    nothing", so folding rollup_for into totals would lose the per-repo answer.

    What neither is for is deciding an exit code — this counts cases on disk, while s11
    validates only the subset select_cases picked.
    """
    repo_a, repo_b = tmp_path / "a", tmp_path / "b"
    _write_case(repo_a, "01_finding", _case("F-1", Decision.FIXED))
    _write_case(repo_b, "01_finding", _case("F-2"))  # remediated, never judged

    case_rollup.record(repo_a)
    case_rollup.record(repo_b)

    assert case_rollup.totals()["states"]["validated"] > 0
    assert "validated" not in case_rollup.rollup_for(repo_b)["states"]


def test_totals_survive_every_per_repo_reset_a_batch_performs(tmp_path: Path) -> None:
    """The mirror of test_counters_dump_survives_a_batch_reset, and it exists for the
    same reason: batch.py's per-repo reset list is hand-kept.

    A batch run resets the token, stage, counter, quality and warn-once globals between
    repos while ONE manifest covers the whole invocation, so the rollup must survive all
    of them. reset() is public and nothing structurally stops it being added to that
    list, after which the manifest would report only the batch's last repo and every
    other test would still pass. This is the test that would fail instead.
    """
    from vvaharness.util.counters import COUNTERS
    from vvaharness.util.stage_telemetry import STAGES
    from vvaharness.util.tokens import TOKENS

    repo_a, repo_b = tmp_path / "a", tmp_path / "b"
    _write_case(repo_a, "01_finding", _case("F-1", Decision.FIXED))
    _write_case(repo_b, "01_finding", _case("F-2", Decision.NOT_FIXED))

    case_rollup.record(repo_a)
    TOKENS.reset()
    STAGES.reset()
    COUNTERS.reset()
    case_rollup.record(repo_b)

    assert case_rollup.totals() == {
        "cases": 2,
        "states": {"failed": 1, "validated": 1},
        "decisions": {"fixed": 1, "not_fixed": 1},
    }


def test_totals_is_empty_until_something_is_recorded_and_reset_clears_it(
    tmp_path: Path,
) -> None:
    assert case_rollup.totals() == {}
    _write_case(tmp_path, "01_finding", _case("F-1", Decision.FIXED))
    case_rollup.record(tmp_path)
    assert case_rollup.totals() != {}
    case_rollup.reset()
    assert case_rollup.totals() == {}
