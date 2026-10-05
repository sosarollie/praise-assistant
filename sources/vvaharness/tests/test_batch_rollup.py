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

"""How a batch reports a repo that ran fine and validated nothing it remediated.

`_outcome_status` mapped every non-zero exit code to DEGRADED — "a scan stage exited N;
see the per-repo log". Once exit 3 means "the run completed but nothing validated", that
mapping would claim a stage failed for every such repo, rebuilding at the batch layer the
exact conflation the exit code removes. So 3 gets its own row status, and the three places
that partitioned rows into OK / not-OK now ask a three-way question through one helper.

The three-way split has to hold in all three: both invocation returns AND the summary
renderer. A fix to the returns alone would leave batch_summary.md calling an unremediated
repo failed while the exit code beside it says otherwise.
"""
from __future__ import annotations

from types import SimpleNamespace

from vvaharness.orchestrator import batch
from vvaharness.orchestrator.case_rollup import EXIT_NOT_REMEDIATED
from vvaharness.orchestrator.scan import ScanOutcome


def _mk_repos(tmp_path, n=2):
    refs = []
    for i in range(n):
        d = tmp_path / f"repo{i}"
        d.mkdir()
        (d / "app.py").write_text("print('x')\n", encoding="utf-8")
        refs.append(d)
    return refs


def _args(tmp_path, **over):
    base = dict(workspace=str(tmp_path / "ws"), group_by_app=False,
                stop_after=None, keep_clones=True, resume=False)
    base.update(over)
    return SimpleNamespace(**base)


def _list_file(tmp_path, refs):
    path = tmp_path / "repos.txt"
    path.write_text("".join(f"app{i},repo{i},{d}\n" for i, d in enumerate(refs)),
                    encoding="utf-8")
    return path


def _row(status: str, module: str = "m", app_id: str = "a") -> dict:
    return {"status": status, "module": module, "app_id": app_id, "ref": "git@x/y.git",
            "error": "boom", "findings": 0, "report": "", "elapsed": 1.0}


# _outcome_status — the row


def test_exit_three_becomes_not_remediated_and_blames_no_stage() -> None:
    row = batch._outcome_status(ScanOutcome(None, 5, EXIT_NOT_REMEDIATED))

    assert row["status"] == "NOT_REMEDIATED"
    # The old message would have claimed a stage failed. Every stage ran.
    assert "stage exited" not in row["error"]
    assert row["error"] == "the scan completed but nothing it remediated validated as fixed"


def test_other_nonzero_codes_are_still_degraded() -> None:
    """Only 3 is an outcome claim; 1 and 2 remain health claims, worded as before."""
    for code in (1, 2, 130):
        row = batch._outcome_status(ScanOutcome(None, 0, code))
        assert row["status"] == "DEGRADED", code
        assert row["error"] == f"a scan stage exited {code}; see the per-repo log"


def test_a_clean_outcome_is_untouched() -> None:
    row = batch._outcome_status(ScanOutcome(None, 3, 0))
    assert (row["status"], row["error"]) == ("OK", "")


# _split_non_ok — the one partition all three sites share


def test_split_separates_unremediated_from_real_failures() -> None:
    unremediated, failed = batch._split_non_ok(
        [_row("OK"), _row("NOT_REMEDIATED"), _row("FAILED"), _row("DEGRADED")])

    assert [r["status"] for r in unremediated] == ["NOT_REMEDIATED"]
    assert [r["status"] for r in failed] == ["FAILED", "DEGRADED"]


def test_an_aborted_row_is_a_failure_not_a_shortfall() -> None:
    """ABORTED is set per repo on KeyboardInterrupt. A batch the operator interrupted did
    not run fine and validate nothing, so it must never be reported as exit 3.

    Pinned on the helper rather than end to end because both KeyboardInterrupt handlers
    append the ABORTED row and immediately re-raise, so neither fold nor the summary write
    executes and the process becomes 130 — there is no path on which run_batch returns a
    code for an aborted batch. The guard is still load-bearing: a future handler that
    stops re-raising would otherwise silently downgrade an abort to a shortfall.
    """
    unremediated, failed = batch._split_non_ok([_row("ABORTED"), _row("NOT_REMEDIATED")])

    assert [r["status"] for r in failed] == ["ABORTED"]
    assert len(unremediated) == 1


def test_an_unknown_future_status_is_treated_as_a_failure() -> None:
    """A deny-list, not an allow-list: a sixth status added later must not fall out of
    both buckets and turn a failure into "all repos OK"."""
    unremediated, failed = batch._split_non_ok([_row("SOMETHING_NEW")])

    assert not unremediated
    assert [r["status"] for r in failed] == ["SOMETHING_NEW"]


# run_batch / _run_batch_grouped — the two invocation returns


def _run(tmp_path, monkeypatch, codes, **over):
    refs = _mk_repos(tmp_path, n=len(codes))
    seq = list(codes)

    def fake_scan(repo, module, app_id, args, cfg, path_prefix=None):
        return ScanOutcome(report_path=None, finding_count=0, exit_code=seq.pop(0))

    monkeypatch.setattr(batch, "scan_repo", fake_scan)
    return batch.run_batch(_list_file(tmp_path, refs), _args(tmp_path, **over),
                           SimpleNamespace())


def test_batch_exits_three_when_every_non_ok_row_is_unremediated(tmp_path, monkeypatch):
    assert _run(tmp_path, monkeypatch, [0, EXIT_NOT_REMEDIATED]) == EXIT_NOT_REMEDIATED


def test_batch_exits_one_when_any_row_really_failed(tmp_path, monkeypatch):
    """Health outranks outcome, the same precedence the single-repo path applies."""
    assert _run(tmp_path, monkeypatch, [1, EXIT_NOT_REMEDIATED]) == 1


def test_batch_still_exits_zero_when_every_repo_is_ok(tmp_path, monkeypatch, capsys):
    assert _run(tmp_path, monkeypatch, [0, 0]) == 0
    assert "all 2 repos OK" in capsys.readouterr().err


def test_an_unremediated_repo_is_not_printed_under_repos_failed(tmp_path, monkeypatch,
                                                                capsys):
    _run(tmp_path, monkeypatch, [EXIT_NOT_REMEDIATED, EXIT_NOT_REMEDIATED])
    err = capsys.readouterr().err

    assert "repos FAILED" not in err
    assert "2/2 repos validated nothing they remediated" in err
    # And it must not claim the batch was clean either.
    assert "all 2 repos OK" not in err


def test_grouped_batch_applies_the_same_rule(tmp_path, monkeypatch):
    """The duplication this commit exists to fix: a change to run_batch alone would ship
    the grouped path wrong and still look tested."""
    assert _run(tmp_path, monkeypatch, [0, EXIT_NOT_REMEDIATED],
                group_by_app=True) == EXIT_NOT_REMEDIATED


def test_grouped_batch_lets_a_real_failure_outrank(tmp_path, monkeypatch):
    assert _run(tmp_path, monkeypatch, [1, EXIT_NOT_REMEDIATED], group_by_app=True) == 1


# _render_batch_summary — the third copy of the fold


def test_the_summary_counts_unremediated_repos_separately() -> None:
    md = batch._render_batch_summary(
        [_row("OK"), _row("NOT_REMEDIATED"), _row("FAILED")], "list.txt", 12.0)

    assert "- Repos: 3 (1 OK, 1 not remediated, 1 failed)" in md


def test_the_summary_does_not_list_an_unremediated_repo_as_a_failure() -> None:
    """It gets its own section rather than an entry under Failures — and rather than only
    a status cell, since the table carries no error column and would otherwise say
    nothing about what happened."""
    md = batch._render_batch_summary([_row("NOT_REMEDIATED", module="quiet")],
                                     "list.txt", 1.0)

    assert "## Failures" not in md
    assert "## Not remediated" in md
    assert "NOT_REMEDIATED" in md  # the status cell still renders verbatim
    assert "quiet" in md


def test_the_summary_keeps_a_failures_section_for_real_failures() -> None:
    md = batch._render_batch_summary([_row("DEGRADED", module="broken")], "list.txt", 1.0)

    assert "## Failures" in md
    assert "## Not remediated" not in md
    assert "- Error: boom" in md


def test_the_new_status_does_not_weaken_the_markdown_defences() -> None:
    """The status cell goes through _md_cell like every other operator-supplied field.
    NOT_REMEDIATED is a literal this module defines, so it carries no injection risk of
    its own, but a crafted module name in the same row must still be neutralised.
    """
    md = batch._render_batch_summary(
        [_row("NOT_REMEDIATED", module="a|b\ninjected")], "list.txt", 1.0)

    assert "a|b" not in md          # the pipe is escaped, so the raw pair never appears
    assert "\ninjected" not in md   # the newline is folded, so no forged row is possible
    assert r"a\|b injected" in md
