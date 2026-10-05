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

"""CMDB id-collision guard for vvaharness.report.enrich.load_cmdb_csv.

``normalize_app_id`` strips leading zeros + surrounding whitespace, so distinct
CMDB rows (e.g. ``042`` vs ``42``) can collide on one key. Last-wins is kept,
but a collision whose rows carry DIFFERENT exposure/sensitivity must no longer
be silent — it drifts VulContextSeverity / OffensivePriority enrichment for the
app that looks it up. These tests pin: (1) a conflicting collision warns and
names both raw ids, (2) a benign duplicate stays silent, (3) last-wins is
preserved, (4) distinct keys never warn."""
from __future__ import annotations

from pathlib import Path

from vvaharness.report.enrich import load_cmdb_csv, normalize_app_id

_HEADER = "id,name,externally_facing,pci,pan,pii,parent_id\n"


def _write_cmdb(tmp_path: Path, rows: str) -> str:
    p = tmp_path / "cmdb.csv"
    p.write_text(_HEADER + rows, encoding="utf-8")
    return str(p)


def test_conflicting_collision_warns_and_keeps_last(tmp_path, capsys) -> None:
    # '042' and '42' normalise to the same key but differ on exposure/pci.
    path = _write_cmdb(
        tmp_path,
        "042,Alpha,no,no,no,no,\n"
        "42,Beta,yes,yes,no,no,\n",
    )
    cmdb = load_cmdb_csv(path)
    err = capsys.readouterr().err

    # Exactly one key survives; last-wins keeps the second ('42'/Beta) row.
    assert set(cmdb) == {normalize_app_id("42")}
    survivor = cmdb[normalize_app_id("42")]
    assert survivor.id == "42"
    assert survivor.externally_facing is True
    assert survivor.pci_scoped is True

    # The drift is surfaced loudly, naming BOTH raw ids.
    assert "[cmdb] WARN" in err
    assert "'42'" in err and "'042'" in err


def test_benign_duplicate_collision_is_silent(tmp_path, capsys) -> None:
    # Same normalised key AND identical enrichment → no drift → no warning.
    path = _write_cmdb(
        tmp_path,
        "042,Alpha,yes,no,no,no,\n"
        "42,Alpha,yes,no,no,no,\n",
    )
    cmdb = load_cmdb_csv(path)
    err = capsys.readouterr().err

    assert set(cmdb) == {normalize_app_id("42")}
    assert "WARN" not in err


def test_distinct_keys_do_not_warn(tmp_path, capsys) -> None:
    path = _write_cmdb(
        tmp_path,
        "100,Alpha,yes,no,no,no,\n"
        "200,Beta,no,yes,no,no,\n",
    )
    cmdb = load_cmdb_csv(path)
    err = capsys.readouterr().err

    assert set(cmdb) == {"100", "200"}
    assert "WARN" not in err


def test_parent_difference_counts_as_conflict(tmp_path, capsys) -> None:
    # Decision bools match, but the rows inherit from DIFFERENT parents — that
    # changes the merged result, so it must warn.
    path = _write_cmdb(
        tmp_path,
        "07,Gamma,no,no,no,no,500\n"
        "7,Gamma,no,no,no,no,900\n",
    )
    load_cmdb_csv(path)
    err = capsys.readouterr().err
    assert "[cmdb] WARN" in err
