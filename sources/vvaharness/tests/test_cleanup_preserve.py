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
"""Tests for the batch clone purge's preserve set.

This is a data-loss guard, not a tidiness one. ``_purge_clone`` deletes everything under the
clone that is not named in the keep set, so a directory a stage writes and this set omits is
gone with no signal. Both artefact dirs must therefore be in the default.
"""
from __future__ import annotations

from types import SimpleNamespace

from vvaharness.orchestrator.artifacts import CASE_DIR_NAME, SCAN_DIR_NAME
from vvaharness.orchestrator.cleanup import (
    _CLONE_KEEP_DEFAULT,
    _preserve_set,
    _purge_clone,
)


def test_default_keeps_both_artifact_dirs():
    """The case-file dir belongs here for the same reason the scan dir does."""
    assert set(_CLONE_KEEP_DEFAULT) == {SCAN_DIR_NAME, CASE_DIR_NAME}


def test_default_applies_when_a_profile_sets_nothing():
    cfg = SimpleNamespace(output=SimpleNamespace(preserve_on_cleanup=None))
    assert _preserve_set(cfg) == {SCAN_DIR_NAME, CASE_DIR_NAME}


def test_purge_keeps_case_files_and_deletes_the_source(tmp_path):
    """A case file that only exists inside the clone must survive the purge."""
    case_file = tmp_path / CASE_DIR_NAME / "vvaf1_abc" / "finding_case.json"
    case_file.parent.mkdir(parents=True)
    case_file.write_text("{}", encoding="utf-8")
    report = tmp_path / SCAN_DIR_NAME / "r.md"
    report.parent.mkdir(parents=True)
    report.write_text("# report", encoding="utf-8")
    source = tmp_path / "app"
    source.mkdir()
    (source / "db.py").write_text("q = 1", encoding="utf-8")
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")

    _purge_clone(tmp_path, set(_CLONE_KEEP_DEFAULT))

    assert case_file.is_file()
    assert report.is_file()
    assert not source.exists()
    assert not (tmp_path / "README.md").exists()
