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

"""Grouped-batch staging safety: slug disambiguation + source-binding markers.

A staged repo at workspace/<app>/<slug> must (a) get a UNIQUE slug so two repo
names with the same tail don't collide, and (b) only be reused when a state-dir
marker proves it was staged from THIS ref — never a stale, foreign, or
pre-seeded dir. Markers live in $VVAHARNESS_STATE_DIR (operator-private), not in
the shared workspace, so a workspace writer cannot forge one. Offline/local-only
(no git/network)."""
import os

import pytest

from vvaharness.orchestrator.batch import (
    _assign_slugs,
    _stage_dir_bound,
    _stage_marker_path,
    _stage_repo,
)


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    d = tmp_path / "state"
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(d))
    return d


def _mk_src(tmp_path, name, content="real"):
    src = tmp_path / name
    src.mkdir()
    (src / "app.py").write_text(content, encoding="utf-8")
    return src


def test_assign_slugs_disambiguates_same_tail():
    # org-a/service and org-b/service both tail to "service" — the old code
    # collided them (second silently reused the first's dir, never scanned).
    repos = [{"repo_name": "org-a/service"}, {"repo_name": "org-b/service"}]
    slugs = _assign_slugs(repos)
    assert len(set(slugs)) == 2            # both distinct → both staged & scanned
    assert slugs[0] == "service"           # first keeps the clean tail
    assert slugs[1].startswith("service-") # collider disambiguated by hash


def test_assign_slugs_distinct_unchanged():
    repos = [{"repo_name": "org/api"}, {"repo_name": "org/web"}]
    assert _assign_slugs(repos) == ["api", "web"]


def test_assign_slugs_stable_per_repo():
    repos = [{"repo_name": "x/svc"}, {"repo_name": "y/svc"}]
    assert _assign_slugs(repos) == _assign_slugs(repos)   # deterministic re-runs


def test_stage_local_writes_marker_and_reuses_verified(tmp_path, state_dir):
    src = _mk_src(tmp_path, "src")
    app_dir = tmp_path / "ws" / "app1"
    _stage_repo(str(src), app_dir, "service", None)
    dest = app_dir / "service"
    assert (dest / "app.py").read_text() == "real"
    assert _stage_marker_path(dest).is_file()
    assert _stage_dir_bound(dest, str(src))
    # A verified reuse must NOT re-copy — a sentinel written into dest survives.
    (dest / "sentinel.txt").write_text("x", encoding="utf-8")
    _stage_repo(str(src), app_dir, "service", None)
    assert (dest / "sentinel.txt").is_file()


def test_stage_local_replaces_preseeded_dir(tmp_path, state_dir):
    # Pre-seeded (attacker/stale) dir with NO marker must be replaced, not scanned.
    src = _mk_src(tmp_path, "src", content="real")
    app_dir = tmp_path / "ws" / "app1"
    dest = app_dir / "service"
    dest.mkdir(parents=True)
    (dest / "attacker.py").write_text("evil", encoding="utf-8")
    _stage_repo(str(src), app_dir, "service", None)
    assert not (dest / "attacker.py").exists()       # foreign content removed
    assert (dest / "app.py").read_text() == "real"   # real source staged
    assert _stage_dir_bound(dest, str(src))          # now bound to the real ref


def test_stage_local_replaces_foreign_binding(tmp_path, state_dir):
    # Dir bound to ref A must not be reused for ref B at the same path.
    src_a = _mk_src(tmp_path, "a", content="A")
    src_b = _mk_src(tmp_path, "b", content="B")
    app_dir = tmp_path / "ws" / "app1"
    _stage_repo(str(src_a), app_dir, "service", None)
    dest = app_dir / "service"
    assert _stage_dir_bound(dest, str(src_a))
    _stage_repo(str(src_b), app_dir, "service", None)   # same dest, different ref
    assert (dest / "app.py").read_text() == "B"
    assert _stage_dir_bound(dest, str(src_b))
    assert not _stage_dir_bound(dest, str(src_a))


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes only")
def test_stage_marker_dir_is_owner_only(tmp_path, state_dir):
    """The stage marker is an integrity control -- it proves a staged dir came from
    the ref it claims, so a workspace-only writer cannot forge reuse of a foreign
    tree. Its directory was created at the umask default while every other directory
    under the state root was owner-only."""
    import stat as _stat

    src = _mk_src(tmp_path, "src")
    app_dir = tmp_path / "ws" / "app1"
    _stage_repo(str(src), app_dir, "service", None)
    markers = state_dir / "stage-markers"
    assert markers.is_dir()
    assert _stat.S_IMODE(markers.stat().st_mode) == 0o700
    assert _stat.S_IMODE(state_dir.stat().st_mode) == 0o700


def test_marker_lives_outside_workspace(tmp_path, state_dir):
    # The binding anchor must be in the operator-private state dir, NOT inside
    # the (shared/attacker-writable) staged tree — else a workspace writer forges it.
    src = _mk_src(tmp_path, "src")
    app_dir = tmp_path / "ws" / "app1"
    _stage_repo(str(src), app_dir, "service", None)
    dest = app_dir / "service"
    assert str(state_dir) in str(_stage_marker_path(dest).resolve())
    assert not (dest / ".vvaharness-stage.json").exists()   # nothing in the scan tree