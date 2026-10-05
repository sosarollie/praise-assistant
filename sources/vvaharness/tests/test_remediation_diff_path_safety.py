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

"""Repo-relative file references in diff capture are confined to the repo.

``snapshot_files`` and ``synth_unified_diff`` take file references that originate
from the scan ``Finding`` and from LLM/plugin-controlled ``verdict.changes`` /
``files_touched``. An absolute path, a ``../`` traversal, or an in-repo symlink
resolving outside the tree must NOT read host or CI-workspace files into the
snapshot or the synthesized diff artifact (CWE-22). These tests assert each
escape is refused (fails closed) while ordinary in-repo files still work.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff import (
    _safe_repo_path,
    capture_git_diff,
    snapshot_files,
    synth_unified_diff,
)


def test_safe_repo_path_accepts_in_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "x.py").write_text("ok\n")
    p = _safe_repo_path(repo, "app/x.py:10-12")  # location suffix tolerated
    assert p is not None
    assert p == (repo / "app" / "x.py").resolve()


def test_safe_repo_path_rejects_absolute(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("secret\n")
    assert _safe_repo_path(repo, str(outside)) is None


def test_safe_repo_path_rejects_dotdot(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "secret.txt").write_text("secret\n")
    assert _safe_repo_path(repo, "../secret.txt") is None


def test_safe_repo_path_rejects_symlink_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "real.txt"
    outside.write_text("secret\n")
    (repo / "link.txt").symlink_to(outside)
    assert _safe_repo_path(repo, "link.txt") is None


# START GENAI
def test_safe_repo_path_rejects_unc_and_drive(tmp_path: Path) -> None:
    """UNC and Windows drive-letter refs are host-rooted and must be
    rejected on ANY platform — Path.is_absolute() only flags them when running
    on Windows, so a Windows-style ref slips through on a POSIX runner."""
    repo = tmp_path / "repo"
    repo.mkdir()
    for ref in (r"\\attacker\share\x", "//attacker/share/x",
                r"C:\Windows\System32\x", "C:/Windows/x", "D:rel"):
        assert _safe_repo_path(repo, ref) is None, ref


def test_capture_git_diff_drops_unsafe_paths(tmp_path: Path, monkeypatch) -> None:
    """capture_git_diff must confine every ref to the repo before it
    reaches a git pathspec. An absolute / UNC / drive-letter / ../ ref (e.g.
    ``\\\\attacker\\share`` — an outbound SMB auth leak on a Windows runner)
    must never appear in the ``git add`` / ``git diff`` argv; only the in-repo
    file survives."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "x.py").write_text("v=1\n")
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-qm", "init"],
                   check=True, capture_output=True)
    (repo / "app" / "x.py").write_text("v=2\n")   # a real change to diff

    seen: list[list[str]] = []
    real_run = subprocess.run

    def spy(cmd, *a, **k):
        seen.append(list(cmd))
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(
        "vvaharness.remediation_agent.artifacts.diff.gitcapture.subprocess.run",
        spy)

    malicious = [r"\\attacker\share\x", "//attacker/share/x",
                 r"C:\Windows\System32\x", "/etc/passwd", "../escape"]
    capture_git_diff(repo, ["app/x.py", *malicious])

    argv = [tok for cmd in seen for tok in cmd]
    for bad in malicious:
        assert bad not in argv, f"unsafe ref reached git argv: {bad!r}"
    assert "app/x.py" in argv          # the legit in-repo path WAS scoped


def test_capture_git_diff_pins_deterministic_safe_git_options(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "x.py").write_text("v=2\n")
    calls: list[tuple[list[str], dict]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append((list(cmd), kwargs))
        stdout = "true\n" if "rev-parse" in cmd else ""
        if "diff" in cmd:
            stdout = "diff --git a/app/x.py b/app/x.py\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(
        "vvaharness.remediation_agent.artifacts.diff.gitcapture.subprocess.run",
        fake_run,
    )

    assert capture_git_diff(repo, ["app/x.py"]) is not None
    assert all(kwargs["env"]["LC_ALL"] == "C" for _, kwargs in calls)
    assert all("color.ui=false" in command for command, _ in calls)
    diff_command = next(command for command, _ in calls if "diff" in command)
    assert "--no-ext-diff" in diff_command
    assert diff_command[-3:] == ["--no-ext-diff", "--", "app/x.py"]
# END GENAI


def test_snapshot_skips_absolute_path(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("TOP SECRET\n")
    snap = snapshot_files(repo, [str(outside)])
    # The out-of-repo file is neither read nor recorded under any key.
    assert snap == {}
    assert "TOP SECRET" not in "".join(str(v) for v in snap.values())


def test_snapshot_skips_dotdot_but_keeps_in_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "ok.py").write_text("clean\n")
    (tmp_path / "secret.txt").write_text("secret\n")
    snap = snapshot_files(repo, ["../secret.txt", "app/ok.py"])
    assert "app/ok.py" in snap and snap["app/ok.py"] == "clean\n"
    assert all("secret" not in (v or "") for v in snap.values())


def test_snapshot_skips_symlink_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "real.txt"
    outside.write_text("secret\n")
    (repo / "link.txt").symlink_to(outside)
    snap = snapshot_files(repo, ["link.txt"])
    assert snap == {}


def test_synth_diff_does_not_read_out_of_repo_extra_file(tmp_path: Path) -> None:
    """An LLM-reported ``extra_files`` entry pointing outside the repo must not
    have its contents pulled into the synthesized diff."""
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("SECRET CONTENTS\n")
    diff = synth_unified_diff(repo, before={}, extra_files=[str(outside)])
    # No in-repo change + escape refused → nothing to diff.
    assert diff is None


def test_synth_diff_renders_in_repo_change(tmp_path: Path) -> None:
    """A genuine in-repo edit still produces a diff (escapes are dropped, not
    fatal)."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "x.py").write_text("new line\n")
    outside = tmp_path / "secret.txt"
    outside.write_text("SECRET\n")
    diff = synth_unified_diff(
        repo,
        before={"app/x.py": "old line\n"},
        extra_files=[str(outside), "app/x.py"],
    )
    assert diff is not None
    assert "app/x.py" in diff
    assert "new line" in diff
    # The out-of-repo file's contents never leak into the diff.
    assert "SECRET" not in diff
