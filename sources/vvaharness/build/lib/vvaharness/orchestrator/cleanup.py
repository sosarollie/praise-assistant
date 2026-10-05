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


from __future__ import annotations

"""orchestrator.cleanup — see package docstring."""
import os
import shutil
import stat
import sys
from pathlib import Path

from vvaharness.orchestrator.artifacts import CASE_DIR_NAME, SCAN_DIR_NAME


def _rmtree_rw(path: Path) -> None:
    """shutil.rmtree that clears the read-only bit on Windows, where RO .git/objects/* make ignore_errors=True silently leave the tree behind."""
    def _on_err(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    shutil.rmtree(path, onerror=_on_err)


# A profile that doesn't set output.preserve_on_cleanup falls back to this tuple; anything absent from it is deleted outright by the batch clone purge — a case file not listed here is data loss, not a stale artefact.
_CLONE_KEEP_DEFAULT = (SCAN_DIR_NAME, CASE_DIR_NAME)


def _preserve_set(cfg) -> set[str]:
    vals = getattr(getattr(cfg, "output", None), "preserve_on_cleanup", None)
    return set(vals) if vals else set(_CLONE_KEEP_DEFAULT)


def _purge_clone(root: Path, keep: set[str]) -> None:
    """Delete the cloned source under `root` but preserve the named artifact folders (security-scan/ and security-remediation/ by default)."""
    if not root.exists():
        return
    for child in root.iterdir():
        if child.name in keep:
            continue
        if child.is_dir():
            _rmtree_rw(child)
        else:
            try:
                os.chmod(child, stat.S_IWRITE)
            except OSError:
                pass
            child.unlink(missing_ok=True)

    # A failed delete would otherwise leave a secret-bearing clone on disk with no signal; surface any survivor so the operator knows.
    leftover = [c.name for c in root.iterdir() if c.name not in keep]
    if leftover:
        print(f"  [cleanup] WARN: {len(leftover)} item(s) survived purge under "
              f"{root}: {', '.join(sorted(leftover))}", file=sys.stderr)
