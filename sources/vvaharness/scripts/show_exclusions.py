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

import sys

from vvaharness import config as cm
from vvaharness.orchestrator import _default_config
from vvaharness.pipeline.stages.s1_preprocess import (_DEFAULT_EXCLUDE_DIRS, _DEFAULT_EXCLUDE_EXTS,
                                 _DEFAULT_EXCLUDE_GLOBS, _exclusion_sets)

# Resolve config the same way the CLI does — ./config.yaml if present, else the
# packaged default profile — so this helper doesn't crash without a local file.
cfg = cm.load(_default_config())
dirs, exts, globs = _exclusion_sets(cfg)

cfg_dirs  = {d.lower() for d in (getattr(cfg.step1, "exclude_dirs",  None) or [])}
cfg_exts  = set(getattr(cfg.step1, "exclude_exts",  None) or [])
cfg_globs = set(getattr(cfg.step1, "exclude_globs", None) or [])
def_dirs  = {d.lower() for d in _DEFAULT_EXCLUDE_DIRS}


def tag(x, in_default, in_cfg):
    if in_default and in_cfg: return "both   "
    if in_cfg:                return "config "
    return                       "builtin"


print(f"\n=== EXCLUDE_DIRS  (effective: {len(dirs)}; case-insensitive path-segment match) ===")
for x in sorted(dirs):
    print(f"  [{tag(x, x in def_dirs, x in cfg_dirs)}] {x}")

print(f"\n=== EXCLUDE_EXTS  (effective: {len(exts)}; suffix match) ===")
for x in sorted(exts):
    print(f"  [{tag(x, x in _DEFAULT_EXCLUDE_EXTS, x in cfg_exts)}] {x}")

print(f"\n=== EXCLUDE_GLOBS  (effective: {len(globs)}; repo-relative posix fnmatch) ===")
for g in globs:
    print(f"  [{tag(g, g in _DEFAULT_EXCLUDE_GLOBS, g in cfg_globs)}] {g}")

print(f"\n=== SIZE GATE ===")
print(f"  max_file_kb = {getattr(cfg.step1, 'max_file_kb', 1024)}  "
      f"(files larger than this are skipped)")

# Sanity warnings for distribution
warn = []
for e in sorted(exts):
    if not e.startswith("."):
        warn.append(f"  ext missing leading dot: {e!r}")
seen = {}
for e in exts:
    k = e.lower()
    seen.setdefault(k, []).append(e)
for k, v in seen.items():
    if len(v) > 1:
        warn.append(f"  duplicate ext entries (case/repeat): {v}")
if warn:
    print("\n=== WARNINGS ===")
    print("\n".join(warn))
