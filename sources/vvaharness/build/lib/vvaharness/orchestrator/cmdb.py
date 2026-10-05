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

"""orchestrator.cmdb — see package docstring."""
import sys
from pathlib import Path

from vvaharness.models import AppProfile
from vvaharness.orchestrator.config_paths import _resolve_against
from vvaharness.report import enrich as vcs_enrich

_CMDB_CSV: str = ""


def _cmdb_path() -> str:
    return _CMDB_CSV


def _set_cmdb_path(cfg, cfg_dir: Path) -> None:
    """Resolve inject.cmdb_file to an absolute path, or "" if unset. A missing
    or empty path is fine — load_cmdb_csv returns {} and VulContextSeverity is skipped."""
    global _CMDB_CSV
    p = getattr(getattr(cfg, "inject", None), "cmdb_file", None)
    _CMDB_CSV = _resolve_against(cfg_dir, p) if p else ""


def _load_app_profile(application_id: str | None
                      ) -> tuple[AppProfile | None, "vcs_enrich.AppInfo | None"]:
    """CMDB lookup → (AppProfile threaded into ctx for s1–s8; raw AppInfo for
    post-s7 VulContextSeverity/OffensivePriority enrichment + s9 SARIF). Loaded once per scan."""
    if not application_id:
        return None, None
    try:
        cmdb = vcs_enrich.load_cmdb_csv(_cmdb_path())
        info = vcs_enrich.lookup_app(application_id, cmdb, {})
    except Exception as e:
        print(f"  [cmdb] lookup failed for {application_id}: {e}", file=sys.stderr)
        return None, None
    if info is None:
        print(f"  [cmdb] application_id {application_id} not found", file=sys.stderr)
        return None, None
    profile = AppProfile(
        application_id=str(application_id),
        name=info.name,
        externally_facing=info.externally_facing,
        pci_scoped=info.pci_scoped,
        processes_pan=info.processes_pan,
        pii=info.pii,
        source=info.source,
    )
    return profile, info
