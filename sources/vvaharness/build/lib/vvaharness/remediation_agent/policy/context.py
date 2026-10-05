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

"""remediation_agent.policy.context — load the gate + playbook once per run.

:class:`PolicyContext` bundles the deterministic gate, the fix-strategy
playbook, and the repo's detected frameworks. :func:`build_context` resolves any
profile path overrides (mirroring how ``scan.py`` resolves ``cfg.inject.*``) and
detects frameworks once from the repo root."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from vvaharness.config import is_network_path
from vvaharness.orchestrator.config_paths import _resolve_against
from vvaharness.remediation_agent.frameworks import detect_frameworks
from vvaharness.remediation_agent.playbook import Playbook
from vvaharness.remediation_agent.policy_gate import RemediationGate

log = logging.getLogger(__name__)


def _sr(cfg, key: str, default):
    sr = getattr(cfg, "step_remediate", None)
    return getattr(sr, key, default) if sr else default


def policy_enabled(cfg) -> bool:
    """Whether the policy gate / playbook are active for this run.

    The gate is controlled by ``step_remediate.enforce_policy`` and defaults
    on when a custom profile omits the key. Operators may still explicitly opt
    out for a trusted target."""
    return bool(_sr(cfg, "enforce_policy", True))


@dataclass
class PolicyContext:
    """Everything the per-finding loop needs to enforce policy. Built once per
    run (the gate + playbook are loaded from the shipped rule files under
    repo-root inputs/, frameworks are detected once from the repo root)."""
    gate: RemediationGate
    playbook: Playbook
    frameworks: set[str]
    enabled: bool = True



def _resolve_input(cfg, raw: str | None) -> str | None:
    """Resolve an input-style path (e.g. ``./inputs/remediation_policy.yaml``)
    against the directory the config was loaded from — exactly how
    ``scan.py`` resolves ``cfg.inject.*``. Absolute paths pass through; a
    ``None``/empty value falls back to the gate/playbook's own shipped default.

    If the resolved path does NOT exist, return ``None`` so the caller falls
    back to the gate/playbook's bundled default (repo-root ``inputs/``) instead
    of handing the loader a non-existent path — which would otherwise fail
    closed and deny EVERY finding. This matters for the packaged ``default``
    profile, whose config dir is ``vvaharness/config/profiles/`` so
    ``./inputs/...`` resolves to a directory that ships no input files."""
    if not raw:
        return None
    # When cfg_dir is set, _resolve_against rejects network/UNC paths; guard the
    # cfg_dir-less branch too so a UNC override can't slip through unresolved and
    # leak the user's NTLM hash over SMB on Windows.
    if is_network_path(raw):
        raise ValueError(
            f"refusing network/UNC remediation input path {raw!r} "
            f"(reading it could leak credentials over SMB)")
    cfg_dir = getattr(cfg, "_data", {}).get("_config_dir") if cfg else None
    resolved = _resolve_against(Path(cfg_dir), raw) if cfg_dir else raw
    if resolved and not Path(resolved).exists():
        log.warning("configured remediation input %r not found at %s — "
                    "falling back to bundled default", raw, resolved)
        return None
    return resolved


def build_context(cfg, repo_root: str | Path) -> PolicyContext:
    """Load the gate + playbook (honouring profile path overrides) and detect
    the repo's frameworks once."""
    policy_file = _resolve_input(cfg, _sr(cfg, "policy_file", None))
    playbook_file = _resolve_input(cfg, _sr(cfg, "playbook_file", None))
    gate = RemediationGate(policy_file)
    pb = Playbook(playbook_file)
    try:
        fw = detect_frameworks(repo_root)
    except Exception:                                  # noqa: BLE001
        fw = set()
    return PolicyContext(gate=gate, playbook=pb, frameworks=fw,
                         enabled=policy_enabled(cfg))
