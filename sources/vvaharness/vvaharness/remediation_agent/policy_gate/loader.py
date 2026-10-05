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

"""remediation_agent.policy_gate.loader — parse the shipped remediation_policy.yaml.

Reads + normalises the policy document into the structured fields the gate
holds (deny/allow CWE maps, deny/forbid path globs, kill-switch, default
action). Fail-closed: any load/parse error returns ``None`` so the gate denies
everything."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from vvaharness.remediation_agent.policy_gate.action import Action

log = logging.getLogger(__name__)


def _norm_cwe(raw) -> str | None:
    """Normalise a CWE reference (``943`` / ``CWE-943`` / ``cwe-943``) → ``CWE-943``."""
    if raw is None:
        return None
    s = str(raw).strip().upper()
    if s.startswith("CWE-"):
        s = s[4:]
    return f"CWE-{s}" if s.isdigit() else None


@dataclass
class PolicyData:
    """The structured policy the gate enforces (post-parse)."""
    deny: dict[str, str] = field(default_factory=dict)        # CWE-id -> reason
    allow: set[str] = field(default_factory=set)              # CWE-ids patchable
    deny_paths: list[str] = field(default_factory=list)
    forbid_patch_paths: list[str] = field(default_factory=list)
    kill_env: str | None = None
    kill_file: Path | None = None
    default: Action = Action.GUIDANCE_ONLY


def parse_policy(path: Path) -> PolicyData | None:
    """Parse ``remediation_policy.yaml`` into a :class:`PolicyData`, or ``None``
    on any load/parse error (the caller fails closed and denies everything)."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:                       # noqa: BLE001
        log.error("remediation policy load failed (%s) — fail-closed", exc)
        return None

    data = PolicyData()
    # default_action is binary: ``allow`` → patch everything not denied;
    # ``deny`` (the safe default) → patch only what the allow-list lists.
    default = str(doc.get("default_action", "deny")).lower()
    data.default = Action.PATCH if default == "allow" else Action.GUIDANCE_ONLY

    for entry in doc.get("deny", []) or []:
        cwe = _norm_cwe(entry.get("id"))
        if not cwe:
            continue
        reason = entry.get("reason", "policy_denied")
        data.deny[cwe] = reason
        for child in entry.get("descendants", []) or []:
            c = _norm_cwe(child)
            if c:
                data.deny.setdefault(c, f"descendant_of:{cwe} ({reason})")

    for entry in doc.get("allow", []) or []:
        cwe = _norm_cwe(entry.get("id"))
        if cwe:
            data.allow.add(cwe)

    data.deny_paths = [str(p) for p in (doc.get("deny_paths") or [])]
    data.forbid_patch_paths = [str(p) for p in (doc.get("forbid_patch_paths") or [])]
    ks = doc.get("kill_switch") or {}
    data.kill_env = ks.get("env_var") or None
    kf = ks.get("file")
    data.kill_file = Path(kf) if kf else None
    log.info(
        "remediation policy loaded: deny=%d allow=%d deny_paths=%d "
        "forbid_patch_paths=%d default=%s",
        len(data.deny), len(data.allow), len(data.deny_paths),
        len(data.forbid_patch_paths), data.default,
    )
    return data
