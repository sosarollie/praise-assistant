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

"""remediation_agent.playbook — fix-strategy resolver for the Remediation Agent.

The agent does NOT invent a fix approach — it selects one from
``inputs/remediation_playbook.yaml``. :meth:`Playbook.resolve` walks
CWE → language → framework → ``default`` → CWE-level ``fallback`` → None, and the
resolved :class:`Strategy` text is injected into the agentic prompt (see
``remediation_agent.prompts``). :meth:`Playbook.guidance_for` returns prose-only
advice for the policy-denied (guidance-only) path."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from vvaharness.remediation_agent.rule_paths import locate_rule

log = logging.getLogger(__name__)

def _default_playbook_path() -> Path:
    """Locate the playbook in a source checkout or an installed wheel."""
    return locate_rule("remediation_playbook.yaml", __file__)


DEFAULT_PLAYBOOK_PATH = _default_playbook_path()
RULES_DIR = DEFAULT_PLAYBOOK_PATH.parent


@dataclass
class Strategy:
    name: str
    instruction: str
    cwe: str
    cwe_title: str = ""
    confidence: str = "suggest"      # auto | suggest | guidance
    example_before: str = ""
    example_after: str = ""
    allowed_deps: list[str] = field(default_factory=list)
    fix_location: str = "sink"       # sink | source | trust_boundary
    notes: str = ""

    def as_prompt_block(self) -> str:
        """Render the strategy as an authoritative prompt section the agent must
        follow. Kept compact (a few lines) so it's cheap on every backend."""
        lines = [
            f"## Required fix strategy: {self.name}",
            f"CWE: {self.cwe}" + (f" — {self.cwe_title}" if self.cwe_title else ""),
            f"Fix location: {self.fix_location}",
            "",
            self.instruction.strip() or "(no specific instruction)",
        ]
        if self.example_after:
            lines += ["", "Reference pattern (the shape your fix should take):",
                      "```", self.example_after.strip(), "```"]
        deps = ", ".join(self.allowed_deps) if self.allowed_deps else "(none)"
        lines += ["", f"Allowed new dependencies: {deps}.",
                  "Select THIS strategy; do not invent an alternative approach."]
        return "\n".join(lines)


class Playbook:

    def __init__(self, path: Path | str | None = None):
        self._cwe: dict = {}
        self._policy: dict = {}
        self._loaded = False
        self._load(Path(path) if path else DEFAULT_PLAYBOOK_PATH)

    def _load(self, path: Path) -> None:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:                       # noqa: BLE001
            log.error("playbook load failed (%s) — guidance-only for all "
                      "findings", exc)
            return
        self._cwe = doc.get("cwe") or {}
        self._policy = doc.get("policy") or {}
        self._loaded = True

    @property
    def max_diff_lines(self) -> int:
        return int(self._policy.get("max_diff_lines", 40))

    @property
    def max_files_touched(self) -> int:
        return int(self._policy.get("max_files_touched", 2))

    # ─────────────────────────────────────────────────────────── resolve
    def resolve(self, cwe: str | None, language: str,
                frameworks: set[str]) -> Strategy | None:
        """CWE → language → framework → ``default`` → CWE ``fallback`` → None."""
        entry = self._cwe.get(cwe or "")
        if not entry:
            return None
        title = entry.get("title", "")
        conf = entry.get("confidence", "suggest")
        loc = entry.get("fix_location", "sink")
        notes = entry.get("notes", "")

        strategies = entry.get("strategies") or {}
        lang_block = strategies.get(language) or strategies.get("default") or {}

        node: dict | None = None
        if isinstance(lang_block, dict):
            # framework match first, then 'default' under that language.
            for fw in frameworks or set():
                if fw in lang_block:
                    node = lang_block[fw]
                    break
            if node is None:
                node = (lang_block.get("default")
                        or (lang_block if "name" in lang_block else None))
        if node is None:
            node = entry.get("fallback")
        if not node:
            return None
        return Strategy(
            name=node.get("name", "unnamed"),
            instruction=str(node.get("instruction", "")).strip(),
            cwe=cwe or "", cwe_title=title,
            confidence=node.get("confidence", conf),
            example_before=str(node.get("example_before", "")).strip(),
            example_after=str(node.get("example_after", "")).strip(),
            allowed_deps=list(node.get("allowed_deps") or []),
            fix_location=loc, notes=notes,
        )

    def guidance_for(self, cwe: str | None) -> str:
        """Prose-only advice for guidance-only (policy-denied) outcomes."""
        entry = self._cwe.get(cwe or "") or {}
        notes = entry.get("notes") or ""
        title = entry.get("title") or (cwe or "this finding")
        fb = (entry.get("fallback") or {}).get("instruction", "")
        body = notes or fb or (
            "No safe automated fix is defined for this vulnerability class. "
            "Review the source→sink trace and apply a context-appropriate "
            "mitigation manually.")
        return f"**{title}** — {body}"
