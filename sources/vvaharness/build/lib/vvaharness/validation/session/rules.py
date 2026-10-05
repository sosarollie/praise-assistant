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

"""Read the bundled validation rules as prompt text.

``.claude/rules/`` is injected only for the ``cli``/``sdk`` backends; others get the same
rules inlined into their prompts instead -- same files, different delivery.
"""

from __future__ import annotations

import re

# The rules files open with an HTML licence comment that must not reach the model.
_LICENCE_COMMENT = re.compile(r"\A\s*<!--.*?-->\s*", re.DOTALL)

SCORING_RULES = "scoring-matrix.md"
ADVERSARIAL_RULES = "adversarial-review.md"


def _rules_text(filename: str) -> str:
    """Return the body of a bundled rules file, licence comment stripped."""
    # Imported lazily: config_inject pulls in the launcher, which imports this module.
    from vvaharness.validation.session import config_inject

    path = config_inject.CLAUDE_CONFIG_SOURCE / "rules" / filename
    if not path.is_file():
        raise FileNotFoundError(f"required claude_config rule missing at {path}")
    return _LICENCE_COMMENT.sub("", path.read_text(encoding="utf-8")).strip()


def orchestrator_rules_text() -> str:
    """Both rules files, for the orchestrator's system prompt."""
    return f"{_rules_text(SCORING_RULES)}\n\n{_rules_text(ADVERSARIAL_RULES)}"


def persona_rules_text() -> str:
    """The adversarial-review rules, for each persona's prompt."""
    return _rules_text(ADVERSARIAL_RULES)


__all__ = [
    "ADVERSARIAL_RULES",
    "SCORING_RULES",
    "orchestrator_rules_text",
    "persona_rules_text",
]
