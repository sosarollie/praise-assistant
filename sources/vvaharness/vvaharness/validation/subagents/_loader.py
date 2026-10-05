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

"""Load subagent definitions from bundled .md authoring files."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import replace
from importlib.resources import files
from pathlib import Path

from vvaharness.backends.harness import SubagentDefinition
from vvaharness.validation.models.persona_report import PersonaReport
from vvaharness.validation.subagents._frontmatter import parse_frontmatter
from vvaharness.validation.subagents.models import SubagentFrontmatterMeta

FIX_PATH_AGENTS: tuple[str, ...] = (
    "security-architect",
    "penetration-tester",
    "cross-repo-analyzer",
)


def _optional_str_tuple(value: list[str] | None) -> tuple[str, ...] | None:
    """Convert a frontmatter list value to a tuple, or None if empty or absent."""
    return tuple(value) if isinstance(value, list) and value else None


def _build_subagent_definition(
    meta: SubagentFrontmatterMeta,
    prompt: str,
) -> SubagentDefinition:
    """Build a SubagentDefinition from parsed frontmatter and body prompt."""
    name = meta.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("subagent frontmatter missing 'name'")
    description = meta.get("description")
    if not isinstance(description, str) or not description:
        raise ValueError(f"subagent {name!r} missing 'description'")
    model = meta.get("model")
    return SubagentDefinition(
        name=name,
        description=description,
        prompt=prompt,
        tools=_optional_str_tuple(meta.get("allowedTools")),
        disallowed_tools=_optional_str_tuple(meta.get("deniedTools")),
        model=model if isinstance(model, str) else None,
        skills=_optional_str_tuple(meta.get("skills")),
        # Every validation persona returns a structured PersonaReport.
        response_model=PersonaReport,
    )


def _iter_bundled_files() -> Iterator[Path]:
    """Yield Path objects for each bundled .md subagent file."""
    pkg_root = files("vvaharness.validation.subagents")
    for entry in pkg_root.iterdir():
        if entry.name.endswith(".md"):
            yield Path(str(entry))


def load_agents(
    names: Iterable[str] | None = None,
    model_overrides: dict[str, str] | None = None,
    tools_override: tuple[str, ...] | None = None,
    prompt_suffix: str | None = None,
) -> dict[str, SubagentDefinition]:
    """Load subagent definitions from bundled .md files, optionally filtered and overridden."""
    wanted: set[str] | None = set(names) if names is not None else None
    overrides = model_overrides or {}
    result: dict[str, SubagentDefinition] = {}
    for path in _iter_bundled_files():
        text = path.read_text(encoding="utf-8")
        meta, prompt = parse_frontmatter(text)
        subagent = _build_subagent_definition(meta, prompt)
        if wanted is not None and subagent.name not in wanted:
            continue
        if subagent.name in overrides:
            subagent = replace(subagent, model=overrides[subagent.name])
        if tools_override is not None:
            subagent = replace(subagent, tools=tools_override)
        if prompt_suffix:
            subagent = replace(
                subagent, prompt=f"{subagent.prompt.rstrip()}\n\n{prompt_suffix}"
            )
        result[subagent.name] = subagent
    _assert_all_found(wanted, set(result.keys()))
    return result


def _assert_all_found(wanted: set[str] | None, found: set[str]) -> None:
    """Raise if any explicitly-requested subagent name was not loaded."""
    if wanted is None:
        return
    missing = wanted - found
    if missing:
        raise ValueError(f"requested subagents not found: {sorted(missing)}")
