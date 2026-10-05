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

"""Packaging guard (F34): the internal rule-corpus leak must not recur.

The distribution must never ship org-specific / harvested ``*.kb.yaml`` corpora.
These tests assert on the packaging *allowlist* rather than the working tree so
they are deterministic regardless of any untracked local corpora a developer may
have sitting in ``vvaharness/rules/``.
"""
from __future__ import annotations

import importlib.metadata
import re
import tomllib
from pathlib import Path

from vvaharness.util import environment

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _REPO_ROOT / "pyproject.toml"


def _package_data_rules() -> list[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    entries = data["tool"]["setuptools"]["package-data"]["vvaharness"]
    return [e for e in entries if e.startswith("rules/")]


def test_no_broad_rules_glob():
    """A broad ``rules/*.yaml`` glob is what let ``custom.kb.yaml`` ship; forbid it."""
    rules = _package_data_rules()
    assert "rules/*.yaml" not in rules, (
        "Broad rules/*.yaml glob would package any dropped-in corpus, including "
        "harvested internal *.kb.yaml files. Use an explicit allowlist."
    )
    yaml_globs = [e for e in rules if e.endswith("*.yaml") or e.endswith("*.yml")]
    assert not yaml_globs, f"No wildcard yaml packaging allowed under rules/: {yaml_globs}"


def test_only_public_corpora_are_packaged():
    """Only the three public, generated/generic corpora may be packaged."""
    allowed = {
        "rules/sources.generated.yaml",
        "rules/sinks.generated.yaml",
        "rules/generic.kb.yaml",
    }
    packaged_yaml = {e for e in _package_data_rules() if e.endswith((".yaml", ".yml"))}
    extra = packaged_yaml - allowed
    assert not extra, f"Unexpected rule corpora in packaging allowlist: {sorted(extra)}"


def test_internal_catalogue_not_tracked():
    """The harvested internal catalogue must not be re-added to the tree."""
    assert not (_REPO_ROOT / "vvaharness" / "rules" / "custom.kb.yaml").exists(), (
        "vvaharness/rules/custom.kb.yaml is a harvested internal review catalogue "
        "and must not exist in the repository (F34)."
    )


def _dependency(name: str) -> str:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dep = next((d for d in data["project"]["dependencies"]
                if re.match(rf"{re.escape(name)}\s*[\[<>=!~;]", d)), None)
    assert dep is not None, f"{name} is no longer a declared dependency"
    return dep


def test_anthropic_pin_still_bars_the_breaking_major(monkeypatch):
    """Deleting or reshaping the ``anthropic`` ceiling silently reopens the 1.x
    crash: 1.0 removed ``temperature`` from the Messages methods, so a
    ``via:sdk`` role configured with one raises ``TypeError`` before any request
    is sent.

    Asserted through ``environment.anthropic_version_check()`` fed the REAL
    declaration from pyproject.toml, not by pattern-matching the string. A
    regex-on-the-string guard passes for pin shapes the check cannot actually
    evaluate (``<=``, ``~=``, an extra), which would leave the row reporting
    green on exactly the environment it exists to catch. Driving the check
    means the guard fails whenever the declaration and the comparison disagree.

    pyproject.toml rather than installed metadata so it holds in a source-tree
    run, where vvaharness has no .dist-info at all.
    """
    declared = _dependency("anthropic")
    real_version = importlib.metadata.version

    def fake(installed):
        monkeypatch.setattr(
            importlib.metadata, "version",
            lambda n: installed if n == "anthropic" else real_version(n))
        monkeypatch.setattr(importlib.metadata, "requires", lambda n: [declared])
        return environment.anthropic_version_check()

    blocked = fake("1.2.0")
    assert blocked.status == environment.FAIL and blocked.required, (
        f"anthropic pin no longer bars the 1.x major: {declared!r} "
        f"-> {blocked!r}")
    # Read the floor from the declaration: a literal goes stale on the next bump.
    floor = re.search(r">=\s*(\d[^,\s]*)", declared)
    assert floor, f"anthropic declaration has no floor to check: {declared!r}"
    allowed = fake(floor.group(1))
    assert allowed.status == environment.OK and not allowed.required, (
        f"anthropic pin rejects the floor it declares: {declared!r} "
        f"-> {allowed!r}")
