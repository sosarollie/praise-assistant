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

"""Tests for per-CWE validator-hint loading and launch-prompt injection.

Exercises the live hints loader (``vvaharness.validation.hints``) and the
prompt renderer (``vvaharness.validation.session.launch_prompt``) directly --
no model/SDK call is made. The hints data ships at
``vvaharness/validation/hints/validator_hints.yaml``.
"""
from vvaharness.models import Finding
from vvaharness.validation.hints import hints_for
from vvaharness.validation.models import Manifest
from vvaharness.validation.session.launch_prompt import build_launch_prompt


def test_hints_for_known_cwe() -> None:
    """A mapped CWE returns its non-empty bypass list."""
    hints = hints_for("CWE-89")
    assert hints, "CWE-89 must map to a non-empty bypass list"
    assert any("stacked queries" in h for h in hints)


def test_hints_for_prefix_match() -> None:
    """A 'CWE-89: SQL Injection' style category resolves via the prefix branch."""
    assert hints_for("CWE-89: SQL Injection") == hints_for("CWE-89")


def test_hints_for_unmapped_and_empty() -> None:
    """An unmapped CWE and the empty string both return []."""
    assert hints_for("CWE-9999") == []
    assert hints_for("") == []


def _manifest(category: str) -> Manifest:
    """A manifest whose finding carries *category* as its CWE — the hint lookup key."""
    return Manifest(
        case_id="F-0",
        session_id="s",
        finding=Finding(
            title="SQLi", file="app/x.py", line_start=1, vuln_class="injection", cwe=category
        ),
    )


def test_launch_prompt_renders_hints() -> None:
    """The launch prompt injects bypass hints for a finding whose CWE is mapped."""
    prompt = build_launch_prompt(_manifest("CWE-89"))
    assert "Known bypass patterns for CWE-89" in prompt
    assert "stacked queries" in prompt


def test_launch_prompt_omits_section_without_hints() -> None:
    """No bypass section is rendered when the finding's CWE has no hints."""
    assert "Known bypass patterns" not in build_launch_prompt(_manifest("CWE-9999"))
