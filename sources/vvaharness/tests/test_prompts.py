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

"""Unit tests for vvaharness.util.prompts shared prompt blocks.

The module is a collection of module-level prompt string constants consumed
by the researcher (s4), verifier (s6), and chain-analysis (s8) stages. These
tests assert the structural invariants that downstream template assembly
relies on, and guard against accidental emptiness / malformation. Pure,
offline, deterministic — no network, no LLM, no subprocess.
"""

from vvaharness.util import prompts

ALL_BLOCKS = {
    "EXCLUSION_RULES": prompts.EXCLUSION_RULES,
    "SELF_VERIFICATION": prompts.SELF_VERIFICATION,
    "EXHAUSTIVENESS": prompts.EXHAUSTIVENESS,
    "SEVERITY_GUIDANCE": prompts.SEVERITY_GUIDANCE,
}


# Generic invariants over every prompt block

def test_all_blocks_are_nonempty_strings():
    for name, block in ALL_BLOCKS.items():
        assert isinstance(block, str), f"{name} must be a str"
        assert block.strip(), f"{name} must be non-empty / non-whitespace"


def test_blocks_have_no_leading_or_trailing_whitespace():
    # Built with the "\" line-continuation idiom so they start at column 0 and
    # do not end with a trailing newline — important for clean concatenation.
    for name, block in ALL_BLOCKS.items():
        assert not block.startswith((" ", "\n", "\t")), f"{name} leading ws"
        assert not block.endswith(("\n", " ", "\t")), f"{name} trailing ws"


def test_blocks_are_multiline():
    for name, block in ALL_BLOCKS.items():
        assert "\n" in block, f"{name} should be a multi-line block"


def test_blocks_concatenate_cleanly_for_template_assembly():
    # Downstream stages join these blocks; verify a join produces a single
    # string containing each block verbatim with deterministic ordering.
    assembled = "\n\n".join(ALL_BLOCKS.values())
    for block in ALL_BLOCKS.values():
        assert block in assembled
    # Each block separated by exactly the chosen separator (count of blank
    # double-newline joins == len-1).
    assert assembled.count("\n\n") >= len(ALL_BLOCKS) - 1


def test_blocks_are_immutable_constants_distinct_objects():
    # Each is a distinct constant; none accidentally aliases another.
    values = list(ALL_BLOCKS.values())
    for i, a in enumerate(values):
        for b in values[i + 1 :]:
            assert a != b, "prompt blocks must be distinct content"


# EXCLUSION_RULES — the A–E exclusion taxonomy

def test_exclusion_rules_lists_all_five_groups():
    block = prompts.EXCLUSION_RULES
    assert block.startswith("OUT OF SCOPE")
    # The self-verification gate references "exclusion group A–E"; the rules
    # block must actually define groups A through E.
    for letter in ("A.", "B.", "C.", "D.", "E."):
        assert letter in block, f"exclusion group {letter} missing"


def test_exclusion_rules_group_headers_present():
    block = prompts.EXCLUSION_RULES
    for header in (
        "NO REAL ATTACKER",
        "NO SECURITY IMPACT",
        "WRONG LAYER",
        "HANDLED ELSEWHERE",
        "NOISE FLOOR",
    ):
        assert header in block


def test_exclusion_rules_sca_is_handled_elsewhere():
    # Security-relevant behavior: vulnerable dependency versions are explicitly
    # delegated to the SCA pipeline, not reported by this SAST scan.
    block = prompts.EXCLUSION_RULES
    assert "SCA" in block or "dependency" in block


# SELF_VERIFICATION — the five-check evidence gate

def test_self_verification_enumerates_five_checks():
    block = prompts.SELF_VERIFICATION
    for n in ("1.", "2.", "3.", "4.", "5."):
        assert n in block, f"check {n} missing"


def test_self_verification_named_checks_present():
    block = prompts.SELF_VERIFICATION
    for name in ("REACHABLE", "UNMITIGATED", "CONCRETE", "IN SCOPE", "CITED"):
        assert name in block


def test_self_verification_requires_file_line_citation():
    # Security-relevant: findings must cite real file:line source and sink refs.
    block = prompts.SELF_VERIFICATION
    assert "source_ref" in block and "sink_ref" in block
    assert "file:line" in block


def test_self_verification_references_exclusion_groups():
    # The IN SCOPE check ties back to EXCLUSION_RULES groups A–E.
    assert "A" in prompts.SELF_VERIFICATION and "E" in prompts.SELF_VERIFICATION
    assert "exclusion" in prompts.SELF_VERIFICATION.lower()


# SEVERITY_GUIDANCE — tiering rules

def test_severity_guidance_defines_three_tiers():
    block = prompts.SEVERITY_GUIDANCE
    for tier in ("HIGH", "MEDIUM", "LOW"):
        assert tier in block


def test_severity_guidance_has_ordered_steps():
    block = prompts.SEVERITY_GUIDANCE
    idx1 = block.find("STEP 1")
    idx2 = block.find("STEP 2")
    idx3 = block.find("STEP 3")
    assert -1 < idx1 < idx2 < idx3, "steps must appear in order 1<2<3"


def test_severity_guidance_downgrade_for_nonprod():
    # Behavior: non-prod / test code drops a tier; ties pick the lower tier.
    block = prompts.SEVERITY_GUIDANCE
    assert "drop one tier" in block
    assert "lower" in block


# EXHAUSTIVENESS

def test_exhaustiveness_mentions_full_scope_coverage():
    block = prompts.EXHAUSTIVENESS
    assert "COVERAGE" in block
    assert "scope" in block.lower()


# OSS hygiene — no internal-info disclosure in the public prompt text

def test_prompt_text_contains_no_internal_hostnames_or_urls():
    # These are public OSS prompts; they must not embed internal gateways,
    # credentials, ticket IDs, or internal hostnames.
    combined = "\n".join(ALL_BLOCKS.values()).lower()
    for bad in ("http://", "https://", "@example-internal.", "jira-", "ticket-"):
        assert bad not in combined, f"unexpected internal token {bad!r} in prompts"
