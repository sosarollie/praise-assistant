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

"""Unit tests for OffensivePriority tagging (report.enrich.offensive_priority_for).

Focus: the priority tier must not contradict the finding's own CVSS Privileges
Required. A stray "unauthenticated"/"public" keyword in prose must NOT promote a
finding whose vector explicitly says PR:L/PR:H into the top unauthenticated tier.
Pure function, no network.
"""
from vvaharness.report.enrich import AppInfo, offensive_priority_for

_EXTERNAL = AppInfo(externally_facing=True)
_PRL_VEC = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
_PRN_VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_pr_low_vector_vetoes_no_auth_keyword():
    # The prose says "unauthenticated / public endpoint" but the vector scored
    # PR:L (auth required). The explicit PR:L must veto P1 -> P2, and the reason
    # must NOT falsely claim PR:N.
    prio, reason = offensive_priority_for(
        "Unauthenticated SQLi on public endpoint", "injection",
        "reachable without auth", _PRL_VEC, _EXTERNAL)
    assert prio == "P2"
    assert "PR:N" not in reason
    assert "PR:L" in reason


def test_explicit_pr_none_is_p1_unauthenticated():
    prio, reason = offensive_priority_for(
        "SQLi", "injection", "no credentials required", _PRN_VEC, _EXTERNAL)
    assert prio == "P1"
    assert "unauthenticated" in reason
    assert "PR:N" in reason


def test_no_vector_keyword_still_drives_p1():
    # With no CVSS vector at all, a genuine no-auth keyword still tags P1, and
    # the reason makes no PR claim it can't support.
    prio, reason = offensive_priority_for(
        "Unauthenticated access", "access-control", "publicly accessible",
        None, _EXTERNAL)
    assert prio == "P1"
    assert "unauthenticated" in reason
    assert "PR:" not in reason


def test_pr_high_vector_is_not_p1():
    prio, _ = offensive_priority_for(
        "Admin-only but described as public", "logic",
        "publicly accessible endpoint",
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", _EXTERNAL)
    assert prio != "P1"

def test_no_cmdb_av_network_is_capped_p3_not_internet_facing():
    # app=None (no CMDB match): a no-auth AV:N finding must NOT be labelled
    # P1/internet-facing on the vector alone; cap at P3 with an explicit caveat.
    prio, reason = offensive_priority_for(
        "SQLi", "injection", "no credentials required", _PRN_VEC, None)
    assert prio == "P3"
    assert "exposure unverified" in reason
    assert "internet-facing" not in reason


def test_no_cmdb_high_priv_keeps_privilege_reason():
    # No CMDB + high-privilege precondition: still P3, but the privilege reason
    # is preserved (the exposure-unknown caveat defers to the high-priv branch).
    prio, reason = offensive_priority_for(
        "Admin RCE", "logic", "requires admin role",
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", None)
    assert prio == "P3"
    assert "PR:H" in reason or "privileg" in reason.lower()


def test_cmdb_external_unchanged_still_p1():
    # Positive CMDB evidence of external exposure is unaffected by the fix.
    prio, reason = offensive_priority_for(
        "SQLi", "injection", "no credentials required", _PRN_VEC, _EXTERNAL)
    assert prio == "P1"
    assert "internet-facing" in reason
