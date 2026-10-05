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

"""A gate nobody evaluated must never erase a gate somebody failed.

``skip`` means "not evaluated", and the engine drops a skipped gate from BOTH sides
of the score -- so a skip does not merely abstain, it removes that gate's weight from
the denominator. Counting skip as an ordinary vote therefore let two personas who
never looked outvote one that did, deleting a `fail` and RAISING the score. Every
persona is instructed to emit skip without evidence, and cross-repo-analyzer emits
two by design, so a skip majority is routine rather than exotic.

Offline and deterministic: no network, no LLM, no subprocess.
"""

from __future__ import annotations

from vvaharness.models import Decision, GateStatus
from vvaharness.validation.models.persona_report import PersonaReport
from vvaharness.validation.scoring import score_fix
from vvaharness.validation.synthesis._consensus import synthesize_gates_for_finding

TRACKING_ID = "T-1"
GATES = (
    "root_cause",
    "instance_coverage",
    "no_new_vulnerabilities",
    "security_best_practices",
)


def _report(persona: str, target: str, statuses: list[str]) -> PersonaReport:
    """A report where *target* carries every status in *statuses*, rest pass."""
    gates = [{"gate_name": target, "status": s, "summary": f"{persona}:{s}"} for s in statuses]
    gates += [{"gate_name": g, "status": "pass", "summary": "s"} for g in GATES if g != target]
    return PersonaReport(persona=persona, tracking_id=TRACKING_ID, gates=gates)


def _status_of(reports: list[PersonaReport], gate: str) -> tuple[str, str]:
    for synthesized in synthesize_gates_for_finding(reports, TRACKING_ID):
        if synthesized.gate_name == gate:
            return synthesized.status, synthesized.confidence
    raise AssertionError(f"{gate} not synthesized")


def test_skip_majority_cannot_bury_a_fail() -> None:
    """The regression: 2 abstentions outvoting 1 fail scored the finding Fixed/1.0."""
    reports = [
        _report("security-architect", "root_cause", ["fail"]),
        _report("penetration-tester", "root_cause", ["skip"]),
        _report("cross-repo-analyzer", "root_cause", ["skip"]),
    ]
    status, _ = _status_of(reports, "root_cause")
    assert status == "fail"


def test_skip_majority_cannot_bury_a_partial() -> None:
    reports = [
        _report("security-architect", "instance_coverage", ["partial"]),
        _report("penetration-tester", "instance_coverage", ["skip"]),
        _report("cross-repo-analyzer", "instance_coverage", ["skip"]),
    ]
    assert _status_of(reports, "instance_coverage")[0] == "partial"


def test_gate_nobody_evaluated_stays_skip() -> None:
    """Skip is still the honest answer when no persona evaluated the gate."""
    reports = [
        _report(p, "security_best_practices", ["skip"])
        for p in ("security-architect", "penetration-tester", "cross-repo-analyzer")
    ]
    status, confidence = _status_of(reports, "security_best_practices")
    assert status == GateStatus.SKIP.value
    assert confidence == "FLAGGED"


def test_skip_does_not_win_a_tie_against_an_evaluated_status() -> None:
    """A 1-1 skip/pass split must resolve on the evaluated vote, not a rank table."""
    reports = [
        _report("security-architect", "no_new_vulnerabilities", ["pass"]),
        _report("penetration-tester", "no_new_vulnerabilities", ["skip"]),
    ]
    assert _status_of(reports, "no_new_vulnerabilities")[0] == "pass"


def test_one_pass_and_two_skips_cannot_validate_a_fix() -> None:
    """A lone evaluated vote stays visible but cannot become a host verdict."""
    reports = [
        _report("security-architect", "root_cause", ["pass"]),
        _report("penetration-tester", "root_cause", ["skip"]),
        _report("cross-repo-analyzer", "root_cause", ["skip"]),
    ]

    gates = synthesize_gates_for_finding(reports, TRACKING_ID)
    root_cause = next(gate for gate in gates if gate.gate_name == "root_cause")
    result = score_fix([gate.model_dump() for gate in gates])

    assert root_cause.status is GateStatus.PASS
    assert root_cause.confidence == "FLAGGED"
    assert result.decision is Decision.INCONCLUSIVE
    assert result.raw_score == 0.0
    assert "Insufficient persona consensus" in result.justification


def test_duplicate_gate_from_one_persona_keeps_the_conservative_vote() -> None:
    """One report listing a gate twice was last-write-wins, dropping the fail AND
    faking a second agreeing vote, which read as HIGH-confidence consensus."""
    reports = [
        _report("penetration-tester", "no_new_vulnerabilities", ["fail", "pass"]),
        _report("security-architect", "no_new_vulnerabilities", ["pass"]),
    ]
    status, confidence = _status_of(reports, "no_new_vulnerabilities")
    assert status == "fail"
    assert confidence == "FLAGGED"


def test_lone_fail_with_skip_majority_is_inconclusive() -> None:
    """A conservative lone vote stays visible but still lacks consensus."""
    reports = [
        _report("security-architect", "root_cause", ["fail"]),
        _report("penetration-tester", "root_cause", ["skip"]),
        _report("cross-repo-analyzer", "root_cause", ["skip"]),
    ]
    gates = [g.model_dump() for g in synthesize_gates_for_finding(reports, TRACKING_ID)]
    result = score_fix(gates)
    assert result.decision is Decision.INCONCLUSIVE
    assert result.raw_score == 0.0


def test_root_cause_is_critical_so_skipping_it_cannot_pass() -> None:
    """43% of the score unevaluated must not read as Fixed; the coverage floor alone
    lets it through at 0.57 evaluated."""
    gates = [{"gate_name": "root_cause", "status": "skip"}]
    gates += [{"gate_name": g, "status": "pass"} for g in GATES[1:]]
    assert score_fix(gates).decision is Decision.INCONCLUSIVE


def test_skipping_the_security_gate_cannot_pass() -> None:
    gates = [{"gate_name": "no_new_vulnerabilities", "status": "skip"}]
    gates += [{"gate_name": g, "status": "pass"} for g in GATES if g != "no_new_vulnerabilities"]
    assert score_fix(gates).decision is Decision.INCONCLUSIVE
