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

"""Deterministic synthesis of persona gate reports into host-owned gate verdicts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from pydantic import BaseModel

from vvaharness.models import GateStatus
from vvaharness.validation.constants.synthesis import MIN_CONSENSUS_VOTES
from vvaharness.validation.enums.synthesis import SynthesisConfidence
from vvaharness.validation.models.persona_report import (
    PersonaGateEntry,
    PersonaReport,
)

# Most-severe-first ordering for persona synthesis; this panel's tie-break policy, not vocabulary.
_STATUS_CONSERVATIVE_RANK: tuple[GateStatus, ...] = (
    GateStatus.FAIL,
    GateStatus.PARTIAL,
    GateStatus.PASS,
    GateStatus.SKIP,
    GateStatus.INVALID,
)


class SynthesizedEvidence(BaseModel):
    """One persona's file/line evidence, carried onto a synthesized gate verdict."""

    persona: str
    file: str
    line: int | None
    snippet: str


class SynthesizedGate(BaseModel):
    """Host-produced gate verdict for one finding."""

    tracking_id: str
    gate_name: str
    status: GateStatus
    confidence: SynthesisConfidence
    summary: str
    details: str
    evidence: list[SynthesizedEvidence]
    persona_votes: dict[str, GateStatus]


def _most_conservative_status(statuses: Iterable[GateStatus]) -> GateStatus:
    """Return the most conservative status in *statuses*."""
    present = set(statuses)
    for status in _STATUS_CONSERVATIVE_RANK:
        if status in present:
            return status
    return GateStatus.INVALID


def synthesize_gates_for_finding(
    reports: list[PersonaReport],
    tracking_id: str,
) -> list[SynthesizedGate]:
    """Apply conservative consensus: 2+ votes win at HIGH, else most conservative wins FLAGGED."""
    by_gate: dict[str, list[tuple[str, PersonaGateEntry]]] = {}
    for report in reports:
        if report.tracking_id != tracking_id:
            continue
        for gate in report.gates:
            by_gate.setdefault(gate.gate_name, []).append((report.persona, gate))

    synthesized: list[SynthesizedGate] = []
    for gate_name, entries in sorted(by_gate.items()):
        # One vote per persona: listing the same gate twice would be last-write-wins, faking a vote.
        votes: dict[str, GateStatus] = {}
        for persona, gate in entries:
            prior = votes.get(persona)
            votes[persona] = (
                _most_conservative_status([prior, gate.status]) if prior else gate.status
            )

        evaluated = [s for s in votes.values() if s != GateStatus.SKIP]
        if not evaluated:
            chosen_status, confidence = GateStatus.SKIP, SynthesisConfidence.FLAGGED
        else:
            counter = Counter(evaluated)
            top_frequency = max(counter.values())
            top_statuses = [s for s, freq in counter.items() if freq == top_frequency]
            if len(top_statuses) == 1 and top_frequency >= MIN_CONSENSUS_VOTES:
                chosen_status, confidence = top_statuses[0], SynthesisConfidence.HIGH
            else:
                chosen_status = _most_conservative_status(top_statuses)
                confidence = SynthesisConfidence.FLAGGED

        summaries: list[str] = []
        details_pieces: list[str] = []
        evidence: list[SynthesizedEvidence] = []
        for persona, gate in sorted(entries, key=lambda item: item[0]):
            if gate.summary:
                summaries.append(f"{persona}: {gate.summary}")
            if gate.details:
                details_pieces.append(f"{persona}: {gate.details}")
            evidence.extend(
                SynthesizedEvidence(persona=persona, file=ev.file, line=ev.line, snippet=ev.snippet)
                for ev in gate.evidence
            )

        synthesized.append(
            SynthesizedGate(
                tracking_id=tracking_id,
                gate_name=gate_name,
                status=chosen_status,
                confidence=confidence,
                summary=" | ".join(summaries),
                details=" | ".join(details_pieces),
                evidence=sorted(
                    evidence,
                    key=lambda item: (item.file or "", item.line or 0),
                ),
                persona_votes=dict(sorted(votes.items())),
            )
        )

    return synthesized
