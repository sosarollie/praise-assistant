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

"""Deterministic host-side scoring from synthesized_gates.json; agent math is not authoritative."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import NamedTuple
from pathlib import Path
from typing import TYPE_CHECKING

from vvaharness.models import Decision, Provenance, ScoringPolicy, Verdict
from vvaharness.validation.constants.artifacts import SYNTHESIZED_GATES_FILENAME
from vvaharness.validation.scoring import score_fix

if TYPE_CHECKING:
    from vvaharness.validation.models.output import OutputFinding

log = logging.getLogger(__name__)

__all__ = ["conformant", "load_synthesized_gates", "verdict_for"]

#: Rationale when no gates reached the host, so a reader can tell "unscored" from "scored zero".
_NO_GATES = (
    "no host-verified gates were available for this finding; the agent's self-reported "
    "verdict is not authoritative, so no score is recorded"
)


def _read_gates_text(workspace_dir: Path) -> str | None:
    """Read synthesized_gates.json; None when absent -- the normal, silent fail-closed case."""
    try:
        return (workspace_dir / SYNTHESIZED_GATES_FILENAME).read_text(encoding="utf-8")
    except OSError:
        # No file written: the agent produced no gates. Normal; fail closed silently.
        return None


def _parse_gates_array(text: str) -> list[object] | None:
    """Parse the gates JSON array; None (with a warning) when unparseable or not an array."""
    try:
        data: object = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        log.warning("%s present but unparseable; failing closed", SYNTHESIZED_GATES_FILENAME)
        return None
    if isinstance(data, list):
        return data
    log.warning("%s is not a JSON array; failing closed", SYNTHESIZED_GATES_FILENAME)
    return None


def _gates_by_tracking_id(data: list[object]) -> dict[str, list[Mapping[str, object]]]:
    """Index well-formed entries by tracking_id; drop and count malformed ones."""
    gates_by_id: dict[str, list[Mapping[str, object]]] = {}
    dropped: int = 0
    for entry in data:
        if isinstance(entry, Mapping) and isinstance(entry.get("gates"), list):
            gates_by_id[str(entry.get("tracking_id", ""))] = entry["gates"]
        else:
            dropped += 1
    if dropped:
        log.warning("dropped %d malformed entries from %s", dropped, SYNTHESIZED_GATES_FILENAME)
    return gates_by_id


def load_synthesized_gates(workspace_dir: Path) -> dict[str, list[Mapping[str, object]]]:
    """Map tracking_id -> raw gate dicts from synthesized_gates.json; {} on absent/malformed."""
    text: str | None = _read_gates_text(workspace_dir)
    if text is None:
        return {}
    data: list[object] | None = _parse_gates_array(text)
    if data is None:
        return {}
    return _gates_by_tracking_id(data)


class _Narrative(NamedTuple):
    """Everything the agent said that the host keeps, as opposed to recomputes."""

    conditions: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()
    rationale: str = ""


def _narrative(output_finding: OutputFinding | None) -> _Narrative:
    """Return what the agent said; its prose survives even when its score does not."""
    if output_finding is None:
        return _Narrative()
    return _Narrative(
        conditions=tuple(output_finding.conditions_for_full_fix),
        recommendations=tuple(output_finding.recommendations),
        rationale=output_finding.justification or "",
    )


def conformant(verdict: Verdict, policy: ScoringPolicy | None) -> Verdict:
    """Harness acceptance check: a verdict silent on a required gate downgrades to INCONCLUSIVE."""
    if policy is None:
        return verdict
    missing = policy.missing_from(gate.name for gate in verdict.gates)
    if not missing:
        return verdict
    return verdict.model_copy(update={
        "decision": Decision.INCONCLUSIVE,
        "score": None,
        "rationale": (f"verdict does not answer required gate(s): {', '.join(missing)}; "
                      f"not scored"),
    })


def verdict_for(
    output_finding: OutputFinding | None,
    gates: list[Mapping[str, object]] | None,
    *,
    provenance: Provenance,
    policy: ScoringPolicy | None = None,
) -> Verdict:
    """Return the authoritative verdict: host numbers, agent narrative, never fix_status."""
    said = _narrative(output_finding)
    if not gates:
        return Verdict(
            decision=Decision.INCONCLUSIVE,
            rationale=_NO_GATES,
            score=None,
            conditions=said.conditions,
            recommendations=said.recommendations,
            engine_rationale=said.rationale,
            produced_by=provenance,
        )
    scored = score_fix(list(gates), policy=policy)
    return Verdict(
        decision=scored.decision,
        rationale=scored.justification,
        # A refusal inside the engine also means "no number", not zero confidence.
        score=None if scored.decision is Decision.INCONCLUSIVE else scored.raw_score,
        gates=scored.gates,
        conditions=said.conditions,
        recommendations=said.recommendations,
        engine_rationale=said.rationale,
        produced_by=provenance,
    )
