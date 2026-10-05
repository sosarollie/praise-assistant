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


"""Data contracts passed between pipeline steps; no raw dicts cross step boundaries."""

from vvaharness.models._scan import (
    _MD_INVISIBLE_RX,
    _MD_LINEBREAK_RX,
    CFG,
    CVE,
    OFFENSIVE_LABELS,
    AppProfile,
    Asset,
    BridgeUncertaintyEdge,
    CFGNode,
    Chain,
    Chunk,
    ChunkSize,
    ConditionTaintEdge,
    ContextPackage,
    Control,
    DroppedFinding,
    DupLocation,
    EntryPoint,
    FinalReport,
    Finding,
    FrameworkMarkerFact,
    FrameworkTaintEdge,
    ModuleInfo,
    RankedFinding,
    ReflectionFact,
    ReflectionTaintEdge,
    ResponseDataflowFact,
    RouteTaintFact,
    ScanMetrics,
    ScopeEntry,
    Severity,
    Sink,
    TaintEvidencePath,
    TaintSymbolRef,
    TaintTransferEdge,
    TaskManifest,
    Threat,
    ThreatModel,
    TrustBoundary,
    VulnClass,
    _demote_md_headings,
    _md_cell,
)
from vvaharness.models.case import Attempt, FindingCase
from vvaharness.models.context import ScoringPolicy
from vvaharness.models.derive import merge_readiness_for, state_of, verdict_state
from vvaharness.models.gates import EvidenceAnchor, GateAssessment
from vvaharness.models.provenance import (
    HARNESS_REGISTRY,
    LLM_REGISTRY,
    Provenance,
)
from vvaharness.models.remediation import (
    FileChange,
    Remediation,
    RemediationEvidence,
    finalize,
)
from vvaharness.models.verdict import Ticket, Verdict
from vvaharness.models.vocab import (
    CANONICAL_GATE_NAMES,
    EVIDENCE_GATES,
    FIX_VALIDATION_GATES,
    CaseState,
    Decision,
    Disposition,
    GateStatus,
    MergeReadiness,
    RemediationKind,
    RemediationOutcome,
    normalise_gate_name,
)

__all__ = [
    "CANONICAL_GATE_NAMES",
    "CFG",
    "CVE",
    "EVIDENCE_GATES",
    "FIX_VALIDATION_GATES",
    "OFFENSIVE_LABELS",
    "AppProfile",
    "Asset",
    "Attempt",
    "BridgeUncertaintyEdge",
    "CFGNode",
    "CaseState",
    "Chain",
    "Chunk",
    "ChunkSize",
    "ConditionTaintEdge",
    "ContextPackage",
    "Control",
    "Decision",
    "Disposition",
    "DroppedFinding",
    "DupLocation",
    "EntryPoint",
    "EvidenceAnchor",
    "FileChange",
    "FinalReport",
    "Finding",
    "FindingCase",
    "FrameworkMarkerFact",
    "FrameworkTaintEdge",
    "GateAssessment",
    "GateStatus",
    "MergeReadiness",
    "ModuleInfo",
    "HARNESS_REGISTRY",
    "LLM_REGISTRY",
    "Provenance",
    "RankedFinding",
    "ReflectionFact",
    "ReflectionTaintEdge",
    "Remediation",
    "RemediationEvidence",
    "RemediationKind",
    "RemediationOutcome",
    "ResponseDataflowFact",
    "RouteTaintFact",
    "ScanMetrics",
    "ScopeEntry",
    "ScoringPolicy",
    "Severity",
    "Sink",
    "TaintEvidencePath",
    "TaintSymbolRef",
    "TaintTransferEdge",
    "TaskManifest",
    "Threat",
    "ThreatModel",
    "Ticket",
    "TrustBoundary",
    "Verdict",
    "VulnClass",
    "finalize",
    "merge_readiness_for",
    "normalise_gate_name",
    "state_of",
    "verdict_state",
]
